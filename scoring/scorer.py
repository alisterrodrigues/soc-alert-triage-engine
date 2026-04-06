"""Multi-factor alert priority scoring with configurable weights and analyst summaries."""
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

PRIORITY_LABELS = [
    ("INVESTIGATE_NOW",  0.80),
    ("INVESTIGATE_SOON", 0.55),
    ("MONITOR",          0.30),
    ("LOW_PRIORITY",     0.00),
]

# High/medium risk port sets used by _compute_shodan_exposure
_HIGH_RISK_PORTS = {3389, 445, 5900, 1433, 9200, 27017, 6379, 4444, 8080, 2375}
_MEDIUM_RISK_PORTS = {22, 21, 23, 25, 3306, 5432, 5984, 11211, 2181}


@dataclass
class TriageResult:
    """Scored triage output for a single alert."""

    alert_id: str
    score: float
    priority_label: str       # INVESTIGATE_NOW | INVESTIGATE_SOON | MONITOR | LOW_PRIORITY
    confidence: str           # high | medium | low
    analyst_summary: str
    score_breakdown: dict = field(default_factory=dict)
    enrichment_completeness: float = 1.0  # 1.0=full, 0.5=one source missing, 0.0=both missing
    prior_sightings_count: Optional[int] = None  # how many prior appearances in lookback window


def score_alert(
    alert,
    weights: dict,
    severity_map: dict,
    confidence_thresholds: dict,
    prior_sightings_count: Optional[int] = None,
) -> TriageResult:
    """Compute a weighted priority score for a single enriched Alert.

    Each factor is normalised to [0.0, 1.0] before weighting. When enrichment
    data is unavailable (None), weights are renormalised across available factors
    so the score represents the best estimate from available data.
    Never raises — any factor computation error is caught and logged.

    Args:
        alert: An Alert instance with enrichment fields populated (or None for dry-run).
        weights: Dict with keys: severity, vt_malicious_ratio, shodan_exposure,
                 asset_criticality, recency, prior_sightings. Values sum to ~1.0.
        severity_map: Dict mapping severity labels (critical/high/medium/low) to floats.
        confidence_thresholds: Dict with keys high_confidence and medium_confidence (floats).
        prior_sightings_count: Count of matching alerts in the historical lookback window,
            or None when the DB is unavailable (factor excluded from renormalization).

    Returns:
        A TriageResult with score, priority_label, confidence, score_breakdown,
        enrichment_completeness, prior_sightings_count, and analyst_summary.
    """
    # ── Factor 1: Severity ──────────────────────────────────────────
    try:
        severity_score = severity_map.get(alert.severity, severity_map.get("low", 0.20))
    except Exception as e:
        logger.warning(f"Severity factor error for {alert.alert_id}: {e}")
        severity_score = 0.0

    # ── Factor 2: VT malicious ratio ────────────────────────────────
    try:
        if alert.vt_malicious_ratio is not None:
            vt_score = float(alert.vt_malicious_ratio)
        else:
            vt_score = None
    except Exception as e:
        logger.warning(f"VT factor error for {alert.alert_id}: {e}")
        vt_score = None

    # ── Factor 3: Shodan exposure — weighted port/CVE model ──────────
    try:
        if alert.shodan_open_ports or alert.shodan_vulns:
            shodan_score = _compute_shodan_exposure(alert.shodan_open_ports, alert.shodan_vulns)
        elif alert.shodan_exposure_score is not None:
            shodan_score = float(alert.shodan_exposure_score)
        else:
            shodan_score = None
    except Exception as e:
        logger.warning(f"Shodan factor error for {alert.alert_id}: {e}")
        shodan_score = None

    # ── Factor 4: Asset criticality ──────────────────────────────────
    try:
        tags = set(alert.asset_tags)
        if "dc" in tags or "server" in tags:
            asset_score = 1.0
        elif "cloud" in tags:
            asset_score = 0.5
        else:
            asset_score = 0.2
    except Exception as e:
        logger.warning(f"Asset criticality factor error for {alert.alert_id}: {e}")
        asset_score = 0.2

    # ── Factor 5: Recency ────────────────────────────────────────────
    try:
        recency_score = _compute_recency(alert.timestamp)
    except Exception as e:
        logger.warning(f"Recency factor error for {alert.alert_id}: {e}")
        recency_score = 0.4

    # ── Factor 6: Prior sightings ────────────────────────────────────
    # prior_sightings_count is passed in as an optional int (None if DB not available)
    try:
        if prior_sightings_count is not None:
            # 0 prior → 0.0, 1 → 0.3, 2 → 0.51, 3 → 0.657, 5+ → 0.832+, capped at 1.0
            sightings_score = round(min(1 - (0.7 ** prior_sightings_count), 1.0), 4)
        else:
            sightings_score = None
    except Exception as e:
        logger.warning(f"Prior sightings factor error for {alert.alert_id}: {e}")
        sightings_score = None

    # ── Build factor values — None means unavailable ─────────────────
    factor_values = {
        "severity":           severity_score,
        "vt_malicious_ratio": vt_score if alert.vt_malicious_ratio is not None else None,
        "shodan_exposure":    shodan_score if (alert.shodan_exposure_score is not None or alert.shodan_open_ports) else None,
        "asset_criticality":  asset_score,
        "recency":            recency_score,
        "prior_sightings":    sightings_score,
    }

    # Count missing enrichment (VT and Shodan only — severity/asset/recency always available)
    missing_enrichment = sum(1 for k in ("vt_malicious_ratio", "shodan_exposure") if factor_values[k] is None)

    # Renormalize weights across available factors
    available_weight = sum(
        weights.get(k, 0.0) for k, v in factor_values.items() if v is not None
    )
    if available_weight <= 0:
        available_weight = 1.0

    score_breakdown = {}
    for k, v in factor_values.items():
        w = weights.get(k, 0.0)
        if v is not None:
            # Renormalized weight: scale up proportionally so available factors sum to 1.0
            effective_w = w / available_weight
            score_breakdown[k] = round(v * effective_w, 4)
        else:
            score_breakdown[k] = 0.0

    final_score = round(sum(score_breakdown.values()), 4)

    # ── Priority label ───────────────────────────────────────────────
    priority_label = _score_to_label(final_score)

    # ── Confidence ───────────────────────────────────────────────────
    confidence = _compute_confidence(missing_enrichment, final_score, confidence_thresholds)

    # ── Enrichment completeness ──────────────────────────────────────
    enrichment_completeness = 1.0 - (missing_enrichment * 0.5)

    # ── Analyst summary ──────────────────────────────────────────────
    analyst_summary = _build_summary(
        alert, final_score, priority_label, confidence, vt_score, shodan_score
    )

    return TriageResult(
        alert_id=alert.alert_id,
        score=final_score,
        priority_label=priority_label,
        confidence=confidence,
        analyst_summary=analyst_summary,
        score_breakdown=score_breakdown,
        enrichment_completeness=enrichment_completeness,
        prior_sightings_count=prior_sightings_count,
    )


def _compute_recency(timestamp_str: str) -> float:
    """Convert an ISO 8601 timestamp to a recency score using exponential decay.

    Uses a 6-hour half-life model: score halves every 6 hours from 1.0,
    with a floor of 0.10 so old-but-severe alerts remain visible.
    Falls back to 0.4 on parse failure.

    Args:
        timestamp_str: ISO 8601 datetime string, e.g. "2026-04-04T10:00:00Z".

    Returns:
        Float recency score in [0.10, 1.0].
    """
    try:
        ts = timestamp_str.replace("Z", "+00:00")
        alert_time = datetime.fromisoformat(ts)
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_hours = (now - alert_time).total_seconds() / 3600
        half_life = 6.0
        decay = math.exp(-math.log(2) * age_hours / half_life)
        return round(max(decay, 0.10), 4)
    except Exception as e:
        logger.debug(f"Could not parse timestamp '{timestamp_str}': {e}")
        return 0.4


def _compute_shodan_exposure(open_ports: list, vulns: list) -> float:
    """Compute a weighted Shodan exposure score from open ports and known vulnerabilities.

    Port scoring: high-risk ports (RDP, SMB, VNC, MSSQL, Elasticsearch, MongoDB,
    Redis, metasploit default, alt-HTTP, Docker daemon) score 0.15 each.
    Medium-risk ports (SSH, FTP, Telnet, SMTP, MySQL, Postgres, CouchDB,
    Memcached, Zookeeper) score 0.07 each. All others score 0.02.
    Port contribution capped at 0.60.

    Vulnerability scoring: 0.12 per known CVE, capped at 0.40.
    Total capped at 1.0.

    Args:
        open_ports: List of integer port numbers from Shodan.
        vulns: List of CVE ID strings from Shodan.

    Returns:
        Float exposure score in [0.0, 1.0].
    """
    port_score = 0.0
    for p in open_ports:
        if p in _HIGH_RISK_PORTS:
            port_score += 0.15
        elif p in _MEDIUM_RISK_PORTS:
            port_score += 0.07
        else:
            port_score += 0.02
    port_score = min(port_score, 0.60)
    vuln_score = min(len(vulns) * 0.12, 0.40)
    return round(min(port_score + vuln_score, 1.0), 4)


def _score_to_label(score: float) -> str:
    """Map a numeric score to the appropriate priority label.

    Thresholds (inclusive lower bound, iterated highest-first):
        >= 0.80 → INVESTIGATE_NOW
        >= 0.55 → INVESTIGATE_SOON
        >= 0.30 → MONITOR
        <  0.30 → LOW_PRIORITY

    Args:
        score: Float in [0.0, 1.0].

    Returns:
        One of: INVESTIGATE_NOW, INVESTIGATE_SOON, MONITOR, LOW_PRIORITY.
    """
    for label, threshold in PRIORITY_LABELS:
        if score >= threshold:
            return label
    return "LOW_PRIORITY"


def _compute_confidence(missing_enrichment: int, score: float, thresholds: dict) -> str:
    """Determine confidence level based on enrichment completeness and score.

    Rules:
        - Both VT and Shodan data present (missing=0):
            score >= high_confidence threshold → 'high', else → 'medium'
        - One missing (missing=1): always 'medium'
        - Both missing (missing=2): always 'low'

    Args:
        missing_enrichment: Count of enrichment sources that returned None (0, 1, or 2).
        score: The final numeric score.
        thresholds: Dict with high_confidence and medium_confidence float keys.

    Returns:
        One of: 'high', 'medium', 'low'.
    """
    if missing_enrichment == 2:
        return "low"
    elif missing_enrichment == 1:
        return "medium"
    else:
        high_thresh = thresholds.get("high_confidence", 0.80)
        return "high" if score >= high_thresh else "medium"


def _build_summary(
    alert,
    score: float,
    label: str,
    confidence: str,
    vt_score: Optional[float],
    shodan_score: Optional[float],
) -> str:
    """Generate a one-sentence analyst summary describing why the score was assigned.

    The summary is deterministic and human-readable — no randomness, no LLM calls.
    It states severity, category, asset context, and the most influential factor.

    Args:
        alert: Alert dataclass instance.
        score: Final numeric score.
        label: Priority label string.
        confidence: Confidence string.
        vt_score: VT malicious ratio, or None if unavailable.
        shodan_score: Shodan exposure score, or None if unavailable.

    Returns:
        A single sentence string suitable for display in the HTML report and terminal.
    """
    severity = alert.severity.capitalize()
    category = alert.category.replace("_", " ")
    tags = alert.asset_tags
    asset_ctx = (
        "domain controller" if "dc" in tags else
        "server" if "server" in tags else
        "cloud asset" if "cloud" in tags else
        "workstation" if "workstation" in tags else
        "endpoint"
    )

    if confidence == "low":
        conf_note = " (low confidence — enrichment unavailable, score renormalized over available factors)"
    elif confidence == "medium":
        conf_note = " (medium confidence — partial enrichment)"
    else:
        conf_note = ""

    # Pick the dominant factor to highlight
    if vt_score is not None and vt_score >= 0.30:
        factor_note = f"VT detection ratio {vt_score:.0%}"
    elif shodan_score is not None and shodan_score >= 0.50:
        factor_note = f"Shodan exposure score {shodan_score:.2f}"
    elif alert.severity in ("critical", "high"):
        factor_note = f"{severity} severity"
    else:
        factor_note = "low threat indicators"

    if label == "INVESTIGATE_NOW":
        action = "Immediate investigation warranted"
    elif label == "INVESTIGATE_SOON":
        action = "Investigate within the shift"
    elif label == "MONITOR":
        action = "Monitor for escalation"
    else:
        action = "Low priority — review when time allows"

    return (
        f"{severity}-severity {category} alert on {asset_ctx} "
        f"(score {score:.2f}, {factor_note}). {action}{conf_note}."
    )
