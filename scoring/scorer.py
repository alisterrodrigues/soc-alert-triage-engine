"""Multi-factor alert priority scoring with configurable weights and analyst summaries."""
import logging
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


@dataclass
class TriageResult:
    """Scored triage output for a single alert."""

    alert_id: str
    score: float
    priority_label: str       # INVESTIGATE_NOW | INVESTIGATE_SOON | MONITOR | LOW_PRIORITY
    confidence: str           # high | medium | low
    analyst_summary: str
    score_breakdown: dict = field(default_factory=dict)


def score_alert(alert, weights: dict, severity_map: dict, confidence_thresholds: dict) -> TriageResult:
    """Compute a weighted priority score for a single enriched Alert.

    Each factor is normalised to [0.0, 1.0] before weighting. Factors where
    enrichment data is unavailable (None) default to 0.0 and reduce confidence.
    The final score is the sum of (factor_value * weight) across all factors.
    Never raises — any factor computation error is caught and logged.

    Args:
        alert: An Alert instance with enrichment fields populated (or None for dry-run).
        weights: Dict with keys: severity, vt_malicious_ratio, shodan_exposure,
                 asset_criticality, recency. Values are floats summing to ~1.0.
        severity_map: Dict mapping severity labels (critical/high/medium/low) to floats.
        confidence_thresholds: Dict with keys high_confidence and medium_confidence (floats).

    Returns:
        A TriageResult with score, priority_label, confidence, score_breakdown,
        and a one-sentence analyst_summary.
    """
    missing_enrichment = 0

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
            vt_score = 0.0
            missing_enrichment += 1
    except Exception as e:
        logger.warning(f"VT factor error for {alert.alert_id}: {e}")
        vt_score = 0.0
        missing_enrichment += 1

    # ── Factor 3: Shodan exposure ────────────────────────────────────
    try:
        if alert.shodan_exposure_score is not None:
            shodan_score = float(alert.shodan_exposure_score)
        else:
            shodan_score = 0.0
            missing_enrichment += 1
    except Exception as e:
        logger.warning(f"Shodan factor error for {alert.alert_id}: {e}")
        shodan_score = 0.0
        missing_enrichment += 1

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

    # ── Weighted sum ─────────────────────────────────────────────────
    score_breakdown = {
        "severity":           round(severity_score * weights.get("severity", 0.35), 4),
        "vt_malicious_ratio": round(vt_score       * weights.get("vt_malicious_ratio", 0.25), 4),
        "shodan_exposure":    round(shodan_score    * weights.get("shodan_exposure", 0.20), 4),
        "asset_criticality":  round(asset_score     * weights.get("asset_criticality", 0.10), 4),
        "recency":            round(recency_score   * weights.get("recency", 0.10), 4),
    }
    final_score = round(sum(score_breakdown.values()), 4)

    # ── Priority label ───────────────────────────────────────────────
    priority_label = _score_to_label(final_score)

    # ── Confidence ───────────────────────────────────────────────────
    confidence = _compute_confidence(missing_enrichment, final_score, confidence_thresholds)

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
    )


def _compute_recency(timestamp_str: str) -> float:
    """Convert an ISO 8601 timestamp to a recency score from 0.0 to 1.0.

    Scoring tiers:
        < 1 hour   → 1.0
        < 6 hours  → 0.7
        < 24 hours → 0.4
        >= 24 hours → 0.1

    Falls back to 0.4 (medium recency) if the timestamp cannot be parsed,
    logging a debug message rather than raising.

    Args:
        timestamp_str: ISO 8601 datetime string, e.g. "2026-04-04T10:00:00Z".

    Returns:
        Float recency score in [0.0, 1.0].
    """
    try:
        # Handle both Z suffix and +00:00 offset
        ts = timestamp_str.replace("Z", "+00:00")
        alert_time = datetime.fromisoformat(ts)
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_hours = (now - alert_time).total_seconds() / 3600
        if age_hours < 1:
            return 1.0
        elif age_hours < 6:
            return 0.7
        elif age_hours < 24:
            return 0.4
        else:
            return 0.1
    except Exception as e:
        logger.debug(f"Could not parse timestamp '{timestamp_str}': {e}")
        return 0.4


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
    vt_score: float,
    shodan_score: float,
) -> str:
    """Generate a one-sentence analyst summary describing why the score was assigned.

    The summary is deterministic and human-readable — no randomness, no LLM calls.
    It states severity, category, asset context, and the most influential factor.

    Args:
        alert: Alert dataclass instance.
        score: Final numeric score.
        label: Priority label string.
        confidence: Confidence string.
        vt_score: VT malicious ratio (0.0 if unavailable).
        shodan_score: Shodan exposure score (0.0 if unavailable).

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
        conf_note = " (low confidence — enrichment unavailable)"
    else:
        conf_note = ""

    # Pick the dominant factor to highlight
    if vt_score >= 0.30:
        factor_note = f"VT detection ratio {vt_score:.0%}"
    elif shodan_score >= 0.50:
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
