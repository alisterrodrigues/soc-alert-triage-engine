"""Alert correlation engine: groups scored alerts into time-windowed incidents and detects kill chains."""
import logging
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

MITRE_TACTIC_STAGES = {
    "RECONNAISSANCE", "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE",
    "PRIVILEGE_ESCALATION", "DEFENSE_EVASION", "CREDENTIAL_ACCESS",
    "DISCOVERY", "LATERAL_MOVEMENT", "COLLECTION",
    "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT",
}

_PRIORITY_LABELS = [
    ("INVESTIGATE_NOW",  0.80),
    ("INVESTIGATE_SOON", 0.55),
    ("MONITOR",          0.30),
    ("LOW_PRIORITY",     0.00),
]


@dataclass
class CorrelatedIncident:
    """A group of temporally related alerts from the same source host."""

    incident_id: str
    host: str
    alert_ids: list = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    peak_score: float = 0.0
    combined_score: float = 0.0
    tactic_chain: list = field(default_factory=list)
    kill_chain_detected: bool = False
    alert_count: int = 0
    priority_label: str = "LOW_PRIORITY"
    summary: str = ""


def correlate_alerts(
    alerts: list,
    results: list,
    window_minutes: int = 15,
    min_alerts_per_incident: int = 1,
) -> list:
    """Group alerts by source_ip within a rolling time window and detect multi-stage chains.

    Algorithm:
    1. Build a dict mapping alert_id → TriageResult for O(1) score lookup.
    2. Sort alerts by (source_ip, timestamp) so temporal grouping is O(n).
    3. For each source_ip group: slide a window of `window_minutes` width.
       Any alert whose timestamp falls within `window_minutes` of the first alert
       in the current group joins that incident. When a gap > window_minutes is
       found, close the current incident and start a new one.
    4. Combined score formula:
       combined_score = peak_score * 0.6 + mean_score * 0.3 + min(alert_count / 10, 1.0) * 0.1
       Capped at 1.0.
    5. tactic_chain: extract mitre_tactic from each alert (field added by Spec C).
       If mitre_tactic is None or empty, skip. Deduplicate preserving order.
    6. kill_chain_detected: True if tactic_chain contains >= 2 of these tactic stages:
       RECONNAISSANCE, INITIAL_ACCESS, EXECUTION, PERSISTENCE, PRIVILEGE_ESCALATION,
       DEFENSE_EVASION, CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT, COLLECTION,
       COMMAND_AND_CONTROL, EXFILTRATION, IMPACT.
    7. summary: "{alert_count} alerts from {host} over {duration_minutes}min — {top tactic or category}."

    Args:
        alerts: List of Alert instances (with mitre_tactic populated if Spec C is applied).
        results: List of TriageResult instances parallel to alerts.
        window_minutes: Maximum gap between consecutive alerts to group them.
        min_alerts_per_incident: Incidents with fewer alerts than this are still returned
            (set to 1 so single high-severity alerts are included as incidents).

    Returns:
        List of CorrelatedIncident instances sorted by combined_score descending.
    """
    if not alerts:
        return []

    result_map = {r.alert_id: r for r in results}

    def _sort_key(alert):
        ts = _parse_ts(alert.timestamp)
        return (alert.source_ip, ts if ts is not None else datetime(1970, 1, 1, tzinfo=timezone.utc))

    sorted_alerts = sorted(alerts, key=_sort_key)

    incidents = []
    current_group = [sorted_alerts[0]]
    current_ip = sorted_alerts[0].source_ip

    for alert in sorted_alerts[1:]:
        if alert.source_ip != current_ip:
            incidents.append(_build_incident(current_group, result_map))
            current_group = [alert]
            current_ip = alert.source_ip
        else:
            prev_ts = _parse_ts(current_group[-1].timestamp)
            curr_ts = _parse_ts(alert.timestamp)
            if prev_ts is not None and curr_ts is not None:
                gap_min = (curr_ts - prev_ts).total_seconds() / 60
            else:
                gap_min = 0.0

            if gap_min <= window_minutes:
                current_group.append(alert)
            else:
                incidents.append(_build_incident(current_group, result_map))
                current_group = [alert]

    incidents.append(_build_incident(current_group, result_map))

    incidents.sort(key=lambda i: i.combined_score, reverse=True)
    return incidents


def _build_incident(alerts: list, result_map: dict) -> CorrelatedIncident:
    """Construct a CorrelatedIncident from a list of alerts belonging to one window."""
    host = alerts[0].source_ip
    alert_ids = [a.alert_id for a in alerts]
    alert_count = len(alerts)

    parsed_ts = [_parse_ts(a.timestamp) for a in alerts]
    valid_ts = [t for t in parsed_ts if t is not None]
    now = datetime.now(timezone.utc)
    start_ts = min(valid_ts) if valid_ts else now
    end_ts = max(valid_ts) if valid_ts else now
    duration_min = int((end_ts - start_ts).total_seconds() / 60)

    scores = [result_map[a.alert_id].score if a.alert_id in result_map else 0.0 for a in alerts]
    peak_score = max(scores) if scores else 0.0
    mean_score = sum(scores) / len(scores) if scores else 0.0
    combined_score = round(
        min(peak_score * 0.6 + mean_score * 0.3 + min(alert_count / 10, 1.0) * 0.1, 1.0),
        4,
    )

    # Tactic chain — deduplicate preserving chronological order
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    seen: set = set()
    tactic_chain = []
    for a in ordered:
        tactic = getattr(a, "mitre_tactic", None)
        if tactic and tactic not in seen:
            seen.add(tactic)
            tactic_chain.append(tactic)

    kill_chain_detected = sum(1 for t in tactic_chain if t in MITRE_TACTIC_STAGES) >= 2

    priority_label = _score_to_label(combined_score)

    top_context = tactic_chain[0] if tactic_chain else _most_common_category(alerts)
    summary = f"{alert_count} alerts from {host} over {duration_min}min — {top_context}."

    return CorrelatedIncident(
        incident_id=str(uuid.uuid4()),
        host=host,
        alert_ids=alert_ids,
        start_time=start_ts.isoformat(),
        end_time=end_ts.isoformat(),
        peak_score=round(peak_score, 4),
        combined_score=combined_score,
        tactic_chain=tactic_chain,
        kill_chain_detected=kill_chain_detected,
        alert_count=alert_count,
        priority_label=priority_label,
        summary=summary,
    )


def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string, returning None on failure."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _score_to_label(score: float) -> str:
    """Map a combined score to a priority label using the standard thresholds."""
    for label, threshold in _PRIORITY_LABELS:
        if score >= threshold:
            return label
    return "LOW_PRIORITY"


def _most_common_category(alerts: list) -> str:
    """Return the most frequent alert category among the given alerts."""
    categories = [getattr(a, "category", "other") for a in alerts]
    if not categories:
        return "unknown"
    return Counter(categories).most_common(1)[0][0].replace("_", " ")
