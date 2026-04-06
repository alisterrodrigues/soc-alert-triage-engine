import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CATEGORIES = {"malware", "phishing", "lateral_movement", "c2", "data_exfil", "recon", "other"}


@dataclass
class Alert:
    """Normalised representation of a single SOC alert."""

    alert_id: str
    timestamp: str                       # ISO 8601 string, not parsed to datetime
    source_ip: str
    alert_name: str
    severity: str                        # critical | high | medium | low
    category: str                        # malware | phishing | lateral_movement | c2 | data_exfil | recon | other
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    rule_id: Optional[str] = None
    asset_tags: list[str] = field(default_factory=list)   # split from comma-separated string
    raw_payload: Optional[str] = None
    analyst_notes: Optional[str] = None
    # Enrichment fields — populated in Phase 2
    vt_malicious_ratio: Optional[float] = None
    vt_country: Optional[str] = None
    vt_as_owner: Optional[str] = None
    shodan_open_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    shodan_org: Optional[str] = None
    shodan_exposure_score: Optional[float] = None
    enrichment_source: str = "pending"   # pending | live | cache | dry_run
    # MITRE ATT&CK fields — populated by correlation/tagger.py
    mitre_tactic: Optional[str] = None          # e.g. "LATERAL_MOVEMENT"
    mitre_technique: Optional[str] = None        # e.g. "T1021.001"
    mitre_technique_name: Optional[str] = None   # e.g. "Remote Desktop Protocol" | skipped_private


def _opt_str(val) -> Optional[str]:
    """Return None if val is None or empty after stripping, else the stripped string.

    Prevents Python None values from becoming the literal string 'None' when
    ingesting fields that may be null in JSON input.

    Args:
        val: Raw value from a CSV row or JSON object.

    Returns:
        Stripped string, or None if val was None or blank.
    """
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _validate_and_build(row: dict, source: str) -> Optional[Alert]:
    """Validate a raw dict and return a fully constructed Alert, or None on failure.

    Args:
        row: Dict of field names to raw string values, from a CSV row or JSON object.
        source: Human-readable label used in warning messages (e.g. "csv row 3").

    Returns:
        A validated Alert dataclass instance, or None if any required field is absent.
    """
    required = ["alert_id", "timestamp", "source_ip", "alert_name"]
    for field_name in required:
        if not str(row.get(field_name, "")).strip():
            logger.warning(f"Skipping {source}: missing required field '{field_name}'")
            return None

    severity = str(row.get("severity", "low")).strip().lower()
    if severity not in VALID_SEVERITIES:
        logger.warning(f"{source}: invalid severity '{severity}', defaulting to 'low'")
        severity = "low"

    category = str(row.get("category", "other")).strip().lower()
    if category not in VALID_CATEGORIES:
        logger.warning(f"{source}: invalid category '{category}', defaulting to 'other'")
        category = "other"

    tags_raw = _opt_str(row.get("asset_tags"))
    asset_tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

    dest_port: Optional[int] = None
    port_raw = row.get("destination_port", "")
    if port_raw:
        try:
            dest_port = int(port_raw)
        except (ValueError, TypeError):
            logger.warning(f"{source}: invalid destination_port '{port_raw}', setting to None")

    return Alert(
        alert_id=str(row["alert_id"]).strip(),
        timestamp=str(row["timestamp"]).strip(),
        source_ip=str(row["source_ip"]).strip(),
        alert_name=str(row["alert_name"]).strip(),
        severity=severity,
        category=category,
        destination_ip=_opt_str(row.get("destination_ip")),
        destination_port=dest_port,
        rule_id=_opt_str(row.get("rule_id")),
        asset_tags=asset_tags,
        raw_payload=_opt_str(row.get("raw_payload")),
        analyst_notes=_opt_str(row.get("analyst_notes")),
    )
