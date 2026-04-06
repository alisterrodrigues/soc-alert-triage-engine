"""MITRE ATT&CK tactic and technique tagger for SOC alerts."""
import logging
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Load mappings once at import time — path is relative to this file so it
# works regardless of the process working directory.
_MAPPINGS_PATH = Path(__file__).parent / "mitre_mappings.yaml"


def load_mappings() -> dict:
    """Load and return the MITRE mapping YAML. Returns empty dict on failure.

    Returns:
        Dict with 'categories' and 'rule_id_prefixes' keys, or {} on any error.
    """
    try:
        with open(_MAPPINGS_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning(f"Failed to load MITRE mappings from {_MAPPINGS_PATH}: {e}")
        return {}


_MAPPINGS: dict = load_mappings()


def tag_alert(alert) -> None:
    """Populate mitre_tactic, mitre_technique, mitre_technique_name on an Alert in-place.

    Rule ID prefix takes priority over category mapping when both match.
    Sets fields to None when no match is found.

    Args:
        alert: Alert dataclass instance. Modified in-place.
    """
    match: Optional[dict] = None

    # Check rule_id prefix first — highest priority
    rule_id = getattr(alert, "rule_id", None)
    if rule_id:
        for prefix, mapping in _MAPPINGS.get("rule_id_prefixes", {}).items():
            if rule_id.startswith(prefix):
                match = mapping
                break

    # Fall back to category mapping
    if match is None:
        category = getattr(alert, "category", None)
        if category:
            match = _MAPPINGS.get("categories", {}).get(category)

    if match:
        alert.mitre_tactic = match.get("tactic")
        alert.mitre_technique = match.get("technique")
        alert.mitre_technique_name = match.get("technique_name")
    else:
        alert.mitre_tactic = None
        alert.mitre_technique = None
        alert.mitre_technique_name = None
