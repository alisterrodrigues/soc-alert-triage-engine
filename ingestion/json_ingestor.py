import json
import logging
from pathlib import Path

from ingestion import Alert, _validate_and_build

logger = logging.getLogger(__name__)


def ingest_json(filepath: str) -> list[Alert]:
    """Parse a JSON alert file (array of objects) into a list of Alert objects.

    Expects a top-level JSON array. Each object must include required fields.
    Skips invalid objects with a logged warning. Returns empty list on error.

    Args:
        filepath: Absolute or relative path to the JSON file.

    Returns:
        List of validated Alert instances; may be empty if all items fail validation.
    """
    path = Path(filepath)
    if not path.exists():
        logger.error(f"JSON file not found: {filepath}")
        return []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse JSON {filepath}: {e}")
        return []

    if not isinstance(data, list):
        logger.error(f"JSON file must contain a top-level array: {filepath}")
        return []

    alerts: list[Alert] = []
    for i, obj in enumerate(data):
        alert = _validate_and_build(obj, source=f"json item {i}")
        if alert:
            alerts.append(alert)

    logger.info(f"Ingested {len(alerts)} alerts from {filepath}")
    return alerts
