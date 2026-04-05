import csv
import logging
from pathlib import Path

from ingestion import Alert, _validate_and_build

logger = logging.getLogger(__name__)


def ingest_csv(filepath: str) -> list[Alert]:
    """Parse a CSV alert file into a list of Alert objects.

    Expects a header row matching the Alert schema field names.
    Skips rows with missing required fields (logs warning per skip).
    Returns empty list on file-not-found or parse error.

    Args:
        filepath: Absolute or relative path to the CSV file.

    Returns:
        List of validated Alert instances; may be empty if all rows fail validation.
    """
    path = Path(filepath)
    if not path.exists():
        logger.error(f"CSV file not found: {filepath}")
        return []

    alerts: list[Alert] = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader, start=2):  # start=2 because row 1 is header
                alert = _validate_and_build(row, source=f"csv row {i}")
                if alert:
                    alerts.append(alert)
    except Exception as e:
        logger.error(f"Failed to parse CSV {filepath}: {e}")
        return []

    logger.info(f"Ingested {len(alerts)} alerts from {filepath}")
    return alerts
