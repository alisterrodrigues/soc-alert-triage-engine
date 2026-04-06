"""File-based alert source — wraps the existing CSV/JSON ingestors."""
from pathlib import Path

from sources.base import AlertSource
from ingestion.csv_ingestor import ingest_csv
from ingestion.json_ingestor import ingest_json


class FileSource(AlertSource):
    """Alert source backed by a local CSV or JSON file.

    This is the only source that returns Alert objects instead of raw dicts,
    because the underlying ingestors already handle normalization via
    ingestion._validate_and_build().
    """

    def __init__(self, filepath: str, fmt: str) -> None:
        """
        Args:
            filepath: Path to the CSV or JSON alert file.
            fmt: 'csv' or 'json'.
        """
        self._filepath = filepath
        self._fmt = fmt

    def fetch(self) -> list:
        """Return a list of Alert dataclass instances (not raw dicts).

        Delegates directly to ingest_csv or ingest_json, which handle
        field validation and normalization via _validate_and_build() internally.
        Returns an empty list on any failure; never raises.
        """
        if self._fmt == "csv":
            return ingest_csv(self._filepath)
        return ingest_json(self._filepath)

    def source_name(self) -> str:
        return f"file:{self._filepath}"
