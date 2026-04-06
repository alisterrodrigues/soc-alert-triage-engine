"""Abstract base class for all alert source providers."""
from abc import ABC, abstractmethod


class AlertSource(ABC):
    """Provider interface for fetching raw alerts from any source."""

    @abstractmethod
    def fetch(self) -> list[dict]:
        """Fetch raw alert dicts from the source.

        Returns:
            List of raw dict rows. Each dict must be normalizable by
            ingestion._validate_and_build(). Keys should match the Alert schema.
            Empty list on failure — never raises.
        """

    @abstractmethod
    def source_name(self) -> str:
        """Human-readable identifier for this source, used in log messages."""
