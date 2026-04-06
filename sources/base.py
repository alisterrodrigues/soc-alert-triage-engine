"""Abstract base class for all alert source providers."""
from abc import ABC, abstractmethod


class AlertSource(ABC):
    """Provider interface for fetching raw alerts from any source."""

    @abstractmethod
    def fetch(self) -> list:
        """Fetch alerts from the source.

        Returns:
            For file-based sources: a list of Alert dataclass instances.
            For API-based sources (Splunk, Elastic): a list of raw field dicts
            that must be normalized via _validate_and_build() before use.
            The concrete type differs by implementation — callers must handle both.
            Returns an empty list on any failure; never raises.
        """

    @abstractmethod
    def source_name(self) -> str:
        """Human-readable identifier for this source, used in log messages."""
