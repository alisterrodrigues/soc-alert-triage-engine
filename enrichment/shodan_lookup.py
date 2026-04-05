"""Shodan enrichment — implemented in Phase 2."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def lookup_ip(ip: str, api_key: str, timeout: int = 10) -> dict:
    """Query Shodan for host intelligence on the given IP address.

    Args:
        ip: IPv4 address to look up.
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict containing open_ports, vulns, org, and exposure_score keys.
    """
    raise NotImplementedError("Shodan enrichment is implemented in Phase 2")


def compute_exposure_score(open_ports: list[int], vulns: list[str]) -> float:
    """Derive a normalised exposure score (0.0–1.0) from Shodan host data.

    Args:
        open_ports: List of open port numbers reported by Shodan.
        vulns: List of CVE identifiers reported by Shodan.

    Returns:
        Float in [0.0, 1.0] representing host exposure severity.
    """
    raise NotImplementedError("Exposure scoring is implemented in Phase 2")
