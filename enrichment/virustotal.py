"""VirusTotal enrichment — implemented in Phase 2."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def lookup_ip(ip: str, api_key: str, timeout: int = 10) -> dict:
    """Query VirusTotal for reputation data on the given IP address.

    Args:
        ip: IPv4 address to look up.
        api_key: VirusTotal API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict containing vt_malicious_ratio, vt_country, and vt_as_owner keys.
    """
    raise NotImplementedError("VirusTotal enrichment is implemented in Phase 2")


def parse_vt_response(response: dict) -> dict:
    """Extract normalised fields from a raw VirusTotal API response.

    Args:
        response: Raw JSON response dict from the VirusTotal v3 IP API.

    Returns:
        Dict with keys: malicious_ratio (float), country (str), as_owner (str).
    """
    raise NotImplementedError("VirusTotal response parsing is implemented in Phase 2")
