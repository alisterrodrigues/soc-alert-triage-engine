"""Shodan IP lookup for open ports, known CVEs, and exposure scoring."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def lookup_ip(ip: str, api_key: str, timeout: int = 10) -> Optional[dict]:
    """Look up an IP address in Shodan and return exposure data.

    Uses the official shodan Python library. Handles APIError (no data for
    host, rate limit exceeded, or invalid key) gracefully — logs a warning
    and returns None without raising.

    The shodan library is imported inside this function so that the module
    can be imported safely even if the library is not installed.

    Args:
        ip: IPv4 address to query.
        api_key: Shodan API key (read from environment by the caller).
        timeout: Not used by shodan library directly; kept for API consistency.

    Returns:
        Dict with keys: shodan_open_ports (list[int]), shodan_vulns (list[str]),
        shodan_org (str or None), shodan_isp (str or None),
        shodan_country_code (str or None), shodan_exposure_score (float).
        Returns None on any API error.
    """
    try:
        import shodan
    except ImportError:
        logger.error("shodan library not installed — run: pip install shodan")
        return None

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)
    except Exception as e:
        # Catches shodan.exception.APIError, network errors, and anything else
        logger.warning(f"Shodan lookup failed for {ip}: {e}")
        return None

    return _parse_shodan_response(host)


def _parse_shodan_response(host: dict) -> dict:
    """Extract normalised exposure data from a raw Shodan host response.

    Exposure score formula:
        base = len(open_ports) * 0.05, capped at 0.50
        bonus = len(vulns) * 0.10, capped at 0.50
        exposure_score = min(base + bonus, 1.0)

    Args:
        host: Raw dict returned by shodan.Shodan().host(ip).

    Returns:
        Dict with keys: shodan_open_ports, shodan_vulns, shodan_org,
        shodan_isp, shodan_country_code, shodan_exposure_score.
    """
    # open ports — may be under 'ports' or embedded in 'data' items
    open_ports = host.get("ports", [])

    # vulns is a dict of CVE_ID -> details in Shodan's response
    vulns_raw = host.get("vulns", {})
    vuln_ids = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else []

    base = min(len(open_ports) * 0.05, 0.50)
    bonus = min(len(vuln_ids) * 0.10, 0.50)
    exposure_score = round(min(base + bonus, 1.0), 4)

    return {
        "shodan_open_ports": open_ports,
        "shodan_vulns": vuln_ids,
        "shodan_org": host.get("org"),
        "shodan_isp": host.get("isp"),
        "shodan_country_code": host.get("country_code"),
        "shodan_exposure_score": exposure_score,
    }
