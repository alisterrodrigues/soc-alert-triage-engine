"""VirusTotal IP reputation enrichment with rate limiting and graceful failure."""
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3/ip_addresses"
_last_call_time: float = 0.0


def _rate_limit(calls_per_min: int) -> None:
    """Block until enough time has passed to respect the per-minute rate limit.

    Uses a module-level timestamp so rate limiting is shared across all calls
    in a single process. Calculates minimum seconds per call from calls_per_min.

    Args:
        calls_per_min: Maximum API calls allowed per minute.
    """
    global _last_call_time
    min_interval = 60.0 / calls_per_min
    elapsed = time.time() - _last_call_time
    if elapsed < min_interval:
        wait = min_interval - elapsed
        logger.debug(f"VT rate limit: sleeping {wait:.2f}s")
        time.sleep(wait)
    _last_call_time = time.time()


def lookup_ip(
    ip: str,
    api_key: str,
    timeout: int = 10,
    rate_limit_per_min: int = 4,
) -> Optional[dict]:
    """Query VirusTotal for reputation data on the given IP address.

    Applies rate limiting before every call. On HTTP 429, waits 60 seconds
    and retries once. On 404, returns a zero-ratio result (IP not found is
    not an error — it means no detections). On all other errors, logs a
    warning and returns None — never raises.

    Args:
        ip: IPv4 address to look up.
        api_key: VirusTotal API key (read from environment by the caller).
        timeout: HTTP request timeout in seconds.
        rate_limit_per_min: Calls per minute to enforce (4 for free tier).

    Returns:
        Dict with keys: vt_malicious_ratio (float), vt_country (str),
        vt_as_owner (str), vt_reputation (int). Returns None on API failure.
    """
    _rate_limit(rate_limit_per_min)
    url = f"{VT_API_BASE}/{ip}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        logger.warning(f"VT request failed for {ip}: {e}")
        return None

    if resp.status_code == 404:
        # IP not found in VT database — not an error, return zero detections
        logger.debug(f"VT: IP not found ({ip}), returning zero ratio")
        return {
            "vt_malicious_ratio": 0.0,
            "vt_country": None,
            "vt_as_owner": None,
            "vt_reputation": 0,
        }

    if resp.status_code == 429:
        logger.warning(f"VT rate limit hit for {ip}, retrying after 60s")
        time.sleep(60)
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            logger.warning(f"VT retry failed for {ip}: {e}")
            return None
        if resp.status_code != 200:
            logger.warning(f"VT retry returned {resp.status_code} for {ip}")
            return None

    if resp.status_code != 200:
        logger.warning(f"VT returned HTTP {resp.status_code} for {ip}")
        return None

    try:
        return _parse_vt_response(resp.json())
    except Exception as e:
        logger.warning(f"VT response parse error for {ip}: {e}")
        return None


def _parse_vt_response(response: dict) -> dict:
    """Extract normalised fields from a raw VirusTotal API v3 IP response.

    Computes malicious_ratio = malicious / total_engines, handling zero
    division safely (returns 0.0 when total is zero).

    Args:
        response: Raw JSON response dict from the VirusTotal v3 IP endpoint.

    Returns:
        Dict with keys: vt_malicious_ratio (float), vt_country (str or None),
        vt_as_owner (str or None), vt_reputation (int).
    """
    attrs = response.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    ratio = malicious / total if total > 0 else 0.0

    return {
        "vt_malicious_ratio": round(ratio, 4),
        "vt_country": attrs.get("country"),
        "vt_as_owner": attrs.get("as_owner"),
        "vt_reputation": attrs.get("reputation", 0),
    }
