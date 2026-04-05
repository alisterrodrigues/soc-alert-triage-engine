"""Tests for enrichment modules — all API calls are mocked, no real network traffic."""
import time
from unittest.mock import MagicMock, patch

import pytest

from enrichment.cache import EnrichmentCache


# ─────────────────────────── Cache tests ───────────────────────────


def test_cache_miss_returns_none(tmp_path):
    """A fresh cache must return None for any key that has never been set."""
    cache = EnrichmentCache(cache_dir=str(tmp_path), ttl_seconds=3600)
    assert cache.get("vt", "1.2.3.4") is None


def test_cache_set_then_get_returns_data(tmp_path):
    """Data written via set() must be returned identically by get()."""
    cache = EnrichmentCache(cache_dir=str(tmp_path), ttl_seconds=3600)
    data = {"vt_malicious_ratio": 0.5}
    cache.set("vt", "1.2.3.4", data)
    result = cache.get("vt", "1.2.3.4")
    assert result == data


def test_cache_expired_entry_returns_none(tmp_path):
    """An entry past its TTL must be treated as a miss and return None."""
    cache = EnrichmentCache(cache_dir=str(tmp_path), ttl_seconds=1)
    cache.set("vt", "1.2.3.4", {"vt_malicious_ratio": 0.5})
    time.sleep(2)
    assert cache.get("vt", "1.2.3.4") is None


def test_cache_different_modules_do_not_collide(tmp_path):
    """Entries for the same IP under different modules must be stored independently."""
    cache = EnrichmentCache(cache_dir=str(tmp_path), ttl_seconds=3600)
    cache.set("vt", "1.2.3.4", {"source": "vt"})
    cache.set("shodan", "1.2.3.4", {"source": "shodan"})
    assert cache.get("vt", "1.2.3.4")["source"] == "vt"
    assert cache.get("shodan", "1.2.3.4")["source"] == "shodan"


def test_cache_creates_directory_if_missing(tmp_path):
    """EnrichmentCache must create nested cache directories automatically."""
    cache_dir = str(tmp_path / "nested" / "cache")
    cache = EnrichmentCache(cache_dir=cache_dir, ttl_seconds=3600)
    cache.set("vt", "1.2.3.4", {"x": 1})
    assert cache.get("vt", "1.2.3.4") == {"x": 1}


# ─────────────────────────── VT tests ───────────────────────────


def _make_vt_response(
    malicious=5,
    suspicious=2,
    harmless=60,
    undetected=5,
    country="DE",
    as_owner="SomeISP",
):
    """Build a minimal VirusTotal API v3 response dict."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": -10,
                "country": country,
                "as_owner": as_owner,
            }
        }
    }


@patch("enrichment.virustotal.requests.get")
def test_vt_lookup_returns_ratio_on_200(mock_get):
    """A 200 response must produce a correctly computed malicious ratio."""
    from enrichment.virustotal import lookup_ip

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _make_vt_response(
        malicious=14, suspicious=0, harmless=58, undetected=0
    )
    mock_get.return_value = mock_resp

    result = lookup_ip("185.220.101.47", api_key="FAKE", rate_limit_per_min=999)
    assert result is not None
    # 14 / (14 + 0 + 58 + 0) = 14/72 ≈ 0.1944
    assert abs(result["vt_malicious_ratio"] - (14 / 72)) < 0.001


@patch("enrichment.virustotal.requests.get")
def test_vt_lookup_404_returns_zero_ratio(mock_get):
    """A 404 response must return a zero-ratio dict, not None."""
    from enrichment.virustotal import lookup_ip

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    result = lookup_ip("10.0.0.1", api_key="FAKE", rate_limit_per_min=999)
    assert result is not None
    assert result["vt_malicious_ratio"] == 0.0


@patch("enrichment.virustotal.requests.get")
def test_vt_lookup_429_retries_once_then_returns_none(mock_get):
    """On 429 followed by a non-200 retry, lookup_ip must return None."""
    from enrichment.virustotal import lookup_ip

    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429
    mock_resp_500 = MagicMock()
    mock_resp_500.status_code = 500
    # First call → 429, retry → 500
    mock_get.side_effect = [mock_resp_429, mock_resp_500]

    with patch("enrichment.virustotal.time.sleep"):  # Don't actually sleep in tests
        result = lookup_ip("1.2.3.4", api_key="FAKE", rate_limit_per_min=999)
    assert result is None


@patch("enrichment.virustotal.requests.get")
def test_vt_network_error_returns_none(mock_get):
    """A requests.RequestException must cause lookup_ip to return None, not raise."""
    import requests as req_lib
    from enrichment.virustotal import lookup_ip

    mock_get.side_effect = req_lib.RequestException("network down")

    result = lookup_ip("1.2.3.4", api_key="FAKE", rate_limit_per_min=999)
    assert result is None


def test_vt_zero_total_engines_no_division_error():
    """When all engine counts are zero, malicious_ratio must be 0.0 (no ZeroDivisionError)."""
    from enrichment.virustotal import _parse_vt_response

    response = _make_vt_response(malicious=0, suspicious=0, harmless=0, undetected=0)
    result = _parse_vt_response(response)
    assert result["vt_malicious_ratio"] == 0.0


# ─────────────────────────── Shodan tests ───────────────────────────


def test_shodan_api_error_returns_none():
    """Shodan APIError (host not found, rate limit, etc.) must return None, not raise.

    shodan is imported inside lookup_ip(), so it must be injected via sys.modules
    rather than patched as a module-level attribute.
    """
    from enrichment.shodan_lookup import lookup_ip

    mock_api_instance = MagicMock()
    mock_api_instance.host.side_effect = Exception("No information available for that IP")

    mock_shodan_mod = MagicMock()
    mock_shodan_mod.Shodan.return_value = mock_api_instance

    with patch.dict("sys.modules", {"shodan": mock_shodan_mod}):
        result = lookup_ip("10.0.0.1", api_key="FAKE")

    assert result is None


def test_shodan_exposure_score_with_ports_and_vulns():
    """Exposure score formula must correctly sum base and bonus components."""
    from enrichment.shodan_lookup import _parse_shodan_response

    host = {
        "ports": [22, 80, 443, 8080, 3389, 5900, 21, 23, 25, 1433],  # 10 ports → base 0.50
        "vulns": {"CVE-2021-44228": {}, "CVE-2022-0001": {}},          # 2 vulns → bonus 0.20
        "org": "Evil Corp",
        "isp": "Bad ISP",
        "country_code": "RU",
    }
    result = _parse_shodan_response(host)
    # base = min(10 * 0.05, 0.50) = 0.50, bonus = min(2 * 0.10, 0.50) = 0.20
    assert abs(result["shodan_exposure_score"] - 0.70) < 0.001
    assert "CVE-2021-44228" in result["shodan_vulns"]
    assert 22 in result["shodan_open_ports"]


def test_shodan_no_ports_no_vulns_exposure_zero():
    """A host with no ports and no vulns must have exposure_score of 0.0."""
    from enrichment.shodan_lookup import _parse_shodan_response

    host = {"ports": [], "vulns": {}, "org": None, "isp": None, "country_code": None}
    result = _parse_shodan_response(host)
    assert result["shodan_exposure_score"] == 0.0


def test_shodan_exposure_score_capped_at_1():
    """Exposure score must never exceed 1.0 regardless of port or vuln counts."""
    from enrichment.shodan_lookup import _parse_shodan_response

    host = {
        "ports": list(range(100)),                                    # 100 ports → base capped at 0.50
        "vulns": {f"CVE-2022-{i:04d}": {} for i in range(50)},       # 50 vulns → bonus capped at 0.50
        "org": "Test",
        "isp": "Test",
        "country_code": "US",
    }
    result = _parse_shodan_response(host)
    assert result["shodan_exposure_score"] == 1.0


# ─────────────────────────── Cache integration with VT ───────────────────────────


@patch("enrichment.virustotal.requests.get")
def test_cache_hit_prevents_api_call(mock_get, tmp_path):
    """When cache has a valid entry, the VT API must not be called."""
    cache = EnrichmentCache(cache_dir=str(tmp_path), ttl_seconds=3600)
    cache.set(
        "vt",
        "1.2.3.4",
        {
            "vt_malicious_ratio": 0.99,
            "vt_country": "US",
            "vt_as_owner": "X",
            "vt_reputation": 0,
        },
    )

    cached = cache.get("vt", "1.2.3.4")
    assert cached is not None
    assert cached["vt_malicious_ratio"] == 0.99
    # The key assertion: mock_get was never called because we used cache directly
    mock_get.assert_not_called()
