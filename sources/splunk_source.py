"""Splunk alert source — fetches recent alerts via the Splunk REST API."""
import hashlib
import logging
import os

import requests

from sources.base import AlertSource

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SplunkSource(AlertSource):
    """Fetch alerts from a Splunk instance using the saved search REST API.

    Authentication: username/password via Basic Auth.
    The Splunk search query, host, port, and credentials are passed via config.
    All field mapping (Splunk field names → Alert schema field names) is done here.

    Required config keys (under sources.splunk in config.yaml):
        host: Splunk server hostname
        port: Splunk REST API port (default 8089)
        username_env: environment variable name holding Splunk username
        password_env: environment variable name holding Splunk password
        search: Splunk SPL query string (e.g. "search index=alerts earliest=-1h")
        verify_ssl: bool (default false for self-signed certs in lab environments)
        timeout_seconds: int (default 30)

    Field mapping (Splunk → Alert schema):
        src_ip or src → source_ip
        dest_ip or dest → destination_ip
        signature or alert_name → alert_name
        severity or urgency → severity (informational→low, medium→medium, high→high, critical→critical)
        category or type → category
        rule_name or savedsearch_name → rule_id
        _time → timestamp (ISO 8601)
        _raw → raw_payload
    """

    def __init__(self, config: dict) -> None:
        self._host = config.get("host", "localhost")
        self._port = int(config.get("port", 8089))
        self._search = config.get("search", "search index=alerts earliest=-1h | head 500")
        self._verify_ssl = bool(config.get("verify_ssl", False))
        self._timeout = int(config.get("timeout_seconds", 30))

        username_env = config.get("username_env", "SPLUNK_USERNAME")
        password_env = config.get("password_env", "SPLUNK_PASSWORD")
        self._username = os.environ.get(username_env, "")
        self._password = os.environ.get(password_env, "")

    def fetch(self) -> list:
        """Run the configured SPL query and return raw field dicts.

        Returns a list of dicts that must be normalized via _validate_and_build()
        before use. Uses Splunk's oneshot search endpoint so no async job polling
        is needed. Returns empty list on any connection, auth, or parse failure.
        Logs error with enough detail to diagnose (URL, status code) without
        logging credential values.
        """
        url = f"https://{self._host}:{self._port}/services/search/jobs"
        try:
            response = requests.post(
                url,
                data={
                    "search": self._search,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 500,
                },
                auth=(self._username, self._password),
                verify=self._verify_ssl,
                timeout=self._timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            logger.error("Splunk connection failed — url=%s error=%s", url, exc)
            return []
        except requests.exceptions.Timeout:
            logger.error("Splunk request timed out — url=%s timeout=%ss", url, self._timeout)
            return []
        except requests.exceptions.RequestException as exc:
            logger.error("Splunk request error — url=%s error=%s", url, exc)
            return []

        if response.status_code == 401:
            logger.error(
                "Splunk authentication failed — url=%s status=401 "
                "(check %s / %s env vars)",
                url,
                "SPLUNK_USERNAME",
                "SPLUNK_PASSWORD",
            )
            return []

        if not response.ok:
            logger.error(
                "Splunk returned non-200 — url=%s status=%d body=%s",
                url,
                response.status_code,
                response.text[:200],
            )
            return []

        try:
            payload = response.json()
        except ValueError as exc:
            logger.error("Splunk response is not valid JSON — url=%s error=%s", url, exc)
            return []

        raw_results = payload.get("results", [])
        if not isinstance(raw_results, list):
            logger.error("Splunk results field is not a list — url=%s", url)
            return []

        mapped = [self._map_row(hit) for hit in raw_results]
        logger.info("Splunk: fetched %d results from %s", len(mapped), url)
        return mapped

    def _map_row(self, hit: dict) -> dict:
        """Translate a Splunk result dict into an Alert schema dict."""
        raw_severity = (hit.get("severity") or hit.get("urgency") or "low").lower()
        severity = _SEVERITY_MAP.get(raw_severity, "low")

        source_ip = hit.get("src_ip") or hit.get("src", "")
        timestamp = hit.get("_time", "")
        alert_name = hit.get("signature") or hit.get("alert_name", "")

        # Derive a stable alert_id from the combination of time + source + name
        fingerprint = f"{timestamp}:{source_ip}:{alert_name}"
        alert_id = hashlib.md5(fingerprint.encode()).hexdigest()[:16]

        return {
            "alert_id": hit.get("alert_id") or alert_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": hit.get("dest_ip") or hit.get("dest"),
            "alert_name": alert_name,
            "severity": severity,
            "category": hit.get("category") or hit.get("type", "other"),
            "rule_id": hit.get("rule_name") or hit.get("savedsearch_name"),
            "raw_payload": hit.get("_raw"),
        }

    def source_name(self) -> str:
        return f"splunk:{self._host}"
