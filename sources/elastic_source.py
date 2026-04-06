"""Elasticsearch alert source — fetches alerts from an Elastic SIEM/Security index."""
import logging
import os
from datetime import datetime, timezone, timedelta

from sources.base import AlertSource

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _nested_get(d: dict, path: str, default=None):
    """Retrieve a value from a nested dict using dot-separated key path.

    Args:
        d: The dict to traverse.
        path: Dot-separated key path (e.g. "source.ip").
        default: Value to return when any key in the path is missing.

    Returns:
        The value at the path, or default if any segment is absent or not a dict.
    """
    val = d
    for key in path.split("."):
        if not isinstance(val, dict):
            return default
        val = val.get(key)
        if val is None:
            return default
    return val


class ElasticSource(AlertSource):
    """Fetch alerts from Elasticsearch using the Python elasticsearch client.

    Uses API key authentication (preferred) or username/password.
    Queries the configured index with a date-range filter on @timestamp.

    Required config keys (under sources.elastic in config.yaml):
        host: Elasticsearch host URL (e.g. https://localhost:9200)
        api_key_env: environment variable holding the Elastic API key (preferred)
        username_env: fallback if api_key_env is not set
        password_env: fallback if api_key_env is not set
        index: index pattern to query (e.g. ".alerts-security.alerts-default")
        lookback_minutes: how many minutes back to query (default 60)
        max_alerts: maximum alerts to fetch per run (default 500)
        verify_ssl: bool (default false for lab environments)

    Field mapping (ECS → Alert schema):
        source.ip → source_ip
        destination.ip → destination_ip
        kibana.alert.rule.name or rule.name → alert_name
        kibana.alert.severity or event.severity → severity
        event.category[0] → category
        kibana.alert.rule.uuid → rule_id
        @timestamp → timestamp
        event.original → raw_payload
        kibana.alert.risk_score → (used as a pre-score hint, not replacing our model)
    """

    def __init__(self, config: dict) -> None:
        self._host = config.get("host", "https://localhost:9200")
        self._index = config.get("index", ".alerts-security.alerts-default")
        self._lookback_minutes = int(config.get("lookback_minutes", 60))
        self._max_alerts = int(config.get("max_alerts", 500))
        self._verify_ssl = bool(config.get("verify_ssl", False))

        api_key_env = config.get("api_key_env", "ELASTIC_API_KEY")
        username_env = config.get("username_env", "ELASTIC_USERNAME")
        password_env = config.get("password_env", "ELASTIC_PASSWORD")

        self._api_key = os.environ.get(api_key_env, "")
        self._username = os.environ.get(username_env, "")
        self._password = os.environ.get(password_env, "")

    def fetch(self) -> list:
        """Execute the Elasticsearch query and return raw field dicts.

        Returns a list of dicts that must be normalized via _validate_and_build()
        before use. The elasticsearch package is imported here (not at module level)
        so this tool works without it installed when not using the Elastic source.

        Returns empty list on connection failure, auth failure, or if the
        elasticsearch package is not installed.
        """
        try:
            from elasticsearch import Elasticsearch, AuthenticationException, ConnectionError as ESConnectionError
        except ImportError:
            logger.error(
                "The 'elasticsearch' package is not installed. "
                "Run: pip install 'elasticsearch>=8.0,<9'"
            )
            return []

        try:
            client_kwargs: dict = {
                "hosts": [self._host],
                "verify_certs": self._verify_ssl,
            }
            if self._api_key:
                client_kwargs["api_key"] = self._api_key
            elif self._username and self._password:
                client_kwargs["basic_auth"] = (self._username, self._password)

            es = Elasticsearch(**client_kwargs)

            now = datetime.now(timezone.utc)
            lookback = now - timedelta(minutes=self._lookback_minutes)

            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": lookback.isoformat(),
                            "lte": now.isoformat(),
                        }
                    }
                },
                "size": self._max_alerts,
            }

            response = es.search(index=self._index, body=query)
            hits = response["hits"]["hits"]

        except AuthenticationException:
            logger.error(
                "Elasticsearch authentication failed — host=%s "
                "(check ELASTIC_API_KEY / ELASTIC_USERNAME / ELASTIC_PASSWORD env vars)",
                self._host,
            )
            return []
        except ESConnectionError as exc:
            logger.error("Elasticsearch connection failed — host=%s error=%s", self._host, exc)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("Elasticsearch query error — host=%s error=%s", self._host, exc)
            return []

        mapped = [self._map_hit(hit) for hit in hits]
        logger.info("Elastic: fetched %d hits from %s/%s", len(mapped), self._host, self._index)
        return mapped

    def _map_hit(self, hit: dict) -> dict:
        """Translate an Elasticsearch hit into an Alert schema dict."""
        src = hit.get("_source", {})

        raw_severity = (
            _nested_get(src, "kibana.alert.severity")
            or _nested_get(src, "event.severity")
            or "low"
        )
        severity = _SEVERITY_MAP.get(str(raw_severity).lower(), "low")

        event_category = _nested_get(src, "event.category")
        if isinstance(event_category, list) and event_category:
            category = event_category[0]
        elif isinstance(event_category, str):
            category = event_category
        else:
            category = "other"

        alert_name = (
            _nested_get(src, "kibana.alert.rule.name")
            or _nested_get(src, "rule.name")
            or ""
        )

        return {
            "alert_id": hit.get("_id", ""),
            "timestamp": src.get("@timestamp", ""),
            "source_ip": _nested_get(src, "source.ip", ""),
            "destination_ip": _nested_get(src, "destination.ip"),
            "alert_name": alert_name,
            "severity": severity,
            "category": category,
            "rule_id": _nested_get(src, "kibana.alert.rule.uuid"),
            "raw_payload": _nested_get(src, "event.original"),
        }

    def source_name(self) -> str:
        return f"elastic:{self._host}"
