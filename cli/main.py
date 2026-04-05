import argparse
import logging
import os
import sys
from collections import Counter
from pathlib import Path

import yaml

from enrichment.cache import EnrichmentCache
from ingestion.csv_ingestor import ingest_csv
from ingestion.json_ingestor import ingest_json
from scoring.scorer import score_alert, TriageResult
from store.alert_db import AlertDB


def setup_logging(level: str) -> None:
    """Configure root logging with a consistent format.

    Args:
        level: Logging level string (e.g. 'INFO', 'DEBUG').
    """
    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
    )


def load_config(config_path: str) -> dict:
    """Load and return the YAML config file as a dict.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Parsed config dict.
    """
    path = Path(config_path)
    if not path.exists():
        print(f"[ERROR] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def detect_format(filepath: str) -> str:
    """Return 'csv' or 'json' based on the file extension.

    Args:
        filepath: Path to the alert input file.

    Returns:
        'csv' or 'json'; defaults to 'csv' for unrecognised extensions.
    """
    suffix = Path(filepath).suffix.lower()
    if suffix == ".csv":
        return "csv"
    elif suffix == ".json":
        return "json"
    return "csv"


def _get_api_key(env_var: str, service_name: str, dry_run: bool) -> str:
    """Read an API key from the environment. Exit with a clear error if missing and not dry-run.

    Args:
        env_var: Name of the environment variable to read.
        service_name: Human-readable service name for the error message.
        dry_run: When True, missing keys are allowed — return empty string.

    Returns:
        The API key string, or "" in dry-run mode.
    """
    key = os.environ.get(env_var, "")
    if not key and not dry_run:
        print(
            f"[ERROR] {service_name} API key not set. "
            f"Export {env_var} or run with --dry-run.",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


def _enrich_alert(
    alert,
    vt_key: str,
    shodan_key: str,
    config: dict,
    cache,
    dry_run: bool,
) -> str:
    """Run VT and Shodan enrichment on a single alert, updating it in-place.

    In dry-run mode, skips all API calls and sets enrichment_source to 'dry_run'.
    On any enrichment failure, the alert is left with None enrichment fields
    rather than raising — the pipeline always continues.

    Args:
        alert: Alert dataclass instance to enrich in-place.
        vt_key: VirusTotal API key string (may be empty in dry-run).
        shodan_key: Shodan API key string (may be empty in dry-run).
        config: Full config dict (for rate limits and timeouts).
        cache: EnrichmentCache instance (or _NoopCache) to check before API calls.
        dry_run: When True, skip all API calls.

    Returns:
        Enrichment source string: 'dry_run', 'cache', or 'live'.
    """
    logger = logging.getLogger("cli.enrich")

    if dry_run:
        alert.enrichment_source = "dry_run"
        return "dry_run"

    ip = alert.source_ip
    enrichment_source = "live"
    vt_cfg = config.get("enrichment", {}).get("virustotal", {})
    shodan_cfg = config.get("enrichment", {}).get("shodan", {})
    vt_data = None
    shodan_data = None

    if vt_cfg.get("enabled", True) and vt_key:
        cached = cache.get("vt", ip)
        if cached is not None:
            vt_data = cached
            enrichment_source = "cache"
            logger.debug(f"VT cache hit: {ip}")
        else:
            from enrichment.virustotal import lookup_ip as vt_lookup
            vt_data = vt_lookup(
                ip,
                api_key=vt_key,
                timeout=vt_cfg.get("timeout_seconds", 10),
                rate_limit_per_min=vt_cfg.get("rate_limit_per_min", 4),
            )
            if vt_data:
                cache.set("vt", ip, vt_data)

        if vt_data:
            alert.vt_malicious_ratio = vt_data.get("vt_malicious_ratio")
            alert.vt_country = vt_data.get("vt_country")
            alert.vt_as_owner = vt_data.get("vt_as_owner")

    if shodan_cfg.get("enabled", True) and shodan_key:
        cached = cache.get("shodan", ip)
        if cached is not None:
            shodan_data = cached
            enrichment_source = "cache"
            logger.debug(f"Shodan cache hit: {ip}")
        else:
            from enrichment.shodan_lookup import lookup_ip as shodan_lookup
            shodan_data = shodan_lookup(
                ip,
                api_key=shodan_key,
                timeout=shodan_cfg.get("timeout_seconds", 10),
            )
            if shodan_data:
                cache.set("shodan", ip, shodan_data)

        if shodan_data:
            alert.shodan_open_ports = shodan_data.get("shodan_open_ports", [])
            alert.shodan_vulns = shodan_data.get("shodan_vulns", [])
            alert.shodan_org = shodan_data.get("shodan_org")
            alert.shodan_exposure_score = shodan_data.get("shodan_exposure_score")

    alert.enrichment_source = enrichment_source
    return enrichment_source


class _NoopCache:
    """Drop-in replacement for EnrichmentCache that always misses — used with --no-cache."""

    def get(self, module: str, ip: str):
        """Always return None to force a live API call.

        Args:
            module: Cache module name (ignored).
            ip: IP address (ignored).

        Returns:
            None unconditionally.
        """
        return None

    def set(self, module: str, ip: str, data: dict) -> None:
        """Discard the data — no-op when caching is disabled.

        Args:
            module: Cache module name (ignored).
            ip: IP address (ignored).
            data: Result dict (discarded).
        """
        pass


def main() -> None:
    """Entry point for the SOC Alert Triage Engine CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m cli.main",
        description="SOC Alert Triage Engine — ingest, enrich, score, and report on security alerts",
    )
    parser.add_argument("--input", metavar="FILE", help="Path to CSV or JSON alert input file")
    parser.add_argument(
        "--config",
        metavar="FILE",
        default="config/config.yaml",
        help="Config file path",
    )
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["csv", "json", "auto"],
        default="auto",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip API calls, use zeros for enrichment",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable enrichment cache; always call APIs directly",
    )
    parser.add_argument("--output-dir", metavar="DIR", default=None)

    args = parser.parse_args()

    if not args.input:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    setup_logging(config.get("pipeline", {}).get("log_level", "INFO"))
    logger = logging.getLogger("cli.main")

    db_path = config.get("pipeline", {}).get("db_path", "output/triage.db")

    # Ingest
    fmt = args.format
    if fmt == "auto":
        fmt = detect_format(args.input)
    alerts = ingest_csv(args.input) if fmt == "csv" else ingest_json(args.input)

    if not alerts:
        logger.error("No alerts ingested — check input file and format")
        sys.exit(1)

    logger.info(f"Ingested {len(alerts)} alerts")

    # API keys — checked before any cache or enrichment work is done
    vt_key = _get_api_key(
        config.get("enrichment", {}).get("virustotal", {}).get("api_key_env", "VT_API_KEY"),
        "VirusTotal",
        args.dry_run,
    )
    shodan_key = _get_api_key(
        config.get("enrichment", {}).get("shodan", {}).get("api_key_env", "SHODAN_API_KEY"),
        "Shodan",
        args.dry_run,
    )

    # Cache setup
    cache_cfg = config.get("enrichment", {}).get("cache", {})
    if args.no_cache:
        cache = _NoopCache()
    else:
        cache = EnrichmentCache(
            cache_dir=cache_cfg.get("cache_dir", "output/.cache"),
            ttl_seconds=cache_cfg.get("ttl_seconds", 3600),
        )

    # Enrich — separate loop from scoring
    for alert in alerts:
        _enrich_alert(alert, vt_key, shodan_key, config, cache, args.dry_run)

    logger.info(f"Enrichment complete — {len(alerts)}/{len(alerts)} alerts processed")

    # Score — separate loop from enrichment
    scoring_cfg = config.get("scoring", {})
    weights = scoring_cfg.get("weights", {})
    severity_map = scoring_cfg.get("severity_map", {})
    confidence_thresholds = scoring_cfg.get("confidence_thresholds", {})

    results: list[TriageResult] = []
    for alert in alerts:
        result = score_alert(alert, weights, severity_map, confidence_thresholds)
        results.append(result)

    logger.info(f"Scoring complete — {len(results)} alerts scored")

    # Store
    db = AlertDB(db_path)
    run_id = db.start_run()
    for alert, result in zip(alerts, results):
        db.store_alert(run_id, alert, triage_result=result)
    db.finish_run(run_id, len(alerts))
    db.close()

    # Print summary
    label_counts = Counter(r.priority_label for r in results)
    top_n = sorted(results, key=lambda r: r.score, reverse=True)[:5]

    print("\n" + "━" * 50)
    print("  Alert Triage Engine — Run Summary")
    print("━" * 50)
    print(f"  Alerts ingested:    {len(alerts)}")
    print(f"  Alerts scored:      {len(results)}")
    print(f"  Run ID:             {run_id}")
    print()
    print("  Priority breakdown:")
    for label in ["INVESTIGATE_NOW", "INVESTIGATE_SOON", "MONITOR", "LOW_PRIORITY"]:
        print(f"    {label:<22} {label_counts.get(label, 0)}")
    print()
    print("  Top 5 alerts:")
    for i, r in enumerate(top_n, 1):
        print(f"  #{i}  [{r.priority_label:<18} {r.score:.2f}]  {r.analyst_summary[:80]}")
    print("━" * 50)


if __name__ == "__main__":
    main()
