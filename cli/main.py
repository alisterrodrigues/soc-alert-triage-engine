import argparse
import ipaddress
import json
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

    Exits with a clear error message for unrecognised extensions rather than
    silently defaulting to CSV.

    Args:
        filepath: Path to the alert input file.

    Returns:
        'csv' or 'json'.
    """
    suffix = Path(filepath).suffix.lower()
    if suffix == ".csv":
        return "csv"
    elif suffix == ".json":
        return "json"
    print(
        f"[ERROR] Cannot auto-detect format for '{filepath}'. "
        "Use --format csv or --format json.",
        file=sys.stderr,
    )
    sys.exit(1)


def _is_private_ip(ip: str) -> bool:
    """Return True if ip is a private, loopback, or otherwise non-routable address.

    Used to skip enrichment API calls for RFC1918 addresses that will never
    return useful VirusTotal or Shodan data.

    Args:
        ip: IP address string to test.

    Returns:
        True if the address is private/reserved; False for public IPs and
        non-IP hostnames (which are not skipped).
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


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
    Private/RFC1918 source IPs are skipped — they return no useful data from
    external APIs and waste rate-limited quota.
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
        Enrichment source string: 'dry_run', 'skipped_private', 'cache', or 'live'.
    """
    logger = logging.getLogger("cli.enrich")

    if dry_run:
        alert.enrichment_source = "dry_run"
        return "dry_run"

    ip = alert.source_ip

    if _is_private_ip(ip):
        logger.debug(f"Skipping enrichment for private IP: {ip}")
        alert.enrichment_source = "skipped_private"
        return "skipped_private"

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


def _export_results(results: list, alerts: list, fmt: str, output_dir: str) -> None:
    """Export scored alert results to CSV and/or JSON files in output_dir.

    Skips writing if results is empty. Creates output_dir if it does not exist.

    Args:
        results: List of TriageResult instances.
        alerts: List of Alert instances parallel to results.
        fmt: One of 'csv', 'json', or 'both'.
        output_dir: Directory path to write export files into.
    """
    import csv as csv_mod
    from datetime import datetime, timezone

    if not results:
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    alert_map = {a.alert_id: a for a in alerts}
    rows = []
    for r in results:
        a = alert_map.get(r.alert_id)
        rows.append({
            "alert_id": r.alert_id,
            "alert_name": a.alert_name if a else "",
            "source_ip": a.source_ip if a else "",
            "severity": a.severity if a else "",
            "category": a.category if a else "",
            "score": r.score,
            "priority_label": r.priority_label,
            "confidence": r.confidence,
            "analyst_summary": r.analyst_summary,
            "vt_malicious_ratio": a.vt_malicious_ratio if a else None,
            "shodan_exposure_score": a.shodan_exposure_score if a else None,
        })

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if fmt in ("csv", "both"):
        csv_path = out / f"triage_results_{ts}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv_mod.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Exported CSV: {csv_path}")

    if fmt in ("json", "both"):
        json_path = out / f"triage_results_{ts}.json"
        json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"  Exported JSON: {json_path}")


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
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument(
        "--export",
        metavar="FORMAT",
        choices=["csv", "json", "both"],
        help="Export scored alerts to file",
    )

    args = parser.parse_args()

    if not args.input:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    setup_logging(config.get("pipeline", {}).get("log_level", "INFO"))
    logger = logging.getLogger("cli.main")

    db_path = config.get("pipeline", {}).get("db_path", "output/triage.db")
    output_dir = args.output_dir or config.get("pipeline", {}).get("output_dir", "output/")

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

    # Tag with MITRE ATT&CK
    from correlation.tagger import tag_alert
    for alert in alerts:
        tag_alert(alert)
    logger.info("MITRE ATT&CK tagging complete")

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

    # Correlate
    correlation_cfg = config.get("correlation", {})
    window_min = correlation_cfg.get("window_minutes", 15)
    from correlation.engine import correlate_alerts
    incidents = correlate_alerts(alerts, results, window_minutes=window_min)
    logger.info(f"Correlation complete — {len(incidents)} incidents identified from {len(alerts)} alerts")

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
    print("  Correlated incidents:")
    print(f"    Total incidents:       {len(incidents)}")
    kill_chain_count = sum(1 for i in incidents if i.kill_chain_detected)
    print(f"    Kill chain detected:   {kill_chain_count}")
    if incidents:
        top_incident = incidents[0]
        print(f"    Top incident score:    {top_incident.combined_score:.2f} ({top_incident.alert_count} alerts, {top_incident.host})")
    print()
    print("  Top 5 alerts:")
    for i, r in enumerate(top_n, 1):
        print(f"  #{i}  [{r.priority_label:<18} {r.score:.2f}]  {r.analyst_summary[:80]}")
    print("━" * 50)

    # HTML report
    if args.report:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = str(Path(output_dir) / f"triage_report_{ts}.html")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        from reporting.html_report import render_report
        rendered = render_report(
            results=results,
            alerts=alerts,
            run_id=run_id,
            config=config,
            output_path=report_path,
            incidents=incidents,
        )
        if rendered:
            print(f"\n  Report: {rendered}")

    # Export
    if args.export:
        _export_results(results, alerts, args.export, output_dir)


if __name__ == "__main__":
    main()
