import argparse
import logging
import sys
from pathlib import Path

import yaml

from ingestion.csv_ingestor import ingest_csv
from ingestion.json_ingestor import ingest_json
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
    parser.add_argument("--output-dir", metavar="DIR", default=None)

    args = parser.parse_args()

    if not args.input:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    setup_logging(config.get("pipeline", {}).get("log_level", "INFO"))

    logger = logging.getLogger("cli.main")

    db_path = config.get("pipeline", {}).get("db_path", "output/triage.db")

    fmt = args.format
    if fmt == "auto":
        fmt = detect_format(args.input)

    if fmt == "csv":
        alerts = ingest_csv(args.input)
    else:
        alerts = ingest_json(args.input)

    if not alerts:
        logger.error("No alerts ingested — check input file and format")
        sys.exit(1)

    logger.info(f"Ingested {len(alerts)} alerts")

    db = AlertDB(db_path)
    run_id = db.start_run()

    for alert in alerts:
        alert.enrichment_source = "dry_run" if args.dry_run else "pending"
        db.store_alert(run_id, alert)

    db.finish_run(run_id, len(alerts))
    db.close()

    print(f"\nPhase 1 ingestion complete — {len(alerts)} alerts stored (run_id: {run_id})")
    print(f"DB: {db_path}")


if __name__ == "__main__":
    main()
