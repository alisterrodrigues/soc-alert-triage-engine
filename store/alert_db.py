import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# run_metadata is created first so triage_results FK reference is valid
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS run_metadata (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    alerts_processed INTEGER DEFAULT 0,
    config_hash TEXT,
    scoring_weights TEXT
);

CREATE TABLE IF NOT EXISTS triage_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES run_metadata(run_id),
    alert_id TEXT NOT NULL,
    timestamp TEXT,
    source_ip TEXT,
    alert_name TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low')),
    category TEXT,
    score REAL,
    priority_label TEXT CHECK(priority_label IN ('INVESTIGATE_NOW','INVESTIGATE_SOON','MONITOR','LOW_PRIORITY')),
    confidence TEXT,
    analyst_summary TEXT,
    vt_malicious_ratio REAL,
    shodan_exposure_score REAL,
    shodan_open_ports TEXT,
    shodan_vulns TEXT,
    score_breakdown TEXT,
    raw_alert TEXT,
    enrichment_source TEXT,
    enrichment_completeness REAL,
    prior_sightings_count INTEGER,
    processed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_run_score
    ON triage_results (run_id, score DESC);

CREATE INDEX IF NOT EXISTS idx_triage_ip_ts
    ON triage_results (source_ip, timestamp);
"""


class AlertDB:
    """SQLite-backed store for alert triage results and run metadata."""

    def __init__(self, db_path: str):
        """Initialise the database, creating parent directories and schema if needed.

        Args:
            db_path: File path for the SQLite database.
        """
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create database tables and indexes if they do not already exist."""
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def start_run(self, config_hash: str = "", scoring_weights: Optional[dict] = None) -> str:
        """Create a run_metadata record and return the new run_id (UUID).

        Args:
            config_hash: Optional hash of the config file in use for this run.
            scoring_weights: Optional dict of scoring weights for reproducibility.

        Returns:
            UUID string identifying this triage run.
        """
        run_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO run_metadata (run_id, started_at, config_hash, scoring_weights) VALUES (?, ?, ?, ?)",
            (
                run_id,
                datetime.now(timezone.utc).isoformat(),
                config_hash,
                json.dumps(scoring_weights or {}),
            ),
        )
        self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, alerts_processed: int) -> None:
        """Mark a run as finished and record the alert count.

        Args:
            run_id: UUID of the run to close.
            alerts_processed: Total number of alerts ingested and stored in this run.
        """
        self._conn.execute(
            "UPDATE run_metadata SET finished_at = ?, alerts_processed = ? WHERE run_id = ?",
            (datetime.now(timezone.utc).isoformat(), alerts_processed, run_id),
        )
        self._conn.commit()

    def store_alerts_batch(self, run_id: str, alert_result_pairs: list) -> None:
        """Persist a batch of (alert, triage_result) pairs inside a single transaction.

        Significantly faster than calling store_alert() per row for large datasets.

        Args:
            run_id: UUID of the current triage run.
            alert_result_pairs: List of (Alert, TriageResult) tuples.
        """
        rows = []
        for alert, triage_result in alert_result_pairs:
            score = None
            priority_label = None
            confidence = None
            analyst_summary = None
            score_breakdown = None
            enrichment_completeness = None
            prior_sightings_count = None

            if triage_result is not None:
                score = triage_result.score
                priority_label = triage_result.priority_label
                confidence = triage_result.confidence
                analyst_summary = triage_result.analyst_summary
                score_breakdown = json.dumps(triage_result.score_breakdown)
                enrichment_completeness = getattr(triage_result, "enrichment_completeness", None)
                prior_sightings_count = getattr(triage_result, "prior_sightings_count", None)

            rows.append((
                run_id,
                alert.alert_id,
                alert.timestamp,
                alert.source_ip,
                alert.alert_name,
                alert.severity,
                alert.category,
                score,
                priority_label,
                confidence,
                analyst_summary,
                alert.vt_malicious_ratio,
                alert.shodan_exposure_score,
                json.dumps(alert.shodan_open_ports),
                json.dumps(alert.shodan_vulns),
                score_breakdown,
                json.dumps(alert.__dict__),
                alert.enrichment_source,
                enrichment_completeness,
                prior_sightings_count,
                datetime.now(timezone.utc).isoformat(),
            ))

        with self._conn:
            self._conn.executemany(
                """
                INSERT INTO triage_results (
                    run_id, alert_id, timestamp, source_ip, alert_name, severity, category,
                    score, priority_label, confidence, analyst_summary,
                    vt_malicious_ratio, shodan_exposure_score,
                    shodan_open_ports, shodan_vulns, score_breakdown,
                    raw_alert, enrichment_source, enrichment_completeness,
                    prior_sightings_count, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def store_alert(self, run_id: str, alert, triage_result=None) -> None:
        """Persist a single alert and its triage result to triage_results.

        Delegates to store_alerts_batch() with a single-element list.
        triage_result may be None, in which case all scoring columns are stored as NULL.

        Args:
            run_id: UUID of the current triage run.
            alert: An Alert dataclass instance to persist.
            triage_result: Optional TriageResult; when None all scoring columns are NULL.
        """
        self.store_alerts_batch(run_id, [(alert, triage_result)])

    def get_alerts_by_run(self, run_id: str) -> list[dict]:
        """Return all triage_results rows for a given run_id as dicts.

        Args:
            run_id: UUID of the run whose alerts should be retrieved.

        Returns:
            List of row dicts ordered by score descending (NULLs last).
        """
        cursor = self._conn.execute(
            "SELECT * FROM triage_results WHERE run_id = ? ORDER BY score DESC NULLS LAST",
            (run_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_prior_sightings(self, source_ip: str, rule_id: Optional[str], lookback_days: int = 7) -> int:
        """Count prior appearances of a source IP within the lookback window.

        Queries completed triage runs for any alert from the given source IP
        in the last N days. Used by the scoring layer to detect repeat offenders.
        rule_id is accepted for API compatibility but is not currently used in
        the query — per-rule filtering is a planned future enhancement.

        Args:
            source_ip: Source IP address string to look up.
            rule_id: Reserved for future per-rule filtering. Pass None or alert.rule_id.
            lookback_days: Number of days of history to search.

        Returns:
            Integer count of prior alert rows from this source IP in the lookback window.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM triage_results WHERE source_ip = ? AND timestamp >= ?",
            (source_ip, cutoff),
        )
        return cursor.fetchone()[0]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()
