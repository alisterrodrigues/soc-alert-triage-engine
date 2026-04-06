# Architecture — SOC Alert Triage Engine

This document describes the module structure, data flow, and design decisions behind the triage engine.

---

## Overview

The engine is a multi-stage Python CLI pipeline. Each stage has a single responsibility and passes its output to the next via well-defined data structures. No stage reaches into another's internals.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        INPUT SOURCES                           │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │ CSV / JSON │  │   Splunk    │  │  Elasticsearch  │  │
│  └─────┬─────┘  └─────┬─────┘  └────────┬────────┘  │
└────────────┤────────────┤─────────────────┬─────────────────────────┘
                       │
            ┌─────────┴─────────┐
            │   INGESTION / NORM   │
            │ ingestion/__init__.py│  ← Alert dataclass
            │ csv_ingestor.py      │     _validate_and_build()
            │ json_ingestor.py     │     _opt_str() null guard
            └─────────┬─────────┘
                       │  List[Alert]
            ┌─────────┴─────────┐
            │     ENRICHMENT        │
            │ enrichment/          │  ← VT malicious ratio
            │   virustotal.py      │     Shodan open ports + CVEs
            │   shodan_lookup.py   │     File-based JSON cache
            │   cache.py           │     Private IP short-circuit
            └─────────┬─────────┘
                       │  Alert (enriched)
            ┌─────────┴─────────┐
            │    MITRE TAGGING      │
            │ correlation/         │  ← category + rule_id →
            │   tagger.py         │     tactic + technique
            │   mitre_mappings.yaml│     inline YAML lookup
            └─────────┬─────────┘
                       │  Alert (tagged)
            ┌─────────┴─────────┐
            │      SCORING          │
            │ scoring/scorer.py    │  ← 6-factor weighted model
            │                      │     Renormalization for dry-run
            │                      │     Weighted Shodan exposure
            │                      │     Exponential recency decay
            └─────────┬─────────┘
                       │  List[TriageResult]
            ┌─────────┴─────────┐
            │    CORRELATION        │
            │ correlation/         │  ← Time-window grouping
            │   engine.py         │     Kill chain detection
            │                      │     CorrelatedIncident output
            └────┬─────────────┬───┘
                 │             │
     ┌─────────┴─────┐  ┌────┴─────────┐
     │  SQLite STORE  │  │  HTML REPORT   │
     │ store/         │  │ reporting/    │
     │   alert_db.py  │  │ html_report.py│
     └───────────────┘  └───────────────┘
```

---

## Module Reference

### `ingestion/`

Normalizes raw alert data from any source into the canonical `Alert` dataclass.

- **`__init__.py`** — Defines `Alert` and `_validate_and_build()`. The `Alert` dataclass is the single canonical representation used by every downstream module. `_opt_str()` prevents Python `None` values from becoming the literal string `"None"` when ingesting JSON null fields.
- **`csv_ingestor.py`** — Opens files with `utf-8-sig` encoding to transparently handle UTF-8 BOM headers produced by Excel and many SIEMs.
- **`json_ingestor.py`** — Expects a JSON array at the root. Single-object files return empty.

**Design decision:** Both ingestors call the same `_validate_and_build()` function. There is no field normalization logic duplicated between them. All validation (severity, category, port parsing, tag lowercasing) happens in one place.

### `sources/`

Provider abstraction for alert acquisition. Decouples the pipeline from its input mechanism.

- **`base.py`** — `AlertSource` ABC defines `fetch() -> list` and `source_name() -> str`.
- **`file_source.py`** — Wraps the existing file ingestors. The only source that returns `Alert` objects directly (ingestors already call `_validate_and_build`).
- **`splunk_source.py`** — Queries Splunk's REST jobs API using `exec_mode=oneshot`. Handles field mapping from Splunk event fields to the `Alert` schema. Credentials read from environment variables.
- **`elastic_source.py`** — Queries an Elasticsearch index with a `@timestamp` date-range filter. Supports API key auth (preferred) and username/password fallback. The `elasticsearch` package is imported inside `fetch()` so the tool works without it installed unless `--source elastic` is used.

**Design decision:** The provider interface means adding a new source (e.g. AWS Security Hub, Microsoft Sentinel) requires one new class implementing `fetch()` and a field mapping function. The scoring, enrichment, and reporting stages are untouched.

### `enrichment/`

Enriches `Alert` objects in-place with external threat intelligence.

- **`virustotal.py`** — Queries the VT IP reputation endpoint. Returns `vt_malicious_ratio` (float 0–1), `vt_country`, `vt_as_owner`. Rate-limited at module level using `_last_call_time`.
- **`shodan_lookup.py`** — Queries Shodan for open ports, known CVEs, org, and a pre-computed exposure score. The `shodan` library is imported inside `lookup_ip()` to allow graceful failure when not installed.
- **`cache.py`** — File-based JSON cache keyed by `{module}_{safe_ip}` in `output/.cache/`. TTL-checked at read time. Concurrent write safety is not guaranteed (single-process assumption).

**Design decision:** Private/reserved/non-routable IPs (including RFC1918, loopback, and link-local addresses) are short-circuited before any API call in `_enrich_alert()`. Internal IPs are enriched by correlation and asset data, not by external threat feeds.

### `correlation/`

Two responsibilities: MITRE ATT&CK tagging and time-windowed incident correlation.

- **`tagger.py`** — Maps `alert.category` and `alert.rule_id` prefix to a MITRE tactic and technique. Rule ID prefix takes priority over category when both match. Mappings live in `mitre_mappings.yaml` adjacent to the module, loaded once at import time.
- **`mitre_mappings.yaml`** — Human-editable lookup table. 7 category mappings, 16 rule ID prefix mappings.
- **`engine.py`** — Groups alerts by `source_ip` within a configurable time window (default 15 minutes). Computes a combined incident score using `peak * 0.6 + mean * 0.3 + min(count/10, 1.0) * 0.1`. Detects kill chains when the tactic chain spans two or more distinct MITRE tactic stages.

**Design decision:** Private-IP alerts are included in correlation. RFC1918 source IPs frequently represent the most significant lateral movement paths and should not be excluded from incident grouping just because external enrichment was skipped.

### `scoring/`

Computes a normalized priority score for each `Alert`.

- **`scorer.py`** — Implements the 6-factor weighted scoring model. See `docs/scoring_model.md` for full formula documentation.

**Design decision:** When enrichment is unavailable (dry-run or API failure), missing factors are excluded from the weighted sum and the remaining weights are renormalized to 1.0. A high-severity alert on a critical asset scores correctly even without VT/Shodan data — and the result is explicitly marked as low confidence so the analyst knows enrichment was missing. This is more honest than treating missing data as benign.

### `store/`

Persists all run data to SQLite.

- **`alert_db.py`** — Two tables: `run_metadata` (one row per pipeline run) and `triage_results` (one row per alert per run). Batch inserts via `executemany` inside a single transaction. Foreign key enforcement enabled. Indexes on `(run_id, score DESC)` and `(source_ip, timestamp)` for baseline queries. `get_prior_sightings()` counts prior appearances of a host+rule pair within a configurable lookback window.

**Design decision:** The DB is opened before the scoring loop (not after) so `get_prior_sightings()` can query historical data during scoring. The run record is not created until after scores are ready to store — read queries during scoring do not create orphaned run records.

### `reporting/`

Generates a self-contained HTML analyst report.

- **`html_report.py`** — All HTML, CSS, and JavaScript are inlined. No CDN dependencies. The report works fully offline. Sections: correlated incidents panel, score distribution histogram, priority summary cards, sortable/filterable alert table with MITRE tactic column, prior sightings column, and expandable score breakdowns. All user-supplied strings pass through `_esc()` before HTML insertion.

---

## Data Flow: Alert Lifecycle

```
Raw input row (dict)
  ↓ _validate_and_build()
Alert(alert_id, timestamp, source_ip, ..., enrichment_source="pending")
  ↓ _enrich_alert() [skipped if private/reserved/non-routable IP]
Alert(..., vt_malicious_ratio=0.72, shodan_open_ports=[3389,445], shodan_vulns=["CVE-2021-34527"], enrichment_source="live")
  ↓ tag_alert()
Alert(..., mitre_tactic="LATERAL_MOVEMENT", mitre_technique="T1021.001")
  ↓ score_alert(prior_sightings_count=2)
TriageResult(score=0.84, priority_label="INVESTIGATE_NOW", confidence="high", enrichment_completeness=1.0)
  ↓ correlate_alerts()
CorrelatedIncident(host="185.x.x.x", alert_count=3, kill_chain_detected=True, combined_score=0.81)
  ↓ store_alerts_batch()
SQLite row in triage_results
  ↓ render_report()
Self-contained HTML file
```

---

## Configuration

All tunables live in `config/config.yaml`. No hardcoded values in library code. Key sections:

| Section | Purpose |
|---|---|
| `pipeline` | Log level, output directory, DB path |
| `pipeline.dry_run` | Skip all API calls when true; also settable via `--dry-run` CLI flag |
| `enrichment` | VT/Shodan enable flags, API key env vars, cache TTL |
| `sources` | Splunk and Elastic connection parameters |
| `scoring.weights` | Per-factor weights (must sum to 1.0) |
| `scoring.severity_map` | Severity string → float mapping |
| `scoring.confidence_thresholds` | Score thresholds for high/medium confidence |
| `scoring.baseline_lookback_days` | Prior sightings query window |
| `correlation` | Time window in minutes, minimum alert count |
| `correlation.min_alerts_per_incident` | Minimum alerts for an incident to be returned (default: 1) |
| `reporting` | Top-N highlight count |

---

## Testing

The test suite is organized by module and uses only the Python standard library plus `pytest`. No network calls, no test databases, no mocking of external services except where testing error handling.

```
tests/
  test_ingestion.py    ← CSV/JSON parsing, null handling, BOM, tag normalization
  test_enrichment.py   ← VT/Shodan mocking, cache hit/miss, rate limiter
  test_scoring.py      ← Precision assertions, renorm invariants, Shodan model
  test_correlation.py  ← Window grouping, kill chain detection, edge cases
  test_report.py       ← HTML structure, self-containment, new sections
```

Run all tests:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## Operational Assumptions and Limitations

**Single-process:** The rate limiter, cache, and DB connection are designed for single-process execution. Running two instances simultaneously against the same cache directory or database may produce torn writes or duplicate run records.

**Enrichment is best-effort:** API failures, timeouts, and private IPs all result in `enrichment_source` values that are not `"live"`. The scoring model handles this explicitly via renormalization and confidence degradation rather than silently treating missing data as clean data.

**Recency is runtime-calculated:** Alert scores drift over time because recency uses the current wall clock. An alert scored at T=0 and re-scored at T+12h will produce a lower recency component. The DB stores the score at the time of the run, not a live recalculation.

**Prior sightings requires history:** On the first run against a fresh database, all alerts will have zero prior sightings. The baseline factor becomes meaningful after several runs have accumulated.

**Splunk/Elastic adapters are connection-tested, not production-hardened:** The adapters handle auth failures and connection errors gracefully but do not implement pagination, streaming, or checkpoint-based deduplication. For high-volume environments, implement a checkpoint file or use Splunk's `latest` parameter.
