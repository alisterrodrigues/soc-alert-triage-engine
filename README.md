# SOC Alert Triage Engine

A production-grade Python CLI that ingests security alerts from any source, enriches them with VirusTotal and Shodan threat intelligence, scores priority using a 6-factor weighted model, detects correlated incidents and kill chains, and generates a self-contained HTML analyst report.

---

## What it does

Security operations centers deal with alert fatigue. A typical SIEM generates hundreds of alerts per shift, most of which are noise. The question an analyst asks every time is: **which of these actually needs my attention right now?**

This tool answers that question systematically. It pulls alerts from a file export, Splunk, or Elasticsearch, enriches each source IP against VirusTotal and Shodan, scores priority using a configurable weighted model, groups related alerts into time-windowed incidents, and flags multi-stage kill chains. The output is a scored, sorted, filterable analyst report.

```
$ python -m cli.main --input alerts.csv --config config/config.yaml --dry-run --report

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Alert Triage Engine — Run Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Alerts ingested:    40
  Alerts scored:      40
  Run ID:             a3f1c2d4-...

  Priority breakdown:
    INVESTIGATE_NOW        3
    INVESTIGATE_SOON       7
    MONITOR               18
    LOW_PRIORITY          12

  Correlated incidents:
    Total incidents:       11
    Kill chain detected:   2
    Top incident score:    0.84 (4 alerts, 185.220.101.47)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Screenshots

### Terminal output — dry-run
![Terminal dry-run output showing alert triage summary](docs/screenshots/screenshot_terminal_dryrun.png)

### Terminal output — live API run
![Terminal live output showing INVESTIGATE_NOW alerts](docs/screenshots/screenshot_terminal_live.png)

### HTML report — correlated incidents and priority overview
![HTML report showing incident panel and priority summary cards](docs/screenshots/screenshot_report_overview.png)

### HTML report — alert table with ATT&CK tags and score breakdowns
![HTML report showing sortable alert table with MITRE tactic column](docs/screenshots/screenshot_report_breakdown.png)

---

## Pipeline

```
Input source → Ingestion → Enrichment → MITRE Tagging → Scoring → Correlation → Store → Report
```

| Stage | What happens |
|---|---|
| **Ingestion** | CSV, JSON, Splunk REST API, or Elasticsearch query → normalized `Alert` objects |
| **Enrichment** | VirusTotal IP reputation + Shodan port/CVE lookup per public source IP. File-based cache with configurable TTL. Private IPs short-circuited. |
| **MITRE Tagging** | Each alert mapped to a MITRE ATT&CK tactic and technique via category + rule ID prefix lookup |
| **Scoring** | 6-factor weighted model. Weights renormalize when enrichment is unavailable. |
| **Correlation** | Alerts grouped by source IP within a 15-minute window. Kill chain detection across MITRE tactic stages. |
| **Store** | All results persisted to SQLite with full score breakdown, enrichment fields, and run metadata |
| **Report** | Self-contained HTML — no CDN, works offline. Filterable table, score distribution histogram, correlated incidents panel. |

---

## Quick Start

**Requirements:** Python 3.11+

```bash
# Clone and set up
git clone https://github.com/alisterrodrigues/soc-alert-triage-engine.git
cd soc-alert-triage-engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Dry-run against sample data (no API keys needed)
python -m cli.main \
  --input sample_data/alerts_sample.csv \
  --config config/config.yaml \
  --dry-run

# Generate HTML report
python -m cli.main \
  --input sample_data/alerts_sample.csv \
  --config config/config.yaml \
  --dry-run \
  --report

# Live enrichment run (requires API keys)
export VT_API_KEY=your_virustotal_key
export SHODAN_API_KEY=your_shodan_key
python -m cli.main \
  --input sample_data/alerts_sample.csv \
  --config config/config.yaml \
  --report
```

### Splunk source

```bash
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your_password
python -m cli.main \
  --source splunk \
  --config config/config.yaml \
  --report
```

### Elasticsearch source

```bash
export ELASTIC_API_KEY=your_api_key
python -m cli.main \
  --source elastic \
  --config config/config.yaml \
  --report
```

---

## Scoring Model

Each alert receives a score in `[0.0, 1.0]` computed as a weighted sum of six factors:

| Factor | Default weight | Description |
|---|---|---|
| Severity | 0.25 | `critical`=1.0, `high`=0.75, `medium`=0.45, `low`=0.20 |
| VT malicious ratio | 0.20 | Fraction of VirusTotal engines flagging the source IP |
| Shodan exposure | 0.15 | Weighted port score + CVE count (RDP/SMB score higher than HTTP) |
| Asset criticality | 0.15 | `dc`/`server`=1.0, `cloud`=0.5, `workstation`/other=0.2 |
| Recency | 0.15 | Exponential decay with 6-hour half-life, floor at 0.10 |
| Prior sightings | 0.10 | `1 - 0.7^n` where n = prior appearances in last 7 days |

**Dry-run behavior:** When VT and Shodan data are unavailable, the model renormalizes the remaining weights to 1.0 rather than treating missing enrichment as zero threat signal. A `critical`-severity alert on a domain controller will still score high in dry-run — and the result is explicitly marked `confidence: low` so the analyst knows enrichment was absent. See [docs/scoring_model.md](docs/scoring_model.md) for the full formula.

Scores map to priority labels:

| Score | Label |
|---|---|
| ≥ 0.80 | `INVESTIGATE_NOW` |
| ≥ 0.55 | `INVESTIGATE_SOON` |
| ≥ 0.30 | `MONITOR` |
| < 0.30 | `LOW_PRIORITY` |

---

## Incident Correlation

Alerts sharing a source IP within a configurable time window (default: 15 minutes) are grouped into a `CorrelatedIncident`. The combined incident score is:

```
combined = peak_score * 0.6 + mean_score * 0.3 + min(alert_count / 10, 1.0) * 0.1
```

Kill chain detection fires when the tactic chain spans two or more distinct MITRE ATT&CK stages (e.g. `RECONNAISSANCE → LATERAL_MOVEMENT → EXFILTRATION`). Internal/RFC1918 IPs are included in correlation — private IP addresses are frequently the most significant lateral movement paths.

---

## Alert Input Format

For file-based ingestion, the CSV or JSON must contain these fields:

| Field | Required | Notes |
|---|---|---|
| `alert_id` | Yes | Unique alert identifier |
| `timestamp` | Yes | ISO 8601, e.g. `2026-04-05T14:30:00Z` |
| `source_ip` | Yes | IPv4 address |
| `alert_name` | Yes | Human-readable alert description |
| `severity` | No | `critical`, `high`, `medium`, `low` (defaults to `low`) |
| `category` | No | `malware`, `phishing`, `lateral_movement`, `c2`, `data_exfil`, `recon`, `other` |
| `destination_ip` | No | |
| `destination_port` | No | Integer |
| `rule_id` | No | Used for MITRE rule ID prefix mapping and prior sightings tracking |
| `asset_tags` | No | Comma-separated: `dc,server,endpoint,cloud,workstation` |
| `raw_payload` | No | JSON string of raw SIEM event |
| `analyst_notes` | No | Pre-existing analyst annotations |

Sample data is in `sample_data/` — 40 alerts covering a range of severity, category, and asset combinations. The source IPs in sample data are documented malicious IPs used for testing only.

---

## Configuration

All parameters are in `config/config.yaml`. No values are hardcoded in library code. Key options:

```yaml
scoring:
  weights:                   # Must sum to 1.0
    severity: 0.25
    vt_malicious_ratio: 0.20
    shodan_exposure: 0.15
    asset_criticality: 0.15
    recency: 0.15
    prior_sightings: 0.10
  baseline_lookback_days: 7  # History window for prior sightings

correlation:
  window_minutes: 15         # Time window for incident grouping

enrichment:
  cache:
    ttl_seconds: 3600        # Cache TTL per IP
```

---

## MITRE ATT&CK Tagging

Each alert is tagged with a MITRE ATT&CK tactic and technique based on its category and rule ID prefix. Rule ID prefix takes priority when both match. Mappings are in `correlation/mitre_mappings.yaml` and can be extended without code changes.

Example mappings:

| Rule ID prefix / Category | Tactic | Technique |
|---|---|---|
| `RDP-*` | LATERAL_MOVEMENT | T1021.001 — Remote Desktop Protocol |
| `PERSIST-*` | PERSISTENCE | T1547 — Boot or Logon Autostart Execution |
| `EXFIL-*` | EXFILTRATION | T1041 — Exfiltration Over C2 Channel |
| category: `c2` | COMMAND_AND_CONTROL | T1071 — Application Layer Protocol |
| category: `phishing` | INITIAL_ACCESS | T1566 — Phishing |

Tactics appear as colored badges in the HTML report and in the terminal summary.

---

## Export Options

```bash
# Export scored results to JSON
python -m cli.main --input alerts.csv --config config/config.yaml --export json

# Export to CSV and JSON both
python -m cli.main --input alerts.csv --config config/config.yaml --export both

# Specify output directory
python -m cli.main --input alerts.csv --config config/config.yaml --output-dir /tmp/triage-out --report
```

---

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
pytest tests/ -v --cov=. --cov-report=term-missing
```

The test suite covers ingestion normalization and edge cases, enrichment mocking, scoring precision and invariants, correlation logic, and HTML report structure. No tests make network calls.

---

## Project Structure

```
soc-alert-triage-engine/
├── cli/main.py                  ← Entry point, pipeline orchestration
├── ingestion/                   ← Alert normalization
├── sources/                     ← Splunk, Elastic, file providers
├── enrichment/                  ← VirusTotal, Shodan, cache
├── correlation/                 ← MITRE tagging, incident grouping
├── scoring/                     ← 6-factor weighted model
├── store/                       ← SQLite persistence
├── reporting/                   ← Self-contained HTML report
├── tests/                       ← Full test suite
├── sample_data/                 ← 40 sample alerts (CSV + JSON)
├── docs/                        ← Architecture and scoring model docs
└── config/config.yaml           ← All tunables
```

See [docs/architecture.md](docs/architecture.md) for module-level documentation and design decisions.

---

## Design Decisions

**Enrichment absent ≠ threat absent.** Missing VT/Shodan data renormalizes the scoring model rather than silently deflating scores. An analyst looking at a `INVESTIGATE_NOW` with `confidence: low` knows exactly what it means: the structural factors are alarming, but the external intelligence layer could not confirm it. That is more honest and more actionable than a suppressed score.

**Private IPs are not skipped from correlation.** RFC1918 addresses are short-circuited from external enrichment (they’d waste API quota and return nothing). But they are fully included in incident correlation, because internal lateral movement is exactly the pattern you want to detect.

**No hardcoded values.** Weights, thresholds, severity mappings, API rate limits, cache TTL, time windows — everything is in `config/config.yaml`. Tuning the model for a specific environment requires no code changes.

**Self-contained report.** The HTML report has zero runtime dependencies. No CDN, no external fonts, no JavaScript libraries. It renders identically online and offline, can be emailed, and does not leak alert data to external servers.

**Source provider abstraction.** Adding a new alert source (AWS Security Hub, Microsoft Sentinel, a custom webhook) requires implementing one class with a `fetch()` method and a field mapping function. The enrichment, scoring, and reporting stages are untouched.

---

## Known Limitations

- Enrichment is source-IP-centric. For phishing and exfiltration alerts, the destination entity is often more relevant. Entity-type-aware enrichment routing is a planned improvement.
- The VT rate limiter is process-local. Concurrent runs will not coordinate API call timing.
- Prior sightings does not deduplicate within a single run. High-volume alert bursts may inflate future sighting counts.
- Splunk and Elastic adapters do not implement checkpoint-based deduplication for continuous polling scenarios.
- Scoring weights have not been validated against historical incident ground truth. They reflect operational judgment, not learned parameters.
