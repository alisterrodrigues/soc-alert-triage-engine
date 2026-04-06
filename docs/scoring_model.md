# Scoring Model — SOC Alert Triage Engine

This document describes the 6-factor weighted scoring model used to assign priority scores to alerts.

---

## Overview

Each alert receives a score in `[0.0, 1.0]`. The score is computed as a weighted sum of six normalized factors. The weights are configurable in `config/config.yaml` and must sum to 1.0.

Default weights:

| Factor | Weight | Source |
|---|---|---|
| Severity | 0.25 | Alert metadata |
| VT malicious ratio | 0.20 | VirusTotal API |
| Shodan exposure | 0.15 | Shodan API |
| Asset criticality | 0.15 | Alert asset tags |
| Recency | 0.15 | Alert timestamp |
| Prior sightings | 0.10 | SQLite run history |

---

## Factor Definitions

### 1. Severity (`severity`)

Maps the alert severity string to a float using `config.scoring.severity_map`:

| Severity | Score |
|---|---|
| `critical` | 1.00 |
| `high` | 0.75 |
| `medium` | 0.45 |
| `low` | 0.20 |

Unrecognized severity strings default to `low` at ingestion time.

### 2. VT Malicious Ratio (`vt_malicious_ratio`)

The ratio of VirusTotal engines that flagged the source IP as malicious:

```
vt_score = malicious_count / total_engine_count
```

Range: `[0.0, 1.0]`. A ratio of 0.40 means 40% of VT engines returned a positive signal.

### 3. Shodan Exposure (`shodan_exposure`)

Computed from open ports and known CVEs using a service-weighted model:

```
port_score = sum(port_weight for each open port), capped at 0.60
vuln_score = count(CVEs) * 0.12, capped at 0.40
shodan_exposure = min(port_score + vuln_score, 1.0)
```

Port weight table:

| Risk tier | Ports | Weight each |
|---|---|---|
| High risk | 3389 (RDP), 445 (SMB), 5900 (VNC), 1433 (MSSQL), 9200 (Elasticsearch), 27017 (MongoDB), 6379 (Redis), 4444 (Metasploit default), 8080 (alt-HTTP), 2375 (Docker daemon) | 0.15 |
| Medium risk | 22 (SSH), 21 (FTP), 23 (Telnet), 25 (SMTP), 3306 (MySQL), 5432 (PostgreSQL), 5984 (CouchDB), 11211 (Memcached), 2181 (Zookeeper) | 0.07 |
| Other | All other ports | 0.02 |

**Why this model over raw counts:** Port 3389 exposed to the internet is not equivalent to port 80. Counting them equally would make a web server with many open ports appear more exposed than an RDP-accessible Windows host with one. The weighted model reflects real-world attack surface.

When `shodan_open_ports` is populated (from a live or cached Shodan lookup), the weighted model is used. When only the pre-computed `shodan_exposure_score` float is available (e.g. from a legacy import), it is used directly.

### 4. Asset Criticality (`asset_criticality`)

Derived from the `asset_tags` field of the alert:

| Tags contain | Score |
|---|---|
| `dc` or `server` | 1.00 |
| `cloud` | 0.50 |
| `workstation` | 0.20 |
| anything else / none | 0.20 |

Tags are normalized to lowercase at ingestion time so `"DC"`, `"Server"`, and `"server"` all match correctly.

### 5. Recency (`recency`)

Uses an exponential half-life decay with a 6-hour half-life and a floor of 0.10:

```
recency_score = max(exp(-ln(2) * age_hours / 6.0), 0.10)
```

Example values:

| Alert age | Score |
|---|---|
| 10 minutes | ~0.98 |
| 1 hour | ~0.89 |
| 6 hours | ~0.50 |
| 12 hours | ~0.25 |
| 24 hours | ~0.10 (floor) |
| 7 days | 0.10 (floor) |

**Why exponential over step function:** A 59-minute-old alert and a 61-minute-old alert should not receive materially different scores just because they straddle an arbitrary tier boundary. The continuous model eliminates cliff edges and is more defensible as a scoring decision.

### 6. Prior Sightings (`prior_sightings`)

Counts how many times the same `source_ip` + `rule_id` pair has fired in the last N days (configurable, default 7):

```
sightings_score = min(1 - (0.7 ^ prior_sightings_count), 1.0)
```

Example values:

| Prior sightings | Score |
|---|---|
| 0 (first seen) | 0.00 |
| 1 | 0.30 |
| 2 | 0.51 |
| 3 | 0.66 |
| 5 | 0.83 |
| 10 | 0.97 |

**Why this matters:** A one-off alert from a never-before-seen host is different from the same alert firing for the fifth time this week from the same IP. Repeated sightings are a strong signal that a threat is persistent and not just noise.

On the first pipeline run against a fresh database, all prior sightings counts are zero. The factor becomes meaningful after several runs have accumulated history.

---

## Renormalization for Missing Enrichment

When VT or Shodan data is unavailable (dry-run mode, API failure, or private IP), the missing factors are excluded from the weighted sum and the remaining weights are scaled up proportionally:

```
available_weight = sum(weights[k] for k in factors where value is not None)
effective_weight[k] = weights[k] / available_weight
score[k] = factor_value[k] * effective_weight[k]
final_score = sum(score[k] for all k)
```

**Example — high-severity server alert in dry-run (VT + Shodan both None):**

Original weights: severity=0.25, asset=0.15, recency=0.15 (sum of available = 0.55)
Renormalized: severity=0.455, asset=0.273, recency=0.273

A `high`-severity `server` alert from 30 minutes ago produces a score of ~0.87 in dry-run. The same alert with full enrichment and no VT/Shodan detections would score ~0.55. This is intentional: the model does not treat absence of threat intelligence as absence of threat.

**The result is explicitly marked as `confidence: low`** so the analyst knows that VT and Shodan data were not available and the score is operating on structural factors only.

---

## Priority Labels

The final score maps to a priority label using inclusive lower-bound thresholds:

| Score | Label |
|---|---|
| ≥ 0.80 | `INVESTIGATE_NOW` |
| ≥ 0.55 | `INVESTIGATE_SOON` |
| ≥ 0.30 | `MONITOR` |
| < 0.30 | `LOW_PRIORITY` |

---

## Confidence Levels

Confidence reflects enrichment completeness, not score magnitude:

| Enrichment state | Confidence |
|---|---|
| Both VT and Shodan present | `high` (if score ≥ 0.80) or `medium` |
| One of VT or Shodan missing | `medium` (always) |
| Both VT and Shodan missing | `low` (always) |

Confidence is independent of the priority label. A `INVESTIGATE_NOW` alert with `confidence: low` means the engine has flagged it as high-priority based on structural factors (severity + asset criticality) but enrichment was not available to confirm the threat.

---

## Known Limitations

**Enrichment is source-IP-centric.** VT and Shodan are queried against `source_ip`. For some alert categories (phishing, data exfiltration), the more relevant entity is the destination IP, domain, URL, or file hash. Future versions may add entity-type-aware enrichment routing.

**Asset criticality is tag-based.** Tags are assigned at SIEM export time and may not reflect reality. A misconfigured SIEM export that omits asset tags will cause all alerts to score as `endpoint`-level assets.

**Prior sightings does not deduplicate.** If the same SIEM fires 50 identical alerts in one run, all 50 are stored and will inflate the prior sightings count for future runs. Deduplication at ingestion time is a planned enhancement.

**The model is additive.** Interaction effects between factors are not modeled. A high-severity alert with high VT and high Shodan exposure does not receive a multiplicative bonus beyond the weighted sum. Real threat correlation is non-linear.

**Weights are not learned.** The default weights reflect reasonable operational judgment but have not been validated against historical incident data. Organizations should tune weights based on their own environment and false positive rates.

---

## Tuning Guide

To adjust the model for your environment, edit `config/config.yaml`:

```yaml
scoring:
  weights:
    severity: 0.25           # Increase if your SIEM severity is reliable
    vt_malicious_ratio: 0.20 # Decrease if VT produces many false positives
    shodan_exposure: 0.15    # Increase for internet-facing infrastructure
    asset_criticality: 0.15  # Increase if asset tagging is comprehensive
    recency: 0.15            # Decrease if batch processing old events
    prior_sightings: 0.10    # Increase after history accumulates
```

Weights must sum to exactly 1.0. Confidence thresholds and severity mapping are also configurable without code changes.
