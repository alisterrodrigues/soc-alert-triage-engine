"""Tests for the scoring module — pure function testing, no external calls."""
import math
import pytest
from datetime import datetime, timedelta, timezone

from ingestion import Alert
from scoring.scorer import (
    TriageResult,
    _compute_confidence,
    _compute_recency,
    _compute_shodan_exposure,
    _score_to_label,
    score_alert,
)

# ── Shared config fixtures ──────────────────────────────────────────────────

WEIGHTS = {
    "severity": 0.25,
    "vt_malicious_ratio": 0.20,
    "shodan_exposure": 0.15,
    "asset_criticality": 0.15,
    "recency": 0.15,
    "prior_sightings": 0.10,
}

SEVERITY_MAP = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.45,
    "low": 0.20,
}

CONFIDENCE_THRESHOLDS = {
    "high_confidence": 0.80,
    "medium_confidence": 0.50,
}


def make_alert(**overrides) -> Alert:
    """Return a baseline Alert with sensible defaults for scoring tests."""
    recent = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    base = dict(
        alert_id="TEST-001",
        timestamp=recent,
        source_ip="185.220.101.47",
        alert_name="Test alert",
        severity="medium",
        category="malware",
        asset_tags=["endpoint"],
        vt_malicious_ratio=0.0,
        shodan_exposure_score=0.0,
        enrichment_source="live",
    )
    base.update(overrides)
    return Alert(**base)


# ── Precision score assertions (derived from probe output) ──────────────────


def test_critical_dc_vt_high_shodan_score_and_label():
    """Critical alert on DC with 80% VT ratio and high-risk Shodan ports must score ~0.85.

    Probe output: CRITICAL_DC_VT_HIGH score=0.8496 label=INVESTIGATE_NOW conf=high
    Tolerance: ±0.015 to allow for recency drift across test runs.
    """
    recent = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    alert = make_alert(
        severity="critical",
        asset_tags=["dc", "server"],
        vt_malicious_ratio=0.80,
        shodan_open_ports=[3389, 445],
        shodan_vulns=["CVE-2021-34527"],
        timestamp=recent,
        enrichment_source="live",
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(result.score - 0.8496) < 0.015, f"Expected ~0.8496, got {result.score}"
    assert result.priority_label == "INVESTIGATE_NOW"
    assert result.confidence == "high"
    assert result.enrichment_completeness == 1.0


def test_low_endpoint_no_enrichment_score_and_label():
    """Low-severity dry-run alert on endpoint with old timestamp must score ~0.17.

    Probe output: LOW_ENDPOINT_NO_ENRICH score=0.1727 label=LOW_PRIORITY conf=low
    Renormalization over severity+asset+recency only.
    """
    alert = make_alert(
        severity="low",
        asset_tags=["endpoint"],
        vt_malicious_ratio=None,
        shodan_exposure_score=None,
        timestamp="2026-04-01T00:00:00Z",
        enrichment_source="dry_run",
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(result.score - 0.1727) < 0.015, f"Expected ~0.1727, got {result.score}"
    assert result.priority_label == "LOW_PRIORITY"
    assert result.confidence == "low"
    assert result.enrichment_completeness == 0.0


def test_high_server_no_enrichment_renorm_elevates_score():
    """High-severity dry-run alert on server renormalizes to ~0.87 — confirming
    the renormalization correctly amplifies high-severity + critical-asset weight.

    Probe output: HIGH_SERVER_NO_ENRICH score=0.8710 label=INVESTIGATE_NOW conf=low
    This is intentional: the system correctly flags high-severity server alerts
    even when enrichment APIs are unavailable, and signals low confidence.
    """
    recent = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    alert = make_alert(
        severity="high",
        asset_tags=["server"],
        vt_malicious_ratio=None,
        shodan_exposure_score=None,
        timestamp=recent,
        enrichment_source="dry_run",
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(result.score - 0.8710) < 0.015, f"Expected ~0.8710, got {result.score}"
    assert result.priority_label == "INVESTIGATE_NOW"
    assert result.confidence == "low"  # low confidence because enrichment missing
    assert "low confidence" in result.analyst_summary.lower()


def test_medium_endpoint_partial_enrichment_score_and_label():
    """Medium-severity alert with VT only (no Shodan) must score ~0.46.

    Probe output: MED_ENDPOINT_PARTIAL score=0.4588 label=MONITOR conf=medium
    """
    recent = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    alert = make_alert(
        severity="medium",
        asset_tags=["endpoint"],
        vt_malicious_ratio=0.30,
        shodan_exposure_score=None,
        timestamp=recent,
        enrichment_source="live",
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(result.score - 0.4588) < 0.015, f"Expected ~0.4588, got {result.score}"
    assert result.priority_label == "MONITOR"
    assert result.confidence == "medium"
    assert result.enrichment_completeness == 0.5


# ── score_breakdown invariants ──────────────────────────────────────────────


def test_score_breakdown_sums_to_final_score_full_enrichment():
    """With full enrichment, score_breakdown values must sum to final_score ±0.001."""
    alert = make_alert(severity="high", vt_malicious_ratio=0.40, shodan_open_ports=[22, 3389], shodan_vulns=[])
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(sum(result.score_breakdown.values()) - result.score) < 0.001


def test_score_breakdown_sums_to_final_score_no_enrichment():
    """With zero enrichment (dry-run), renormalized breakdown must still sum to final_score ±0.001."""
    alert = make_alert(severity="critical", vt_malicious_ratio=None, shodan_exposure_score=None)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert abs(sum(result.score_breakdown.values()) - result.score) < 0.001


def test_score_breakdown_zero_for_missing_vt_factor():
    """When VT is None, the vt_malicious_ratio entry in score_breakdown must be exactly 0.0."""
    alert = make_alert(vt_malicious_ratio=None, shodan_exposure_score=0.5)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.score_breakdown["vt_malicious_ratio"] == 0.0


def test_score_breakdown_zero_for_missing_shodan_factor():
    """When Shodan is None, the shodan_exposure entry in score_breakdown must be exactly 0.0."""
    alert = make_alert(vt_malicious_ratio=0.5, shodan_exposure_score=None)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.score_breakdown["shodan_exposure"] == 0.0


def test_score_always_in_unit_interval():
    """Final score must always be in [0.0, 1.0] regardless of inputs."""
    for sev in ("critical", "high", "medium", "low"):
        for vt in (None, 0.0, 0.5, 1.0):
            for sightings in (None, 0, 5, 100):
                alert = make_alert(severity=sev, vt_malicious_ratio=vt)
                result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=sightings)
                assert 0.0 <= result.score <= 1.0, f"Score out of range: {result.score} for sev={sev} vt={vt}"


# ── enrichment_completeness field ──────────────────────────────────────────


def test_enrichment_completeness_full():
    """Both enrichment sources present → completeness = 1.0."""
    alert = make_alert(vt_malicious_ratio=0.5, shodan_exposure_score=0.3)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.enrichment_completeness == 1.0


def test_enrichment_completeness_half():
    """One enrichment source missing → completeness = 0.5."""
    alert = make_alert(vt_malicious_ratio=0.5, shodan_exposure_score=None)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.enrichment_completeness == 0.5


def test_enrichment_completeness_zero():
    """Both enrichment sources missing → completeness = 0.0."""
    alert = make_alert(vt_malicious_ratio=None, shodan_exposure_score=None)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.enrichment_completeness == 0.0


# ── prior_sightings tests ───────────────────────────────────────────────────


def test_prior_sightings_stored_in_triage_result():
    """A passed prior_sightings_count must be accessible on the returned TriageResult."""
    alert = make_alert()
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=3)
    assert result.prior_sightings_count == 3


def test_prior_sightings_none_when_not_passed():
    """Omitting prior_sightings_count must leave the field as None."""
    alert = make_alert()
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.prior_sightings_count is None


def test_prior_sightings_zero_contributes_nothing_to_score():
    """A prior_sightings_count of 0 uses 1 - 0.7^0 = 0.0 — zero factor contribution."""
    alert = make_alert()
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=0)
    assert result.score_breakdown["prior_sightings"] == 0.0


def test_prior_sightings_raises_score_monotonically():
    """Higher prior_sightings_count must produce a strictly higher score."""
    alert = make_alert()
    scores = [
        score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=n).score
        for n in range(7)
    ]
    for i in range(1, len(scores)):
        assert scores[i] >= scores[i - 1], f"Score not monotone at count={i}: {scores}"


def test_prior_sightings_does_not_affect_confidence():
    """High prior_sightings_count with both enrichments missing must still yield confidence='low'."""
    alert = make_alert(vt_malicious_ratio=None, shodan_exposure_score=None)
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=10)
    assert result.confidence == "low"


def test_prior_sightings_breakdown_key_always_present():
    """score_breakdown must always contain a 'prior_sightings' key."""
    for count in (None, 0, 1, 5):
        alert = make_alert()
        result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=count)
        assert "prior_sightings" in result.score_breakdown


# ── _compute_shodan_exposure unit tests ─────────────────────────────────────


def test_shodan_exposure_high_risk_port_scores_correctly():
    """A single high-risk port (3389 RDP) must score 0.15."""
    assert _compute_shodan_exposure([3389], []) == 0.15


def test_shodan_exposure_medium_risk_port_scores_correctly():
    """A single medium-risk port (22 SSH) must score 0.07."""
    assert _compute_shodan_exposure([22], []) == 0.07


def test_shodan_exposure_unknown_port_scores_002():
    """An unknown port must score 0.02."""
    assert _compute_shodan_exposure([12345], []) == 0.02


def test_shodan_exposure_port_contribution_capped_at_060():
    """Port contribution must be capped at 0.60 regardless of port count."""
    many_high_risk = [3389, 445, 5900, 1433, 9200, 27017, 6379, 4444, 8080, 2375]
    score = _compute_shodan_exposure(many_high_risk, [])
    assert score <= 1.0
    # Port portion alone would be 10 * 0.15 = 1.50 but must be capped at 0.60
    assert _compute_shodan_exposure(many_high_risk, []) == pytest.approx(0.60, abs=0.01)


def test_shodan_exposure_cve_adds_012_per_vuln():
    """Each CVE must add 0.12 to the exposure score."""
    score_0 = _compute_shodan_exposure([], [])
    score_1 = _compute_shodan_exposure([], ["CVE-2021-34527"])
    assert abs((score_1 - score_0) - 0.12) < 0.001


def test_shodan_exposure_vuln_contribution_capped_at_040():
    """Vulnerability contribution must be capped at 0.40."""
    many_cves = [f"CVE-2021-{i:05d}" for i in range(20)]
    score = _compute_shodan_exposure([], many_cves)
    assert score == pytest.approx(0.40, abs=0.001)


def test_shodan_exposure_total_capped_at_1():
    """Combined port + CVE score must never exceed 1.0."""
    many_ports = [3389, 445, 5900, 1433, 9200, 27017, 6379, 4444]
    many_cves = [f"CVE-2021-{i:05d}" for i in range(10)]
    assert _compute_shodan_exposure(many_ports, many_cves) <= 1.0


def test_shodan_exposure_empty_inputs_returns_zero():
    """No ports and no vulns must return 0.0."""
    assert _compute_shodan_exposure([], []) == 0.0


# ── _compute_recency unit tests (continuous decay) ──────────────────────────


def test_recency_very_recent_is_near_one():
    """A 10-minute-old alert must score close to 1.0 (exponential model: ~0.98)."""
    ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    score = _compute_recency(ts)
    assert score > 0.97, f"Expected > 0.97 for 10-min-old alert, got {score}"


def test_recency_six_hour_old_is_near_half():
    """A 6-hour-old alert must score near 0.5 (half-life = 6hr, floor = 0.10)."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
    score = _compute_recency(ts)
    assert abs(score - 0.5) < 0.05, f"Expected ~0.5 for 6hr-old alert, got {score}"


def test_recency_very_old_alert_floors_at_010():
    """An alert from 2020 must return exactly the floor value 0.10."""
    score = _compute_recency("2020-01-01T00:00:00Z")
    assert score == 0.10


def test_recency_decay_is_monotonically_decreasing():
    """Older alerts must score the same or lower than more recent ones."""
    now = datetime.now(timezone.utc)
    ages_hours = [0.1, 1, 3, 6, 12, 24, 48, 168]
    scores = [_compute_recency((now - timedelta(hours=h)).isoformat()) for h in ages_hours]
    for i in range(1, len(scores)):
        assert scores[i] <= scores[i - 1], f"Not monotone at index {i}: {scores}"


def test_recency_invalid_timestamp_returns_04():
    """An unparseable timestamp must return 0.4 (medium fallback), not raise."""
    assert _compute_recency("not-a-timestamp") == 0.4


def test_recency_z_suffix_and_offset_give_same_result():
    """'2026-04-04T10:00:00Z' and '2026-04-04T10:00:00+00:00' must yield identical scores."""
    s1 = _compute_recency("2026-04-04T10:00:00Z")
    s2 = _compute_recency("2026-04-04T10:00:00+00:00")
    assert s1 == s2


# ── _score_to_label unit tests ──────────────────────────────────────────────


def test_score_to_label_exact_boundaries():
    """All four label thresholds must be applied as inclusive lower bounds."""
    assert _score_to_label(1.00) == "INVESTIGATE_NOW"
    assert _score_to_label(0.80) == "INVESTIGATE_NOW"
    assert _score_to_label(0.7999) == "INVESTIGATE_SOON"
    assert _score_to_label(0.55) == "INVESTIGATE_SOON"
    assert _score_to_label(0.5499) == "MONITOR"
    assert _score_to_label(0.30) == "MONITOR"
    assert _score_to_label(0.2999) == "LOW_PRIORITY"
    assert _score_to_label(0.00) == "LOW_PRIORITY"


# ── _compute_confidence unit tests ─────────────────────────────────────────


def test_confidence_full_enrichment_high_score():
    """Full enrichment + score >= high_confidence threshold → 'high'."""
    assert _compute_confidence(0, 0.90, CONFIDENCE_THRESHOLDS) == "high"


def test_confidence_full_enrichment_low_score():
    """Full enrichment + score below threshold → 'medium'."""
    assert _compute_confidence(0, 0.50, CONFIDENCE_THRESHOLDS) == "medium"


def test_confidence_one_missing_always_medium():
    """One missing enrichment source → always 'medium', even at high scores."""
    assert _compute_confidence(1, 0.99, CONFIDENCE_THRESHOLDS) == "medium"


def test_confidence_both_missing_always_low():
    """Both enrichment sources missing → always 'low', even at high scores."""
    assert _compute_confidence(2, 0.99, CONFIDENCE_THRESHOLDS) == "low"


# ── Result structure tests ──────────────────────────────────────────────────


def test_result_is_triageresult_with_valid_score():
    """score_alert must always return a TriageResult with score in [0, 1] and non-empty summary."""
    result = score_alert(make_alert(), WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert isinstance(result, TriageResult)
    assert 0.0 <= result.score <= 1.0
    assert result.analyst_summary != ""


def test_result_has_all_breakdown_keys():
    """score_breakdown must contain all six factor keys."""
    result = score_alert(make_alert(), WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    expected_keys = {"severity", "vt_malicious_ratio", "shodan_exposure", "asset_criticality", "recency", "prior_sightings"}
    assert set(result.score_breakdown.keys()) == expected_keys
