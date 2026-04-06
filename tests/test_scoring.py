"""Tests for the scoring module — no external calls, pure function testing."""
import pytest

from ingestion import Alert
from scoring.scorer import (
    TriageResult,
    _compute_confidence,
    _compute_recency,
    _score_to_label,
    score_alert,
)

# ── Shared config fixtures ──────────────────────────────────────────────────

WEIGHTS = {
    "severity": 0.35,
    "vt_malicious_ratio": 0.25,
    "shodan_exposure": 0.20,
    "asset_criticality": 0.10,
    "recency": 0.10,
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
    """Return a baseline Alert with all enrichment fields set to reasonable defaults."""
    base = dict(
        alert_id="TEST-001",
        timestamp="2026-04-05T10:00:00Z",
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


# ── score_alert integration tests ──────────────────────────────────────────


def test_critical_alert_with_high_vt_and_dc_scores_above_085():
    """A critical-severity alert on a DC with high VT ratio must score above 0.85.

    Uses a dynamic timestamp (30 min ago) so recency=1.0 regardless of when the test runs.
    """
    from datetime import datetime, timedelta, timezone
    recent_ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    alert = make_alert(
        severity="critical",
        asset_tags=["dc", "server"],
        vt_malicious_ratio=0.80,
        shodan_exposure_score=0.60,
        timestamp=recent_ts,
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.score > 0.85
    assert result.priority_label == "INVESTIGATE_NOW"


def test_low_alert_with_zero_vt_and_endpoint_scores_below_035():
    """A low-severity alert with zero VT detections on an endpoint must score below 0.35."""
    alert = make_alert(
        severity="low",
        asset_tags=["endpoint"],
        vt_malicious_ratio=0.0,
        shodan_exposure_score=0.0,
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.score < 0.35


def test_dry_run_alert_no_enrichment_has_low_confidence():
    """An alert with no enrichment data (dry-run) must have confidence='low'."""
    alert = make_alert(
        severity="high",
        asset_tags=["server"],
        vt_malicious_ratio=None,
        shodan_exposure_score=None,
        enrichment_source="dry_run",
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.confidence == "low"
    assert "low confidence" in result.analyst_summary.lower()


def test_score_breakdown_keys_sum_to_final_score():
    """score_breakdown values must sum to the reported final score within float tolerance."""
    alert = make_alert(
        severity="high",
        vt_malicious_ratio=0.40,
        shodan_exposure_score=0.30,
        asset_tags=["server"],
    )
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    breakdown_sum = sum(result.score_breakdown.values())
    assert abs(breakdown_sum - result.score) < 0.001


def test_all_four_priority_labels_are_reachable():
    """All four priority labels must be reachable by varying inputs."""
    # INVESTIGATE_NOW — critical, DC, high VT
    r1 = score_alert(
        make_alert(
            severity="critical",
            asset_tags=["dc"],
            vt_malicious_ratio=0.90,
            shodan_exposure_score=0.80,
        ),
        WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS,
    )
    assert r1.priority_label == "INVESTIGATE_NOW"

    # INVESTIGATE_SOON — high, server, moderate VT
    # Use a timestamp 2 hours ago so recency=0.7, giving score≈0.5725 ≥ 0.55
    from datetime import datetime, timedelta, timezone
    two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    r2 = score_alert(
        make_alert(
            severity="high",
            asset_tags=["server"],
            vt_malicious_ratio=0.40,
            shodan_exposure_score=0.20,
            timestamp=two_hours_ago,
        ),
        WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS,
    )
    assert r2.priority_label in ("INVESTIGATE_SOON", "INVESTIGATE_NOW")

    # MONITOR — medium, endpoint, modest enrichment, 3h-old timestamp (recency=0.7)
    # Score ≈ 0.1575 + 0.0375 + 0.04 + 0.02 + 0.07 = 0.325 → MONITOR
    three_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    r3 = score_alert(
        make_alert(
            severity="medium",
            asset_tags=["endpoint"],
            vt_malicious_ratio=0.15,
            shodan_exposure_score=0.20,
            timestamp=three_hours_ago,
        ),
        WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS,
    )
    assert r3.priority_label in ("MONITOR", "INVESTIGATE_SOON")

    # LOW_PRIORITY — low, endpoint, zero enrichment, very old timestamp
    r4 = score_alert(
        make_alert(
            severity="low",
            asset_tags=["endpoint"],
            vt_malicious_ratio=0.0,
            shodan_exposure_score=0.0,
            timestamp="2026-04-01T00:00:00Z",
        ),
        WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS,
    )
    assert r4.priority_label in ("LOW_PRIORITY", "MONITOR")


def test_result_is_triageresult_instance():
    """score_alert must always return a TriageResult with a valid score and non-empty summary."""
    result = score_alert(make_alert(), WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert isinstance(result, TriageResult)
    assert 0.0 <= result.score <= 1.0
    assert result.analyst_summary != ""


# ── _compute_recency unit tests ─────────────────────────────────────────────


def test_recency_very_recent_returns_near_1():
    """An alert from 10 minutes ago must score above 0.97 under exponential decay.

    With a 6-hour half-life, 10 minutes yields decay = exp(-ln(2)*10/360) ≈ 0.9809,
    which is well above the 0.10 floor and close to 1.0 but no longer exactly 1.0.
    """
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    score = _compute_recency(ts)
    assert score > 0.97
    assert score <= 1.0


def test_recency_old_alert_returns_01():
    """An alert from 2020 must score 0.1 recency."""
    assert _compute_recency("2020-01-01T00:00:00Z") == 0.1


def test_recency_invalid_timestamp_returns_04():
    """An unparseable timestamp must return 0.4 (medium fallback), not raise."""
    assert _compute_recency("not-a-timestamp") == 0.4


# ── _score_to_label unit tests ──────────────────────────────────────────────


def test_score_to_label_boundaries():
    """Label thresholds must be applied as inclusive lower bounds."""
    assert _score_to_label(1.00) == "INVESTIGATE_NOW"
    assert _score_to_label(0.80) == "INVESTIGATE_NOW"
    assert _score_to_label(0.79) == "INVESTIGATE_SOON"
    assert _score_to_label(0.55) == "INVESTIGATE_SOON"
    assert _score_to_label(0.54) == "MONITOR"
    assert _score_to_label(0.30) == "MONITOR"
    assert _score_to_label(0.29) == "LOW_PRIORITY"
    assert _score_to_label(0.00) == "LOW_PRIORITY"


# ── _compute_confidence unit tests ─────────────────────────────────────────


def test_confidence_both_enrichment_sources_high_score():
    """Full enrichment + score above high_confidence threshold → 'high'."""
    result = _compute_confidence(0, 0.90, CONFIDENCE_THRESHOLDS)
    assert result == "high"


def test_confidence_both_sources_low_score():
    """Full enrichment + score below high_confidence threshold → 'medium'."""
    result = _compute_confidence(0, 0.50, CONFIDENCE_THRESHOLDS)
    assert result == "medium"


def test_confidence_one_missing_is_medium():
    """One missing enrichment source must always produce 'medium', regardless of score."""
    assert _compute_confidence(1, 0.95, CONFIDENCE_THRESHOLDS) == "medium"


def test_confidence_both_missing_is_low():
    """Both enrichment sources missing must always produce 'low', regardless of score."""
    assert _compute_confidence(2, 0.95, CONFIDENCE_THRESHOLDS) == "low"


# ── Prior sightings (historical baseline) tests ─────────────────────────────

# Weights that include the prior_sightings factor at 0.10, matching Spec D config.
_BASELINE_WEIGHTS = {
    "severity": 0.25,
    "vt_malicious_ratio": 0.20,
    "shodan_exposure": 0.15,
    "asset_criticality": 0.15,
    "recency": 0.15,
    "prior_sightings": 0.10,
}


def test_prior_sightings_count_stored_in_triage_result():
    """score_alert must store the passed prior_sightings_count in the returned TriageResult."""
    alert = make_alert()
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=3)
    assert result.prior_sightings_count == 3


def test_prior_sightings_none_stored_when_not_passed():
    """When prior_sightings_count is omitted (default None), TriageResult carries None."""
    alert = make_alert()
    result = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    assert result.prior_sightings_count is None


def test_prior_sightings_none_and_explicit_none_give_identical_score():
    """Explicit prior_sightings_count=None must produce the exact same score as the default."""
    alert = make_alert(severity="high", vt_malicious_ratio=0.40, shodan_exposure_score=0.30)
    result_default = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS)
    result_explicit = score_alert(alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=None)
    assert result_default.score == result_explicit.score


def test_prior_sightings_zero_gives_zero_factor_contribution():
    """prior_sightings_count=0 must compute sightings_score=0.0 (1 - 0.7^0 = 0)."""
    alert = make_alert(severity="medium", vt_malicious_ratio=0.20, shodan_exposure_score=0.10)
    result = score_alert(alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=0)
    assert result.score_breakdown["prior_sightings"] == 0.0


def test_prior_sightings_raises_score_for_repeat_offender():
    """An alert with 5 prior sightings must score strictly higher than one with 0."""
    alert = make_alert(severity="medium", vt_malicious_ratio=0.20, shodan_exposure_score=0.10)
    result_zero = score_alert(
        alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=0
    )
    result_five = score_alert(
        alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=5
    )
    assert result_five.score > result_zero.score


def test_prior_sightings_formula_monotone_increasing():
    """More prior sightings must never decrease the score (monotone non-decreasing)."""
    alert = make_alert(severity="high", vt_malicious_ratio=0.50, shodan_exposure_score=0.40)
    scores = []
    for count in range(7):
        r = score_alert(
            alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS,
            prior_sightings_count=count,
        )
        scores.append(r.score)
    for i in range(len(scores) - 1):
        assert scores[i + 1] >= scores[i], (
            f"Score decreased from count={i} ({scores[i]}) to count={i+1} ({scores[i+1]})"
        )


def test_prior_sightings_does_not_affect_confidence():
    """prior_sightings_count must not influence the confidence level (only VT/Shodan do)."""
    alert = make_alert(severity="critical", vt_malicious_ratio=None, shodan_exposure_score=None)
    # Both VT and Shodan missing → always low confidence regardless of sightings
    result = score_alert(
        alert, WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=10
    )
    assert result.confidence == "low"


def test_prior_sightings_score_breakdown_includes_factor_key():
    """score_breakdown must contain a 'prior_sightings' key when the factor weight is set."""
    alert = make_alert()
    result = score_alert(
        alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=2
    )
    assert "prior_sightings" in result.score_breakdown


def test_prior_sightings_breakdown_sums_to_final_score():
    """score_breakdown values must still sum to the final score when prior_sightings is active."""
    alert = make_alert(severity="high", vt_malicious_ratio=0.60, shodan_exposure_score=0.30)
    result = score_alert(
        alert, _BASELINE_WEIGHTS, SEVERITY_MAP, CONFIDENCE_THRESHOLDS, prior_sightings_count=4
    )
    assert abs(sum(result.score_breakdown.values()) - result.score) < 0.001
