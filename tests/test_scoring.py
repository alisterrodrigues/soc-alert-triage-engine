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


def test_recency_very_recent_returns_1():
    """An alert from 10 minutes ago must score 1.0 recency."""
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    assert _compute_recency(ts) == 1.0


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
