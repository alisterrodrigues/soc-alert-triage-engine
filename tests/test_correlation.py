"""Tests for the correlation engine — no external calls, pure function testing."""
from datetime import datetime, timedelta, timezone

import pytest

from ingestion import Alert
from scoring.scorer import TriageResult
from correlation.engine import CorrelatedIncident, correlate_alerts

# ── Helpers ─────────────────────────────────────────────────────────────────

_BASE_TS = datetime(2026, 4, 5, 10, 0, 0, tzinfo=timezone.utc)


def make_alert(
    alert_id: str = "A1",
    source_ip: str = "1.2.3.4",
    offset_minutes: int = 0,
    category: str = "malware",
    severity: str = "high",
    mitre_tactic: str = None,
) -> Alert:
    ts = (_BASE_TS + timedelta(minutes=offset_minutes)).isoformat()
    a = Alert(
        alert_id=alert_id,
        timestamp=ts,
        source_ip=source_ip,
        alert_name=f"Alert {alert_id}",
        severity=severity,
        category=category,
    )
    if mitre_tactic is not None:
        a.mitre_tactic = mitre_tactic
    return a


def make_result(alert_id: str = "A1", score: float = 0.70) -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        score=score,
        priority_label="INVESTIGATE_SOON",
        confidence="high",
        analyst_summary="Test summary.",
    )


# ── Grouping tests ────────────────────────────────────────────────────────────


def test_same_ip_within_window_grouped_into_one_incident():
    """Two alerts from the same IP within 10 minutes must form one incident (window=15)."""
    a1 = make_alert("A1", "1.2.3.4", 0)
    a2 = make_alert("A2", "1.2.3.4", 10)
    r1 = make_result("A1", 0.70)
    r2 = make_result("A2", 0.60)

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 1
    assert incidents[0].alert_count == 2
    assert set(incidents[0].alert_ids) == {"A1", "A2"}


def test_same_ip_outside_window_split_into_two_incidents():
    """Two alerts from the same IP 30 minutes apart (window=15) must become two incidents."""
    a1 = make_alert("A1", "1.2.3.4", 0)
    a2 = make_alert("A2", "1.2.3.4", 30)
    r1 = make_result("A1")
    r2 = make_result("A2")

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 2


def test_different_ips_within_one_minute_not_grouped():
    """Two alerts from different IPs within 1 minute must NOT be grouped."""
    a1 = make_alert("A1", "1.2.3.4", 0)
    a2 = make_alert("A2", "5.6.7.8", 1)
    r1 = make_result("A1")
    r2 = make_result("A2")

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 2
    hosts = {i.host for i in incidents}
    assert "1.2.3.4" in hosts
    assert "5.6.7.8" in hosts


# ── Score tests ───────────────────────────────────────────────────────────────


def test_combined_score_always_between_zero_and_one():
    """combined_score must be in [0.0, 1.0] for any input combination."""
    # Max possible: peak=1.0, mean=1.0, count=100
    alerts = [make_alert(f"A{i}", "1.2.3.4", i) for i in range(20)]
    results = [make_result(f"A{i}", 1.0) for i in range(20)]

    incidents = correlate_alerts(alerts, results, window_minutes=60)

    for incident in incidents:
        assert 0.0 <= incident.combined_score <= 1.0


def test_combined_score_zero_scores_stays_in_range():
    """combined_score with all-zero individual scores must still be in [0.0, 1.0]."""
    a1 = make_alert("A1", "1.2.3.4", 0)
    r1 = make_result("A1", 0.0)

    incidents = correlate_alerts([a1], [r1])

    assert 0.0 <= incidents[0].combined_score <= 1.0


# ── Kill chain tests ──────────────────────────────────────────────────────────


def test_kill_chain_detected_with_lateral_movement_and_exfiltration():
    """kill_chain_detected must be True when LATERAL_MOVEMENT + EXFILTRATION are in tactic_chain."""
    a1 = make_alert("A1", "1.2.3.4", 0, mitre_tactic="LATERAL_MOVEMENT")
    a2 = make_alert("A2", "1.2.3.4", 5, mitre_tactic="EXFILTRATION")
    r1 = make_result("A1")
    r2 = make_result("A2")

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 1
    assert incidents[0].kill_chain_detected is True
    assert "LATERAL_MOVEMENT" in incidents[0].tactic_chain
    assert "EXFILTRATION" in incidents[0].tactic_chain


def test_kill_chain_not_detected_single_tactic():
    """kill_chain_detected must be False when tactic_chain contains only one distinct tactic."""
    a1 = make_alert("A1", "1.2.3.4", 0, mitre_tactic="LATERAL_MOVEMENT")
    a2 = make_alert("A2", "1.2.3.4", 5, mitre_tactic="LATERAL_MOVEMENT")
    r1 = make_result("A1")
    r2 = make_result("A2")

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 1
    assert incidents[0].kill_chain_detected is False
    assert incidents[0].tactic_chain == ["LATERAL_MOVEMENT"]


# ── Edge case tests ───────────────────────────────────────────────────────────


def test_empty_alert_list_returns_empty_list():
    """An empty alert list must return an empty list without raising."""
    incidents = correlate_alerts([], [], window_minutes=15)
    assert incidents == []


def test_single_alert_returns_one_incident_with_count_one():
    """A single alert must produce exactly one incident with alert_count == 1."""
    a = make_alert("A1", "10.0.0.1", 0)
    r = make_result("A1", 0.85)

    incidents = correlate_alerts([a], [r])

    assert len(incidents) == 1
    assert incidents[0].alert_count == 1
    assert incidents[0].host == "10.0.0.1"
    assert incidents[0].alert_ids == ["A1"]
    assert isinstance(incidents[0], CorrelatedIncident)


# ── Output ordering and structure ─────────────────────────────────────────────


def test_incidents_sorted_by_combined_score_descending():
    """correlate_alerts must return incidents sorted by combined_score descending."""
    a1 = make_alert("A1", "1.1.1.1", 0)
    a2 = make_alert("A2", "2.2.2.2", 0)
    r1 = make_result("A1", 0.90)
    r2 = make_result("A2", 0.30)

    incidents = correlate_alerts([a1, a2], [r1, r2])

    assert incidents[0].combined_score >= incidents[1].combined_score


def test_tactic_chain_deduplicates_preserving_order():
    """tactic_chain must list each MITRE tactic exactly once, in chronological order."""
    a1 = make_alert("A1", "1.2.3.4", 0, mitre_tactic="DISCOVERY")
    a2 = make_alert("A2", "1.2.3.4", 2, mitre_tactic="LATERAL_MOVEMENT")
    a3 = make_alert("A3", "1.2.3.4", 4, mitre_tactic="DISCOVERY")  # duplicate
    results = [make_result("A1"), make_result("A2"), make_result("A3")]

    incidents = correlate_alerts([a1, a2, a3], results, window_minutes=15)

    assert len(incidents) == 1
    assert incidents[0].tactic_chain == ["DISCOVERY", "LATERAL_MOVEMENT"]


def test_skipped_private_enrichment_source_still_correlated():
    """Alerts with enrichment_source == 'skipped_private' must be included in incidents."""
    a1 = make_alert("A1", "192.168.1.10", 0)
    a1.enrichment_source = "skipped_private"
    a2 = make_alert("A2", "192.168.1.10", 5)
    a2.enrichment_source = "skipped_private"
    r1 = make_result("A1", 0.60)
    r2 = make_result("A2", 0.55)

    incidents = correlate_alerts([a1, a2], [r1, r2], window_minutes=15)

    assert len(incidents) == 1
    assert incidents[0].alert_count == 2
