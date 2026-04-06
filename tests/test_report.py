"""Tests for the HTML report generator."""
import os
import tempfile
from pathlib import Path

import pytest

from correlation.engine import CorrelatedIncident
from ingestion import Alert
from reporting.html_report import render_report, _esc
from scoring.scorer import TriageResult


def make_result(
    alert_id: str = "TEST-001",
    score: float = 0.75,
    label: str = "INVESTIGATE_SOON",
    confidence: str = "medium",
) -> TriageResult:
    """Return a TriageResult with realistic default values."""
    return TriageResult(
        alert_id=alert_id,
        score=score,
        priority_label=label,
        confidence=confidence,
        analyst_summary=f"Test summary for {alert_id}.",
        score_breakdown={
            "severity": 0.26,
            "vt_malicious_ratio": 0.20,
            "shodan_exposure": 0.15,
            "asset_criticality": 0.08,
            "recency": 0.06,
        },
    )


def make_alert(alert_id: str = "TEST-001") -> Alert:
    """Return an Alert with realistic default values."""
    return Alert(
        alert_id=alert_id,
        timestamp="2026-04-05T10:00:00Z",
        source_ip="185.220.101.47",
        alert_name="Test malware beacon",
        severity="high",
        category="malware",
        asset_tags=["server"],
        vt_malicious_ratio=0.80,
        shodan_exposure_score=0.40,
        enrichment_source="live",
    )


SAMPLE_CONFIG = {
    "scoring": {
        "weights": {
            "severity": 0.35,
            "vt_malicious_ratio": 0.25,
            "shodan_exposure": 0.20,
            "asset_criticality": 0.10,
            "recency": 0.10,
        }
    },
    "reporting": {
        "max_alerts_in_report": 200,
        "include_raw_alert": True,
        "highlight_top_n": 3,
    },
}


def test_report_generates_without_exception():
    """render_report must complete without raising given valid inputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        result = render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run-id",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        assert result == out


def test_report_output_file_exists_and_nonempty():
    """The output file must exist and contain a substantial amount of content after rendering."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run-id",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        assert Path(out).exists()
        assert Path(out).stat().st_size > 1000


def test_report_contains_alert_ids():
    """The rendered HTML must contain the alert_id of every result."""
    results = [make_result("ALERT-001"), make_result("ALERT-002", score=0.30, label="MONITOR")]
    alerts = [make_alert("ALERT-001"), make_alert("ALERT-002")]
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(results=results, alerts=alerts, run_id="test-run", config=SAMPLE_CONFIG, output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        assert "ALERT-001" in html
        assert "ALERT-002" in html


def test_report_contains_priority_labels():
    """Priority labels must appear in the rendered HTML."""
    results = [
        make_result("A1", score=0.90, label="INVESTIGATE_NOW"),
        make_result("A2", score=0.60, label="INVESTIGATE_SOON"),
    ]
    alerts = [make_alert("A1"), make_alert("A2")]
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(results=results, alerts=alerts, run_id="r1", config=SAMPLE_CONFIG, output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        assert "INVESTIGATE_NOW" in html
        assert "INVESTIGATE_SOON" in html


def test_report_returns_empty_string_on_bad_path():
    """render_report must return '' rather than raising when the output path is invalid."""
    result = render_report(
        results=[make_result()],
        alerts=[make_alert()],
        run_id="r",
        config=SAMPLE_CONFIG,
        output_path="/no/such/directory/report.html",
    )
    assert result == ""


def test_report_is_self_contained_html():
    """The output must be a valid HTML document with no external resource links."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(results=[make_result()], alerts=[make_alert()], run_id="r", config=SAMPLE_CONFIG, output_path=out)
        html = Path(out).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "cdn." not in html
        assert 'src="http' not in html
        assert 'href="http' not in html


def test_esc_handles_html_special_chars():
    """_esc must escape the four HTML-significant characters."""
    assert _esc("<script>") == "&lt;script&gt;"
    assert _esc('"quoted"') == "&quot;quoted&quot;"
    assert _esc("a & b") == "a &amp; b"


def test_esc_handles_non_string_input():
    """_esc must accept non-string inputs and cast them to str before escaping."""
    assert _esc(42) == "42"
    assert _esc(None) == "None"
    assert _esc(3.14) == "3.14"


def test_report_with_empty_results_does_not_crash():
    """Rendering with no alerts must not raise — must return the output path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        result = render_report(results=[], alerts=[], run_id="empty", config=SAMPLE_CONFIG, output_path=out)
        assert result == out


# ── Spec F new tests ──────────────────────────────────────────────────────────

def make_incident(
    host: str = "10.0.0.1",
    combined_score: float = 0.75,
    alert_count: int = 3,
    kill_chain: bool = False,
    tactic_chain: list | None = None,
) -> CorrelatedIncident:
    """Return a CorrelatedIncident with realistic default values."""
    return CorrelatedIncident(
        incident_id="test-incident-uuid-0001",
        host=host,
        alert_ids=["A1", "A2", "A3"][:alert_count],
        start_time="2026-04-05T10:00:00+00:00",
        end_time="2026-04-05T10:23:00+00:00",
        peak_score=combined_score,
        combined_score=combined_score,
        tactic_chain=tactic_chain or [],
        kill_chain_detected=kill_chain,
        alert_count=alert_count,
        priority_label="INVESTIGATE_SOON",
        summary=f"{alert_count} alerts from {host} over 23min — malware.",
    )


def test_render_report_with_empty_incidents_still_valid():
    """render_report with incidents=[] must succeed and produce valid HTML."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        result = render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
            incidents=[],
        )
        assert result == out
        html = Path(out).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html


def test_render_report_with_incident_contains_host_ip():
    """render_report with one CorrelatedIncident must include the incident host in HTML."""
    incident = make_incident(host="185.220.101.50", combined_score=0.82)
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
            incidents=[incident],
        )
        html = Path(out).read_text(encoding="utf-8")
        assert "185.220.101.50" in html


def test_mitre_tactic_badge_appears_when_set():
    """When alert.mitre_tactic is set, its value must appear as a badge in the HTML."""
    alert = make_alert()
    alert.mitre_tactic = "LATERAL_MOVEMENT"
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[make_result()],
            alerts=[alert],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        html = Path(out).read_text(encoding="utf-8")
        assert "LATERAL_MOVEMENT" in html
        assert "tactic-badge" in html


def test_first_seen_text_when_prior_sightings_zero():
    """'First seen' must appear in the HTML when prior_sightings_count == 0."""
    result = TriageResult(
        alert_id="TEST-001",
        score=0.55,
        priority_label="INVESTIGATE_SOON",
        confidence="medium",
        analyst_summary="Test summary.",
        score_breakdown={"severity": 0.55},
        prior_sightings_count=0,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[result],
            alerts=[make_alert()],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        html = Path(out).read_text(encoding="utf-8")
        assert "First seen" in html


def test_search_box_present_in_html():
    """The search box with id='search-box' must be present in the rendered HTML."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        html = Path(out).read_text(encoding="utf-8")
        assert 'id="search-box"' in html


def test_score_distribution_svg_present():
    """The score distribution SVG histogram must be present in the rendered HTML."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "report.html")
        render_report(
            results=[make_result()],
            alerts=[make_alert()],
            run_id="test-run",
            config=SAMPLE_CONFIG,
            output_path=out,
        )
        html = Path(out).read_text(encoding="utf-8")
        assert "<svg" in html
        assert "Score Distribution" in html
