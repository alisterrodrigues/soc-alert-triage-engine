"""Tests for ingestion — CSV and JSON parsing, normalization, and edge cases."""
import csv
import io
import json
import os
import tempfile
from pathlib import Path

import pytest

from ingestion import Alert, _opt_str, _validate_and_build
from ingestion.csv_ingestor import ingest_csv
from ingestion.json_ingestor import ingest_json

SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_ROW = {
    "alert_id": "TEST-001",
    "timestamp": "2026-04-04T10:00:00Z",
    "source_ip": "192.168.1.10",
    "destination_ip": "185.220.101.47",
    "destination_port": "443",
    "alert_name": "Test malware beacon",
    "severity": "high",
    "category": "malware",
    "rule_id": "MAL-001",
    "asset_tags": "server,dc",
    "raw_payload": "",
    "analyst_notes": "",
}


def write_csv(rows: list[dict], tmp_path: Path, headers=None, encoding="utf-8") -> str:
    """Write rows to a temp CSV file and return the path."""
    path = str(tmp_path / "test.csv")
    with open(path, "w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=headers or list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_csv_with_bom(rows: list[dict], tmp_path: Path) -> str:
    """Write rows to a temp CSV file with a UTF-8 BOM prefix."""
    path = str(tmp_path / "test_bom.csv")
    with open(path, "wb") as f:
        content = io.StringIO()
        writer = csv.DictWriter(content, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        f.write(b"\xef\xbb\xbf")  # UTF-8 BOM
        f.write(content.getvalue().encode("utf-8"))
    return path


def write_json(data, tmp_path: Path) -> str:
    """Write data to a temp JSON file and return the path."""
    path = str(tmp_path / "test.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


# ---------------------------------------------------------------------------
# _opt_str unit tests
# ---------------------------------------------------------------------------


def test_opt_str_none_returns_none():
    """Python None must return None — not the string 'None'."""
    assert _opt_str(None) is None


def test_opt_str_empty_string_returns_none():
    """An empty string must return None."""
    assert _opt_str("") is None


def test_opt_str_whitespace_only_returns_none():
    """A whitespace-only string must return None after stripping."""
    assert _opt_str("   ") is None


def test_opt_str_integer_zero_returns_string():
    """Integer 0 must return '0', not None."""
    assert _opt_str(0) == "0"


def test_opt_str_valid_string_stripped():
    """A string with leading/trailing spaces must be stripped."""
    assert _opt_str("  hello  ") == "hello"


# ---------------------------------------------------------------------------
# CSV tests
# ---------------------------------------------------------------------------


def test_csv_valid_row_parses_correctly(tmp_path):
    """A fully valid CSV row should produce one Alert with correct field values."""
    path = write_csv([VALID_ROW], tmp_path)
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_id == "TEST-001"
    assert a.severity == "high"
    assert a.category == "malware"
    assert a.destination_port == 443
    assert "server" in a.asset_tags
    assert "dc" in a.asset_tags


def test_csv_asset_tags_are_lowercased(tmp_path):
    """Asset tags read from CSV must be lowercased so scoring logic matches correctly."""
    row = dict(VALID_ROW)
    row["asset_tags"] = "DC,Server,Cloud"
    path = write_csv([row], tmp_path)
    alerts = ingest_csv(path)
    assert alerts[0].asset_tags == ["dc", "server", "cloud"]


def test_csv_bom_prefix_is_stripped(tmp_path):
    """A UTF-8 BOM at the start of the file must not corrupt the first column name."""
    path = write_csv_with_bom([VALID_ROW], tmp_path)
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    assert alerts[0].alert_id == "TEST-001"  # would be \ufeffTEST-001 without BOM handling


def test_csv_missing_required_field_skips_row(tmp_path):
    """A row with an empty required field should be skipped entirely."""
    row = dict(VALID_ROW)
    row["alert_id"] = ""
    path = write_csv([row], tmp_path)
    assert ingest_csv(path) == []


def test_csv_invalid_severity_defaults_to_low(tmp_path):
    """An unrecognised severity value should be replaced with 'low'."""
    row = dict(VALID_ROW)
    row["severity"] = "urgent"
    path = write_csv([row], tmp_path)
    alerts = ingest_csv(path)
    assert alerts[0].severity == "low"


def test_csv_invalid_port_sets_none(tmp_path):
    """A non-numeric destination_port should result in None, not an error."""
    row = dict(VALID_ROW)
    row["destination_port"] = "not_a_port"
    path = write_csv([row], tmp_path)
    assert ingest_csv(path)[0].destination_port is None


def test_csv_empty_asset_tags_returns_empty_list(tmp_path):
    """An empty asset_tags field must produce [], not ['']."""
    row = dict(VALID_ROW)
    row["asset_tags"] = ""
    path = write_csv([row], tmp_path)
    assert ingest_csv(path)[0].asset_tags == []


def test_csv_file_not_found_returns_empty():
    assert ingest_csv("/nonexistent/path/file.csv") == []


def test_csv_empty_file_returns_empty():
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    assert ingest_csv(path) == []


# ---------------------------------------------------------------------------
# JSON null / None handling tests
# ---------------------------------------------------------------------------


def test_json_null_destination_ip_is_none_not_string(tmp_path):
    """A JSON null for destination_ip must produce None, not the string 'None'."""
    row = dict(VALID_ROW)
    row["destination_ip"] = None
    path = write_json([row], tmp_path)
    alerts = ingest_json(path)
    assert alerts[0].destination_ip is None
    assert alerts[0].destination_ip != "None"


def test_json_null_rule_id_is_none_not_string(tmp_path):
    """A JSON null for rule_id must produce None, not the string 'None'."""
    row = dict(VALID_ROW)
    row["rule_id"] = None
    path = write_json([row], tmp_path)
    alerts = ingest_json(path)
    assert alerts[0].rule_id is None


def test_json_null_analyst_notes_is_none_not_string(tmp_path):
    """A JSON null for analyst_notes must produce None, not the string 'None'."""
    row = dict(VALID_ROW)
    row["analyst_notes"] = None
    path = write_json([row], tmp_path)
    alerts = ingest_json(path)
    assert alerts[0].analyst_notes is None


def test_json_null_raw_payload_is_none_not_string(tmp_path):
    """A JSON null for raw_payload must produce None, not the string 'None'."""
    row = dict(VALID_ROW)
    row["raw_payload"] = None
    path = write_json([row], tmp_path)
    alerts = ingest_json(path)
    assert alerts[0].raw_payload is None


def test_json_asset_tags_are_lowercased(tmp_path):
    """Asset tags in JSON must be lowercased so DC/Server match scoring logic."""
    row = dict(VALID_ROW)
    row["asset_tags"] = "DC,Server"
    path = write_json([row], tmp_path)
    alerts = ingest_json(path)
    assert "dc" in alerts[0].asset_tags
    assert "server" in alerts[0].asset_tags
    assert "DC" not in alerts[0].asset_tags


# ---------------------------------------------------------------------------
# JSON structural tests
# ---------------------------------------------------------------------------


def test_json_valid_array_parses_correctly(tmp_path):
    path = write_json([VALID_ROW], tmp_path)
    alerts = ingest_json(path)
    assert len(alerts) == 1
    assert alerts[0].alert_id == "TEST-001"


def test_json_missing_required_field_skips_item(tmp_path):
    row = dict(VALID_ROW)
    row["source_ip"] = ""
    path = write_json([row], tmp_path)
    assert ingest_json(path) == []


def test_json_not_array_returns_empty(tmp_path):
    path = write_json({"single": "object"}, tmp_path)
    assert ingest_json(path) == []


def test_json_file_not_found_returns_empty():
    assert ingest_json("/nonexistent/path/file.json") == []


def test_json_invalid_severity_defaults_to_low(tmp_path):
    row = dict(VALID_ROW)
    row["severity"] = "CRITICAL_ALERT"
    path = write_json([row], tmp_path)
    assert ingest_json(path)[0].severity == "low"


# ---------------------------------------------------------------------------
# Private IP enrichment skip tests
# ---------------------------------------------------------------------------


def test_private_ip_alert_can_be_ingested(tmp_path):
    """RFC1918 source IPs must ingest correctly — the private IP skip is enrichment-layer only."""
    row = dict(VALID_ROW)
    row["source_ip"] = "10.0.1.5"
    path = write_csv([row], tmp_path)
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.1.5"


# ---------------------------------------------------------------------------
# MITRE ATT&CK field defaults
# ---------------------------------------------------------------------------


def test_alert_mitre_fields_default_to_none(tmp_path):
    """Freshly ingested Alert must have all three MITRE fields as None by default."""
    path = write_csv([VALID_ROW], tmp_path)
    alerts = ingest_csv(path)
    a = alerts[0]
    assert a.mitre_tactic is None
    assert a.mitre_technique is None
    assert a.mitre_technique_name is None


# ---------------------------------------------------------------------------
# Sample data integration tests
# ---------------------------------------------------------------------------


def test_sample_csv_loads_40_alerts():
    """The canonical sample CSV must contain exactly 40 valid alerts."""
    alerts = ingest_csv(str(SAMPLE_DIR / "alerts_sample.csv"))
    assert len(alerts) == 40


def test_sample_json_loads_40_alerts():
    """The canonical sample JSON must contain exactly 40 valid alerts."""
    alerts = ingest_json(str(SAMPLE_DIR / "alerts_sample.json"))
    assert len(alerts) == 40


def test_sample_csv_all_severities_valid():
    """Every alert in the sample CSV must have a valid severity value."""
    alerts = ingest_csv(str(SAMPLE_DIR / "alerts_sample.csv"))
    valid = {"critical", "high", "medium", "low"}
    for a in alerts:
        assert a.severity in valid, f"{a.alert_id} has invalid severity: {a.severity}"


def test_sample_csv_asset_tags_all_lowercase():
    """All asset_tags in the sample CSV must be lowercase after ingestion."""
    alerts = ingest_csv(str(SAMPLE_DIR / "alerts_sample.csv"))
    for a in alerts:
        for tag in a.asset_tags:
            assert tag == tag.lower(), f"{a.alert_id} has non-lowercase tag: {tag}"
