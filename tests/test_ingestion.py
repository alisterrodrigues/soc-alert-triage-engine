import csv
import json
import os
import tempfile

import pytest

from ingestion import Alert
from ingestion.csv_ingestor import ingest_csv
from ingestion.json_ingestor import ingest_json

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


def write_csv(rows: list[dict], headers=None) -> str:
    """Write rows to a temp CSV file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers or list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_json(data) -> str:
    """Write data to a temp JSON file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


# ---------------------------------------------------------------------------
# CSV tests
# ---------------------------------------------------------------------------

def test_csv_valid_row_parses_correctly():
    """A fully valid CSV row should produce one Alert with correct field values."""
    path = write_csv([VALID_ROW])
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_id == "TEST-001"
    assert a.severity == "high"
    assert a.category == "malware"
    assert a.destination_port == 443
    assert "server" in a.asset_tags
    assert "dc" in a.asset_tags


def test_csv_missing_required_field_skips_row():
    """A row with an empty required field should be skipped entirely."""
    row = dict(VALID_ROW)
    row["alert_id"] = ""
    path = write_csv([row])
    alerts = ingest_csv(path)
    assert alerts == []


def test_csv_invalid_severity_defaults_to_low():
    """An unrecognised severity value should be replaced with 'low'."""
    row = dict(VALID_ROW)
    row["severity"] = "urgent"
    path = write_csv([row])
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    assert alerts[0].severity == "low"


def test_csv_invalid_port_sets_none():
    """A non-numeric destination_port should result in None, not an error."""
    row = dict(VALID_ROW)
    row["destination_port"] = "not_a_port"
    path = write_csv([row])
    alerts = ingest_csv(path)
    assert len(alerts) == 1
    assert alerts[0].destination_port is None


def test_csv_empty_asset_tags_returns_empty_list():
    """An empty asset_tags field should produce an empty list, not a list with one empty string."""
    row = dict(VALID_ROW)
    row["asset_tags"] = ""
    path = write_csv([row])
    alerts = ingest_csv(path)
    assert alerts[0].asset_tags == []


def test_csv_file_not_found_returns_empty():
    """A path that does not exist should return an empty list without raising."""
    alerts = ingest_csv("/nonexistent/path/file.csv")
    assert alerts == []


def test_csv_empty_file_returns_empty():
    """A CSV file with no rows (only optional header or truly empty) should return []."""
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    alerts = ingest_csv(path)
    assert alerts == []


# ---------------------------------------------------------------------------
# JSON tests
# ---------------------------------------------------------------------------

def test_json_valid_array_parses_correctly():
    """A JSON array with one valid object should produce one Alert."""
    path = write_json([VALID_ROW])
    alerts = ingest_json(path)
    assert len(alerts) == 1
    assert alerts[0].alert_id == "TEST-001"


def test_json_missing_required_field_skips_item():
    """A JSON object missing a required field should be skipped."""
    row = dict(VALID_ROW)
    row["source_ip"] = ""
    path = write_json([row])
    alerts = ingest_json(path)
    assert alerts == []


def test_json_not_array_returns_empty():
    """A JSON file whose root is not an array should return an empty list."""
    path = write_json({"single": "object"})
    alerts = ingest_json(path)
    assert alerts == []


def test_json_file_not_found_returns_empty():
    """A path that does not exist should return an empty list without raising."""
    alerts = ingest_json("/nonexistent/path/file.json")
    assert alerts == []


def test_json_invalid_severity_defaults_to_low():
    """An unrecognised severity value in JSON should be replaced with 'low'."""
    row = dict(VALID_ROW)
    row["severity"] = "CRITICAL_ALERT"
    path = write_json([row])
    alerts = ingest_json(path)
    assert alerts[0].severity == "low"


# ---------------------------------------------------------------------------
# Sample data integration tests
# ---------------------------------------------------------------------------

def test_sample_csv_loads_40_alerts():
    """The canonical sample CSV must contain exactly 40 valid alerts."""
    alerts = ingest_csv("sample_data/alerts_sample.csv")
    assert len(alerts) == 40


def test_sample_json_loads_40_alerts():
    """The canonical sample JSON must contain exactly 40 valid alerts."""
    alerts = ingest_json("sample_data/alerts_sample.json")
    assert len(alerts) == 40
