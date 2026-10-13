from src.nightwatch.reporting import generate_incident_report
import json
from datetime import datetime, timedelta, timezone

import pytest

from src.nightwatch.detections import detect_repeated_failures


def make_event(event_type, source_ip, timestamp):
    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "timestamp": timestamp.isoformat(),
    }


def test_detects_repeated_failures():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", "192.0.2.10", start),
        make_event("login_failure", "192.0.2.10", start + timedelta(seconds=8)),
        make_event("login_failure", "192.0.2.10", start + timedelta(seconds=15)),
    ]

    alerts = detect_repeated_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.10"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["window_minutes"] == 5


def test_ignores_single_failure():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", "192.0.2.30", start),
    ]

    assert detect_repeated_failures(events) == []

def test_rejects_timestamp_without_timezone():
    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.0.2.10",
            "timestamp": "2026-10-13T10:00:00",
        }
    ]

    with pytest.raises(ValueError, match="timezone"):
        detect_repeated_failures(events)
def test_ignores_successful_logins():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_success", "192.0.2.10", start),
        make_event("login_success", "192.0.2.10", start + timedelta(seconds=5)),
        make_event("login_success", "192.0.2.10", start + timedelta(seconds=10)),
    ]

    assert detect_repeated_failures(events) == []


def test_rejects_invalid_threshold():
    with pytest.raises(ValueError):
        detect_repeated_failures([], threshold=0)


def test_failures_outside_time_window_do_not_alert():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", "192.0.2.10", start),
        make_event("login_failure", "192.0.2.10", start + timedelta(minutes=6)),
        make_event("login_failure", "192.0.2.10", start + timedelta(minutes=12)),
    ]

    assert detect_repeated_failures(events) == []


def test_saved_alert_report_is_valid_json(tmp_path):
    alerts = [
        {
            "rule": "REPEATED_LOGIN_FAILURES",
            "source_ip": "192.0.2.10",
            "failed_attempts": 3,
            "window_minutes": 5,
            "severity": "medium",
        }
    ]

    report_file = tmp_path / "alerts.json"
    report_file.write_text(json.dumps(alerts), encoding="utf-8")

    loaded_alerts = json.loads(
        report_file.read_text(encoding="utf-8")
    )

    assert loaded_alerts == alerts


def test_generate_incident_report(tmp_path):
    alerts = [
        {
            "rule": "REPEATED_LOGIN_FAILURES",
            "source_ip": "192.0.2.10",
            "failed_attempts": 3,
            "window_minutes": 5,
            "severity": "medium",
        }
    ]

    timeline = [
        {
            "timestamp": "2026-10-13T10:00:00Z",
            "event_type": "login_failure",
            "source_ip": "192.0.2.10",
        },
        {
            "timestamp": "2026-10-13T10:00:08Z",
            "event_type": "login_failure",
            "source_ip": "192.0.2.10",
        },
    ]

    report_file = tmp_path / "sample-incident" / "report.json"

    report = generate_incident_report(
        alerts,
        report_file,
        timeline=timeline,
    )

    assert report_file.exists()
    assert report["report_title"] == "NightWatch Incident Report"
    assert report["total_alerts"] == 1
    assert report["alerts"] == alerts
    assert report["timeline"] == timeline
    assert len(report["timeline"]) == 2

    saved_report = json.loads(
        report_file.read_text(encoding="utf-8")
    )

    assert saved_report == report

def test_failures_from_different_ips_do_not_trigger_alert():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", "192.0.2.10", start),
        make_event("login_failure", "192.0.2.20", start + timedelta(seconds=5)),
        make_event("login_failure", "192.0.2.30", start + timedelta(seconds=10)),
    ]

    assert detect_repeated_failures(events) == []

def test_failures_at_exact_window_boundary_trigger_alert():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", "192.0.2.10", start),
        make_event("login_failure", "192.0.2.10", start + timedelta(minutes=2)),
        make_event("login_failure", "192.0.2.10", start + timedelta(minutes=5)),
    ]

    alerts = detect_repeated_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 3
