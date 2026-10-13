import json
from src.nightwatch.timeline import save_timeline
from datetime import datetime, timedelta, timezone

import pytest

from src.nightwatch.timeline import build_timeline


def make_event(event_type, timestamp):
    return {
        "event_type": event_type,
        "source_ip": "192.0.2.10",
        "timestamp": timestamp.isoformat(),
    }


def test_sorts_events_chronologically():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_success", start + timedelta(minutes=2)),
        make_event("login_failure", start),
        make_event("login_failure", start + timedelta(minutes=1)),
    ]

    timeline = build_timeline(events)

    assert [
        event["event_type"] for event in timeline
    ] == [
        "login_failure",
        "login_failure",
        "login_success",
    ]


def test_keeps_already_sorted_events():
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_failure", start),
        make_event("login_success", start + timedelta(minutes=1)),
    ]

    assert build_timeline(events) == events


def test_rejects_timestamp_without_timezone():
    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.0.2.10",
            "timestamp": "2026-10-13T10:00:00",
        }
    ]

    with pytest.raises(ValueError, match="timezone"):
        build_timeline(events)


def test_rejects_invalid_timestamp():
    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.0.2.10",
            "timestamp": "not-a-timestamp",
        }
    ]

    with pytest.raises(ValueError, match="Invalid timestamp"):
        build_timeline(events)

def test_saves_timeline_as_json(tmp_path):
    start = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event("login_success", start + timedelta(minutes=1)),
        make_event("login_failure", start),
    ]

    output_file = tmp_path / "reports" / "timeline.json"

    timeline = save_timeline(events, output_file)

    assert output_file.exists()
    assert timeline[0]["event_type"] == "login_failure"

    saved_timeline = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert saved_timeline == timeline
