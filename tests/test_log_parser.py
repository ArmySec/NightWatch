
from src.nightwatch.log_parser import parse_ssh_line


def test_parse_failed_ssh_login():
    line = (
        "Oct 13 10:00:00 server sshd[1234]: "
        "Failed password for analyst from 192.0.2.10 port 54321 ssh2"
    )

    event = parse_ssh_line(line, year=2026)

    assert event["event_type"] == "login_failure"
    assert event["username"] == "analyst"
    assert event["source_ip"] == "192.0.2.10"
    assert event["timestamp"] == "2026-10-13T10:00:00+00:00"


def test_parse_successful_ssh_login():
    line = (
        "Oct 13 10:00:30 server sshd[1235]: "
        "Accepted password for analyst from 192.0.2.10 port 54322 ssh2"
    )

    event = parse_ssh_line(line, year=2026)

    assert event["event_type"] == "login_success"
    assert event["username"] == "analyst"
    assert event["source_ip"] == "192.0.2.10"


def test_reject_unsupported_ssh_line():
    line = "This is not a valid SSH authentication log"

    assert parse_ssh_line(line, year=2026) is None


def test_parsed_ssh_events_do_not_alert_below_threshold(tmp_path):
    from src.nightwatch.detections import (
        detect_repeated_failures,
        detect_success_after_repeated_failures,
    )

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Oct 13 10:00:00 server sshd[1234]: "
        "Failed password for analyst from 192.0.2.40 port 54321 ssh2\n"
        "Oct 13 10:00:30 server sshd[1235]: "
        "Accepted password for analyst from 192.0.2.40 port 54322 ssh2\n",
        encoding="utf-8",
    )

    from src.nightwatch.log_parser import parse_ssh_file

    events = parse_ssh_file(log_file, year=2026)

    assert len(events) == 2
    assert detect_repeated_failures(events) == []
    assert detect_success_after_repeated_failures(events) == []

def test_reject_invalid_ipv4_address():
    line = (
        "Oct 13 10:00:00 server sshd[1234]: "
        "Failed password for analyst "
        "from 999.999.999.999 port 54321 ssh2"
    )

    assert parse_ssh_line(line, year=2026) is None
