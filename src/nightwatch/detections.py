from src.nightwatch.log_parser import parse_ssh_file
from src.nightwatch.timeline import build_timeline
from src.nightwatch.reporting import generate_incident_report
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path


def load_events(file_path):
    """Load authentication events from a JSON file."""
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Expected a JSON list of events")

    return events


def parse_timestamp(value):
    """Parse an ISO 8601 timestamp, including the Z suffix."""
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {value}") from exc

    if parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")

    return parsed


def detect_repeated_failures(
    events,
    threshold=3,
    window_minutes=5,
):
    """Detect repeated failed logins from one IP within a time window."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("Window must be greater than 0")

    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a JSON object")

        if event.get("event_type") != "login_failure":
            continue

        source_ip = event.get("source_ip")

        if not isinstance(source_ip, str) or not source_ip.strip():
            continue

        timestamp = parse_timestamp(event.get("timestamp"))
        failures_by_ip[source_ip].append(timestamp)

    alerts = []

    for source_ip, timestamps in sorted(failures_by_ip.items()):
        timestamps.sort()
        recent = deque()

        for timestamp in timestamps:
            while recent and timestamp - recent[0] > window:
                recent.popleft()

            recent.append(timestamp)

            if len(recent) == threshold:
                alerts.append({
                    "rule": "REPEATED_LOGIN_FAILURES",
                    "source_ip": source_ip,
                    "failed_attempts": threshold,
                    "window_minutes": window_minutes,
                    "first_seen": recent[0].isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "severity": "medium",
                })
                break

    return alerts



def main():
    project_root = Path(__file__).resolve().parents[2]
    events_file = (
        project_root / "data" / "sample" / "auth_events.json"
    )
    ssh_log_file = (
        project_root / "data" / "sample" / "ssh-logs" / "auth.log"
    )
    report_file = (
        project_root
        / "reports"
        / "sample-incident"
        / "alerts.json"
    )

    events = load_events(events_file)
    events.extend(parse_ssh_file(ssh_log_file, year=2026))

    alerts = (
        detect_repeated_failures(events)
        + detect_success_after_repeated_failures(events)
    )

    timeline = build_timeline(events)

    report_file.parent.mkdir(parents=True, exist_ok=True)

    generate_incident_report(
        alerts,
        report_file,
        timeline=timeline,
    )

    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Report saved to: {report_file.relative_to(project_root)}")

    for alert in alerts:
        print(json.dumps(alert, indent=2))



def detect_success_after_repeated_failures(
    events,
    threshold=3,
    window_minutes=5,
):
    """Detect a successful login after repeated failures from the same IP."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("Window must be greater than 0")

    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(deque)
    alerts = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a JSON object")

    sorted_events = sorted(
        events,
        key=lambda event: parse_timestamp(event.get("timestamp")),
    )

    for event in sorted_events:

        source_ip = event.get("source_ip")

        if not isinstance(source_ip, str) or not source_ip.strip():
            continue

        timestamp = parse_timestamp(event.get("timestamp"))
        recent = failures_by_ip[source_ip]

        while recent and timestamp - recent[0] > window:
            recent.popleft()

        if event.get("event_type") == "login_failure":
            recent.append(timestamp)

        elif (
            event.get("event_type") == "login_success"
            and len(recent) >= threshold
        ):
            alerts.append({
                "rule": "SUCCESS_AFTER_REPEATED_FAILURES",
                "source_ip": source_ip,
                "failed_attempts": len(recent),
                "window_minutes": window_minutes,
                "first_seen": recent[0].isoformat(),
                "last_seen": timestamp.isoformat(),
                "severity": "high",
            })

            # Clear the failure window to avoid duplicate alerts
            # from the same series of failures.
            recent.clear()

    return alerts

if __name__ == "__main__":
    main()

