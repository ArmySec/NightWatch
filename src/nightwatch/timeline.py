import json
from pathlib import Path
from datetime import datetime


def build_timeline(events):
    """Return events sorted chronologically by timestamp."""
    timeline = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a JSON object")

        timestamp = event.get("timestamp")

        if not isinstance(timestamp, str):
            raise ValueError("Timestamp must be a string")

        try:
            parsed_timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid timestamp: {timestamp}"
            ) from exc

        if parsed_timestamp.utcoffset() is None:
            raise ValueError(
                "Timestamp must include a timezone"
            )

        timeline.append((parsed_timestamp, event))

    timeline.sort(key=lambda item: item[0])

    return [event for _, event in timeline]


def save_timeline(events, output_file):
    """Build and save a chronological timeline as JSON."""
    timeline = build_timeline(events)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(timeline, file, indent=2)

    return timeline

def load_events(file_path):
    """Load authentication events from a JSON file."""
    with Path(file_path).open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Expected a JSON list of events")

    return events

def main():
    project_root = Path(__file__).resolve().parents[2]

    events_file = (
        project_root / "data" / "sample" / "auth_events.json"
    )

    timeline_file = (
        project_root
        / "reports"
        / "sample-incident"
        / "timeline.json"
    )

    events = load_events(events_file)
    timeline = save_timeline(events, timeline_file)

    print(f"Events processed: {len(timeline)}")
    print(f"Timeline saved to: {timeline_file.relative_to(project_root)}")


if __name__ == "__main__":
    main()
