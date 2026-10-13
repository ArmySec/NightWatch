
import json
from pathlib import Path


def generate_incident_report(
    alerts,
    output_file,
    timeline=None,
):
    """Save alerts and an optional event timeline in one report."""
    report = {
        "report_title": "NightWatch Incident Report",
        "total_alerts": len(alerts),
        "alerts": alerts,
        "timeline": timeline if timeline is not None else [],
        "limitations": [
            "This report is based on synthetic training data.",
            "An alert indicates suspicious activity, not confirmed compromise.",
            "Events from different source IPs are not assumed to be related.",
        ],
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report

