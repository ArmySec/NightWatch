# NightWatch — DFIR & Threat Detection Lab

NightWatch is a Python-based cybersecurity project focused on authentication log analysis, suspicious activity detection, and incident reporting.

The project simulates a basic Blue Team workflow by analyzing authentication events, identifying repeated failed login attempts, building a chronological event timeline, and generating structured JSON incident reports.

## Features

- **Authentication Log Analysis:** Load and process authentication events from JSON files.
- **Threat Detection:** Identify repeated failed login attempts from the same source IP within a configurable time window.
- **Event Timeline:** Sort authentication events chronologically to support incident investigation.
- **Incident Reporting:** Generate structured JSON reports containing alerts, timelines, and investigation limitations.
- **Automated Testing:** Validate detection logic, timestamp handling, timeline generation, and report creation with pytest.
- **Synthetic Training Data:** Use sample events designed for safe testing and investigation practice.

## Project Status

NightWatch is an educational project under active development. It is designed to demonstrate foundational Blue Team, threat detection, and Digital Forensics and Incident Response (DFIR) concepts.

## Disclaimer

This project uses synthetic training data. Generated alerts indicate potentially suspicious activity and do not independently confirm a security incident or system compromise.


## Requirements

- Python 3
- `pytest` for running the test suite

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd NightWatch
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install pytest:

```bash
python -m pip install pytest
```

## Usage

Run the authentication event analysis:

```bash
python -m src.nightwatch.detections
```

NightWatch loads the sample authentication events, detects repeated login failures, builds a chronological timeline, and generates an incident report.

The generated report is saved to:

```text
reports/sample-incident/alerts.json
```

## Example Detection

Using the included synthetic dataset, NightWatch detects three failed login attempts from the same source IP within five minutes.

| Field | Result |
|---|---|
| Detection rule | `REPEATED_LOGIN_FAILURES` |
| Source IP | `192.0.2.10` |
| Failed attempts | 3 |
| Time window | 5 minutes |
| Severity | Medium |

The alert identifies suspicious authentication activity for further investigation. It does not establish that an account was compromised.

## Running Tests

Run the automated test suite from the project root:

```bash
python -m pytest -v
```

The current test suite contains 13 tests covering detection logic, timestamp validation, event timelines, and incident report generation.

## Project Structure

```text
NightWatch/
├── data/
│   └── sample/
│       └── auth_events.json
├── docs/
├── reports/
│   └── sample-incident/
├── rules/
│   └── sigma/
├── screenshots/
├── src/
│   └── nightwatch/
│       ├── detections.py
│       ├── reporting.py
│       └── timeline.py
└── tests/
    ├── test_detections.py
    └── test_timeline.py
```
