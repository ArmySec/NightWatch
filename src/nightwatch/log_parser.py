import ipaddress
import re
from datetime import datetime, timezone


SSH_LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<action>Failed password|Accepted password|Invalid user)\s+"
    r"(?:for\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"port\s+\d+(?:\s+ssh2)?$"
)


def parse_ssh_line(line, year=None):
    match = SSH_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    if year is None:
        year = datetime.now(timezone.utc).year

    data = match.groupdict()
    try:
        ipaddress.IPv4Address(data["source_ip"])
    except ipaddress.AddressValueError:
        return None
    try:
        timestamp = datetime.strptime(
            f"{year} {data['month']} {data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    event_type = (
         "login_failure"
         if data["action"] in ("Failed password", "Invalid user")
         else "login_success"
    )

    return {
        "timestamp": timestamp.replace(tzinfo=timezone.utc).isoformat(),
        "source": "sshd",
        "event_type": event_type,
        "username": data["username"],
        "source_ip": data["source_ip"],
    }


def parse_ssh_file(file_path, year=None):
    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_ssh_line(line, year=year)

            if event is not None:
                events.append(event)

    return events
