from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import re

# Detection configuration
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

# Expected log format:
# 2026-10-27 10:15:01 LOGIN_FAILED user=admin ip=192.0.2.10

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<event>[A-Z_]+) "
    r"user=(?P<user>\S+) "
    r"ip=(?P<ip>\S+)$"
)


def parse_log_line(line):
    """Parse one security log entry."""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    try:
        data["timestamp"] = datetime.strptime(
            data["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return data


def analyze_logs(log_path):
    """Analyze a log file and return events, alerts, and statistics."""
    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    events = []
    invalid_lines = 0

    with path.open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            if not line.strip():
                continue

            event = parse_log_line(line)

            if event is None:
                invalid_lines += 1
                continue

            events.append(event)

    alerts = []
    failed_by_ip = defaultdict(list)

    for event in events:
        if event["event"] == "LOGIN_FAILED":
            failed_by_ip[event["ip"]].append(event)

    # Detect repeated failed login attempts from one IP.
    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda item: item["timestamp"])

        left = 0

        for right, current in enumerate(failures):
            while (
                current["timestamp"]
                - failures[left]["timestamp"]
            ).total_seconds() > TIME_WINDOW_MINUTES * 60:
                left += 1

            count = right - left + 1

            if count >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "title": "Repeated Failed Login Attempts",
                    "severity": "High",
                    "source": ip,
                    "description": (
                        f"{count} failed login attempts were observed "
                        "from this IP within a five-minute window."
                    ),
                    "recommendation": (
                        "Review authentication logs, verify whether "
                        "the activity is legitimate, and consider "
                        "rate limiting."
                    ),
                    "timestamp": current["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                })

                # Generate only one alert for this IP.
                break

    # Calculate event statistics.
    event_counts = Counter(
        event["event"] for event in events
    )

    statistics = {
        "total_events": len(events),
        "failed_logins": event_counts["LOGIN_FAILED"],
        "successful_logins": event_counts["LOGIN_SUCCESS"],
        "other_events": sum(
            count
            for event_name, count in event_counts.items()
            if event_name not in {
                "LOGIN_FAILED", "LOGIN_SUCCESS"
            }
        ),
        "invalid_lines": invalid_lines,
        "alerts_generated": len(alerts),
    }

    return {
        "events": events,
        "alerts": alerts,
        "statistics": statistics,
    }