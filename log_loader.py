"""
log_loader.py
Loads all three log files into memory once at import time.
All tool functions import EVENTS and REFERENCE_TIME from here.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).parent / "security_logs"
LOG_FILES = [
    LOG_DIR / "auth_service.log",
    LOG_DIR / "api_gateway.log",
    LOG_DIR / "admin_panel.log",
]


def load_logs() -> tuple:
    """
    Parse all log files into a list of dicts.
    Each event gets a '_ts' key (parsed datetime) for fast time filtering.
    Returns (events, reference_time) where reference_time = latest timestamp.
    """
    events = []

    for path in LOG_FILES:
        if not path.exists():
            print(f"[log_loader] Warning: {path.name} not found, skipping.")
            continue

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    # Parse timestamp — handle both 'Z' and '+00:00' suffixes
                    ts_str = event.get("timestamp", "")
                    ts_str = ts_str.replace("Z", "+00:00")
                    event["_ts"] = datetime.fromisoformat(ts_str)
                    events.append(event)
                except (json.JSONDecodeError, ValueError, KeyError):
                    # Skip malformed lines silently
                    continue

    if not events:
        raise RuntimeError(
            f"No log events loaded. Check that log files exist in: {LOG_DIR}"
        )

    # Sort chronologically
    events.sort(key=lambda e: e["_ts"])

    # Reference time = latest timestamp in logs
    # This is "now" for all time-window calculations
    reference_time = events[-1]["_ts"]

    print(
        f"[log_loader] Loaded {len(events)} events from {len(LOG_FILES)} files. "
        f"Reference time: {reference_time.isoformat()}"
    )

    return events, reference_time


# --- Singleton: loaded once, reused by all tools ---
EVENTS, REFERENCE_TIME = load_logs()


def get_events_in_window(time_window_str: str) -> list:
    """
    Convenience helper: return events within the given time window
    measured back from REFERENCE_TIME.
    time_window_str examples: '1h', '6h', '24h', '7d', '30m'
    """
    from tools.auth_analysis import parse_window
    delta = parse_window(time_window_str)
    cutoff = REFERENCE_TIME - delta
    return [e for e in EVENTS if e["_ts"] >= cutoff]
