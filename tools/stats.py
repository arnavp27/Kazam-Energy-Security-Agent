"""
tools/stats.py
Event statistics, trend analysis, and period comparisons.
Tool: get_event_statistics
"""

from collections import Counter

from log_loader import EVENTS, REFERENCE_TIME
from tools.auth_analysis import parse_window


def get_event_statistics(time_window: str = "24h") -> list:
    """
    Return event counts and trends for a time window.
    Automatically computes the previous equal period for comparison.
    Handles: 'most common event', 'compare this hour vs last',
             'how many failed logins', 'daily summary'.
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window
    prev_cutoff = cutoff - window  # equal previous period

    current = [e for e in EVENTS if e["_ts"] >= cutoff]
    previous = [e for e in EVENTS if prev_cutoff <= e["_ts"] < cutoff]

    if not current:
        return [{
            "message": f"No events found in the last {time_window}.",
            "severity": "INFO",
            "confidence": "definite",
        }]

    current_counts = Counter(e.get("event_type") for e in current)
    previous_counts = Counter(e.get("event_type") for e in previous)

    most_common_type, most_common_count = current_counts.most_common(1)[0]

    # Failed login trend
    current_failed = current_counts.get("login_failed", 0)
    previous_failed = previous_counts.get("login_failed", 0)
    if previous_failed > 0:
        change_pct = round((current_failed - previous_failed) / previous_failed * 100, 1)
        change_str = f"+{change_pct}%" if change_pct >= 0 else f"{change_pct}%"
    else:
        change_str = "N/A (no prior data)"

    # Peak hour
    hour_counts = Counter(e["_ts"].hour for e in current)
    peak_hour = hour_counts.most_common(1)[0][0] if hour_counts else None
    peak_hour_str = (
        f"{peak_hour:02d}:00–{(peak_hour + 1) % 24:02d}:00"
        if peak_hour is not None else "N/A"
    )

    # By severity level
    level_counts = Counter(e.get("level") for e in current)

    # Top 3 source IPs
    ip_counts = Counter(e.get("ip_address") for e in current if e.get("ip_address"))
    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(3)]

    return [{
        "time_window": time_window,
        "total_events": len(current),
        "previous_period_total": len(previous),
        "by_event_type": dict(current_counts.most_common(10)),
        "most_common_event": most_common_type,
        "most_common_count": most_common_count,
        "failed_logins_current_period": current_failed,
        "failed_logins_previous_period": previous_failed,
        "failed_login_change": change_str,
        "peak_activity_hour": peak_hour_str,
        "by_log_level": dict(level_counts),
        "top_source_ips": top_ips,
        "severity": "INFO",
        "confidence": "definite",
    }]
