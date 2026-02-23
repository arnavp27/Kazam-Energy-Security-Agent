"""
tools/access_analysis.py
Identifies anomalous access patterns: new locations, session hijacking, odd-hours access.
Tool: check_unusual_access
"""

from collections import defaultdict

from log_loader import EVENTS, REFERENCE_TIME
from tools.auth_analysis import parse_window


def check_unusual_access(
    user_id: str = None,
    time_window: str = "24h",
) -> list:
    """
    Detect:
    - Session hijacking (event_type = session_hijack_suspected)
    - New IP / location for a known user
    - Access at unusual hours (midnight–6 AM)
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window

    # All events in window (optionally filtered by user)
    window_events = [
        e for e in EVENTS
        if e["_ts"] >= cutoff
        and e.get("user_id")
    ]
    if user_id:
        window_events = [e for e in window_events if e.get("user_id") == user_id]

    if not window_events:
        return []

    findings = []
    flagged_users: set = set()

    # === 1. Session Hijack Events (already flagged in logs) ===
    for e in window_events:
        if e.get("event_type") != "session_hijack_suspected":
            continue
        uid = e.get("user_id")
        meta = e.get("metadata", {})
        findings.append({
            "anomaly_type": "session_hijack_suspected",
            "user_id": uid,
            "current_ip": e.get("ip_address"),
            "previous_ip": meta.get("previous_ip"),
            "time_delta_seconds": meta.get("time_delta_seconds"),
            "first_seen": e["timestamp"],
            "last_seen": e["timestamp"],
            "severity": "CRITICAL",
            "confidence": meta.get("confidence", "high"),
            "recommendation": (
                f"Immediately invalidate all sessions for {uid}, "
                "force re-authentication, check for concurrent sessions"
            ),
            "false_positive_note": "Could be legitimate VPN reconnection or IP change",
        })
        flagged_users.add(uid)

    # === 2. New Location Detection ===
    # Build pre-window location baseline per user
    pre_window_locations: dict = defaultdict(set)
    for e in EVENTS:
        if e["_ts"] >= cutoff:
            break  # events are sorted, stop when we hit the window
        uid = e.get("user_id")
        loc = e.get("metadata", {}).get("location_hint")
        if uid and loc:
            pre_window_locations[uid].add(loc)

    # Collect locations seen in window per user
    window_locations: dict = defaultdict(lambda: {"locations": set(), "events": []})
    for e in window_events:
        uid = e.get("user_id")
        loc = e.get("metadata", {}).get("location_hint")
        if loc:
            window_locations[uid]["locations"].add(loc)
        window_locations[uid]["events"].append(e)

    for uid, data in window_locations.items():
        if uid in flagged_users:
            continue

        pre_locs = pre_window_locations.get(uid, set())
        new_locs = data["locations"] - pre_locs

        # Only flag if user has a known history AND a new location appears
        if not new_locs or not pre_locs:
            continue

        user_events = sorted(data["events"], key=lambda e: e["_ts"])
        findings.append({
            "anomaly_type": "new_location",
            "user_id": uid,
            "new_locations": list(new_locs),
            "known_locations": list(pre_locs),
            "first_seen": user_events[0]["timestamp"],
            "last_seen": user_events[-1]["timestamp"],
            "severity": "MEDIUM",
            "confidence": "probable",
            "recommendation": f"Verify session legitimacy with {uid}",
            "false_positive_note": "Could be VPN, business travel, or remote work",
        })
        flagged_users.add(uid)

    # === 3. Odd-Hours Access (midnight–6 AM) ===
    odd_by_user: dict = defaultdict(list)
    for e in window_events:
        if e.get("event_type") not in ("login_success", "api_access"):
            continue
        if 0 <= e["_ts"].hour < 6:
            odd_by_user[e.get("user_id")].append(e)

    for uid, events in odd_by_user.items():
        if uid in flagged_users or len(events) < 2:
            continue
        events_sorted = sorted(events, key=lambda e: e["_ts"])
        findings.append({
            "anomaly_type": "odd_hours_access",
            "user_id": uid,
            "event_count": len(events),
            "access_times": [e["timestamp"] for e in events_sorted[:5]],
            "first_seen": events_sorted[0]["timestamp"],
            "last_seen": events_sorted[-1]["timestamp"],
            "severity": "LOW",
            "confidence": "possible",
            "recommendation": f"Review if off-hours access is expected for {uid}",
            "false_positive_note": "Could be different timezone, on-call rotation, or scheduled job",
        })

    return findings
