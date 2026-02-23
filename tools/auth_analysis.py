"""
tools/auth_analysis.py
Detects brute force attacks and credential stuffing patterns.
Tool: detect_failed_login_patterns
"""

from collections import defaultdict
from datetime import timedelta

from log_loader import EVENTS, REFERENCE_TIME


def parse_window(time_window: str) -> timedelta:
    """Convert '1h', '6h', '24h', '7d', '30m' to timedelta."""
    time_window = time_window.strip().lower()
    unit = time_window[-1]
    try:
        value = int(time_window[:-1])
    except ValueError:
        return timedelta(hours=1)  # safe default

    if unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)
    elif unit == "m":
        return timedelta(minutes=value)
    return timedelta(hours=1)


def detect_failed_login_patterns(
    time_window: str = "1h",
    threshold: int = 5,
) -> list:
    """
    Detect brute force (same IP → many attempts) and
    credential stuffing (many IPs → same user).
    Also performs persistence check: did any targeted user
    successfully log in after the failed attempts?
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window

    failed = [
        e for e in EVENTS
        if e.get("event_type") == "login_failed"
        and e["_ts"] >= cutoff
    ]

    if not failed:
        return []

    # --- Build lookup sets for cross-referencing ---
    successes_in_window = {
        e.get("user_id")
        for e in EVENTS
        if e.get("event_type") == "login_success"
        and e["_ts"] >= cutoff
    }
    locked_in_window = {
        e.get("user_id")
        for e in EVENTS
        if e.get("event_type") == "account_locked"
        and e["_ts"] >= cutoff
    }

    # --- Group by IP (volume / brute force attack) ---
    by_ip: dict = defaultdict(list)
    for e in failed:
        by_ip[e.get("ip_address", "unknown")].append(e)

    # --- Group by user (credential stuffing) ---
    by_user: dict = defaultdict(lambda: {"events": [], "ips": set()})
    for e in failed:
        uid = e.get("user_id", "unknown")
        by_user[uid]["events"].append(e)
        by_user[uid]["ips"].add(e.get("ip_address", "unknown"))

    findings = []

    # === Volume Attack: same IP, many targets ===
    for ip, events in by_ip.items():
        if len(events) < threshold:
            continue

        targeted_users = list({e.get("user_id") for e in events})
        events_sorted = sorted(events, key=lambda e: e["_ts"])
        first_ts = events_sorted[0]["_ts"]
        last_ts = events_sorted[-1]["_ts"]
        duration_minutes = (last_ts - first_ts).total_seconds() / 60

        any_locked = any(u in locked_in_window for u in targeted_users)
        any_succeeded = any(u in successes_in_window for u in targeted_users)

        # Severity: CRITICAL if dense burst, escalate if attacker succeeded
        if any_succeeded:
            severity = "CRITICAL"
            confidence = "definite"
        elif len(events) >= 5 and duration_minutes <= 5:
            severity = "CRITICAL"
            confidence = "definite"
        elif len(events) >= 10:
            severity = "HIGH"
            confidence = "definite"
        else:
            severity = "MEDIUM"
            confidence = "probable"

        recommendation = f"Block IP {ip}"
        if any_succeeded:
            recommendation += f", URGENT: investigate compromised account(s): {', '.join(targeted_users)}"
        elif any_locked:
            recommendation += ", accounts have been auto-locked"

        findings.append({
            "attack_type": "volume_attack",
            "ip_address": ip,
            "targeted_users": targeted_users,
            "attempt_count": len(events),
            "first_seen": events_sorted[0]["timestamp"],
            "last_seen": events_sorted[-1]["timestamp"],
            "duration_minutes": round(duration_minutes, 1),
            "account_locked": any_locked,
            "subsequently_succeeded": any_succeeded,
            "severity": severity,
            "confidence": confidence,
            "recommendation": recommendation,
            "false_positive_note": "Could be shared corporate IP, proxy, or NAT gateway",
        })

    # === Credential Stuffing: many IPs → same user ===
    for uid, data in by_user.items():
        unique_ips = data["ips"]
        events = sorted(data["events"], key=lambda e: e["_ts"])

        # Need 3+ different IPs targeting same user to flag stuffing
        if len(unique_ips) < 3 or len(events) < threshold:
            continue

        is_locked = uid in locked_in_window
        is_compromised = uid in successes_in_window

        severity = "CRITICAL" if is_compromised else "HIGH"

        findings.append({
            "attack_type": "credential_stuffing",
            "targeted_user": uid,
            "source_ip_count": len(unique_ips),
            "source_ips": list(unique_ips),
            "attempt_count": len(events),
            "first_seen": events[0]["timestamp"],
            "last_seen": events[-1]["timestamp"],
            "account_locked": is_locked,
            "subsequently_succeeded": is_compromised,
            "severity": severity,
            "confidence": "probable",
            "recommendation": (
                f"URGENT: force password reset for {uid}, enable MFA, invalidate all sessions"
                if is_compromised
                else f"Force password reset for {uid}, enable MFA"
            ),
            "false_positive_note": "Could be user on mobile/VPN switching IPs frequently",
        })

    return findings
