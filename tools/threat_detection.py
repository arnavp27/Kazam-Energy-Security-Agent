"""
tools/threat_detection.py
Tracks admin actions, privilege escalations, config changes, sensitive data access.
Also detects API rate limit abuse and web application attacks (SQLi, XSS, path traversal).
Tools: audit_privilege_actions, analyze_rate_limit_violations, detect_web_attacks
"""

from collections import defaultdict

from log_loader import EVENTS, REFERENCE_TIME
from tools.auth_analysis import parse_window

# Admin actions considered high-risk
HIGH_RISK_ACTIONS = {
    "user_deleted", "permissions_modified", "data_exported",
    "system_config", "bulk_delete", "role_assigned",
}


def audit_privilege_actions(
    time_window: str = "24h",
    severity: str = "all",
) -> list:
    """
    Track privilege escalations, sensitive data access,
    configuration changes, and admin panel actions.
    severity filter: 'all' | 'high' | 'critical'
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window

    target_types = {
        "privilege_escalation",
        "sensitive_data_access",
        "config_changed",
        "admin_action",
    }

    events = [
        e for e in EVENTS
        if e["_ts"] >= cutoff
        and e.get("event_type") in target_types
    ]

    if not events:
        return []

    findings = []

    for e in events:
        etype = e.get("event_type")
        meta = e.get("metadata", {})
        uid = e.get("user_id", "unknown")
        ip = e.get("ip_address", "unknown")

        if etype == "privilege_escalation":
            from_role = meta.get("from_role", "unknown")
            to_role = meta.get("to_role", "unknown")
            granted_by = meta.get("granted_by", "unknown")
            sev = "HIGH" if to_role in ("admin", "superuser") else "MEDIUM"

            findings.append({
                "event_type": "privilege_escalation",
                "user_id": uid,
                "ip_address": ip,
                "from_role": from_role,
                "to_role": to_role,
                "granted_by": granted_by,
                "reason": meta.get("reason"),
                "timestamp": e["timestamp"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "severity": sev,
                "confidence": "definite",
                "recommendation": (
                    f"Verify privilege grant for {uid} with approver {granted_by}. "
                    "Check if this escalation was planned/authorized."
                ),
            })

        elif etype == "sensitive_data_access":
            record_count = meta.get("record_count", 0)
            data_type = meta.get("data_type", "unknown")
            action = meta.get("action", "accessed")
            sev = "HIGH" if record_count > 50 else "MEDIUM"

            findings.append({
                "event_type": "sensitive_data_access",
                "user_id": uid,
                "ip_address": ip,
                "data_type": data_type,
                "action": action,
                "record_count": record_count,
                "timestamp": e["timestamp"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "severity": sev,
                "confidence": "definite",
                "recommendation": (
                    f"Verify {uid} is authorized to {action} {record_count} "
                    f"{data_type} records. Review data access policy."
                ),
            })

        elif etype == "config_changed":
            setting = meta.get("setting", "unknown")
            findings.append({
                "event_type": "config_changed",
                "user_id": uid,
                "ip_address": ip,
                "setting": setting,
                "old_value": meta.get("old_value"),
                "new_value": meta.get("new_value"),
                "timestamp": e["timestamp"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "severity": "LOW",
                "confidence": "definite",
                "recommendation": (
                    f"Confirm config change to '{setting}' by {uid} was authorized. "
                    "Check change management log."
                ),
            })

        elif etype == "admin_action":
            action = meta.get("action", "unknown")
            sev = "MEDIUM" if action in HIGH_RISK_ACTIONS else "LOW"
            findings.append({
                "event_type": "admin_action",
                "user_id": uid,
                "ip_address": ip,
                "action": action,
                "target_resource": meta.get("target_resource"),
                "timestamp": e["timestamp"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "severity": sev,
                "confidence": "definite",
                "recommendation": (
                    f"Review high-risk action '{action}' by {uid}"
                    if sev == "MEDIUM" else None
                ),
            })

    # Apply severity filter
    if severity == "high":
        findings = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
    elif severity == "critical":
        findings = [f for f in findings if f["severity"] == "CRITICAL"]

    return findings


def analyze_rate_limit_violations(
    service: str = None,
    time_window: str = "6h",
) -> list:
    """
    Detect API abuse: repeated rate limit hits, scraping patterns,
    and distributed bot activity.
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window

    events = [
        e for e in EVENTS
        if e["_ts"] >= cutoff
        and e.get("event_type") == "rate_limit_exceeded"
    ]

    if service:
        events = [e for e in events if e.get("service") == service]

    if not events:
        return []

    # Group by IP
    by_ip: dict = defaultdict(list)
    for e in events:
        by_ip[e.get("ip_address", "unknown")].append(e)

    findings = []

    for ip, ip_events in by_ip.items():
        ip_events_sorted = sorted(ip_events, key=lambda e: e["_ts"])
        endpoints = list({e.get("endpoint") for e in ip_events if e.get("endpoint")})
        user_agents = list({
            e.get("metadata", {}).get("user_agent", "")
            for e in ip_events
            if e.get("metadata", {}).get("user_agent")
        })

        is_scraper = len(endpoints) > 1
        is_automated = any(
            kw in ua.lower()
            for ua in user_agents
            for kw in ("python", "curl", "wget", "bot", "spider", "scraper", "requests")
        )

        if len(ip_events) >= 10:
            severity = "HIGH"
        elif len(ip_events) >= 5:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if is_scraper and is_automated:
            pattern = "distributed_bot"
        elif is_scraper:
            pattern = "api_scraping"
        elif is_automated:
            pattern = "automated_abuse"
        else:
            pattern = "repeated_violations"

        recommendation = f"Block or throttle IP {ip}"
        if is_scraper:
            recommendation += ", review endpoint-level access controls"
        if is_automated:
            recommendation += ", add bot detection (CAPTCHA or JS challenge)"

        findings.append({
            "ip_address": ip,
            "violation_count": len(ip_events),
            "endpoints_targeted": endpoints,
            "user_agents": user_agents,
            "pattern": pattern,
            "first_seen": ip_events_sorted[0]["timestamp"],
            "last_seen": ip_events_sorted[-1]["timestamp"],
            "severity": severity,
            "confidence": "definite" if is_automated else "probable",
            "recommendation": recommendation,
            "false_positive_note": "Could be a legitimate high-volume API consumer or CI pipeline",
        })

    return findings


# OWASP attack type severity mapping
_WEB_ATTACK_SEVERITY = {
    "sql_injection_attempt": "CRITICAL",
    "xss_attempt": "HIGH",
    "path_traversal_attempt": "HIGH",
    "sequential_enumeration": "MEDIUM",
}

# Known offensive security tools found in User-Agent strings
_KNOWN_ATTACK_TOOLS = ("sqlmap", "nikto", "masscan", "nmap", "metasploit", "burpsuite", "zap")


def _web_attack_recommendation(attack_type: str, attack_tools: list, endpoints: list) -> str:
    base = {
        "sql_injection_attempt": (
            "Enable WAF SQL injection ruleset. Verify all DB queries use parameterized statements. "
            "Audit affected endpoints for ORM misuse."
        ),
        "xss_attempt": (
            "Enable WAF XSS ruleset. Add Content-Security-Policy headers. "
            "Confirm output encoding is applied on all affected endpoints."
        ),
        "path_traversal_attempt": (
            "Enable WAF path traversal rules. Ensure file paths are resolved and jail-checked "
            "against a root directory. Never pass user input directly to file open/read calls."
        ),
        "sequential_enumeration": (
            "Rate-limit enumeration-prone endpoints. Add CAPTCHA after repeated requests. "
            "Consider returning identical responses for valid/invalid IDs to prevent enumeration."
        ),
    }.get(attack_type, "Review application logs for the affected endpoints and block source IPs.")

    if attack_tools:
        tool_list = ", ".join(attack_tools)
        base = f"Known attack tool(s) detected: {tool_list}. " + base

    return base


def detect_web_attacks(
    time_window: str = "24h",
    attack_type: str = None,
) -> list:
    """
    Detect OWASP Top 10 web attack attempts: SQL injection, XSS,
    path traversal, and sequential enumeration/reconnaissance.

    Aggregates findings by attack type, showing unique IPs, targeted
    endpoints, known attack tools (sqlmap, nikto), and sample payloads.

    attack_type filter: None (all) | 'sql_injection_attempt' | 'xss_attempt'
                        | 'path_traversal_attempt' | 'sequential_enumeration'
    """
    window = parse_window(time_window)
    cutoff = REFERENCE_TIME - window

    events = [
        e for e in EVENTS
        if e["_ts"] >= cutoff
        and e.get("event_type") == "suspicious_activity"
    ]

    if attack_type:
        events = [
            e for e in events
            if e.get("metadata", {}).get("attack_type") == attack_type
        ]

    if not events:
        return []

    # Group by attack_type
    by_type: dict = defaultdict(list)
    for e in events:
        atype = e.get("metadata", {}).get("attack_type", "unknown")
        by_type[atype].append(e)

    findings = []

    for atype, aevents in by_type.items():
        sorted_events = sorted(aevents, key=lambda e: e["_ts"])

        unique_ips = list({e.get("ip_address", "unknown") for e in aevents})
        endpoints = list({e.get("endpoint") for e in aevents if e.get("endpoint")})
        user_agents = list({
            e.get("metadata", {}).get("user_agent", "")
            for e in aevents
            if e.get("metadata", {}).get("user_agent")
        })

        # Identify known offensive tools by User-Agent
        attack_tools = sorted({
            ua for ua in user_agents
            if any(tool in ua.lower() for tool in _KNOWN_ATTACK_TOOLS)
        })

        # Up to 3 sample payloads for analyst context
        sample_payloads = [
            e.get("metadata", {}).get("payload_snippet")
            for e in sorted_events
            if e.get("metadata", {}).get("payload_snippet")
        ][:3]

        status_codes = list({
            e.get("metadata", {}).get("http_status_code")
            for e in aevents
            if e.get("metadata", {}).get("http_status_code") is not None
        })
        gateway_blocked = bool(status_codes) and all(sc == 403 for sc in status_codes)

        severity = _WEB_ATTACK_SEVERITY.get(atype, "HIGH")

        findings.append({
            "attack_type": atype,
            "total_attempts": len(aevents),
            "unique_source_ips": len(unique_ips),
            "source_ips": unique_ips[:10],
            "endpoints_targeted": endpoints,
            "attack_tools_detected": attack_tools,
            "sample_payloads": sample_payloads,
            "http_status_codes": status_codes,
            "gateway_blocked": gateway_blocked,
            "first_seen": sorted_events[0]["timestamp"],
            "last_seen": sorted_events[-1]["timestamp"],
            "severity": severity,
            "confidence": "definite",
            "recommendation": _web_attack_recommendation(atype, attack_tools, endpoints),
            "false_positive_note": (
                "Verify this is not an authorized penetration test. "
                "All attempts were blocked (HTTP 403) — no data exfiltration confirmed."
                if gateway_blocked else
                "Some requests may not have been blocked — review application-level logs."
            ),
        })

    return findings
