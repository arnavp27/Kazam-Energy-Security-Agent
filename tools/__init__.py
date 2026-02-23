"""
tools/__init__.py
Central tool registry, output formatter, and schema builder.
To add a new tool: import it here, add to TOOL_REGISTRY and TOOL_SCHEMAS.
"""

import json

from tools.auth_analysis import detect_failed_login_patterns
from tools.access_analysis import check_unusual_access
from tools.threat_detection import audit_privilege_actions, analyze_rate_limit_violations, detect_web_attacks
from tools.stats import get_event_statistics

# --- Output Formatting ---
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MAX_FINDINGS = 5


def format_tool_output(findings: list, tool_name: str) -> dict:
    """
    Deterministic output trimming — Python decides, not the LLM.
    Always sorts by severity, always caps at MAX_FINDINGS.
    """
    if not findings:
        return {
            "tool": tool_name,
            "total_found": 0,
            "showing": 0,
            "truncated": False,
            "findings": [],
            "message": "No findings in this time window.",
        }

    sorted_findings = sorted(
        findings,
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4),
    )
    trimmed = sorted_findings[:MAX_FINDINGS]

    return {
        "tool": tool_name,
        "total_found": len(findings),
        "showing": len(trimmed),
        "truncated": len(findings) > MAX_FINDINGS,
        "findings": trimmed,
    }


# --- Tool Registry ---
TOOL_REGISTRY = {
    "detect_failed_login_patterns": detect_failed_login_patterns,
    "check_unusual_access": check_unusual_access,
    "audit_privilege_actions": audit_privilege_actions,
    "analyze_rate_limit_violations": analyze_rate_limit_violations,
    "detect_web_attacks": detect_web_attacks,
    "get_event_statistics": get_event_statistics,
}

ALL_TOOL_NAMES = list(TOOL_REGISTRY.keys())


def execute_tool(tool_name: str, tool_args: dict) -> dict:
    """Execute a tool by name. Returns formatted output."""
    if tool_name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {tool_name}", "tool": tool_name}
    try:
        result = TOOL_REGISTRY[tool_name](**tool_args)
        return format_tool_output(result, tool_name)
    except TypeError as e:
        return {"error": f"Invalid arguments for {tool_name}: {e}", "tool": tool_name}
    except Exception as e:
        return {"error": f"Tool {tool_name} failed: {e}", "tool": tool_name}


# --- LLM Tool Schemas ---
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "detect_failed_login_patterns",
            "description": (
                "Detect brute force attacks and credential stuffing. "
                "Call this when the user asks about: failed logins, brute force, "
                "account lockouts, password attempts, or login anomalies. "
                "Also performs a persistence check — did the attacker later succeed?"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Examples: '1h', '6h', '24h', '7d'.",
                    },
                    "threshold": {
                        "type": "integer",
                        "description": "Minimum failed attempts to flag as suspicious. Default: 5.",
                    },
                },
                "required": ["time_window"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_unusual_access",
            "description": (
                "Identify anomalous access patterns: new IP/location for known users, "
                "session hijacking, and access at unusual hours. "
                "Call this for: suspicious IPs, location changes, session anomalies, "
                "or when investigating a specific user."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "Specific user to investigate. Omit to check all users.",
                    },
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Default: '24h'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_privilege_actions",
            "description": (
                "Track admin actions, privilege escalations, config changes, "
                "and sensitive data access. "
                "Call this for: admin activity, role changes, permission grants, "
                "data exports, or configuration modifications."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Default: '24h'.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["all", "high", "critical"],
                        "description": "Filter by minimum severity. Default: 'all'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_rate_limit_violations",
            "description": (
                "Detect API abuse, rate limit violations, scraping, and DoS patterns. "
                "Call this for: rate limit hits, API flooding, scraping suspicions, "
                "or automated abuse detection."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Filter by service name. Omit for all services.",
                    },
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Default: '6h'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_web_attacks",
            "description": (
                "Detect OWASP Top 10 web application attack attempts: SQL injection, XSS, "
                "path traversal, and sequential enumeration/reconnaissance. "
                "Call this for: web attacks, SQLi, XSS, injection, path traversal, "
                "sqlmap, nikto, scanning tools, suspicious payloads, or application-layer threats."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Examples: '1h', '6h', '24h', '7d'.",
                    },
                    "attack_type": {
                        "type": "string",
                        "enum": [
                            "sql_injection_attempt",
                            "xss_attempt",
                            "path_traversal_attempt",
                            "sequential_enumeration",
                        ],
                        "description": (
                            "Filter by specific attack type. "
                            "Omit to return all web attack types."
                        ),
                    },
                },
                "required": ["time_window"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_event_statistics",
            "description": (
                "Get event counts, trends, and period comparisons. "
                "Call this for: most common events, comparing time periods, "
                "daily summaries, total counts, peak hours, or trend analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "time_window": {
                        "type": "string",
                        "description": "Time window to analyze. Default: '24h'.",
                    },
                },
                "required": [],
            },
        },
    },
]

_schema_by_name = {s["function"]["name"]: s for s in TOOL_SCHEMAS}


def build_tool_schemas(tool_names: list = None) -> list:
    """Return tool schemas for given names, or all schemas if None."""
    if tool_names is None:
        return TOOL_SCHEMAS
    return [_schema_by_name[n] for n in tool_names if n in _schema_by_name]
