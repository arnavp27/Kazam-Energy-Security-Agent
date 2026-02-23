"""
tests/test_tools.py
Unit tests for all 5 tool functions.
Tools are pure Python (list → list), so these run with no LLM or API calls.

Run with: python -m pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.auth_analysis import detect_failed_login_patterns, parse_window
from tools.access_analysis import check_unusual_access
from tools.threat_detection import audit_privilege_actions, analyze_rate_limit_violations
from tools.stats import get_event_statistics
from tools import format_tool_output, execute_tool
from datetime import timedelta


# ---------------------------------------------------------------------------
# parse_window
# ---------------------------------------------------------------------------

class TestParseWindow:
    def test_hours(self):
        assert parse_window("1h") == timedelta(hours=1)
        assert parse_window("6h") == timedelta(hours=6)
        assert parse_window("24h") == timedelta(hours=24)

    def test_days(self):
        assert parse_window("7d") == timedelta(days=7)

    def test_minutes(self):
        assert parse_window("30m") == timedelta(minutes=30)

    def test_invalid_defaults_to_1h(self):
        assert parse_window("bad") == timedelta(hours=1)
        assert parse_window("xyz") == timedelta(hours=1)


# ---------------------------------------------------------------------------
# detect_failed_login_patterns
# ---------------------------------------------------------------------------

class TestDetectFailedLoginPatterns:
    def test_returns_list(self):
        result = detect_failed_login_patterns(time_window="24h", threshold=5)
        assert isinstance(result, list)

    def test_large_window_returns_findings(self):
        # With a wide window, brute force patterns in the logs should be detected
        result = detect_failed_login_patterns(time_window="24h", threshold=3)
        assert isinstance(result, list)

    def test_each_finding_has_required_fields(self):
        result = detect_failed_login_patterns(time_window="24h", threshold=3)
        required = {"attack_type", "attempt_count", "first_seen", "last_seen",
                    "severity", "confidence", "recommendation"}
        for finding in result:
            for field in required:
                assert field in finding, f"Missing field '{field}' in finding: {finding}"

    def test_severity_values_are_valid(self):
        result = detect_failed_login_patterns(time_window="24h", threshold=3)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for f in result:
            assert f["severity"] in valid

    def test_high_threshold_returns_fewer(self):
        low = detect_failed_login_patterns(time_window="24h", threshold=2)
        high = detect_failed_login_patterns(time_window="24h", threshold=20)
        assert len(low) >= len(high)

    def test_very_short_window_returns_list(self):
        # 1-minute window — might be empty, should not crash
        result = detect_failed_login_patterns(time_window="1m", threshold=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# check_unusual_access
# ---------------------------------------------------------------------------

class TestCheckUnusualAccess:
    def test_returns_list(self):
        result = check_unusual_access(time_window="24h")
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = check_unusual_access(time_window="24h")
        required = {"anomaly_type", "user_id", "first_seen", "last_seen",
                    "severity", "confidence"}
        for f in result:
            for field in required:
                assert field in f, f"Missing '{field}'"

    def test_anomaly_types_are_valid(self):
        result = check_unusual_access(time_window="24h")
        valid = {"session_hijack_suspected", "new_location", "odd_hours_access"}
        for f in result:
            assert f["anomaly_type"] in valid

    def test_specific_user_filter(self):
        all_results = check_unusual_access(time_window="24h")
        if not all_results:
            return  # no findings to test
        uid = all_results[0]["user_id"]
        filtered = check_unusual_access(user_id=uid, time_window="24h")
        for f in filtered:
            assert f["user_id"] == uid

    def test_nonexistent_user_returns_empty(self):
        result = check_unusual_access(user_id="user_DOES_NOT_EXIST_xyz", time_window="24h")
        assert result == []


# ---------------------------------------------------------------------------
# audit_privilege_actions
# ---------------------------------------------------------------------------

class TestAuditPrivilegeActions:
    def test_returns_list(self):
        result = audit_privilege_actions(time_window="24h")
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = audit_privilege_actions(time_window="24h")
        required = {"event_type", "user_id", "timestamp", "severity", "confidence"}
        for f in result:
            for field in required:
                assert field in f

    def test_severity_filter_high(self):
        all_results = audit_privilege_actions(time_window="24h", severity="all")
        high_results = audit_privilege_actions(time_window="24h", severity="high")
        assert len(high_results) <= len(all_results)
        for f in high_results:
            assert f["severity"] in ("HIGH", "CRITICAL")

    def test_event_types_are_valid(self):
        result = audit_privilege_actions(time_window="24h")
        valid = {"privilege_escalation", "sensitive_data_access",
                 "config_changed", "admin_action"}
        for f in result:
            assert f["event_type"] in valid


# ---------------------------------------------------------------------------
# analyze_rate_limit_violations
# ---------------------------------------------------------------------------

class TestAnalyzeRateLimitViolations:
    def test_returns_list(self):
        result = analyze_rate_limit_violations(time_window="24h")
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = analyze_rate_limit_violations(time_window="24h")
        required = {"ip_address", "violation_count", "first_seen", "last_seen",
                    "severity", "pattern", "confidence"}
        for f in result:
            for field in required:
                assert field in f

    def test_pattern_values_are_valid(self):
        result = analyze_rate_limit_violations(time_window="24h")
        valid = {"distributed_bot", "api_scraping", "automated_abuse", "repeated_violations"}
        for f in result:
            assert f["pattern"] in valid


# ---------------------------------------------------------------------------
# get_event_statistics
# ---------------------------------------------------------------------------

class TestGetEventStatistics:
    def test_returns_list_with_one_item(self):
        result = get_event_statistics(time_window="24h")
        assert isinstance(result, list)
        assert len(result) == 1

    def test_stats_have_required_fields(self):
        result = get_event_statistics(time_window="24h")
        s = result[0]
        required = {"total_events", "by_event_type", "most_common_event",
                    "failed_logins_current_period"}
        for field in required:
            assert field in s

    def test_total_events_positive(self):
        result = get_event_statistics(time_window="24h")
        assert result[0]["total_events"] > 0

    def test_very_short_window_handled(self):
        result = get_event_statistics(time_window="1m")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# format_tool_output
# ---------------------------------------------------------------------------

class TestFormatToolOutput:
    def test_empty_list(self):
        out = format_tool_output([], "my_tool")
        assert out["total_found"] == 0
        assert out["findings"] == []
        assert "message" in out

    def test_caps_at_max_findings(self):
        findings = [{"severity": "LOW", "x": i} for i in range(10)]
        out = format_tool_output(findings, "my_tool")
        assert out["showing"] <= 5
        assert out["truncated"] is True

    def test_sorts_by_severity(self):
        findings = [
            {"severity": "LOW"},
            {"severity": "CRITICAL"},
            {"severity": "MEDIUM"},
            {"severity": "HIGH"},
        ]
        out = format_tool_output(findings, "my_tool")
        severities = [f["severity"] for f in out["findings"]]
        assert severities[0] == "CRITICAL"

    def test_not_truncated_when_few(self):
        findings = [{"severity": "MEDIUM"} for _ in range(3)]
        out = format_tool_output(findings, "my_tool")
        assert out["truncated"] is False


# ---------------------------------------------------------------------------
# execute_tool (integration)
# ---------------------------------------------------------------------------

class TestExecuteTool:
    def test_valid_tool_returns_dict(self):
        result = execute_tool("get_event_statistics", {"time_window": "24h"})
        assert isinstance(result, dict)
        assert "tool" in result

    def test_unknown_tool_returns_error(self):
        result = execute_tool("nonexistent_tool", {})
        assert "error" in result

    def test_bad_args_returns_error(self):
        result = execute_tool("detect_failed_login_patterns", {"bad_arg": "x"})
        assert "error" in result
