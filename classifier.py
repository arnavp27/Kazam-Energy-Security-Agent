"""
classifier.py
Regex-based query intent classifier.
Zero cost — no LLM call, runs before the agent loop.
Returns (intent, matched_tool_names) to drive tool selection.
"""

import re
from typing import Tuple, List

# --- Vague query patterns ---
# These trigger clarification mode — no tools called yet
VAGUE_PATTERNS = [
    r"^show\s+(me\s+)?(security\s+)?issues?\.?$",
    r"^any\s+(security\s+)?problems?\??$",
    r"^what.s\s+happening",
    r"^(give\s+me\s+(a\s+)?)?status\.?$",
    r"^overview\.?$",
    r"^check\s+everything\.?$",
    r"^(run\s+)?(full\s+)?scan\.?$",
    r"^analyze\s*(everything|all)?\??$",
    r"^(any\s+)?alerts?\??$",
    r"^(what|anything)\s+(is\s+)?(suspicious|wrong|bad)\??$",
]

# --- Conjunction words that signal multi-tool queries ---
# e.g. "brute force AND privilege escalation"
CONJUNCTION_PATTERNS = [
    r"\band\b",
    r"\bafter\b",
    r"\bfollowed\s+by\b",
    r"\bcombined\s+with\b",
    r"\balso\b",
    r"\bthen\b",
    r"\bplus\b",
    r"\bcross[\s-]?reference\b",
    r"\bcorrelate\b",
]

# --- Tool hint patterns (intentionally overlapping) ---
# Overlap is intentional: "escalate after brute force" matches both tools
TOOL_HINTS = {
    "detect_failed_login_patterns": [
        r"brute[\s_]?force",
        r"failed\s+log[io]n",
        r"login\s+attempt",
        r"account\s+lock",
        r"wrong\s+password",
        r"password\s+attempt",
        r"too\s+many\s+(login|attempt|fail)",
        r"credential\s+stuff",
        r"password\s+spray",
        r"invalid\s+(password|credential)",
        r"login\s+fail",
        r"multiple\s+fail",
    ],
    "check_unusual_access": [
        r"unusual",
        r"suspicious\s+ip",
        r"new\s+(ip|location)",
        r"different\s+(country|location|region)",
        r"session\s+hijack",
        r"anomal",
        r"location\s+change",
        r"access\s+from",
        r"where.*log.*in",
        r"odd[\s-]hours?",
        r"midnight",
        r"after\s+hours?",
        r"new\s+device",
    ],
    "audit_privilege_actions": [
        r"privileg",
        r"escalat",
        r"admin\s+action",
        r"config\s+change",
        r"sensitive\s+data",
        r"admin\s+panel",
        r"permission",
        r"role\s+change",
        r"user.*admin",
        r"granted\s+(by|to)",
        r"data\s+(export|access)",
        r"configuration",
    ],
    "analyze_rate_limit_violations": [
        r"rate\s+limit",
        r"api\s+abuse",
        r"\bdos\b",
        r"\bddos\b",
        r"scraping",
        r"spam(ming)?",
        r"too\s+many\s+request",
        r"throttl",
        r"flood(ing)?",
        r"api\s+(attack|violation|exceed)",
        r"429",
    ],
    "detect_web_attacks": [
        r"sql\s*inject",
        r"\bsqli\b",
        r"\bxss\b",
        r"cross[\s-]?site\s+script",
        r"path\s+traversal",
        r"directory\s+traversal",
        r"\.\./",
        r"web\s+attack",
        r"application[\s-]layer\s+attack",
        r"\bsqlmap\b",
        r"\bnikto\b",
        r"owasp",
        r"injection\s+attempt",
        r"payload",
        r"suspicious\s+activit",
        r"scanning\s+(tool|attempt)",
        r"sequential\s+enumerat",
        r"enumerat",
    ],
    "get_event_statistics": [
        r"most\s+common",
        r"compare",
        r"trend",
        r"this\s+hour\s+vs",
        r"statistic",
        r"summary",
        r"how\s+many",
        r"count",
        r"total",
        r"breakdown",
        r"distribution",
        r"peak",
    ],
}

# get_event_statistics is always useful alongside specific tools
ALWAYS_INCLUDE = {"get_event_statistics"}


def classify_query(query: str) -> Tuple[str, List[str]]:
    """
    Classify user query intent.

    Returns:
        (intent, tool_names)

        intent:
            "vague"    — query is too broad, ask for clarification (no tools)
            "specific" — matched one or more tool hints (use matched_tools)
            "general"  — no clear match, let LLM decide (use all tools)

        tool_names:
            List of tool names to enable for this query.
            Empty for "vague". Full list for "general".
    """
    q = query.lower().strip()

    # 1. Check vague first
    for pattern in VAGUE_PATTERNS:
        if re.search(pattern, q):
            return "vague", []

    # 2. Detect conjunctions — signals multi-tool intent
    has_conjunction = any(re.search(p, q) for p in CONJUNCTION_PATTERNS)

    # 3. Match tool hints
    matched = []
    for tool, patterns in TOOL_HINTS.items():
        if any(re.search(p, q) for p in patterns):
            matched.append(tool)

    if matched:
        # Always include stats for context enrichment
        matched_with_stats = list(set(matched) | ALWAYS_INCLUDE)
        return "specific", matched_with_stats

    # 4. Fallback — general, let LLM decide with all tools
    return "general", []
