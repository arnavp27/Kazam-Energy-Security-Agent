"""
cache.py
Bonus 1: Intelligent caching + cost tracking + query tracing.

QueryCache    — memoizes tool results, auto-invalidates when logs change
CostTracker   — tracks tokens, cost, and cache savings per query
QueryTrace    — structured record of every agent decision (portfolio-grade observability)
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

LOG_DIR = Path(__file__).parent / "security_logs"

# DeepSeek V3 (deepseek-chat) pricing
# Pricing is per 1 Million tokens
DEEPSEEK_INPUT_PER_1M_TOKENS = 0.28   # USD per 1M input tokens (Standard/Cache Miss)
DEEPSEEK_OUTPUT_PER_1M_TOKENS = 0.42  # USD per 1M output tokens


def _get_logs_mtime() -> float:
    """Latest modification time across all log files. Used for cache invalidation."""
    mtimes = [
        os.path.getmtime(f)
        for f in LOG_DIR.glob("*.log")
        if f.exists()
    ]
    return max(mtimes) if mtimes else 0.0


# ---------------------------------------------------------------------------
# Trace dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StepTrace:
    """Records what happened in one step of the agent loop."""
    step: int
    tools_called: list = field(default_factory=list)
    cache_hits: list = field(default_factory=list)   # parallel to tools_called
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class QueryTrace:
    """Full observability record for one user query."""
    query: str
    intent: str                          # vague / specific / general
    intent_hints: list = field(default_factory=list)
    steps: list = field(default_factory=list)

    # Metrics interviewers ask about
    llm_calls: int = 0
    tool_calls: int = 0

    # Cost tracking
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    cache_hits: int = 0
    cost_usd: float = 0.0

    # Timing + result
    duration_seconds: float = 0.0
    final_answer: str = ""

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "intent": self.intent,
            "intent_hints": self.intent_hints,
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "cache_hits": self.cache_hits,
            "cost_usd": round(self.cost_usd, 6),
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# Query Cache
# ---------------------------------------------------------------------------

class QueryCache:
    """
    Memoizes tool function results.
    Cache key = hash(tool_name + normalized_args + log_files_mtime).
    Auto-invalidates when any log file is modified.
    """

    def __init__(self):
        self._cache: dict = {}
        self.total_hits: int = 0
        self.total_misses: int = 0

    def _make_key(self, tool_name: str, tool_args: dict) -> str:
        key_data = {
            "tool": tool_name,
            "args": tool_args,            # args already normalized (sorted) by caller
            "mtime": _get_logs_mtime(),
        }
        return hashlib.md5(
            json.dumps(key_data, sort_keys=True).encode()
        ).hexdigest()

    def get(self, tool_name: str, tool_args: dict) -> Optional[dict]:
        key = self._make_key(tool_name, tool_args)
        if key in self._cache:
            self.total_hits += 1
            return self._cache[key]
        self.total_misses += 1
        return None

    def set(self, tool_name: str, tool_args: dict, result: dict) -> None:
        key = self._make_key(tool_name, tool_args)
        self._cache[key] = result

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> str:
        total = self.total_hits + self.total_misses
        if total == 0:
            return "0%"
        return f"{(self.total_hits / total * 100):.0f}%"


# ---------------------------------------------------------------------------
# Cost Tracker
# ---------------------------------------------------------------------------

class CostTracker:
    """
    Tracks token usage and cost per query.
    Maintains a list of QueryTrace objects for the session.
    """

    def __init__(self):
        self.queries: list = []
        self._current: Optional[QueryTrace] = None
        self._start_time: float = 0.0

    def start_query(self, query: str, intent: str, hints: list) -> QueryTrace:
        self._current = QueryTrace(query=query, intent=intent, intent_hints=hints)
        self._start_time = time.time()
        return self._current

    def record_llm_call(self, input_tokens: int, output_tokens: int) -> None:
        if not self._current:
            return
        self._current.llm_calls += 1
        self._current.total_input_tokens += input_tokens
        self._current.total_output_tokens += output_tokens
        
        # Calculate cost using DeepSeek's per-Million rates
        cost = (
            (input_tokens / 1_000_000) * DEEPSEEK_INPUT_PER_1M_TOKENS
            + (output_tokens / 1_000_000) * DEEPSEEK_OUTPUT_PER_1M_TOKENS
        )
        self._current.cost_usd += cost

    def record_tool_call(self, tool_name: str, cached: bool) -> None:
        if not self._current:
            return
        self._current.tool_calls += 1
        if cached:
            self._current.cache_hits += 1

    def end_query(self, final_answer: str) -> QueryTrace:
        if not self._current:
            return QueryTrace(query="", intent="unknown", final_answer=final_answer)
        self._current.final_answer = final_answer
        self._current.duration_seconds = round(time.time() - self._start_time, 2)
        self.queries.append(self._current)
        trace = self._current
        self._current = None
        return trace

    @property
    def session_totals(self) -> dict:
        total_cost = sum(q.cost_usd for q in self.queries)
        total_in = sum(q.total_input_tokens for q in self.queries)
        total_out = sum(q.total_output_tokens for q in self.queries)
        total_cache = sum(q.cache_hits for q in self.queries)
        total_tools = sum(q.tool_calls for q in self.queries)
        total_llm = sum(q.llm_calls for q in self.queries)

        hit_rate = (
            f"{(total_cache / total_tools * 100):.0f}%"
            if total_tools > 0 else "0%"
        )

        return {
            "queries_answered": len(self.queries),
            "llm_calls": total_llm,
            "total_tool_calls": total_tools,
            "cache_hits": total_cache,
            "cache_hit_rate": hit_rate,
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "total_cost_usd": round(total_cost, 6),
        }
