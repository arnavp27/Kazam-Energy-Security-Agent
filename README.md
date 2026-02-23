# Security Log Analysis Agent

An AI agent that lets security engineers query logs using natural language to detect threats, anomalies, and suspicious patterns.

---

## Quick Start

```bash
# 1. Clone / unzip the project
cd security-agent

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment
cp .env.example .env
# Edit .env and add your ZAI_API_KEY

# 4. Run the app
streamlit run app.py
```

The app opens at `http://localhost:8501`. Logs load automatically from `security_logs/`.

> **Note:** Log files are stored in `security_logs/` (the provided sample files).

---

## Usage

Type any security question in the chat box, or click a quick-query button in the sidebar.

**Example queries:**
- "Are there any brute force attacks?"
- "Show privilege escalations in the last 24 hours"
- "Did anyone escalate privileges after failed login attempts?"
- "Any rate limit violations today?"
- "Compare failed login rates this hour vs last hour"

For **vague queries** ("show me issues", "any problems?"), the agent asks for a time window before running analysis.

**Debug Mode** (sidebar toggle) — shows tool calls, cache hits, token usage, and cost per query.

---

## Architecture

```
User Query
    │
    ▼
classifier.py          ← Regex-based intent classifier (zero LLM cost)
    │                    Returns: vague / specific / general
    │
    ▼
agent.py               ← Agentic loop (max 5 steps, dedup protection)
    │
    ├── GLM-4.7 API    ← Decides which tools to call
    │   (via OpenAI SDK pointed at z.ai)
    │
    ├── tools/         ← Pure Python functions, query in-memory log data
    │   ├── auth_analysis.py      detect_failed_login_patterns
    │   ├── access_analysis.py    check_unusual_access
    │   ├── threat_detection.py   audit_privilege_actions
    │   │                         analyze_rate_limit_violations
    │   └── stats.py              get_event_statistics
    │
    └── cache.py       ← Memoizes tool results, tracks tokens + cost
```

**Key design decisions:**
- **No framework** (no LangChain, no CrewAI) — raw OpenAI SDK gives full control
- **In-memory log loading** — ~850KB across 3 files, loaded once at startup
- **Python is the executor** — LLM decides *what* to call, Python does the actual work
- **Deterministic trimming** — tool output always sorted by severity, capped at 5 findings before being sent to LLM

---

## Tool Functions

| Function | Purpose | Key Parameters |
|---|---|---|
| `detect_failed_login_patterns` | Brute force + credential stuffing detection. Includes persistence check (did attacker succeed?) | `time_window`, `threshold` |
| `check_unusual_access` | New IP/location for known users, session hijacking, odd-hours access | `user_id`, `time_window` |
| `audit_privilege_actions` | Privilege escalations, sensitive data access, config changes, admin actions | `time_window`, `severity` |
| `analyze_rate_limit_violations` | API abuse, rate limit violations, scraping patterns, bot detection | `service`, `time_window` |
| `get_event_statistics` | Event counts, trends, period comparisons, peak hours | `time_window` |

**Adding a new tool:**
1. Write the function in `tools/`
2. Add it to `TOOL_REGISTRY` and `TOOL_SCHEMAS` in `tools/__init__.py`
3. Add hint patterns to `TOOL_HINTS` in `classifier.py`

That's it — the agent loop picks it up automatically.

---

## Bonus: Cost Optimization

**Caching:** Tool results are memoized by `hash(tool_name + args + log_file_mtime)`. Identical queries within a session skip re-analysis entirely. Cache auto-invalidates if log files change.

**Token minimization:**
- Classifier runs before LLM — vague queries never hit the API
- Specific queries only send relevant tool schemas (smaller context)
- Tool output capped at 5 findings before sending to LLM

**Cost tracking:** Every query records input/output tokens and estimated cost (visible in sidebar and debug mode).

---

## Limitations & Known Issues

- **Single-day logs** — reference time is fixed to the latest log timestamp (`2025-02-19`). Time windows like "last hour" are relative to this, not actual current time.
- **Mock geolocation** — `location_hint` values in logs are pre-computed (e.g. `US-CA`, `IN-MH`). No real IP geolocation is performed.
- **No pagination** — all logs loaded in memory. For production use with multi-day logs, a lightweight index (SQLite or DuckDB) would be needed.
- **Config change values** — `old_value`/`new_value` in config_changed events are numeric strings in the sample data (mock artifact), not actual setting values.

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Tests cover all 5 tool functions, output formatting, and tool registry — no API calls required.

---

## Time Investment

- Planning & architecture: ~2h
- Tool functions + log parsing: ~3h
- Agent loop + classifier + cache: ~2h
- Streamlit UI: ~1.5h
- Tests + documentation: ~1h
- Total: ~9.5h

---

## AI Assistance Used

Built with Claude Code (Claude Sonnet 4.6) for architecture planning and code generation. All generated code was reviewed for correctness, security patterns were verified against OWASP Brute Force documentation, and the tool function logic was tested against the actual sample log data before finalizing.
