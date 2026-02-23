# Security Log Analysis Agent

An AI agent that lets security engineers query logs using natural language to detect threats, anomalies, and suspicious patterns.

---

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
cd security-agent

# 2. Create a virtual environment
uv venv

# 3. Install dependencies
uv pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Open .env and add your DEEPSEEK_API_KEY

# 5. Run the app
uv run streamlit run app.py
```

The app opens at `http://localhost:8501`. Logs load automatically from `security_logs/`.

> **Don't have uv?** Install it with `pip install uv` or see [docs.astral.sh/uv](https://docs.astral.sh/uv).

---

## Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Default | Description |
|---|---|---|---|
| `DEEPSEEK_API_KEY` | Yes | — | Your DeepSeek API key |
| `BASE_URL` | No | `https://api.deepseek.com` | API base URL |
| `MODEL` | No | `deepseek-chat` | Model name |
| `MAX_STEPS` | No | `5` | Max agent loop iterations |

Get a DeepSeek API key at [platform.deepseek.com](https://platform.deepseek.com).

---

## Usage

Type any security question in the chat box, or click a quick-query button in the sidebar.

**Example queries (use `7 days` as the time window for the sample data):**
- "Are there any brute force attacks in the last 7 days?"
- "Show privilege escalations in the last 7 days"
- "Did anyone escalate privileges after failed login attempts?"
- "Any rate limit violations in the last 7 days?"
- "What's the most common security event in the last 7 days?"

> **Note on sample data:** The provided logs cover `2025-02-19` to `2025-02-20`.
> The agent's reference time is the latest log timestamp (`2025-02-21 00:00 UTC`).
> Queries like "last hour" or "last 24h" will return no results on this dataset — use `7 days` to see all findings.

For **vague queries** ("show me issues", "any problems?"), the agent asks for a time window before running any analysis.

**Debug Mode** (sidebar toggle) — shows every tool call, cache hits, token usage, and estimated cost per query.

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
    ├── DeepSeek API   ← Decides which tools to call
    │   (deepseek-chat via OpenAI-compatible SDK)
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
- **No framework** (no LangChain, no CrewAI) — raw OpenAI-compatible SDK gives full control
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
| `detect_web_attacks` | OWASP Top 10 web attack detection: SQL injection, XSS, path traversal, sequential enumeration. Identifies attack tools (sqlmap, nikto) and sample payloads. | `time_window`, `attack_type` |
| `get_event_statistics` | Event counts, trends, period comparisons, peak hours | `time_window` |

> **Note on `detect_web_attacks` (6th tool, added after log review):**
> The project spec listed `suspicious_activity` as an event type in the log format but did not assign a required tool to it — the 4 mandatory tools only cover brute force, access anomalies, privilege actions, and rate limits. After skimming the actual log files and cross-referencing the OWASP Top 10 resource linked in the spec, it became clear that all 41 `suspicious_activity` events in the sample data were active web attack attempts (SQL injection, XSS, path traversal, sequential enumeration) using known offensive tools (sqlmap, nikto). These were completely invisible to every other tool — they only surfaced as a raw count in statistics. Adding a dedicated tool was the right call: these are distinct OWASP Top 10 attack categories that carry their own severity, remediation steps, and detection logic, none of which belong in `analyze_rate_limit_violations`.

**Adding a new tool:**
1. Write the function in `tools/`
2. Add it to `TOOL_REGISTRY` and `TOOL_SCHEMAS` in `tools/__init__.py`
3. Add hint patterns to `TOOL_HINTS` in `classifier.py`

The agent loop picks it up automatically — no other changes needed.

---

## Bonus: Cost Optimization

**Caching:** Tool results are memoized by `hash(tool_name + args + log_file_mtime)`. Identical queries within a session skip re-analysis entirely. Cache auto-invalidates if log files change.

**Token minimization:**
- Classifier runs before LLM — vague queries never hit the API
- Specific queries only send relevant tool schemas (smaller context = fewer input tokens)
- Tool output capped at 5 findings before sending to LLM

**Cost tracking:** Every query records input/output tokens and estimated cost, visible in the sidebar and debug mode.

---

## Running Tests

```bash
uv run python -m pytest tests/ -v
```

33 tests covering all 5 tool functions, output formatting, and tool registry. No API calls required — tests run against log files directly.

---

## Project Structure

```
security-agent/
├── app.py                  # Streamlit UI
├── agent.py                # Agentic loop (MAX_STEPS, dedup, tracing)
├── log_loader.py           # Load all logs into memory at startup
├── cache.py                # Caching + cost tracking + query tracing
├── classifier.py           # Regex intent classifier
├── tools/
│   ├── __init__.py         # Tool registry + output formatter
│   ├── auth_analysis.py
│   ├── access_analysis.py
│   ├── threat_detection.py
│   └── stats.py
├── prompts/
│   └── system_prompt.txt
├── tests/
│   └── test_tools.py
├── security_logs/          # Provided sample log files
├── demo/
│   └── example_queries.txt
├── .env.example
├── requirements.txt
└── README.md
```

---

## Limitations & Known Issues

**Data scope:**
- Logs cover 2025-02-19 to 2025-02-20. Reference time is anchored to the latest log entry (`2025-02-21 00:00 UTC`), not the wall clock. This means queries like "last hour" or "last 24h" compute a cutoff that excludes almost all events. Use `7 days` to include the full dataset.
- All logs are loaded once at startup. Events appended to log files after the app launches are not picked up — there is no real-time tailing.

**Detection gaps:**
- **New location detection** depends on a pre-window baseline. With a wide window like `7d` that covers all available data, there is no prior period to compare against, so `check_unusual_access` returns no location anomalies for that window. It works correctly with short windows (`1h`, `6h`). Fix: maintain a persistent `user_baselines.json` independent of the query window.
- **Credential stuffing** requires 3+ unique source IPs attacking the same account. A two-IP distributed attack is not flagged — the threshold exists to reduce false positives from shared NAT/proxy IPs.
- **Web attack correlation across types** is not deterministic. `detect_web_attacks` groups results by attack type, so if a single IP launched both SQLi and XSS probes, those findings appear as two separate entries. Cross-type attribution is left to the LLM to reason about, not enforced in Python.
- **WAF-bypassed attacks are invisible.** `detect_web_attacks` only surfaces events the gateway already tagged as `suspicious_activity` (HTTP 403). Attacks that bypassed the WAF and logged as normal `data_access` or `api_request` events would not be caught by this tool.

**Infrastructure:**
- Conversation history grows unboundedly within a session. On very long conversations this could hit the model's context window limit. Fix: trim history to the last N turns or summarize periodically.
- No retry logic on `_call_llm()`. A transient DeepSeek API error (network timeout, 5xx) surfaces as an unhandled exception. Fix: wrap with exponential backoff.
- No persistent state — conversation history and session stats reset on app restart.

**Mock data artifacts:**
- `old_value`/`new_value` in `config_changed` events are numeric strings in the sample data, not real configuration setting names/values.
- `location_hint` is pre-computed in the log data. No live IP geolocation is performed at query time.
- All 41 web attack events return HTTP 403 and involve 41 unique single-use IPs — a pattern characteristic of generated test data rather than a realistic sustained campaign from a smaller set of IPs.

---

## What I'd Improve With More Time

1. **Fix new location detection** — maintain a persistent `user_baselines.json` that tracks each user's known IPs and locations independently of the query window.

2. **IP reputation enrichment** — integrate [AbuseIPDB](https://www.abuseipdb.com/) free tier to check suspicious IPs against known threat databases. The brute force IP `203.45.67.89` and rate-limiting IP `45.123.56.78` would benefit from this immediately.

3. **Cross-tool correlation in Python** — currently the LLM handles cross-referencing (e.g. "brute force then privilege escalation"). A dedicated `correlate_events(user_id, time_window)` tool that joins findings across all tools would make this deterministic and testable.

4. **Alert triggers** — fire a notification (email or Slack webhook) automatically when a CRITICAL finding is detected, without the user needing to query. Configurable thresholds via `.env`.

5. **Real-time log tailing** — use `watchdog` to monitor the `security_logs/` directory and reload events incrementally when files change.

6. **API retry logic** — wrap `_call_llm()` with exponential backoff for network errors and rate limit responses from the model API.

7. **Export findings** — add a "Download as CSV" button in the Streamlit sidebar for the current session's findings.

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

Built with Claude Code (Claude Sonnet 4.6) for architecture planning and code generation. All generated code was reviewed for correctness, security patterns were verified against OWASP Brute Force documentation, and tool function logic was tested against the actual sample log data before finalizing.
