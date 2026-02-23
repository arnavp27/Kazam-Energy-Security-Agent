"""
app.py
Streamlit UI for the Security Log Analysis Agent.
Run with: streamlit run app.py
"""

import streamlit as st
from pathlib import Path

from agent import run_agent, get_cache, get_cost_tracker
from log_loader import REFERENCE_TIME

# --- Page Config ---
st.set_page_config(
    page_title="Security Log Analyst",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Load System Prompt (once) ---
@st.cache_resource
def load_system_prompt() -> str:
    path = Path(__file__).parent / "prompts" / "system_prompt.txt"
    prompt = path.read_text(encoding="utf-8")
    return prompt.replace("{reference_time}", str(REFERENCE_TIME))

SYSTEM_PROMPT = load_system_prompt()

# --- Session State Init ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "traces" not in st.session_state:
    st.session_state.traces = []

# --- Sidebar ---
with st.sidebar:
    st.title("🔒 Security Agent")
    st.caption(f"Log reference time:  \n`{REFERENCE_TIME.strftime('%Y-%m-%d %H:%M UTC')}`")
    st.divider()

    debug_mode = st.toggle(
        "Debug Mode",
        value=False,
        help="Show tool calls, cache hits, and trace info for each query.",
    )

    st.divider()
    st.subheader("📊 Session Stats")

    cache = get_cache()
    tracker = get_cost_tracker()
    totals = tracker.session_totals

    col1, col2 = st.columns(2)
    col1.metric("Queries", totals["queries_answered"])
    col2.metric("Est. Cost", f"${totals['total_cost_usd']:.4f}")
    col1.metric("Tokens In", f"{totals['total_input_tokens']:,}")
    col2.metric("Tokens Out", f"{totals['total_output_tokens']:,}")
    col1.metric("Tool Calls", totals["total_tool_calls"])
    col2.metric("Cache Hits", f"{totals['cache_hits']} ({totals['cache_hit_rate']})")

    if st.button("🗑️ Clear Cache", use_container_width=True):
        cache.clear()
        st.success(f"Cache cleared.")
        st.rerun()

    st.divider()
    st.subheader("⚡ Quick Queries")
    QUICK_QUERIES = [
        "Are there any brute force attacks in the last 7 days?",
        "Show unusual access patterns in last 7 days",
        "Show privilege escalations in last 7 days",
        "Any rate limit violations in the last 7 days?",
        "Any web attacks (SQLi, XSS, path traversal) in the last 7 days?",
        "What's the most common security event in the last 7 days?",
        "Did anyone escalate privileges after failed logins?",
        "Show me all critical security issues in last 7 days",
    ]
    for q in QUICK_QUERIES:
        if st.button(q, use_container_width=True, key=f"quick_{q}"):
            st.session_state["pending_query"] = q
            st.rerun()

    st.divider()
    if st.button("🔄 Clear Conversation", use_container_width=True):
        st.session_state.messages = []
        st.session_state.traces = []
        st.rerun()

# --- Main Chat Area ---
st.title("🔒 Security Log Analysis Agent")
st.caption(
    "Ask about brute force attacks, unusual access, privilege escalations, "
    "API abuse, or security trends."
)

# Render conversation history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Pick up quick-query button clicks
if "pending_query" in st.session_state:
    prompt = st.session_state.pop("pending_query")
else:
    prompt = st.chat_input("Ask about security events... (e.g. 'Any brute force attacks in the last hour?')")

# --- Process Query ---
if prompt:
    # Show user message immediately
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Run agent and stream response
    with st.chat_message("assistant"):
        # Live tool-call status display
        tool_status_placeholder = st.empty()
        called_tools = []

        def on_tool_call(name: str, args: dict, is_cached: bool):
            called_tools.append({"name": name, "cached": is_cached})
            icons = []
            for t in called_tools:
                icon = "🟡 (cached)" if t["cached"] else "🔵"
                icons.append(f"{icon} `{t['name']}`")
            tool_status_placeholder.markdown(
                "**Analyzing logs:** " + " → ".join(icons)
            )

        # Build conversation history (exclude last user message — already in prompt)
        history = [
            {"role": m["role"], "content": m["content"]}
            for m in st.session_state.messages[:-1]
        ]

        with st.spinner("Analyzing..."):
            answer, trace = run_agent(
                user_query=prompt,
                conversation_history=history,
                system_prompt=SYSTEM_PROMPT,
                on_tool_call=on_tool_call,
            )

        # Clear tool status, show answer
        tool_status_placeholder.empty()
        st.markdown(answer)

        # Debug trace (shown only in debug mode)
        if debug_mode and trace:
            with st.expander("🔍 Query Trace", expanded=False):
                trace_data = trace.to_dict()
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Intent", trace_data["intent"])
                col2.metric("LLM Calls", trace_data["llm_calls"])
                col3.metric("Tool Calls", trace_data["tool_calls"])
                col4.metric("Cache Hits", trace_data["cache_hits"])

                col1.metric("Input Tokens", trace_data["total_input_tokens"])
                col2.metric("Output Tokens", trace_data["total_output_tokens"])
                col3.metric("Cost", f"${trace_data['cost_usd']:.6f}")
                col4.metric("Duration", f"{trace_data['duration_seconds']}s")

                if trace_data["intent_hints"]:
                    st.caption(f"**Classifier matched tools:** {', '.join(trace_data['intent_hints'])}")

                st.json(trace_data)

    # Save to session state
    st.session_state.messages.append({"role": "assistant", "content": answer})
    st.session_state.traces.append(trace)

    # Refresh sidebar stats
    st.rerun()
