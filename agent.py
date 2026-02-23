"""
agent.py
Core agentic loop. No UI logic here — pure orchestration.
Imports: OpenAI SDK (pointed at z.ai), tools, classifier, cache.
"""

import json
import os
from pathlib import Path
from typing import Callable, Optional

from dotenv import load_dotenv
from openai import OpenAI

from cache import QueryCache, CostTracker, QueryTrace
from classifier import classify_query
from tools import ALL_TOOL_NAMES, build_tool_schemas, execute_tool

load_dotenv()

# --- Constants ---
MAX_STEPS = int(os.getenv("MAX_STEPS", 5))

CLARIFICATION_MESSAGE = (
    "I'll analyze security events. What timeframe should I check?\n\n"
    "- **Last hour** — most urgent, catch ongoing attacks\n"
    "- **Last 6 hours** — current shift overview\n"
    "- **Last 24 hours** — full daily summary\n"
    "- **Custom** — tell me the window (e.g. 'last 2 hours', 'last 3 days')"
)

# --- Singletons (shared across all queries in a session) ---
_cache = QueryCache()
_cost_tracker = CostTracker()


def get_cache() -> QueryCache:
    return _cache


def get_cost_tracker() -> CostTracker:
    return _cost_tracker


# --- LLM Client ---
def _make_client() -> OpenAI:
    api_key = os.getenv("DEEPSEEK_API_KEY")
    base_url = os.getenv("BASE_URL", "https://api.deepseek.com")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY not set. Check your .env file.")
    return OpenAI(api_key=api_key, base_url=base_url)


def _call_llm(
    client: OpenAI,
    messages: list,
    tools: Optional[list] = None,
) -> tuple:
    """
    Call the LLM. Returns (response, input_tokens, output_tokens).
    Safe token counting — response.usage may be absent on some endpoints.
    """
    model = os.getenv("MODEL", "deepseek-chat")
    kwargs = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,   # low temp = more deterministic security analysis
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    response = client.chat.completions.create(**kwargs)
    
    # Safe token extraction
    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
    output_tokens = getattr(usage, "completion_tokens", 0) if usage else 0

    return response, input_tokens, output_tokens


# --- Main Agent Function ---
def run_agent(
    user_query: str,
    conversation_history: list,
    system_prompt: str,
    on_tool_call: Optional[Callable] = None,
) -> tuple:
    """
    Run the agentic loop for a single user query.

    Args:
        user_query:            The user's message.
        conversation_history:  Prior messages (role/content dicts).
        system_prompt:         The security analyst system prompt.
        on_tool_call:          Optional callback(tool_name, args, is_cached)
                               called before each tool execution (for UI updates).

    Returns:
        (final_answer: str, trace: QueryTrace)
    """
    client = _make_client()

    # 1. Classify intent
    intent, matched_tools = classify_query(user_query)
    trace = _cost_tracker.start_query(user_query, intent, matched_tools)

    # 2. Vague query — ask for clarification, skip tools
    if intent == "vague":
        return CLARIFICATION_MESSAGE, _cost_tracker.end_query(CLARIFICATION_MESSAGE)

    # 3. Select tools based on intent
    if intent == "specific":
        active_tools = build_tool_schemas(matched_tools)
    else:
        active_tools = build_tool_schemas()   # all tools for general queries

    # 4. Build message list
    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(conversation_history)
    messages.append({"role": "user", "content": user_query})

    # 5. Agentic loop
    step = 0
    seen_calls: set = set()   # dedup: (tool_name, normalized_args) → skip repeat calls

    while step < MAX_STEPS:
        step += 1
        response, in_tok, out_tok = _call_llm(client, messages, active_tools)
        _cost_tracker.record_llm_call(in_tok, out_tok)
        trace.llm_calls += 1

        choice = response.choices[0]
        finish_reason = choice.finish_reason

        # --- Handle all finish reasons ---

        if finish_reason in ("stop", None):
            answer = choice.message.content or ""
            return answer, _cost_tracker.end_query(answer)

        elif finish_reason == "length":
            # Context window hit — force a condensed summary
            messages.append({
                "role": "assistant",
                "content": choice.message.content or "",
            })
            messages.append({
                "role": "user",
                "content": (
                    "Context limit reached. Please summarize the key security "
                    "findings discovered so far, grouped by severity."
                ),
            })
            continue

        elif finish_reason == "tool_calls":
            tool_calls = choice.message.tool_calls or []

            # Append the assistant message with tool_calls
            messages.append({
                "role": "assistant",
                "content": choice.message.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls
                ],
            })

            for tc in tool_calls:
                tool_name = tc.function.name

                # Safely parse arguments
                try:
                    args_dict = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args_dict = {}

                # Dedup: skip identical tool+args combinations
                sig = f"{tool_name}:{json.dumps(args_dict, sort_keys=True)}"
                if sig in seen_calls:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps({
                            "note": "Duplicate call skipped. Use the result from the previous identical call."
                        }),
                    })
                    continue
                seen_calls.add(sig)

                # Cache check
                cached_result = _cache.get(tool_name, args_dict)
                is_cached = cached_result is not None
                _cost_tracker.record_tool_call(tool_name, is_cached)
                trace.tool_calls += 1

                # Notify UI (Streamlit callback for live "thinking" display)
                if on_tool_call:
                    on_tool_call(tool_name, args_dict, is_cached)

                if is_cached:
                    result = cached_result
                else:
                    result = execute_tool(tool_name, args_dict)
                    _cache.set(tool_name, args_dict, result)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

        else:
            # Unknown finish reason — treat as done
            answer = choice.message.content or "Analysis complete."
            return answer, _cost_tracker.end_query(answer)

    # 6. MAX_STEPS reached — force final answer without tools
    messages.append({
        "role": "user",
        "content": (
            "Maximum analysis steps reached. Please provide a concise summary "
            "of all security findings discovered, grouped by severity (CRITICAL first)."
        ),
    })
    response, in_tok, out_tok = _call_llm(client, messages, tools=None)
    _cost_tracker.record_llm_call(in_tok, out_tok)
    answer = response.choices[0].message.content or "Analysis complete (step limit reached)."
    return answer, _cost_tracker.end_query(answer)
