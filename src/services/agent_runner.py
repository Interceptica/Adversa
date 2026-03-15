"""
Shared agent runner — executes ClaudeSDKClient in a dedicated thread.

All agentic phases use this to avoid the anyio/Temporal cancel-scope conflict:
- Temporal's asyncio task management + anyio cancel scopes don't mix
- A fresh event loop via asyncio.run() in a ThreadPoolExecutor isolates them
- contextvars are propagated so Langfuse/OTel tracing context is preserved

Usage:
    from src.services.agent_runner import run_agent

    result = await run_agent(
        options=ClaudeAgentOptions(...),
        prompt="...",
        config=config,
    )
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)

from src.config.models import AdversaConfig

log = logging.getLogger(__name__)


def _extract_json(text: str) -> dict | None:
    """Extract the last JSON object from a string that may contain prose + JSON."""
    # Try parsing the whole string first
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass

    # Find all JSON-like blocks (outermost { ... })
    matches = list(re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL))
    for match in reversed(matches):  # try last match first
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def build_agent_env(config: AdversaConfig) -> dict[str, str]:
    """Build the env dict for ClaudeAgentOptions from AdversaConfig."""
    env: dict[str, str] = {"ANTHROPIC_API_KEY": config.llm.api_key}
    if config.llm.base_url:
        env["ANTHROPIC_BASE_URL"] = config.llm.base_url
    return env


async def run_agent(
    *,
    options: ClaudeAgentOptions,
    prompt: str,
    config: AdversaConfig,
    parse_json: bool = False,
) -> dict[str, Any]:
    """
    Run a ClaudeSDKClient agent in a dedicated thread with a fresh event loop.

    Returns a dict with:
      - result: str — final ResultMessage text (or last assistant text as fallback)
      - parsed: dict | None — if parse_json=True, extracted JSON from the response
      - error: str | None — error message if the agent failed

    Never raises — all errors are captured in the return dict.
    """

    def _run_in_thread() -> dict[str, Any]:
        async def _inner() -> dict[str, Any]:
            # Re-configure tracing inside this thread's event loop.
            # configure_claude_agent_sdk() patches ClaudeSDKClient — must be called
            # before creating the client instance in this new loop.
            if config.tracing.enabled:
                try:
                    # Langfuse must init first — it registers the OTel exporter
                    # that receives spans from configure_claude_agent_sdk().
                    from langfuse import get_client as _get_langfuse
                    _get_langfuse()
                    from langsmith.integrations.claude_agent_sdk import configure_claude_agent_sdk
                    configure_claude_agent_sdk()
                except Exception:
                    pass

            result_text: str = ""
            last_assistant_text: str = ""
            try:
                async with ClaudeSDKClient(options=options) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        if isinstance(message, AssistantMessage):
                            for block in message.content:
                                if isinstance(block, TextBlock) and block.text.strip():
                                    last_assistant_text = block.text.strip()
                        if isinstance(message, ResultMessage):
                            result_text = (message.result or "").strip()
            except Exception as exc:
                log.warning("Agent failed: %s", exc)
                return {"result": "", "parsed": None, "error": str(exc)}

            # Use last assistant text as fallback when ResultMessage.result is empty
            final = result_text or last_assistant_text

            parsed = None
            if parse_json and final:
                parsed = _extract_json(final)
                if parsed is None:
                    log.warning("Agent JSON extraction failed | raw=%r", final[:300])

            return {"result": final, "parsed": parsed, "error": None}

        return asyncio.run(_inner())

    ctx = contextvars.copy_context()
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, lambda: ctx.run(_run_in_thread))
