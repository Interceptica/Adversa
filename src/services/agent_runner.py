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
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
)

from src.config.models import AdversaConfig

log = logging.getLogger(__name__)


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
) -> dict[str, Any]:
    """
    Run a ClaudeSDKClient agent in a dedicated thread with a fresh event loop.

    The agent returns structured output via ResultMessage.structured_output
    when options.output_format is set (enforced by the SDK as a tool call).

    Returns a dict with:
      - result: str — final ResultMessage text
      - structured_output: dict | None — validated structured output
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
                    from langfuse import get_client as _get_langfuse
                    _get_langfuse()
                    from langsmith.integrations.claude_agent_sdk import configure_claude_agent_sdk
                    configure_claude_agent_sdk()
                except Exception:
                    pass

            result_text: str = ""
            structured: dict | None = None
            try:
                async with ClaudeSDKClient(options=options) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        if isinstance(message, ResultMessage):
                            result_text = (message.result or "").strip()
                            structured = getattr(message, "structured_output", None)
            except Exception as exc:
                log.warning("Agent failed: %s", exc)
                return {"result": "", "structured_output": None, "error": str(exc)}

            return {"result": result_text, "structured_output": structured, "error": None}

        return asyncio.run(_inner())

    ctx = contextvars.copy_context()
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, lambda: ctx.run(_run_in_thread))
