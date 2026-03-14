from __future__ import annotations

from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny, ToolPermissionContext

from src.audit.logger import AuditLogger
from src.config.models import AdversaConfig
from src.scope.enforcer import ScopeEnforcer, _extract_url


def build_can_use_tool(config: AdversaConfig, audit: AuditLogger):
    """
    Returns a can_use_tool callback for ClaudeAgentOptions.
    This is Layer 3 of scope enforcement — deterministic, cannot be bypassed by the LLM.

    Usage:
        options = ClaudeAgentOptions(
            can_use_tool=build_can_use_tool(config, audit),
            ...
        )
    """
    enforcer = ScopeEnforcer.from_config(config)

    async def can_use_tool(
        tool_name: str,
        input_data: dict,
        context: ToolPermissionContext,
    ) -> PermissionResultAllow | PermissionResultDeny:
        url = _extract_url(input_data)
        if url:
            result = enforcer.check(url)
            if not result.allowed:
                audit.log_scope_block(
                    url=url,
                    reason=result.reason,
                    tool=tool_name,
                )
                return PermissionResultDeny(
                    message=f"Out of scope: {result.reason}",
                    interrupt=False,
                )
        return PermissionResultAllow(updated_input=input_data)

    return can_use_tool
