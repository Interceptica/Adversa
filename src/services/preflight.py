"""
Phase 0: Pre-flight checks.

Runs before any LLM or tool call. Validates that the engagement is correctly
configured and all prerequisites exist. Collects ALL failures in one pass —
never short-circuits after the first error.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import httpx

from src.artifacts.schemas import Check, PreflightResult
from src.config.models import AdversaConfig
from src.scope.enforcer import ScopeEnforcer

# Tools that must be present in the container for scans to run.
_BASE_REQUIRED_TOOLS = ["semgrep", "trivy", "nmap", "subfinder", "httpx"]
_JOERN_TOOL = "joern"


async def run_preflight(config: AdversaConfig) -> PreflightResult:
    """
    Run all pre-flight checks and return a PreflightResult.

    Checks (in order):
      1. scope_valid        — included_hosts list is non-empty
      2. target_reachable   — HTTP HEAD to base_url succeeds within 10 s
      3. repo_accessible    — repo path exists and is a directory
      4. tool:<name>        — each required binary is on PATH (via `which`)
      5. api_key_valid      — minimal Anthropic-compatible API call succeeds
    """
    checks: list[Check] = []

    # 1. Scope — already validated by Pydantic but re-confirm at runtime
    if not config.target.included_hosts:
        checks.append(Check("scope_valid", "fail", "included_hosts must not be empty"))
    else:
        checks.append(Check("scope_valid", "pass"))

    # 2. Target reachable
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.head(config.target.base_url)
        checks.append(Check("target_reachable", "pass", f"HTTP {r.status_code}"))
    except Exception as exc:
        checks.append(Check("target_reachable", "fail", str(exc)))

    # 3. Repo path accessible
    repo = Path(config.repo.path)
    if repo.exists() and repo.is_dir():
        checks.append(Check("repo_accessible", "pass"))
    else:
        checks.append(Check("repo_accessible", "fail", f"Path not found: {config.repo.path}"))

    # 4. Required tools on PATH
    # subprocess.run is synchronous and technically blocks the event loop, but
    # `which` completes in microseconds so it is inconsequential here.
    # If async subprocess becomes a wider pattern, prefer:
    #   proc = await asyncio.create_subprocess_exec(
    #       "which", tool,
    #       stdout=asyncio.subprocess.DEVNULL,
    #       stderr=asyncio.subprocess.DEVNULL,
    #   )
    #   await proc.wait()
    required_tools = list(_BASE_REQUIRED_TOOLS)
    if config.repo.joern_enabled:
        required_tools.append(_JOERN_TOOL)

    for tool in required_tools:
        proc = subprocess.run(["which", tool], capture_output=True)
        status = "pass" if proc.returncode == 0 else "fail"
        checks.append(Check(f"tool:{tool}", status))

    # 5. LLM API key — minimal messages call (1 token) to validate credentials.
    #    Uses config.llm.base_url if set, otherwise Anthropic default.
    #    We call the API directly via httpx to avoid importing `anthropic`
    #    (claude-agent-sdk owns that dependency per CLAUDE.md).
    base = (config.llm.base_url or "https://api.anthropic.com").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{base}/v1/messages",
                headers={
                    "x-api-key": config.llm.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": config.llm.model_name,
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "ping"}],
                },
            )
        # 401/403 → bad key; 4xx (e.g. 400 invalid model) still means key is accepted
        if resp.status_code in (401, 403):
            checks.append(Check("api_key_valid", "fail", f"HTTP {resp.status_code}"))
        else:
            checks.append(Check("api_key_valid", "pass", f"HTTP {resp.status_code}"))
    except Exception as exc:
        checks.append(Check("api_key_valid", "fail", str(exc)))

    failed = [c for c in checks if c.status == "fail"]
    scope_manifest = ScopeEnforcer.from_config(config).to_json()

    return PreflightResult(
        status="fail" if failed else "pass",
        checks=checks,
        errors=[c.detail for c in failed if c.detail],
        scope_manifest=scope_manifest,
    )
