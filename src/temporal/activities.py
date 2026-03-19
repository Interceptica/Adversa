"""
Activity stubs for the Adversa Temporal pipeline.

Unimplemented activities return WorkflowResult(status="complete") so the full
workflow runs end-to-end during development. Replace each stub with real logic
as the corresponding ticket is implemented.

Activities are thin wrappers only; all business logic lives in src/services/.
Retry policy (3 attempts, exponential backoff) is set on the workflow side.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging

from temporalio import activity

logger = logging.getLogger(__name__)

# Tracing is initialised lazily per-thread via agent_runner.py when
# config.tracing.enabled=true. No global setup needed here — the runner
# calls configure_claude_agent_sdk() inside each thread's fresh event loop
# (which is where ClaudeSDKClient is created and must be patched).

from src.types import WorkflowInput, WorkflowResult


@activity.defn
async def run_preflight_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 0 — preflight checks, scope manifest, repo introspection."""
    from src.services.preflight import run_preflight

    result = await run_preflight(input.config)
    preflight_json = json.dumps(dataclasses.asdict(result))

    if result.status == "fail":
        return WorkflowResult(
            status="aborted",
            reason=f"Pre-flight failed: {'; '.join(result.errors)}",
            preflight_json=preflight_json,
        )
    return WorkflowResult(status="complete", preflight_json=preflight_json)


@activity.defn
async def run_pre_recon_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 1 — agent-driven pre-recon: semgrep, trivy, nmap, subfinder, httpx, joern."""
    from src.artifacts.store import ArtifactStore
    from src.agents.pre_recon import run_pre_recon

    store = ArtifactStore(input.config.meta.engagement_id)
    try:
        output = await run_pre_recon(input.config, store)
    except asyncio.CancelledError:
        logger.info("Pre-recon activity cancelled by workflow")
        return WorkflowResult(status="aborted", reason="Cancelled by user")

    # Check for any scanner-level errors
    errors = []
    for key in ("semgrep_error", "sca_error", "joern_error"):
        err = output.get(key)
        if err:
            errors.append(f"{key.replace('_error', '')}: {err}")

    if errors:
        return WorkflowResult(status="partial", reason="; ".join(errors))
    return WorkflowResult(status="complete")


@activity.defn
async def run_recon_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 2 — whitebox recon agent: source-driven endpoint discovery, auth session, markdown deliverable."""
    from src.artifacts.store import ArtifactStore
    from src.agents.recon import run_recon

    store = ArtifactStore(input.config.meta.engagement_id)
    try:
        output = await run_recon(input.config, store)
    except asyncio.CancelledError:
        logger.info("Recon activity cancelled by workflow")
        return WorkflowResult(status="aborted", reason="Cancelled by user")

    if not output.get("markdown_written"):
        reason = output.get("error", "recon_deliverable.md was not written")
        return WorkflowResult(status="failed", reason=reason)

    return WorkflowResult(status="complete")


@activity.defn
async def run_injection_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — injection vulnerability analysis (STRIDE: Tampering, OWASP A03)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_authz_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — authorisation analysis (STRIDE: Spoofing+EoP, OWASP A01/A07)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_info_disclosure_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — information disclosure analysis (STRIDE: Info Disclosure, OWASP A01/A02)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_ssrf_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SSRF analysis (OWASP A10)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_sast_triage(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SAST finding triage against Semgrep/Joern results (OWASP A03/A05/A08)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_sca_reachability(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SCA reachability analysis of Trivy findings (OWASP A06)."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 3 ticket


@activity.defn
async def run_exploit_agent(input: WorkflowInput) -> WorkflowResult:
    """Phase 4 (Pro only) — conditional parallel exploitation."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 4 ticket (Pro)


@activity.defn
async def run_findings_report(input: WorkflowInput) -> WorkflowResult:
    """Phase 5a (OSS) — findings report generation."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 5a ticket


@activity.defn
async def run_pentest_report(input: WorkflowInput) -> WorkflowResult:
    """Phase 5b (Pro only) — full pentest report generation."""
    return WorkflowResult(status="complete")  # stub — implement in Phase 5b ticket (Pro)
