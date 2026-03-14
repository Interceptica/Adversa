"""
Activity stubs for the Adversa Temporal pipeline.

All activities raise NotImplementedError — business logic lands in subsequent tickets.
Activities are thin wrappers only; they must import from src.services/, never the reverse.
Retry policy (3 attempts, exponential backoff) is set on the workflow side.
"""
from __future__ import annotations

from temporalio import activity

from src.types import WorkflowInput, WorkflowResult


@activity.defn
async def run_preflight_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 0 — preflight checks, scope manifest, repo introspection."""
    from src.services.preflight import run_preflight

    result = await run_preflight(input.config)
    if result.status == "fail":
        return WorkflowResult(
            status="aborted",
            reason=f"Pre-flight failed: {'; '.join(result.errors)}",
        )
    return WorkflowResult(status="complete")


@activity.defn
async def run_pre_recon_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 1 — tool-only recon: nmap, subfinder, httpx, Semgrep, Trivy, Joern CPG build."""
    raise NotImplementedError("run_pre_recon_phase not yet implemented")


@activity.defn
async def run_recon_phase(input: WorkflowInput) -> WorkflowResult:
    """Phase 2 — LLM-driven recon agent: endpoint discovery, auth session, recon map."""
    raise NotImplementedError("run_recon_phase not yet implemented")


@activity.defn
async def run_injection_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — injection vulnerability analysis (STRIDE: Tampering, OWASP A03)."""
    raise NotImplementedError("run_injection_analysis not yet implemented")


@activity.defn
async def run_authz_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — authorisation analysis (STRIDE: Spoofing+EoP, OWASP A01/A07)."""
    raise NotImplementedError("run_authz_analysis not yet implemented")


@activity.defn
async def run_info_disclosure_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — information disclosure analysis (STRIDE: Info Disclosure, OWASP A01/A02)."""
    raise NotImplementedError("run_info_disclosure_analysis not yet implemented")


@activity.defn
async def run_ssrf_analysis(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SSRF analysis (OWASP A10)."""
    raise NotImplementedError("run_ssrf_analysis not yet implemented")


@activity.defn
async def run_sast_triage(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SAST finding triage against Semgrep/Joern results (OWASP A03/A05/A08)."""
    raise NotImplementedError("run_sast_triage not yet implemented")


@activity.defn
async def run_sca_reachability(input: WorkflowInput) -> WorkflowResult:
    """Phase 3 — SCA reachability analysis of Trivy findings (OWASP A06)."""
    raise NotImplementedError("run_sca_reachability not yet implemented")


@activity.defn
async def run_exploit_agent(input: WorkflowInput) -> WorkflowResult:
    """Phase 4 (Pro only) — conditional parallel exploitation."""
    raise NotImplementedError("run_exploit_agent not yet implemented")


@activity.defn
async def run_findings_report(input: WorkflowInput) -> WorkflowResult:
    """Phase 5a (OSS) — findings report generation."""
    raise NotImplementedError("run_findings_report not yet implemented")


@activity.defn
async def run_pentest_report(input: WorkflowInput) -> WorkflowResult:
    """Phase 5b (Pro only) — full pentest report generation."""
    raise NotImplementedError("run_pentest_report not yet implemented")
