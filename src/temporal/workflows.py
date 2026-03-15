"""
Adversa top-level Temporal workflow.

PentestPipelineWorkflow orchestrates all phases in order:
  Phase 0 → preflight
  Phase 1 → pre-recon (tool-only)
  Phase 2 → recon (LLM)
  Phase 3 → parallel vulnerability analysis (6 agents)
  Phase 4 → exploitation (Pro only)
  Phase 5a → findings report (OSS)
  Phase 5b → pentest report (Pro only)

Unimplemented phases are stubs that return WorkflowResult(status="complete")
immediately. Replace each stub with real logic as the phase is built.
This means the full workflow can be run end-to-end at any stage of development
without needing separate test workflows.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from src.types import WorkflowInput, WorkflowResult

with workflow.unsafe.imports_passed_through():
    from src.temporal.activities import (
        run_authz_analysis,
        run_exploit_agent,
        run_findings_report,
        run_info_disclosure_analysis,
        run_injection_analysis,
        run_pentest_report,
        run_pre_recon_phase,
        run_preflight_phase,
        run_recon_phase,
        run_sast_triage,
        run_sca_reachability,
        run_ssrf_analysis,
    )

_RETRY_POLICY = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
)

_PHASE3_TIMEOUT = timedelta(minutes=60)
_PHASE3_HEARTBEAT = timedelta(minutes=2)


@workflow.defn
class PentestPipelineWorkflow:
    @workflow.run
    async def run(self, input: WorkflowInput) -> WorkflowResult:
        # ── Phase 0: preflight ────────────────────────────────────────────────
        preflight = await workflow.execute_activity(
            run_preflight_phase,
            input,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_POLICY,
        )
        if preflight.status == "aborted":
            return WorkflowResult(
                status="aborted",
                reason=preflight.reason,
                preflight_json=preflight.preflight_json,
            )

        # ── Phase 1: tool-only pre-recon ──────────────────────────────────────
        await workflow.execute_activity(
            run_pre_recon_phase,
            input,
            start_to_close_timeout=timedelta(minutes=30),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_POLICY,
        )

        # ── Phase 2: LLM recon ────────────────────────────────────────────────
        await workflow.execute_activity(
            run_recon_phase,
            input,
            start_to_close_timeout=timedelta(minutes=45),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_POLICY,
        )

        # ── Phase 3: parallel vulnerability analysis ──────────────────────────
        vuln_results = await asyncio.gather(
            workflow.execute_activity(
                run_injection_analysis,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            workflow.execute_activity(
                run_authz_analysis,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            workflow.execute_activity(
                run_info_disclosure_analysis,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            workflow.execute_activity(
                run_ssrf_analysis,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            workflow.execute_activity(
                run_sast_triage,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            workflow.execute_activity(
                run_sca_reachability,
                input,
                start_to_close_timeout=_PHASE3_TIMEOUT,
                heartbeat_timeout=_PHASE3_HEARTBEAT,
                retry_policy=_RETRY_POLICY,
            ),
            return_exceptions=True,
        )

        # ── OSS path: findings report (Phase 5a) ──────────────────────────────
        if not input.is_pro:
            return await workflow.execute_activity(
                run_findings_report,
                input,
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_POLICY,
            )

        # ── Pro path: Phase 4 — conditional parallel exploitation ─────────────
        exploit_tasks = [
            workflow.execute_activity(
                run_exploit_agent,
                input,
                start_to_close_timeout=timedelta(minutes=60),
                heartbeat_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_POLICY,
            )
            for result in vuln_results
            if isinstance(result, WorkflowResult) and result.status != "aborted"
        ]
        await asyncio.gather(*exploit_tasks, return_exceptions=True)

        # ── Pro path: Phase 5b — pentest report ───────────────────────────────
        return await workflow.execute_activity(
            run_pentest_report,
            input,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_POLICY,
        )
