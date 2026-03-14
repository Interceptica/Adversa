"""
Temporal worker — registers PentestPipelineWorkflow and all activity stubs.
Run this as the worker process; it polls Temporal server on the default task queue.
"""
from __future__ import annotations

import asyncio
import os

from temporalio.client import Client
from temporalio.worker import Worker

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
from src.temporal.workflows import PentestPipelineWorkflow

TASK_QUEUE = "adversa-pipeline"


async def run_worker() -> None:
    temporal_url = os.environ.get("TEMPORAL_SERVER_URL", "localhost:7233")
    client = await Client.connect(temporal_url)

    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[PentestPipelineWorkflow],
        activities=[
            run_preflight_phase,
            run_pre_recon_phase,
            run_recon_phase,
            run_injection_analysis,
            run_authz_analysis,
            run_info_disclosure_analysis,
            run_ssrf_analysis,
            run_sast_triage,
            run_sca_reachability,
            run_exploit_agent,
            run_findings_report,
            run_pentest_report,
        ],
    )

    print(f"Worker started — polling task queue '{TASK_QUEUE}' on {temporal_url}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
