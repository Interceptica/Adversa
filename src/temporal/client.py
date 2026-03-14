"""
Temporal client — submits PentestPipelineWorkflow for a given WorkflowInput.
"""
from __future__ import annotations

import os
import uuid

from temporalio.client import Client

from src.temporal.worker import TASK_QUEUE
from src.temporal.workflows import PentestPipelineWorkflow
from src.types import WorkflowInput, WorkflowResult


async def submit_engagement(input: WorkflowInput) -> WorkflowResult:
    """
    Submit a new pentest engagement workflow and wait for the result.

    Returns WorkflowResult with status "complete", "aborted", or "partial".
    """
    temporal_url = os.environ.get("TEMPORAL_SERVER_URL", "localhost:7233")
    client = await Client.connect(temporal_url)

    workflow_id = input.config.meta.engagement_id or f"adv-{uuid.uuid4().hex[:8]}"

    result: WorkflowResult = await client.execute_workflow(
        PentestPipelineWorkflow.run,
        input,
        id=workflow_id,
        task_queue=TASK_QUEUE,
    )
    return result
