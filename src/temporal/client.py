"""
Temporal client — submits PentestPipelineWorkflow for a given WorkflowInput.

Can also be run directly as a module for dev/smoke-testing:

    python -m src.temporal.client --config ./configs/juiceshop.config.yaml --phase preflight

Unimplemented phases are stubs so the workflow completes quickly. The
--phase flag controls what the output focuses on (currently: preflight).
"""
from __future__ import annotations

import json
import os
import sys
import uuid

from temporalio.client import Client

from src.temporal.worker import TASK_QUEUE
from src.temporal.workflows import PentestPipelineWorkflow
from src.types import WorkflowInput, WorkflowResult


async def submit_engagement(input: WorkflowInput) -> WorkflowResult:
    """
    Submit PentestPipelineWorkflow and wait for the result.

    Returns WorkflowResult with status "complete", "aborted", or "partial".
    preflight_json is populated regardless of whether later phases succeed.
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


# ─── __main__ — used by `./adversa dev` and `./adversa start` ────────────────

if __name__ == "__main__":
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(description="Adversa workflow client")
    parser.add_argument("--config", required=True, help="Path to adversa config YAML")
    parser.add_argument(
        "--phase",
        default=None,
        choices=["preflight", "prerecon"],
        help="Focus output on a specific phase result (workflow always runs in full)",
    )
    args = parser.parse_args()

    from src.config.loader import load_config

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"[error] Failed to load config: {exc}", file=sys.stderr)
        sys.exit(1)

    workflow_input = WorkflowInput(config=config)

    async def _run() -> int:
        result = await submit_engagement(workflow_input)

        if args.phase == "preflight" and result.preflight_json:
            # Print the PreflightResult JSON so dev can inspect Phase 0 output
            data = json.loads(result.preflight_json)
            print(json.dumps(data, indent=2))
        elif args.phase == "prerecon":
            # Print Phase 1 artifact summary from artifact store
            from src.artifacts.store import ArtifactStore
            store = ArtifactStore(config.meta.engagement_id)
            summary = {}
            all_warnings: list[str] = []
            for artifact in ["SEMGREP_RAW", "SBOM", "INFRA_MAP", "TECH_STACK", "JOERN_CPG_PATH"]:
                if store.exists(artifact):
                    data = store.read(artifact)
                    # Collect warnings from all artifacts
                    artifact_warnings = data.get("warnings", [])
                    for w in artifact_warnings:
                        all_warnings.append(f"[{artifact}] {w}")
                    # Show counts/status, not full data
                    if artifact == "SEMGREP_RAW":
                        summary[artifact] = {
                            "total": data.get("total"),
                            "files_scanned": data.get("files_scanned", 0),
                            "by_severity": data.get("by_severity"),
                            "rulesets_used": data.get("rulesets_used"),
                            "error": data.get("error"),
                        }
                    elif artifact == "SBOM":
                        summary[artifact] = {
                            "total": data.get("total"),
                            "by_severity": data.get("by_severity"),
                            "lockfile_found": data.get("lockfile_found"),
                            "lockfile_type": data.get("lockfile_type"),
                            "error": data.get("error"),
                        }
                    elif artifact == "INFRA_MAP":
                        summary[artifact] = {"total_hosts": data.get("total_hosts"), "total_open_ports": data.get("total_open_ports")}
                    elif artifact == "TECH_STACK":
                        summary[artifact] = {"technologies": data.get("technologies", []), "servers": data.get("servers", [])}
                    elif artifact == "JOERN_CPG_PATH":
                        summary[artifact] = {"success": data.get("success"), "error": data.get("error")}
                else:
                    summary[artifact] = {"status": "missing"}
                    all_warnings.append(f"[{artifact}] Artifact not produced — scanner may have crashed.")
            output = {
                "status": result.status,
                "reason": result.reason,
                "artifacts": summary,
            }
            if all_warnings:
                output["warnings"] = all_warnings
            print(json.dumps(output, indent=2))
        else:
            print(json.dumps({"status": result.status, "reason": result.reason}, indent=2))

        return 0 if result.status == "complete" else 1

    sys.exit(asyncio.run(_run()))
