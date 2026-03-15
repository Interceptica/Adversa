from __future__ import annotations

from dataclasses import dataclass, field

from src.config.models import AdversaConfig


@dataclass
class WorkflowInput:
    config: AdversaConfig
    is_pro: bool = False


@dataclass
class WorkflowResult:
    status: str  # "complete" | "aborted" | "partial"
    report_path: str | None = None
    reason: str | None = None
    preflight_json: str | None = None  # serialised PreflightResult, set by PreflightWorkflow
