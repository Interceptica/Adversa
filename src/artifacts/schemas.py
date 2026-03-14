"""
Typed artifact schemas for inter-phase communication.

All artifacts are written via the save_deliverable MCP tool and read by
subsequent phases. No direct agent-to-agent calls — everything flows through
these typed structures.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ─── Phase 0 ──────────────────────────────────────────────────────────────────


@dataclass
class Check:
    name: str
    status: str  # "pass" | "fail"
    detail: str | None = None


@dataclass
class PreflightResult:
    status: str  # "pass" | "fail"
    checks: list[Check] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scope_manifest: dict = field(default_factory=dict)
