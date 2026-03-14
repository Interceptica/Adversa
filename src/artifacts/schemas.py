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
class RepoProfile:
    """
    Tech-stack profile produced by Phase 0 repo introspection.

    languages / frameworks are lists to correctly represent monorepos
    (e.g. FastAPI backend + Next.js frontend in the same repo).

    detection_method:
      "deterministic" — manifest files only, no LLM tokens spent
      "llm"           — LLM called because no manifest files were found
      "config"        — user supplied language/rulesets in adversa.config.yaml
    """

    languages: list[str]               # e.g. ["python", "typescript"]
    frameworks: list[str]              # e.g. ["fastapi", "nextjs"]
    semgrep_rulesets: list[str]        # e.g. ["p/owasp-top-ten", "p/python"]
    joern_enabled: bool = True
    detection_method: str = "deterministic"
    confidence: str = "high"           # "high" | "medium" | "low"


@dataclass
class PreflightResult:
    status: str  # "pass" | "fail"
    checks: list[Check] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scope_manifest: dict = field(default_factory=dict)
    repo_profile: RepoProfile | None = None
