"""
Shared utilities for agentic phases.

Extracted from pre_recon.py to avoid duplication across agents.
"""
from __future__ import annotations

from src.artifacts.store import ArtifactStore
from src.config.models import AdversaConfig


def format_scope_rules(config: AdversaConfig) -> str:
    """Format scope avoid/focus rules as markdown for prompt injection."""
    lines: list[str] = []
    avoid = config.scope.rules.avoid
    focus = config.scope.rules.focus

    if not avoid and not focus:
        return ""

    lines.append("## Scope Rules\n")

    if avoid:
        lines.append("**AVOID these paths/endpoints (do NOT scan, probe, or include in results):**")
        for rule in avoid:
            path = rule.url_path or "(host-level)"
            lines.append(f"- `{path}` ({rule.type}) — {rule.description}")
        lines.append("")

    if focus:
        lines.append("**FOCUS on these paths/endpoints (prioritize scanning and deeper analysis):**")
        for rule in focus:
            path = rule.url_path or "(host-level)"
            lines.append(f"- `{path}` ({rule.type}) — {rule.description}")
        lines.append("")

    return "\n".join(lines)


def format_preflight_context(store: ArtifactStore) -> str:
    """Format preflight results as context for the agent prompt."""
    if not store.exists("PREFLIGHT_RESULT"):
        return ""

    preflight = store.read("PREFLIGHT_RESULT")
    lines: list[str] = ["**Phase 0 Preflight Results (use this to guide your scans):**"]

    # Repo profile — frameworks are especially useful for choosing scan strategies
    rp = preflight.get("repo_profile")
    if rp:
        if rp.get("frameworks"):
            lines.append(f"- Frameworks detected: {', '.join(rp['frameworks'])}")
        lines.append(f"- Detection method: {rp.get('detection_method', 'unknown')}, "
                     f"confidence: {rp.get('confidence', 'unknown')}")

    # Scope manifest — agent needs to know what's in/out of scope
    sm = preflight.get("scope_manifest")
    if sm:
        import json
        manifest = json.loads(sm) if isinstance(sm, str) else sm
        if manifest.get("excluded_paths"):
            lines.append(f"- Excluded paths: {', '.join(manifest['excluded_paths'])}")
        if manifest.get("excluded_patterns"):
            lines.append(f"- Excluded patterns: {', '.join(manifest['excluded_patterns'])}")

    # Check results — warn about any failures the agent should know about
    checks = preflight.get("checks", [])
    failed = [c for c in checks if c.get("status") == "fail"]
    if failed:
        lines.append("- **Preflight warnings:**")
        for c in failed:
            lines.append(f"  - {c['name']}: {c.get('detail', 'failed')}")

    return "\n".join(lines) + "\n"


def is_docker() -> bool:
    """Detect if running inside Docker."""
    try:
        with open("/proc/1/cgroup") as f:
            return "docker" in f.read()
    except Exception:
        return False
