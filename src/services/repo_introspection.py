"""
Phase 0: Repo introspection — auto-detect language, frameworks, and Semgrep rulesets.
"""
from __future__ import annotations

from pathlib import Path

from typing import Literal

from claude_agent_sdk import ClaudeAgentOptions
from pydantic import BaseModel, Field

from src.artifacts.schemas import RepoProfile
from src.config.models import AdversaConfig
from src.services.agent_runner import build_agent_env, run_agent

# Read-only Claude Code built-in tools the introspection agent may use.
# LS   — list directory contents
# Read — read file contents
# Glob — find files by pattern
# Grep — search within files (useful for spotting deps inside manifests)
_ALLOWED_TOOLS = ["LS", "Read", "Glob", "Grep"]

# ─── Language → manifest file signals ─────────────────────────────────────────
# Stable. These filenames don't change as new frameworks appear.
# ALL matching languages are collected (no break) to support monorepos.

MANIFEST_SIGNALS: dict[str, list[str]] = {
    "python":     ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "javascript": ["package.json"],
    "typescript": ["tsconfig.json"],
    "java":       ["pom.xml", "build.gradle", "build.gradle.kts"],
    "go":         ["go.mod"],
    "rust":       ["Cargo.toml"],
    "ruby":       ["Gemfile"],
    "php":        ["composer.json"],
}

# ─── Valid Semgrep rulesets ────────────────────────────────────────────────────
# Agent-suggested rulesets are filtered against this set.
# To add a new ruleset: one-line addition here.

VALID_RULESETS: set[str] = {
    "p/owasp-top-ten",
    "p/python",
    "p/django",
    "p/flask",
    "p/java",
    "p/spring",
    "p/javascript",
    "p/typescript",
    "p/nodejs",
    "p/golang",
    "p/jwt",
    "p/ruby",
    "p/php",
}

# ─── Structured output schema ─────────────────────────────────────────────────


class IntrospectionResult(BaseModel):
    """Schema for the agent's structured output — drives JSON validation via claude-agent-sdk."""

    frameworks: list[str] = Field(
        description="Detected frameworks and libraries (e.g. ['express', 'angular', 'sequelize', 'jwt'])",
    )
    semgrep_rulesets: list[str] = Field(
        description="Semgrep rulesets to use — must be from the allowed list provided in the prompt",
    )
    confidence: Literal["high", "medium", "low"] = Field(
        description="How confident the detection is based on evidence found in the repo",
    )
    reasoning: str = Field(
        description="One-sentence explanation of what was found and how confidence was determined",
    )


_OUTPUT_FORMAT: dict = {
    "type": "json_schema",
    "schema": IntrospectionResult.model_json_schema(),
}

# ─── Agent prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a fast tech stack detection tool. "
    "Find and read dependency manifest files, identify frameworks, then return your result. "
    "Do NOT read source code. Do NOT verify framework usage. Only read manifest files."
)

_USER_PROMPT = """\
Analyse the repository at: {repo_path}

Languages already confirmed: {detected_languages}

Steps (do exactly these, nothing more):
1. Use Glob to find all manifest files: package.json, pyproject.toml, requirements.txt, go.mod, pom.xml, Cargo.toml, Gemfile, composer.json (search up to 2 levels deep)
2. Read each manifest file found
3. Return your result immediately after reading all manifests

Do NOT read source code files. Do NOT verify framework usage. Just read manifests and return.

Rules for your output:
- frameworks: list all frameworks/libraries found across ALL manifests (e.g. ["express", "angular", "fastapi", "sequelize"])
- semgrep_rulesets: choose ONLY from: {valid_rulesets}
- Always include p/owasp-top-ten
- Include p/jwt if any JWT dependency is present (jsonwebtoken, pyjwt, express-jwt, etc.)
"""


# ─── Public entry point ───────────────────────────────────────────────────────


async def run_repo_introspection(config: AdversaConfig) -> RepoProfile:
    """
    Detect languages deterministically, then run an agent that explores the
    repo with LS/Read/Glob tools to identify frameworks and Semgrep rulesets.

    Config-provided values always override detected values.
    Agent call is skipped when config already supplies both language and rulesets.
    """
    repo_path = Path(config.repo.path)

    # Step 1 — deterministic language detection (all languages, no break)
    detected_languages = _detect_languages(repo_path)

    # Step 2 — config override short-circuit (no agent call needed)
    if config.repo.language and config.repo.semgrep_rulesets:
        return RepoProfile(
            languages=[config.repo.language],
            frameworks=[],
            semgrep_rulesets=config.repo.semgrep_rulesets,
            joern_enabled=config.repo.joern_enabled,
            detection_method="config",
            confidence="high",
        )

    # Step 3 — agent explores the repo with tools and identifies frameworks
    agent_result = await _run_introspection_agent(
        repo_path=repo_path,
        detected_languages=detected_languages,
        config=config,
    )

    return _resolve(config, detected_languages, agent_result)


# ─── Step 1: deterministic language detection ─────────────────────────────────


def _detect_languages(repo_path: Path) -> list[str]:
    """Return all languages whose manifest files are present. No break — handles monorepos."""
    try:
        files = {f.name for f in repo_path.iterdir() if f.is_file()}
    except OSError:
        return []

    return [
        lang
        for lang, manifests in MANIFEST_SIGNALS.items()
        if any(m in files for m in manifests)
    ]


# ─── Step 2: agent — explores repo with tools ─────────────────────────────────


async def _run_introspection_agent(
    repo_path: Path,
    detected_languages: list[str],
    config: AdversaConfig,
) -> dict:
    """
    Run an agent with LS/Read/Glob tools to explore the repo and identify
    frameworks and Semgrep rulesets. Returns parsed JSON dict, or {} on failure.
    """
    prompt = _USER_PROMPT.format(
        repo_path=str(repo_path),
        detected_languages=", ".join(detected_languages) if detected_languages else "unknown",
        valid_rulesets=", ".join(sorted(VALID_RULESETS)),
    )

    options = ClaudeAgentOptions(
        model=config.llm.model_name,
        system_prompt=_SYSTEM_PROMPT,
        allowed_tools=_ALLOWED_TOOLS,
        max_turns=20,  
        cwd=str(repo_path),
        env=build_agent_env(config),
        permission_mode="default",
        output_format=_OUTPUT_FORMAT,
    )

    result = await run_agent(
        options=options,
        prompt=prompt,
        config=config,
    )

    return result.get("structured_output") or {}


# ─── Step 3: resolve + validate ───────────────────────────────────────────────


def _resolve(
    config: AdversaConfig,
    detected_languages: list[str],
    agent_result: dict,
) -> RepoProfile:
    """Merge deterministic languages with agent frameworks/rulesets. Validate rulesets."""
    frameworks: list[str] = agent_result.get("frameworks") or []
    confidence: str = agent_result.get("confidence", "low") if agent_result else "low"
    detection_method = "llm" if agent_result else "deterministic"

    # Validate agent-suggested rulesets — filter any hallucinated names
    raw_rulesets: list[str] = agent_result.get("semgrep_rulesets") or []
    rulesets = [r for r in raw_rulesets if r in VALID_RULESETS]

    # Always ensure the baseline ruleset is present
    if "p/owasp-top-ten" not in rulesets:
        rulesets.insert(0, "p/owasp-top-ten")

    # Fall back to language-derived rulesets if agent returned nothing useful
    if len(rulesets) == 1 and detected_languages:
        rulesets = _fallback_rulesets(detected_languages)

    # Config overrides for individual fields
    final_languages = [config.repo.language] if config.repo.language else detected_languages or ["unknown"]
    final_rulesets = config.repo.semgrep_rulesets or rulesets

    if config.repo.language or config.repo.semgrep_rulesets:
        detection_method = "config"

    return RepoProfile(
        languages=final_languages,
        frameworks=frameworks,
        semgrep_rulesets=final_rulesets,
        joern_enabled=config.repo.joern_enabled,
        detection_method=detection_method,
        confidence=confidence,
    )


def _fallback_rulesets(languages: list[str]) -> list[str]:
    """Minimal safe rulesets derived from detected languages when agent fails."""
    _lang_rulesets: dict[str, str] = {
        "python": "p/python",
        "javascript": "p/javascript",
        "typescript": "p/typescript",
        "java": "p/java",
        "go": "p/golang",
        "ruby": "p/ruby",
        "php": "p/php",
    }
    rulesets = ["p/owasp-top-ten"]
    for lang in languages:
        rs = _lang_rulesets.get(lang)
        if rs and rs not in rulesets:
            rulesets.append(rs)
    return rulesets
