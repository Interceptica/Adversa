"""
Phase 0: Repo introspection — auto-detect language, frameworks, and Semgrep rulesets.
"""
from __future__ import annotations

from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions

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

# ─── Agent prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a tech stack detection tool for security testing. "
    "Explore the repository using your tools, then respond with a single valid "
    "JSON object — no markdown, no explanation."
)

_USER_PROMPT = """\
Analyse the repository at: {repo_path}

Languages already confirmed from manifest filenames (treat as ground truth):
{detected_languages}

Use your tools to explore the repository:
1. Use LS to list the root directory and any relevant subdirectories
2. Use Read to examine manifest files (package.json, pyproject.toml, requirements.txt, go.mod, pom.xml, Cargo.toml, etc.)
3. Use Glob to find any other relevant configuration or dependency files

Once you have explored enough, respond with ONLY this JSON structure:
{{
  "frameworks": ["<name>", ...],
  "semgrep_rulesets": ["<ruleset>", ...],
  "confidence": "<high|medium|low>",
  "reasoning": "<one sentence>"
}}

Rules:
- frameworks: list every framework/library you can identify (e.g. ["fastapi", "nextjs", "celery", "sqlalchemy"])
- semgrep_rulesets: choose only from this allowed list:
  {valid_rulesets}
- Always include p/owasp-top-ten
- Always include p/jwt if any JWT-related dependency is present
- If you cannot determine frameworks, return an empty list
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
        max_turns=15,
        cwd=str(repo_path),
        env=build_agent_env(config),
        permission_mode="default",
    )

    result = await run_agent(
        options=options,
        prompt=prompt,
        config=config,
        parse_json=True,
    )

    return result.get("parsed") or {}


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
