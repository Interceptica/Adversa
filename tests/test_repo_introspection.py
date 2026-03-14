"""
Tests for INT-299: Phase 0 repo introspection.

Strategy under test:
  - Language detection: deterministic (manifest filenames)
  - Framework detection: claude-agent-sdk agent (query() mocked)
  - Ruleset validation: filtered by VALID_RULESETS
  - Config overrides: always win
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.artifacts.schemas import RepoProfile
from src.config.models import (
    AdversaConfig,
    AuthConfig,
    LLMConfig,
    MetaConfig,
    PipelineConfig,
    RepoConfig,
    ScopeConfig,
    ScopeRules,
    TargetConfig,
)
from src.services.repo_introspection import (
    VALID_RULESETS,
    _detect_languages,
    _fallback_rulesets,
    run_repo_introspection,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_config(
    repo_path: str = "/tmp",
    language: str | None = None,
    semgrep_rulesets: list[str] | None = None,
    joern_enabled: bool = False,
) -> AdversaConfig:
    return AdversaConfig(
        meta=MetaConfig(project="test", engagement_id="adv-test-001"),
        llm=LLMConfig(model_name="claude-sonnet-4-6", api_key="sk-test"),
        target=TargetConfig(base_url="https://api.target.com", included_hosts=["api.target.com"]),
        authentication=AuthConfig(login_type="none"),
        scope=ScopeConfig(rules=ScopeRules()),
        pipeline=PipelineConfig(enabled=["sast"]),
        repo=RepoConfig(path=repo_path, language=language, semgrep_rulesets=semgrep_rulesets, joern_enabled=joern_enabled),
    )


def _make_result_message(payload: str):
    """Construct a ResultMessage with all required fields populated."""
    from claude_agent_sdk import ResultMessage
    return ResultMessage(
        subtype="success",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id="test-session",
        result=payload,
    )


def _mock_query(frameworks: list[str], rulesets: list[str], confidence: str = "high"):
    """
    Return an async generator that yields a ResultMessage with the given payload.
    Used to mock claude_agent_sdk.query().
    """
    payload = json.dumps({
        "frameworks": frameworks,
        "semgrep_rulesets": rulesets,
        "confidence": confidence,
        "reasoning": "test",
    })

    async def _gen(*args, **kwargs):
        yield _make_result_message(payload)

    return _gen


def _mock_query_failure():
    """Returns an async generator that raises on iteration."""
    async def _gen(*args, **kwargs):
        raise Exception("agent call failed")
        yield  # make it a generator

    return _gen


def _mock_query_bad_json():
    """Returns an async generator that yields a ResultMessage with non-JSON text."""
    async def _gen(*args, **kwargs):
        yield _make_result_message("not valid json {{{{")

    return _gen


# ─── Language detection (deterministic) ───────────────────────────────────────


def test_detects_python_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.poetry]")
    assert "python" in _detect_languages(tmp_path)


def test_detects_python_from_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n")
    assert "python" in _detect_languages(tmp_path)


def test_detects_typescript_alongside_python(tmp_path):
    """Monorepo: both pyproject.toml and tsconfig.json present."""
    (tmp_path / "pyproject.toml").write_text("[project]")
    (tmp_path / "tsconfig.json").write_text("{}")
    langs = _detect_languages(tmp_path)
    assert "python" in langs
    assert "typescript" in langs


def test_detects_go(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    assert "go" in _detect_languages(tmp_path)


def test_detects_java_from_pom(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    assert "java" in _detect_languages(tmp_path)


def test_empty_repo_returns_no_languages(tmp_path):
    assert _detect_languages(tmp_path) == []


# ─── Full introspection — agent path ──────────────────────────────────────────


async def test_fastapi_repo_detected(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi"]')
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query(
        ["fastapi"], ["p/owasp-top-ten", "p/python"]
    )):
        result = await run_repo_introspection(config)

    assert "python" in result.languages
    assert "fastapi" in result.frameworks
    assert "p/python" in result.semgrep_rulesets
    assert "p/owasp-top-ten" in result.semgrep_rulesets


async def test_monorepo_fastapi_nextjs(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi"]')
    (tmp_path / "tsconfig.json").write_text("{}")
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "14.0.0"}}')
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query(
        ["fastapi", "nextjs"],
        ["p/owasp-top-ten", "p/python", "p/typescript", "p/nodejs"],
    )):
        result = await run_repo_introspection(config)

    assert "python" in result.languages
    assert "typescript" in result.languages
    assert "fastapi" in result.frameworks
    assert "nextjs" in result.frameworks
    assert "p/python" in result.semgrep_rulesets
    assert "p/typescript" in result.semgrep_rulesets


async def test_jwt_ruleset_included_when_agent_returns_it(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\npyjwt\n")
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query(
        ["fastapi"], ["p/owasp-top-ten", "p/python", "p/jwt"]
    )):
        result = await run_repo_introspection(config)

    assert "p/jwt" in result.semgrep_rulesets


# ─── Ruleset validation ───────────────────────────────────────────────────────


async def test_hallucinated_ruleset_filtered_out(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query(
        ["fastapi"],
        ["p/owasp-top-ten", "p/python", "p/made-up-ruleset", "p/another-fake"],
    )):
        result = await run_repo_introspection(config)

    for rs in result.semgrep_rulesets:
        assert rs in VALID_RULESETS, f"Invalid ruleset leaked through: {rs}"


async def test_owasp_always_present_even_if_agent_omits_it(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query(
        ["fastapi"], ["p/python"]  # no owasp
    )):
        result = await run_repo_introspection(config)

    assert "p/owasp-top-ten" in result.semgrep_rulesets


# ─── Agent failure fallback ───────────────────────────────────────────────────


async def test_agent_failure_falls_back_to_deterministic_rulesets(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query_failure()):
        result = await run_repo_introspection(config)

    assert "p/owasp-top-ten" in result.semgrep_rulesets
    assert "p/python" in result.semgrep_rulesets
    assert result.confidence == "low"


async def test_agent_invalid_json_falls_back(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app")
    config = _make_config(repo_path=str(tmp_path))

    with patch("src.services.repo_introspection.query", _mock_query_bad_json()):
        result = await run_repo_introspection(config)

    assert "p/owasp-top-ten" in result.semgrep_rulesets
    assert "go" in result.languages


# ─── Config overrides ─────────────────────────────────────────────────────────


async def test_config_language_overrides_detected(tmp_path):
    # Repo has go.mod but config says python
    (tmp_path / "go.mod").write_text("module example.com/app")
    config = _make_config(repo_path=str(tmp_path), language="python", semgrep_rulesets=["p/owasp-top-ten", "p/python"])

    result = await run_repo_introspection(config)

    assert result.languages == ["python"]
    assert result.detection_method == "config"


async def test_config_rulesets_override_detected(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    custom = ["p/owasp-top-ten", "p/django"]
    config = _make_config(repo_path=str(tmp_path), language="python", semgrep_rulesets=custom)

    result = await run_repo_introspection(config)

    assert result.semgrep_rulesets == custom
    assert result.detection_method == "config"


async def test_config_short_circuits_agent_call(tmp_path):
    """When config provides both language and rulesets, no agent call should be made."""
    (tmp_path / "pyproject.toml").write_text("[project]")
    config = _make_config(repo_path=str(tmp_path), language="python", semgrep_rulesets=["p/owasp-top-ten"])

    with patch("src.services.repo_introspection.query") as mock_query:
        await run_repo_introspection(config)
        mock_query.assert_not_called()


# ─── Fallback ruleset helper ──────────────────────────────────────────────────


def test_fallback_rulesets_python():
    assert "p/python" in _fallback_rulesets(["python"])
    assert "p/owasp-top-ten" in _fallback_rulesets(["python"])


def test_fallback_rulesets_multiple_languages():
    result = _fallback_rulesets(["python", "typescript"])
    assert "p/python" in result
    assert "p/typescript" in result
    assert "p/owasp-top-ten" in result


def test_fallback_rulesets_unknown_language():
    result = _fallback_rulesets(["cobol"])
    assert result == ["p/owasp-top-ten"]
