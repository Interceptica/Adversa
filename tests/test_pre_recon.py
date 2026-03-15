"""Tests for Phase 1 pre-recon agent — artifact verification, fallback, repo profile, scope rules."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test")

from src.agents.pre_recon import (
    _fallback_output,
    _format_scope_rules,
    _load_repo_profile,
    _verify_artifacts,
)
from src.artifacts.store import ArtifactStore
from src.config.models import (
    AdversaConfig,
    AuthConfig,
    LLMConfig,
    MetaConfig,
    PipelineConfig,
    RepoConfig,
    ScopeConfig,
    ScopeRule,
    ScopeRules,
    TargetConfig,
)


def _make_config(joern_enabled: bool = True, avoid=None, focus=None) -> AdversaConfig:
    rules = ScopeRules(avoid=avoid or [], focus=focus or [])
    return AdversaConfig(
        meta=MetaConfig(project="test", engagement_id="adv-test-prerecon"),
        llm=LLMConfig(model_name="claude-sonnet-4-6", api_key_env="ANTHROPIC_API_KEY"),
        target=TargetConfig(base_url="https://example.com", included_hosts=["example.com"]),
        authentication=AuthConfig(login_type="none"),
        scope=ScopeConfig(rules=rules),
        pipeline=PipelineConfig(enabled=["injection"]),
        repo=RepoConfig(path="/tmp/repo", joern_enabled=joern_enabled),
    )


# ─── _load_repo_profile ─────────────────────────────────────────────────────


def test_load_repo_profile_from_store(tmp_path):
    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))
    store.write("PREFLIGHT_RESULT", {
        "status": "pass",
        "repo_profile": {
            "languages": ["python"],
            "semgrep_rulesets": ["p/owasp-top-ten", "p/python"],
            "joern_enabled": True,
        },
    })

    profile = _load_repo_profile(store, config)
    assert profile["languages"] == ["python"]
    assert "p/python" in profile["semgrep_rulesets"]


def test_load_repo_profile_fallback(tmp_path):
    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    profile = _load_repo_profile(store, config)
    assert profile["semgrep_rulesets"] == ["p/owasp-top-ten"]
    assert profile["joern_enabled"] is True


def test_load_repo_profile_with_config_language(tmp_path):
    config = AdversaConfig(
        meta=MetaConfig(project="test", engagement_id="adv-test-prerecon"),
        llm=LLMConfig(model_name="claude-sonnet-4-6", api_key_env="ANTHROPIC_API_KEY"),
        target=TargetConfig(base_url="https://example.com", included_hosts=["example.com"]),
        authentication=AuthConfig(login_type="none"),
        scope=ScopeConfig(rules=ScopeRules()),
        pipeline=PipelineConfig(enabled=["injection"]),
        repo=RepoConfig(path="/tmp/repo", language="java", semgrep_rulesets=["p/java", "p/spring"]),
    )
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    profile = _load_repo_profile(store, config)
    assert profile["languages"] == ["java"]
    assert profile["semgrep_rulesets"] == ["p/java", "p/spring"]


def test_load_repo_profile_null_repo_profile(tmp_path):
    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))
    store.write("PREFLIGHT_RESULT", {"status": "pass", "repo_profile": None})

    profile = _load_repo_profile(store, config)
    assert profile["semgrep_rulesets"] == ["p/owasp-top-ten"]


# ─── _format_scope_rules ───────────────────────────────────────────────────


def test_format_scope_rules_empty():
    config = _make_config()
    assert _format_scope_rules(config) == ""


def test_format_scope_rules_avoid_only():
    config = _make_config(avoid=[
        ScopeRule(description="Skip health", type="path", url_path="/health"),
    ])
    result = _format_scope_rules(config)
    assert "AVOID" in result
    assert "/health" in result
    assert "Skip health" in result
    assert "FOCUS" not in result


def test_format_scope_rules_focus_only():
    config = _make_config(focus=[
        ScopeRule(description="Focus on API", type="path_pattern", url_path="/api/*"),
    ])
    result = _format_scope_rules(config)
    assert "FOCUS" in result
    assert "/api/*" in result
    assert "AVOID" not in result


def test_format_scope_rules_both():
    config = _make_config(
        avoid=[ScopeRule(description="Skip health", type="path", url_path="/health")],
        focus=[ScopeRule(description="Focus on API", type="path_pattern", url_path="/api/*")],
    )
    result = _format_scope_rules(config)
    assert "AVOID" in result
    assert "FOCUS" in result
    assert "/health" in result
    assert "/api/*" in result


# ─── _verify_artifacts ──────────────────────────────────────────────────────


def test_verify_artifacts_all_present(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    for name in ["SEMGREP_RAW", "SBOM", "INFRA_MAP", "TECH_STACK", "JOERN_CPG_PATH"]:
        store.write(name, {})

    # Should not raise or log warnings
    _verify_artifacts(store)


def test_verify_artifacts_missing(tmp_path, caplog):
    import logging
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("SEMGREP_RAW", {})

    with caplog.at_level(logging.WARNING):
        _verify_artifacts(store)

    assert "SBOM" in caplog.text
    assert "INFRA_MAP" in caplog.text


# ─── _fallback_output ────────────────────────────────────────────────────────


def test_fallback_output_has_all_keys():
    output = _fallback_output("connection refused")

    assert output["semgrep_error"] == "connection refused"
    assert output["sca_error"] == "connection refused"
    assert output["joern_success"] is False
    assert output["semgrep_findings_count"] == 0
    assert output["sca_vulns_count"] == 0
    assert output["infra_open_ports"] == 0
    assert "failed" in output["summary"]


# ─── run_pre_recon (agent mocked) ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_pre_recon_success(tmp_path):
    from src.agents.pre_recon import run_pre_recon

    config = _make_config(joern_enabled=False)
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))
    store.write("PREFLIGHT_RESULT", {
        "status": "pass",
        "repo_profile": {
            "languages": ["javascript"],
            "semgrep_rulesets": ["p/owasp-top-ten", "p/javascript"],
            "joern_enabled": False,
        },
    })

    # Simulate that agent wrote artifacts via Bash
    for name in ["SEMGREP_RAW", "SBOM", "INFRA_MAP", "TECH_STACK", "JOERN_CPG_PATH"]:
        store.write(name, {})

    mock_output = {
        "semgrep_findings_count": 2,
        "semgrep_error": None,
        "sca_vulns_count": 1,
        "sca_lockfile_found": True,
        "sca_error": None,
        "infra_open_ports": 3,
        "joern_success": False,
        "joern_error": "Joern disabled in config",
        "summary": "Scanned successfully",
    }

    with patch(
        "src.agents.pre_recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "", "structured_output": mock_output, "error": None},
    ):
        result = await run_pre_recon(config, store)

    assert result["semgrep_findings_count"] == 2
    assert result["sca_lockfile_found"] is True
    assert result["summary"] == "Scanned successfully"


@pytest.mark.asyncio
async def test_run_pre_recon_agent_failure(tmp_path):
    from src.agents.pre_recon import run_pre_recon

    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    with patch(
        "src.agents.pre_recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "", "structured_output": None, "error": "API timeout"},
    ):
        result = await run_pre_recon(config, store)

    # Should use fallback output
    assert result["semgrep_error"] == "API timeout"
    assert result["joern_success"] is False
    assert "failed" in result["summary"]
