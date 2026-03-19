"""Tests for Phase 2 recon agent — login flow, phase1 context, artifact verification, fallback."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test")

from src.agents.recon import (
    RECON_DELIVERABLE,
    _build_playwright_mcp,
    _fallback_output,
    _format_login_flow,
    _format_phase1_context,
    _verify_artifacts,
)
from src.artifacts.store import ArtifactStore
from src.config.models import (
    AdversaConfig,
    AuthConfig,
    AuthCredentials,
    LLMConfig,
    MetaConfig,
    PipelineConfig,
    RepoConfig,
    ScopeConfig,
    ScopeRules,
    SuccessCondition,
    TargetConfig,
    TokenExtraction,
)


def _make_config(
    login_type: str = "none",
    credentials: AuthCredentials | None = None,
    login_flow: list[str] | None = None,
    login_url: str | None = None,
    success_condition: SuccessCondition | None = None,
    token_extraction: TokenExtraction | None = None,
) -> AdversaConfig:
    return AdversaConfig(
        meta=MetaConfig(project="test", engagement_id="adv-test-recon"),
        llm=LLMConfig(model_name="claude-sonnet-4-6", api_key_env="ANTHROPIC_API_KEY"),
        target=TargetConfig(base_url="https://juice.shop", included_hosts=["juice.shop"]),
        authentication=AuthConfig(
            login_type=login_type,
            login_url=login_url,
            credentials=credentials,
            login_flow=login_flow or [],
            success_condition=success_condition,
            token_extraction=token_extraction,
        ),
        scope=ScopeConfig(rules=ScopeRules()),
        pipeline=PipelineConfig(enabled=["injection"]),
        repo=RepoConfig(path="/tmp/repo"),
    )


# ─── _format_login_flow ────────────────────────────────────────────────────


def test_format_login_flow_none():
    config = _make_config(login_type="none")
    result = _format_login_flow(config)
    assert "No authentication required" in result


def test_format_login_flow_form():
    config = _make_config(
        login_type="form",
        login_url="https://juice.shop/#/login",
        credentials=AuthCredentials(username="admin@juice.shop", password="admin123"),
        login_flow=[
            "Type $username into the email field",
            "Type $password into the password field",
            "Click the Log in button",
        ],
        success_condition=SuccessCondition(type="url_contains", value="/search"),
    )
    result = _format_login_flow(config)

    assert "admin@juice.shop" in result
    assert "admin123" in result
    assert "$username" not in result
    assert "$password" not in result
    assert "1. Navigate to" in result
    assert "url_contains" in result
    assert "/search" in result


def test_format_login_flow_bearer():
    config = _make_config(
        login_type="bearer",
        credentials=AuthCredentials(username="unused", password="test-token-xyz"),
    )
    result = _format_login_flow(config)
    assert "Bearer" in result
    assert "test-token-xyz" in result
    assert "No browser login needed" in result


def test_format_login_flow_totp():
    config = _make_config(
        login_type="form",
        login_url="https://app.example.com/login",
        credentials=AuthCredentials(
            username="user@example.com",
            password="secret",
            totp_secret="JBSWY3DPEHPK3PXP",
        ),
        login_flow=["Type $username into email", "Type $password into password", "Click Sign In"],
    )
    result = _format_login_flow(config)
    assert "JBSWY3DPEHPK3PXP" in result
    assert "oathtool" in result


def test_format_login_flow_api_key():
    config = _make_config(
        login_type="api_key",
        credentials=AuthCredentials(username="unused", password="x-api-key: abc123"),
    )
    result = _format_login_flow(config)
    assert "x-api-key: abc123" in result
    assert "No browser login needed" in result


def test_format_login_flow_token_extraction_cookie():
    config = _make_config(
        login_type="form",
        login_url="https://app.example.com/login",
        credentials=AuthCredentials(username="user", password="pass"),
        login_flow=["Type $username into email", "Type $password into password", "Click Login"],
        token_extraction=TokenExtraction(type="cookie"),
    )
    result = _format_login_flow(config)
    assert "cookie" in result.lower()


def test_format_login_flow_token_extraction_header():
    config = _make_config(
        login_type="form",
        login_url="https://app.example.com/login",
        credentials=AuthCredentials(username="user", password="pass"),
        login_flow=["Type $username into email", "Type $password into password", "Click Login"],
        token_extraction=TokenExtraction(type="response_header", header="X-Auth-Token"),
    )
    result = _format_login_flow(config)
    assert "X-Auth-Token" in result


# ─── _format_phase1_context ─────────────────────────────────────────────────


def test_format_phase1_context_all(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("INFRA_MAP", {
        "hosts": [{"hostname": "juice.shop", "ports": [{"port": 3000, "service": "http"}]}],
        "total_hosts": 1,
        "total_open_ports": 1,
    })
    store.write("TECH_STACK", {
        "technologies": ["Node.js", "Express", "Angular"],
        "servers": ["Express/4.18"],
    })
    store.write("SEMGREP_RAW", {
        "results": [{"rule_id": "test", "path": "server.js", "start": {"line": 10}}],
    })
    store.write("PREFLIGHT_RESULT", {
        "status": "pass",
        "repo_profile": {
            "frameworks": ["express"],
            "detection_method": "deterministic",
            "confidence": "high",
        },
    })

    result = _format_phase1_context(store)
    assert "juice.shop" in result
    assert "3000" in result
    assert "Node.js" in result
    assert "1 finding" in result


def test_format_phase1_context_missing(tmp_path):
    store = ArtifactStore("eng-002", base_dir=str(tmp_path))
    result = _format_phase1_context(store)
    assert "No Phase 1 artifacts" in result


def test_format_phase1_context_partial(tmp_path):
    store = ArtifactStore("eng-003", base_dir=str(tmp_path))
    store.write("TECH_STACK", {"technologies": ["Django"], "servers": []})
    result = _format_phase1_context(store)
    assert "Django" in result


# ─── _verify_artifacts ──────────────────────────────────────────────────────


def test_verify_artifacts_present(tmp_path):
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("AUTH_SESSION", {"success": True})
    (Path(tmp_path) / "eng-001" / "artifacts" / RECON_DELIVERABLE).write_text("# Recon\n...")

    _verify_artifacts(store)  # no warnings expected


def test_verify_artifacts_missing(tmp_path, caplog):
    import logging
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))

    with caplog.at_level(logging.WARNING):
        _verify_artifacts(store)

    assert RECON_DELIVERABLE in caplog.text
    assert "AUTH_SESSION" in caplog.text


def test_verify_artifacts_only_markdown_missing(tmp_path, caplog):
    import logging
    store = ArtifactStore("eng-001", base_dir=str(tmp_path))
    store.write("AUTH_SESSION", {"success": True})

    with caplog.at_level(logging.WARNING):
        _verify_artifacts(store)

    assert RECON_DELIVERABLE in caplog.text
    assert "AUTH_SESSION" not in caplog.text


# ─── _fallback_output ────────────────────────────────────────────────────────


def test_fallback_output():
    output = _fallback_output("connection refused")
    assert output["markdown_written"] is False
    assert output["markdown_path"] is None
    assert output["error"] == "connection refused"


# ─── _build_playwright_mcp ──────────────────────────────────────────────────


def test_build_playwright_mcp():
    mcp = _build_playwright_mcp()
    assert mcp["command"] == "npx"
    assert "@playwright/mcp@latest" in mcp["args"]
    assert "--headless" in mcp["args"]
    assert "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH" in mcp["env"]


def test_build_playwright_mcp_custom_path(monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", "/custom/chromium")
    mcp = _build_playwright_mcp()
    assert mcp["env"]["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"] == "/custom/chromium"


# ─── run_recon (agent mocked) ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_recon_success(tmp_path):
    from src.agents.recon import run_recon

    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    # Simulate agent writing both artifacts via Bash
    artifact_dir = Path(tmp_path) / config.meta.engagement_id / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / RECON_DELIVERABLE).write_text("# Reconnaissance Deliverable\n\n## 1. Executive Summary\n...")
    store.write("AUTH_SESSION", {"success": True, "login_type": "none", "cookies": {}, "headers": {}})

    with patch(
        "src.agents.recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "Recon complete", "structured_output": None, "error": None},
    ):
        result = await run_recon(config, store)

    assert result["markdown_written"] is True
    assert result["error"] is None
    assert RECON_DELIVERABLE in result["markdown_path"]


@pytest.mark.asyncio
async def test_run_recon_no_markdown_written(tmp_path):
    from src.agents.recon import run_recon

    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    # Agent ran but didn't write the markdown
    with patch(
        "src.agents.recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "", "structured_output": None, "error": None},
    ):
        result = await run_recon(config, store)

    assert result["markdown_written"] is False
    assert "recon_deliverable.md" in result["error"]


@pytest.mark.asyncio
async def test_run_recon_agent_failure(tmp_path):
    from src.agents.recon import run_recon

    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    with patch(
        "src.agents.recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "", "structured_output": None, "error": "API timeout"},
    ):
        result = await run_recon(config, store)

    assert result["markdown_written"] is False
    # Error from agent is preserved
    assert result["error"] is not None


@pytest.mark.asyncio
async def test_run_recon_empty_markdown_treated_as_failure(tmp_path):
    from src.agents.recon import run_recon

    config = _make_config()
    store = ArtifactStore(config.meta.engagement_id, base_dir=str(tmp_path))

    # Agent wrote an empty file
    artifact_dir = Path(tmp_path) / config.meta.engagement_id / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / RECON_DELIVERABLE).write_text("")

    with patch(
        "src.agents.recon.run_agent",
        new_callable=AsyncMock,
        return_value={"result": "", "structured_output": None, "error": None},
    ):
        result = await run_recon(config, store)

    assert result["markdown_written"] is False
