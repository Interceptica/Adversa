"""
Tests for INT-282: Phase 0 pre-flight activity.

Networking and subprocess calls are fully mocked so tests run offline
with no external dependencies.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.artifacts.schemas import Check, PreflightResult
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
from src.services.preflight import run_preflight


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_config(
    base_url: str = "https://api.target.com",
    included_hosts: list[str] | None = None,
    repo_path: str = "/tmp",
    joern_enabled: bool = False,
    api_key: str = "sk-test",
    model_name: str = "claude-sonnet-4-6",
) -> AdversaConfig:
    return AdversaConfig(
        meta=MetaConfig(project="test", engagement_id="adv-test-001"),
        llm=LLMConfig(model_name=model_name, api_key=api_key),
        target=TargetConfig(
            base_url=base_url,
            included_hosts=included_hosts or ["api.target.com"],
        ),
        authentication=AuthConfig(login_type="none"),
        scope=ScopeConfig(rules=ScopeRules()),
        pipeline=PipelineConfig(enabled=["sast"]),
        repo=RepoConfig(path=repo_path, joern_enabled=joern_enabled),
    )


def _mock_which_pass(tool_names: list[str]):
    """Return a subprocess mock where every `which <tool>` call succeeds."""
    result = MagicMock()
    result.returncode = 0
    return result


def _mock_http_response(status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _check_by_name(result: PreflightResult, name: str) -> Check:
    for c in result.checks:
        if c.name == name:
            return c
    raise KeyError(f"Check '{name}' not found in result")


# ─── All-pass scenario ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_all_checks_pass(tmp_path):
    config = _make_config(repo_path=str(tmp_path))

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        # HEAD → 200, POST (api_key) → 200
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(200))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert result.status == "pass"
    assert result.errors == []
    assert _check_by_name(result, "scope_valid").status == "pass"
    assert _check_by_name(result, "target_reachable").status == "pass"
    assert _check_by_name(result, "repo_accessible").status == "pass"
    assert _check_by_name(result, "tool:semgrep").status == "pass"
    assert _check_by_name(result, "api_key_valid").status == "pass"
    assert isinstance(result.scope_manifest, dict)
    assert "included_hosts" in result.scope_manifest


# ─── Target unreachable ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unreachable_target_fails(tmp_path):
    config = _make_config(repo_path=str(tmp_path))

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.post = AsyncMock(return_value=_mock_http_response(200))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert result.status == "fail"
    assert _check_by_name(result, "target_reachable").status == "fail"
    assert any("Connection refused" in e for e in result.errors)


# ─── Missing repo path ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_repo_path_fails(tmp_path):
    config = _make_config(repo_path="/nonexistent/repo/path")

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(200))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert result.status == "fail"
    assert _check_by_name(result, "repo_accessible").status == "fail"
    assert any("/nonexistent/repo/path" in e for e in result.errors)


# ─── Multiple failures collected in one pass (not short-circuited) ────────────


@pytest.mark.asyncio
async def test_multiple_failures_all_collected(tmp_path):
    config = _make_config(repo_path="/nonexistent/path")

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=1)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(side_effect=Exception("timeout"))
        mock_client.post = AsyncMock(return_value=_mock_http_response(401))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert result.status == "fail"
    failed_names = {c.name for c in result.checks if c.status == "fail"}
    # repo, target, all tools, api_key must all be in the result — not stopped early
    assert "target_reachable" in failed_names
    assert "repo_accessible" in failed_names
    assert "tool:semgrep" in failed_names
    assert "api_key_valid" in failed_names
    # errors only contains non-null details; failed checks (incl. tools) are in checks
    assert len([c for c in result.checks if c.status == "fail"]) >= 4


# ─── API key invalid (401) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invalid_api_key_fails(tmp_path):
    config = _make_config(repo_path=str(tmp_path))

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(401))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert result.status == "fail"
    assert _check_by_name(result, "api_key_valid").status == "fail"


# ─── 400 from API still means key is accepted ─────────────────────────────────


@pytest.mark.asyncio
async def test_api_400_treated_as_key_valid(tmp_path):
    """A 400 (e.g. unknown model) means the key was accepted — not a key failure."""
    config = _make_config(repo_path=str(tmp_path))

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(400))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    assert _check_by_name(result, "api_key_valid").status == "pass"


# ─── Joern added to tool list when joern_enabled=True ────────────────────────


@pytest.mark.asyncio
async def test_joern_checked_when_enabled(tmp_path):
    config = _make_config(repo_path=str(tmp_path), joern_enabled=True)

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(200))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    check_names = {c.name for c in result.checks}
    assert "tool:joern" in check_names


@pytest.mark.asyncio
async def test_joern_not_checked_when_disabled(tmp_path):
    config = _make_config(repo_path=str(tmp_path), joern_enabled=False)

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(return_value=_mock_http_response(200))
        mock_client.post = AsyncMock(return_value=_mock_http_response(200))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    check_names = {c.name for c in result.checks}
    assert "tool:joern" not in check_names


# ─── scope_manifest is always populated ───────────────────────────────────────


@pytest.mark.asyncio
async def test_scope_manifest_always_emitted(tmp_path):
    config = _make_config(repo_path="/nonexistent/path")

    with (
        patch("src.services.preflight.httpx.AsyncClient") as mock_client_cls,
        patch("src.services.preflight.subprocess.run", return_value=MagicMock(returncode=1)),
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.head = AsyncMock(side_effect=Exception("timeout"))
        mock_client.post = AsyncMock(return_value=_mock_http_response(401))
        mock_client_cls.return_value = mock_client

        result = await run_preflight(config)

    # scope_manifest must be emitted even when status=fail
    assert isinstance(result.scope_manifest, dict)
    assert "included_hosts" in result.scope_manifest
