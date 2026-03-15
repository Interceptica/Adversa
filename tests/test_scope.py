"""
Tests for INT-279: ScopeEnforcer + can_use_tool + AuditLogger.
"""
from __future__ import annotations

import json
import asyncio
import os
from pathlib import Path

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test")

from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny, ToolPermissionContext

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
from src.audit.logger import AuditLogger
from src.scope.enforcer import ScopeEnforcer, ScopeResult, _extract_url
from src.scope.can_use_tool import build_can_use_tool


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_scope_config(avoid: list[dict] | None = None, focus: list[dict] | None = None) -> ScopeConfig:
    avoid_rules = [ScopeRule(**r) for r in (avoid or [])]
    focus_rules = [ScopeRule(**r) for r in (focus or [])]
    return ScopeConfig(rules=ScopeRules(avoid=avoid_rules, focus=focus_rules))


def _make_enforcer(
    included_hosts: list[str] | None = None,
    excluded_hosts: list[str] | None = None,
    avoid: list[dict] | None = None,
) -> ScopeEnforcer:
    scope = _make_scope_config(avoid=avoid)
    return ScopeEnforcer(
        config=scope,
        included_hosts=included_hosts or ["api.target.com"],
        excluded_hosts=excluded_hosts or [],
    )


def _make_full_config(
    included_hosts: list[str] | None = None,
    excluded_hosts: list[str] | None = None,
    avoid: list[dict] | None = None,
) -> AdversaConfig:
    return AdversaConfig(
        meta=MetaConfig(project="test-project", engagement_id="adv-test-001"),
        llm=LLMConfig(model_name="claude-sonnet-4-6", api_key_env="ANTHROPIC_API_KEY"),
        target=TargetConfig(
            base_url="https://api.target.com",
            included_hosts=included_hosts or ["api.target.com"],
            excluded_hosts=excluded_hosts or [],
        ),
        authentication=AuthConfig(login_type="none"),
        scope=_make_scope_config(avoid=avoid),
        pipeline=PipelineConfig(enabled=["sast"]),
        repo=RepoConfig(path="./repos/target"),
    )


# ─── ScopeEnforcer.check() ────────────────────────────────────────────────────


def test_host_not_in_included_is_blocked():
    enforcer = _make_enforcer(included_hosts=["api.target.com"])
    result = enforcer.check("https://api.client.com/health")
    assert not result.allowed
    assert "not in included_hosts" in result.reason


def test_in_scope_host_and_path_allowed():
    enforcer = _make_enforcer(included_hosts=["api.target.com"])
    result = enforcer.check("https://api.target.com/api/users")
    assert result.allowed
    assert result.reason is None


def test_excluded_path_is_blocked():
    enforcer = _make_enforcer(
        avoid=[{"description": "health endpoint", "type": "path", "url_path": "/health"}]
    )
    result = enforcer.check("https://api.target.com/health")
    assert not result.allowed
    assert "is excluded" in result.reason


def test_path_pattern_blocks_matching_path():
    enforcer = _make_enforcer(
        avoid=[{"description": "admin area", "type": "path_pattern", "url_path": "/admin/*"}]
    )
    result = enforcer.check("https://api.target.com/admin/users")
    assert not result.allowed
    assert "matches excluded pattern" in result.reason


def test_path_pattern_does_not_block_non_matching():
    enforcer = _make_enforcer(
        avoid=[{"description": "admin area", "type": "path_pattern", "url_path": "/admin/*"}]
    )
    result = enforcer.check("https://api.target.com/api/users")
    assert result.allowed


def test_excluded_host_is_blocked():
    enforcer = _make_enforcer(
        included_hosts=["api.target.com", "prod.client.com"],
        excluded_hosts=["prod.client.com"],
    )
    result = enforcer.check("https://prod.client.com/api/data")
    assert not result.allowed
    assert "explicitly excluded" in result.reason


def test_empty_included_hosts_allows_any_host():
    """When included_hosts is empty the enforcer skips host-allowlist check."""
    scope = _make_scope_config()
    enforcer = ScopeEnforcer(config=scope, included_hosts=[], excluded_hosts=[])
    result = enforcer.check("https://anything.example.com/path")
    assert result.allowed


# ─── to_json() ────────────────────────────────────────────────────────────────


def test_to_json_serialises_correctly():
    enforcer = _make_enforcer(
        included_hosts=["api.target.com"],
        excluded_hosts=["prod.target.com"],
        avoid=[
            {"description": "health", "type": "path", "url_path": "/health"},
            {"description": "admin", "type": "path_pattern", "url_path": "/admin/*"},
        ],
    )
    data = enforcer.to_json()
    assert "api.target.com" in data["included_hosts"]
    assert "prod.target.com" in data["excluded_hosts"]
    assert "/health" in data["excluded_paths"]
    assert "/admin/*" in data["excluded_patterns"]
    assert len(data["avoid_rules"]) == 2
    assert data["focus_rules"] == []


# ─── from_config() ────────────────────────────────────────────────────────────


def test_from_config_builds_enforcer():
    config = _make_full_config(
        included_hosts=["api.target.com"],
        excluded_hosts=["prod.target.com"],
    )
    enforcer = ScopeEnforcer.from_config(config)
    assert "api.target.com" in enforcer.included_hosts
    assert "prod.target.com" in enforcer.excluded_hosts


# ─── _extract_url() ───────────────────────────────────────────────────────────


def test_extract_url_finds_url_key():
    assert _extract_url({"url": "https://example.com/path"}) == "https://example.com/path"


def test_extract_url_finds_target_key():
    assert _extract_url({"target": "https://example.com"}) == "https://example.com"


def test_extract_url_ignores_non_http():
    assert _extract_url({"url": "/local/path"}) is None


def test_extract_url_returns_none_when_absent():
    assert _extract_url({"query": "SELECT 1"}) is None


# ─── can_use_tool callback ────────────────────────────────────────────────────


@pytest.fixture
def tmp_audit(tmp_path):
    return AuditLogger(str(tmp_path / "audit" / "scope.jsonl"))


@pytest.fixture
def in_scope_config():
    return _make_full_config(included_hosts=["api.target.com"])


def test_can_use_tool_denies_out_of_scope_url(tmp_audit, in_scope_config):
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    result = asyncio.get_event_loop().run_until_complete(
        callback("http_probe", {"url": "https://evil.com/attack"}, ctx)
    )
    assert isinstance(result, PermissionResultDeny)
    assert "Out of scope" in result.message


def test_can_use_tool_allows_in_scope_url(tmp_audit, in_scope_config):
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    result = asyncio.get_event_loop().run_until_complete(
        callback("http_probe", {"url": "https://api.target.com/users"}, ctx)
    )
    assert isinstance(result, PermissionResultAllow)


def test_can_use_tool_allows_when_no_url_in_input(tmp_audit, in_scope_config):
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    result = asyncio.get_event_loop().run_until_complete(
        callback("query_joern", {"query": "SELECT * FROM methods"}, ctx)
    )
    assert isinstance(result, PermissionResultAllow)


# ─── AuditLogger ──────────────────────────────────────────────────────────────


def test_scope_block_written_to_audit_log(tmp_audit, in_scope_config):
    log_path = tmp_audit.log_path
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    asyncio.get_event_loop().run_until_complete(
        callback("http_probe", {"url": "https://evil.com/attack"}, ctx)
    )
    assert log_path.exists()
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event"] == "scope_blocked"
    assert entry["url"] == "https://evil.com/attack"
    assert entry["tool"] == "http_probe"
    assert "timestamp" in entry


def test_audit_log_not_written_for_allowed_url(tmp_audit, in_scope_config):
    log_path = tmp_audit.log_path
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    asyncio.get_event_loop().run_until_complete(
        callback("http_probe", {"url": "https://api.target.com/health"}, ctx)
    )
    assert not log_path.exists()


def test_audit_log_appends_multiple_blocks(tmp_audit, in_scope_config):
    callback = build_can_use_tool(in_scope_config, tmp_audit)
    ctx = ToolPermissionContext()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(callback("http_probe", {"url": "https://evil.com/a"}, ctx))
    loop.run_until_complete(callback("browser_navigate", {"url": "https://evil.com/b"}, ctx))
    entries = [json.loads(l) for l in tmp_audit.log_path.read_text().splitlines()]
    assert len(entries) == 2
    assert entries[0]["tool"] == "http_probe"
    assert entries[1]["tool"] == "browser_navigate"
