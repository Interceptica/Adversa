"""Tests for INT-278: Pydantic config schema + YAML loader."""
from __future__ import annotations

import os
import re
import textwrap

import pytest
from pydantic import ValidationError

from src.config.loader import ConfigError, finalise_engagement_id, load_config_from_bytes
from src.config.models import AdversaConfig


# ─── Fixtures ─────────────────────────────────────────────────────────────────

MINIMAL_CONFIG = textwrap.dedent("""\
    meta:
      project: "test-project"
      report_output: "./reports/output.html"

    llm:
      model_name: "claude-sonnet-4-6"
      api_key: "test-key"
      base_url: null

    target:
      base_url: "https://example.com"
      included_hosts:
        - "example.com"

    authentication:
      login_type: "none"

    scope:
      rules:
        avoid: []
        focus: []
      max_depth: 3
      rate_limit_rps: 10

    pipeline:
      enabled:
        - "injection"
      parallel: true
      max_concurrent_pipelines: 5

    repo:
      path: "/tmp/repo"
      language: null
      semgrep_rulesets: null
      joern_enabled: true
""")


def _load(yaml_str: str, env: dict | None = None) -> AdversaConfig:
    """Load config from a YAML string, optionally setting env vars."""
    existing = {}
    if env:
        for k, v in env.items():
            existing[k] = os.environ.get(k)
            os.environ[k] = v
    try:
        return load_config_from_bytes(yaml_str.encode())
    finally:
        if env:
            for k, v in existing.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


# ─── LLM tests ────────────────────────────────────────────────────────────────


def test_llm_base_url_null():
    """Valid config with base_url: null — llm.base_url is None."""
    cfg = _load(MINIMAL_CONFIG)
    assert cfg.llm.base_url is None
    assert cfg.llm.model_name == "claude-sonnet-4-6"
    assert cfg.llm.api_key == "test-key"


def test_llm_base_url_set():
    """Valid config with base_url set loads correctly."""
    yaml_str = MINIMAL_CONFIG.replace("base_url: null", "base_url: https://my-provider.example.com/v1")
    cfg = _load(yaml_str)
    assert cfg.llm.base_url == "https://my-provider.example.com/v1"


# ─── Engagement ID tests ───────────────────────────────────────────────────────


def test_engagement_id_auto_generated():
    """engagement_id is auto-generated when omitted."""
    cfg = _load(MINIMAL_CONFIG)
    assert cfg.meta.engagement_id is not None
    assert cfg.meta.engagement_id.startswith("adv-")
    # Format: adv-YYYYMMDD-HHmm
    assert re.match(r"adv-\d{8}-\d{4}", cfg.meta.engagement_id), (
        f"Unexpected format: {cfg.meta.engagement_id}"
    )


def test_engagement_id_preserved_when_provided():
    """User-provided engagement_id is kept unchanged."""
    yaml_str = MINIMAL_CONFIG.replace(
        "  project: \"test-project\"",
        "  project: \"test-project\"\n  engagement_id: \"my-custom-id\"",
    )
    cfg = _load(yaml_str)
    assert cfg.meta.engagement_id == "my-custom-id"


def test_finalise_engagement_id_auto_generated():
    """finalise_engagement_id() generates adv-{repo-name}-{YYYYMMDD-HHmm}."""
    cfg = _load(MINIMAL_CONFIG)
    result = finalise_engagement_id(cfg, "/workspace/my-app")
    assert result.startswith("adv-my-app-")
    assert re.match(r"adv-my-app-\d{8}-\d{4}", result)


def test_finalise_engagement_id_preserves_custom_id():
    """finalise_engagement_id() returns user-provided ID unchanged."""
    yaml_str = MINIMAL_CONFIG.replace(
        "  project: \"test-project\"",
        "  project: \"test-project\"\n  engagement_id: \"my-custom-id\"",
    )
    cfg = _load(yaml_str)
    result = finalise_engagement_id(cfg, "/workspace/my-app")
    assert result == "my-custom-id"


# ─── Repo optional fields ──────────────────────────────────────────────────────


def test_repo_language_null():
    """language: null is accepted — repo.language is None."""
    cfg = _load(MINIMAL_CONFIG)
    assert cfg.repo.language is None


def test_repo_semgrep_rulesets_null():
    """semgrep_rulesets: null is accepted — repo.semgrep_rulesets is None."""
    cfg = _load(MINIMAL_CONFIG)
    assert cfg.repo.semgrep_rulesets is None


# ─── Env var interpolation ────────────────────────────────────────────────────


def test_env_var_interpolation():
    """${ENV_VAR} placeholders are resolved from environment."""
    yaml_str = MINIMAL_CONFIG.replace('api_key: "test-key"', "api_key: ${MY_API_KEY}")
    cfg = _load(yaml_str, env={"MY_API_KEY": "secret-from-env"})
    assert cfg.llm.api_key == "secret-from-env"


def test_missing_env_var_raises_config_error():
    """Missing ${ENV_VAR} raises ConfigError."""
    yaml_str = MINIMAL_CONFIG.replace('api_key: "test-key"', "api_key: ${MISSING_VAR_XYZ}")
    os.environ.pop("MISSING_VAR_XYZ", None)
    with pytest.raises(ConfigError, match="MISSING_VAR_XYZ"):
        load_config_from_bytes(yaml_str.encode())


# ─── Validation errors ────────────────────────────────────────────────────────


def test_empty_included_hosts_raises():
    """Empty included_hosts raises ValidationError."""
    yaml_str = MINIMAL_CONFIG.replace(
        "  included_hosts:\n    - \"example.com\"",
        "  included_hosts: []",
    )
    with pytest.raises((ValidationError, ConfigError)):
        _load(yaml_str)


def test_extra_unknown_fields_raise():
    """Extra unknown YAML fields raise ValidationError (extra='forbid')."""
    yaml_str = MINIMAL_CONFIG + "\nunknown_top_level_key: surprise\n"
    with pytest.raises((ValidationError, ConfigError)):
        _load(yaml_str)


def test_extra_field_in_llm_raises():
    """Extra field inside llm block raises ValidationError."""
    yaml_str = MINIMAL_CONFIG.replace(
        "  base_url: null",
        "  base_url: null\n  unknown_llm_field: oops",
    )
    with pytest.raises((ValidationError, ConfigError)):
        _load(yaml_str)
