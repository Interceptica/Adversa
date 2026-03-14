from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ─── LLM ──────────────────────────────────────────────────────────────────────


class LLMConfig(BaseModel):
    """
    Single LLM provider. All phases use this model.
    base_url=None  → Anthropic default (passed as ANTHROPIC_BASE_URL env var to CLI).
    base_url set   → any Anthropic messages-compatible provider.
    """

    model_config = ConfigDict(extra="forbid")

    model_name: str
    api_key: str
    base_url: Optional[str] = Field(
        default=None,
        description=(
            "Custom endpoint for Anthropic-compatible providers. "
            "Null uses Anthropic directly."
        ),
    )


# ─── Scope ────────────────────────────────────────────────────────────────────


class ScopeRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    type: Literal["path", "path_pattern", "host"]
    url_path: Optional[str] = None

    @field_validator("url_path")
    @classmethod
    def path_required_for_path_type(cls, v, info):
        if info.data.get("type") in ("path", "path_pattern") and not v:
            raise ValueError("url_path is required when type is 'path' or 'path_pattern'")
        return v


class ScopeRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    avoid: list[ScopeRule] = []
    focus: list[ScopeRule] = []


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: ScopeRules
    max_depth: int = 3
    rate_limit_rps: int = 10


# ─── Auth ─────────────────────────────────────────────────────────────────────


class AuthCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: str
    totp_secret: Optional[str] = None


class SuccessCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["url_contains", "status_code", "body_contains"]
    value: str


class TokenExtraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["response_header", "response_body", "cookie"]
    header: Optional[str] = None


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_type: Literal["form", "bearer", "oauth2", "api_key", "none"]
    login_url: Optional[str] = None
    credentials: Optional[AuthCredentials] = None
    login_flow: list[str] = []
    success_condition: Optional[SuccessCondition] = None
    token_extraction: Optional[TokenExtraction] = None


# ─── Target ───────────────────────────────────────────────────────────────────


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str
    included_hosts: list[str] = []
    excluded_hosts: list[str] = []

    @field_validator("included_hosts")
    @classmethod
    def must_have_at_least_one_host(cls, v):
        if not v:
            raise ValueError("included_hosts must contain at least one host")
        return v


# ─── Repo ─────────────────────────────────────────────────────────────────────


class RepoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    language: Optional[str] = None  # auto-detected by Phase 0 if omitted
    semgrep_rulesets: Optional[list[str]] = None  # auto-detected by Phase 0 if omitted
    joern_enabled: bool = True


# ─── Pipeline ─────────────────────────────────────────────────────────────────


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: list[str]
    timeout_per_pipeline_seconds: int = 300
    parallel: bool = True
    max_concurrent_pipelines: int = Field(default=5, ge=1, le=10)


# ─── Meta ─────────────────────────────────────────────────────────────────────


class MetaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str
    engagement_id: Optional[str] = None  # auto-generated if omitted
    report_output: str = "./reports/output.html"

    @model_validator(mode="after")
    def generate_engagement_id(self) -> "MetaConfig":
        """Fallback timestamp ID — finalised with repo name in Phase 0."""
        if self.engagement_id is None:
            ts = datetime.now(UTC).strftime("%Y%m%d-%H%M")
            self.engagement_id = f"adv-{ts}"
        return self


# ─── Root ─────────────────────────────────────────────────────────────────────


class AdversaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: MetaConfig
    llm: LLMConfig  # single LLM for all phases
    target: TargetConfig
    authentication: AuthConfig
    scope: ScopeConfig
    pipeline: PipelineConfig
    repo: RepoConfig
