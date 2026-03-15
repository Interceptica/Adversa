from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ─── LLM ──────────────────────────────────────────────────────────────────────


class LLMConfig(BaseModel):
    """
    Single LLM provider for all phases.
    Set base_url to point at any Anthropic messages-compatible endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    model_name: str = Field(
        description="Model identifier passed to the provider (e.g. 'claude-sonnet-4-6').",
    )
    api_key_env: str = Field(
        description=(
            "Name of the environment variable that holds the API key "
            "(e.g. 'LLM_API_KEY', 'Novita_api_key'). "
            "The value is read from os.environ at runtime — never stored in Temporal history."
        ),
    )
    base_url: Optional[str] = Field(
        default=None,
        description=(
            "Custom endpoint for Anthropic-compatible providers "
            "(e.g. 'https://api.novita.ai/anthropic'). "
            "null = Anthropic default."
        ),
    )

    @property
    def api_key(self) -> str:
        """Resolve the actual API key from the environment at runtime."""
        import os
        val = os.environ.get(self.api_key_env)
        if not val:
            raise ValueError(
                f"LLM API key environment variable '{self.api_key_env}' is not set or empty."
            )
        return val


# ─── Scope ────────────────────────────────────────────────────────────────────


class ScopeRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(
        description="Human-readable label for this rule, included in the scope manifest.",
    )
    type: Literal["path", "path_pattern", "host"] = Field(
        description=(
            "'path' — exact path match. "
            "'path_pattern' — glob match (e.g. '/api/*'). "
            "'host' — match by hostname."
        ),
    )
    url_path: Optional[str] = Field(
        default=None,
        description="URL path or glob pattern. Required when type is 'path' or 'path_pattern'.",
    )

    @field_validator("url_path")
    @classmethod
    def path_required_for_path_type(cls, v, info):
        if info.data.get("type") in ("path", "path_pattern") and not v:
            raise ValueError("url_path is required when type is 'path' or 'path_pattern'")
        return v


class ScopeRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    avoid: list[ScopeRule] = Field(
        default=[],
        description="Endpoints the agent must never probe (blocked at can_use_tool layer).",
    )
    focus: list[ScopeRule] = Field(
        default=[],
        description="Endpoints to prioritise — informational hint injected into the system prompt.",
    )


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: ScopeRules = Field(
        description="Avoid/focus rules applied to every outbound tool call.",
    )
    max_depth: int = Field(
        default=3,
        description="Maximum link-follow depth during crawl/recon.",
    )
    rate_limit_rps: int = Field(
        default=10,
        description="Maximum outbound requests per second to the target.",
    )


# ─── Auth ─────────────────────────────────────────────────────────────────────


class AuthCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        description="Login username or email. Use '${ENV_VAR}' to avoid hardcoding.",
    )
    password: str = Field(
        description="Login password. Use '${ENV_VAR}' to avoid hardcoding.",
    )
    totp_secret: Optional[str] = Field(
        default=None,
        description="Base32 TOTP secret for MFA. null if MFA is not required.",
    )


class SuccessCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["url_contains", "status_code", "body_contains"] = Field(
        description="How to detect a successful login after the login flow completes.",
    )
    value: str = Field(
        description="Expected value — URL fragment, HTTP status code, or response body substring.",
    )


class TokenExtraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["response_header", "response_body", "cookie"] = Field(
        description="Where to find the auth token after login.",
    )
    header: Optional[str] = Field(
        default=None,
        description="Header name to extract from (only used when type='response_header').",
    )


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_type: Literal["form", "bearer", "oauth2", "api_key", "none"] = Field(
        description=(
            "'none' — no authentication. "
            "'form' — browser-driven form login (uses login_flow). "
            "'bearer' — static Bearer token in credentials.password. "
            "'oauth2' — OAuth2 client credentials. "
            "'api_key' — static API key header."
        ),
    )
    login_url: Optional[str] = Field(
        default=None,
        description="URL of the login page or token endpoint. Required for form/oauth2.",
    )
    credentials: Optional[AuthCredentials] = Field(
        default=None,
        description="Username/password/TOTP. Not required when login_type='none'.",
    )
    login_flow: list[str] = Field(
        default=[],
        description=(
            "Ordered natural-language steps the browser agent follows to log in "
            "(e.g. ['Type $username into the email field', 'Click Sign In'])."
        ),
    )
    success_condition: Optional[SuccessCondition] = Field(
        default=None,
        description="How to verify the login succeeded.",
    )
    token_extraction: Optional[TokenExtraction] = Field(
        default=None,
        description="Where to read the session token from after a successful login.",
    )


# ─── Target ───────────────────────────────────────────────────────────────────


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(
        description="Root URL of the target application (e.g. 'https://staging.example.com').",
    )
    included_hosts: list[str] = Field(
        default=[],
        description=(
            "Hosts the agent is allowed to contact. At least one required. "
            "Requests to any other host are blocked by can_use_tool."
        ),
    )
    excluded_hosts: list[str] = Field(
        default=[],
        description="Hosts explicitly off-limits (e.g. production). Blocked even if in scope.",
    )

    @field_validator("included_hosts")
    @classmethod
    def must_have_at_least_one_host(cls, v):
        if not v:
            raise ValueError("included_hosts must contain at least one host")
        return v


# ─── Repo ─────────────────────────────────────────────────────────────────────


class RepoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        description=(
            "Filesystem path to the target repository, relative to the worker's working directory. "
            "Mounted via Docker volume — e.g. './repos/juice-shop' maps to '/app/repos/juice-shop'."
        ),
    )
    language: Optional[str] = Field(
        default=None,
        description=(
            "Override the primary language (e.g. 'python'). "
            "Auto-detected from manifest files by Phase 0 if null."
        ),
    )
    semgrep_rulesets: Optional[list[str]] = Field(
        default=None,
        description=(
            "Override Semgrep rulesets (e.g. ['p/owasp-top-ten', 'p/python']). "
            "Auto-selected by Phase 0 based on detected language/framework if null."
        ),
    )
    joern_enabled: bool = Field(
        default=True,
        description=(
            "Enable Joern Code Property Graph build and taint-flow queries. "
            "Set false for JavaScript/TypeScript repos where Joern support is limited."
        ),
    )


# ─── Pipeline ─────────────────────────────────────────────────────────────────


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: list[str] = Field(
        description=(
            "Which analysis pipelines to run. Valid values: "
            "'injection', 'authz', 'info_disclosure', 'ssrf', 'sast_triage', 'sca_reachability'."
        ),
    )
    timeout_per_pipeline_seconds: int = Field(
        default=300,
        description="Maximum wall-clock seconds allowed for each individual pipeline activity.",
    )
    parallel: bool = Field(
        default=True,
        description="Run Phase 3 analysis pipelines concurrently (recommended).",
    )
    max_concurrent_pipelines: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum number of Phase 3 pipelines running simultaneously (1–10).",
    )


# ─── Tracing ─────────────────────────────────────────────────────────────────


class TracingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description=(
            "Enable Langfuse tracing for all agentic phases. "
            "Requires LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, and LANGFUSE_BASE_URL "
            "environment variables to be set in the worker environment."
        ),
    )


# ─── Meta ─────────────────────────────────────────────────────────────────────


class MetaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str = Field(
        description="Human-readable project name, included in all reports and audit logs.",
    )
    engagement_id: Optional[str] = Field(
        default=None,
        description=(
            "Unique engagement identifier used as the Temporal workflow ID and output directory name. "
            "Auto-generated as 'adv-{YYYYMMDD-HHmm}' if omitted."
        ),
    )
    report_output: str = Field(
        default="./reports/output.html",
        description="Output path for the HTML findings report.",
    )

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

    meta: MetaConfig = Field(description="Engagement metadata — project name, ID, output paths.")
    llm: LLMConfig = Field(description="LLM provider used for all agentic phases.")
    target: TargetConfig = Field(description="Target application URL and allowed hosts.")
    authentication: AuthConfig = Field(description="How the agent authenticates with the target.")
    scope: ScopeConfig = Field(description="Scope rules and crawl limits enforced on every tool call.")
    pipeline: PipelineConfig = Field(description="Which analysis pipelines to run and how.")
    repo: RepoConfig = Field(description="Source repository path and static analysis settings.")
    tracing: TracingConfig = Field(
        default_factory=TracingConfig,
        description="Langfuse observability tracing. Disabled by default.",
    )
