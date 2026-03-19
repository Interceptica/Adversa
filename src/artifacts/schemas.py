"""
Typed artifact schemas for inter-phase communication.

All artifacts are written via the save_deliverable MCP tool and read by
subsequent phases. No direct agent-to-agent calls — everything flows through
these typed structures.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ─── Phase 0 ──────────────────────────────────────────────────────────────────


@dataclass
class Check:
    name: str
    status: str  # "pass" | "fail"
    detail: str | None = None


@dataclass
class RepoProfile:
    """
    Tech-stack profile produced by Phase 0 repo introspection.

    languages / frameworks are lists to correctly represent monorepos
    (e.g. FastAPI backend + Next.js frontend in the same repo).

    detection_method:
      "deterministic" — manifest files only, no LLM tokens spent
      "llm"           — LLM called because no manifest files were found
      "config"        — user supplied language/rulesets in adversa.config.yaml
    """

    languages: list[str]               # e.g. ["python", "typescript"]
    frameworks: list[str]              # e.g. ["fastapi", "nextjs"]
    semgrep_rulesets: list[str]        # e.g. ["p/owasp-top-ten", "p/python"]
    joern_enabled: bool = True
    detection_method: str = "deterministic"
    confidence: str = "high"           # "high" | "medium" | "low"


@dataclass
class PreflightResult:
    status: str  # "pass" | "fail"
    checks: list[Check] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scope_manifest: dict = field(default_factory=dict)
    repo_profile: RepoProfile | None = None


# ─── Phase 1 ──────────────────────────────────────────────────────────────────


@dataclass
class SemgrepFinding:
    """Single Semgrep finding with normalized paths and metadata."""
    rule_id: str
    path: str
    start_line: int
    end_line: int
    severity: str       # "ERROR" | "WARNING" | "INFO"
    message: str
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)


@dataclass
class SemgrepRaw:
    """Aggregate SAST result — SEMGREP_RAW artifact."""
    findings: list[SemgrepFinding]
    total: int
    by_severity: dict[str, int] = field(default_factory=dict)
    rulesets_used: list[str] = field(default_factory=list)
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScaVulnerability:
    """Single CVE from Trivy scan."""
    cve_id: str
    package: str
    installed_version: str
    severity: str           # "CRITICAL" | "HIGH" | "MEDIUM"
    fixed_version: str | None = None
    cvss: float | None = None
    title: str = ""
    reachable: bool | None = None  # Phase 3f fills this in


@dataclass
class ScaResult:
    """Aggregate SCA result — SBOM artifact."""
    vulnerabilities: list[ScaVulnerability]
    total: int
    by_severity: dict[str, int] = field(default_factory=dict)
    lockfile_found: bool = False
    lockfile_type: str | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class HostPort:
    """Single open port on a host."""
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""


@dataclass
class InfraHost:
    """Host with its open ports from nmap scan."""
    hostname: str
    ports: list[HostPort] = field(default_factory=list)


@dataclass
class InfraMap:
    """Aggregate infrastructure scan result — INFRA_MAP artifact."""
    hosts: list[InfraHost]
    total_hosts: int = 0
    total_open_ports: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class TechStack:
    """Technology fingerprinting from httpx — TECH_STACK artifact."""
    technologies: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)


@dataclass
class JoernCpgResult:
    """Joern CPG build result — JOERN_CPG_PATH artifact."""
    success: bool
    cpg_path: str | None = None
    error: str | None = None


@dataclass
class PreReconResult:
    """Aggregate Phase 1 result returned by PreReconWorkflow."""
    status: str  # "complete" | "partial"
    errors: list[str] = field(default_factory=list)


# ─── Phase 2 ──────────────────────────────────────────────────────────────────
# The primary Phase 2 deliverable is recon_deliverable.md (markdown narrative).
# AUTH_SESSION is the only structured artifact — Phase 3 agents need the raw
# cookie/header values to make authenticated HTTP requests programmatically.


@dataclass
class AuthSession:
    """AUTH_SESSION artifact — machine-readable session for Phase 3 HTTP requests."""
    success: bool
    login_type: str                              # "form" | "bearer" | "none" | etc.
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)  # e.g. {"Authorization": "Bearer ..."}
    error: str | None = None
