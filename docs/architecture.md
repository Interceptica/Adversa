# Adversa — System Architecture Reference

> Extracted from PRD v0.2. Covers sections 6, 7, 10, 11, 13, 14.
> For phase inputs/outputs see `phase-contracts.md`. For artifact schemas see `artifact-schemas.md`.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    adversa.config.yaml                       │
└──────────────────────┬──────────────────────────────────────┘
                       │ parsed + validated (Pydantic)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│               Temporal Workflow Engine                       │
└───┬──────────┬──────────┬──────────────────────────────────┘
    │          │          │
    ▼          ▼          ▼
 Phase 0    Phase 1    Phase 2         Phase 3 (parallel)
 Pre-Flight  Pre-Recon   Recon          STRIDE-aligned agents:
 (no LLM)   (no LLM)   (Novita)        [Tampering | Spoofing |
                                        Info Disclosure |
                                        Elevation of Privilege |
                                        SSRF | SCA Reachability]
                                               │
                          ┌────────────────────┴─────────────────────┐
                          │                                          │
                          ▼                                          ▼
                   ── OSS STOPS HERE ──                 ── PRO CONTINUES ──
                   Phase 5a: Findings Report            Phase 4: Exploitation
                   (OWASP-mapped, no PoC)               (conditional parallel)
                                                               │
                                                               ▼
                                                        Phase 5b: Pentest Report
                                                        (OWASP-mapped, PoC, PDF)
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Orchestration | Temporal (Python SDK) |
| Agentic reasoning | Anthropic Claude SDK (`claude-sonnet-4-6`, `claude-opus-4-6`) |
| Recon LLM | Novita `meta-llama/llama-3.1-70b-instruct` via Anthropic SDK (`base_url` swap) |
| SAST | Semgrep |
| SCA | Trivy (CycloneDX SBOM + VEX) |
| DAST | Nuclei |
| Taint analysis | Joern (CPG-based) |
| Recon tools | nmap, subfinder, httpx, WhatWeb (Docker-isolated) |
| API layer | FastAPI |
| Report rendering | Jinja2 HTML + WeasyPrint PDF |
| Config validation | Pydantic v2 + JSON Schema |

### LLM Provider Pattern

Both primary and recon clients use the Anthropic SDK — only `base_url` and `api_key` differ:

```python
from anthropic import Anthropic

# Primary: Claude Sonnet/Opus — vuln analysis, reporting
client = Anthropic(api_key=config.provider.api_key)

# Recon: Novita Llama 3.1 70B — cheaper, good enough for crawl tasks
recon_client = Anthropic(
    base_url="https://api.novita.ai/anthropic",
    api_key=config.provider.recon_api_key,
)
```

Same `client.messages.create()`, same messages format, same tool use, same stop reasons. No LiteLLM needed.

### Model Allocation

| Phase | Model | Reason |
|---|---|---|
| Phase 1 | None | Tools only |
| Phase 2 Recon | Novita Llama 3.1 70B | Cheap structured crawl |
| Phase 3 Injection/Taint | `claude-opus-4-6` | Deep taint reasoning |
| Phase 3 Others | `claude-sonnet-4-6` | Balanced |
| Phase 4 Exploit (Pro) | `claude-opus-4-6` | Exploit reasoning |
| Phase 5 Reports | `claude-sonnet-4-6` | Structured writing |

---

## Configuration System

### Config File: `adversa.config.yaml`

```yaml
meta:
  project: "ClientName Pentest"
  engagement_id: "adv-2026-001"

provider:
  llm: "anthropic"
  model: "claude-sonnet-4-6"
  api_key: "${ANTHROPIC_API_KEY}"
  recon_llm: "novita/meta-llama/llama-3.1-70b-instruct"
  recon_api_key: "${NOVITA_API_KEY}"

target:
  base_url: "https://api.client.com"
  included_hosts:
    - "api.client.com"
  excluded_hosts:
    - "prod.client.com"

authentication:
  login_type: form
  login_url: "https://api.client.com/login"
  credentials:
    username: "${TARGET_USERNAME}"
    password: "${TARGET_PASSWORD}"
    totp_secret: "${TARGET_TOTP}"
  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the Sign In button"
  success_condition:
    type: url_contains
    value: "/dashboard"

scope:
  rules:
    avoid:
      - description: "Skip health endpoints"
        type: path
        url_path: "/health"
      - description: "Avoid logout"
        type: path
        url_path: "/logout"
      - description: "Avoid admin panel"
        type: path_pattern
        url_path: "/admin/*"
    focus:
      - description: "Prioritise API endpoints"
        type: path_pattern
        url_path: "/api/*"
  max_depth: 3
  rate_limit_rps: 10

pipeline:
  enabled:
    - pre_recon
    - recon
    - sast
    - sca
    - dast
    - taint_analysis
  timeout_per_pipeline_seconds: 300
  parallel: true
  max_concurrent_pipelines: 5

repo:
  path: "/repos/client-app"
  language: "python"
  semgrep_rulesets:
    - "p/owasp-top-ten"
    - "p/python"
  joern_enabled: true
```

### Config Processing Pipeline

```
adversa.config.yaml
    │
    ├─► yaml.safe_load() + env var interpolation
    │       raise ConfigError if any ${VAR} is undefined
    │
    ├─► Pydantic v2 validation (AdversaConfig)
    │
    ├─► ScopeEnforcer.build(config.scope)
    │       serialise to SCOPE_MANIFEST JSON
    │
    ├─► LLMProviderFactory.build(config.provider)
    │
    ├─► PromptFactory.build(config)
    │       pre-render system prompts for all phases once
    │
    └─► WorkflowInput → Temporal workflow start
```

**Key principle:** Config is immutable once validated. No phase modifies the config object. Every agent receives a read-only view of the config relevant to its phase only.

---

## Design Layers

### Layer 1: Config Processing

Config is loaded, env vars resolved, Pydantic-validated, and frozen. Downstream components receive immutable slices.

### Layer 2: Prompt Layer

System prompts are the **signature** of each agent:
- Built once at workflow start, never rebuilt at runtime
- Stored in `prompts/` (versioned in git) — Phase 3 templates are proprietary
- Static sections eligible for Anthropic prompt caching

**Prompt Template Variables:**

| Variable | Source |
|---|---|
| `{{TARGET_URL}}` | `config.target.base_url` |
| `{{SCOPE_MANIFEST}}` | `ScopeEnforcer.to_json()` |
| `{{LOGIN_INSTRUCTIONS}}` | `config.authentication` rendered |
| `{{TECH_STACK}}` | `CODE_ANALYSIS.tech_stack` |
| `{{KNOWN_ENDPOINTS}}` | `CODE_ANALYSIS.endpoints` |
| `{{RECON_MAP}}` | Phase 2 artifact |
| `{{QUEUE}}` | Phase 3 queue artifact (exploit agents) |
| `{{AUTH_SESSION}}` | Phase 2 artifact |
| `{{OWASP_MAPPING_REFERENCE}}` | Static reference table (Phase 5) |

**Prompt Structure (all agents):**
```
[AGENT IDENTITY]        ← static, cache-eligible
[SCOPE RULES]           ← static per engagement, cache-eligible
[CONSTRAINTS]           ← static, cache-eligible
[CONTEXT]               ← dynamic (artifacts injected here)
[TASK]                  ← dynamic
[OUTPUT FORMAT]         ← static, cache-eligible
```

### Layer 3: Scope Enforcement (Guardrails)

Scope enforcement is **deterministic** — not probabilistic.

#### Four-Layer Enforcement Model

**Layer 1: Config Validation (Parse-Time)**
Pydantic rejects malformed scope rules before any LLM tokens are spent.

**Layer 2: System Prompt Injection (Probabilistic)**
Scope rules rendered into every agent's system prompt. Reduces wasted tool calls. Not relied upon for enforcement — efficiency only.

**Layer 3: Pre-Tool Hook in Agent Loop (Deterministic)**
Every tool call passes through `ScopeEnforcer.check()` before execution:

```python
async def dispatch_tool(tool_call: ToolCall, scope: ScopeEnforcer) -> dict:
    url = extract_url(tool_call.input)
    if url:
        result = scope.check(url)
        if not result.allowed:
            return {"status": "skipped", "reason": result.reason, "url": url}
    return await route_to_tool(tool_call)
```

**Layer 4: Tool Implementation Hard Block (Deterministic)**
Every tool that makes an HTTP request, runs a scan, or navigates a browser calls `scope.check()` internally. The LLM cannot instruct a tool to bypass its own scope check.

**Layer 5: Rate Limiter (Safety)**
Per-domain rate limiter wraps all outbound HTTP. Configured via `scope.rate_limit_rps`.

#### Guardrail Summary

| Layer | Type | Bypassed by LLM? |
|---|---|---|
| Config validation | Deterministic | No — before any LLM call |
| System prompt | Probabilistic | Theoretically yes |
| Pre-tool hook | Deterministic | No |
| Tool implementation | Deterministic | No |
| Rate limiter | Deterministic | No |

Every blocked call is logged to `session_metrics.json` with timestamp, URL, reason, and agent name.

> **Marketing claim:** *"Adversa is architecturally incapable of testing an excluded endpoint. Scope compliance is guaranteed by the tool layer, not by trusting an LLM."*

### Layer 4: Tool & MCP Layer

**Security design:**
- MCP subprocess environment contains only tool-specific env vars — no API keys or AWS credentials leaked in
- No `bypassPermissions` — every tool capability explicitly declared in the MCP manifest
- `targetDir` captured in closure per-workflow — agents cannot escape to arbitrary paths

**MCP Tools:**

| Tool | Scope-checked | Description |
|---|---|---|
| `http_probe` | ✅ | Scoped HTTP request to target |
| `run_nuclei` | ✅ | Nuclei template against endpoint |
| `browser_navigate` | ✅ | Playwright navigation |
| `browser_click` | No | Click element |
| `browser_type` | No | Type into form field |
| `browser_screenshot` | No | Capture screenshot |
| `run_semgrep` | No | Query Semgrep results |
| `query_joern` | No | Joern CPG query |
| `read_file` | No (repo-scoped) | Read specific file:line from repo |
| `generate_totp` | No | TOTP code from secret |
| `save_deliverable` | No | Write typed artifact |
| `flag_vulnerability` | No | Add confirmed finding to evidence |

### Layer 5: Orchestration Layer

```python
@workflow.defn
class PentestPipelineWorkflow:
    @workflow.run
    async def run(self, input: WorkflowInput) -> WorkflowResult:

        # Phase 0
        preflight = await workflow.execute_activity(run_preflight_phase, ...)
        if preflight.status == "fail":
            return WorkflowResult(status="aborted", reason=preflight.errors)

        # Phase 1 — tools only
        pre_recon = await workflow.execute_activity(run_pre_recon_phase, ...)

        # Phase 2 — Novita LLM
        recon = await workflow.execute_activity(run_recon_phase, ...)

        # Phase 3 — parallel vulnerability analysis
        vuln_results = await asyncio.gather(
            workflow.execute_activity(run_injection_analysis, ...),
            workflow.execute_activity(run_authz_analysis, ...),
            workflow.execute_activity(run_info_disclosure_analysis, ...),
            workflow.execute_activity(run_ssrf_analysis, ...),
            workflow.execute_activity(run_sast_triage, ...),
            workflow.execute_activity(run_sca_reachability, ...),
            return_exceptions=True,
        )

        # OSS: stop here, produce findings report
        if not input.is_pro:
            report = await workflow.execute_activity(run_findings_report, vuln_results, ...)
            return WorkflowResult(status="complete", report=report)

        # Pro: Phase 4 — conditional parallel exploitation
        exploit_tasks = [
            workflow.execute_activity(run_exploit_agent, queue, ...)
            for queue in vuln_results
            if queue and len(queue.items) > 0
        ]
        exploit_results = await asyncio.gather(*exploit_tasks, return_exceptions=True)

        # Pro: Phase 5b — pentest report
        report = await workflow.execute_activity(run_pentest_report, exploit_results, ...)
        return WorkflowResult(status="complete", report=report)
```

**Activity design principles:**
- Activities are thin wrappers around `src/services/` — no Temporal imports in service layer
- All activities heartbeat every 90 seconds for long-running tasks
- Failed activities retry 3× with exponential backoff before marking phase `partial`
- Individual phase failure does not abort the workflow — partial results still feed into reporting

---

## Agent Design Principles

1. **System prompt is immutable per engagement.** Built once at workflow start. Config changes require a new workflow.

2. **Agents communicate via artifacts only.** No direct agent-to-agent calls. All inter-phase communication passes through typed artifacts and Temporal workflow state.

3. **No speculative codebase reads.** Every file read is triggered by a tool finding. LLMs read specific files at specific lines — never entire directories.
   ```
   Correct:
     Joern identifies taint path ending at routes/users.py:87
     → Agent calls read_file("routes/users.py", around_line=87, context=20)

   Wrong (Shannon's approach):
     Agent dumps entire repo into context window and reasons about it
   ```

4. **Structured output only.** Agents write to `save_deliverable` with a typed schema. Free-form text is not treated as an artifact.

5. **Fail gracefully.** Hitting max turns or a timeout saves partial results and marks the phase `partial`. The workflow continues to reporting.

6. **Tiered models by task complexity** — see model allocation table above.

7. **No `bypassPermissions`.** Every tool capability is explicitly declared in the MCP manifest.

8. **Phase 3 prompts are proprietary.** Not included in the OSS release.

---

## Non-Functional Requirements

### Performance
- OSS pipeline (Phases 0–3 + findings report): < 30 minutes
- Pro pipeline (all phases): < 45 minutes
- Per-run cost: OSS < $5, Pro < $15

### Reliability
- Temporal provides durable execution — worker crashes do not lose progress
- Partial phase results are still reportable
- Failed activities retry 3× with exponential backoff

### Security
- Secrets resolved from env vars at parse time — never written to disk or passed to subprocesses
- MCP subprocess env is minimal — no API keys leaked
- Repo files accessed read-only (Docker bind mount `ro`)
- Non-root container execution
- Scope enforcement audit trail in every engagement

### Scalability
- One Temporal worker per concurrent engagement
- Horizontal scaling via ECS/Fargate replicas
- Per-client namespace isolation in Temporal Cloud

### Observability
- Temporal Web UI for workflow state
- Structured JSON logs (structlog) for all activities
- Token cost tracking per workflow via Anthropic SDK
- Prometheus metrics: active workflows, phase durations, finding counts

---

## Vulnerability Framework Alignment

### External Reporting: OWASP

All Adversa reports map every finding to:
- **OWASP Top 10 (2021)** — universal language; referenced by every SOC2 auditor
- **OWASP API Security Top 10 (2023)** — for API-first products; covers BOLA (API1)

Pro reports additionally carry **CVSS 3.1 score and vector string** per finding.

### Internal Reasoning: STRIDE

Phase 3 agents reason using STRIDE threat categories. STRIDE → OWASP mapping:

| STRIDE Threat | Adversa Agent | OWASP Top 10 | OWASP API |
|---|---|---|---|
| Tampering | Injection agent | A03 Injection | — |
| Spoofing | Auth agent | A07 Auth Failures | API2 |
| Information Disclosure | Info disclosure agent | A01, A02 | API3, API9 |
| Elevation of Privilege | AuthZ agent | A01 | API1 BOLA, API5 |
| SSRF | SSRF agent | A10 SSRF | API7 |
| — | SAST triage agent | A03, A05, A08 | — |
| — | SCA reachability agent | A06 | — |

> DoS and Repudiation are excluded. DoS requires manual verification to avoid impacting staging. Repudiation (logging failures) cannot be reliably detected automatically.

### OWASP Coverage

| Category | Covered | Method |
|---|---|---|
| A01 Broken Access Control | ✅ | Phase 3b/3c (IDOR, AuthZ) |
| A02 Cryptographic Failures | Partial | Phase 3e (Semgrep rules) |
| A03 Injection | ✅ | Phase 3a (Joern taint) |
| A04 Insecure Design | Partial | Phase 3b (business logic) |
| A05 Security Misconfiguration | ✅ | Phase 1 (Nuclei) + Phase 3e |
| A06 Vulnerable Components | ✅ | Phase 3f (Trivy + reachability) |
| A07 Auth Failures | ✅ | Phase 3b |
| A08 Integrity Failures | Partial | Phase 3e (Semgrep) |
| A09 Logging Failures | ❌ | Cannot reliably auto-detect |
| A10 SSRF | ✅ | Phase 3d |
| API1 BOLA | ✅ | Phase 3b/3c |
| API2 Broken Auth | ✅ | Phase 3b |
| API3 Broken Object Property Auth | Partial | Phase 3e |
| API4 Resource Consumption | ❌ | Requires manual testing |
| API5 Broken Function Level Auth | ✅ | Phase 3b |
| API6 Sensitive Business Flows | Partial | Phase 3b |
| API7 SSRF | ✅ | Phase 3d |
| API8 Security Misconfiguration | ✅ | Phase 1 + Phase 3e |
| API9 Improper Inventory | ✅ | Phase 2 (shadow API discovery) |
| API10 Unsafe API Consumption | ❌ | Out of scope v1 |
