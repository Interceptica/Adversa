# Adversa — Phase Contracts

> Defines what each phase **consumes** and **produces**. This is the authoritative reference for activity inputs/outputs.
> Full artifact JSON schemas: `artifact-schemas.md`. Architecture decisions: `architecture.md`.

---

## Pipeline Overview

```
Phase 0: Pre-Flight          → PREFLIGHT_RESULT, SCOPE_MANIFEST, TOOL_MANIFEST
Phase 1: Pre-Recon           → CODE_ANALYSIS, SBOM, SEMGREP_RAW, JOERN_CPG_PATH, INFRA_MAP, TECH_STACK
Phase 2: Recon               → RECON_MAP, AUTH_SESSION, ENDPOINT_INVENTORY, ATTACK_SURFACE_SUMMARY
Phase 3: Vuln Analysis ──┬──→ INJECTION_QUEUE
(parallel)               ├──→ AUTHZ_QUEUE
                         ├──→ INFO_DISCLOSURE_QUEUE
                         ├──→ SSRF_QUEUE
                         ├──→ SAST_CONFIRMED_QUEUE
                         └──→ SCA_REACHABILITY_REPORT

OSS stops here → Phase 5a: Findings Report

Phase 4: Exploitation ───┬──→ INJECTION_EVIDENCE
(Pro only, parallel)     ├──→ AUTHZ_EVIDENCE
                         ├──→ INFO_DISCLOSURE_EVIDENCE
                         ├──→ SSRF_EVIDENCE
                         ├──→ SAST_EVIDENCE
                         └──→ FALSE_POSITIVES

Phase 5b: Pentest Report (Pro) → pentest_report.html, pentest_report.pdf, findings.json
```

---

## Phase 0: Pre-Flight & Config Validation

**Purpose:** Validate all inputs before any agent or tool runs. Fail fast and free.

**LLM:** None | **Cost:** Zero

**Consumes:**
- `adversa.config.yaml` (from filesystem)
- Environment variables (resolved inline)

**Steps:**
1. Parse and validate `adversa.config.yaml` against Pydantic schema
2. Resolve all `${ENV_VAR}` — fail if any are missing
3. Verify target host is reachable (HTTP HEAD)
4. Verify repo path exists and is readable
5. Verify all enabled pipeline tools are installed in container
6. Lightweight API key validity check
7. Build `ScopeEnforcer` and validate at least one included host

**Exit condition:** Any failed check aborts the workflow immediately with a structured error. No LLM tokens spent.

**Produces:**

| Artifact | Consumed By |
|---|---|
| `PREFLIGHT_RESULT` | Workflow (proceed or abort) |
| `SCOPE_MANIFEST` | All phases |
| `TOOL_MANIFEST` | Phase 1 |

**Abort condition:** `PREFLIGHT_RESULT.status == "fail"` → workflow returns `WorkflowResult(status="aborted", reason=errors)`.

---

## Phase 1: Pre-Recon (Tools Only)

**Purpose:** Build a static picture of the attack surface using deterministic tools. No LLM.

**LLM:** None — tools only

**Why no LLM:** Semgrep, Trivy, Joern, nmap, and httpx are fully deterministic and produce structured JSON directly. The Joern CPG is built here once and reused throughout Phase 3.

**Consumes:**
- `SCOPE_MANIFEST`
- `TOOL_MANIFEST`
- `config.repo.path`, `config.repo.language`, `config.repo.semgrep_rulesets`
- `config.target.included_hosts`

**Steps:**
1. `nmap` port scan on target hosts
2. `subfinder` subdomain enumeration
3. `httpx` + `WhatWeb` tech fingerprinting
4. `semgrep` SAST scan → raw findings JSON
5. `trivy` filesystem scan → SBOM (CycloneDX) + raw CVE list
6. Joern CPG build from repo (expensive, done once)
7. OpenAPI/Swagger spec extraction if present

**Produces:**

| Artifact | Consumed By |
|---|---|
| `CODE_ANALYSIS` | Phase 2, Phase 3 agents |
| `SBOM` | Phase 3f (SCA reachability), Phase 5 |
| `SEMGREP_RAW` | Phase 3e (SAST triage) |
| `JOERN_CPG_PATH` | Phase 3a, 3b, 3d, 3f (taint/query agents) |
| `INFRA_MAP` | Phase 2, Phase 3 |
| `TECH_STACK` | Phase 2, Phase 3 |

---

## Phase 2: Recon

**Purpose:** Live application exploration — authenticate, crawl, map real endpoints and correlate with Phase 1 static analysis.

**LLM:** `novita/meta-llama/llama-3.1-70b-instruct` (cost-optimised)
**Max turns:** 2,000

**Why Novita:** Recon is a structured task — log in, crawl, correlate, output a map. Llama 3.1 70B handles this at ~10% of Claude Sonnet cost.

**Consumes:**
- `SCOPE_MANIFEST`
- `CODE_ANALYSIS` (injected as structured context — LLM does **not** read the codebase directly)
- `TECH_STACK`
- `INFRA_MAP`
- `config.authentication` (login instructions, credentials)
- `config.target.base_url`

**LLM role:** Agent receives `CODE_ANALYSIS` as structured context to correlate live endpoints with known source locations.

**Tools available:** `http_probe` (scope-checked), `browser_navigate` (scope-checked), `browser_click`, `browser_type`, `browser_screenshot`, `generate_totp`, `save_deliverable`

**Produces:**

| Artifact | Consumed By |
|---|---|
| `RECON_MAP` | All Phase 3 agents |
| `AUTH_SESSION` | Phase 3 DAST agents, Phase 4 (Pro) |
| `ENDPOINT_INVENTORY` | Phase 3, Phase 5 |
| `ATTACK_SURFACE_SUMMARY` | Phase 5 report |

---

## Phase 3: Vulnerability Analysis (Parallel)

**Purpose:** Specialised agents hunt for vulnerability classes using static analysis results and the live recon map. Each agent produces a structured queue of hypothesised exploitable paths.

**LLM:** `claude-opus-4-6` for agents 3a (injection/taint); `claude-sonnet-4-6` for others
**Parallelism:** All 6 agents run concurrently via `asyncio.gather`
**Max turns per agent:** 3,000

> **IP note:** Phase 3 system prompt templates are proprietary and not included in the OSS release.

**Shared inputs (all Phase 3 agents):**
- `SCOPE_MANIFEST`
- `RECON_MAP`
- `ENDPOINT_INVENTORY`
- `CODE_ANALYSIS`
- `AUTH_SESSION`
- `TECH_STACK`

**Tool policy:** LLMs NEVER read files speculatively. Every `read_file` call must be triggered by a tool finding (Joern taint path or Semgrep hit).

---

### 3a. Injection Agent (STRIDE: Tampering)

**LLM:** `claude-opus-4-6`

**Additional inputs:**
- `JOERN_CPG_PATH` (primary signal source)
- `SEMGREP_RAW` (corroborating signal)

**What it does:**
Queries Joern to trace user-controlled inputs to dangerous sinks (SQL, shell exec, XML parsers, template engines). Reads specific file:line for each confirmed taint path to verify no effective sanitisation exists.

**Tools:** `query_joern`, `run_semgrep`, `read_file`, `save_deliverable`, `flag_vulnerability`

**Produces:** `INJECTION_QUEUE`

**OWASP mapping:** A03 Injection | CWEs: CWE-89, CWE-78, CWE-94, CWE-611

---

### 3b. Auth & AuthZ Agent (STRIDE: Spoofing + Elevation of Privilege)

**LLM:** `claude-sonnet-4-6`

**Additional inputs:**
- `JOERN_CPG_PATH`
- `SEMGREP_RAW`

**What it does:**
Analyses auth logic for broken JWT validation, missing role checks, IDOR patterns, privilege escalation paths between roles. Tests auth bypasses against live target using authenticated session.

**Tools:** `query_joern`, `run_semgrep`, `read_file`, `http_probe`, `save_deliverable`, `flag_vulnerability`

**Produces:** `AUTHZ_QUEUE`

**OWASP mapping:** A01 Broken Access Control, A07 Auth Failures | API1 BOLA, API2, API5

---

### 3c. Information Disclosure Agent (STRIDE: Information Disclosure)

**LLM:** `claude-sonnet-4-6`

**Additional inputs:**
- `SEMGREP_RAW`

**What it does:**
Finds endpoints leaking sensitive data — excessive data exposure, verbose errors, debug endpoints, path traversal, missing auth on data endpoints.

**Tools:** `query_joern`, `run_semgrep`, `read_file`, `http_probe`, `save_deliverable`, `flag_vulnerability`

**Produces:** `INFO_DISCLOSURE_QUEUE`

**OWASP mapping:** A01, A02 | API3, API9 | CWE-200, CWE-22

---

### 3d. SSRF Agent (STRIDE: SSRF)

**LLM:** `claude-sonnet-4-6`

**Additional inputs:**
- `JOERN_CPG_PATH`

**What it does:**
Finds parameters accepting URLs or file paths and traces to HTTP client calls or file system operations via Joern.

**Tools:** `query_joern`, `read_file`, `http_probe`, `save_deliverable`, `flag_vulnerability`

**Produces:** `SSRF_QUEUE`

**OWASP mapping:** A10 SSRF | API7 SSRF | CWE-918

---

### 3e. SAST Triage Agent

**LLM:** `claude-sonnet-4-6`

**Additional inputs:**
- `SEMGREP_RAW` (primary input)
- `JOERN_CPG_PATH` (for reachability confirmation)

**What it does:**
Triages raw Semgrep findings for reachability. Discards dead code and unexposed endpoint findings. Reads flagged file:line to assess context for remaining findings.

**Tools:** `run_semgrep`, `query_joern`, `read_file`, `save_deliverable`

**Produces:** `SAST_CONFIRMED_QUEUE`

**OWASP mapping:** A03, A05, A08 | CWE varies by rule

---

### 3f. SCA Reachability Agent

**LLM:** `claude-sonnet-4-6`

**Additional inputs:**
- `SBOM` (primary input — CVE list from Trivy)
- `JOERN_CPG_PATH` (call graph for reachability)

**What it does:**
For each CVE in the SBOM, queries Joern to determine if the vulnerable function is actually called and reachable from an exposed endpoint.

**Tools:** `query_joern`, `save_deliverable`

**Produces:** `SCA_REACHABILITY_REPORT`

**OWASP mapping:** A06 Vulnerable and Outdated Components

---

## Phase 4: Exploitation & Validation (Pro Only)

**Purpose:** Prove each Phase 3 hypothesis is actually exploitable against the live target.

**Edition:** Adversa Pro only
**LLM:** `claude-opus-4-6`
**Parallelism:** One exploit agent per non-empty Phase 3 queue
**Condition:** Agent only spawned if corresponding queue is non-empty

**Consumes (per agent):**
- Corresponding Phase 3 queue (`INJECTION_QUEUE`, `AUTHZ_QUEUE`, etc.)
- `AUTH_SESSION`
- `SCOPE_MANIFEST`
- `config.target.base_url`

**Exploit agent behaviour:**
1. Receive hypothesis queue from Phase 3
2. Construct a proof-of-concept for each item
3. Execute against live target via Playwright or direct HTTP
4. Capture evidence: HTTP status, response diff, exfiltrated data, screenshot
5. Confirmed exploit → write to `*_EVIDENCE` artifact with full PoC
6. Failed exploit after 3 variations → discard as `false_positive`

**Tools:** `http_probe` (scope-checked), `browser_navigate` (scope-checked), `browser_click`, `browser_type`, `browser_screenshot`, `save_deliverable`, `flag_vulnerability`

**Produces:**

| Artifact | Consumed By |
|---|---|
| `INJECTION_EVIDENCE` | Phase 5b |
| `AUTHZ_EVIDENCE` | Phase 5b |
| `INFO_DISCLOSURE_EVIDENCE` | Phase 5b |
| `SSRF_EVIDENCE` | Phase 5b |
| `SAST_EVIDENCE` | Phase 5b |
| `FALSE_POSITIVES` | Phase 5b (stats only) |

---

## Phase 5a: Findings Report (OSS)

**Purpose:** Collate Phase 3 queues into an OWASP-mapped findings report for a developer audience.

**Edition:** Both (OSS stops here; Pro also produces 5b)
**LLM:** `claude-sonnet-4-6`

**Consumes:**
- `INJECTION_QUEUE`
- `AUTHZ_QUEUE`
- `INFO_DISCLOSURE_QUEUE`
- `SSRF_QUEUE`
- `SAST_CONFIRMED_QUEUE`
- `SCA_REACHABILITY_REPORT`
- `ENDPOINT_INVENTORY`
- `SCOPE_MANIFEST`
- `session_metrics` (in progress)

**Report structure:**
```
1. Summary
   - Finding counts by severity
   - OWASP categories covered
   - Note: proof-of-exploitability not included in this edition

2. Findings by OWASP Category
   For each finding:
   - Title, severity badge, OWASP category, CWE ID
   - Affected endpoint + source file:line
   - Description (plain English)
   - Taint path or static analysis evidence
   - Remediation guidance + code fix

3. SCA / Dependency Risk (A06)
   - Reachable CVEs with update priority

4. Appendix
   - Endpoint inventory, tools used, scope and exclusions
```

**Produces:**

| Artifact | Format |
|---|---|
| `findings_report.html` | Jinja2 HTML (Adversa branded) |
| `findings.json` | Machine-readable, CI/CD consumable |
| `session_metrics.json` | Cost, duration, scope blocks, turn counts |

---

## Phase 5b: Pentest Report (Pro Only)

**Purpose:** Produce an audit-ready pentest report with proof-of-exploitability per finding.

**Edition:** Adversa Pro only
**LLM:** `claude-sonnet-4-6`

**Consumes:**
- All Phase 4 evidence artifacts (`INJECTION_EVIDENCE`, `AUTHZ_EVIDENCE`, `INFO_DISCLOSURE_EVIDENCE`, `SSRF_EVIDENCE`, `SAST_EVIDENCE`)
- `FALSE_POSITIVES`
- `SCA_REACHABILITY_REPORT`
- `ENDPOINT_INVENTORY`
- `ATTACK_SURFACE_SUMMARY`
- `SCOPE_MANIFEST`
- `session_metrics` (in progress)

**Additional requirements beyond Phase 5a (per finding):**
- CVSS 3.1 score and vector string
- Copy-paste proof-of-concept (curl command or script)
- HTTP request/response evidence
- Business impact statement
- Remediation priority: `immediate | short-term | long-term`
- Only confirmed findings included — unconfirmed hypotheses excluded

**Report structure:**
```
1. Executive Summary
   - Overall risk rating, finding counts by severity
   - Top 3 critical findings
   - Business impact summary

2. Methodology
   - Phases executed, tools used
   - Scope and exclusions with scope enforcement audit trail

3. Findings by OWASP Category (confirmed only)
   For each finding:
   - Title, severity badge, CVSS score, OWASP category, CWE ID
   - Affected endpoint + source file:line
   - Description
   - Proof of concept (copy-paste curl/script)
   - HTTP evidence (request + response excerpt)
   - Business impact
   - Remediation guidance + code fix
   - Remediation priority

4. API Security Findings (OWASP API Top 10)

5. Dependency Risk (A06)
   - Reachable CVEs with CVSS, packages to update

6. Remediation Priority Matrix
   - Table: Finding | Severity | CVSS | Effort | Priority

7. Appendix
   - Full endpoint inventory
   - Scope enforcement audit trail
   - Tool versions, engagement metadata
```

**Produces:**

| Artifact | Format |
|---|---|
| `pentest_report.html` | Jinja2 HTML |
| `pentest_report.pdf` | WeasyPrint PDF (signed) |
| `findings.json` | Machine-readable, SOC2 evidence package |
| `session_metrics.json` | Full engagement metrics |

---

## Artifact Flow Summary

```
Phase 0 → PREFLIGHT_RESULT, SCOPE_MANIFEST, TOOL_MANIFEST
Phase 1 → CODE_ANALYSIS, SBOM, SEMGREP_RAW, JOERN_CPG_PATH, INFRA_MAP, TECH_STACK
Phase 2 → RECON_MAP, AUTH_SESSION, ENDPOINT_INVENTORY, ATTACK_SURFACE_SUMMARY
Phase 3 → INJECTION_QUEUE, AUTHZ_QUEUE, INFO_DISCLOSURE_QUEUE,
          SSRF_QUEUE, SAST_CONFIRMED_QUEUE, SCA_REACHABILITY_REPORT
Phase 4 → INJECTION_EVIDENCE, AUTHZ_EVIDENCE, INFO_DISCLOSURE_EVIDENCE,
          SSRF_EVIDENCE, SAST_EVIDENCE, FALSE_POSITIVES  [Pro only]
Phase 5a → findings_report.html, findings.json, session_metrics.json  [OSS]
Phase 5b → pentest_report.html, pentest_report.pdf, findings.json, session_metrics.json  [Pro]
```
