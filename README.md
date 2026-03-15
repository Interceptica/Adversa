# Adversa

**Whitebox AI penetration testing. SAST + SCA + DAST + taint analysis in a single agentic pipeline.**

Adversa combines static code analysis, dependency scanning, dynamic testing, and taint-flow analysis to find exploitable vulnerabilities in your web applications — guided by an AI agent that reads your source code, not just your HTTP traffic.

> ⚠️ **Use only on systems you own or have explicit written authorisation to test. Adversa executes real analysis against live targets and can have side effects on application data.**

---

## How It Works

```
Your repo + adversa.config.yaml
          │
          ▼
  Phase 0: Pre-flight + repo introspection
          │   Auto-detects language, framework, Semgrep rulesets
          ▼
  Phase 1: Static analysis (no LLM)
          │   Semgrep SAST · Trivy SCA + SBOM · Joern CPG build
          │   nmap · subfinder · httpx · WhatWeb
          ▼
  Phase 2: Live recon
          │   Authenticates · crawls · maps endpoints
          │   Correlates live routes with source locations
          ▼
  Phase 3: Vulnerability analysis (parallel)
          │   6 STRIDE-aligned agents run simultaneously:
          │   Injection (taint) · AuthZ/IDOR · Info Disclosure
          │   SSRF · SAST triage · SCA reachability
          ▼
  Phase 5a: Findings report
          OWASP Top 10 (2021) + API Security Top 10 (2023)
          Code-level evidence · Remediation guidance · findings.json
```

---

## Why Adversa

**Whitebox-native.** Repo access means Adversa traces vulnerabilities from source to sink using Joern's Code Property Graph — not just from what's observable over HTTP. A SQL injection that's five function calls deep gets found.

**Deterministic scope enforcement.** Excluded endpoints are blocked at the tool layer via `can_use_tool`, not just mentioned in a prompt. The LLM cannot probe `/health` or `/logout` regardless of what it reasons. Every blocked call is logged and included in the report as proof.

**No false positives from dead code.** The SAST triage agent cross-references Semgrep findings against the live endpoint inventory. Findings in code that's never reachable from an HTTP route are discarded before they reach your report.

**Audit-ready output.** Every finding maps to OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) with CWE IDs, source file:line, and remediation guidance with code examples. The `findings.json` output integrates directly into CI/CD pipelines.

---

## Editions

| | **Adversa OSS** | **Adversa Pro** |
|---|---|---|
| License | AGPL-3.0 | Commercial |
| Phases 0–3 (SAST + SCA + taint + DAST) | ✅ | ✅ |
| Findings report (OWASP-mapped, no PoC) | ✅ | ✅ |
| `findings.json` for CI/CD | ✅ | ✅ |
| Phase 4: Exploitation + proof-of-exploitability | ❌ | ✅ |
| Pentest report (CVSS, PoC, audit-ready PDF) | ❌ | ✅ |
| SOC2 / ISO 27001 evidence package | ❌ | ✅ |

[→ Learn about Adversa Pro](https://adversa.io)

---

## Requirements

- **Docker** and **Docker Compose**
- An LLM API key (Anthropic Claude recommended). Any Anthropic messages-compatible provider works — set `llm.base_url` in config to point at it.
- The target application's source code cloned locally

---

## Quick Start

```bash
# 1. Clone Adversa
git clone https://github.com/interceptica/adversa-core.git
cd adversa-core

# 2. Set your API key
cp .env.example .env
# Edit .env — set LLM_API_KEY

# 3. Clone the target repo
git clone https://github.com/your-org/your-app.git ./repos/your-app

# 4. Option A — use a config file (recommended)
cp configs/example-config.yaml adversa.config.yaml
# Edit adversa.config.yaml — set target URL, included_hosts, auth flow
./adversa start CONFIG=./adversa.config.yaml

# 4. Option B — quick start without a config file
./adversa start URL=https://staging.your-app.com REPO=./repos/your-app

# Adversa starts the containers, submits the workflow, and returns an engagement ID:
# → adv-your-app-20260314-1430

# 5. Monitor in real time
./adversa logs ID=adv-your-app-20260314-1430
open http://localhost:8233              # Temporal Web UI (full workflow graph)

# 6. Check progress
./adversa query ID=adv-your-app-20260314-1430

# 7. Open your report when complete
./adversa report ID=adv-your-app-20260314-1430
```

---

## Configuration

Adversa is driven by a single YAML file. Most fields are optional — language and Semgrep rulesets are auto-detected from your repo.

```yaml
# adversa.config.yaml
meta:
  project: "My App Security Assessment"
  # engagement_id is auto-generated: adv-{repo-name}-{YYYYMMDD-HHmm}

llm:
  model_name: "claude-sonnet-4-6"
  api_key: "${LLM_API_KEY}"
  base_url: null                    # null = Anthropic. Set for third-party providers.

target:
  base_url: "https://staging.your-app.com"
  included_hosts:
    - "staging.your-app.com"
  excluded_hosts:
    - "your-app.com"                # production — never touched

authentication:
  login_type: form
  login_url: "https://staging.your-app.com/login"
  credentials:
    username: "${TARGET_USERNAME}"
    password: "${TARGET_PASSWORD}"
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
      - description: "Skip health probes"
        type: path
        url_path: "/health"
      - description: "Avoid logout"
        type: path
        url_path: "/auth/logout"
    focus:
      - description: "Prioritise API endpoints"
        type: path_pattern
        url_path: "/api/*"

repo:
  path: "./repos/your-app"
  # language and semgrep_rulesets are auto-detected if omitted
  joern_enabled: true
```

See [`configs/example-config.yaml`](configs/example-config.yaml) for the full reference.

---

## What Gets Reported

Each finding in the OSS findings report includes:

- **OWASP Top 10 (2021)** and **OWASP API Security Top 10 (2023)** category
- **CWE ID**
- **Severity** (Critical / High / Medium / Low)
- **Affected endpoint** — URL, method, parameter
- **Source location** — file path and line number
- **Taint path** — how user input reaches the dangerous sink
- **Remediation** — plain-English guidance and a code fix example

```json
{
  "id": "inj-001",
  "vulnerability_class": "SQL Injection",
  "owasp_top10": "A03:2021 - Injection",
  "owasp_api_top10": null,
  "cwe": "CWE-89",
  "severity": "critical",
  "endpoint": "/api/users/search",
  "method": "GET",
  "parameter": "q",
  "source_file": "routes/users.py",
  "line": 87,
  "taint_path": ["q (HTTP param) → search_term (line 82) → cursor.execute() (line 87)"],
  "evidence": "Joern taint path confirmed. Semgrep rule also triggered.",
  "confidence": "high",
  "confirmed": false
}
```

`confirmed: false` means the finding has strong code-level evidence but has not been validated against a live target. Adversa Pro adds exploitation validation and sets `confirmed: true` on proven findings.

---

## OWASP Coverage

| Category | Status | Method |
|---|---|---|
| A01 Broken Access Control | ✅ | IDOR / AuthZ agent |
| A02 Cryptographic Failures | Partial | Semgrep rules |
| A03 Injection | ✅ | Joern taint analysis |
| A04 Insecure Design | Partial | Business logic patterns |
| A05 Security Misconfiguration | ✅ | Nuclei + Semgrep |
| A06 Vulnerable Components | ✅ | Trivy + Joern reachability |
| A07 Auth Failures | ✅ | AuthZ agent |
| A08 Integrity Failures | Partial | Semgrep |
| A09 Logging Failures | ❌ | Cannot reliably auto-detect |
| A10 SSRF | ✅ | SSRF agent + Joern |
| API1 BOLA | ✅ | AuthZ / IDOR agent |
| API2 Broken Auth | ✅ | AuthZ agent |
| API3 Broken Object Property Auth | Partial | Semgrep |
| API5 Broken Function Level Auth | ✅ | AuthZ agent |
| API7 SSRF | ✅ | SSRF agent |
| API8 Security Misconfiguration | ✅ | Nuclei + Semgrep |
| API9 Improper Inventory | ✅ | Recon phase (shadow APIs) |

---

## Architecture

Adversa is orchestrated by [Temporal](https://temporal.io) for durable, resumable execution. If the worker crashes mid-run, the workflow resumes from where it left off.

The agent layer uses `claude-agent-sdk`. Scope enforcement is implemented via `can_use_tool` — a callback that fires before every tool execution. Excluded paths are blocked deterministically, not just mentioned in a prompt.

```
Temporal Workflow
├── Phase 0: Pre-flight + repo introspection  (deterministic)
├── Phase 1: Static analysis                  (tools only, no LLM)
├── Phase 2: Live recon                       (LLM agent)
├── Phase 3: Vulnerability analysis           (6 parallel LLM agents)
│   ├── Injection agent       → INJECTION_QUEUE
│   ├── AuthZ agent           → AUTHZ_QUEUE
│   ├── Info Disclosure agent → INFO_DISCLOSURE_QUEUE
│   ├── SSRF agent            → SSRF_QUEUE
│   ├── SAST triage agent     → SAST_CONFIRMED_QUEUE
│   └── SCA reachability agent → SCA_REACHABILITY_REPORT
└── Phase 5a: Findings report                 (LLM agent)
```

---

## Monitoring

```bash
# Real-time logs for a specific engagement
./adversa logs ID=adv-your-app-20260314-1430

# Query engagement status and current phase
./adversa query ID=adv-your-app-20260314-1430

# Open the findings report in your browser
./adversa report ID=adv-your-app-20260314-1430

# List all past engagements
./adversa workspaces

# Full Temporal workflow UI
open http://localhost:8233

# Stop containers (data preserved)
./adversa stop

# Stop and wipe all data
./adversa stop CLEAN=true
```

Output is saved to `./audit-logs/{engagement_id}/`:

```
audit-logs/adv-your-app-20260314-1430/
├── findings_report.html     # Human-readable report
├── findings.json            # Machine-readable — import into CI/CD
├── scope.jsonl              # Audit trail of every scope enforcement decision
└── deliverables/            # Raw artifacts from each phase
```

---

## Supported Languages

Auto-detected from your repo. Override by setting `repo.language` in config.

| Language | SAST | Taint (Joern) | SCA |
|---|---|---|---|
| Python | ✅ | ✅ | ✅ |
| JavaScript / TypeScript | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ |

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Adversa security scan
  run: |
    docker compose up -d
    ./adversa start URL=${{ vars.STAGING_URL }} REPO=app --wait
    
- name: Check for critical findings
  run: |
    CRITICAL=$(jq '[.findings[] | select(.severity == "critical")] | length' audit-logs/latest/findings.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::$CRITICAL critical findings detected"
      exit 1
    fi
```

---

## Development / Testing Against Juice Shop

Run Phase 0 end-to-end against OWASP Juice Shop before building Phase 1.

```bash
# Clone Juice Shop
git clone https://github.com/juice-shop/juice-shop.git ./repos/juice-shop

# Start Juice Shop (exposes port 3000)
cd repos/juice-shop && docker compose up -d && cd ../..

# Run Phase 0 smoke test
./adversa dev CONFIG=./configs/juiceshop.config.yaml
```

Expected output:
```json
{
  "status": "pass",
  "checks": [...],
  "errors": [],
  "scope_manifest": { "included_hosts": ["host.docker.internal"], ... },
  "repo_profile": {
    "languages": ["javascript", "typescript"],
    "frameworks": ["express", ...],
    "semgrep_rulesets": ["p/owasp-top-ten", "p/javascript", "p/typescript"],
    "detection_method": "llm",
    "confidence": "high"
  }
}
```

The `dev` command:
1. Builds the `adversa` worker image (uses Docker layer cache — fast on re-runs)
2. Starts the full stack (`postgresql`, `temporal`, `adversa` worker)
3. Submits `PreflightWorkflow` (Phase 0 only — does not proceed to Phase 1+)
4. Prints the `PreflightResult` JSON and exits `0` (pass) or `1` (fail)

---

## Disclaimers

- Adversa is designed for **whitebox testing** — it requires source code access
- Run against **staging or development environments only**, never production
- You must have **explicit written authorisation** from the system owner before running
- The exploitation phase (Adversa Pro) actively executes attacks and can modify application data

---

## License

Adversa OSS is released under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

You may use it freely for internal security testing and modify it privately without sharing changes. If you offer Adversa as a public service or SaaS, AGPL requires you to open-source your modifications.

For commercial licensing (proprietary SaaS, white-labelling, Adversa Pro features), contact [hello@adversa.io](mailto:info@interceptica.com).



---

*Built by [Interceptica](https://interceptica.com)*