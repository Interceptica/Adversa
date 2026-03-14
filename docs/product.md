# Adversa — Product & Business Context

> Extracted from PRD v0.2 (sections 1–4, 15–16).
> Technical architecture: `architecture.md`. Phase contracts: `phase-contracts.md`. Artifact schemas: `artifact-schemas.md`.

---

## Executive Summary

Adversa is a **whitebox, AI-powered penetration testing platform** that combines static code analysis (SAST), dependency scanning (SCA), dynamic application testing (DAST), and taint-flow analysis into a single agentic pipeline. Unlike blackbox competitors (XBOW) or prompt-only tools (Shannon), Adversa has native repository access — enabling it to trace vulnerabilities from source to sink rather than infer them from observable behaviour alone.

**Two editions:**
- **Adversa OSS (AGPL-3.0):** Phases 0–3 + findings report. Triaged, OWASP-mapped vulnerability hypothesis report with code-level evidence. Serves developers.
- **Adversa Pro (Commercial):** Full pipeline including Phase 4 exploitation and audit-ready pentest report with proof-of-exploitability. Serves CTOs and compliance leads.

---

## Problem Statement & Competitive Context

### The Gap

Modern engineering teams ship continuously. Penetration tests happen once or twice a year. AI coding tools (Cursor, Claude Code) accelerate this gap — teams ship code faster than security can review it.

### Existing Tools Fall Short

| Tool | Approach | Key Limitation |
|---|---|---|
| XBOW | Blackbox DAST | No code access; can only test what is observable |
| Shannon | Whitebox + Claude Agent SDK | Scope enforcement is prompt-only (probabilistic); no SAST/SCA; ~$50/run |
| Burp Suite | Manual DAST | Requires skilled operator; not automated |
| Semgrep / Snyk | SAST / SCA only | No dynamic validation; high false positive rate |
| Pentest firms | Human-led | Expensive, slow, not continuous |

### Shannon's Specific Weaknesses

- Scope rules are injected as `{{CONFIG_CONTEXT}}` into the prompt — purely probabilistic. A hallucinating model can still probe excluded endpoints.
- Runs with `bypassPermissions: true` and leaks the entire process environment (all API keys) into the Playwright MCP subprocess — a known security issue flagged by their own community.
- No SAST, no SCA, no taint analysis. DAST only despite calling itself whitebox.
- No tiered model strategy — pays Claude Sonnet rates for trivial recon tasks.
- TypeScript-only, making deep AppSec tool integration (Joern, Semgrep) awkward.

**Adversa's answer:** Deterministic scope enforcement at the tool layer, layered SAST + SCA + DAST + taint, tiered model cost strategy, Python-native AppSec tooling, and a clean OSS/paid split that does not give exploitation away for free.

---

## Product Vision & Differentiators

> "The first AI pentester a Series A startup can trust with their production codebase — continuously, not annually."

**1. Deterministic Scope Enforcement**
Scope rules are enforced at four independent layers. The tool is *architecturally incapable* of testing an excluded endpoint — not just instructed to avoid it.

**2. Whitebox-Native**
Repo access enables real static analysis: taint-flow via Joern, SAST via Semgrep, SCA with reachability via Trivy. LLM reads of code files are always tool-triggered — Joern finds the taint path, the LLM reads the specific file:line to reason about it. Never speculative.

**3. Tiered Model Cost Strategy**
Recon uses Novita (Llama 3.1 70B) at ~1/10th the cost. Vuln analysis and exploitation use Claude Opus. Reporting uses Claude Sonnet. Per-run cost target: <$15 vs Shannon's ~$50.

**4. OWASP-Mapped Audit-Ready Output**
Every finding maps to OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) with CWE IDs and CVSS 3.1 scores — structured for SOC2/ISO 27001 audit evidence packages.

**5. Clean OSS / Paid Split**
OSS gives developers real value (triaged, code-level findings). Paid gives compliance leads what they actually need (proof of exploitability). No grey zone.

> **Phase 3 prompt templates are not open sourced.** The Joern query patterns, taint analysis heuristics, and false positive reduction logic in those prompts are Adversa's primary technical moat. The orchestration scaffolding can be open — the prompts stay proprietary.

---

## Target Users & ICP

### Ideal Customer Profile

- **Stage:** Series A or B
- **Sector:** Fintech, healthtech
- **Driver:** Undergoing SOC2 Type II or ISO 27001
- **Geography:** Australia (primary), US and Europe (secondary)
- **Team size:** 10–50 engineers, no dedicated AppSec team

### User Personas

**Engineering Lead / CTO (Primary)**
Needs a credible pentest report for auditors without a $30K engagement. Wants CI/CD integration for every major release.

**Compliance Lead / CISO (Secondary)**
Needs OWASP-structured evidence (CVSS, CWE, remediation) for audit packages.

**Senior Developer (OSS user)**
Needs actionable findings with file:line references and fix suggestions before the paid pentest confirms them.

---

## Product Editions

| Capability | Adversa OSS | Adversa Pro |
|---|---|---|
| Phase 0: Pre-flight | ✅ | ✅ |
| Phase 1: Pre-recon (tools only) | ✅ | ✅ |
| Phase 2: Recon | ✅ | ✅ |
| Phase 3: Vulnerability analysis (SAST + SCA + taint) | ✅ | ✅ |
| Phase 4: Exploitation & proof-of-exploitability | ❌ | ✅ |
| Findings report (OWASP-mapped, no PoC) | ✅ | ✅ |
| Pentest report (with PoC, CVSS, audit-ready PDF) | ❌ | ✅ |
| Phase 3 prompt templates | ❌ Proprietary | ✅ |
| `findings.json` for CI/CD | ✅ | ✅ |
| Signed PDF export | ❌ | ✅ |
| SOC2 evidence package format | ❌ | ✅ |
| License | AGPL-3.0 | Commercial |

**Why this split works:**
- OSS serves developers: *"show me what to fix and where"*
- Pro serves compliance leads: *"prove it's exploitable for my SOC2 auditor"*

The OSS findings report is better than raw Semgrep output — the LLM has triaged false positives and explained taint flows in plain English. But it is not sufficient for a compliance auditor who needs **proof of exploitability**.

---

## Go-To-Market & Pricing

### Pricing

| Tier | Price | Includes |
|---|---|---|
| OSS | Free | Phases 0–3 + findings report, self-hosted |
| Starter | $499/engagement | Full Pro pipeline, HTML + PDF report |
| Growth | $299/engagement (volume) | Same + `findings.json`, priority queue |
| Enterprise | Custom | CI/CD, Jira/Linear sync, SOC2 evidence package, custom rulesets |

### 90-Day Milestones

**Days 1–30: Core OSS Pipeline**
- [ ] Phases 0–2 complete with scope enforcement
- [ ] Phase 3 injection + authz agents end-to-end
- [ ] Phase 5a findings report with OWASP mapping
- [ ] `adversa.config.yaml` schema + validation complete
- [ ] Docker compose local dev setup
- [ ] 1 internal test engagement (Juice Shop or crAPI)

**Days 31–60: Full OSS + Pro Foundation**
- [ ] All Phase 3 agents (info disclosure, SSRF, SAST triage, SCA reachability)
- [ ] Joern CPG integration for taint analysis
- [ ] Trivy SBOM + CVE reachability
- [ ] Phase 4 exploitation agent (Pro)
- [ ] Phase 5b pentest report with PDF export
- [ ] `findings.json` machine-readable output
- [ ] 2nd internal test engagement (OWASP crAPI)
- [ ] First external beta client onboarded

**Days 61–90: SaaS + First Revenue**
- [ ] FastAPI wrapper (REST API for triggering engagements)
- [ ] Web-based report viewer
- [ ] Customer config upload flow
- [ ] Temporal Cloud migration
- [ ] 3 paying clients at $499/engagement
- [ ] SOC2 evidence package format
- [ ] Outreach pipeline live

---

## Open Questions & Risks

| # | Risk | Priority |
|---|---|---|
| 1 | Joern CPG build time for large repos (>100k LOC) may blow Phase 1 timeout | High |
| 2 | Client repo access model — local clone or secure ingestion endpoint? | High |
| 3 | AGPL-3.0 OSS licence — ensure no Shannon code is used directly given Adversa is SaaS | High |
| 4 | SOC2 compliance for Adversa itself — clients will ask | High |
| 5 | Novita API reliability — fallback to Claude Haiku if Novita is down? | Medium |
| 6 | Playwright in Docker on ARM (Mac M-series dev) — Chromium ARM compatibility | Medium |
| 7 | False negative rate — how do we measure recall across vulnerability classes? | Medium |
| 8 | Anthropic 5-hour rolling rate limit can stall long Pro runs | Medium |
| 9 | Extended thinking for taint analysis agents — cost vs quality tradeoff | Low |
| 10 | Multi-tenancy in Temporal — namespace isolation vs workflow ID prefixing | Low |
