"""
Phase 1: Pre-recon agent — runs SAST, SCA, infra scanning via claude-agent-sdk.

A single LLM agent with Bash access that runs semgrep, trivy, nmap, subfinder,
httpx, and optionally joern-parse. It writes each scan result directly to the
artifact store via Bash, then returns a lightweight summary.

Produces: SEMGREP_RAW, SBOM, INFRA_MAP, TECH_STACK, JOERN_CPG_PATH artifacts.
"""
from __future__ import annotations

import logging
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions
from pydantic import BaseModel, Field

from src.artifacts.store import ArtifactStore
from src.config.models import AdversaConfig
from src.services.agent_runner import build_agent_env, run_agent

logger = logging.getLogger(__name__)

# The agent needs Bash to run scanner tools and write artifacts, Read/Glob to inspect files
_ALLOWED_TOOLS = ["Bash", "Read", "Glob", "Grep"]


# ─── Simplified structured output schema ─────────────────────────────────────
# The agent writes full scan data to artifact files via Bash.
# Structured output is just a summary for the activity to check status.


class PreReconSummary(BaseModel):
    """Lightweight summary returned by the pre-recon agent."""
    semgrep_findings_count: int = Field(description="Total Semgrep findings")
    semgrep_error: str | None = Field(default=None, description="Error if Semgrep failed")
    sca_vulns_count: int = Field(description="Total Trivy CVE vulnerabilities")
    sca_lockfile_found: bool = Field(description="Whether a lockfile was found or generated")
    sca_error: str | None = Field(default=None, description="Error if Trivy failed")
    infra_open_ports: int = Field(description="Total open ports found by nmap")
    joern_success: bool = Field(description="Whether Joern CPG was built")
    joern_error: str | None = Field(default=None, description="Error if Joern failed or was skipped")
    summary: str = Field(description="One-paragraph summary of all scan results")


_OUTPUT_FORMAT: dict = {
    "type": "json_schema",
    "schema": PreReconSummary.model_json_schema(),
}


# ─── Scope rules formatting ─────────────────────────────────────────────────


def _format_scope_rules(config: AdversaConfig) -> str:
    """Format scope avoid/focus rules as markdown for prompt injection."""
    lines: list[str] = []
    avoid = config.scope.rules.avoid
    focus = config.scope.rules.focus

    if not avoid and not focus:
        return ""

    lines.append("## Scope Rules\n")

    if avoid:
        lines.append("**AVOID these paths/endpoints (do NOT scan, probe, or include in results):**")
        for rule in avoid:
            path = rule.url_path or "(host-level)"
            lines.append(f"- `{path}` ({rule.type}) — {rule.description}")
        lines.append("")

    if focus:
        lines.append("**FOCUS on these paths/endpoints (prioritize scanning and deeper analysis):**")
        for rule in focus:
            path = rule.url_path or "(host-level)"
            lines.append(f"- `{path}` ({rule.type}) — {rule.description}")
        lines.append("")

    return "\n".join(lines)


def _format_preflight_context(store: ArtifactStore) -> str:
    """Format preflight results as context for the agent prompt."""
    if not store.exists("PREFLIGHT_RESULT"):
        return ""

    preflight = store.read("PREFLIGHT_RESULT")
    lines: list[str] = ["**Phase 0 Preflight Results (use this to guide your scans):**"]

    # Repo profile — frameworks are especially useful for choosing scan strategies
    rp = preflight.get("repo_profile")
    if rp:
        if rp.get("frameworks"):
            lines.append(f"- Frameworks detected: {', '.join(rp['frameworks'])}")
        lines.append(f"- Detection method: {rp.get('detection_method', 'unknown')}, "
                     f"confidence: {rp.get('confidence', 'unknown')}")

    # Scope manifest — agent needs to know what's in/out of scope
    sm = preflight.get("scope_manifest")
    if sm:
        import json
        manifest = json.loads(sm) if isinstance(sm, str) else sm
        if manifest.get("excluded_paths"):
            lines.append(f"- Excluded paths: {', '.join(manifest['excluded_paths'])}")
        if manifest.get("excluded_patterns"):
            lines.append(f"- Excluded patterns: {', '.join(manifest['excluded_patterns'])}")

    # Check results — warn about any failures the agent should know about
    checks = preflight.get("checks", [])
    failed = [c for c in checks if c.get("status") == "fail"]
    if failed:
        lines.append("- **Preflight warnings:**")
        for c in failed:
            lines.append(f"  - {c['name']}: {c.get('detail', 'failed')}")

    return "\n".join(lines) + "\n"


# ─── Prompts ──────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are the **Phase 1 Pre-Recon Scanner** in Adversa, a whitebox AI-powered \
penetration testing pipeline.

**Pipeline context:**
- Phase 0 (complete): Preflight identified the target's languages, frameworks, \
and Semgrep rulesets.
- **Phase 1 (YOU): Run static analysis and infrastructure scanning.** Your output \
is the foundation everything downstream depends on.
- Phase 2 (next): A recon agent uses your INFRA_MAP and TECH_STACK to discover \
endpoints and establish authenticated sessions.
- Phase 3 (downstream): Six parallel vulnerability agents consume your output:
  - **Injection agent** — SEMGREP_RAW + Joern CPG for taint-flow confirmation
  - **AuthZ agent** — INFRA_MAP endpoints to test BOLA, privilege escalation
  - **Info Disclosure agent** — TECH_STACK for misconfigured headers, debug endpoints
  - **SSRF agent** — endpoint inventory + INFRA_MAP for internal service probing
  - **SAST Triage agent** — cross-references SEMGREP_RAW against source code
  - **SCA Reachability agent** — SBOM vulnerabilities for reachable code paths

**Why your output quality matters:**
- Empty SEMGREP_RAW → SAST Triage and Injection agents have nothing to work with.
- SBOM with 0 vulns because of a missing lockfile → SCA Reachability skips entirely.
- Incomplete INFRA_MAP → recon agent misses services, AuthZ/SSRF have blind spots.
- False negatives at Phase 1 propagate as blind spots through the entire pentest.

**Available tools on PATH:**
- `semgrep` — SAST scanner (supports 30+ languages, custom rulesets)
- `trivy` — SCA scanner (SBOM, CVE, secret, misconfig scanning)
- `nmap` — network/port scanner
- `subfinder` — passive subdomain enumeration
- `pd-httpx` — ProjectDiscovery HTTP probe / tech detection (NOT Python httpx)
- `joern-parse` / `joern` — CPG builder for taint-flow analysis (if enabled)
- `npm` — available for lockfile generation (JS/TS targets)
- Standard Unix tools: `curl`, `jq`, `grep`, `awk`, etc.

**Hard rules (non-negotiable):**
- **Save each scan result to the artifact directory immediately** — do NOT wait \
until the end. Use Bash to write JSON files as you go.
- **Respect scope avoid/focus rules** — skip endpoints under AVOID, prioritize FOCUS.
- **Never modify source code** — lockfile generation is OK, code changes are not.
- **Strip the repo base path** from all file paths in findings for portability.
- If a tool fails, capture the error, log it, and continue with other tools.

**Soft guidelines (adapt as needed):**
- The recommended commands below are starting points. You have full discretion to \
adjust flags, add retries, run additional passes, or use different tool modes \
based on what you discover about the target.
- If results are empty or suspicious, investigate WHY and try alternative approaches \
before accepting the result (wrong path? missing lockfile? unsupported language? \
wrong scan mode?).
- If you discover something unexpected (additional services, interesting files, \
unusual tech stack), capture it in the artifacts — more data is better for \
downstream agents.
- Generate missing lockfiles before SCA scanning — downstream agents need \
dependency data. Use the appropriate package manager for the detected language.
"""

_USER_PROMPT = """\
Run Phase 1 pre-recon scans on the target.

**Artifact directory:** `{artifact_dir}`
```
mkdir -p {artifact_dir}
```

**Configuration:**
- **Repository:** {repo_path}
- **Target URL:** {base_url}
- **Target Hosts:** {included_hosts}
- **Detected Languages:** {languages}
- **Detected Frameworks:** {frameworks}
- **Semgrep Rulesets:** {rulesets}
- **Joern Enabled:** {joern_enabled}

{preflight_context}

{scope_rules}\
---

## 1. SAST — Semgrep → `{artifact_dir}/SEMGREP_RAW.json`

**Goal:** Find all static analysis findings in the repo. Downstream Injection and \
SAST Triage agents depend on comprehensive coverage.

**Recommended approach:**
```
semgrep scan {ruleset_flags} --json --quiet --metrics=off --timeout 120 {repo_path} \
  > {artifact_dir}/SEMGREP_RAW.json 2>/dev/null
```

**You may adapt:** Add extra rulesets if you notice frameworks not covered by the \
defaults (e.g. `--config p/django` for Python/Django, `--config p/react` for React, \
`--config p/jwt` for JWT handling). Adjust `--timeout` for large repos. If Semgrep \
reports 0 findings, investigate and retry with broader rulesets before accepting.

After saving, read the JSON to count findings by severity and files scanned.

## 2. SCA — Trivy → `{artifact_dir}/SBOM.json`

**Goal:** Identify all known CVEs in dependencies. The SCA Reachability agent needs \
a populated vulnerability list.

**Recommended approach:**
1. Check for lockfiles. If none exist, generate one:
   - JS/TS: `cd {repo_path} && npm install --package-lock-only --ignore-scripts`
   - Python: `cd {repo_path} && pip freeze > requirements.txt` (or `uv lock`)
   - Go: `cd {repo_path} && go mod tidy`
   - Other: use the appropriate package manager
2. Run Trivy:
```
trivy fs --format json --severity CRITICAL,HIGH,MEDIUM --quiet {repo_path} \
  > {artifact_dir}/SBOM.json 2>/dev/null
```

**You may adapt:** Add `--scanners vuln,secret,misconfig` if you want broader \
coverage. Use `--list-all-pkgs` to include all packages (not just vulnerable ones) \
for a more complete SBOM. If Trivy returns 0 vulns but a lockfile exists, try \
`trivy fs --scanners vuln --format json {repo_path}` without severity filter.

## 3. Infrastructure → `{artifact_dir}/INFRA_MAP.json` + `{artifact_dir}/TECH_STACK.json`

**Goal:** Map all open ports, services, and technologies. Downstream Recon, AuthZ, \
SSRF, and Info Disclosure agents depend on complete infrastructure visibility.

**Recommended tools:**
- **nmap** — port scanning: `nmap -sV -T4 --top-ports 1000 -oX - {{host}}`
- **subfinder** — subdomain enumeration (skip for localhost/Docker/IP targets): \
`subfinder -d {{domain}} -silent`
- **pd-httpx** — HTTP probing and tech detection: \
`echo "{{targets}}" | pd-httpx -json -tech-detect -status-code -title -server -silent`

**You may adapt:**
- For targets behind WAFs or with rate limiting, reduce nmap timing (`-T3` or `-T2`).
- If `--top-ports 1000` misses expected services, try a full port scan (`-p-`) on \
specific hosts.
- Add `-sU --top-ports 20` for UDP scanning on high-value targets.
- If pd-httpx fails or is unavailable, infer tech stack from nmap service banners, \
HTTP response headers (`curl -sI`), and repo source code.
- Probe each discovered HTTP port for common paths (`/robots.txt`, `/sitemap.xml`, \
`/.well-known/`, `/api/`, `/swagger.json`, `/health`) to enrich the INFRA_MAP.

**Artifact format — INFRA_MAP.json:**
```json
{{
  "hosts": [{{"hostname": "...", "ports": [{{"port": N, "protocol": "tcp", \
"service": "...", "version": "...", "product": "..."}}]}}],
  "total_hosts": N,
  "total_open_ports": N,
  "warnings": ["..."]
}}
```

**Artifact format — TECH_STACK.json:**
```json
{{
  "technologies": ["Node.js", "Express", ...],
  "servers": ["nginx/1.24", ...],
  "subdomains": ["api.example.com", ...]
}}
```

## 4. Joern CPG Build (conditional)

{joern_instructions}

## Final Summary

Do NOT return raw scan data — it's already saved in the artifact files. \
Return ONLY a lightweight summary:
- `semgrep_findings_count`: total findings
- `sca_vulns_count`: total CVEs from Trivy
- `infra_open_ports`: total open ports
- `joern_success`: true/false
- `summary`: one paragraph — what was found, what downstream agents should \
focus on, any gaps/limitations, and your confidence in the scan coverage
"""


# ─── Entry point ──────────────────────────────────────────────────────────────


async def run_pre_recon(config: AdversaConfig, store: ArtifactStore) -> dict[str, Any]:
    """
    Run a single LLM agent that executes all Phase 1 scans, writes artifacts
    directly to the store directory via Bash, and returns a lightweight summary.

    Returns the summary dict, or a fallback dict on agent failure.
    """
    repo_profile = _load_repo_profile(store, config)
    languages = repo_profile.get("languages", [])
    rulesets = repo_profile.get("semgrep_rulesets", ["p/owasp-top-ten"])
    joern_enabled = config.repo.joern_enabled

    # Build ruleset flags for semgrep command
    ruleset_flags = " ".join(f"--config {r}" for r in rulesets)

    # Joern instructions
    if joern_enabled:
        lang = languages[0] if languages else "unknown"
        lang_map = {
            "python": "pythonsrc", "java": "javasrc",
            "javascript": "jssrc", "typescript": "jssrc", "go": "golang",
        }
        joern_lang = lang_map.get(lang, "")
        lang_flag = f"--language {joern_lang}" if joern_lang else ""
        joern_instructions = f"""\
Joern is ENABLED. Build the Code Property Graph:
```
joern-parse {config.repo.path} --output {store._dir}/cpg.bin {lang_flag}
```
Then write the result:
```
cat > {store._dir}/JOERN_CPG_PATH.json << 'JOERN_EOF'
{{"success": true, "cpg_path": "{store._dir}/cpg.bin", "error": null}}
JOERN_EOF
```
If it fails, write: `{{"success": false, "cpg_path": null, "error": "...the error..."}}`"""
    else:
        joern_instructions = f"""\
Joern is DISABLED. Write the skip result:
```
cat > {store._dir}/JOERN_CPG_PATH.json << 'JOERN_EOF'
{{"success": false, "cpg_path": null, "error": "Joern disabled in config"}}
JOERN_EOF
```"""

    # Format scope rules and preflight context
    scope_rules = _format_scope_rules(config)
    preflight_context = _format_preflight_context(store)
    frameworks = repo_profile.get("frameworks", [])

    # Artifact directory path the agent will write to
    artifact_dir = str(store._dir)

    prompt = _USER_PROMPT.format(
        repo_path=config.repo.path,
        base_url=config.target.base_url,
        included_hosts=", ".join(config.target.included_hosts),
        languages=", ".join(languages) if languages else "unknown",
        frameworks=", ".join(frameworks) if frameworks else "none detected",
        rulesets=", ".join(rulesets),
        ruleset_flags=ruleset_flags,
        joern_enabled=joern_enabled,
        joern_instructions=joern_instructions,
        scope_rules=scope_rules,
        preflight_context=preflight_context,
        artifact_dir=artifact_dir,
    )

    options = ClaudeAgentOptions(
        model=config.llm.model_name,
        system_prompt=_SYSTEM_PROMPT,
        allowed_tools=_ALLOWED_TOOLS,
        max_turns=50,
        cwd="/app" if _is_docker() else ".",
        env=build_agent_env(config),
        permission_mode="bypassPermissions",
        output_format=_OUTPUT_FORMAT,
    )

    logger.info("Starting pre-recon agent (model=%s, repo=%s)", config.llm.model_name, config.repo.path)

    result = await run_agent(
        options=options,
        prompt=prompt,
        config=config,
    )

    output = result.get("structured_output")
    if not output:
        logger.error("Pre-recon agent returned no structured output: %s", result.get("error"))
        output = _fallback_output(result.get("error", "Agent returned no output"))

    # Verify artifacts were written by the agent
    _verify_artifacts(store)

    logger.info("Pre-recon agent complete: %s", output.get("summary", "no summary"))
    return output


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _load_repo_profile(store: ArtifactStore, config: AdversaConfig) -> dict:
    """Load repo profile from artifact store, falling back to config defaults."""
    if store.exists("PREFLIGHT_RESULT"):
        preflight = store.read("PREFLIGHT_RESULT")
        repo_profile = preflight.get("repo_profile")
        if repo_profile:
            return repo_profile
    return {
        "languages": [config.repo.language] if config.repo.language else [],
        "semgrep_rulesets": config.repo.semgrep_rulesets or ["p/owasp-top-ten"],
        "joern_enabled": config.repo.joern_enabled,
    }


def _is_docker() -> bool:
    """Detect if running inside Docker."""
    try:
        with open("/proc/1/cgroup") as f:
            return "docker" in f.read()
    except Exception:
        return False


def _verify_artifacts(store: ArtifactStore) -> None:
    """Check that the agent wrote expected artifacts. Log warnings for missing ones."""
    expected = ["SEMGREP_RAW", "SBOM", "INFRA_MAP", "TECH_STACK", "JOERN_CPG_PATH"]
    for artifact in expected:
        if not store.exists(artifact):
            logger.warning("Pre-recon agent did not write artifact: %s", artifact)


def _fallback_output(error: str) -> dict:
    """Return a minimal valid summary dict when the agent fails entirely."""
    return {
        "semgrep_findings_count": 0,
        "semgrep_error": error,
        "sca_vulns_count": 0,
        "sca_lockfile_found": False,
        "sca_error": error,
        "infra_open_ports": 0,
        "joern_success": False,
        "joern_error": error,
        "summary": f"Pre-recon agent failed: {error}",
    }
