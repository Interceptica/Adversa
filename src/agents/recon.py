"""
Phase 2: Recon agent — whitebox source-code-first reconnaissance.

Primary method is source code reading (fast, deterministic), NOT browser crawling.
The agent reads route files, middleware, models, and auth guards directly — exactly
like Shannon — then uses the browser only for the auth flow and SPA-only routes.

Produces:
  recon_deliverable.md  — rich narrative (the primary deliverable for Phase 3 agents)
  AUTH_SESSION.json     — machine-readable session tokens/cookies for Phase 3 HTTP requests
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions

from src.agents._shared import format_preflight_context, format_scope_rules, is_docker
from src.artifacts.store import ArtifactStore
from src.audit.logger import AuditLogger
from src.config.models import AdversaConfig
from src.scope.can_use_tool import build_can_use_tool
from src.services.agent_runner import build_agent_env, run_agent

logger = logging.getLogger(__name__)

# Source reading is the primary method — Bash for writing artifacts + curl probing,
# Playwright only for auth flow and SPA route confirmation.
_ALLOWED_TOOLS = [
    "Bash", "Read", "Glob", "Grep",
    "mcp__playwright__browser_navigate",
    "mcp__playwright__browser_click",
    "mcp__playwright__browser_type",
    "mcp__playwright__browser_take_screenshot",
    "mcp__playwright__browser_snapshot",
    "mcp__playwright__browser_network_requests",
]

# Markdown deliverable filename — written by agent via Bash
RECON_DELIVERABLE = "recon_deliverable.md"


# ─── Playwright MCP server config ─────────────────────────────────────────────


def _build_playwright_mcp() -> dict:
    """Build the MCP server config for Microsoft's @playwright/mcp server."""
    return {
        "command": "npx",
        "args": ["@playwright/mcp@latest", "--headless"],
        "env": {
            "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH": os.environ.get(
                "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", "/usr/bin/chromium"
            ),
        },
    }


# ─── Prompt helpers ──────────────────────────────────────────────────────────


def _format_login_flow(config: AdversaConfig) -> str:
    """Convert authentication config into numbered instructions."""
    auth = config.authentication

    if auth.login_type == "none":
        return "No authentication required. Skip the browser auth step."

    if auth.login_type == "bearer":
        token = auth.credentials.password if auth.credentials else "<missing>"
        return (
            f"Set Authorization header: `Bearer {token}`\n\n"
            "Write AUTH_SESSION.json with this header. No browser login needed."
        )

    if auth.login_type == "api_key":
        key = auth.credentials.password if auth.credentials else "<missing>"
        return (
            f"Set API key header: `{key}`\n\n"
            "Write AUTH_SESSION.json with this header. No browser login needed."
        )

    # Form-based login
    lines: list[str] = []
    login_url = auth.login_url or config.target.base_url
    lines.append(f"1. Navigate to the login page: `{login_url}`")

    step_num = 2
    username = auth.credentials.username if auth.credentials else "<missing>"
    password = auth.credentials.password if auth.credentials else "<missing>"

    for step in auth.login_flow:
        instruction = step.replace("$username", username).replace("$password", password)
        lines.append(f"{step_num}. {instruction}")
        step_num += 1

    if auth.credentials and auth.credentials.totp_secret:
        secret = auth.credentials.totp_secret
        lines.append(
            f"{step_num}. If a TOTP/MFA prompt appears, run "
            f"`oathtool --totp -b {secret}` via Bash to generate the code, then type it."
        )
        step_num += 1

    if auth.success_condition:
        sc = auth.success_condition
        lines.append(f"\n**Success condition:** `{sc.type}` matches `{sc.value}`.")

    if auth.token_extraction:
        te = auth.token_extraction
        if te.type == "cookie":
            lines.append("\n**Token extraction:** Capture session cookies after login.")
        elif te.type == "response_header":
            header = te.header or "Authorization"
            lines.append(f"\n**Token extraction:** Extract `{header}` response header after login.")
        elif te.type == "response_body":
            lines.append("\n**Token extraction:** Extract Bearer token from response body after login.")

    return "\n".join(lines)


def _format_phase1_context(store: ArtifactStore) -> str:
    """Format Phase 1 artifact summaries as agent context."""
    sections: list[str] = []

    if store.exists("INFRA_MAP"):
        infra = store.read("INFRA_MAP")
        hosts = infra.get("hosts", [])
        total_ports = infra.get("total_open_ports", 0)
        sections.append(
            f"**INFRA_MAP:** {len(hosts)} host(s), {total_ports} open port(s)."
        )
        for host in hosts[:5]:
            ports_str = ", ".join(
                f"{p.get('port', '?')}/{p.get('service', '?')}"
                for p in host.get("ports", [])[:10]
            )
            sections.append(f"  - {host.get('hostname', '?')}: {ports_str}")

    if store.exists("TECH_STACK"):
        tech = store.read("TECH_STACK")
        techs = tech.get("technologies", [])
        servers = tech.get("servers", [])
        if techs:
            sections.append(f"**TECH_STACK:** {', '.join(techs[:15])}")
        if servers:
            sections.append(f"**Servers:** {', '.join(servers[:10])}")

    if store.exists("SEMGREP_RAW"):
        semgrep = store.read("SEMGREP_RAW")
        results = semgrep.get("results", [])
        sections.append(
            f"**SEMGREP_RAW:** {len(results)} finding(s). "
            "Full JSON at `{artifact_dir}/SEMGREP_RAW.json` — read to identify "
            "vulnerable file:line locations and correlate with route files."
        )

    preflight_ctx = format_preflight_context(store)
    if preflight_ctx:
        sections.append(preflight_ctx)

    if not sections:
        return "**No Phase 1 artifacts found.** Proceed with source-first blind recon."

    return "\n\n".join(sections)


# ─── Prompts ──────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are the **Phase 2 Recon Agent** in Adversa, a whitebox AI-powered \
penetration testing pipeline.

**Pipeline context:**
- Phase 0 (complete): Preflight — languages, frameworks, scope manifest.
- Phase 1 (complete): Pre-recon — SEMGREP_RAW, SBOM, INFRA_MAP, TECH_STACK, JOERN_CPG_PATH.
- **Phase 2 (YOU): Whitebox recon — produce a comprehensive attack surface map.**
- Phase 3 (next): Six parallel agents read your `recon_deliverable.md` to guide testing:
  - Injection agent, AuthZ agent, Info Disclosure agent, SSRF agent,
    SAST Triage agent, SCA Reachability agent.

**PRIMARY METHOD: Source code reading, NOT browser crawling.**

The fastest and most complete way to discover endpoints is to read the source.
A `Read` call takes milliseconds. A browser navigation takes seconds and may miss
server-side routes entirely. Follow this order:

1. Find the application entry point (`server.ts`, `app.py`, `main.py`, `app.js`, etc.)
2. Read route registration files (`routes/`, `controllers/`, `views/`, `api/`)
3. Read auth middleware (`lib/insecurity.ts`, `middleware/auth.py`, guards, etc.)
4. Read model files for data shapes and ID field names
5. Check `swagger.json` / `openapi.json` / `/api-docs` if they exist
6. Run **Katana** to discover live endpoints, SPA routes, and XHR calls the source
   doesn't show — see Step 2 item 7 in the user prompt for exact commands
7. Use the browser only for: (a) executing form-based login flows, (b) confirming
   specific SPA routes that Katana did not reach

**Available tools:**
- `Read`, `Glob`, `Grep` — source code reading (primary method)
- `Bash` — run katana, curl probes, write artifacts
- `katana` — fast web crawler: standard + headless (Angular/SPA) modes,
  JS crawling, XHR extraction, authenticated crawling via -H flag
- Playwright browser tools — form-based auth flows only

**Hard rules:**
- Write `{artifact_dir}/recon_deliverable.md` incrementally — start writing early,
  append sections as you complete them. Do NOT wait until the end.
- Write `{artifact_dir}/AUTH_SESSION.json` immediately after authentication.
- Never modify source code.
- Respect scope rules — `can_use_tool` blocks out-of-scope URLs automatically.
- Rate limit: {rate_limit_rps} rps for any live probing.
"""

_USER_PROMPT = """\
Run Phase 2 whitebox recon on the target.

**Artifact directory:** `{artifact_dir}`
```
mkdir -p {artifact_dir}
```

**Configuration:**
- **Repository:** {repo_path}
- **Target URL:** {base_url}
- **Target Hosts:** {included_hosts}
- **Rate Limit:** {rate_limit_rps} rps

---

## Phase 1 Context

{phase1_context}

{scope_rules}\
---

## Step 1: Authentication → `{artifact_dir}/AUTH_SESSION.json`

{login_flow}

Write immediately after auth:
```json
{{
  "success": true,
  "login_type": "{login_type}",
  "cookies": {{"token": "..."}},
  "headers": {{"Authorization": "Bearer ..."}},
  "error": null
}}
```

---

## Step 2: Source-Driven Endpoint Discovery

**Start here — do NOT start with the browser.**

1. Find the server entry point:
   ```
   find {repo_path} -maxdepth 2 -name "server.ts" -o -name "app.py" \
     -o -name "main.py" -o -name "app.js" -o -name "index.ts" | head -5
   ```

2. Read the entry point to find route registration patterns and middleware.

3. Glob all route/controller files:
   ```
   # Examples — adapt to the detected framework:
   find {repo_path}/routes -type f | head -50
   find {repo_path}/controllers -type f | head -50
   find {repo_path}/api -type f | head -50
   ```

4. Read each route file and extract:
   - HTTP method + path pattern
   - Auth guards / middleware applied
   - Path/query/body parameters
   - Which role/permission is required
   - Object ID parameters (numeric IDs, UUIDs in paths)

5. Read auth middleware to understand the role model:
   - What roles exist? What do the guards check?
   - How is the JWT/session structured?

6. Probe for auto-generated docs:
   ```
   curl -s {base_url}/swagger.json | head -100
   curl -s {base_url}/api-docs | head -100
   curl -s {base_url}/openapi.json | head -100
   ```

7. **Katana crawl** — run AFTER source reading, to discover live endpoints, SPA
   routes, and XHR calls the source doesn't show:

   ```bash
   # Standard crawl (fast, catches all static + JS-referenced endpoints)
   katana -u {base_url} -d {max_depth} -jc -kf all -silent -j \
     -o {artifact_dir}/katana_endpoints.jsonl 2>/dev/null

   # Headless crawl (Angular SPA routes + XHR calls)
   katana -u {base_url} -d {max_depth} -hl -system-chrome -nos \
     -jc -xhr -fx -silent -j \
     -o {artifact_dir}/katana_headless.jsonl 2>/dev/null
   ```

   If AUTH_SESSION.json has cookies or headers, add a third authenticated pass:
   ```bash
   # Authenticated crawl (discovers auth-gated endpoints)
   katana -u {base_url} -d {max_depth} -hl -system-chrome -nos \
     -jc -xhr -silent -j \
     -H "Authorization: Bearer <token_from_auth_session>" \
     -o {artifact_dir}/katana_auth.jsonl 2>/dev/null
   ```

   Parse the JSONL output and merge discovered paths into your endpoint table,
   adding any routes not already found in source.

---

## Step 3: Write `{artifact_dir}/recon_deliverable.md`

Produce a deliverable matching this structure (adapt depth to what you find):

```markdown
# Reconnaissance Deliverable: {project_name}

## 0) How to Read This
[Guide for downstream Phase 3 agents — which sections are most relevant to each agent]

## 1. Executive Summary
[App purpose, tech stack headline, key security observations, total endpoints found]

## 2. Tech Stack
[Languages, frameworks, DB, auth mechanism, notable libraries]

## 3. Authentication Architecture
[Login flow, JWT/session structure, token storage, how auth is verified per-request]

## 4. API Endpoint Inventory

| Path | Method | Auth Required | Required Role | Object-ID Params | Notes |
|------|--------|--------------|---------------|-----------------|-------|
| /api/users/:id | GET | Yes | customer | :id (numeric) | Returns user by ID |
...

## 5. Input Vector Summary
[URL params count, POST body fields count, headers, file uploads, WebSocket events]

## 6. Network & Interaction Map
[Services, datastores, external dependencies, data sensitivity zones]

## 7. Role & Privilege Architecture
[Role hierarchy, privilege lattice, what each role can access, where roles are enforced]

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation (IDOR)
[Endpoints with object IDs where another user's data may be accessible]

### 8.2 Vertical Privilege Escalation
[Endpoints reachable by lower roles that should require higher roles]

### 8.3 Context-Based Bypasses
[Workflow bypasses, state-dependent auth]

## 9. Injection & Other Vulnerability Sources
[For each source: endpoint, parameter, file:line, data flow, example payload]

### 9.1 SQL Injection
### 9.2 NoSQL Injection
### 9.3 SSRF
### 9.4 Path Traversal / LFI
### 9.5 XSS (Stored / Reflected)
### 9.6 Command / Code Injection
### 9.7 File Upload Vulnerabilities
```

Write sections incrementally as you gather data. The deliverable is the primary
artifact — make it as comprehensive as Shannon's output above.

---

## Final Step

Verify both artifacts exist:
```
ls -la {artifact_dir}/recon_deliverable.md {artifact_dir}/AUTH_SESSION.json
```

Do NOT return raw data inline. Your final message should be a one-paragraph
summary of what you found (endpoint count, key vulnerability categories, any gaps).
"""


# ─── Entry point ──────────────────────────────────────────────────────────────


async def run_recon(config: AdversaConfig, store: ArtifactStore) -> dict[str, Any]:
    """
    Run the whitebox recon agent.

    The agent writes recon_deliverable.md and AUTH_SESSION.json directly to the
    artifact directory via Bash. No structured output — success is determined by
    whether the markdown deliverable was written.

    Returns a status dict for the Temporal activity.
    """
    artifact_dir = str(store._dir)

    login_flow = _format_login_flow(config)
    phase1_context = _format_phase1_context(store)
    scope_rules = format_scope_rules(config)

    prompt = _USER_PROMPT.format(
        artifact_dir=artifact_dir,
        repo_path=config.repo.path,
        base_url=config.target.base_url,
        included_hosts=", ".join(config.target.included_hosts),
        rate_limit_rps=config.scope.rate_limit_rps,
        max_depth=config.scope.max_depth,
        login_type=config.authentication.login_type,
        login_flow=login_flow,
        phase1_context=phase1_context,
        scope_rules=scope_rules,
        project_name=config.meta.project,
    )

    system_prompt = _SYSTEM_PROMPT.format(
        artifact_dir=artifact_dir,
        rate_limit_rps=config.scope.rate_limit_rps,
    )

    audit = AuditLogger(f"{artifact_dir}/audit.jsonl")

    options = ClaudeAgentOptions(
        model=config.llm.model_name,
        system_prompt=system_prompt,
        allowed_tools=_ALLOWED_TOOLS,
        max_turns=70,                         
        mcp_servers={"playwright": _build_playwright_mcp()},
        can_use_tool=build_can_use_tool(config, audit),
        cwd="/app" if is_docker() else ".",
        env=build_agent_env(config),
        permission_mode="bypassPermissions",
        # No output_format — agent writes markdown directly, no structured output
    )

    logger.info(
        "Starting recon agent (model=%s, target=%s)",
        config.llm.model_name,
        config.target.base_url,
    )

    result = await run_agent(options=options, prompt=prompt, config=config)

    _verify_artifacts(store)

    markdown_path = Path(artifact_dir) / RECON_DELIVERABLE
    if markdown_path.exists() and markdown_path.stat().st_size > 0:
        logger.info("Recon agent complete — deliverable: %s bytes", markdown_path.stat().st_size)
        return {
            "markdown_written": True,
            "markdown_path": str(markdown_path),
            "error": result.get("error"),
        }

    error = result.get("error") or "Agent did not write recon_deliverable.md"
    logger.error("Recon agent failed: %s", error)
    return {"markdown_written": False, "markdown_path": None, "error": error}


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _verify_artifacts(store: ArtifactStore) -> None:
    """Log warnings for missing artifacts."""
    artifact_dir = Path(store._dir)

    markdown = artifact_dir / RECON_DELIVERABLE
    if not markdown.exists():
        logger.warning("Recon agent did not write %s", RECON_DELIVERABLE)

    if not store.exists("AUTH_SESSION"):
        logger.warning("Recon agent did not write artifact: AUTH_SESSION")


def _fallback_output(error: str) -> dict:
    """Minimal status dict on total agent failure."""
    return {"markdown_written": False, "markdown_path": None, "error": error}
