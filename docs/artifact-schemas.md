# Adversa — Artifact Schemas

> All inter-phase communication passes through typed artifacts. Agents write via `save_deliverable`. No direct agent-to-agent calls.

---

## Artifact Registry

| Artifact | Phase | Edition | Format | Description |
|---|---|---|---|---|
| `PREFLIGHT_RESULT` | 0 | Both | JSON | Preflight check results |
| `SCOPE_MANIFEST` | 0 | Both | JSON | Serialised scope enforcer |
| `TOOL_MANIFEST` | 0 | Both | JSON | Available tools in container |
| `CODE_ANALYSIS` | 1 | Both | JSON | Endpoints, tech stack, infra |
| `SBOM` | 1 | Both | CycloneDX JSON | Software Bill of Materials |
| `SEMGREP_RAW` | 1 | Both | JSON | Raw Semgrep findings |
| `JOERN_CPG_PATH` | 1 | Both | string | Path to built Joern CPG |
| `INFRA_MAP` | 1 | Both | JSON | Ports, subdomains, services |
| `TECH_STACK` | 1 | Both | JSON | Language, framework, DB |
| `RECON_MAP` | 2 | Both | JSON | Live endpoint inventory |
| `AUTH_SESSION` | 2 | Both | JSON | Session tokens / cookies |
| `ENDPOINT_INVENTORY` | 2 | Both | JSON | Full endpoint list |
| `ATTACK_SURFACE_SUMMARY` | 2 | Both | Markdown | Human-readable surface map |
| `INJECTION_QUEUE` | 3a | Both | JSON | Injection hypotheses |
| `AUTHZ_QUEUE` | 3b | Both | JSON | Auth / IDOR hypotheses |
| `INFO_DISCLOSURE_QUEUE` | 3c | Both | JSON | Info disclosure hypotheses |
| `SSRF_QUEUE` | 3d | Both | JSON | SSRF hypotheses |
| `SAST_CONFIRMED_QUEUE` | 3e | Both | JSON | Triaged SAST findings |
| `SCA_REACHABILITY_REPORT` | 3f | Both | JSON | CVEs with reachability verdict |
| `INJECTION_EVIDENCE` | 4 | Pro only | JSON | Confirmed injection PoCs |
| `AUTHZ_EVIDENCE` | 4 | Pro only | JSON | Confirmed auth / IDOR PoCs |
| `INFO_DISCLOSURE_EVIDENCE` | 4 | Pro only | JSON | Confirmed disclosure PoCs |
| `SSRF_EVIDENCE` | 4 | Pro only | JSON | Confirmed SSRF PoCs |
| `SAST_EVIDENCE` | 4 | Pro only | JSON | Confirmed SAST PoCs |
| `FALSE_POSITIVES` | 4 | Pro only | JSON | Discarded hypotheses |
| `findings_report.html` | 5a | OSS | HTML | Developer findings report |
| `findings.json` | 5a/5b | Both | JSON | Machine-readable findings |
| `pentest_report.html` | 5b | Pro | HTML | Audit-ready pentest report |
| `pentest_report.pdf` | 5b | Pro | PDF | Signed PDF for auditors |
| `session_metrics.json` | 5 | Both | JSON | Cost, time, turn counts |

---

## Phase 0 Schemas

### PREFLIGHT_RESULT

```json
{
  "status": "pass | fail",
  "checks": [
    {
      "name": "config_valid",
      "status": "pass | fail",
      "detail": "string"
    },
    {
      "name": "target_reachable",
      "status": "pass | fail",
      "detail": "HTTP 200 from HEAD https://api.client.com"
    },
    {
      "name": "repo_readable",
      "status": "pass | fail",
      "detail": "string"
    },
    {
      "name": "tools_installed",
      "status": "pass | fail",
      "missing": []
    },
    {
      "name": "api_key_valid",
      "status": "pass | fail",
      "detail": "string"
    }
  ],
  "errors": ["string"]
}
```

### SCOPE_MANIFEST

```json
{
  "included_hosts": ["api.client.com"],
  "excluded_hosts": ["prod.client.com"],
  "avoid_paths": ["/health", "/logout"],
  "avoid_path_patterns": ["/admin/*"],
  "focus_path_patterns": ["/api/*"],
  "max_depth": 3,
  "rate_limit_rps": 10,
  "generated_at": "2026-03-14T10:00:00Z"
}
```

### TOOL_MANIFEST

```json
{
  "available": ["semgrep", "trivy", "joern", "nmap", "subfinder", "httpx", "nuclei", "playwright"],
  "missing": [],
  "versions": {
    "semgrep": "1.x",
    "trivy": "0.x",
    "joern": "2.x"
  }
}
```

---

## Phase 1 Schemas

### CODE_ANALYSIS

```json
{
  "endpoints": [
    {
      "path": "/api/users/search",
      "method": "GET",
      "source_file": "routes/users.py",
      "line": 45,
      "auth_required": true,
      "parameters": ["q", "page", "limit"]
    }
  ],
  "tech_stack": {
    "language": "python",
    "framework": "fastapi",
    "database": "postgresql",
    "orm": "sqlalchemy"
  },
  "openapi_spec": null
}
```

### INFRA_MAP

```json
{
  "hosts": [
    {
      "host": "api.client.com",
      "ip": "1.2.3.4",
      "open_ports": [80, 443],
      "services": {"443": "https"},
      "subdomains": ["api.client.com", "staging.client.com"]
    }
  ],
  "whatweb": {
    "server": "nginx/1.24",
    "technologies": ["Python", "FastAPI"]
  }
}
```

### TECH_STACK

```json
{
  "language": "python",
  "version": "3.11",
  "framework": "fastapi",
  "database": "postgresql",
  "orm": "sqlalchemy",
  "auth": "jwt",
  "dependencies_count": 42
}
```

### SEMGREP_RAW

```json
{
  "version": "1.x",
  "results": [
    {
      "check_id": "python.lang.security.audit.formatted-sql-query",
      "path": "routes/users.py",
      "start": {"line": 87, "col": 4},
      "end": {"line": 87, "col": 52},
      "extra": {
        "message": "Possible SQL injection via string formatting",
        "severity": "ERROR",
        "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]}
      }
    }
  ],
  "stats": {"total": 12, "by_severity": {"ERROR": 3, "WARNING": 9}}
}
```

### JOERN_CPG_PATH

```json
{
  "path": "/tmp/adversa/engagements/adv-2026-001/cpg",
  "built_at": "2026-03-14T10:05:00Z",
  "repo_path": "/repos/client-app",
  "language": "python",
  "build_duration_seconds": 45
}
```

### SBOM

Standard CycloneDX JSON format. Key fields used by Phase 3f:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "name": "sqlalchemy",
      "version": "1.4.0",
      "purl": "pkg:pypi/sqlalchemy@1.4.0"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-XXXX",
      "affects": [{"ref": "pkg:pypi/sqlalchemy@1.4.0"}],
      "ratings": [{"severity": "high", "score": 8.1}]
    }
  ]
}
```

---

## Phase 2 Schemas

### RECON_MAP

```json
{
  "generated_at": "2026-03-14T10:10:00Z",
  "base_url": "https://api.client.com",
  "endpoints": [
    {
      "path": "/api/users/{id}",
      "method": "GET",
      "auth_required": true,
      "source_file": "routes/users.py",
      "line": 23,
      "parameters": ["id"],
      "flags": ["user_controlled_id", "elevated_privilege"]
    }
  ],
  "shadow_endpoints": [
    {
      "path": "/api/internal/admin",
      "method": "GET",
      "note": "Not in OpenAPI spec, discovered via crawl"
    }
  ]
}
```

### AUTH_SESSION

```json
{
  "type": "jwt | cookie | apikey",
  "token": "eyJ...",
  "cookies": {"session": "abc123"},
  "headers": {"Authorization": "Bearer eyJ..."},
  "expires_at": "2026-03-14T12:00:00Z",
  "user_role": "standard_user",
  "login_url": "https://api.client.com/login"
}
```

### ENDPOINT_INVENTORY

```json
{
  "total": 47,
  "authenticated": 38,
  "unauthenticated": 9,
  "endpoints": [
    {
      "path": "/api/users/{id}",
      "method": "GET",
      "auth_required": true,
      "content_type": "application/json",
      "response_fields": ["id", "email", "role", "created_at"]
    }
  ]
}
```

---

## Phase 3 Queue Schemas

All Phase 3 queues share the same envelope:

```json
{
  "queue_type": "INJECTION_QUEUE | AUTHZ_QUEUE | INFO_DISCLOSURE_QUEUE | SSRF_QUEUE | SAST_CONFIRMED_QUEUE",
  "stride_category": "Tampering | Spoofing | Information Disclosure | Elevation of Privilege | SSRF",
  "generated_at": "2026-03-14T10:15:00Z",
  "agent": "injection_agent | authz_agent | ...",
  "status": "complete | partial",
  "items": []
}
```

### INJECTION_QUEUE items

```json
{
  "id": "inj-001",
  "vulnerability_class": "SQL Injection",
  "owasp_top10": "A03:2021 - Injection",
  "owasp_api_top10": null,
  "cwe": "CWE-89",
  "severity": "critical | high | medium | low | informational",
  "endpoint": "/api/users/search",
  "method": "GET",
  "parameter": "q",
  "source_file": "routes/users.py",
  "line": 87,
  "sink_type": "sql_query | shell_exec | template_render | xml_parse",
  "taint_path": [
    "q (HTTP param) → search_term (line 82) → cursor.execute() (line 87)"
  ],
  "evidence": "Joern taint path confirmed. Semgrep rule also triggered.",
  "confidence": "high | medium | low"
}
```

### AUTHZ_QUEUE items

```json
{
  "id": "authz-001",
  "vulnerability_class": "IDOR | Broken JWT | Missing Role Check | Privilege Escalation",
  "owasp_top10": "A01:2021 - Broken Access Control",
  "owasp_api_top10": "API1:2023 - BOLA",
  "cwe": "CWE-639",
  "severity": "high",
  "endpoint": "/api/users/{id}",
  "method": "GET",
  "parameter": "id",
  "source_file": "routes/users.py",
  "line": 23,
  "hypothesis": "User ID in path parameter not validated against authenticated user — potential IDOR",
  "evidence": "No ownership check found in handler. Joern shows direct DB query by path param.",
  "confidence": "high"
}
```

### INFO_DISCLOSURE_QUEUE items

```json
{
  "id": "info-001",
  "vulnerability_class": "Excessive Data Exposure | Verbose Error | Debug Endpoint | Path Traversal",
  "owasp_top10": "A01:2021 - Broken Access Control",
  "owasp_api_top10": "API3:2023 - Broken Object Property Level Authorization",
  "cwe": "CWE-200",
  "severity": "medium",
  "endpoint": "/api/users/{id}",
  "method": "GET",
  "source_file": "serializers/user.py",
  "line": 12,
  "hypothesis": "Response serialiser returns password_hash and internal_role fields",
  "evidence": "Semgrep finds no field exclusion in UserSerializer. Response schema includes sensitive fields.",
  "confidence": "medium"
}
```

### SSRF_QUEUE items

```json
{
  "id": "ssrf-001",
  "vulnerability_class": "SSRF",
  "owasp_top10": "A10:2021 - SSRF",
  "owasp_api_top10": "API7:2023 - SSRF",
  "cwe": "CWE-918",
  "severity": "high",
  "endpoint": "/api/webhooks",
  "method": "POST",
  "parameter": "callback_url",
  "source_file": "services/webhook.py",
  "line": 34,
  "sink_type": "http_client | file_read",
  "taint_path": [
    "callback_url (POST body) → url (line 30) → requests.get(url) (line 34)"
  ],
  "evidence": "Joern taint path confirmed. No URL validation found.",
  "confidence": "high"
}
```

### SAST_CONFIRMED_QUEUE items

```json
{
  "id": "sast-001",
  "semgrep_rule": "python.lang.security.audit.formatted-sql-query",
  "original_severity": "ERROR",
  "triaged_severity": "high",
  "owasp_top10": "A03:2021 - Injection",
  "cwe": "CWE-89",
  "source_file": "routes/users.py",
  "line": 87,
  "reachable": true,
  "reachability_reason": "Endpoint /api/users/search is authenticated and exposed. Handler calls vulnerable line directly.",
  "false_positive_reason": null,
  "confidence": "high"
}
```

### SCA_REACHABILITY_REPORT

```json
{
  "queue_type": "SCA_REACHABILITY_REPORT",
  "generated_at": "2026-03-14T10:20:00Z",
  "items": [
    {
      "cve_id": "CVE-2023-XXXX",
      "package": "sqlalchemy",
      "version": "1.4.0",
      "fix_version": "2.0.0",
      "cvss_score": 8.1,
      "severity": "high",
      "vulnerable_function": "sqlalchemy.orm.Session.execute",
      "reachable": true,
      "call_chain": [
        "routes/users.py:search_users() → db.execute() → sqlalchemy.orm.Session.execute()"
      ],
      "owasp_top10": "A06:2021 - Vulnerable and Outdated Components",
      "cwe": "CWE-89",
      "confidence": "high"
    }
  ]
}
```

---

## Phase 4 Evidence Schemas (Pro Only)

All evidence artifacts share the same envelope. Items extend the corresponding Phase 3 queue item with proof.

```json
{
  "artifact_type": "INJECTION_EVIDENCE | AUTHZ_EVIDENCE | INFO_DISCLOSURE_EVIDENCE | SSRF_EVIDENCE | SAST_EVIDENCE",
  "generated_at": "2026-03-14T10:30:00Z",
  "items": [
    {
      "hypothesis_id": "inj-001",
      "exploited": true,
      "poc_type": "http_request | playwright_script | curl",
      "poc": "curl -X GET 'https://api.client.com/api/users/search?q=1%27+OR+1%3D1--'",
      "request": {
        "method": "GET",
        "url": "https://api.client.com/api/users/search?q=1' OR 1=1--",
        "headers": {"Authorization": "Bearer eyJ..."}
      },
      "response": {
        "status": 200,
        "body_excerpt": "[{\"id\":1,\"email\":\"admin@client.com\"},{\"id\":2,...}]"
      },
      "screenshot_path": null,
      "exfiltrated_data_sample": "admin@client.com",
      "business_impact": "Full database table enumeration possible by any authenticated user.",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    }
  ]
}
```

### FALSE_POSITIVES

```json
{
  "artifact_type": "FALSE_POSITIVES",
  "generated_at": "2026-03-14T10:30:00Z",
  "items": [
    {
      "hypothesis_id": "inj-003",
      "queue_type": "INJECTION_QUEUE",
      "reason": "Parameterised query found at sink after reading route handler. Sanitisation is effective.",
      "attempts": 3
    }
  ]
}
```

---

## Phase 5 Output Schemas

### findings.json (Both Editions)

```json
{
  "engagement_id": "adv-2026-001",
  "project": "ClientName Pentest",
  "generated_at": "2026-03-14T10:45:00Z",
  "edition": "oss | pro",
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "informational": 1,
    "total": 12
  },
  "findings": [
    {
      "id": "finding-001",
      "title": "SQL Injection in /api/users/search",
      "severity": "critical",
      "owasp_top10": "A03:2021 - Injection",
      "owasp_api_top10": null,
      "cwe": "CWE-89",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "endpoint": "/api/users/search",
      "method": "GET",
      "parameter": "q",
      "source_file": "routes/users.py",
      "line": 87,
      "description": "string",
      "evidence": "string",
      "poc": "curl ...",
      "remediation": "string",
      "remediation_priority": "immediate | short-term | long-term",
      "confirmed": true
    }
  ]
}
```

### session_metrics.json

```json
{
  "engagement_id": "adv-2026-001",
  "started_at": "2026-03-14T10:00:00Z",
  "completed_at": "2026-03-14T10:45:00Z",
  "duration_seconds": 2700,
  "edition": "oss | pro",
  "phases": {
    "phase0": {"status": "complete", "duration_seconds": 10},
    "phase1": {"status": "complete", "duration_seconds": 120},
    "phase2": {"status": "complete", "duration_seconds": 300, "turns": 87},
    "phase3": {"status": "complete", "duration_seconds": 600, "turns_by_agent": {
      "injection": 245, "authz": 189, "info_disclosure": 112,
      "ssrf": 98, "sast_triage": 67, "sca_reachability": 45
    }},
    "phase5a": {"status": "complete", "duration_seconds": 180, "turns": 32}
  },
  "llm_cost_usd": {
    "phase2_novita": 0.12,
    "phase3_opus": 2.45,
    "phase3_sonnet": 1.18,
    "phase5_sonnet": 0.34,
    "total": 4.09
  },
  "scope_blocks": [
    {
      "timestamp": "2026-03-14T10:15:32Z",
      "agent": "injection_agent",
      "url": "https://api.client.com/health",
      "reason": "Path /health is in avoid list"
    }
  ],
  "findings_count": {"critical": 1, "high": 3, "medium": 5, "low": 2, "informational": 1}
}
```
