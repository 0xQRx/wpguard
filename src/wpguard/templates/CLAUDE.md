# WordPressGuard Security Research Project

Wordfence Bug Bounty Program research project. Use `/pm` to start.

## Commands

- `/pm` - PM orchestrator — coordinates all research, delegates to agents
- `/target-research` - Find and scope WordPress plugins for analysis

## Agents

Delegated by `/pm` — not invoked directly.

### Vulnerability Experts
| Agent | Focus |
|-------|-------|
| `file-rce-expert` | File upload/read/write/delete, path traversal, RCE |
| `sqli-expert` | SQL injection (UNION, blind, second-order) |
| `xss-expert` | Stored, reflected, DOM XSS |
| `missing-auth-expert` | Missing capability checks on AJAX/REST/admin endpoints |
| `idor-expert` | Insecure Direct Object Reference, object-level access control |
| `priv-esc-expert` | Privilege escalation, options update chains, role manipulation, auth bypass |
| `object-injection-expert` | PHP object injection, phar deserialization |
| `ssrf-expert` | SSRF, cloud metadata |
| `race-condition-expert` | TOCTOU, database races, limit bypass |
| `csrf-expert` | CSRF, missing nonce validation |
| `critical-thinker` | Cross-domain chains, second-order bugs, logic flaws, subtle multi-step vulns |
| `lfi-rfi-expert` | LFI/RFI, path traversal |
| `xxe-expert` | XXE, SVG/XML processing |
| `deserialization-expert` | Unsafe deserialization, type juggling |
| `logic-flaw-expert` | Business logic, payment bypass |
| `info-disclosure-expert` | Data exposure, debug endpoints |
| `code-injection-expert` | eval, call_user_func, dynamic dispatch, callback injection |
| `open-redirect-expert` | wp_redirect, header Location, JavaScript redirects |

### Verification Pipeline
```
Expert finds vuln → PoC Writer → PoC Runner → QA Triage
```
| Agent | Role |
|-------|------|
| `poc-writer` | Writes PoC scripts with declared expected results |
| `poc-runner` | Executes PoCs, verifies results, catches false positives (has Playwright) |
| `qa-triage` | Final validation, scope check, CVSS, writeups, Discord notifications |

### Utility
| Agent | Role |
|-------|------|
| `poc-creator` | n-day research — changelog/CVE analysis, PoCs for patched vulns |
| `sandbox-admin` | Sandbox maintenance — plugin install, user reset, DB cleanup (on-demand) |

## Directory Structure

```
targets/{plugin_slug}/extracted/   — Plugin source code
reports/{plugin_slug}/             — Findings, writeups, PoC scripts
wpguard_findings.json              — Findings database
```

## Environment

- Sandbox: `172.17.0.1:8000` (Docker: wp_app)
- Test users: subscriber/subscriber, contributor/contributor, author/author
- Editor and Administrator are OUT OF SCOPE

## Scope Quick Reference

| Min Installs | Vulnerability Types |
|--------------|---------------------|
| 25 | RCE, File Upload/Read/Delete, Options Update, Auth Bypass, Priv Esc |
| 500 | SQL Injection, Stored XSS |
| 50,000 | Reflected XSS*, CSRF*, Missing Auth, IDOR, SSRF, Object Injection |

*Reflected XSS and CSRF are always `auth_level="unauthenticated"` — attacker crafts payload locally, victim executes it.

## Rules

- **USE `/pm` TO START ALL RESEARCH** — the PM orchestrator creates a plan and delegates to expert agents. Do not skip `/pm` or run agents directly.
- **NEVER SKIP PHASES** — every phase in the PM plan must be fully completed. Do not skip experts, do not shortcut verification, do not mark phases done without running them.
- **PROVE code is vulnerable** — your job is to FIND vulnerabilities and PROVE they are exploitable. You are NOT here to confirm code is safe. Every agent must assume the plugin is vulnerable and exhaust all attack vectors before moving on.
- Previous CVEs mean incomplete fixes — check for bypasses
- Test ALL auth levels (unauth → subscriber → contributor → author)
- No agent may manipulate the database to fake results
- Do not give up on a component after surface-level analysis — dig deep, trace data flows, check all code paths
