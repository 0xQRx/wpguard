# WordPressGuard Security Research Project

Wordfence Bug Bounty Program research project — supports both **plugins** and **themes**. Use `/pm` to start.

## Commands

- `/pm` - PM orchestrator — coordinates all research, delegates to agents
- `/target-research` - Find and scope WordPress plugins for analysis
- `/status` - Quick dashboard of current audit progress
- `/recon` - Lightweight plugin assessment before full audit (installs, CVE history, scope)
- `/findings` - List all findings with status and severity
- `/nday` - N-day research shortcut — PoCs for known/patched CVEs
- `/watch` - Plugin update monitor — global ecosystem scan + watchlist changes
- `/diff` - Security-focused version diff — analyze code changes between versions
- `/patrol` - Lightweight watchdog — checks audit progress, re-triggers stalls, picks next target (for cron loops)

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
| `data-flow-expert` | Cross-feature data flows — writes in one feature consumed unsafely by another |
| `protocol-confusion-expert` | Dispatch/validation desync — validation vs. dispatch mismatch, nesting bypass of allow-lists, schema params reinterpreted into sinks (REST batch route confusion). Always included for core research. |
| `lfi-rfi-expert` | LFI/RFI, path traversal |
| `xxe-expert` | XXE, SVG/XML processing |
| `deserialization-expert` | Unsafe deserialization, type juggling |
| `logic-flaw-expert` | Business logic, payment bypass |
| `info-disclosure-expert` | Data exposure, debug endpoints |
| `code-injection-expert` | eval, call_user_func, dynamic dispatch, callback injection |
| `open-redirect-expert` | wp_redirect, header Location, JavaScript redirects |

### Verification Pipeline (ALL steps mandatory — no finding skips any)
```
Expert finds vuln → Impact Assessor → PoC Writer → PoC Runner → QA Triage → BB Submission
```
| Agent | Role |
|-------|------|
| `impact-assessor` | **RUNS FIRST** — reviews raw findings, kills obscure impact before PoCs are written |
| `poc-writer` | Writes PoC scripts for findings that survived impact gate |
| `poc-runner` | Executes PoCs, verifies results, catches false positives (has Playwright) |
| `qa-triage` | Final validation, scope check, CVSS, writeups, Discord notifications |
| `bb-submission` | **MANDATORY** — submission prep, clean sandbox repro, Wordfence format |

### Utility
| Agent | Role |
|-------|------|
| `poc-recorder` | Records terminal (asciinema) and browser (Playwright) PoC videos on demand |
| `poc-creator` | n-day research — changelog/CVE analysis, PoCs for patched vulns |
| `sandbox-admin` | Sandbox maintenance — plugin install, user reset, DB cleanup (on-demand) |
| `surface-mapper` | Fast attack surface recon — counts endpoints, dangerous functions, auth gaps |
| `vuln-escalator` | Post-expert escalation — tests lower auth levels, expands impact, chains findings |
| `dynamic-tracer` | Runtime data-flow verifier — proves a write/forge/deserialize/priv-change against ground truth (sink tracer → DB re-read → Xdebug CLI probe). Owns the deep-tracing tooling; any agent delegates focused verification to it. |

## MCP Servers

| Server | Purpose |
|--------|---------|
| `wpguard` | Core tools — downloads, CVE lookup, sandbox, findings, scope checks (60+ tools). Includes `wpguard_sink_trace`, the runtime data-flow oracle (SQL/option/user/meta/HTTP/mail writes + backtrace, plus Xdebug internal-function trace) — use it to confirm any write/forge/priv-change against ground truth. |
| `playwright` | Browser automation for poc-runner / bb-submission video evidence |
| `devrag` | Local web-pentest knowledge base (semantic doc search) |
| `veloria` | WordPress-wide regex code search — indexes every plugin/theme/core on wordpress.org. Use for variant hunting and pattern-based target discovery in `/target-research` and `/nday`. Queries are private by default. |

## Directory Structure

```
targets/{slug}/extracted/          — Plugin or theme source code
reports/{slug}/                    — All audit artifacts
  PLAN.md                          — Audit plan and progress tracking
  SUMMARY.md                       — Engagement summary
  surface_map.md                   — Attack surface report
  progress_{agent}.md              — Expert progress reports
  {finding_id}/                    — Per-finding directory
    poc.py                         — PoC script
    writeup.md                     — Vulnerability writeup
wpguard_findings.json              — Findings database
```

## Environment

- Sandbox: `172.17.0.1:8000` (Docker: wp_app)
- Test users: subscriber/subscriber, contributor/contributor, author/author
- Editor and Administrator are OUT OF SCOPE for the attacker role
- Author IS IN SCOPE — author-level RCE, file upload, SQLi etc. are all bounty-eligible
- **Addon dependencies:** surface-mapper detects base plugin requirements (WooCommerce, Elementor, etc.) during recon. PM delegates ecosystem setup to sandbox-admin BEFORE launching experts.
- **Ecosystem-specific roles:** `customer` (WooCommerce), BuddyPress members, etc. are created during ecosystem setup and should be tested by experts as additional auth levels.

## Scope Quick Reference

| Min Installs | Vulnerability Types | Max Auth Level |
|--------------|---------------------|----------------|
| 25 | RCE, File Upload/Read/Delete, Options Update, Auth Bypass, Priv Esc | Author |
| 500 | SQL Injection, Stored XSS | Author |
| 50,000 | Reflected XSS*, CSRF*, Missing Auth, IDOR, SSRF, Object Injection | Author (Reflected XSS/CSRF: unauthenticated*) |

*Reflected XSS and CSRF are always `auth_level="unauthenticated"` — attacker crafts payload locally, victim executes it.

### Out of Scope (Common Traps)
Open Redirect, Self-XSS, Username Enumeration, SSRF via DNS Rebinding, Missing Headers,
Clickjacking, CSV Injection, CAPTCHA Bypass, CORS, Full Path Disclosure, Tabnabbing,
non-replicable Race Conditions, CSRF without impact, DoS without impact, CVSS < 4.0.
See QA Triage for complete list. Editor/Admin/Shop Manager = always OOS (PR:H).

**Author-level bugs are HIGH VALUE.** Authors can upload media, publish posts, and access post editor features. Bugs exploitable at Author level include:
- RCE via media upload (SVG, image processing, EXIF)
- File read/delete via attachment handling
- SQL injection via post meta, custom fields, shortcode attributes
- Stored XSS via post content rendered to other users
- Object injection via metadata
- SSRF via embed/oEmbed processing

## WordPress Core Research

The system also researches **WordPress core** (target slug `core-{version}`, source at
`targets/core-{version}/extracted/`) alongside plugins and themes. Core breaks the plugin
assumptions, so it runs a parallel flow — see the PM's **Core Research Mode**:

- **Scope by subsystem, not install count.** Core has no active-install tiers. Instead of a
  `surface_map.md`, scope analysis to `core-subsystems.md` (in the project root) — a catalog of
  high-value core surfaces (REST + batch controller, `WP_Query`/`meta_query` SQL builders,
  shortcodes, `wp_kses`, XML-RPC, phar/deserialization, auth/nonce/cap, multisite, media). Never
  grep-map all of core. **Lead with the `/diff` of a security release** to narrow to the changed
  subsystem.
- **Core scope + submission.** Validate findings with `wpguard_core_scope_check` (no install tiers,
  core OOS list, `EXCLUDED_VENDORS` bypass, multisite super-admin auth model). Core findings are
  submitted to the **HackerOne "WordPress" program** (not Wordfence) with HackerOne format and core
  CVSS norms.
- **Sandbox pinned by version** via `wpguard_sandbox_set_core_version`; sandbox-only testing.
- **`protocol-confusion-expert` is always included for core** — it covers the REST batch
  route-confusion / dispatch-desync class that is core's signature bug.

## Rules

- **USE `/pm` TO START ALL RESEARCH** — the PM orchestrator creates a plan and delegates to expert agents. Do not skip `/pm` or run agents directly.
- **NEVER SKIP PHASES** — every phase in the PM plan must be fully completed. Do not skip experts, do not shortcut verification, do not mark phases done without running them.
- **PROVE code is vulnerable** — your job is to FIND vulnerabilities and PROVE they are exploitable. You are NOT here to confirm code is safe. Every agent must assume the plugin is vulnerable and exhaust all attack vectors before moving on.
- Previous CVEs mean incomplete fixes — check for bypasses
- **Test ALL auth levels** (unauth → subscriber → contributor → author) — do NOT stop at contributor. Author-level bugs are bounty-eligible for all vulnerability types.
- Do not give up on a component after surface-level analysis — dig deep, trace data flows, check all code paths

## ⚠️ REALISTIC EXPLOITATION ONLY — NO FABRICATION

**Every exploit must use a realistic attack flow that a real attacker could reproduce.** If you cannot exploit a vulnerability through a legitimate user flow, it is NOT exploitable — report it as a draft or move on.

### FORBIDDEN (these invalidate a finding):
- **Do NOT insert payloads directly into the database** — use HTTP requests through WordPress endpoints only
- **Do NOT create fake plugins/themes/mu-plugins** to extract nonces, bypass checks, or enable functionality
- **Do NOT use WP-CLI to set up preconditions** that a real attacker couldn't create (e.g., `wp option update`, `wp user meta update`)
- **Do NOT use sandbox admin access to store XSS payloads** — if the vuln requires Stored XSS, the payload must be storable through the plugin's own input fields at the claimed auth level
- **Do NOT fabricate nonces** — nonces must be obtainable through page source, AJAX responses, or REST API endpoints accessible at the attacker's auth level
- **Do NOT assume the attacker has prior access to admin pages** unless the vuln is specifically about admin-level issues

### REQUIRED for valid exploitation:
- **Attacker perspective only** — every step must be possible from the claimed auth level (unauthenticated, subscriber, contributor, etc.)
- **Nonces must be obtained legitimately** — from pages/endpoints the attacker's role can access. If a nonce is only on admin pages and the vuln claims subscriber-level, you must prove a subscriber can reach that page
- **Payload delivery through plugin endpoints** — XSS payloads go through the plugin's forms/AJAX/REST, not direct DB writes
- **Setup conditions must be realistic** — if exploitation requires a specific plugin setting, verify the default value or prove the attacker can change it
- **If you can't exploit it legitimately, say so** — create a draft finding explaining what you found in static analysis and why dynamic exploitation failed. Honest drafts are valuable; fabricated PoCs are harmful
