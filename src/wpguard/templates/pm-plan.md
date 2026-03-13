# Research Plan — {plugin_slug}

## Target Info
- **Plugin:** {plugin_slug}
- **Version:** {version}
- **Active Installs:** {active_installs}
- **Source:** targets/{plugin_slug}/extracted/
- **Started:** {date}

## Pre-Research
- [ ] Plugin downloaded and extracted to targets/
- [ ] Scope check passed (`wpguard_scope_check_plugin`)
- [ ] CVE history reviewed (`wpguard_cve_search`)
- [ ] Sandbox prepared (`sandbox-admin` — plugin installed, users reset)

## Expert Analysis
- [ ] `file-rce-expert` — File upload/read/write/delete, RCE
- [ ] `sqli-expert` — SQL injection
- [ ] `xss-expert` — Stored/Reflected/DOM XSS
- [ ] `missing-auth-expert` — Missing capability checks on endpoints
- [ ] `idor-expert` — IDOR, object-level access control
- [ ] `priv-esc-expert` — Privilege escalation, options update, auth bypass
- [ ] `object-injection-expert` — PHP object injection
- [ ] `ssrf-expert` — SSRF
- [ ] `race-condition-expert` — Race conditions
- [ ] `csrf-expert` — CSRF
- [ ] `lfi-rfi-expert` — LFI/RFI
- [ ] `xxe-expert` — XXE
- [ ] `deserialization-expert` — Deserialization
- [ ] `logic-flaw-expert` — Business logic
- [ ] `info-disclosure-expert` — Info disclosure
- [ ] `code-injection-expert` — eval, call_user_func, dynamic dispatch
- [ ] `open-redirect-expert` — wp_redirect, header Location, JS redirects
- [ ] `critical-thinker` — Cross-domain chains, second-order bugs, subtle logic flaws

### Expert Results
| Expert | Findings | Status |
|--------|----------|--------|
| file-rce-expert | — | pending |
| sqli-expert | — | pending |
| xss-expert | — | pending |
| missing-auth-expert | — | pending |
| idor-expert | — | pending |
| priv-esc-expert | — | pending |
| object-injection-expert | — | pending |
| ssrf-expert | — | pending |
| race-condition-expert | — | pending |
| csrf-expert | — | pending |
| lfi-rfi-expert | — | pending |
| xxe-expert | — | pending |
| deserialization-expert | — | pending |
| logic-flaw-expert | — | pending |
| info-disclosure-expert | — | pending |
| code-injection-expert | — | pending |
| open-redirect-expert | — | pending |
| critical-thinker | — | pending |

## Verification Pipeline
For each finding from experts:

### Finding: {finding_title}
- [ ] `poc-writer` — PoC script created
  - PoC path: reports/{plugin_slug}/poc_xxx.py
  - Expected result: {description}
  - Sanity test: pass/fail
- [ ] `poc-runner` — PoC verified against sandbox
  - Verdict: CONFIRMED / FALSE POSITIVE / INCONCLUSIVE
  - Browser verification: YES/NO/N/A
  - False positive checks passed: YES/NO
- [ ] `qa-triage` — Final validation
  - Scope check: pass/fail
  - CVSS: {score}
  - Auth level verified (tested bottom-up): {level}
  - Writeup: reports/{plugin_slug}/{vuln_type}_{id}.md
  - Discord notified: YES/NO

## Summary
- [ ] All experts completed
- [ ] All findings through verification pipeline
- [ ] All confirmed findings have writeups in reports/
- [ ] Engagement summary created (SUMMARY_{plugin_slug}.md)
- [ ] Discord summary sent
- [ ] Sandbox cleaned up

## Stats
- Total findings from experts: 0
- Confirmed after PoC verification: 0
- False positives caught: 0
- Final validated for submission: 0
