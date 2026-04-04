# Research Plan — {plugin_slug}

## Target Info
- **Plugin/Theme:** {slug}
- **Version:** {version}
- **Active Installs:** {active_installs}
- **Type:** plugin / theme
- **Source:** targets/{slug}/extracted/
- **Bounty Potential:** {bounty_range} (via `wpguard_bounty_estimate`)
- **Started:** {date}

## Pre-Research
- [ ] Audit history checked (`wpguard_audit_check`)
- [ ] Downloaded and extracted to targets/
- [ ] Scope check passed (`wpguard_scope_check_plugin`)
- [ ] Bounty estimated (`wpguard_bounty_estimate`)
- [ ] CVE history reviewed (`wpguard_cve_search`)
- [ ] Regression check (if updated version): (`wpguard_regression_check`)
- [ ] Sandbox destroyed and rebuilt
- [ ] Sandbox prepared (`sandbox-admin` — plugin installed, users reset)
- [ ] Attack surface mapped (`surface-mapper`) → `reports/{slug}/surface_map.md`

### Dependencies
- [ ] Base plugin(s) installed: {slugs or N/A}
- [ ] Ecosystem setup: {completed / premium-static-only / N/A}
- [ ] Additional test users: {customer, member, etc. or N/A}
- [ ] Cross-plugin interaction analysis: {yes / N/A}

### Surface Map Summary
```
(Fill from surface-mapper output)
ENDPOINTS: ...
DANGEROUS SINKS: ...
RECOMMENDED EXPERTS: ...
STATUS: COMPLETE / PARTIAL
```

## Expert Analysis

Only run experts recommended by surface-mapper. For large plugins, split into multiple instances per expert.

| Expert | Findings | Coverage | Status |
|--------|----------|----------|--------|
| (fill per surface-mapper recommendation) | — | — | pending |

Check `reports/{slug}/progress_{agent_name}.md` for coverage details.

## Post-Expert

- [ ] `data-flow-expert` — Cross-feature data flow chains
- [ ] `critical-thinker` — Cross-domain chains, second-order bugs (runs LAST)
- [ ] `vuln-escalator` — Auth level escalation, impact expansion, chain building

## Verification Pipeline

### 9. Impact Assessment (MANDATORY — runs FIRST)
- [ ] `impact-assessor` — bounty estimate + real-world impact check
  - Findings removed: {count}
  - Findings downgraded: {count}
  - Findings surviving: {count}

### 10-12. PoC Verification
Per finding that survived impact assessment:

#### Finding: {finding_id} — {title}
- [ ] `poc-writer` — PoC created: `reports/{slug}/{finding_id}/poc.py`
- [ ] `poc-runner` — Verdict: CONFIRMED / FALSE POSITIVE
- [ ] `qa-triage` — Scope: pass/fail | CVSS: {score} | Auth: {level}

### 13. Submission Prep (MANDATORY)
- [ ] `bb-submission` — Clean repro, submission report, bounty estimate
- [ ] `poc-recorder` — Terminal + browser video evidence

### 14. Record Audit
- [ ] `wpguard_audit_record(slug, version, findings_count, validated_count)`

## Summary
- [ ] All experts completed (or split instances covered full scope)
- [ ] All findings through verification pipeline
- [ ] Submission reports ready
- [ ] Engagement summary: `reports/{slug}/SUMMARY.md`
- [ ] Discord summary sent

## Stats
- Total findings from experts: 0
- Removed by impact assessor: 0
- Confirmed after PoC: 0
- False positives caught: 0
- Final for submission: 0
- Estimated total bounty: $0
