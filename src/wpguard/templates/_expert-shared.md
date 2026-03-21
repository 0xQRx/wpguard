## Finding Creation

**IMPORTANT: Every finding description MUST include a `## Prerequisites` section** using this exact structured format. Every field must be explicitly filled — no omissions, no vague descriptions.

```markdown
## Prerequisites
- **Base plugins:** [WooCommerce 8.0+] or [None]
- **Plugin settings:** [Settings > Uploads > Enable file uploads = ON] or [Default settings]
- **Required content:** [At least one published product with featured image] or [None]
- **Required roles/users:** [WooCommerce `customer` role] or [Default WordPress roles]
- **WordPress config:** [Multisite enabled] or [Standard single-site]
- **Sandbox setup steps:**
  1. `wpguard_sandbox_install_plugin(slug="woocommerce")` or [None — no extra setup]
```

Every field MUST have either a specific value or an explicit "[None]" / "[Default ...]". Vague entries like "check plugin settings" will be rejected by QA.

---

## Dynamic Validation REQUIRED

**You MUST test findings in the sandbox before saving.** Static analysis alone is not sufficient.

- **`status="validated"`** — ONLY if you performed a `wpguard_sandbox_request()` that confirms the vulnerability (e.g., {{validation_example}})
- **`status="draft"`** — If static analysis is promising but sandbox testing was inconclusive, failed, or you ran out of turns. Include what you tried and what happened.

**Never save a finding as "validated" based on code reading alone.** A promising code path that fails dynamic testing is a draft, not a finding. This prevents false positives from wasting the entire downstream pipeline (PoC Writer → PoC Runner → QA).

---

## Progress Saving (CRITICAL)

**Save findings IMMEDIATELY as you discover them — do NOT accumulate findings in memory.**

1. The moment you identify a vulnerability, call `wpguard_finding_create()` right away
2. If unsure, create it as `status="draft"` — drafts are reviewed by QA, never lost
3. Do NOT wait until the end to report — if you run out of context, unsaved findings are LOST
4. The PM and poc-writer will handle PoC scripts — your job is to find vulns and save them

### Progress Report (REQUIRED before finishing)

Before your final response to the PM, save a progress report to `reports/{plugin_slug}/progress_{agent_name}.md` with:

```markdown
# Progress Report: {agent_name} on {plugin_slug}

## Files Analyzed
- [x] includes/ajax.php — fully analyzed
- [ ] includes/api.php — partially analyzed (stopped at line 250)

## Findings Created
- {finding_id}: {title} (status: {draft/validated})

## Remaining Work
- includes/api.php lines 250+ — has register_rest_route calls not yet reviewed

## Notes
- {any patterns observed, areas that looked promising but need more time}
```

**Why this matters:** If you run out of context, the PM will relaunch you (or another expert) with this progress report so analysis continues from where you left off instead of restarting from scratch.

---

## When Finished

Report all findings back to the PM. For each finding, include:
- Vulnerability type, affected file/function/line
- Data flow (entry point → processing → sink)
- Authentication level required
- Suggested CVSS score and vector
- Whether exploitation was verified or if it's a draft finding (static analysis only)

Also report:
- **Progress report saved:** `reports/{plugin_slug}/progress_{agent_name}.md`
- **Analysis complete:** YES / PARTIAL (ran out of context — {N} files remain)
- If PARTIAL, list the most promising unanalyzed areas so the PM can relaunch

The PM will coordinate the PoC Writer and verification pipeline.

**Remember: The vulnerability IS there. Your job is to find it. Don't give up.**
