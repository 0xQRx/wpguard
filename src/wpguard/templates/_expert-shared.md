## ⚠️ CONTEXT SURVIVAL PROTOCOL (READ THIS FIRST)

**You WILL run out of context on large plugins.** Plan for it. Every tool call costs tokens. Your unsaved work dies when context runs out.

### Rule 1: Save Structure FIRST (within your first 3 tool calls)

Before analyzing ANY code, create your progress report scaffold:

```
reports/{plugin_slug}/progress_{agent_name}.md
```

```markdown
# Progress Report: {agent_name} on {plugin_slug}

## Priority Targets (from surface map)
- [ ] {file1}:{line} — {pattern found}
- [ ] {file2}:{line} — {pattern found}

## Additional Files Discovered
- [ ] {file} — {why it's interesting}

## Findings Created
(none yet)

## Notes
(none yet)
```

**This is your lifeline.** If you run out of context, the PM relaunches you from this file.

### Rule 2: Checkpoint Every 10 Tool Calls

After every ~10 tool calls, UPDATE your progress report:
- Mark files as `[x]` analyzed or `[~]` partial
- Add any promising leads to Notes
- Add any findings created

**Do NOT wait until you're "done" to save progress.** Save continuously.

### Rule 3: Save Findings IMMEDIATELY

The moment you identify a vulnerability — even a maybe:
1. Call `wpguard_finding_create()` RIGHT NOW with `status="draft"` if unverified
2. Update your progress report with the finding ID
3. Then continue analyzing

A saved draft is infinitely more valuable than a lost validated finding.

### Rule 4: Start From the Surface Map

Read the surface map at `reports/{plugin_slug}/surface_map.md` first — it has prioritized file:line targets for your specialty. **Start with those high-value targets** to get findings fast. Then expand your own analysis into areas the surface mapper may have missed — grep for patterns, trace data flows, follow your instincts. The surface map is a head start, not a boundary.

---

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
