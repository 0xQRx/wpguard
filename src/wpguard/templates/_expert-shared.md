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

## Common Missed Patterns (from n-day CVE analysis)

These patterns are consistently missed by security audits. Check for them:

1. **False sanitization → SQLi**: `esc_url_raw()`, `sanitize_text_field()`, `wp_kses()` do NOT escape SQL. Data sanitized for one context flowing into SQL = injection
2. **`$wpdb->insert()` key injection**: If array keys come from `$_POST`, column names are injectable (values are prepared, keys are NOT)
3. **`update_option()` with user-controlled key**: In loops, imports, or form handlers = full site takeover via `default_role` + `users_can_register`
4. **Profile hooks without cap check**: `personal_options_update` fires on own-profile save. Nonce is always available. Missing `current_user_can('promote_users')` = priv esc
5. **`wp_set_password`/`wp_update_user` without ownership check**: If user_id comes from `$_POST` instead of `get_current_user_id()` = account takeover
6. **`rest_pre_dispatch` hooks**: Fire BEFORE any REST route auth — effectively a global unauthenticated endpoint
7. **`init`/`template_redirect` implicit endpoints**: Process input on every page load, often without structured auth
8. **Standalone PHP files**: Files with `require wp-load.php` are directly accessible, bypass all WordPress auth
9. **`basename()` as security check**: `basename('/etc/passwd') === basename('/uploads/passwd')` → true. Always a bypass
10. **Encoded deserialization**: `unserialize(base64_decode($data))` hides the sink from simple grep patterns
11. **`wp_remote_get()` vs `wp_safe_remote_get()`**: The unsafe variant allows `file://` protocol and internal IPs
12. **Hard-coded JWT/HMAC fallbacks**: `defined('SECRET') ? SECRET : 'default_key'` = forgeable tokens
13. **Short OTP without rate limiting**: `rand(1000, 9999)` = 9000 combinations, brute-forceable in minutes

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
