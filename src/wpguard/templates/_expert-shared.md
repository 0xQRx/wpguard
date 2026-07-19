## ⚠️ CONTEXT SURVIVAL PROTOCOL (READ THIS FIRST)

**You WILL run out of context on large plugins.** Plan for it. Every tool call costs tokens. Your unsaved work dies when context runs out.

### Rule 0: BE TERSE — Your Output Eats Your Context

**Your own output counts against the context window.** Every verbose paragraph you write is context you can't use for code analysis.

- **DO NOT** narrate what you're about to do — just do it
- **DO NOT** repeat code you just read back in your response — reference file:line
- **DO NOT** write multi-paragraph analysis between tool calls — save it for the progress report
- **DO** use one-line notes: "ajax.php:142 — $wpdb->query without prepare, POST['id'] concatenated. Tracing source."
- **DO** batch your observations and write them to the progress report, not to conversation
- **Target: < 50 words between tool calls.** If you're writing more, you're wasting context.

### Rule 1: Checkpoint Start (your VERY FIRST tool call)

Before reading ANY code, call:
```
wpguard_agent_checkpoint(action="start", agent_name="{your_name}", plugin_slug="{slug}", priority_targets=[...files from surface map/semgrep...])
```
If you're continuing from a previous run, the tool returns your prior state — skip files already marked analyzed.

### Rule 2: Checkpoint After Every Finding + Every 3-5 Files

After creating a finding OR reading 3-5 files, call:
```
wpguard_agent_checkpoint(action="progress", agent_name="{your_name}", plugin_slug="{slug}", files_analyzed=["file1.php", "file2.php"], notes=["ajax.php:142 — $wpdb->query without prepare"])
```
The tool accumulates your state server-side. **If the response says urgency="high":**
1. Create draft findings for ALL promising leads immediately
2. Call `wpguard_agent_checkpoint(action="partial", files_remaining=[...], notes=["most promising: callbacks.php admin_init handler"])`
3. Stop analysis — the PM will relaunch you from your checkpoint

### Rule 3: Save Findings IMMEDIATELY

The moment you identify a vulnerability — even a maybe:
1. **Check for duplicates**: `wpguard_finding_check_duplicate(plugin_slug, affected_file, affected_function)`
2. Call `wpguard_finding_create()` with `status="draft"` if unverified
3. Call `wpguard_agent_checkpoint(action="progress", findings_created=["{finding_id}"])`
4. Then continue analyzing

### Rule 4: When Done

Call `wpguard_agent_checkpoint(action="complete", agent_name, plugin_slug, notes=["analysis summary"])` — this generates the final progress report the PM reads.

### Rule 5: Use Nonce Mapper for Auth Testing

When you need nonces for testing endpoints, call `wpguard_sandbox_map_nonces()` — it crawls all admin pages at every auth level and returns all available nonces. Much faster than manually hunting through page source. Add plugin-specific pages via `extra_pages` parameter.

### Rule 4: Start From the Surface Map

Read these files in order:
1. `reports/{plugin_slug}/semgrep_scan.md` — pre-identified code patterns (file:line + code snippets, ranked by severity)
2. `reports/{plugin_slug}/progpilot_scan.md` — taint flows (source→sink data paths)
3. `reports/{plugin_slug}/surface_map.md` — auth model, nonce accessibility, REST routes, dependencies

**Start from CRITICAL semgrep/progpilot findings** — jump directly to the flagged file:line and trace from there. Do NOT re-grep for basic SQL/file/XSS patterns; the tools already found them. Focus your context on deep analysis, data flow tracing, and exploitation verification.

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
14. **Export/backup/download functions as file read**: These inherently read files and often have weaker auth than CRUD. Always check path traversal.
15. **ZIP extraction without filename sanitization**: `ZipArchive::extractTo()` with `../` in entry names = zip slip

## PHP Type Coercion Traps (check these in EVERY auth/validation flow)

```
empty('0') === true          — breaks nonce checks, zero-value validation
in_array($val, $list)        — without strict=true, 0 == "admin" is true
array_search($val, $list)    — without strict=true, returns 0 (truthy index)
strcmp([], 'string')          — returns null, null == 0 is true → auth bypass
intval('0e12345') === 0      — magic hash prefix comparison
json_decode('invalid')        — returns null → null propagation through auth
isset() wrapping nonce check — omitting the field entirely bypasses the check
'0' == false === true        — loose comparison on tokens/passwords
```

## Error Handling as Vulnerability Class

Functions that return `false`/`null` on failure are dangerous when callers don't check:
- `openssl_private_decrypt()` fails → returns `false` → passed to next function as empty string
- `get_userdata($email)` → wrong type → returns `false` → fallback to current_user
- `realpath()` on non-existent path → returns `false` → PHP 8 strpos(false, '/') breaks containment
- `file_get_contents()` fails → false → used in comparison → bypasses checks
- Any function with `@` error suppression + boolean return = silent failure path

**Rule: trace what happens when a function FAILS, not just when it succeeds.**

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

### Confirm PRIMITIVES against ground truth — "the response looked right" is NOT verification

A `200`/`207` and a well-formed body do **not** prove a write, forge, or state change happened. The
HTTP response can look perfect while the primitive silently did nothing (a malformed SQL literal, a
suppressed render, a swallowed error). Two classes of mistake this rule exists to stop:

- **Declaring a primitive DEAD from static analysis** (a "this code path can't be reached / can't
  write" conclusion never tested at runtime). The wp2shell escalation was wrongly called "blocked"
  twice this way — both wrong.
- **Declaring a primitive ALIVE from the response shape** (posts came back, so "the forge worked") —
  when the underlying DB write never fired.

When a finding claims a **write / forge / privilege change**, confirm it against a ground-truth oracle,
not the response body:

- **PREFERRED — `wpguard_sink_trace` (the data-flow oracle).** This records every attacker-reachable
  hit on a dangerous sink (SQL, option write, user/role creation, meta write, outbound HTTP/SSRF, mail)
  **with the PHP backtrace**, so you see the whole path from entry point to sink — a superset of the
  general_log (which only sees SQL). Workflow:
    1. `wpguard_sink_trace(action="enable")`  (clears the log and turns tracing on)
    2. Run your PoC request(s) — the real attacker flow (curl / `wpguard_sandbox_request`).
    3. `wpguard_sink_trace(action="read")` — inspect the `records`. Each has `type`, `sink`, `detail`
       (the actual SQL / option+value / user role / meta), the auth `user`, and the `backtrace`.
    4. `wpguard_sink_trace(action="disable")` when done.
  Use it to PROVE a write fired (find the `INSERT`/`update_option`/`user_register` record with your
  marker value) or to prove one did NOT (no record ⇒ the primitive is a no-op, however good the
  response looked). Filter noise with `type_filter` and separate concurrent requests via each record's
  `reqid`. For a compact list use `include_backtrace=false`. wp-cron requests are skipped by default.
  **This is your default write/forge oracle for HTTP PoCs** — sink records + the backtrace answer
  "did the write happen and via what path" for nearly every finding.
  > Need to see argument/return values *inside* an internal PHP function (`move_uploaded_file`,
  > `unserialize`, `wp_check_filetype`, a sanitizer) that the sink tracer can't reach? **Delegate that
  > to the `dynamic-tracer` agent** — it owns the safe CLI-only Xdebug procedure. **Do NOT run Xdebug
  > yourself, and never add an `XDEBUG_TRACE` trigger to a web/REST/AJAX request** — a full trace of a
  > live request is 20–130 MB and wedges the sandbox. For everything else, `wpguard_sink_trace` +
  > independent re-reads are your tools.
- **Fallback — raw MySQL query log:** `wpguard_sandbox_wp_cli` or the DB container: `SET GLOBAL
  log_output='TABLE'; SET GLOBAL general_log='ON';` then inspect `mysql.general_log`.
- **State changes:** also re-read the affected row/option/user via an independent path and diff it
  (before vs after) — the tracer shows the write happened; the re-read confirms the resulting value.
- **A "write" primitive that produces nothing:** if `wpguard_sink_trace` shows no matching sink record,
  treat it as unproven and hunt the reason (empty/invalid SQL literal, `post_password` non-empty
  suppressing render, a guard that returned early, error swallowed) before concluding either
  "blocked" or "works".

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
