# /diff — Security-Focused Version Diff Analysis

Analyze code changes between two versions of a plugin or theme for security-relevant patterns.

## Usage

```
/diff {slug} {old_version} {new_version}
/diff {slug}    (compares last audited version to current)
```

## Steps

1. **Resolve versions to SVN revisions** — call `wpguard_svn_log(slug)` to map version tags to revision numbers. If only a slug is given, check `wpguard_audit_check(slug)` for the last audited version and compare to current.

2. **Get the diff** — call `wpguard_svn_diff(slug, old_rev, new_rev, show_diff=true)` for the full diff output with file lists.

3. **Analyze changed files** — categorize each changed file by risk:
   - **Critical**: files containing AJAX handlers, REST routes, auth checks, SQL queries
   - **High**: files with file operations, user management, options API
   - **Medium**: frontend rendering, shortcodes, widgets
   - **Low**: CSS, JS assets, readme, translations

4. **Scan diff for security-relevant patterns** — in the actual diff output, flag:

   **Added (new attack surface):**
   - New `wp_ajax_nopriv_` / `wp_ajax_` registrations
   - New `register_rest_route()` calls
   - New `update_option()` / `delete_option()` calls
   - New `$wpdb->query()` / `$wpdb->get_results()` without `prepare()`
   - New `unserialize()` / `file_get_contents()` / `eval()` calls
   - New `wp_remote_get()` (not safe variant)
   - New form handlers via `init` / `template_redirect`

   **Removed (potential regression):**
   - Removed `$wpdb->prepare()` calls
   - Removed `current_user_can()` / `wp_verify_nonce()` checks
   - Removed `sanitize_*()` / `esc_*()` calls
   - Removed `wp_safe_redirect()` replaced with `wp_redirect()`

   **Modified (check context):**
   - Changed auth level requirements
   - Modified SQL queries (new parameters, changed WHERE clauses)
   - Changed file path handling
   - Modified serialization/deserialization logic

5. **Cross-reference with CVE history** — call `wpguard_cve_search(slug)` to check if any changes look like patches for known CVEs. If so, check for incomplete fixes.

6. **Produce report** — output structured analysis:

```
## Version Diff: {slug} v{old} → v{new}

### Summary
- Files changed: X | Added: Y | Removed: Z
- Security-relevant changes: N

### Critical Changes
- {file}:{line} — NEW wp_ajax_nopriv handler: {action_name}
- {file}:{line} — REMOVED prepare() from SQL query
  ...

### New Attack Surface
- {file}:{line} — new REST endpoint: /wp-json/{namespace}/{route}
  ...

### Potential Regressions
- {file}:{line} — sanitization removed from {parameter}
  ...

### Recommended Follow-Up
- [ ] Launch {expert} to audit {file} — {reason}
- [ ] Check for incomplete CVE fix: {cve_id}
```

## Notes

- This command is especially useful after `/watch` reports an update — run `/diff` on high-interest updates to decide whether to launch a full audit.
- For theme diffs, use `wpguard_theme_svn_diff` instead of `wpguard_svn_diff`.
- Large diffs (100+ files) may need to be analyzed in chunks — focus on PHP files first, skip assets.
