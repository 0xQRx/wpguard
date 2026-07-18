# /watch — WordPress Update Monitor

Scan the WordPress plugin AND theme ecosystems for recent updates, new additions, and check your watchlist. Any code change is a potential research target — not just security patches.

## Usage

`/watch <target>` — pick exactly which scan to run. Running everything at once is noisy and burns API calls, so this command requires an explicit target.

| Target | Tool | What it does |
|--------|------|--------------|
| `plugins` | `wpguard_watch_global(min_installs=1000)` | Recently updated plugins (≥10k installs enriched with changelog + SVN log) |
| `themes` | `wpguard_watch_global_themes(min_installs=1000)` | Recently updated themes (≥10k installs enriched) |
| `new-plugins` | `wpguard_watch_new(min_installs=0)` | Newly added plugins |
| `new-themes` | `wpguard_watch_new_themes(min_installs=0)` | Newly added themes |
| `list` | `wpguard_watch_check()` | Version changes in watchlist (with SVN diffs) |
| `core` | `wpguard_watch_core(auto_diff=true)` | WordPress **core** release monitor — new/security release, auto-runs the Phase 1 diff |
| `all` | all of the above | Only use when explicitly requested — verbose |

If the user runs `/watch` with no argument, ask which target to run and show the table above. **Do not default to `all`.**

## Steps

1. **Parse the argument.** Map it to exactly one tool (or the full set if `all`). Reject unknown targets with the usage table.

2. **Run only the selected tool(s).** Do not call the others.

3. **Analyze changelogs and SVN logs** for enriched updates:
   - Changelog entries = developer's perspective
   - SVN commit messages = actual code-level changes
   - ANY code change is interesting — new features add attack surface, refactors break assumptions, "bug fixes" can introduce new bugs

4. **Categorize updates** for research potential:
   - **High-value targets** (>50k installs) — always list with changelog summary
   - **Notable** (>10k installs) — list with changelog if available
   - **New plugins/themes** — fresh code with zero prior scrutiny
   - **Watchlist changes** — detailed SVN diff summary

5. **Flag especially interesting changes** — look for keywords in changelogs and commit messages:
   - Security-adjacent: `security`, `fix`, `vulnerability`, `CVE`, `patch`, `sanitize`, `escape`, `nonce`, `auth`, `bypass`
   - New attack surface: `new feature`, `REST API`, `AJAX`, `upload`, `import`, `export`, `webhook`, `payment`, `registration`, `login`, `role`, `capability`
   - Risky operations: `database`, `migration`, `serialize`, `unserialize`, `eval`, `exec`, `include`, `require`, `file_get_contents`

## Output Format

Only include sections for the scans you actually ran.

```
## Plugin Update Monitor — <target>

### Global Updates (X new since last check, Y enriched)

#### High-Value Targets (>50k installs)
- **plugin-name** (slug) v1.2.3 — 500,000 installs
  Changelog: Added new REST API endpoint for bulk operations, fixed form validation
  SVN: r1234 "Add bulk action REST endpoint", r1235 "Update form handler"

#### Notable (>10k installs)
- **plugin-name** (slug) v2.0.0 — 25,000 installs
  Changelog: Major rewrite of import/export system
  SVN: r567 "Rewrite CSV importer with new field mapping"

#### Other Updates
- X plugins with <10k installs updated

### New Plugins (X new since last check)
- plugin-name (slug) v1.0.0 — "Short description..."

### Watchlist Changes
- plugin-name: v1.0 → v1.1 (r1234 → r1240)
  Changed: 5 files | Added: 2 | Removed: 0
  Commits: "Refactor payment handler", "Add webhook endpoint"

### No Changes
- plugin-a, plugin-b (up to date)
```

## Core Release Monitor (`/watch core`)

WordPress **core** is a parallel target type (see the Core Research plan). `wpguard_watch_core` polls the core stable/version-check APIs and persists its own `core_state.json` — fully isolated from the plugin/theme watch state.

Monitoring loop:
1. Poll with `wpguard_watch_core(auto_diff=true)`. It returns `new_release`, `latest`, `previous_latest`, `security_release`, `diff_from`, `diff_to`, and — when `auto_diff` fired — `changed_files` + `total_changes`.
2. **On `security_release: true` (or any `new_release`)** the tool has already run the Phase 1 diff (`diff_from` → `diff_to`). Review `changed_files` to identify the patched subsystem.
3. **Kick off the core-patch variant hunt** — take the diff into `/nday`'s "Core-Patch Variant Hunting" flow: extract the patched pattern, build a `veloria.search_code` RE2 regex, and search `source=plugins`/`source=themes` for plugins replicating it. Each hit is a candidate in-scope Wordfence finding.
4. Use `wpguard_watch_core_state` to inspect the last-seen latest and known-insecure set without re-polling.

Run it on a schedule with `/loop 6h /watch core`.

## Notes

- First run seeds the seen state — all current versions/slugs are "seen", so only future changes will be flagged as new. (The core monitor's first run reports `new_release: true` while seeding `core_state.json` — expected.)
- Changelog and SVN log enrichment only runs for plugins with >= 10k installs to keep API calls reasonable.
- Use `wpguard_watch_add` to add specific plugins for SVN-level change tracking.
- Results are saved to `recently_updated.json` and `new_plugins.json` in the project directory.
- Use `/loop 30m /watch list` (or another specific target) to continuously monitor.
- For high-interest updates, run `/diff {slug}` to analyze security-relevant code changes before launching a full audit.
- Use `wpguard_target_score(slugs=[...])` to rank updated plugins by research priority.
