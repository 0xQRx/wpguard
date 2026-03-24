# /watch — WordPress Update Monitor

Scan the WordPress plugin AND theme ecosystems for recent updates, new additions, and check your watchlist. Any code change is a potential research target — not just security patches.

## Steps

1. **Plugin global scan** — Call `wpguard_watch_global(min_installs=1000)` to discover recently updated plugins. Plugins with >= 10k installs are enriched with changelog and SVN commit log.

2. **Theme global scan** — Call `wpguard_watch_global_themes(min_installs=1000)` to discover recently updated themes. Themes with >= 10k installs are enriched with changelog and SVN log.

3. **New plugins scan** — Call `wpguard_watch_new(min_installs=0)` to discover newly added plugins.

4. **New themes scan** — Call `wpguard_watch_new_themes(min_installs=0)` to discover newly added themes.

5. **Watchlist check** — Call `wpguard_watch_check()` to detect version changes in your watched plugins (with SVN diffs).

4. **Analyze changelogs and SVN logs** — for enriched updates, review what changed:
   - Changelog entries describe the update from the developer's perspective
   - SVN commit messages show the actual code-level changes
   - ANY code change is interesting — new features introduce new attack surface, refactors can break assumptions, "bug fixes" can introduce new bugs

5. **Categorize updates** for research potential:
   - **High-value targets** (>50k installs) — always list with changelog summary
   - **Notable** (>10k installs) — list with changelog if available
   - **New plugins** — fresh code with zero prior scrutiny
   - **Watchlist changes** — detailed SVN diff summary

6. **Flag especially interesting changes** — look for keywords in changelogs and commit messages:
   - Security-adjacent: `security`, `fix`, `vulnerability`, `CVE`, `patch`, `sanitize`, `escape`, `nonce`, `auth`, `bypass`
   - New attack surface: `new feature`, `REST API`, `AJAX`, `upload`, `import`, `export`, `webhook`, `payment`, `registration`, `login`, `role`, `capability`
   - Risky operations: `database`, `migration`, `serialize`, `unserialize`, `eval`, `exec`, `include`, `require`, `file_get_contents`

## Output Format

```
## Plugin Update Monitor

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

## Notes

- First run seeds the seen state — all current versions/slugs are "seen", so only future changes will be flagged as new.
- Changelog and SVN log enrichment only runs for plugins with >= 10k installs to keep API calls reasonable.
- Use `wpguard_watch_add` to add specific plugins for SVN-level change tracking.
- Results are saved to `recently_updated.json` and `new_plugins.json` in the project directory.
- Use `/loop 30m /watch` to continuously monitor for updates.
