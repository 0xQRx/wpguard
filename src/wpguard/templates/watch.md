# /watch — Plugin Update Monitor

Scan the WordPress plugin ecosystem for recent updates, new plugins, and check your watchlist.

## Steps

1. **Global scan** — Call `wpguard_watch_global(min_installs=1000)` to discover recently updated plugins across the WordPress.org repository.

2. **New plugins scan** — Call `wpguard_watch_new(min_installs=0)` to discover newly added plugins.

3. **Watchlist check** — Call `wpguard_watch_check()` to detect version changes in your watched plugins (with SVN diffs).

4. **Summarize results** in three tiers:
   - **High-interest** (>50k active installs) — always show these
   - **Notable** (>10k active installs) — show slug, version, install count
   - **Other** — count only, unless security-relevant

5. **Flag security-relevant updates** — scan plugin names, descriptions, and SVN commit messages for keywords: `security`, `fix`, `vulnerability`, `CVE`, `patch`, `XSS`, `SQL`, `injection`, `auth`, `bypass`, `sanitize`, `escape`, `nonce`.

6. **Watchlist changes** — for any watched plugin that updated, show:
   - Version change (old → new)
   - SVN revision range
   - Changed/added/removed file counts
   - SVN commit log summary (first 3 entries)

## Output Format

```
## Plugin Update Monitor

### Global Updates (X new since last check)

#### High-Interest (>50k installs)
- plugin-name (slug) v1.2.3 — 500,000 installs
  ...

#### Security-Relevant
- plugin-name (slug) v1.2.3 — "Fixed XSS in widget output"
  ...

#### Notable (>10k installs)
- slug v1.2.3 — 25,000 installs
  ...

#### Summary
- Total new updates: X
- Other updates (<10k installs): Y

### New Plugins (X new since last check)
- plugin-name (slug) v1.0.0 — "Short description..."
  ...

### Watchlist Changes
- plugin-name: v1.0 → v1.1 (r1234 → r1240)
  Changed: 5 files | Added: 2 | Removed: 0
  Commits: "Fix security issue in form handler", ...

### No Changes
- plugin-a, plugin-b (up to date)
```

## Notes

- First run seeds the seen state — all current versions/slugs are "seen", so only future changes will be flagged.
- Use `wpguard_watch_add` to add plugins to the watchlist for SVN-level change tracking.
- Results are saved to `recently_updated.json` and `new_plugins.json` in the project directory.
