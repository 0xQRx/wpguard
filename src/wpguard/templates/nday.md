# N-Day Research

Research known vulnerabilities in a plugin to create PoCs for patched bugs.

## Steps:
1. Get the plugin slug (and optionally CVE ID) from the user's message
2. Call `wpguard_cve_search(slug)` to find known CVEs
3. Call `wpguard_plugin_info(slug)` to get current version
4. Delegate to `poc-creator` agent with:
   - Plugin slug and current version
   - List of known CVEs to investigate
   - If user specified a CVE, focus on that one
   - Instructions to check changelogs, SVN diffs, and create PoCs

This is a shortcut that delegates to poc-creator — you don't do the research yourself.

## Variant Hunting (high-leverage extension)

Once poc-creator identifies the broken code pattern in the patched plugin, the single highest-leverage follow-up is **grepping the entire WordPress ecosystem for the same pattern** — other plugins almost certainly copy-pasted or independently reinvented the same bug.

Use the **veloria** MCP server (`search_code` tool) for this. Veloria indexes every plugin, theme, and core release on wordpress.org and supports Go RE2 regex across the whole directory. All MCP queries are private by default.

When delegating to poc-creator, instruct it to:
1. Extract the vulnerable sink from the pre-patch code (e.g. `unserialize($_POST['data'])`, `file_get_contents($_GET['url'])`, specific function signature)
2. Build a RE2 regex matching that pattern
3. Call `veloria.search_code` with `source=plugins`, file type `.php`, exclude minified
4. Triage hits: prioritize plugins with >500 installs, active maintenance, and no recent CVE history
5. Hand promising slugs back to the user for a full `/pm` audit or a targeted expert run

Variant hunting turns one n-day into potentially many 0-days for near-zero additional cost.

## Core-Patch Variant Hunting (WordPress core → plugins/themes)

The same technique applies to **WordPress core security releases**, and it is arguably higher-leverage: core bugs are heavily scrutinized, but plugins that reinvented the same primitive are not. When core ships a security release, the diff *is* the vulnerability disclosure — extract the patched pattern and hunt for plugins/themes that replicate it.

**Trigger:** the `CoreWatcher` (`wpguard_watch_core`) reports `security_release: true`, or you already have a core diff from `wpguard_core_svn_diff` (see the WordPress Core Research plan). `wpguard_watch_core(auto_diff=true)` returns `diff_from`, `diff_to`, and `changed_files` in one call.

**Workflow:**
1. Get the freshly-patched core diff — either `wpguard_watch_core(auto_diff=true)` or `wpguard_core_svn_diff(from_version=<prev latest>, to_version=<new latest>, show_diff=true)`.
2. From the **removed / changed lines**, isolate the vulnerable code pattern (the pre-patch sink and the missing guard). The changed file list points you at the subsystem (e.g. `wp-includes/rest-api/…`, `wp-includes/class-wp-query.php`).
3. Build a Go **RE2** regex matching the *shape* of that pattern — loose enough to catch re-implementations, tight enough to avoid noise.
4. Call `veloria.search_code` with `source=plugins` (then repeat with `source=themes`), file type `.php`, exclude minified. Core itself is `source=core` — use it to confirm your regex matches the pre-patch code before fanning out.
5. Each hit is a candidate **in-scope Wordfence finding**, installs-gated by the normal plugin scope tiers (25 for RCE/upload/auth-bypass, 500 for SQLi/stored-XSS, 50k for the unauth-victim classes). Triage by installs, active maintenance, and no recent CVE.
6. Hand promising slugs to the user for a full `/pm` audit or a targeted expert run.

**Worked example — the wp2shell shape (REST batch route-confusion → `WP_Query` param injection):**
The 6.9.4→7.0.2 core fix hardened how a REST batch/parallel request forwards caller-controlled params into `WP_Query`. Plugins that re-implement REST param → query dispatch without sanitizing the array-typed exclusion params are the variant target. Search for plugins that forward a REST/request param straight into `WP_Query` exclusion args:

```
veloria.search_code(
  source="plugins",           # then rerun with source="themes"
  filetype="php",
  exclude_minified=true,
  # RE2: request param flows into an array-typed WP_Query exclusion arg unsanitized
  regex="(author__not_in|post__not_in|post__in)['\"]?\\s*=>\\s*\\$_(GET|POST|REQUEST)\\[",
)
```

Companion regex for the parallel-array request-dispatch primitive (the route-confusion root cause — a handler that pairs a `routes[]`/`methods[]`-style parallel-array request against a dispatch table):

```
veloria.search_code(
  source="plugins",
  filetype="php",
  exclude_minified=true,
  regex="\\$_(GET|POST|REQUEST)\\[['\"](routes|methods|endpoints|batch)['\"]\\].*(foreach|array_map)",
)
```

Tighten or widen the regex against `source=core` first (it must match the pre-patch `diff_from` tag), then fan out to plugins/themes. As above, prioritize >500-install plugins with no recent CVE history and hand them off for a full audit.
