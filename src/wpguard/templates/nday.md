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
