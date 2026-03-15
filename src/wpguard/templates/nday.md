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
