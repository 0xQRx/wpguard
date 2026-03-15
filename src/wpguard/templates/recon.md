# Plugin Reconnaissance

Quick assessment of a plugin before committing to a full audit.

## Steps:
1. Get the plugin slug from the user's message (or ask if not provided)
2. Call `wpguard_plugin_info(slug)` for install count, version, description
3. Call `wpguard_cve_search(slug)` to check CVE history
4. Call `wpguard_scope_check_plugin(slug)` to verify bounty eligibility
5. If plugin source is in `targets/`, do a quick line count and file count
6. Summarize:

```
RECON: {plugin_name}
===================
Slug:        {slug}
Version:     {version}
Installs:    {active_installs}
Tested Up To: {tested_up_to}
Last Updated: {last_updated}

SCOPE:
  Eligible:  {yes/no}
  Tiers:     {which bounty tiers it qualifies for}

CVE HISTORY: {count}
  Recent:    {list last 3-5 CVEs with type and date}
  Patterns:  {recurring vuln types if any}

VERDICT: {recommend full audit / skip / targeted check}
REASON: {why}
```

If the plugin has many recent CVEs of the same type, recommend targeted analysis for that type + check for incomplete fixes.
If plugin has 0 CVEs and high installs, it's a prime target — recommend full audit.
