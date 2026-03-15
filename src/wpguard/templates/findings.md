# Findings Dashboard

List all findings across all plugins with status and severity.

## Steps:
1. Call `wpguard_finding_list()` to get all findings
2. Call `wpguard_finding_stats()` for summary statistics
3. Display:

```
FINDINGS DASHBOARD
==================
Total: {n}  |  Validated: {n}  |  Draft: {n}  |  Rejected: {n}

BY SEVERITY:
  🔴 Critical: {n}
  🟠 High: {n}
  🟡 Medium: {n}
  🟢 Low: {n}

BY PLUGIN:
  {plugin_slug}: {n} findings ({severities})
  ...

RECENT:
  {id} | {plugin} | {vuln_type} | {severity} | {status} | {auth_level}
  ...
```

If no findings exist, say "No findings yet. Use /pm to start an audit."
