# Audit Status Dashboard

Read the current PLAN file and provide a concise status report.

## Steps:
1. Find the active PLAN file: `ls reports/*/PLAN.md` (or fall back to `ls PLAN_*.md` for legacy projects)
2. Read it
3. Summarize in this format:

```
TARGET: {plugin_slug} v{version} ({installs} installs)

EXPERT PROGRESS: {completed}/{total}
  ✓ {completed agents with findings count}
  ⏳ {running agents}
  ○ {pending agents}

FINDINGS: {total}
  Critical: {n}  High: {n}  Medium: {n}  Low: {n}
  Validated: {n}  Draft: {n}  Rejected: {n}

VERIFICATION:
  PoC Written: {n}/{total}
  PoC Verified: {n}/{total}
  QA Complete: {n}/{total}

NEXT: {what should happen next}
```

4. If no PLAN file exists in either location, say "No active audit. Use /pm to start."
5. Also call `wpguard_finding_list()` to get current finding counts if findings exist.
