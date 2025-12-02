# How to Add a New Expert Agent

Quick reference for adding new expert agents to the WordPressGuard pipeline.

## Files to Modify (4 files + 1 new)

### 1. Create Expert Template
**Location:** `src/wpguard/templates/{expert-name}-expert.md`

Use existing expert as template (e.g., `file-rce-expert.md`). Required sections:

```markdown
# {Expert Name} Expert - Wordfence Edition

## Role
You are an ELITE {specialty} specialist...

## Authorization Context
This agent operates within an authorized bug bounty program...

---

## ⚠️ CRITICAL MINDSET: THE VULNERABILITY EXISTS
**THIS PLUGIN IS VULNERABLE TO {VULN_TYPE}. YOUR JOB IS TO FIND IT.**
...

---

## Your ONLY Focus
**{VULN_TYPE} VULNERABILITIES:**
- Specific vuln type 1
- Specific vuln type 2
...

**IGNORE everything else** - other vulns are for other experts.

---

## Patterns to Hunt

### High Priority Sinks
```php
// Code patterns to search for
```

### Medium Priority
...

---

## Attack Techniques
1. Technique 1
2. Technique 2
...

---

## Bypass Checklist (MANDATORY)
[ ] Check 1
[ ] Check 2
...

---

## Sandbox Testing
```python
# Example sandbox test code
```

---

## Finding Creation
```python
wpguard_finding_create(...)
```

---

## CVSS Reference for {Vuln Type}
```
Unauth {Vuln}: X.X
Auth {Vuln}: X.X
```

---

## PoC Script Creation (REQUIRED)

### File Location
Save PoC to: `reports/{plugin_slug}/poc_{vuln_type}_{short_id}.py`

### PoC Template
```python
#!/usr/bin/env python3
"""
PoC for {Vulnerability Title}
...
"""
import argparse
import requests
...
```

### PoC Checklist
- [ ] Script runs with `python3 poc.py --help`
- [ ] Works against sandbox
- [ ] Clear VULNERABLE/NOT VULNERABLE output
...

---

## Signal Completion
```python
wpguard_scan_state(stage_completed="{expert-name}-expert")
```

**Remember: The vulnerability IS there. Your job is to find it. Don't give up.**
```

### 2. Update Pipeline Stage Order
**File:** `src/wpguard/core/pipeline.py`

```python
# Add to STAGE_ORDER (before qa-triage, around line 30)
STAGE_ORDER = [
    "target-research",
    "security-research",
    "file-rce-expert",
    "sqli-expert",
    "xss-expert",
    "auth-expert",
    "object-injection-expert",
    "ssrf-expert",
    "race-condition-expert",
    "{expert-name}-expert",  # ADD HERE
    "qa-triage",
]

# Add to EXPERT_STAGES (around line 43)
EXPERT_STAGES = [
    "file-rce-expert",
    "sqli-expert",
    "xss-expert",
    "auth-expert",
    "object-injection-expert",
    "ssrf-expert",
    "race-condition-expert",
    "{expert-name}-expert",  # ADD HERE
]
```

### 3. Update Init Module
**File:** `src/wpguard/core/init.py`

```python
# 1. Add to WPGUARD_SLASH_COMMANDS (around line 73)
WPGUARD_SLASH_COMMANDS = [
    ...
    "SlashCommand(/race-condition-expert)",
    "SlashCommand(/{expert-name}-expert)",  # ADD HERE
    "SlashCommand(/qa-triage)",
    ...
]

# 2. Add getter function (around line 185)
def get_{expert_name_underscore}_expert_instructions() -> str:
    """Get {expert name} expert agent instructions."""
    return _load_template("{expert-name}-expert.md")

# 3. Add to initialize_research_project() (around line 245)
(root / ".claude" / "commands" / "{expert-name}-expert.md").write_text(
    get_{expert_name_underscore}_expert_instructions()
)

# 4. Add to commands list in return structure (around line 305)
"commands": [
    ...
    "/race-condition-expert",
    "/{expert-name}-expert",  # ADD HERE
    "/qa-triage",
    ...
],
```

### 4. Update Documentation
**File:** `src/wpguard/templates/CLAUDE.md`

```markdown
### Expert Agents (Deep-Dive Specialists)
...
- `/ssrf-expert` - Server-side request forgery, cloud metadata access
- `/race-condition-expert` - TOCTOU, database races, double-spend, limit bypass
- `/{expert-name}-expert` - Brief description  # ADD HERE

## Pipeline Automation
```
target-research → security-research → ... → race-condition-expert → {expert-name}-expert → qa-triage
```
```

## Checklist

- [ ] Created `src/wpguard/templates/{expert-name}-expert.md`
- [ ] Added to `STAGE_ORDER` in `pipeline.py`
- [ ] Added to `EXPERT_STAGES` in `pipeline.py`
- [ ] Added slash command to `WPGUARD_SLASH_COMMANDS` in `init.py`
- [ ] Added getter function in `init.py`
- [ ] Added file write in `initialize_research_project()` in `init.py`
- [ ] Added to commands list in `init.py`
- [ ] Updated `CLAUDE.md` expert list
- [ ] Updated `CLAUDE.md` pipeline diagram
- [ ] Re-run `wpguard_init_research()` to deploy new command

## Testing

```bash
# 1. Re-initialize project to deploy new command
wpguard_init_research(output_dir=".")

# 2. Verify command file exists
ls .claude/commands/{expert-name}-expert.md

# 3. Test manually with a plugin
/{expert-name}-expert {plugin-slug}

# 4. Test in pipeline (single mode)
wpguard_pipeline_start(mode="single", target_count=1)
```

## Current Expert Order (as of latest update)

```
target-research
    ↓
security-research
    ↓
file-rce-expert
    ↓
sqli-expert
    ↓
xss-expert
    ↓
auth-expert
    ↓
object-injection-expert
    ↓
ssrf-expert
    ↓
race-condition-expert
    ↓
qa-triage
```

## Naming Conventions

- **Template file:** `{expert-name}-expert.md` (kebab-case)
- **Stage name:** `{expert-name}-expert` (kebab-case, same as filename without .md)
- **Getter function:** `get_{expert_name}_expert_instructions()` (snake_case)
- **Slash command:** `/{expert-name}-expert` (kebab-case)

## Tips

1. **Copy existing expert:** Start by copying `file-rce-expert.md` or `race-condition-expert.md`
2. **Focus narrow:** Each expert should focus on ONE vulnerability class only
3. **Include PoC template:** Always include a vulnerability-specific PoC script template
4. **Elite mindset:** Use the "vulnerability EXISTS, find it" mentality throughout
5. **Bypass checklist:** Include a mandatory checklist before marking "not vulnerable"
