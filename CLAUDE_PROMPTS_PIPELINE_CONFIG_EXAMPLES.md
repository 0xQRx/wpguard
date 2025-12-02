# Pipeline Configuration Examples

## Parameter Reference

| Parameter | Description | Values |
|-----------|-------------|--------|
| `mode` | Pipeline execution mode | `"continuous"` (loop forever), `"single"` (one cycle), `"targets-only"` (find targets only) |
| `target_count` | Number of plugins to process per cycle | Integer (e.g., `1`, `5`, `10`) |
| `restart_mode` | What happens after QA completes | `"deeper"` (re-analyze same plugin), `"next"` (move to next), `"configurable"` (auto) |
| `target_criteria` | Instructions for target-research agent | String - can be plugin slug, search criteria, or natural language |
| `max_restarts` | How many restart cycles per plugin | Integer (`0` = no restarts, `1` = 2 total rounds, `2` = 3 total rounds) |
| `expert_restarts` | How many rounds include expert agents | Integer (`1` = experts on round 1 only, `2` = rounds 1-2, etc.) |
| `min_installs` | Minimum active installations filter | Integer (e.g., `500`, `1000`) |
| `worker_timeout_minutes` | Max time per worker stage | Integer (default: `120`) |

---

## Example Configurations

### 1. Single Specific Plugin (Thorough Analysis)

Scan ONE specific plugin with 2 restart cycles, experts on all rounds:

```
Start pipeline: {
    "mode": "single",
    "target_count": 1,
    "restart_mode": "deeper",
    "target_criteria": "modula-best-grid-gallery",
    "max_restarts": 2,
    "expert_restarts": 3
}
```

**Result:** 3 total rounds on modula-best-grid-gallery, all with 13 experts.

---

### 2. Single Plugin, One Pass Only (Quick Scan)

Fast scan of one plugin, no restarts:

```
Start pipeline: {
    "mode": "single",
    "target_count": 1,
    "target_criteria": "contact-form-7",
    "max_restarts": 0,
    "expert_restarts": 1
}
```

**Result:** 1 round → security-research → 13 experts → qa-triage → done.

---

### 3. Batch of Specific Plugins

Scan a list of known plugins:

```
Start pipeline: {
    "mode": "single",
    "target_count": 3,
    "target_criteria": "scan these specific plugins: akismet, wordfence, sucuri-scanner",
    "max_restarts": 1,
    "expert_restarts": 2
}
```

**Result:** 2 rounds each on akismet, wordfence, sucuri-scanner with experts on both rounds.

---

### 4. Continuous Discovery (Overnight Run)

Find and scan file-related plugins continuously:

```
Start pipeline: {
    "mode": "continuous",
    "target_count": 10,
    "restart_mode": "deeper",
    "target_criteria": "browse:updated min_installs:3000 max_installs:5000 plugins that work with files",
    "max_restarts": 1,
    "expert_restarts": 2,
    "min_installs": 500
}
```

**Result:** Loops forever - finds 10 targets → scans each with 2 rounds → finds 10 more → repeat.

---

### 5. Recently Updated Plugins (Changelog Focus)

Target recently updated plugins for patch analysis:

```
Start pipeline: {
    "mode": "single",
    "target_count": 5,
    "target_criteria": "browse:updated plugins updated in last 7 days with security-related changelog entries",
    "max_restarts": 1,
    "expert_restarts": 2
}
```

---

### 6. High-Value Targets (Low Install Count)

Hunt for vulnerabilities in smaller plugins (higher bounty tier):

```
Start pipeline: {
    "mode": "continuous",
    "target_count": 20,
    "target_criteria": "browse:new min_installs:25 max_installs:500 file upload or form plugins",
    "max_restarts": 2,
    "expert_restarts": 3,
    "min_installs": 25
}
```

---

## Common Patterns

### Restart Math
- `max_restarts=0` → 1 total round
- `max_restarts=1` → 2 total rounds
- `max_restarts=2` → 3 total rounds

### Expert Coverage
- `expert_restarts=1` → Experts only on round 1
- `expert_restarts=2` → Experts on rounds 1 and 2
- Set `expert_restarts >= max_restarts + 1` for experts on ALL rounds

### Mode Selection
- `"single"` → One batch, then stop (good for specific targets)
- `"continuous"` → Loop forever (good for overnight discovery)
- `"targets-only"` → Just find targets, don't scan (good for planning)
