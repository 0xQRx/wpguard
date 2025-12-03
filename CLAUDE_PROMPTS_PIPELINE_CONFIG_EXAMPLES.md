# Pipeline Configuration Examples

## Parameter Reference

| Parameter | Description | Values |
|-----------|-------------|--------|
| `mode` | Pipeline execution mode | `"continuous"` (loop forever), `"single"` (one cycle), `"targets-only"` (find targets only) |
| `target_count` | Number of plugins to process per cycle | Integer (e.g., `1`, `5`, `10`) |
| `num_iterations` | How many times to run security-research + experts per plugin | Integer (`1` = single pass, `2` = two passes, `3` = three passes) |
| `deferred_qa` | When QA runs | `true` (after all iterations), `false` (after each iteration) |
| `target_criteria` | Instructions for target-research agent | String - can be plugin slug, search criteria, or natural language |
| `min_installs` | Minimum active installations filter | Integer (e.g., `500`, `1000`) |
| `worker_timeout_minutes` | Max time per worker stage | Integer (default: `120`) |

---

## Example Configurations

### 1. Single Specific Plugin (Thorough Analysis)

Scan ONE specific plugin with 3 iterations:

```
Start pipeline: {
    "mode": "single",
    "target_count": 1,
    "target_criteria": "modula-best-grid-gallery",
    "num_iterations": 3
}
```

**Result:** 3 iterations on modula-best-grid-gallery, each with security-research + 13 experts, then QA once.

---

### 2. Single Plugin, One Pass Only (Quick Scan)

Fast scan of one plugin:

```
Start pipeline: {
    "mode": "single",
    "target_count": 1,
    "target_criteria": "contact-form-7",
    "num_iterations": 1
}
```

**Result:** 1 iteration → security-research → 13 experts → qa-triage → done.

---

### 3. Batch of Specific Plugins

Scan a list of known plugins:

```
Start pipeline: {
    "mode": "single",
    "target_count": 3,
    "target_criteria": "scan these specific plugins: akismet, wordfence, sucuri-scanner",
    "num_iterations": 2
}
```

**Result:** 2 iterations each on akismet, wordfence, sucuri-scanner.

---

### 4. Continuous Discovery (Overnight Run)

Find and scan file-related plugins continuously:

```
Start pipeline, ensure proper config: {
    "mode": "continuous",
    "target_count": 2,
    "target_criteria": "min_installs:60000 max_installs:65000 plugins that work with files, no woocommerce and not depending on other plugins, select 2 best suited targets",
    "num_iterations": 1,
    "min_installs": 50000
}
```

**Result:** Loops forever - finds 10 targets → scans each with 2 iterations → finds 10 more → repeat.

---

### 5. Recently Updated Plugins (Changelog Focus)

Target recently updated plugins for patch analysis:

```
Start pipeline: {
    "mode": "single",
    "target_count": 5,
    "target_criteria": "browse:updated plugins updated in last 7 days with security-related changelog entries",
    "num_iterations": 2
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
    "num_iterations": 3,
    "min_installs": 25
}
```

---

## Common Patterns

### Iterations
- `num_iterations=1` → 1 pass (quick scan)
- `num_iterations=2` → 2 passes (default, good balance)
- `num_iterations=3` → 3 passes (thorough analysis)

### Pipeline Flow (default: num_iterations=2, deferred_qa=true)
```
Iteration 1: security-research → all 13 experts
Iteration 2: security-research → all 13 experts
Final:       qa-triage (runs once)
→ Next plugin
```

### Mode Selection
- `"single"` → One batch, then stop (good for specific targets)
- `"continuous"` → Loop forever (good for overnight discovery)
- `"targets-only"` → Just find targets, don't scan (good for planning)
