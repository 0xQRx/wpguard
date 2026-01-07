# Pipeline Enhancements Specification

## Overview
Improvements to the wpguard pipeline daemon for better automation, reliability, and efficiency.

---

## 1. Auto-Continue from Pending Queue

### Problem
Pipeline stops after completing initial targets even when `plugins_pending` in scan_state has entries. Requires manual restart with new `target_criteria`.

### Solution
Add `source` parameter to `wpguard_pipeline_start` that reads from pending queue.

### API Changes

```python
wpguard_pipeline_start(
    mode: str = "continuous",  # existing
    source: str = "target_criteria",  # NEW: "target_criteria" | "pending_queue" | "both"
    target_criteria: str = None,  # existing
    ...
)
```

### Behavior

| source | Behavior |
|--------|----------|
| `target_criteria` | Current behavior - use target_criteria param |
| `pending_queue` | Read slugs from `wpguard_scan_state.json` → `plugins_pending` |
| `both` | Merge target_criteria slugs + pending_queue (deduplicated) |

### Implementation

```python
# In pipeline daemon startup
def get_target_plugins(config):
    plugins = []

    if config.source in ("target_criteria", "both"):
        if config.target_criteria and config.target_criteria.startswith("slugs:"):
            plugins.extend(config.target_criteria.split(":")[1].split(","))

    if config.source in ("pending_queue", "both"):
        scan_state = load_scan_state()
        plugins.extend(scan_state.get("plugins_pending", []))

    # Deduplicate while preserving order
    seen = set()
    return [p for p in plugins if not (p in seen or seen.add(p))]
```

### State File Updates
After pipeline processes a plugin from pending_queue:
```python
def on_plugin_complete(slug):
    scan_state = load_scan_state()
    if slug in scan_state["plugins_pending"]:
        scan_state["plugins_pending"].remove(slug)
    if slug not in scan_state["plugins_scanned"]:
        scan_state["plugins_scanned"].append(slug)
    save_scan_state(scan_state)
```

---

## 2. Skip Target-Research for Explicit Slugs

### Problem
When `target_criteria="slugs:plugin1,plugin2"` is provided, target-research stage still runs but is redundant - it just validates the slugs exist.

### Solution
Auto-detect explicit slugs and skip target-research stage.

### Implementation

```python
# In pipeline stage sequencing
def get_next_stage(current_stage, config):
    stages = [
        "target-research",
        "security-research",
        "file-rce-expert",
        # ... rest of stages
    ]

    # Skip target-research if explicit slugs provided
    if current_stage is None:  # Starting pipeline
        if config.target_criteria and config.target_criteria.startswith("slugs:"):
            # Parse slugs directly, skip target-research
            slugs = config.target_criteria.split(":")[1].split(",")
            add_to_queue(slugs)
            return "security-research"  # Skip to security-research
        elif config.source == "pending_queue":
            # Already have slugs from pending queue
            return "security-research"

    # Normal stage progression
    current_idx = stages.index(current_stage)
    return stages[current_idx + 1] if current_idx < len(stages) - 1 else None
```

### Config Option
```python
wpguard_pipeline_config(
    skip_target_research_for_explicit_slugs: bool = True  # Default: True
)
```

---

## 3. Persistent Logging

### Problem
Tmux sessions end after stage completes, logs are lost. Can't debug failures or review what happened.

### Solution
Write all worker output to persistent log files.

### Directory Structure
```
wpguard_pipeline_logs/
├── 2026-01-02_04-04-55/           # Session timestamp
│   ├── pipeline_daemon.log        # Main daemon log
│   ├── target-research.log
│   ├── security-research_chatbot.log
│   ├── security-research_plugin2.log
│   ├── sqli-expert_chatbot.log
│   └── ...
└── latest -> 2026-01-02_04-04-55/  # Symlink to latest session
```

### Implementation

```python
import logging
from datetime import datetime

class PipelineLogger:
    def __init__(self, output_dir: str):
        self.session_dir = Path(output_dir) / "wpguard_pipeline_logs" / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir.mkdir(parents=True, exist_ok=True)

        # Update 'latest' symlink
        latest = self.session_dir.parent / "latest"
        if latest.is_symlink():
            latest.unlink()
        latest.symlink_to(self.session_dir.name)

    def get_logger(self, stage: str, plugin: str = None) -> logging.Logger:
        name = f"{stage}_{plugin}" if plugin else stage
        log_file = self.session_dir / f"{name}.log"

        logger = logging.getLogger(name)
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s'
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger
```

### Tmux Integration
Capture tmux pane output to log file:
```bash
# When spawning worker
tmux pipe-pane -o -t "$SESSION_NAME" "cat >> $LOG_FILE"
```

### MCP Tool Update
```python
wpguard_pipeline_logs(
    stage: str,
    plugin: str = None,  # NEW: filter by plugin
    lines: int = 100,
    session: str = "latest",  # NEW: "latest" or timestamp
    persistent: bool = True  # NEW: read from file instead of tmux
)
```

---

## 4. Pipeline Health Monitoring

### Problem
No visibility into pipeline health, resource usage, or stuck workers.

### Solution
Add health metrics and auto-recovery.

### New MCP Tool
```python
wpguard_pipeline_health() -> dict:
    """
    Returns:
    {
        "status": "healthy" | "degraded" | "unhealthy",
        "uptime_seconds": 3600,
        "memory_usage_mb": 512,
        "active_workers": 1,
        "stuck_workers": [],  # Workers not progressing for >10 min
        "failed_stages": [],
        "recommendations": [
            "Worker sqli-expert appears stuck (no output for 15 min)",
            "Memory usage high (>1GB), consider restarting"
        ]
    }
    """
```

### Auto-Recovery Config
```python
wpguard_pipeline_config(
    auto_restart_stuck_workers: bool = True,
    stuck_threshold_minutes: int = 30,
    max_worker_restarts: int = 2,
    auto_heal_sandbox: bool = True  # Restart sandbox if unhealthy
)
```

### Implementation
```python
async def monitor_worker_health(worker):
    last_output_time = worker.last_output_time
    now = datetime.now()

    if (now - last_output_time).seconds > config.stuck_threshold_minutes * 60:
        if worker.restart_count < config.max_worker_restarts:
            logger.warning(f"Worker {worker.stage} stuck, restarting...")
            await restart_worker(worker)
        else:
            logger.error(f"Worker {worker.stage} stuck, max restarts exceeded")
            await fail_worker(worker)
```

---

## 5. Graceful Shutdown and Resume

### Problem
If pipeline is interrupted (system restart, manual stop), progress is lost.

### Solution
Checkpoint progress and support resume.

### Checkpoint Data
```json
{
    "session_id": "2026-01-02_04-04-55",
    "current_plugin": "chatbot",
    "current_stage": "sqli-expert",
    "completed_stages": ["target-research", "security-research", "file-rce-expert"],
    "iteration": 1,
    "plugins_remaining": ["cf7-cost-calculator", "wpdm-gutenberg-blocks"],
    "checkpoint_time": "2026-01-02T04:30:00Z"
}
```

### Resume Command
```python
wpguard_pipeline_resume(
    session_id: str = "latest",  # Resume from checkpoint
    skip_current_stage: bool = False  # Restart current stage or skip it
)
```

### Implementation
```python
def save_checkpoint():
    checkpoint = {
        "session_id": session_id,
        "current_plugin": state.current_plugin,
        "current_stage": state.current_stage,
        "completed_stages": state.completed_stages,
        "iteration": state.iteration,
        "plugins_remaining": state.plugins_queue,
        "checkpoint_time": datetime.now().isoformat()
    }
    Path("wpguard_checkpoint.json").write_text(json.dumps(checkpoint, indent=2))

# Save checkpoint after each stage completes
def on_stage_complete(stage):
    save_checkpoint()
    proceed_to_next_stage()
```

---

## Testing Requirements

1. Unit tests for queue merging logic
2. Integration test: start with pending_queue source
3. Integration test: resume from checkpoint
4. Stress test: 20+ plugins in queue
5. Test log persistence across daemon restart
