# Process Management Specification

## Overview
Tools for managing wpguard processes, memory cleanup, and automated health monitoring.

---

## 1. Stale Process Cleanup

### Problem
Multiple wpguard-mcp processes accumulate over time, consuming RAM (2GB+ observed).

### Solution
New MCP tool to identify and cleanup stale processes.

### New MCP Tool

```python
wpguard_cleanup_processes(
    max_age_hours: float = 2.0,  # Kill processes older than this
    dry_run: bool = False,  # Preview without killing
    force: bool = False  # Kill even if appears active
) -> dict:
    """
    Clean up stale wpguard processes.

    Returns:
    {
        "success": true,
        "processes_found": 16,
        "processes_killed": 12,
        "memory_freed_mb": 2048,
        "active_preserved": [
            {"pid": 12345, "age_hours": 0.5, "status": "active"}
        ],
        "killed": [
            {"pid": 11111, "age_hours": 5.2, "memory_mb": 180}
        ]
    }
    """
```

### Implementation

```python
import psutil
from datetime import datetime, timedelta

def cleanup_processes(max_age_hours: float = 2.0, dry_run: bool = False) -> dict:
    results = {
        "processes_found": 0,
        "processes_killed": 0,
        "memory_freed_mb": 0,
        "active_preserved": [],
        "killed": []
    }

    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'memory_info']):
        try:
            # Check if wpguard-related process
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'wpguard' not in cmdline and 'wpguard-mcp' not in proc.info['name']:
                continue

            results["processes_found"] += 1

            create_time = datetime.fromtimestamp(proc.info['create_time'])
            age_hours = (datetime.now() - create_time).total_seconds() / 3600
            memory_mb = proc.info['memory_info'].rss / (1024 * 1024)

            proc_info = {
                "pid": proc.info['pid'],
                "age_hours": round(age_hours, 2),
                "memory_mb": round(memory_mb, 2)
            }

            # Check if process is stale
            if create_time < cutoff_time:
                if not dry_run:
                    proc.kill()
                results["killed"].append(proc_info)
                results["processes_killed"] += 1
                results["memory_freed_mb"] += memory_mb
            else:
                proc_info["status"] = "active"
                results["active_preserved"].append(proc_info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    results["memory_freed_mb"] = round(results["memory_freed_mb"], 2)
    return results
```

---

## 2. Resource Status Monitor

### Problem
No visibility into resource usage during long-running pipelines.

### Solution
New MCP tool to check resource status.

### New MCP Tool

```python
wpguard_resource_status() -> dict:
    """
    Get current resource usage for wpguard processes.

    Returns:
    {
        "summary": {
            "total_processes": 5,
            "total_memory_mb": 850,
            "total_cpu_percent": 25.5
        },
        "processes": [
            {
                "pid": 12345,
                "type": "pipeline_daemon",
                "memory_mb": 150,
                "cpu_percent": 5.2,
                "age_hours": 1.5,
                "status": "running"
            },
            {
                "pid": 12346,
                "type": "security_research_worker",
                "memory_mb": 400,
                "cpu_percent": 15.0,
                "age_hours": 0.5,
                "status": "running"
            }
        ],
        "system": {
            "total_memory_mb": 16384,
            "available_memory_mb": 8192,
            "memory_percent": 50.0
        },
        "recommendations": [
            "Memory usage normal",
            "Consider cleanup after pipeline completes"
        ]
    }
    """
```

---

## 3. Pipeline Health Observer Agent

### Problem
Pipeline can stall, workers can hang, sessions can run out of context. No automated monitoring.

### Solution
Health observer agent that runs every 5 minutes to check pipeline health and take corrective action.

### New Slash Command: `/pipeline-health-observer`

```markdown
# Pipeline Health Observer Agent

You are a health monitoring agent for the wpguard security research pipeline.
Your job is to quickly check the health of the running pipeline and take corrective action if needed.

## Checks to Perform

1. **Session Health**
   - Check if current worker tmux session exists
   - Verify session has available context (run /usage if possible)
   - Check if session is responsive

2. **Worker Progress**
   - Get last output timestamp from worker
   - Check if worker has been stuck for >15 minutes
   - Verify worker is making progress

3. **Resource Health**
   - Check memory usage of wpguard processes
   - Verify sandbox is accessible
   - Check disk space

4. **Pipeline State**
   - Verify daemon is running
   - Check for error states
   - Verify queue is being processed

## Actions to Take

Based on health check results:

1. **Healthy**: Log status, terminate immediately
2. **Worker Stuck**: Restart current worker, continue
3. **Session Out of Context**: Force terminate worker, signal for restart
4. **Sandbox Unhealthy**: Restart sandbox, pause pipeline
5. **Memory Critical**: Cleanup stale processes
6. **Daemon Dead**: Alert and terminate

## Timeout

This agent MUST complete within 60 seconds. If checks take longer, terminate with partial results.

## Output Format

Report findings concisely:
```
HEALTH CHECK: 2026-01-02 04:15:00
Pipeline: RUNNING (chatbot, security-research)
Worker: HEALTHY (last output 2m ago)
Resources: OK (850MB memory)
Sandbox: OK (response 150ms)
Action: NONE
```

## Self-Termination

After completing checks and any corrective actions, immediately terminate.
Use `wpguard_scan_state(stage_completed="health-check")` to signal completion.
```

### Implementation: Daemon Integration

```python
import asyncio
from datetime import datetime, timedelta

class HealthObserver:
    def __init__(self, pipeline_daemon):
        self.daemon = pipeline_daemon
        self.check_interval = 300  # 5 minutes
        self.worker_stuck_threshold = 900  # 15 minutes
        self.observer_timeout = 60  # 1 minute max

    async def start(self):
        """Start periodic health checks."""
        while self.daemon.is_running():
            await asyncio.sleep(self.check_interval)
            await self.run_health_check()

    async def run_health_check(self):
        """Spawn health observer agent."""
        logger.info("Starting health observer check...")

        # Create tmux session for observer
        session_name = f"wpguard_health_observer_{uuid4().hex[:8]}"

        try:
            # Spawn observer with timeout
            result = await asyncio.wait_for(
                self._spawn_observer(session_name),
                timeout=self.observer_timeout
            )

            # Process results
            await self._handle_results(result)

        except asyncio.TimeoutError:
            logger.warning("Health observer timed out, force terminating")
            await self._kill_session(session_name)

        finally:
            # Always cleanup observer session
            await self._cleanup_session(session_name)

    async def _spawn_observer(self, session_name: str) -> dict:
        """Spawn Claude Code with health observer prompt."""
        cmd = f"""
        tmux new-session -d -s {session_name} \
        'claude --prompt "/pipeline-health-observer" --max-turns 5 --timeout 55'
        """
        await run_command(cmd)

        # Wait for completion signal
        while True:
            state = await load_scan_state()
            if state.get("stage_completed") == "health-check":
                break
            await asyncio.sleep(5)

        return await self._read_observer_output(session_name)

    async def _handle_results(self, result: dict):
        """Take action based on health check results."""
        if result.get("action") == "restart_worker":
            await self.daemon.restart_current_worker()
        elif result.get("action") == "restart_sandbox":
            await sandbox_restart()
            await self.daemon.pause()
        elif result.get("action") == "cleanup_memory":
            await cleanup_processes(max_age_hours=2)
        elif result.get("action") == "alert_daemon_dead":
            logger.critical("Pipeline daemon reported dead!")
            # Send Discord alert
            await discord_send_message("ALERT: Pipeline daemon died!")
```

### Health Check Logic

```python
async def perform_health_checks() -> dict:
    checks = {}
    action = "none"

    # 1. Check worker session
    pipeline_status = await get_pipeline_status()
    current_stage = pipeline_status["pipeline"]["current_stage"]
    worker = pipeline_status["workers"].get(current_stage, {})

    if worker.get("status") == "running":
        session = worker.get("tmux_session")
        if session:
            # Check if session exists
            session_exists = await check_tmux_session(session)
            checks["session_exists"] = session_exists

            if session_exists:
                # Check last output time
                last_output = worker.get("last_output_time")
                if last_output:
                    age = (datetime.now() - last_output).total_seconds()
                    checks["last_output_age_seconds"] = age
                    if age > 900:  # 15 minutes
                        action = "restart_worker"
                        checks["worker_stuck"] = True

    # 2. Check resources
    resource_status = await get_resource_status()
    checks["memory_mb"] = resource_status["summary"]["total_memory_mb"]
    if resource_status["system"]["memory_percent"] > 90:
        action = "cleanup_memory"
        checks["memory_critical"] = True

    # 3. Check sandbox
    try:
        sandbox_status = await sandbox_health_check()
        checks["sandbox_healthy"] = sandbox_status["healthy"]
        if not sandbox_status["healthy"]:
            action = "restart_sandbox"
    except:
        checks["sandbox_healthy"] = False
        action = "restart_sandbox"

    # 4. Check daemon
    checks["daemon_running"] = pipeline_status["daemon"]["status"] == "running"
    if not checks["daemon_running"]:
        action = "alert_daemon_dead"

    return {
        "timestamp": datetime.now().isoformat(),
        "checks": checks,
        "action": action,
        "healthy": action == "none"
    }
```

### Config Options

```python
wpguard_pipeline_config(
    health_observer_enabled: bool = True,  # NEW
    health_check_interval_minutes: int = 5,  # NEW
    worker_stuck_threshold_minutes: int = 15,  # NEW
    auto_restart_stuck_workers: bool = True,  # NEW
    health_observer_timeout_seconds: int = 60  # NEW
)
```

---

## 4. Tmux Session Monitor

### Problem
Can't easily see what's happening in worker sessions.

### Solution
Tool to capture recent output from tmux sessions.

### New MCP Tool

```python
wpguard_session_output(
    session_name: str = None,  # Specific session or current worker
    lines: int = 50,
    since: str = None  # ISO timestamp
) -> dict:
    """
    Get recent output from tmux session.

    Returns:
    {
        "session": "wpguard_security_research_abc123",
        "status": "running",
        "lines": [
            {"timestamp": "2026-01-02T04:15:00", "content": "Analyzing plugin..."},
            {"timestamp": "2026-01-02T04:15:05", "content": "Found potential SQLi..."}
        ],
        "last_activity": "2026-01-02T04:15:30"
    }
    """
```

---

## 5. Auto-Cleanup on Pipeline Complete

### Problem
After pipeline completes, processes and temp files accumulate.

### Solution
Automatic cleanup when pipeline finishes.

### Implementation

```python
async def on_pipeline_complete():
    """Cleanup after pipeline finishes."""
    logger.info("Pipeline complete, running cleanup...")

    # Kill all worker sessions
    for stage in PIPELINE_STAGES:
        session = state["workers"][stage].get("tmux_session")
        if session:
            await kill_tmux_session(session)

    # Cleanup old log files (keep last 5 sessions)
    await cleanup_old_logs(keep_sessions=5)

    # Cleanup stale processes
    await cleanup_processes(max_age_hours=0.5)

    # Optional: Uninstall all plugins from sandbox
    if config.cleanup_sandbox_on_complete:
        await sandbox_wp_cli("plugin deactivate --all")
        await sandbox_wp_cli("plugin delete --all")

    logger.info("Cleanup complete")
```

---

## 6. Kill Specific Worker

### Problem
Sometimes need to kill a specific stuck worker without stopping entire pipeline.

### New MCP Tool

```python
wpguard_kill_worker(
    stage: str,  # Stage name (e.g., "sqli-expert")
    restart: bool = False  # Restart after killing
) -> dict:
    """
    Kill a specific pipeline worker.

    Returns:
    {
        "success": true,
        "stage": "sqli-expert",
        "session_killed": "wpguard_sqli_expert_abc123",
        "restarted": false
    }
    """
```

---

## Testing Requirements

1. Test process cleanup with various age thresholds
2. Test health observer timeout behavior
3. Test auto-restart of stuck workers
4. Test memory threshold detection
5. Integration test: full health check cycle
6. Test observer self-termination
