"""
Pipeline Orchestrator Daemon.

Manages the security research pipeline:
target-research -> security-research -> qa-triage

Spawns Claude Code instances in tmux sessions and monitors their progress.
Controllable via MCP tools.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


# Regex to match ANSI escape sequences (colors, cursor movement, etc.)
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


# Pipeline stage order
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
    "csrf-expert",
    "lfi-rfi-expert",
    "xxe-expert",
    "deserialization-expert",
    "logic-flaw-expert",
    "info-disclosure-expert",
    "qa-triage",
]

# Expert stages (subset of STAGE_ORDER between security-research and qa-triage)
EXPERT_STAGES = [
    "file-rce-expert",
    "sqli-expert",
    "xss-expert",
    "auth-expert",
    "object-injection-expert",
    "ssrf-expert",
    "race-condition-expert",
    "csrf-expert",
    "lfi-rfi-expert",
    "xxe-expert",
    "deserialization-expert",
    "logic-flaw-expert",
    "info-disclosure-expert",
]

# State and PID files
PIPELINE_STATE_FILENAME = "wpguard_pipeline_state.json"
PIPELINE_PID_FILENAME = "wpguard_daemon.pid"
PIPELINE_LOG_DIR = "wpguard_pipeline_logs"

# Default configuration
# NOTE: Discord notifications are handled by qa-triage agent for validated/rejected findings
# Pipeline daemon does NOT send notifications - only QA agent does via wpguard_discord_notify_finding
DEFAULT_PIPELINE_CONFIG = {
    "heartbeat_interval": 30,
    "worker_check_interval": 10,
    "max_restarts": 2,
    "expert_restarts": 2,  # Number of iterations experts run (1 = only first round, 2 = first two rounds, etc.)
    "restart_mode": "deeper",  # "deeper", "next", or "configurable"
    "target_count": 5,
    "min_installs": 500,
    "worker_timeout_minutes": 120,  # 2 hours default timeout per worker
}


class PipelineStatus(Enum):
    """Pipeline daemon status."""
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    CRASHED = "crashed"


class WorkerStatus(Enum):
    """Worker (Claude session) status."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PipelineMode(Enum):
    """Pipeline execution mode."""
    CONTINUOUS = "continuous"  # Loop forever finding new targets
    SINGLE = "single"  # One complete cycle through all targets
    TARGETS_ONLY = "targets-only"  # Just run target-research


class PipelineDaemon:
    """
    Background daemon that orchestrates the security research pipeline.

    Spawns Claude Code instances in tmux sessions for each stage,
    monitors their progress, and handles restarts/recovery.
    """

    def __init__(self, project_dir: str | Path = "."):
        """
        Initialize the pipeline daemon.

        Args:
            project_dir: Root directory of the research project
        """
        self.project_dir = Path(project_dir).resolve()
        self.state_file = self.project_dir / PIPELINE_STATE_FILENAME
        self.pid_file = self.project_dir / PIPELINE_PID_FILENAME
        self.log_dir = self.project_dir / PIPELINE_LOG_DIR

        self.running = False

    # === State Management ===

    def _default_state(self) -> dict[str, Any]:
        """Return default pipeline state structure."""
        return {
            "version": "1.0",
            "daemon": {
                "status": PipelineStatus.STOPPED.value,
                "pid": None,
                "started_at": None,
                "last_heartbeat": None,
            },
            "pipeline": {
                "mode": PipelineMode.CONTINUOUS.value,
                "current_stage": None,
                "current_plugin": None,
                "plugins_queue": [],
                "plugins_completed": [],
                "plugins_failed": [],
                "cycle_count": 0,
            },
            "workers": {
                stage: {
                    "status": WorkerStatus.IDLE.value,
                    "tmux_session": None,
                    "started_at": None,
                    "completed_at": None,
                    "timeout_at": None,
                    "restart_count": 0,
                    "last_output": None,
                    "error": None,
                }
                for stage in STAGE_ORDER
            },
            "metrics": {
                "total_plugins_scanned": 0,
                "total_findings": 0,
                "findings_validated": 0,
                "total_runtime_seconds": 0,
                "session_start": None,
            },
            "config": DEFAULT_PIPELINE_CONFIG.copy(),
        }

    def _load_state(self) -> dict[str, Any]:
        """Load pipeline state from JSON file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    state = json.load(f)
                    # Ensure all expected keys exist
                    default = self._default_state()
                    for key in default:
                        if key not in state:
                            state[key] = default[key]
                    return state
            except (json.JSONDecodeError, KeyError):
                pass
        return self._default_state()

    def _save_state(self, state: dict[str, Any]) -> None:
        """Save pipeline state atomically."""
        state["updated_at"] = datetime.utcnow().isoformat() + "Z"
        tmp_file = self.state_file.with_suffix(".tmp")
        with open(tmp_file, "w") as f:
            json.dump(state, f, indent=2)
        tmp_file.rename(self.state_file)

    # === Process Management ===

    def _process_exists(self, pid: int) -> bool:
        """Check if a process exists."""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _tmux_session_exists(self, session: str) -> bool:
        """Check if a tmux session exists."""
        result = subprocess.run(
            ["tmux", "has-session", "-t", session],
            capture_output=True,
        )
        return result.returncode == 0

    def _get_tmux_output(self, session: str, lines: int = 50, strip_ansi: bool = True) -> str:
        """Get recent output from a tmux session.

        Args:
            session: Tmux session name
            lines: Number of lines to capture
            strip_ansi: If True, strip ANSI escape codes from output

        Returns:
            Session output, optionally cleaned of ANSI codes
        """
        result = subprocess.run(
            ["tmux", "capture-pane", "-t", session, "-p", "-S", f"-{lines}"],
            capture_output=True,
            text=True,
        )
        output = result.stdout if result.returncode == 0 else ""
        if strip_ansi and output:
            output = self._strip_ansi(output)
        return output

    def _kill_tmux_session(self, session: str) -> bool:
        """Kill a tmux session."""
        result = subprocess.run(
            ["tmux", "kill-session", "-t", session],
            capture_output=True,
        )
        return result.returncode == 0

    def _kill_all_wpguard_tmux_sessions(self) -> int:
        """Kill all tmux sessions with wpguard_ prefix.

        Returns:
            Number of sessions killed
        """
        killed = 0
        try:
            # List all tmux sessions
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                sessions = result.stdout.strip().split("\n")
                for session in sessions:
                    if session.startswith("wpguard_"):
                        if self._kill_tmux_session(session):
                            killed += 1
        except subprocess.SubprocessError:
            pass
        return killed

    # === Logging ===

    def _strip_ansi(self, text: str) -> str:
        """Strip ANSI escape codes from text.

        Removes color codes, cursor movement, and other terminal control sequences
        that make log files hard to read.

        Args:
            text: Raw text potentially containing ANSI escape codes

        Returns:
            Clean text with escape codes removed
        """
        return ANSI_ESCAPE_PATTERN.sub('', text)

    def _log_error(self, message: str) -> None:
        """Log an error message to the pipeline error log file.

        Args:
            message: Error message to log
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        error_log = self.log_dir / "pipeline_errors.log"
        timestamp = datetime.utcnow().isoformat() + "Z"
        try:
            with open(error_log, "a") as f:
                f.write(f"[{timestamp}] {message}\n")
        except OSError:
            pass  # Best effort logging

    def _log_info(self, message: str) -> None:
        """Log an info message to the pipeline log file.

        Args:
            message: Info message to log
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        info_log = self.log_dir / "pipeline.log"
        timestamp = datetime.utcnow().isoformat() + "Z"
        try:
            with open(info_log, "a") as f:
                f.write(f"[{timestamp}] {message}\n")
        except OSError:
            pass  # Best effort logging

    # === Worker Management ===

    def _build_claude_command(
        self,
        stage: str,
        state: dict[str, Any],
        plugin_slug: str | None = None,
        is_resume: bool = False,
        restart_count: int = 0,
        findings_count: int = 0,
    ) -> str:
        """
        Build the Claude CLI command for a worker.

        Args:
            stage: Pipeline stage name
            state: Current pipeline state (for accessing config like target_criteria)
            plugin_slug: Plugin being analyzed (for security-research/qa-triage)
            is_resume: Whether this is a resume after context limit
            restart_count: Number of restarts so far
            findings_count: Number of findings found so far

        Returns:
            Full command string to execute
        """
        # Build initial prompt based on stage
        if stage == "target-research":
            target_criteria = state["config"].get("target_criteria")
            if target_criteria:
                initial_prompt = f"/target-research {target_criteria}"
            else:
                initial_prompt = "/target-research"
        elif stage == "security-research":
            if is_resume:
                initial_prompt = (
                    f"Resume security research for {plugin_slug}. "
                    f"This is restart #{restart_count}. "
                    f"Found {findings_count} findings so far. "
                    f"Explore different code paths than previous session. "
                    f"Check wpguard_scan_state.json for progress details."
                )
            else:
                initial_prompt = f"/security-research {plugin_slug}"
        elif stage in EXPERT_STAGES:
            # Expert agents - include restart context if on a pipeline restart cycle
            if is_resume and restart_count > 0:
                initial_prompt = (
                    f"Resume /{stage} for {plugin_slug}. "
                    f"This is pipeline restart #{restart_count}. "
                    f"Found {findings_count} findings so far. "
                    f"Focus on different attack vectors than previous runs. "
                    f"Check wpguard_findings.json to avoid duplicate findings. "
                    f"Be EXTREMELY thorough - do NOT skip anything that looks even remotely promising. "
                    f"Exhaust ALL possibilities before marking complete."
                )
            else:
                initial_prompt = (
                    f"/{stage} {plugin_slug} - "
                    f"Be EXTREMELY thorough in your analysis. "
                    f"Do NOT skip anything that looks even remotely promising. "
                    f"Exhaust ALL attack vectors and bypass techniques before marking complete."
                )
        elif stage == "qa-triage":
            initial_prompt = f"/qa-triage {plugin_slug}"
        else:
            initial_prompt = f"/{stage}"

        # Build command with explicit system prompt from template file
        # This ensures the full template is loaded for each stage
        template_file = f"./.claude/commands/{stage}.md"

        cmd_parts = [
            f"cd {self.project_dir}",
            "&&",
            "claude",
            f'--system-prompt "$(cat {template_file})"',
            "--permission-mode", "dontAsk",
            f"'{initial_prompt}'",
        ]

        return " ".join(cmd_parts)

    def _spawn_worker(self, stage: str, state: dict[str, Any]) -> str | None:
        """
        Spawn a Claude worker in a tmux session.

        Args:
            stage: Pipeline stage to spawn
            state: Current pipeline state

        Returns:
            Tmux session name if successful, None otherwise
        """
        # Generate unique session name
        session_id = uuid.uuid4().hex[:8]
        session_name = f"wpguard_{stage.replace('-', '_')}_{session_id}"

        # Ensure log directory exists (for command scripts)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Build Claude command
        plugin_slug = state["pipeline"].get("current_plugin")

        # For expert stages, use security-research's restart count (pipeline-level restart)
        # Expert stages have their own restart_count=0, but they should know about pipeline restarts
        if stage in EXPERT_STAGES:
            pipeline_restart_count = state["workers"]["security-research"]["restart_count"]
            is_resume = pipeline_restart_count > 0
            restart_count = pipeline_restart_count
        else:
            worker = state["workers"][stage]
            is_resume = worker["restart_count"] > 0
            restart_count = worker["restart_count"]

        # Get findings count for resume context
        findings_count = 0
        if is_resume and plugin_slug:
            findings_count = self._get_plugin_findings_count(plugin_slug)

        claude_cmd = self._build_claude_command(
            stage=stage,
            state=state,
            plugin_slug=plugin_slug,
            is_resume=is_resume,
            restart_count=restart_count,
            findings_count=findings_count,
        )

        # Create tmux session with proper PTY (not bash -c which breaks TUI)
        try:
            # First create the session with a regular shell
            result = subprocess.run(
                ["tmux", "new-session", "-d", "-s", session_name],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                self._log_error(f"Failed to create tmux session: {result.stderr}")
                return None

            # Write command to a temp script file to avoid quote escaping issues
            # This preserves PTY for Claude's TUI while allowing complex commands
            script_file = self.log_dir / f"{stage}_{session_id}_cmd.sh"
            script_file.write_text(f"#!/bin/bash\n{claude_cmd}\n")
            script_file.chmod(0o755)

            # Use script to maintain PTY but discard output to /dev/null
            # This avoids large binary log files while keeping proper terminal handling
            logged_cmd = f"script -q /dev/null -c '{script_file}'"
            subprocess.run(
                ["tmux", "send-keys", "-t", session_name, logged_cmd, "Enter"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            return session_name

        except subprocess.SubprocessError as e:
            self._log_error(f"Failed to spawn worker: {e}")
            return None

    def _get_plugin_findings_count(self, plugin_slug: str) -> int:
        """Get the number of findings for a plugin."""
        from wpguard.core.findings import FindingsManager
        try:
            fm = FindingsManager(str(self.project_dir))
            findings = fm.list_findings(plugin_slug=plugin_slug)
            return len(findings)
        except Exception:
            return 0

    def _get_total_findings_count(self) -> int:
        """Get the total number of all findings."""
        from wpguard.core.findings import FindingsManager
        try:
            fm = FindingsManager(str(self.project_dir))
            findings = fm.list_findings()
            return len(findings)
        except Exception:
            return 0

    def _get_validated_findings_count(self) -> int:
        """Get the number of validated findings."""
        from wpguard.core.findings import FindingsManager
        try:
            fm = FindingsManager(str(self.project_dir))
            findings = fm.list_findings(status="validated")
            return len(findings)
        except Exception:
            return 0

    def _check_worker_completion(self, stage: str, state: dict[str, Any]) -> WorkerStatus:
        """
        Check if a worker has completed its task.

        Returns:
            WorkerStatus indicating the worker's state
        """
        worker = state["workers"][stage]
        session = worker.get("tmux_session")

        if not session:
            return WorkerStatus.IDLE

        # Check for stage_completed marker FIRST (before checking session exists)
        # This allows agents to signal completion while session is still alive
        from wpguard.core.findings import FindingsManager
        try:
            fm = FindingsManager(str(self.project_dir))
            scan_state = fm.get_scan_state()

            if scan_state.get("stage_completed") == stage:
                # Agent signaled completion - kill session and clear marker
                self._kill_tmux_session(session)
                fm.update_scan_state(stage_completed="")  # Clear marker
                return WorkerStatus.COMPLETED
        except Exception:
            pass

        # Check for timeout (worker stuck too long)
        timeout_at = worker.get("timeout_at")
        if timeout_at:
            try:
                timeout_dt = datetime.fromisoformat(timeout_at.replace("Z", "+00:00"))
                now_dt = datetime.utcnow().replace(tzinfo=timeout_dt.tzinfo)
                if now_dt > timeout_dt:
                    self._log_error(f"Worker {stage} timed out (session: {session})")
                    self._kill_tmux_session(session)
                    worker["error"] = "Timeout exceeded"
                    self._save_state(state)
                    return WorkerStatus.FAILED
            except (ValueError, TypeError):
                pass

        # Check if tmux session still exists
        if self._tmux_session_exists(session):
            return WorkerStatus.RUNNING

        # Session ended on its own - determine if successful
        # Check stage-specific completion markers
        if stage == "target-research":
            # Success if plugins were added to scan state
            try:
                fm = FindingsManager(str(self.project_dir))
                scan_state = fm.get_scan_state()
                if scan_state.get("plugins_pending"):
                    self._kill_tmux_session(session)
                    return WorkerStatus.COMPLETED
            except Exception:
                pass
            return WorkerStatus.FAILED

        elif stage == "security-research":
            # Success if plugin was marked as scanned
            plugin = state["pipeline"].get("current_plugin")
            if plugin:
                try:
                    fm = FindingsManager(str(self.project_dir))
                    scan_state = fm.get_scan_state()
                    if plugin in scan_state.get("plugins_scanned", []):
                        self._kill_tmux_session(session)
                        return WorkerStatus.COMPLETED
                except Exception:
                    pass
            return WorkerStatus.FAILED

        elif stage in EXPERT_STAGES:
            # Expert stages complete when session ends (agent signals via stage_completed)
            # If session ended without signal, treat as completed (best effort)
            self._kill_tmux_session(session)
            return WorkerStatus.COMPLETED

        elif stage == "qa-triage":
            # QA stage always "completes" - findings get validated or rejected
            self._kill_tmux_session(session)
            return WorkerStatus.COMPLETED

        return WorkerStatus.FAILED

    # === Pipeline Control (Public API) ===

    def start(
        self,
        mode: str = "continuous",
        target_count: int = 5,
        restart_mode: str = "deeper",
        target_criteria: str | None = None,
        **config_overrides,
    ) -> dict[str, Any]:
        """
        Start the pipeline daemon.

        Args:
            mode: Pipeline mode (continuous, single, targets-only)
            target_count: Number of targets per cycle
            restart_mode: How to handle restarts (deeper, next, configurable)
            **config_overrides: Additional config values to override

        Returns:
            Status dict with success/error
        """
        # Check if already running
        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                if self._process_exists(pid):
                    return {
                        "success": False,
                        "error": f"Pipeline already running (PID: {pid})",
                        "pid": pid,
                    }
            except (ValueError, OSError):
                pass
            # Stale PID file - remove it
            self.pid_file.unlink()

        # Initialize state
        state = self._load_state()
        state["daemon"]["status"] = PipelineStatus.RUNNING.value
        state["daemon"]["started_at"] = datetime.utcnow().isoformat() + "Z"
        state["pipeline"]["mode"] = mode
        state["pipeline"]["current_stage"] = None
        state["config"]["target_count"] = target_count
        state["config"]["restart_mode"] = restart_mode
        state["config"]["target_criteria"] = target_criteria
        state["config"].update(config_overrides)
        state["metrics"]["session_start"] = datetime.utcnow().isoformat() + "Z"
        self._save_state(state)

        # Fork to background
        pid = os.fork()
        if pid > 0:
            # Parent process - return immediately
            # Wait a moment to ensure child starts
            time.sleep(0.5)
            return {
                "success": True,
                "message": "Pipeline daemon started",
                "pid": pid,
                "mode": mode,
                "target_count": target_count,
            }

        # Child process - become daemon
        try:
            os.setsid()
        except OSError:
            pass

        # Second fork to prevent zombie
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Daemon process
        self.pid_file.write_text(str(os.getpid()))

        # Update state with actual PID
        state = self._load_state()
        state["daemon"]["pid"] = os.getpid()
        self._save_state(state)

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Enter main loop
        self.running = True
        self._main_loop()

        return {"success": True}

    def stop(self, force: bool = False) -> dict[str, Any]:
        """
        Stop the pipeline daemon.

        Args:
            force: If True, kill immediately without cleanup

        Returns:
            Status dict
        """
        if not self.pid_file.exists():
            return {"success": False, "error": "Pipeline not running"}

        try:
            pid = int(self.pid_file.read_text().strip())
        except (ValueError, OSError) as e:
            return {"success": False, "error": f"Invalid PID file: {e}"}

        if not self._process_exists(pid):
            # Process already dead - clean up
            self.pid_file.unlink()
            state = self._load_state()
            state["daemon"]["status"] = PipelineStatus.STOPPED.value
            state["daemon"]["pid"] = None
            self._save_state(state)
            return {"success": True, "message": "Pipeline was not running (cleaned up stale state)"}

        # Send signal
        try:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        except OSError as e:
            return {"success": False, "error": f"Failed to kill process: {e}"}

        # Wait for shutdown
        for _ in range(30):
            if not self._process_exists(pid):
                break
            time.sleep(1)

        # Clean up
        if self.pid_file.exists():
            self.pid_file.unlink()

        # Kill all wpguard tmux sessions
        sessions_killed = self._kill_all_wpguard_tmux_sessions()

        state = self._load_state()
        state["daemon"]["status"] = PipelineStatus.STOPPED.value
        state["daemon"]["pid"] = None
        self._save_state(state)

        return {
            "success": True,
            "message": f"Pipeline stopped, killed {sessions_killed} tmux session(s)"
        }

    def pause(self) -> dict[str, Any]:
        """Pause the pipeline after current stage completes."""
        state = self._load_state()

        if state["daemon"]["status"] != PipelineStatus.RUNNING.value:
            return {"success": False, "error": "Pipeline not running"}

        state["daemon"]["status"] = PipelineStatus.PAUSED.value
        self._save_state(state)

        return {"success": True, "message": "Pipeline paused (will stop after current stage)"}

    def resume(self) -> dict[str, Any]:
        """Resume a paused pipeline."""
        state = self._load_state()

        if state["daemon"]["status"] != PipelineStatus.PAUSED.value:
            return {"success": False, "error": "Pipeline not paused"}

        state["daemon"]["status"] = PipelineStatus.RUNNING.value
        self._save_state(state)

        return {"success": True, "message": "Pipeline resumed"}

    def get_status(self, include_logs: bool = False) -> dict[str, Any]:
        """
        Get current pipeline status.

        Args:
            include_logs: Include recent worker output

        Returns:
            Full status dictionary
        """
        state = self._load_state()

        # Check if daemon is actually running
        if state["daemon"]["pid"]:
            if not self._process_exists(state["daemon"]["pid"]):
                state["daemon"]["status"] = PipelineStatus.CRASHED.value

        # Get recent worker output if requested
        if include_logs:
            for stage in STAGE_ORDER:
                session = state["workers"][stage].get("tmux_session")
                if session and self._tmux_session_exists(session):
                    state["workers"][stage]["last_output"] = self._get_tmux_output(session, lines=20)

        return state

    def get_config(self) -> dict[str, Any]:
        """Get current pipeline configuration."""
        state = self._load_state()
        return state.get("config", DEFAULT_PIPELINE_CONFIG.copy())

    def update_config(self, **updates) -> dict[str, Any]:
        """
        Update pipeline configuration.

        Args:
            **updates: Config values to update

        Returns:
            Updated config
        """
        state = self._load_state()

        allowed_keys = set(DEFAULT_PIPELINE_CONFIG.keys())
        for key, value in updates.items():
            if key in allowed_keys:
                state["config"][key] = value

        self._save_state(state)
        return state["config"]

    def get_worker_logs(self, stage: str, lines: int = 100, raw: bool = False) -> dict[str, Any]:
        """
        Get logs from a worker session.

        Args:
            stage: Pipeline stage
            lines: Number of lines to return
            raw: If True, return raw logs with ANSI codes; if False (default), strip them

        Returns:
            Dict with logs and status
        """
        if stage not in STAGE_ORDER:
            return {"success": False, "error": f"Invalid stage: {stage}"}

        state = self._load_state()
        worker = state["workers"][stage]
        session = worker.get("tmux_session")

        if not session:
            return {
                "success": True,
                "stage": stage,
                "status": worker["status"],
                "logs": None,
                "message": "No active session",
            }

        if not self._tmux_session_exists(session):
            return {
                "success": True,
                "stage": stage,
                "status": "ended",
                "logs": None,
                "message": f"Session {session} no longer exists",
            }

        logs = self._get_tmux_output(session, lines=lines, strip_ansi=not raw)
        return {
            "success": True,
            "stage": stage,
            "status": "running",
            "session": session,
            "logs": logs,
        }

    def get_attach_command(self, stage: str) -> dict[str, Any]:
        """
        Get the tmux attach command for a stage.

        Args:
            stage: Pipeline stage

        Returns:
            Dict with attach command
        """
        if stage not in STAGE_ORDER:
            return {"success": False, "error": f"Invalid stage: {stage}"}

        state = self._load_state()
        session = state["workers"][stage].get("tmux_session")

        if not session:
            return {"success": False, "error": f"No active session for {stage}"}

        if not self._tmux_session_exists(session):
            return {"success": False, "error": f"Session {session} no longer exists"}

        return {
            "success": True,
            "stage": stage,
            "session": session,
            "command": f"tmux attach -t {session}",
        }

    # === Signal Handlers ===

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        self.running = False

    # === Main Loop ===

    def _main_loop(self):
        """Main daemon event loop."""
        state = self._load_state()
        check_interval = state["config"].get("worker_check_interval", 10)
        heartbeat_interval = state["config"].get("heartbeat_interval", 30)
        last_heartbeat = time.time()

        while self.running:
            state = self._load_state()

            # Check if paused
            if state["daemon"]["status"] == PipelineStatus.PAUSED.value:
                time.sleep(check_interval)
                continue

            # Update heartbeat
            if time.time() - last_heartbeat > heartbeat_interval:
                state["daemon"]["last_heartbeat"] = datetime.utcnow().isoformat() + "Z"
                self._save_state(state)
                last_heartbeat = time.time()

            # Get current stage
            current_stage = state["pipeline"].get("current_stage")

            if current_stage is None:
                # Start with target research
                self._start_stage("target-research", state)
            else:
                # Check current worker status
                worker_status = self._check_worker_completion(current_stage, state)

                if worker_status == WorkerStatus.COMPLETED:
                    self._handle_stage_complete(current_stage, state)
                elif worker_status == WorkerStatus.FAILED:
                    self._handle_worker_failure(current_stage, state)
                # RUNNING - continue monitoring

            time.sleep(check_interval)

        # Cleanup on exit
        self._cleanup()

    def _start_stage(self, stage: str, state: dict[str, Any]) -> None:
        """Start a pipeline stage."""
        # Spawn worker
        session_name = self._spawn_worker(stage, state)

        if not session_name:
            self._log_error(f"Failed to spawn worker for {stage}")
            return

        # Calculate timeout
        timeout_minutes = state["config"].get("worker_timeout_minutes", 120)
        timeout_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)

        # Update state
        state["pipeline"]["current_stage"] = stage
        state["workers"][stage]["status"] = WorkerStatus.RUNNING.value
        state["workers"][stage]["tmux_session"] = session_name
        state["workers"][stage]["started_at"] = datetime.utcnow().isoformat() + "Z"
        state["workers"][stage]["timeout_at"] = timeout_at.isoformat() + "Z"
        state["workers"][stage]["completed_at"] = None
        state["workers"][stage]["error"] = None
        self._save_state(state)

    def _handle_stage_complete(self, stage: str, state: dict[str, Any]) -> None:
        """Handle successful stage completion."""
        state["workers"][stage]["status"] = WorkerStatus.COMPLETED.value
        state["workers"][stage]["completed_at"] = datetime.utcnow().isoformat() + "Z"

        # Update metrics based on completed stage
        current_plugin = state["pipeline"].get("current_plugin")
        if stage == "security-research" and current_plugin:
            state["metrics"]["total_plugins_scanned"] += 1
            # Count findings created during security research
            findings_count = self._get_plugin_findings_count(current_plugin)
            state["metrics"]["total_findings"] = max(
                state["metrics"]["total_findings"],
                self._get_total_findings_count()
            )
            self._log_info(f"Completed security-research for {current_plugin}, found {findings_count} findings")

        elif stage == "qa-triage" and current_plugin:
            # Count validated findings
            validated_count = self._get_validated_findings_count()
            state["metrics"]["findings_validated"] = validated_count
            self._log_info(f"Completed qa-triage for {current_plugin}")

        # Check for targets-only mode - stop after target-research completes
        if stage == "target-research" and state["pipeline"]["mode"] == PipelineMode.TARGETS_ONLY.value:
            state["daemon"]["status"] = PipelineStatus.STOPPED.value
            state["pipeline"]["current_stage"] = None
            self._save_state(state)
            self.running = False
            return

        # Determine next stage
        next_stage = self._get_next_stage(stage, state)

        if next_stage:
            self._start_stage(next_stage, state)
        else:
            # Cycle complete
            state["pipeline"]["cycle_count"] += 1

            mode = state["pipeline"]["mode"]
            if mode == PipelineMode.CONTINUOUS.value:
                # Start new cycle
                state["pipeline"]["current_stage"] = None
                state["pipeline"]["plugins_completed"].extend(state["pipeline"]["plugins_queue"])
                state["pipeline"]["plugins_queue"] = []
            else:
                # Single cycle complete - stop
                state["daemon"]["status"] = PipelineStatus.STOPPED.value
                self.running = False

        self._save_state(state)

    def _handle_worker_failure(self, stage: str, state: dict[str, Any]) -> None:
        """Handle worker failure with restart logic."""
        worker = state["workers"][stage]
        max_restarts = state["config"].get("max_restarts", 3)

        # Check if we should restart
        if stage == "security-research" and worker["restart_count"] < max_restarts:
            worker["restart_count"] += 1
            worker["status"] = WorkerStatus.IDLE.value

            # Restart the worker
            self._start_stage(stage, state)
            return

        # Cannot retry - mark failed
        worker["status"] = WorkerStatus.FAILED.value
        worker["error"] = "Max restarts exceeded"

        # Move to next plugin or stage
        self._skip_and_continue(stage, state)

    def _get_next_stage(self, current: str, state: dict[str, Any]) -> str | None:
        """Get the next pipeline stage."""
        if current == "target-research":
            # Load plugins from scan state
            from wpguard.core.findings import FindingsManager
            try:
                fm = FindingsManager(str(self.project_dir))
                scan_state = fm.get_scan_state()
                pending = scan_state.get("plugins_pending", [])
                if pending:
                    state["pipeline"]["plugins_queue"] = pending
                    state["pipeline"]["current_plugin"] = pending[0]
                    # Clear plugins_pending to prevent re-queuing on restart
                    fm.update_scan_state(clear_pending=True)
                    # Reset restart count for new plugin
                    state["workers"]["security-research"]["restart_count"] = 0
                    self._log_info(f"Loaded {len(pending)} plugins from target-research: {pending}")
                    return "security-research"
            except Exception as e:
                self._log_error(f"Failed to load pending plugins: {e}")
            return None

        elif current == "security-research":
            # Check if experts should run this iteration
            restart_count = state["workers"]["security-research"]["restart_count"]
            expert_restarts = state["config"].get("expert_restarts", 1)
            if restart_count < expert_restarts:
                # Run experts for first N iterations (configurable)
                return "file-rce-expert"
            else:
                # Skip experts on later restarts - they already ran enough
                return "qa-triage"

        elif current in EXPERT_STAGES:
            # Get next stage in order
            current_idx = STAGE_ORDER.index(current)
            next_idx = current_idx + 1
            if next_idx < len(STAGE_ORDER):
                return STAGE_ORDER[next_idx]
            return None

        elif current == "qa-triage":
            # Check restart mode
            restart_mode = state["config"].get("restart_mode", "deeper")
            worker = state["workers"]["security-research"]
            max_restarts = state["config"].get("max_restarts", 3)

            # Move current plugin to completed
            current_plugin = state["pipeline"].get("current_plugin")
            if current_plugin:
                if current_plugin not in state["pipeline"]["plugins_completed"]:
                    state["pipeline"]["plugins_completed"].append(current_plugin)
                if current_plugin in state["pipeline"]["plugins_queue"]:
                    state["pipeline"]["plugins_queue"].remove(current_plugin)

            # Determine if we go deeper or next
            go_deeper = False
            if restart_mode == "deeper":
                go_deeper = worker["restart_count"] < max_restarts
            elif restart_mode == "configurable":
                # Default: deeper for first 2, then next
                go_deeper = worker["restart_count"] < 2

            if go_deeper:
                # Go back to security research on same plugin
                worker["restart_count"] += 1
                state["pipeline"]["current_plugin"] = current_plugin
                return "security-research"

            # Move to next plugin
            if state["pipeline"]["plugins_queue"]:
                state["pipeline"]["current_plugin"] = state["pipeline"]["plugins_queue"][0]
                state["workers"]["security-research"]["restart_count"] = 0
                return "security-research"

            return None

        return None

    def _skip_and_continue(self, stage: str, state: dict[str, Any]) -> None:
        """Skip failed plugin and continue pipeline."""
        current_plugin = state["pipeline"].get("current_plugin")

        if current_plugin:
            # Mark as failed
            if current_plugin not in state["pipeline"]["plugins_failed"]:
                state["pipeline"]["plugins_failed"].append(current_plugin)
            if current_plugin in state["pipeline"]["plugins_queue"]:
                state["pipeline"]["plugins_queue"].remove(current_plugin)

        # Try next plugin
        if state["pipeline"]["plugins_queue"]:
            state["pipeline"]["current_plugin"] = state["pipeline"]["plugins_queue"][0]
            state["workers"]["security-research"]["restart_count"] = 0
            self._start_stage("security-research", state)
        else:
            # No more plugins
            state["pipeline"]["current_stage"] = None
            state["pipeline"]["current_plugin"] = None

        self._save_state(state)

    def _cleanup(self) -> None:
        """Cleanup on daemon exit."""
        state = self._load_state()

        # Kill any running workers
        for stage in STAGE_ORDER:
            session = state["workers"][stage].get("tmux_session")
            if session and self._tmux_session_exists(session):
                self._kill_tmux_session(session)

        # Update state
        state["daemon"]["status"] = PipelineStatus.STOPPED.value
        state["daemon"]["pid"] = None
        self._save_state(state)

        # Remove PID file
        if self.pid_file.exists():
            self.pid_file.unlink()


# Convenience functions for MCP tools

def get_pipeline(project_dir: str = ".") -> PipelineDaemon:
    """Get a PipelineDaemon instance for a project directory."""
    return PipelineDaemon(project_dir)
