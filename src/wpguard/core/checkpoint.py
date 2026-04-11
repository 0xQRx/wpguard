"""
Agent checkpoint system — server-side progress accumulation.

Reduces friction from "write a markdown document" to "pass arrays to a tool call."
Persists progress on every call so partial state survives context exhaustion.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CheckpointManager:
    """Accumulates and persists agent progress across checkpoint calls."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = Path(output_dir)

    def _state_path(self, plugin_slug: str, agent_name: str) -> Path:
        return self.output_dir / "reports" / plugin_slug / f"checkpoint_{agent_name}.json"

    def _md_path(self, plugin_slug: str, agent_name: str) -> Path:
        return self.output_dir / "reports" / plugin_slug / f"progress_{agent_name}.md"

    def _load(self, plugin_slug: str, agent_name: str) -> dict[str, Any]:
        path = self._state_path(plugin_slug, agent_name)
        if path.exists():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save(self, state: dict[str, Any]) -> None:
        slug = state["plugin_slug"]
        agent = state["agent_name"]
        path = self._state_path(slug, agent)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2))
        # Also render markdown
        self._render_md(state)

    def _render_md(self, state: dict[str, Any]) -> None:
        slug = state["plugin_slug"]
        agent = state["agent_name"]
        md_path = self._md_path(slug, agent)

        lines = [
            f"# Progress Report: {agent} on {slug}\n",
            "## Session Info",
            f"- Started: {state.get('started_at', 'unknown')}",
            f"- Last checkpoint: {state.get('updated_at', 'unknown')}",
            f"- Checkpoints: {state.get('tool_calls', 0)}",
            f"- Status: {state.get('status', 'unknown')}\n",
        ]

        analyzed = state.get("files_analyzed", [])
        if analyzed:
            lines.append(f"## Files Analyzed ({len(analyzed)})")
            for f in analyzed:
                lines.append(f"- [x] {f}")
            lines.append("")

        partial = state.get("files_partial", [])
        if partial:
            lines.append(f"## Files Partial ({len(partial)})")
            for f in partial:
                lines.append(f"- [~] {f}")
            lines.append("")

        remaining = state.get("files_remaining", [])
        if remaining:
            lines.append(f"## Remaining Work ({len(remaining)})")
            for f in remaining:
                lines.append(f"- [ ] {f}")
            lines.append("")

        findings = state.get("findings_created", [])
        if findings:
            lines.append("## Findings Created")
            for fid in findings:
                lines.append(f"- {fid}")
            lines.append("")

        notes = state.get("notes", [])
        if notes:
            lines.append("## Notes")
            for note in notes:
                lines.append(f"- {note}")
            lines.append("")

        md_path.write_text("\n".join(lines))

    def _urgency(self, tool_calls: int) -> dict[str, str]:
        if tool_calls >= 9:
            return {
                "urgency": "high",
                "message": "⚠️ Near context limit. Save ALL findings NOW. Create drafts for promising leads. Call checkpoint(action='partial') with files_remaining.",
            }
        elif tool_calls >= 6:
            return {
                "urgency": "moderate",
                "message": f"~{tool_calls * 10}% of typical agent budget used. Consider saving findings soon.",
            }
        return {"urgency": "normal", "message": ""}

    def start(
        self,
        agent_name: str,
        plugin_slug: str,
        priority_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Initialize or resume an agent session."""
        existing = self._load(plugin_slug, agent_name)
        now = datetime.now(timezone.utc).isoformat()

        if existing and existing.get("status") in ("active", "partial"):
            # Resume from previous state
            existing["updated_at"] = now
            existing["tool_calls"] = existing.get("tool_calls", 0) + 1
            existing["status"] = "active"
            self._save(existing)
            return {
                "resumed": True,
                "state": existing,
                **self._urgency(existing["tool_calls"]),
            }

        # New session
        state = {
            "agent_name": agent_name,
            "plugin_slug": plugin_slug,
            "started_at": now,
            "updated_at": now,
            "tool_calls": 1,
            "files_analyzed": [],
            "files_partial": [],
            "files_remaining": priority_targets or [],
            "findings_created": [],
            "notes": [],
            "status": "active",
        }
        self._save(state)
        return {
            "resumed": False,
            "state": state,
            **self._urgency(1),
        }

    def progress(
        self,
        agent_name: str,
        plugin_slug: str,
        files_analyzed: list[str] | None = None,
        files_partial: list[str] | None = None,
        files_remaining: list[str] | None = None,
        findings_created: list[str] | None = None,
        notes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Save incremental progress. Accumulates state server-side."""
        state = self._load(plugin_slug, agent_name)
        if not state:
            # Auto-start if no session exists
            return self.start(agent_name, plugin_slug)

        now = datetime.now(timezone.utc).isoformat()
        state["updated_at"] = now
        state["tool_calls"] = state.get("tool_calls", 0) + 1

        # Accumulate — union for analyzed, append for notes
        if files_analyzed:
            existing = set(state.get("files_analyzed", []))
            existing.update(files_analyzed)
            state["files_analyzed"] = sorted(existing)
            # Remove from remaining if present
            if state.get("files_remaining"):
                state["files_remaining"] = [f for f in state["files_remaining"] if f not in existing]

        if files_partial:
            existing = set(state.get("files_partial", []))
            existing.update(files_partial)
            # Don't include files that are fully analyzed
            analyzed_set = set(state.get("files_analyzed", []))
            state["files_partial"] = sorted(existing - analyzed_set)

        if files_remaining is not None:
            # Replace remaining list (agent has better visibility)
            state["files_remaining"] = files_remaining

        if findings_created:
            existing = set(state.get("findings_created", []))
            existing.update(findings_created)
            state["findings_created"] = sorted(existing)

        if notes:
            state.setdefault("notes", []).extend(notes)

        self._save(state)
        return {
            "state": state,
            **self._urgency(state["tool_calls"]),
        }

    def complete(
        self,
        agent_name: str,
        plugin_slug: str,
        notes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Mark agent session as complete."""
        state = self._load(plugin_slug, agent_name)
        if not state:
            state = {"agent_name": agent_name, "plugin_slug": plugin_slug}

        state["status"] = "complete"
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["tool_calls"] = state.get("tool_calls", 0) + 1
        if notes:
            state.setdefault("notes", []).extend(notes)

        self._save(state)
        return {"state": state}

    def partial(
        self,
        agent_name: str,
        plugin_slug: str,
        files_remaining: list[str] | None = None,
        notes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Mark agent session as partial (ran out of context)."""
        state = self._load(plugin_slug, agent_name)
        if not state:
            state = {"agent_name": agent_name, "plugin_slug": plugin_slug}

        state["status"] = "partial"
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["tool_calls"] = state.get("tool_calls", 0) + 1
        if files_remaining is not None:
            state["files_remaining"] = files_remaining
        if notes:
            state.setdefault("notes", []).extend(notes)

        self._save(state)
        return {"state": state}
