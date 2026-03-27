"""
Audit History Manager.

Tracks which plugins/themes have been audited, their versions,
and iteration count to prevent redundant re-audits.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wpguard.config import DEFAULT_OUTPUT_DIR


AUDIT_HISTORY_FILENAME = "wpguard_audit_history.json"


class AuditHistoryManager:
    """Manages persistent audit history."""

    def __init__(self, output_dir: str | None = None):
        self.output_dir = Path(output_dir or DEFAULT_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.output_dir / AUDIT_HISTORY_FILENAME
        self._history: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        """Load audit history from JSON file."""
        if self.history_file.exists():
            try:
                with open(self.history_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"version": "1.0", "audits": {}}

    def _save(self) -> None:
        """Save audit history to JSON file."""
        self._history["updated_at"] = datetime.now(timezone.utc).isoformat()
        with open(self.history_file, "w") as f:
            json.dump(self._history, f, indent=2)

    def record_audit(
        self,
        slug: str,
        version: str,
        asset_type: str = "plugin",
        active_installs: int = 0,
        findings_count: int = 0,
        validated_count: int = 0,
        status: str = "completed",
        notes: str = "",
    ) -> dict[str, Any]:
        """
        Record an audit in the history.

        Args:
            slug: Plugin or theme slug
            version: Version that was audited
            asset_type: "plugin" or "theme"
            active_installs: Active installations at time of audit
            findings_count: Total findings discovered
            validated_count: Validated findings count
            status: Audit status (completed, partial, skipped)
            notes: Optional notes about the audit

        Returns:
            The audit record
        """
        audits = self._history["audits"]
        now = datetime.now(timezone.utc).isoformat()

        if slug not in audits:
            audits[slug] = {
                "type": asset_type,
                "iterations": 0,
                "versions_audited": [],
                "first_audited": now,
                "last_audited": now,
                "total_findings": 0,
                "total_validated": 0,
                "history": [],
            }

        record = audits[slug]
        record["iterations"] += 1
        record["last_audited"] = now
        record["total_findings"] += findings_count
        record["total_validated"] += validated_count

        if version not in record["versions_audited"]:
            record["versions_audited"].append(version)

        # Append iteration entry
        entry = {
            "iteration": record["iterations"],
            "version": version,
            "active_installs": active_installs,
            "findings": findings_count,
            "validated": validated_count,
            "status": status,
            "date": now,
        }
        if notes:
            entry["notes"] = notes

        record["history"].append(entry)

        self._save()
        return record

    def check_audit(self, slug: str) -> dict[str, Any]:
        """
        Check if a slug has been audited before.

        Args:
            slug: Plugin or theme slug

        Returns:
            Audit record or indication that it hasn't been audited
        """
        record = self._history["audits"].get(slug)
        if not record:
            return {
                "previously_audited": False,
                "slug": slug,
            }

        return {
            "previously_audited": True,
            "slug": slug,
            "type": record["type"],
            "iterations": record["iterations"],
            "versions_audited": record["versions_audited"],
            "last_audited": record["last_audited"],
            "total_findings": record["total_findings"],
            "total_validated": record["total_validated"],
            "last_entry": record["history"][-1] if record["history"] else None,
        }

    def list_audits(
        self,
        asset_type: str | None = None,
        min_iterations: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        List all audited slugs with summary info.

        Args:
            asset_type: Filter by "plugin" or "theme"
            min_iterations: Minimum number of audit iterations

        Returns:
            List of audit summaries sorted by last_audited desc
        """
        results = []
        for slug, record in self._history["audits"].items():
            if asset_type and record.get("type") != asset_type:
                continue
            if min_iterations and record["iterations"] < min_iterations:
                continue

            results.append({
                "slug": slug,
                "type": record.get("type", "plugin"),
                "iterations": record["iterations"],
                "versions_audited": record["versions_audited"],
                "last_audited": record["last_audited"],
                "total_findings": record["total_findings"],
                "total_validated": record["total_validated"],
            })

        results.sort(key=lambda r: r["last_audited"], reverse=True)
        return results

    def get_stats(self) -> dict[str, Any]:
        """Get audit history statistics."""
        audits = self._history["audits"]
        total_plugins = sum(1 for r in audits.values() if r.get("type") == "plugin")
        total_themes = sum(1 for r in audits.values() if r.get("type") == "theme")
        total_iterations = sum(r["iterations"] for r in audits.values())
        total_findings = sum(r["total_findings"] for r in audits.values())
        total_validated = sum(r["total_validated"] for r in audits.values())

        return {
            "total_audited": len(audits),
            "total_plugins": total_plugins,
            "total_themes": total_themes,
            "total_iterations": total_iterations,
            "total_findings": total_findings,
            "total_validated": total_validated,
        }
