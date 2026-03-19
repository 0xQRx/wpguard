"""
Findings Persistence Manager.

Manages storage and retrieval of security vulnerability findings in JSON format.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from wpguard.config import DEFAULT_OUTPUT_DIR
from wpguard.core.models import Finding


FINDINGS_FILENAME = "wpguard_findings.json"


class FindingsManager:
    """Manages persistence of security findings."""

    def __init__(self, output_dir: str | None = None):
        """
        Initialize the findings manager.

        Args:
            output_dir: Directory for storing findings (default from config)
        """
        self.output_dir = Path(output_dir or DEFAULT_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings_file = self.output_dir / FINDINGS_FILENAME

        # Load existing findings
        self._findings: dict[str, Finding] = {}
        self._load_findings()

    def _load_findings(self) -> None:
        """Load findings from JSON file."""
        if self.findings_file.exists():
            try:
                with open(self.findings_file, "r") as f:
                    data = json.load(f)
                    for finding_data in data.get("findings", []):
                        finding = Finding.from_dict(finding_data)
                        self._findings[finding.id] = finding
            except (json.JSONDecodeError, KeyError):
                self._findings = {}

    def _save_findings(self) -> None:
        """Save findings to JSON file."""
        data = {
            "version": "1.0",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(self._findings),
            "findings": [f.to_dict() for f in self._findings.values()],
        }
        with open(self.findings_file, "w") as f:
            json.dump(data, f, indent=2)

    def create_finding(
        self,
        plugin_slug: str,
        plugin_version: str,
        active_installs: int,
        vuln_type: str,
        title: str,
        description: str,
        auth_level: str,
        cvss_score: float,
        cvss_vector: str,
        affected_file: str,
        affected_function: str = "",
        affected_line: int = 0,
        poc_path: str = "",
        tier: str = "",
    ) -> Finding:
        """
        Create a new finding.

        Args:
            plugin_slug: Plugin slug
            plugin_version: Plugin version
            active_installs: Number of active installations
            vuln_type: Vulnerability type
            title: Finding title
            description: Detailed description
            auth_level: Required authentication level
            cvss_score: CVSS 3.1 score
            cvss_vector: CVSS vector string
            affected_file: Path to affected file
            affected_function: Name of affected function
            affected_line: Line number
            poc_path: Path to PoC script
            tier: Bounty tier

        Returns:
            Created Finding object
        """
        finding_id = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat() + "Z"

        finding = Finding(
            id=finding_id,
            plugin_slug=plugin_slug,
            plugin_version=plugin_version,
            active_installs=active_installs,
            vuln_type=vuln_type,
            title=title,
            description=description,
            auth_level=auth_level,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_file=affected_file,
            affected_function=affected_function,
            affected_line=affected_line,
            poc_path=poc_path,
            status="draft",
            tier=tier,
            created_at=now,
            updated_at=now,
        )

        self._findings[finding_id] = finding
        self._save_findings()

        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        """
        Get a finding by ID.

        Args:
            finding_id: Finding ID

        Returns:
            Finding object or None if not found
        """
        return self._findings.get(finding_id)

    def update_finding(
        self,
        finding_id: str,
        status: str | None = None,
        validation_notes: str | None = None,
        submission_id: str | None = None,
        poc_path: str | None = None,
        **kwargs: Any,
    ) -> Finding | None:
        """
        Update a finding.

        Args:
            finding_id: Finding ID to update
            status: New status
            validation_notes: Validation notes
            submission_id: Submission ID if submitted
            poc_path: Path to PoC
            **kwargs: Additional fields to update

        Returns:
            Updated Finding or None if not found
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return None

        if status is not None:
            finding.status = status
        if validation_notes is not None:
            finding.validation_notes = validation_notes
        if submission_id is not None:
            finding.submission_id = submission_id
        if poc_path is not None:
            finding.poc_path = poc_path

        # Update any additional allowed fields
        allowed_fields = {
            "title", "description", "cvss_score", "cvss_vector",
            "affected_function", "affected_line", "tier",
            "auth_level",
        }
        for key, value in kwargs.items():
            if key in allowed_fields and hasattr(finding, key):
                setattr(finding, key, value)

        finding.updated_at = datetime.utcnow().isoformat() + "Z"
        self._save_findings()

        return finding

    def delete_finding(self, finding_id: str) -> bool:
        """
        Delete a finding.

        Args:
            finding_id: Finding ID to delete

        Returns:
            True if deleted, False if not found
        """
        if finding_id in self._findings:
            del self._findings[finding_id]
            self._save_findings()
            return True
        return False

    def list_findings(
        self,
        plugin_slug: str | None = None,
        status: str | None = None,
        vuln_type: str | None = None,
        min_cvss: float | None = None,
    ) -> list[Finding]:
        """
        List findings with optional filters.

        Args:
            plugin_slug: Filter by plugin
            status: Filter by status
            vuln_type: Filter by vulnerability type
            min_cvss: Minimum CVSS score

        Returns:
            List of matching findings
        """
        results = list(self._findings.values())

        if plugin_slug:
            results = [f for f in results if f.plugin_slug == plugin_slug]
        if status:
            results = [f for f in results if f.status == status]
        if vuln_type:
            results = [f for f in results if f.vuln_type == vuln_type]
        if min_cvss is not None:
            results = [f for f in results if f.cvss_score >= min_cvss]

        # Sort by CVSS score descending
        results.sort(key=lambda f: f.cvss_score, reverse=True)

        return results

    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about findings.

        Returns:
            Dictionary with finding statistics
        """
        findings = list(self._findings.values())

        by_status = {}
        by_tier = {}
        by_vuln_type = {}
        by_plugin = {}

        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
            if f.tier:
                by_tier[f.tier] = by_tier.get(f.tier, 0) + 1
            by_vuln_type[f.vuln_type] = by_vuln_type.get(f.vuln_type, 0) + 1
            by_plugin[f.plugin_slug] = by_plugin.get(f.plugin_slug, 0) + 1

        eligible = [f for f in findings if f.is_eligible]
        validated = [f for f in findings if f.status == "validated"]

        return {
            "total_findings": len(findings),
            "eligible_findings": len(eligible),
            "validated_findings": len(validated),
            "by_status": by_status,
            "by_tier": by_tier,
            "by_vuln_type": by_vuln_type,
            "by_plugin": by_plugin,
            "avg_cvss": sum(f.cvss_score for f in findings) / len(findings) if findings else 0,
        }

