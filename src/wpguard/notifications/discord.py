"""
Discord webhook notification handler.
"""

import requests

from wpguard.config import USER_AGENT
from wpguard.core.models import ChangeReport, Finding


class DiscordNotifier:
    """Sends notifications to Discord via webhooks."""

    # WordPress blue color
    EMBED_COLOR = 0x0073AA

    def __init__(self, webhook_url: str):
        """
        Initialize the Discord notifier.

        Args:
            webhook_url: Discord webhook URL
        """
        self.webhook_url = webhook_url
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
        )

    def _format_file_list(self, files: list[str], max_items: int = 10) -> str:
        """Format a list of files for Discord embed."""
        if not files:
            return ""

        lines = [f"• `{f}`" for f in files[:max_items]]
        if len(files) > max_items:
            lines.append(f"... and {len(files) - max_items} more")
        return "\n".join(lines)

    def _build_embed(self, report: ChangeReport) -> dict:
        """
        Build Discord embed from change report.

        Args:
            report: ChangeReport to format

        Returns:
            Discord embed dictionary
        """
        fields = []

        if report.changed_files:
            fields.append(
                {
                    "name": f"Modified Files ({len(report.changed_files)})",
                    "value": self._format_file_list(report.changed_files),
                    "inline": False,
                }
            )

        if report.added_files:
            fields.append(
                {
                    "name": f"Added Files ({len(report.added_files)})",
                    "value": self._format_file_list(report.added_files),
                    "inline": False,
                }
            )

        if report.removed_files:
            fields.append(
                {
                    "name": f"Removed Files ({len(report.removed_files)})",
                    "value": self._format_file_list(report.removed_files),
                    "inline": False,
                }
            )

        # Download commands
        download_cmds = (
            f"**ZIP:** `wget \"{report.download_link}\"`\n"
            f"**SVN:** `svn checkout {report.svn_url}`"
        )
        fields.append(
            {"name": "Download Commands", "value": download_cmds, "inline": False}
        )

        return {
            "title": f"Plugin Update: {report.plugin_name}",
            "description": (
                f"**{report.plugin_slug}** updated from "
                f"`{report.old_version}` to `{report.new_version}`"
            ),
            "color": self.EMBED_COLOR,
            "fields": fields,
            "footer": {"text": "WordPressGuard Security Monitor"},
            "timestamp": report.timestamp,
        }

    def send_report(self, report: ChangeReport, timeout: int = 10) -> bool:
        """
        Send a change report to Discord.

        Args:
            report: ChangeReport to send
            timeout: Request timeout in seconds

        Returns:
            True if sent successfully
        """
        payload = {"embeds": [self._build_embed(report)]}

        try:
            response = self.session.post(
                self.webhook_url, json=payload, timeout=timeout
            )
            response.raise_for_status()
            print(f"[+] Discord notification sent for {report.plugin_slug}")
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send Discord notification: {e}")
            return False

    def send_message(self, content: str, timeout: int = 10) -> bool:
        """
        Send a simple text message to Discord.

        Args:
            content: Message content
            timeout: Request timeout in seconds

        Returns:
            True if sent successfully
        """
        payload = {"content": content}

        try:
            response = self.session.post(
                self.webhook_url, json=payload, timeout=timeout
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send Discord message: {e}")
            return False

    def send_startup_message(self, plugin_count: int) -> bool:
        """
        Send a startup notification.

        Args:
            plugin_count: Number of plugins being monitored

        Returns:
            True if sent successfully
        """
        embed = {
            "title": "WordPressGuard Started",
            "description": f"Now monitoring **{plugin_count}** plugins for updates.",
            "color": 0x00FF00,  # Green
            "footer": {"text": "WordPressGuard Security Monitor"},
        }
        payload = {"embeds": [embed]}

        try:
            response = self.session.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def test_webhook(self) -> bool:
        """
        Test the webhook connection.

        Returns:
            True if webhook is working
        """
        return self.send_message("WordPressGuard webhook test successful!")

    # Finding Notification Methods

    # Severity colors for findings
    SEVERITY_COLORS = {
        "Critical": 0xFF0000,  # Red
        "High": 0xFF6600,  # Orange
        "Medium": 0xFFCC00,  # Yellow
        "Low": 0x00CC00,  # Green
    }

    def _build_finding_embed(self, finding: Finding, title_prefix: str = "") -> dict:
        """
        Build Discord embed from a security finding.

        Args:
            finding: Finding to format
            title_prefix: Optional prefix for title (e.g., "VALIDATED: ")

        Returns:
            Discord embed dictionary
        """
        color = self.SEVERITY_COLORS.get(finding.severity, self.EMBED_COLOR)

        fields = [
            {
                "name": "Plugin",
                "value": f"`{finding.plugin_slug}` v{finding.plugin_version}",
                "inline": True,
            },
            {
                "name": "Active Installs",
                "value": f"{finding.active_installs:,}",
                "inline": True,
            },
            {
                "name": "Vulnerability Type",
                "value": finding.vuln_type.replace("_", " ").title(),
                "inline": True,
            },
            {
                "name": "Auth Required",
                "value": finding.auth_level.title(),
                "inline": True,
            },
            {
                "name": "CVSS Score",
                "value": f"**{finding.cvss_score}** ({finding.severity})\n`{finding.cvss_vector}`",
                "inline": True,
            },
            {
                "name": "Tier",
                "value": finding.tier.replace("_", " ").title() if finding.tier else "N/A",
                "inline": True,
            },
            {
                "name": "Affected File",
                "value": f"`{finding.affected_file}`",
                "inline": False,
            },
        ]

        if finding.affected_function:
            fields.append({
                "name": "Function / Line",
                "value": f"`{finding.affected_function}` (line {finding.affected_line})",
                "inline": False,
            })

        if finding.description:
            # Truncate description if too long
            desc = finding.description[:500]
            if len(finding.description) > 500:
                desc += "..."
            fields.append({
                "name": "Description",
                "value": desc,
                "inline": False,
            })

        title = f"{title_prefix}{finding.title}"

        return {
            "title": title,
            "description": f"**Finding ID:** `{finding.id}` | **Status:** {finding.status.upper()}",
            "color": color,
            "fields": fields,
            "footer": {"text": "WordPressGuard Security Research"},
            "timestamp": finding.created_at,
        }

    def send_finding(
        self,
        finding: Finding,
        title_prefix: str = "",
        mention: str | None = None,
        timeout: int = 10,
    ) -> bool:
        """
        Send a finding notification to Discord.

        Args:
            finding: Finding to send
            title_prefix: Optional title prefix (e.g., "NEW: ", "VALIDATED: ")
            mention: Optional mention (e.g., "@everyone", "<@user_id>")
            timeout: Request timeout in seconds

        Returns:
            True if sent successfully
        """
        payload = {
            "embeds": [self._build_finding_embed(finding, title_prefix)],
        }

        if mention:
            payload["content"] = mention

        try:
            response = self.session.post(
                self.webhook_url, json=payload, timeout=timeout
            )
            response.raise_for_status()
            print(f"[+] Discord finding notification sent for {finding.id}")
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send Discord finding notification: {e}")
            return False

    def send_validated_finding(self, finding: Finding, mention: str | None = "@everyone") -> bool:
        """
        Send a validated finding notification (ready for submission).

        Args:
            finding: Validated finding to send
            mention: Optional mention for alerting

        Returns:
            True if sent successfully
        """
        return self.send_finding(finding, title_prefix="VALIDATED: ", mention=mention)

    def send_finding_summary(
        self,
        findings: list[Finding],
        title: str = "Security Research Summary",
        timeout: int = 10,
    ) -> bool:
        """
        Send a summary of multiple findings.

        Args:
            findings: List of findings to summarize
            title: Summary title
            timeout: Request timeout

        Returns:
            True if sent successfully
        """
        if not findings:
            return True

        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Group by status
        by_status = {}
        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1

        # Build summary
        severity_text = " | ".join(f"**{k}**: {v}" for k, v in by_severity.items())
        status_text = " | ".join(f"**{k.title()}**: {v}" for k, v in by_status.items())

        # Top findings by CVSS
        top_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)[:5]
        top_text = "\n".join(
            f"• `{f.id}` - {f.plugin_slug} - {f.vuln_type} (CVSS: {f.cvss_score})"
            for f in top_findings
        )

        embed = {
            "title": title,
            "description": f"**Total Findings:** {len(findings)}",
            "color": self.EMBED_COLOR,
            "fields": [
                {"name": "By Severity", "value": severity_text, "inline": False},
                {"name": "By Status", "value": status_text, "inline": False},
                {"name": "Top Findings", "value": top_text, "inline": False},
            ],
            "footer": {"text": "WordPressGuard Security Research"},
        }

        payload = {"embeds": [embed]}

        try:
            response = self.session.post(
                self.webhook_url, json=payload, timeout=timeout
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send Discord summary: {e}")
            return False

    # Pipeline Event Notification Methods

    def send_pipeline_event(
        self,
        event: str,
        title: str | None = None,
        description: str | None = None,
        fields: list[dict] | None = None,
        color: int | None = None,
        timeout: int = 10,
    ) -> bool:
        """
        Send a pipeline event notification with embed.

        Args:
            event: Event type (started, stopped, stage_complete, error, etc.)
            title: Embed title (defaults based on event)
            description: Embed description
            fields: Additional fields for the embed
            color: Embed color (defaults based on event)
            timeout: Request timeout in seconds

        Returns:
            True if sent successfully
        """
        # Default colors based on event type
        colors = {
            "started": 0x00FF00,      # Green
            "stopped": 0x808080,      # Gray
            "paused": 0xFFCC00,       # Yellow
            "resumed": 0x00FF00,      # Green
            "stage_started": 0x0073AA,  # WordPress blue
            "stage_completed": 0x00AA00,  # Dark green
            "worker_restarted": 0xFFCC00,  # Yellow
            "worker_failed": 0xFF0000,   # Red
            "cycle_completed": 0x0073AA,  # WordPress blue
            "error": 0xFF0000,        # Red
        }

        # Default titles based on event type
        titles = {
            "started": "Pipeline Started",
            "stopped": "Pipeline Stopped",
            "paused": "Pipeline Paused",
            "resumed": "Pipeline Resumed",
            "stage_started": "Stage Started",
            "stage_completed": "Stage Completed",
            "worker_restarted": "Worker Restarted",
            "worker_failed": "Worker Failed",
            "cycle_completed": "Cycle Completed",
            "error": "Pipeline Error",
        }

        embed = {
            "title": title or titles.get(event, f"Pipeline: {event}"),
            "color": color or colors.get(event, self.EMBED_COLOR),
            "footer": {"text": "WordPressGuard Pipeline"},
        }

        if description:
            embed["description"] = description

        if fields:
            embed["fields"] = fields

        payload = {"embeds": [embed]}

        try:
            response = self.session.post(
                self.webhook_url, json=payload, timeout=timeout
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send pipeline event: {e}")
            return False

    def send_pipeline_status(
        self,
        status: dict,
        timeout: int = 10,
    ) -> bool:
        """
        Send a detailed pipeline status notification.

        Args:
            status: Pipeline status dict from get_status()
            timeout: Request timeout in seconds

        Returns:
            True if sent successfully
        """
        daemon = status.get("daemon", {})
        pipeline = status.get("pipeline", {})
        metrics = status.get("metrics", {})

        fields = [
            {
                "name": "Status",
                "value": daemon.get("status", "unknown"),
                "inline": True,
            },
            {
                "name": "Current Stage",
                "value": pipeline.get("current_stage") or "idle",
                "inline": True,
            },
            {
                "name": "Current Plugin",
                "value": pipeline.get("current_plugin") or "none",
                "inline": True,
            },
            {
                "name": "Plugins Queue",
                "value": str(len(pipeline.get("plugins_queue", []))),
                "inline": True,
            },
            {
                "name": "Plugins Completed",
                "value": str(len(pipeline.get("plugins_completed", []))),
                "inline": True,
            },
            {
                "name": "Total Findings",
                "value": str(metrics.get("total_findings", 0)),
                "inline": True,
            },
        ]

        return self.send_pipeline_event(
            event="status",
            title="Pipeline Status",
            fields=fields,
            color=0x0073AA,
            timeout=timeout,
        )
