"""
Discord webhook notification handler.
"""

import requests

from wpguard.config import USER_AGENT
from wpguard.core.models import ChangeReport


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
