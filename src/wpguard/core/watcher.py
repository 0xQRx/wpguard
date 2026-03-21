"""
Plugin watching and change detection.
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.config import (
    DEFAULT_OUTPUT_DIR,
    NEW_PLUGINS_FILENAME,
    RECENTLY_UPDATED_FILENAME,
    REPORTS_SUBDIR,
    STATE_FILENAME,
    DEFAULT_WATCH_INTERVAL,
)
from wpguard.core.downloader import SVNClient, SVNChangeInfo
from wpguard.core.models import ChangeReport, PluginInfo
from wpguard.notifications.discord import DiscordNotifier


class PluginWatcher:
    """Watches plugins for updates and changes."""

    def __init__(
        self,
        output_dir: str | Path = DEFAULT_OUTPUT_DIR,
        discord_webhook: str | None = None,
    ):
        """
        Initialize the plugin watcher.

        Args:
            output_dir: Base output directory (default: ./wpguard_output)
            discord_webhook: Discord webhook URL for notifications
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.reports_dir = self.output_dir / REPORTS_SUBDIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # State file in output directory root
        self.state_file = self.output_dir / STATE_FILENAME

        self.api = WordPressPluginAPI()
        self.svn = SVNClient()
        self.notifier = DiscordNotifier(discord_webhook) if discord_webhook else None

        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        """Load watching state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"plugins": {}, "last_check": None}

    def _save_state(self) -> None:
        """Save watching state to file."""
        self.state["last_check"] = datetime.now(timezone.utc).isoformat()
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def add_plugin(self, slug: str) -> bool:
        """
        Add a plugin to watchlist.

        Args:
            slug: Plugin slug

        Returns:
            True if successfully added
        """
        plugin = self.api.get_plugin_info(slug)
        if not plugin:
            print(f"[ERROR] Plugin '{slug}' not found", file=sys.stderr)
            return False

        # Get current SVN revision for future diff tracking
        svn_revision = self.svn.get_latest_revision(slug)

        self.state["plugins"][slug] = {
            "version": plugin.version,
            "last_updated": plugin.last_updated,
            "name": plugin.name,
            "active_installs": plugin.active_installs,
            "download_link": plugin.download_link,
            "svn_revision": svn_revision,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_state()
        print(f"[+] Added {plugin.name} ({slug}) v{plugin.version} to watchlist", file=sys.stderr)
        if svn_revision:
            print(f"    SVN revision: r{svn_revision}", file=sys.stderr)
        return True

    def remove_plugin(self, slug: str) -> bool:
        """
        Remove a plugin from watchlist.

        Args:
            slug: Plugin slug

        Returns:
            True if successfully removed
        """
        if slug in self.state["plugins"]:
            name = self.state["plugins"][slug].get("name", slug)
            del self.state["plugins"][slug]
            self._save_state()
            print(f"[-] Removed {name} ({slug}) from watchlist", file=sys.stderr)
            return True
        else:
            print(f"[!] Plugin '{slug}' not in watchlist", file=sys.stderr)
            return False

    def list_watched(self) -> list[dict[str, Any]]:
        """
        List all watched plugins.

        Returns:
            List of plugin info dictionaries
        """
        plugins_list = []
        for slug, info in self.state["plugins"].items():
            plugins_list.append(
                {
                    "slug": slug,
                    "name": info.get("name", slug),
                    "version": info.get("version", "unknown"),
                    "last_updated": info.get("last_updated", "unknown"),
                    "svn_revision": info.get("svn_revision"),
                }
            )
        return plugins_list

    def print_watched(self) -> None:
        """Print list of watched plugins to console."""
        plugins = self.list_watched()

        if not plugins:
            print("[*] No plugins being watched", file=sys.stderr)
            return

        print("\n[*] Watched Plugins:", file=sys.stderr)
        print("-" * 70, file=sys.stderr)
        for p in plugins:
            svn_info = f" (r{p['svn_revision']})" if p.get("svn_revision") else ""
            print(f"  * {p['name']} ({p['slug']}) - v{p['version']}{svn_info}", file=sys.stderr)
        print("-" * 70, file=sys.stderr)

        if self.state.get("last_check"):
            print(f"Last check: {self.state['last_check']}", file=sys.stderr)

    def save_report(
        self,
        report: ChangeReport,
        svn_change: SVNChangeInfo | None = None,
    ) -> Path:
        """
        Save a change report as JSON file.

        Args:
            report: ChangeReport to save
            svn_change: Optional SVN change info

        Returns:
            Path to saved report file
        """
        # Create plugin reports directory
        plugin_reports_dir = self.reports_dir / report.plugin_slug
        plugin_reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename: {old}_to_{new}_{timestamp}.json
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        filename = f"{report.old_version}_to_{report.new_version}_{timestamp}.json"
        report_path = plugin_reports_dir / filename

        # Build report data
        report_data = {
            "plugin_slug": report.plugin_slug,
            "plugin_name": report.plugin_name,
            "old_version": report.old_version,
            "new_version": report.new_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "changed_files": report.changed_files,
            "added_files": report.added_files,
            "removed_files": report.removed_files,
            "download_commands": {
                "wget": f'wget "{report.download_link}"',
                "svn": f"svn checkout https://plugins.svn.wordpress.org/{report.plugin_slug}/trunk/",
            },
        }

        # Add SVN info if available
        if svn_change:
            report_data["svn_old_revision"] = svn_change.old_revision
            report_data["svn_new_revision"] = svn_change.new_revision
            report_data["svn_log"] = svn_change.log_entries

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)

        print(f"[+] Report saved: {report_path}", file=sys.stderr)
        return report_path

    def check_updates(
        self,
        progress_callback: Callable[[str], None] | None = None,
        use_svn_diff: bool = True,
        save_reports: bool = True,
    ) -> list[tuple[ChangeReport, SVNChangeInfo | None]]:
        """
        Check all watched plugins for updates.

        Args:
            progress_callback: Optional callback for progress updates
            use_svn_diff: Whether to use SVN for detailed diff (default: True)
            save_reports: Whether to save reports locally (default: True)

        Returns:
            List of tuples (ChangeReport, SVNChangeInfo or None)
        """
        reports: list[tuple[ChangeReport, SVNChangeInfo | None]] = []

        for slug, stored_info in list(self.state["plugins"].items()):
            if progress_callback:
                progress_callback(f"Checking {slug}...")
            else:
                print(f"[*] Checking {slug}...", file=sys.stderr)

            current_info = self.api.get_plugin_info(slug)
            if not current_info:
                print(f"[!] Could not fetch info for {slug}", file=sys.stderr)
                continue

            if current_info.version != stored_info["version"]:
                print(
                    f"[!] Update found: {slug} "
                    f"{stored_info['version']} -> {current_info.version}",
                    file=sys.stderr,
                )

                # Get SVN diff if we have previous revision
                svn_change: SVNChangeInfo | None = None
                old_svn_rev = stored_info.get("svn_revision")
                new_svn_rev = self.svn.get_latest_revision(slug)

                if use_svn_diff and old_svn_rev and new_svn_rev:
                    print(f"[*] Getting SVN diff (r{old_svn_rev} -> r{new_svn_rev})...", file=sys.stderr)
                    svn_change = self.svn.compare_revisions(slug, old_svn_rev, new_svn_rev)

                # Build report from SVN data
                report = ChangeReport(
                    plugin_slug=slug,
                    plugin_name=stored_info.get("name", slug),
                    old_version=stored_info.get("version", "unknown"),
                    new_version=current_info.version,
                    changed_files=svn_change.changed_files if svn_change else [],
                    added_files=svn_change.added_files if svn_change else [],
                    removed_files=svn_change.removed_files if svn_change else [],
                    download_link=current_info.download_link,
                )

                # Save report locally
                if save_reports:
                    self.save_report(report, svn_change)

                # Update state with new info
                self.state["plugins"][slug] = {
                    "version": current_info.version,
                    "last_updated": current_info.last_updated,
                    "name": current_info.name,
                    "active_installs": current_info.active_installs,
                    "download_link": current_info.download_link,
                    "svn_revision": new_svn_rev,
                    "added_at": stored_info.get(
                        "added_at", datetime.now(timezone.utc).isoformat()
                    ),
                }

                reports.append((report, svn_change))
            else:
                print(f"[*] {slug} is up to date (v{current_info.version})", file=sys.stderr)

        self._save_state()
        return reports

    def send_report(self, report: ChangeReport) -> bool:
        """
        Send a change report via configured notifiers.

        Args:
            report: ChangeReport to send

        Returns:
            True if sent successfully
        """
        if self.notifier:
            return self.notifier.send_report(report)
        return False

    def watch(
        self,
        interval: int = DEFAULT_WATCH_INTERVAL,
        send_reports: bool = False,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """
        Continuously watch for plugin updates.

        Args:
            interval: Check interval in seconds
            send_reports: Whether to send Discord notifications
            progress_callback: Optional callback for progress updates
        """
        # Format interval for display
        if interval >= 3600:
            hours = interval // 3600
            mins = (interval % 3600) // 60
            interval_str = f"{hours}h{mins}m" if mins else f"{hours}h"
        elif interval >= 60:
            mins = interval // 60
            secs = interval % 60
            interval_str = f"{mins}m{secs}s" if secs else f"{mins}m"
        else:
            interval_str = f"{interval}s"

        print(f"[*] Starting watch mode (interval: {interval_str})", file=sys.stderr)
        print(f"[*] Watching {len(self.state['plugins'])} plugins", file=sys.stderr)
        print("[*] Press Ctrl+C to stop\n", file=sys.stderr)

        try:
            while True:
                results = self.check_updates(progress_callback)

                for report, svn_change in results:
                    print(report.format_console_report(), file=sys.stderr)

                    # Print SVN commit log if available
                    if svn_change and svn_change.log_entries:
                        print("\n[SVN Commit Log]", file=sys.stderr)
                        for entry in svn_change.log_entries[:5]:
                            msg = entry.get("message", "").strip()[:60]
                            print(f"   r{entry['revision']} - {msg}", file=sys.stderr)

                    if send_reports and self.notifier:
                        self.send_report(report)

                print(f"[*] Next check in {interval_str}...", file=sys.stderr)
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[*] Watch mode stopped", file=sys.stderr)

    def get_state_info(self) -> dict[str, Any]:
        """Get current state information."""
        return {
            "plugins_count": len(self.state["plugins"]),
            "last_check": self.state.get("last_check"),
            "state_file": str(self.state_file),
            "output_dir": str(self.output_dir),
        }

    def check_global_updates(
        self,
        min_installs: int = 1000,
        max_pages: int = 2,
    ) -> dict[str, Any]:
        """
        Query WordPress.org for recently updated plugins.

        Returns only NEW updates not seen in previous checks.

        Args:
            min_installs: Minimum active installations filter
            max_pages: Maximum API pages to fetch (250 plugins/page)

        Returns:
            Dict with new_updates list, total_new count, last_checked timestamp
        """
        # Fetch recently updated plugins from WordPress.org API
        limit = max_pages * 250
        plugins = self.api.fetch_all_plugins(
            browse="updated",
            min_installs=min_installs,
            limit=limit,
        )

        # Initialize global monitor state if needed
        if "global_monitor" not in self.state:
            self.state["global_monitor"] = {
                "last_checked": None,
                "seen_versions": {},
            }

        seen = self.state["global_monitor"]["seen_versions"]
        new_updates = []

        for plugin in plugins:
            # Only report if this slug+version combo hasn't been seen before
            if seen.get(plugin.slug) != plugin.version:
                new_updates.append({
                    "slug": plugin.slug,
                    "name": plugin.name,
                    "version": plugin.version,
                    "active_installs": plugin.active_installs,
                    "last_updated": plugin.last_updated,
                    "download_link": plugin.download_link,
                    "short_description": plugin.short_description,
                })
                # Update seen versions
                seen[plugin.slug] = plugin.version

        now = datetime.now(timezone.utc).isoformat()
        self.state["global_monitor"]["last_checked"] = now
        self._save_state()

        result = {
            "last_checked": now,
            "new_updates": new_updates,
            "total_new": len(new_updates),
        }

        # Write recently_updated.json to output dir
        output_path = self.output_dir / RECENTLY_UPDATED_FILENAME
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

        print(
            f"[*] Global monitor: {len(plugins)} plugins checked, "
            f"{len(new_updates)} new updates",
            file=sys.stderr,
        )

        return result

    def check_new_plugins(
        self,
        min_installs: int = 0,
        max_pages: int = 2,
    ) -> dict[str, Any]:
        """
        Query WordPress.org for newly added plugins.

        Returns only plugins not seen in previous checks.

        Args:
            min_installs: Minimum active installations filter
            max_pages: Maximum API pages to fetch (250 plugins/page)

        Returns:
            Dict with new_plugins list, total_new count, last_checked timestamp
        """
        limit = max_pages * 250
        plugins = self.api.fetch_all_plugins(
            browse="new",
            min_installs=min_installs,
            limit=limit,
        )

        # Initialize new plugins monitor state if needed
        if "new_plugins_monitor" not in self.state:
            self.state["new_plugins_monitor"] = {
                "last_checked": None,
                "seen_slugs": [],
            }

        seen = set(self.state["new_plugins_monitor"]["seen_slugs"])
        new_plugins = []

        for plugin in plugins:
            if plugin.slug not in seen:
                new_plugins.append({
                    "slug": plugin.slug,
                    "name": plugin.name,
                    "version": plugin.version,
                    "active_installs": plugin.active_installs,
                    "last_updated": plugin.last_updated,
                    "download_link": plugin.download_link,
                    "short_description": plugin.short_description,
                })
                seen.add(plugin.slug)

        now = datetime.now(timezone.utc).isoformat()
        self.state["new_plugins_monitor"]["last_checked"] = now
        self.state["new_plugins_monitor"]["seen_slugs"] = sorted(seen)
        self._save_state()

        result = {
            "last_checked": now,
            "new_plugins": new_plugins,
            "total_new": len(new_plugins),
        }

        # Write new_plugins.json to output dir
        output_path = self.output_dir / NEW_PLUGINS_FILENAME
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

        print(
            f"[*] New plugins monitor: {len(plugins)} plugins checked, "
            f"{len(new_plugins)} new",
            file=sys.stderr,
        )

        return result
