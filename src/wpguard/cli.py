"""
Command-line interface for WordPressGuard.
"""

import argparse
import subprocess
import sys
import time

from wpguard import __version__
from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.config import (
    DEFAULT_OUTPUT_DIR,
    PLUGINS_SUBDIR,
    DEFAULT_WATCH_INTERVAL,
    WP_PLUGINS_SVN,
    WP_PLUGINS_URL,
    get_discord_webhook,
)
from wpguard.core.downloader import PluginDownloader, SVNClient
from wpguard.core.watcher import PluginWatcher
from wpguard.utils.helpers import parse_duration

# Default delay between downloads (seconds)
DEFAULT_DELAY = 1


def cmd_download(args: argparse.Namespace) -> int:
    """Handle download command."""
    # Build plugins directory path
    plugins_dir = f"{args.output_dir}/{PLUGINS_SUBDIR}"

    api = WordPressPluginAPI()
    downloader = PluginDownloader(plugins_dir)

    def progress(msg: str) -> None:
        print(f"[*] {msg}")

    # Determine limit
    limit = None if args.count == "all" else int(args.count)

    print(
        f"[*] Fetching plugins "
        f"(min: {args.min_installs:,}, max: {args.max_installs or 'unlimited'})"
    )

    plugins = api.fetch_all_plugins(
        search=args.search,
        min_installs=args.min_installs,
        max_installs=args.max_installs,
        limit=limit,
        browse=args.browse,
        progress_callback=progress,
    )

    print(f"[+] Found {len(plugins)} plugins matching criteria")

    if not plugins:
        print("[!] No plugins found")
        return 0

    delay = args.delay

    # Download plugins
    for i, plugin in enumerate(plugins, 1):
        print(f"\n[{i}/{len(plugins)}] {plugin.name} ({plugin.slug})")
        print(f"    Active installs: {plugin.active_installs:,}")
        print(f"    Version: {plugin.version}")

        # Use the unified download method
        result = downloader.download_plugin(
            plugin,
            extract=args.extract,
            svn=args.svn,
        )

        # Print summary of what was downloaded
        if result.zip_path:
            print(f"    ZIP: {result.zip_path}")
        if result.extracted_path:
            print(f"    Extracted: {result.extracted_path}")
        if result.svn_path:
            print(f"    SVN: {result.svn_path}")

        if delay > 0 and i < len(plugins):
            time.sleep(delay)

    print(f"\n[+] Download complete. Files saved to: {plugins_dir}")
    print(f"    Structure: {plugins_dir}/<plugin>/{{zip,extracted,svn}}/")
    return 0


def cmd_svn_diff(args: argparse.Namespace) -> int:
    """Show SVN diff between revisions."""
    svn = SVNClient()

    print(f"[*] Getting diff for {args.slug} (r{args.old_rev} -> {args.new_rev})...")

    change_info = svn.compare_revisions(args.slug, args.old_rev, args.new_rev)

    print(f"\n{'=' * 70}")
    print(f"SVN DIFF: {args.slug}")
    print(f"Revision: {change_info.old_revision} -> {change_info.new_revision}")
    print(f"{'=' * 70}")

    if change_info.changed_files:
        print(f"\n[Modified Files] ({len(change_info.changed_files)})")
        for f in change_info.changed_files:
            print(f"   M {f}")

    if change_info.added_files:
        print(f"\n[Added Files] ({len(change_info.added_files)})")
        for f in change_info.added_files:
            print(f"   A {f}")

    if change_info.removed_files:
        print(f"\n[Removed Files] ({len(change_info.removed_files)})")
        for f in change_info.removed_files:
            print(f"   D {f}")

    if change_info.log_entries:
        print(f"\n[Commit Log] (last {len(change_info.log_entries)} entries)")
        for entry in change_info.log_entries[:10]:
            msg = entry.get("message", "").strip()[:60]
            print(f"   r{entry['revision']} - {msg}")

    if args.show_diff and change_info.diff_output:
        print(f"\n{'=' * 70}")
        print("DIFF OUTPUT:")
        print(f"{'=' * 70}")
        print(change_info.diff_output)

    print(f"{'=' * 70}\n")

    # Save diff to file if requested
    if args.output_file and change_info.diff_output:
        with open(args.output_file, "w") as f:
            f.write(change_info.diff_output)
        print(f"[+] Diff saved to: {args.output_file}")

    return 0


def cmd_svn_log(args: argparse.Namespace) -> int:
    """Show SVN log for a plugin."""
    svn = SVNClient()

    print(f"[*] Getting SVN log for {args.slug}...")

    entries = svn.get_log(args.slug, limit=args.limit)

    if not entries:
        print("[!] No log entries found")
        return 1

    print(f"\n{'=' * 70}")
    print(f"SVN LOG: {args.slug} (last {len(entries)} entries)")
    print(f"{'=' * 70}\n")

    for entry in entries:
        print(f"r{entry['revision']} | {entry['author']} | {entry['date'][:19] if entry['date'] else 'N/A'}")
        if entry['message']:
            # Indent message lines
            for line in entry['message'].strip().split('\n'):
                print(f"    {line}")
        print()

    print(f"{'=' * 70}\n")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    api = WordPressPluginAPI()
    plugin = api.get_plugin_info(args.slug)

    if not plugin:
        print(f"[ERROR] Plugin '{args.slug}' not found")
        return 1

    print(f"\n{'=' * 60}")
    print(f"Plugin: {plugin.name}")
    print(f"{'=' * 60}")
    print(f"Slug:            {plugin.slug}")
    print(f"Version:         {plugin.version}")
    print(f"Active Installs: {plugin.active_installs:,}")
    print(f"Rating:          {plugin.rating:.0f}/100 ({plugin.num_ratings:,} ratings)")
    print(f"Last Updated:    {plugin.last_updated}")
    print(f"Requires WP:     {plugin.requires or 'N/A'}")
    print(f"Tested Up To:    {plugin.tested or 'N/A'}")
    print(f"Requires PHP:    {plugin.requires_php or 'N/A'}")

    if plugin.short_description:
        print(f"\nDescription: {plugin.short_description}")

    print(f"\nDownload URL: {plugin.download_link}")
    print(f"SVN URL:      {WP_PLUGINS_SVN}{plugin.slug}/")
    print(f"Plugin Page:  {WP_PLUGINS_URL}{plugin.slug}/")
    print(f"{'=' * 60}\n")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Handle search command."""
    api = WordPressPluginAPI()

    plugins, total_pages = api.query_plugins(
        search=args.query, page=args.page, per_page=args.per_page
    )

    if not plugins:
        print("[*] No plugins found")
        return 0

    print(f"\n[*] Search results for '{args.query}' (page {args.page}/{total_pages}):\n")
    print(f"{'Slug':<30} {'Installs':<12} {'Version':<10} {'Rating':<8} Name")
    print("-" * 100)

    for p in plugins:
        installs = f"{p.active_installs:,}"
        rating = f"{p.rating:.0f}%" if p.rating else "N/A"
        name = (p.name[:30] + "...") if len(p.name) > 30 else p.name
        print(f"{p.slug:<30} {installs:<12} {p.version:<10} {rating:<8} {name}")

    print("-" * 100)
    print(f"Page {args.page} of {total_pages}")
    return 0


def cmd_watch_add(args: argparse.Namespace) -> int:
    """Add plugins to watchlist."""
    webhook = get_discord_webhook(args.discord_webhook)
    watcher = PluginWatcher(
        output_dir=args.output_dir,
        discord_webhook=webhook,
    )

    success_count = 0
    for slug in args.slugs:
        if watcher.add_plugin(slug):
            success_count += 1

    print(f"\n[*] Added {success_count}/{len(args.slugs)} plugins to watchlist")
    return 0 if success_count > 0 else 1


def cmd_watch_remove(args: argparse.Namespace) -> int:
    """Remove plugins from watchlist."""
    watcher = PluginWatcher(output_dir=args.output_dir)

    for slug in args.slugs:
        watcher.remove_plugin(slug)

    return 0


def cmd_watch_list(args: argparse.Namespace) -> int:
    """List watched plugins."""
    watcher = PluginWatcher(output_dir=args.output_dir)
    watcher.print_watched()
    return 0


def cmd_watch_check(args: argparse.Namespace) -> int:
    """Check watched plugins for updates (single check, no loop)."""
    webhook = get_discord_webhook(args.discord_webhook)

    if args.send_report and not webhook:
        print(
            "[ERROR] Discord webhook required. "
            "Set DISCORD_WEBHOOK_URL or use --discord-webhook"
        )
        return 1

    watcher = PluginWatcher(
        output_dir=args.output_dir,
        discord_webhook=webhook if args.send_report else None,
    )

    results = watcher.check_updates()

    for report, svn_change in results:
        print(report.format_console_report())

        # Print SVN commit log if available
        if svn_change and svn_change.log_entries:
            print("\n[SVN Commit Log]")
            for entry in svn_change.log_entries[:5]:
                msg = entry.get("message", "").strip()[:60]
                print(f"   r{entry['revision']} - {msg}")
            print()

        if args.send_report:
            watcher.send_report(report)

    if not results:
        print("[*] No updates found")

    return 0


def cmd_watch_start(args: argparse.Namespace) -> int:
    """Start continuous watch mode."""
    webhook = get_discord_webhook(args.discord_webhook)

    if args.send_report and not webhook:
        print(
            "[ERROR] Discord webhook required. "
            "Set DISCORD_WEBHOOK_URL or use --discord-webhook"
        )
        return 1

    watcher = PluginWatcher(
        output_dir=args.output_dir,
        discord_webhook=webhook if args.send_report else None,
    )

    if not watcher.state["plugins"]:
        print(
            "[ERROR] No plugins being watched. "
            "Add some first with: wpguard watch add <slug>"
        )
        return 1

    # Parse interval
    try:
        interval = parse_duration(args.interval)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1

    if args.tmux:
        # Build command for tmux
        session_name = args.tmux_session
        cmd_parts = [
            sys.executable,
            "-m",
            "wpguard",
            "watch",
            "--interval",
            str(args.interval),
            "--output-dir",
            str(args.output_dir),
        ]
        if args.send_report:
            cmd_parts.append("--send-report")
            if webhook:
                cmd_parts.extend(["--discord-webhook", webhook])

        cmd_str = " ".join(f'"{p}"' if " " in p else p for p in cmd_parts)

        try:
            # Check if session exists
            check = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True,
            )
            if check.returncode == 0:
                print(f"[!] Tmux session '{session_name}' already exists")
                print(f"    Attach with: tmux attach -t {session_name}")
                return 1

            # Create new session
            subprocess.run(
                ["tmux", "new-session", "-d", "-s", session_name, cmd_str],
                check=True,
            )
            print(f"[+] Watch mode started in tmux session: {session_name}")
            print(f"    Attach with: tmux attach -t {session_name}")
            return 0
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to start tmux session: {e}")
            return 1
        except FileNotFoundError:
            print("[ERROR] tmux not installed. Install with: apt install tmux")
            return 1
    else:
        watcher.watch(interval=interval, send_reports=args.send_report)
        return 0


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="wpguard",
        description="WordPressGuard - WordPress Plugin Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download top 10 plugins with 100k+ installs
  wpguard download --min-installs 100000 --count 10

  # Download all SEO plugins with 10k-100k installs, extract them
  wpguard download --search seo --min-installs 10000 --max-installs 100000 --count all -x

  # Get info about a specific plugin
  wpguard info akismet

  # Add plugins to watchlist
  wpguard watch add akismet wordfence contact-form-7

  # List watched plugins
  wpguard watch list

  # Check once for updates
  wpguard watch check

  # Start continuous monitoring (5 minute interval by default)
  wpguard watch

  # Start monitoring with custom interval
  wpguard watch --interval 1h30m

  # Start monitoring with Discord notifications in tmux
  wpguard watch --interval 30m --send-report --tmux

  # Search for plugins
  wpguard search "security"

  # View SVN commit history
  wpguard svn log akismet --limit 20

  # Compare SVN revisions
  wpguard svn diff akismet 3000000 3000100
        """,
    )

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Download command
    dl_parser = subparsers.add_parser(
        "download", help="Download plugins from WordPress repository"
    )
    dl_parser.add_argument("--search", "-s", help="Search term for plugins")
    dl_parser.add_argument(
        "--min-installs",
        type=int,
        default=0,
        help="Minimum active installations (default: 0)",
    )
    dl_parser.add_argument(
        "--max-installs", type=int, default=None, help="Maximum active installations"
    )
    dl_parser.add_argument(
        "--count",
        "-n",
        default="10",
        help="Number of plugins to download or 'all' (default: 10)",
    )
    dl_parser.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    dl_parser.add_argument(
        "--svn",
        action="store_true",
        help="Also checkout from SVN (in addition to ZIP download)",
    )
    dl_parser.add_argument(
        "--extract", "-x", action="store_true", help="Extract ZIP files after download"
    )
    dl_parser.add_argument(
        "--delay",
        "-d",
        type=int,
        default=DEFAULT_DELAY,
        help=f"Delay between downloads in seconds (default: {DEFAULT_DELAY})",
    )
    dl_parser.add_argument(
        "--browse",
        choices=["popular", "new", "updated"],
        help="Browse category filter",
    )
    dl_parser.set_defaults(func=cmd_download)

    # SVN subcommands
    svn_parser = subparsers.add_parser("svn", help="SVN operations for change tracking")
    svn_sub = svn_parser.add_subparsers(dest="svn_cmd", help="SVN commands")

    # svn diff
    svn_diff = svn_sub.add_parser(
        "diff", help="Show changes between SVN revisions"
    )
    svn_diff.add_argument("slug", help="Plugin slug")
    svn_diff.add_argument("old_rev", help="Old revision number")
    svn_diff.add_argument(
        "new_rev", nargs="?", default="HEAD", help="New revision (default: HEAD)"
    )
    svn_diff.add_argument(
        "--show-diff", action="store_true", help="Show full diff output"
    )
    svn_diff.add_argument(
        "--output-file", "-o", help="Save diff to file"
    )
    svn_diff.set_defaults(func=cmd_svn_diff)

    # svn log
    svn_log = svn_sub.add_parser("log", help="Show SVN commit log")
    svn_log.add_argument("slug", help="Plugin slug")
    svn_log.add_argument(
        "--limit", "-l", type=int, default=10, help="Number of entries (default: 10)"
    )
    svn_log.set_defaults(func=cmd_svn_log)

    # Info command
    info_parser = subparsers.add_parser(
        "info", help="Get information about a specific plugin"
    )
    info_parser.add_argument("slug", help="Plugin slug (e.g., 'akismet')")
    info_parser.set_defaults(func=cmd_info)

    # Search command
    search_parser = subparsers.add_parser("search", help="Search for plugins")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument(
        "--page", "-p", type=int, default=1, help="Page number (default: 1)"
    )
    search_parser.add_argument(
        "--per-page",
        type=int,
        default=20,
        help="Results per page, max 250 (default: 20)",
    )
    search_parser.set_defaults(func=cmd_search)

    # Watch command (consolidated from monitor + watch)
    watch_parser = subparsers.add_parser(
        "watch",
        help="Watch plugins for updates",
        description="Watch plugins for updates. Use subcommands to manage watchlist, or run without subcommand for continuous monitoring.",
    )

    # Add common watch options
    watch_parser.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    watch_parser.add_argument(
        "--interval",
        "-i",
        default="5m",
        help="Check interval: 30s, 5m, 1h, 1h30m, or seconds (default: 5m)",
    )
    watch_parser.add_argument(
        "--send-report", action="store_true", help="Send reports to Discord"
    )
    watch_parser.add_argument("--discord-webhook", help="Discord webhook URL")
    watch_parser.add_argument(
        "--tmux", action="store_true", help="Start in tmux session"
    )
    watch_parser.add_argument(
        "--tmux-session", default="wpguard", help="Tmux session name (default: wpguard)"
    )

    watch_sub = watch_parser.add_subparsers(dest="watch_cmd", help="Watch subcommands")

    # watch add
    watch_add = watch_sub.add_parser("add", help="Add plugins to watchlist")
    watch_add.add_argument("slugs", nargs="+", help="Plugin slugs to watch")
    watch_add.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    watch_add.add_argument("--discord-webhook", help="Discord webhook URL")
    watch_add.set_defaults(func=cmd_watch_add)

    # watch remove
    watch_rm = watch_sub.add_parser("remove", help="Remove plugins from watchlist")
    watch_rm.add_argument("slugs", nargs="+", help="Plugin slugs to remove")
    watch_rm.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    watch_rm.set_defaults(func=cmd_watch_remove)

    # watch list
    watch_list = watch_sub.add_parser("list", help="List watched plugins")
    watch_list.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    watch_list.set_defaults(func=cmd_watch_list)

    # watch check
    watch_check = watch_sub.add_parser("check", help="Check once for updates (no loop)")
    watch_check.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    watch_check.add_argument(
        "--send-report", action="store_true", help="Send report to Discord"
    )
    watch_check.add_argument("--discord-webhook", help="Discord webhook URL")
    watch_check.set_defaults(func=cmd_watch_check)

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "svn" and not getattr(args, "svn_cmd", None):
        # Print svn subcommand help
        parser.parse_args(["svn", "--help"])
        return 0

    # Handle watch command - no subcommand means start continuous monitoring
    if args.command == "watch" and not getattr(args, "watch_cmd", None):
        return cmd_watch_start(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
