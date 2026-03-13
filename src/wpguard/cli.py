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
from wpguard.core.init import initialize_research_project
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

    # Single plugin download mode
    if args.plugin:
        plugin = api.get_plugin_info(args.plugin)
        if not plugin:
            print(f"[ERROR] Plugin '{args.plugin}' not found")
            return 1

        print(f"\n[*] {plugin.name} ({plugin.slug})")
        print(f"    Active installs: {plugin.active_installs:,}")
        print(f"    Version: {plugin.version}")

        result = downloader.download_plugin(
            plugin,
            extract=args.extract,
            svn=args.svn,
        )

        if result.zip_path:
            print(f"    ZIP: {result.zip_path}")
        if result.extracted_path:
            print(f"    Extracted: {result.extracted_path}")
        if result.svn_path:
            print(f"    SVN: {result.svn_path}")

        print(f"\n[+] Download complete. Files saved to: {plugins_dir}")
        return 0

    # Bulk download mode
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


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a research project with agent instructions."""
    result = initialize_research_project(args.directory)

    if result["success"]:
        print(f"\n[+] Research project initialized: {result['path']}")
        print("\n[*] Created structure:")
        print(f"    CLAUDE.md            - Project instructions")
        print(f"    .claude/commands/    - Slash commands (/pm, /target-research)")
        print(f"    .claude/agents/      - Expert agents ({len(result['structure']['agents'])} agents)")
        print(f"    targets/             - Plugin source code")
        print(f"    reports/             - Findings and PoCs")
        print(f"    findings.json        - Vulnerability findings")
        print("\n[*] Slash commands:")
        for cmd in result["structure"]["commands"]:
            print(f"    {cmd}")
        print("\n[*] Expert agents:")
        for agent in result["structure"]["agents"]:
            print(f"    {agent}")
        print(f"\n[*] Next steps:")
        print(f"    cd {result['path']}")
        print(f"    claude  # Start Claude Code in the project directory")
        print(f"    /pm     # Start the PM orchestrator")
        return 0
    else:
        print(f"[ERROR] {result['message']}")
        return 1


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

    # Interactive mode - show numbered list and allow selection
    if args.interactive:
        return _interactive_search(plugins, args, total_pages)

    # Normal mode - just display results
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


def _interactive_search(plugins: list, args: argparse.Namespace, total_pages: int) -> int:
    """Interactive search mode - select plugins to add to watchlist."""
    print(f"\n[*] Search results for '{args.query}' (page {args.page}/{total_pages}):\n")
    print(f"{'#':<4} {'Slug':<30} {'Installs':<12} {'Version':<10} Name")
    print("-" * 100)

    for i, p in enumerate(plugins, 1):
        installs = f"{p.active_installs:,}"
        name = (p.name[:35] + "...") if len(p.name) > 35 else p.name
        print(f"{i:<4} {p.slug:<30} {installs:<12} {p.version:<10} {name}")

    print("-" * 100)
    print(f"\nPage {args.page} of {total_pages}")
    print("\nEnter numbers to add to watchlist (comma-separated, e.g., 1,3,5)")
    print("Or: 'all' to add all, 'q' to quit, 'n' for next page, 'p' for prev page")

    while True:
        try:
            selection = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled")
            return 0

        if selection == 'q' or selection == 'quit':
            print("[*] Cancelled")
            return 0

        if selection == 'n' or selection == 'next':
            if args.page < total_pages:
                args.page += 1
                from wpguard.api.wordpress import WordPressPluginAPI
                api = WordPressPluginAPI()
                plugins, total_pages = api.query_plugins(
                    search=args.query, page=args.page, per_page=args.per_page
                )
                return _interactive_search(plugins, args, total_pages)
            else:
                print("[!] Already on last page")
                continue

        if selection == 'p' or selection == 'prev':
            if args.page > 1:
                args.page -= 1
                from wpguard.api.wordpress import WordPressPluginAPI
                api = WordPressPluginAPI()
                plugins, total_pages = api.query_plugins(
                    search=args.query, page=args.page, per_page=args.per_page
                )
                return _interactive_search(plugins, args, total_pages)
            else:
                print("[!] Already on first page")
                continue

        # Determine which plugins to add
        slugs_to_add = []

        if selection == 'all':
            slugs_to_add = [p.slug for p in plugins]
        else:
            # Parse comma-separated numbers or ranges (e.g., "1,3,5" or "1-5,7")
            try:
                indices = set()
                for part in selection.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = part.split('-', 1)
                        for i in range(int(start), int(end) + 1):
                            indices.add(i)
                    elif part.isdigit():
                        indices.add(int(part))

                for idx in sorted(indices):
                    if 1 <= idx <= len(plugins):
                        slugs_to_add.append(plugins[idx - 1].slug)
                    else:
                        print(f"[!] Invalid number: {idx}")
            except ValueError:
                print("[!] Invalid input. Use numbers like: 1,3,5 or 1-5 or 'all'")
                continue

        if not slugs_to_add:
            print("[!] No valid selections")
            continue

        # Add selected plugins to watchlist
        print(f"\n[*] Adding {len(slugs_to_add)} plugin(s) to watchlist...")
        watcher = PluginWatcher(output_dir=args.output_dir)

        success_count = 0
        for slug in slugs_to_add:
            if watcher.add_plugin(slug):
                success_count += 1

        print(f"\n[+] Added {success_count}/{len(slugs_to_add)} plugins to watchlist")
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

    # Interactive mode - show list and let user select
    if args.interactive:
        return _interactive_remove(watcher)

    # Check if slugs were provided
    if not args.slugs:
        print("[ERROR] No plugins specified. Use -i for interactive mode or provide slugs.")
        return 1

    for slug in args.slugs:
        watcher.remove_plugin(slug)

    return 0


def _interactive_remove(watcher: PluginWatcher) -> int:
    """Interactive remove mode - select plugins to remove from watchlist."""
    plugins = watcher.list_watched()

    if not plugins:
        print("[*] No plugins in watchlist")
        return 0

    print("\n[*] Current watchlist:\n")
    print(f"{'#':<4} {'Slug':<30} {'Version':<12} Name")
    print("-" * 80)

    for i, p in enumerate(plugins, 1):
        svn_info = f" (r{p['svn_revision']})" if p.get('svn_revision') else ""
        print(f"{i:<4} {p['slug']:<30} {p['version']:<12} {p['name'][:30]}{svn_info}")

    print("-" * 80)
    print(f"\nTotal: {len(plugins)} plugin(s)")
    print("\nEnter numbers to remove (comma-separated, e.g., 1,3,5)")
    print("Or: 'all' to remove all, 'q' to quit")

    while True:
        try:
            selection = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled")
            return 0

        if selection == 'q' or selection == 'quit':
            print("[*] Cancelled")
            return 0

        # Determine which plugins to remove
        slugs_to_remove = []

        if selection == 'all':
            slugs_to_remove = [p['slug'] for p in plugins]
        else:
            # Parse comma-separated numbers or ranges
            try:
                indices = set()
                for part in selection.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = part.split('-', 1)
                        for i in range(int(start), int(end) + 1):
                            indices.add(i)
                    elif part.isdigit():
                        indices.add(int(part))

                for idx in sorted(indices):
                    if 1 <= idx <= len(plugins):
                        slugs_to_remove.append(plugins[idx - 1]['slug'])
                    else:
                        print(f"[!] Invalid number: {idx}")
            except ValueError:
                print("[!] Invalid input. Use numbers like: 1,3,5 or 1-5 or 'all'")
                continue

        if not slugs_to_remove:
            print("[!] No valid selections")
            continue

        # Confirm removal
        print(f"\n[?] Remove {len(slugs_to_remove)} plugin(s)? [y/N] ", end="")
        try:
            confirm = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled")
            return 0

        if confirm != 'y' and confirm != 'yes':
            print("[*] Cancelled")
            continue

        # Remove selected plugins
        for slug in slugs_to_remove:
            watcher.remove_plugin(slug)

        print(f"\n[+] Removed {len(slugs_to_remove)} plugin(s) from watchlist")
        return 0


def cmd_watch_list(args: argparse.Namespace) -> int:
    """List watched plugins."""
    watcher = PluginWatcher(output_dir=args.output_dir)
    watcher.print_watched()
    return 0


def cmd_watch_status(args: argparse.Namespace) -> int:
    """Show status of running wpguard tmux sessions."""
    try:
        # Get list of tmux sessions
        result = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("[*] No tmux sessions running")
            return 0

        sessions = result.stdout.strip().split("\n")
        wpguard_sessions = [s for s in sessions if s.startswith("wpguard")]

        if not wpguard_sessions:
            print("[*] No wpguard watch sessions running")
            return 0

        print("\n[*] Running wpguard watch sessions:")
        print("-" * 70)

        for session in wpguard_sessions:
            # Capture recent output from the session
            pane_result = subprocess.run(
                ["tmux", "capture-pane", "-t", session, "-p"],
                capture_output=True,
                text=True,
            )

            print(f"\n  Session: {session}")

            # Parse output to find what's being watched
            if pane_result.returncode == 0:
                output_lines = pane_result.stdout.strip().split("\n")
                interval_info = None
                watching_info = None
                status_info = None

                for line in output_lines:
                    line = line.strip()
                    if not line:
                        continue
                    if "Watching" in line and "plugins" in line:
                        watching_info = line
                    elif "interval:" in line:
                        interval_info = line
                    elif "Next check in" in line:
                        status_info = line

                if interval_info:
                    print(f"  {interval_info}")
                if watching_info:
                    print(f"  {watching_info}")
                if status_info:
                    print(f"  Status: {status_info}")

            print(f"  Attach:  tmux attach -t {session}")
            print(f"  Stop:    wpguard watch stop {session}")

        print("-" * 70)
        return 0

    except FileNotFoundError:
        print("[ERROR] tmux not installed")
        return 1


def cmd_watch_stop(args: argparse.Namespace) -> int:
    """Stop a running wpguard tmux session."""
    session_name = args.session

    try:
        # Check if session exists
        check = subprocess.run(
            ["tmux", "has-session", "-t", session_name],
            capture_output=True,
        )
        if check.returncode != 0:
            print(f"[ERROR] Session '{session_name}' not found")

            # List available sessions
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                sessions = [s for s in result.stdout.strip().split("\n") if s.startswith("wpguard")]
                if sessions:
                    print("\n[*] Available wpguard sessions:")
                    for s in sessions:
                        print(f"    - {s}")
            return 1

        # Kill the session
        subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            check=True,
        )
        print(f"[+] Stopped watch session: {session_name}")
        return 0

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to stop session: {e}")
        return 1
    except FileNotFoundError:
        print("[ERROR] tmux not installed")
        return 1


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
  # Initialize a new research project
  wpguard init autoresearch
  wpguard init /tmp/my-research

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
    dl_parser.add_argument(
        "--plugin", "-p",
        help="Download a single plugin by slug (e.g., --plugin akismet)",
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

    # Init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a research project with agent instructions",
        description="Create a new security research project with CLAUDE.md, slash commands, and directory structure for Wordfence Bug Bounty research.",
    )
    init_parser.add_argument(
        "directory",
        help="Directory to initialize (e.g., 'autoresearch' or '/tmp/my-research')",
    )
    init_parser.set_defaults(func=cmd_init)

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
    search_parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive mode: select plugins to add to watchlist",
    )
    search_parser.add_argument(
        "--output-dir",
        "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for watchlist (default: {DEFAULT_OUTPUT_DIR})",
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
    watch_rm.add_argument("slugs", nargs="*", help="Plugin slugs to remove (or use -i)")
    watch_rm.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive mode: select plugins to remove",
    )
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

    # watch status
    watch_status = watch_sub.add_parser("status", help="Show running watch sessions")
    watch_status.set_defaults(func=cmd_watch_status)

    # watch stop
    watch_stop = watch_sub.add_parser("stop", help="Stop a running watch session")
    watch_stop.add_argument(
        "session",
        nargs="?",
        default="wpguard",
        help="Session name to stop (default: wpguard)",
    )
    watch_stop.set_defaults(func=cmd_watch_stop)

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
