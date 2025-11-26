#!/usr/bin/env python3
"""
MCP Server for WordPressGuard.

Exposes all WordPressGuard functionality as MCP tools for use with Claude and other AI assistants.
"""

import asyncio
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.config import (
    DEFAULT_OUTPUT_DIR,
    PLUGINS_SUBDIR,
    WP_PLUGINS_SVN,
    WP_PLUGINS_URL,
)
from wpguard.core.downloader import PluginDownloader, SVNClient
from wpguard.core.watcher import PluginWatcher


# Initialize the MCP server
server = Server("wpguard")

# Thread pool for running blocking operations
_executor = ThreadPoolExecutor(max_workers=4)


def _check_svn_available() -> bool:
    """Check if SVN is installed and available."""
    try:
        result = subprocess.run(
            ["svn", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


async def run_in_executor(func, *args, **kwargs):
    """Run a blocking function in a thread pool executor."""
    loop = asyncio.get_event_loop()
    if kwargs:
        func = partial(func, **kwargs)
    return await loop.run_in_executor(_executor, func, *args)


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available WordPressGuard tools."""
    return [
        Tool(
            name="wpguard_plugin_info",
            description="Get detailed information about a specific WordPress plugin by its slug",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug (e.g., 'akismet', 'wordfence')",
                    }
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_search",
            description="Search for WordPress plugins in the official repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'security', 'seo', 'backup')",
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number (default: 1)",
                        "default": 1,
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Results per page, max 250 (default: 20)",
                        "default": 20,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="wpguard_download",
            description="Download a WordPress plugin (ZIP and optionally SVN)",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug to download",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                    "extract": {
                        "type": "boolean",
                        "description": "Extract ZIP after download (default: true)",
                        "default": True,
                    },
                    "svn": {
                        "type": "boolean",
                        "description": "Also checkout from SVN (default: false)",
                        "default": False,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_bulk_download",
            description="Download multiple plugins with filtering by active installations",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Search term to filter plugins",
                    },
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations (default: 0)",
                        "default": 0,
                    },
                    "max_installs": {
                        "type": "integer",
                        "description": "Maximum active installations",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of plugins to download (default: 10)",
                        "default": 10,
                    },
                    "browse": {
                        "type": "string",
                        "description": "Browse category: 'popular', 'new', or 'updated'",
                        "enum": ["popular", "new", "updated"],
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                    "extract": {
                        "type": "boolean",
                        "description": "Extract ZIP files (default: true)",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_add",
            description="Add plugins to the watchlist for update monitoring",
            inputSchema={
                "type": "object",
                "properties": {
                    "slugs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of plugin slugs to watch",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["slugs"],
            },
        ),
        Tool(
            name="wpguard_watch_remove",
            description="Remove plugins from the watchlist",
            inputSchema={
                "type": "object",
                "properties": {
                    "slugs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of plugin slugs to remove from watchlist",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["slugs"],
            },
        ),
        Tool(
            name="wpguard_watch_list",
            description="List all plugins currently being watched",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_check",
            description="Check watched plugins for updates (single check, no continuous loop)",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_svn_log",
            description="Get SVN commit history for a WordPress plugin",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of log entries to retrieve (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_svn_diff",
            description="Compare changes between SVN revisions for a plugin",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "old_rev": {
                        "type": "string",
                        "description": "Old revision number",
                    },
                    "new_rev": {
                        "type": "string",
                        "description": "New revision number (default: HEAD)",
                        "default": "HEAD",
                    },
                    "show_diff": {
                        "type": "boolean",
                        "description": "Include full diff output (default: false)",
                        "default": False,
                    },
                },
                "required": ["slug", "old_rev"],
            },
        ),
        Tool(
            name="wpguard_svn_revision",
            description="Get the latest SVN revision number for a plugin",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_plugin_versions",
            description="Get all available versions for a WordPress plugin",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_state_info",
            description="Get current state information (watched plugins count, last check, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        result = await _execute_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def _execute_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute the requested tool and return the result."""

    if name == "wpguard_plugin_info":
        return await _plugin_info(arguments["slug"])

    elif name == "wpguard_search":
        return await _search(
            arguments["query"],
            arguments.get("page", 1),
            arguments.get("per_page", 20),
        )

    elif name == "wpguard_download":
        return await _download(
            arguments["slug"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
            arguments.get("extract", True),
            arguments.get("svn", False),
        )

    elif name == "wpguard_bulk_download":
        return await _bulk_download(
            arguments.get("search"),
            arguments.get("min_installs", 0),
            arguments.get("max_installs"),
            arguments.get("count", 10),
            arguments.get("browse"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
            arguments.get("extract", True),
        )

    elif name == "wpguard_watch_add":
        return await _watch_add(
            arguments["slugs"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_watch_remove":
        return await _watch_remove(
            arguments["slugs"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_watch_list":
        return await _watch_list(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    elif name == "wpguard_watch_check":
        return await _watch_check(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    elif name == "wpguard_svn_log":
        return await _svn_log(
            arguments["slug"],
            arguments.get("limit", 10),
        )

    elif name == "wpguard_svn_diff":
        return await _svn_diff(
            arguments["slug"],
            arguments["old_rev"],
            arguments.get("new_rev", "HEAD"),
            arguments.get("show_diff", False),
        )

    elif name == "wpguard_svn_revision":
        return await _svn_revision(arguments["slug"])

    elif name == "wpguard_plugin_versions":
        return await _plugin_versions(arguments["slug"])

    elif name == "wpguard_state_info":
        return await _state_info(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    else:
        raise ValueError(f"Unknown tool: {name}")


# Tool implementations


async def _plugin_info(slug: str) -> dict[str, Any]:
    """Get detailed plugin information."""
    api = WordPressPluginAPI()
    plugin = api.get_plugin_info(slug)

    if not plugin:
        return {"error": f"Plugin '{slug}' not found"}

    return {
        "slug": plugin.slug,
        "name": plugin.name,
        "version": plugin.version,
        "active_installs": plugin.active_installs,
        "rating": plugin.rating,
        "num_ratings": plugin.num_ratings,
        "last_updated": plugin.last_updated,
        "requires_wp": plugin.requires,
        "tested_up_to": plugin.tested,
        "requires_php": plugin.requires_php,
        "short_description": plugin.short_description,
        "download_link": plugin.download_link,
        "svn_url": f"{WP_PLUGINS_SVN}{plugin.slug}/",
        "plugin_page": f"{WP_PLUGINS_URL}{plugin.slug}/",
    }


async def _search(query: str, page: int, per_page: int) -> dict[str, Any]:
    """Search for plugins."""
    api = WordPressPluginAPI()
    plugins, total_pages = api.query_plugins(search=query, page=page, per_page=per_page)

    return {
        "query": query,
        "page": page,
        "total_pages": total_pages,
        "results_count": len(plugins),
        "results": [
            {
                "slug": p.slug,
                "name": p.name,
                "version": p.version,
                "active_installs": p.active_installs,
                "rating": p.rating,
                "short_description": p.short_description,
            }
            for p in plugins
        ],
    }


async def _download(
    slug: str, output_dir: str, extract: bool, svn: bool
) -> dict[str, Any]:
    """Download a single plugin."""
    api = WordPressPluginAPI()
    plugin = api.get_plugin_info(slug)

    if not plugin:
        return {"error": f"Plugin '{slug}' not found"}

    plugins_dir = f"{output_dir}/{PLUGINS_SUBDIR}"
    downloader = PluginDownloader(plugins_dir)

    result = downloader.download_plugin(plugin, extract=extract, svn=svn)

    return {
        "slug": result.slug,
        "version": result.version,
        "zip_path": str(result.zip_path) if result.zip_path else None,
        "extracted_path": str(result.extracted_path) if result.extracted_path else None,
        "svn_path": str(result.svn_path) if result.svn_path else None,
        "success": result.zip_path is not None,
    }


async def _bulk_download(
    search: str | None,
    min_installs: int,
    max_installs: int | None,
    count: int,
    browse: str | None,
    output_dir: str,
    extract: bool,
) -> dict[str, Any]:
    """Bulk download plugins."""
    api = WordPressPluginAPI()
    plugins_dir = f"{output_dir}/{PLUGINS_SUBDIR}"
    downloader = PluginDownloader(plugins_dir)

    # Fetch plugins matching criteria
    plugins = api.fetch_all_plugins(
        search=search,
        min_installs=min_installs,
        max_installs=max_installs,
        limit=count,
        browse=browse,
    )

    downloaded = []
    for plugin in plugins:
        result = downloader.download_plugin(plugin, extract=extract, svn=False)
        downloaded.append(
            {
                "slug": plugin.slug,
                "name": plugin.name,
                "version": plugin.version,
                "active_installs": plugin.active_installs,
                "zip_path": str(result.zip_path) if result.zip_path else None,
                "extracted_path": str(result.extracted_path)
                if result.extracted_path
                else None,
                "success": result.zip_path is not None,
            }
        )

    return {
        "total_found": len(plugins),
        "downloaded": len([d for d in downloaded if d["success"]]),
        "output_dir": plugins_dir,
        "plugins": downloaded,
    }


async def _watch_add(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Add plugins to watchlist."""
    watcher = PluginWatcher(output_dir=output_dir)

    results = []
    for slug in slugs:
        success = watcher.add_plugin(slug)
        results.append({"slug": slug, "added": success})

    return {
        "added_count": sum(1 for r in results if r["added"]),
        "total_requested": len(slugs),
        "results": results,
        "watchlist_size": len(watcher.state["plugins"]),
    }


async def _watch_remove(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Remove plugins from watchlist."""
    watcher = PluginWatcher(output_dir=output_dir)

    results = []
    for slug in slugs:
        success = watcher.remove_plugin(slug)
        results.append({"slug": slug, "removed": success})

    return {
        "removed_count": sum(1 for r in results if r["removed"]),
        "total_requested": len(slugs),
        "results": results,
        "watchlist_size": len(watcher.state["plugins"]),
    }


async def _watch_list(output_dir: str) -> dict[str, Any]:
    """List watched plugins."""
    watcher = PluginWatcher(output_dir=output_dir)
    plugins = watcher.list_watched()

    return {
        "count": len(plugins),
        "last_check": watcher.state.get("last_check"),
        "plugins": plugins,
    }


async def _watch_check(output_dir: str) -> dict[str, Any]:
    """Check for plugin updates."""
    watcher = PluginWatcher(output_dir=output_dir)
    results = watcher.check_updates()

    updates = []
    for report, svn_change in results:
        update_info = {
            "slug": report.plugin_slug,
            "name": report.plugin_name,
            "old_version": report.old_version,
            "new_version": report.new_version,
            "changed_files": report.changed_files[:20],
            "added_files": report.added_files[:20],
            "removed_files": report.removed_files[:20],
            "total_changes": report.total_changes,
            "download_link": report.download_link,
        }

        if svn_change:
            update_info["svn_old_revision"] = svn_change.old_revision
            update_info["svn_new_revision"] = svn_change.new_revision
            update_info["svn_log"] = svn_change.log_entries[:5]

        updates.append(update_info)

    return {
        "updates_found": len(updates),
        "plugins_checked": len(watcher.state["plugins"]),
        "updates": updates,
    }


def _svn_log_sync(slug: str, limit: int) -> dict[str, Any]:
    """Get SVN log for a plugin (sync version)."""
    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion", "entries": []}

    svn = SVNClient()
    entries = svn.get_log(slug, limit=limit)

    if not entries:
        return {"error": f"No SVN log entries found for '{slug}'", "entries": []}

    return {
        "slug": slug,
        "entries_count": len(entries),
        "entries": entries,
    }


async def _svn_log(slug: str, limit: int) -> dict[str, Any]:
    """Get SVN log for a plugin."""
    return await run_in_executor(_svn_log_sync, slug, limit)


def _svn_diff_sync(
    slug: str, old_rev: str, new_rev: str, show_diff: bool
) -> dict[str, Any]:
    """Get SVN diff between revisions (sync version)."""
    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion"}

    svn = SVNClient()
    change_info = svn.compare_revisions(slug, old_rev, new_rev)

    result = {
        "slug": slug,
        "old_revision": change_info.old_revision,
        "new_revision": change_info.new_revision,
        "changed_files": change_info.changed_files,
        "added_files": change_info.added_files,
        "removed_files": change_info.removed_files,
        "total_changes": change_info.total_changes,
        "log_entries": change_info.log_entries[:10],
    }

    if show_diff:
        # Truncate diff for response
        diff = change_info.diff_output
        if len(diff) > 50000:
            diff = diff[:50000] + "\n... [truncated]"
        result["diff_output"] = diff

    return result


async def _svn_diff(
    slug: str, old_rev: str, new_rev: str, show_diff: bool
) -> dict[str, Any]:
    """Get SVN diff between revisions."""
    return await run_in_executor(_svn_diff_sync, slug, old_rev, new_rev, show_diff)


def _svn_revision_sync(slug: str) -> dict[str, Any]:
    """Get latest SVN revision for a plugin (sync version)."""
    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion"}

    svn = SVNClient()
    revision = svn.get_latest_revision(slug)

    if not revision:
        return {"error": f"Could not get SVN revision for '{slug}'"}

    return {
        "slug": slug,
        "latest_revision": revision,
        "svn_url": f"{WP_PLUGINS_SVN}{slug}/",
    }


async def _svn_revision(slug: str) -> dict[str, Any]:
    """Get latest SVN revision for a plugin."""
    return await run_in_executor(_svn_revision_sync, slug)


async def _plugin_versions(slug: str) -> dict[str, Any]:
    """Get all available versions for a plugin."""
    api = WordPressPluginAPI()
    versions = api.get_plugin_versions(slug)

    if not versions:
        return {"error": f"Could not get versions for '{slug}'", "versions": []}

    return {
        "slug": slug,
        "versions_count": len(versions),
        "versions": versions,
    }


async def _state_info(output_dir: str) -> dict[str, Any]:
    """Get current state information."""
    watcher = PluginWatcher(output_dir=output_dir)
    return watcher.get_state_info()


async def run_server():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point for the MCP server."""
    import asyncio

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
