#!/usr/bin/env python3
"""
MCP Server for WordPressGuard.

Exposes all WordPressGuard functionality as MCP tools for use with Claude and other AI assistants.
"""

import asyncio
import json
import shutil
from datetime import datetime, timezone
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
    PLUGINS_SUBDIR,
    WP_PLUGINS_SVN,
    WP_PLUGINS_URL,
)
from wpguard.core.downloader import PluginDownloader, SVNClient, CoreDownloader
from wpguard.api.wordpress_core import WordPressCoreAPI

# MCP-specific default: use current directory so tools work in initialized project root
# CLI uses DEFAULT_OUTPUT_DIR from config (./wpguard_output) for standalone usage
DEFAULT_OUTPUT_DIR = "."
from wpguard.api.themes import WordPressThemeAPI
from wpguard.core.watcher import PluginWatcher
from wpguard.core.sandbox import WordPressSandbox
from wpguard.core.scope_validator import WorkfenceScopeValidator
from wpguard.core.findings import FindingsManager
from wpguard.notifications.discord import DiscordNotifier
from wpguard.config import DISCORD_WEBHOOK_URL


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
            description="Get detailed plugin information by slug",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    }
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_search",
            description="Search WordPress plugin repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number",
                        "default": 1,
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Results per page, max 250",
                        "default": 20,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="wpguard_download",
            description="Download a WordPress plugin ZIP, optionally with SVN checkout",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                    "extract": {
                        "type": "boolean",
                        "description": "Extract ZIP after download",
                        "default": True,
                    },
                    "svn": {
                        "type": "boolean",
                        "description": "Also checkout from SVN",
                        "default": False,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_bulk_download",
            description="Bulk download plugins with install count filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Search term",
                    },
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations",
                        "default": 0,
                    },
                    "max_installs": {
                        "type": "integer",
                        "description": "Maximum active installations",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of plugins to download",
                        "default": 10,
                    },
                    "browse": {
                        "type": "string",
                        "description": "Browse category",
                        "enum": ["popular", "new", "updated"],
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                    "extract": {
                        "type": "boolean",
                        "description": "Extract ZIP files",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_add",
            description="Add plugins to the update watchlist",
            inputSchema={
                "type": "object",
                "properties": {
                    "slugs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Plugin slugs to watch",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
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
                        "description": "Plugin slugs to remove",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["slugs"],
            },
        ),
        Tool(
            name="wpguard_watch_list",
            description="List all watched plugins",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_check",
            description="Check watched plugins for updates (single check)",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_global",
            description="Recently updated plugins (new since last check)",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations filter",
                        "default": 1000,
                    },
                    "max_pages": {
                        "type": "integer",
                        "description": "API pages to fetch, 250 plugins/page",
                        "default": 2,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_new",
            description="Newly added plugins (not seen in previous checks)",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations filter",
                        "default": 0,
                    },
                    "max_pages": {
                        "type": "integer",
                        "description": "API pages to fetch, 250 plugins/page",
                        "default": 2,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        # ── Theme Tools ──────────────────────────────────────
        Tool(
            name="wpguard_theme_info",
            description="Get detailed theme information by slug",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Theme slug",
                    }
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_theme_search",
            description="Search WordPress theme repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number",
                        "default": 1,
                    },
                    "browse": {
                        "type": "string",
                        "description": "Browse category",
                        "enum": ["popular", "new", "updated"],
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_theme_download",
            description="Download a WordPress theme ZIP",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Theme slug",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                    "extract": {
                        "type": "boolean",
                        "description": "Extract ZIP after download",
                        "default": True,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_theme_svn_log",
            description="Get SVN commit history for a theme",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Theme slug",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max log entries",
                        "default": 10,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_theme_svn_diff",
            description="Diff between SVN revisions for a theme",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Theme slug",
                    },
                    "old_rev": {
                        "type": "string",
                        "description": "Old revision number",
                    },
                    "new_rev": {
                        "type": "string",
                        "description": "New revision (default: HEAD)",
                        "default": "HEAD",
                    },
                    "show_diff": {
                        "type": "boolean",
                        "description": "Include full diff output",
                        "default": False,
                    },
                },
                "required": ["slug", "old_rev"],
            },
        ),
        Tool(
            name="wpguard_watch_global_themes",
            description="Recently updated themes (new since last check)",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations filter",
                        "default": 1000,
                    },
                    "max_pages": {
                        "type": "integer",
                        "description": "API pages to fetch, 250 themes/page",
                        "default": 2,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_watch_new_themes",
            description="Newly added themes (not seen in previous checks)",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_installs": {
                        "type": "integer",
                        "description": "Minimum active installations filter",
                        "default": 0,
                    },
                    "max_pages": {
                        "type": "integer",
                        "description": "API pages to fetch, 250 themes/page",
                        "default": 2,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        # ── Plugin SVN Tools ────────────────────────────────
        Tool(
            name="wpguard_svn_log",
            description="Get SVN commit history for a plugin",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max log entries",
                        "default": 10,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_svn_diff",
            description="Diff between SVN revisions for a plugin",
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
                        "description": "New revision (default: HEAD)",
                        "default": "HEAD",
                    },
                    "show_diff": {
                        "type": "boolean",
                        "description": "Include full diff output",
                        "default": False,
                    },
                },
                "required": ["slug", "old_rev"],
            },
        ),
        Tool(
            name="wpguard_svn_revision",
            description="Get latest SVN revision number for a plugin",
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
            description="List all available versions for a plugin",
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
        # ── Core Tools ──────────────────────────────────────
        Tool(
            name="wpguard_core_versions",
            description="List WordPress core versions with latest/security-release flags",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max versions to return (newest first)",
                        "default": 25,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_core_download",
            description="Download a WordPress core version tag into targets/core-{version}/extracted/",
            inputSchema={
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string",
                        "description": "Core version (e.g. 6.9.4)",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["version"],
            },
        ),
        Tool(
            name="wpguard_core_svn_diff",
            description="Diff two WordPress core version tags (changed files + unified diff)",
            inputSchema={
                "type": "object",
                "properties": {
                    "from_version": {
                        "type": "string",
                        "description": "Older core version tag (e.g. 6.9.4)",
                    },
                    "to_version": {
                        "type": "string",
                        "description": "Newer core version tag (e.g. 7.0.2)",
                    },
                    "show_diff": {
                        "type": "boolean",
                        "description": "Include full diff output",
                        "default": False,
                    },
                },
                "required": ["from_version", "to_version"],
            },
        ),
        Tool(
            name="wpguard_state_info",
            description="Get current watcher state (counts, last check timestamps)",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        # WordPress Sandbox Tools
        Tool(
            name="wpguard_sandbox_status",
            description="Check sandbox connectivity (HTTP, Docker, WP-CLI)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_install_plugin",
            description="Install and activate a plugin in the sandbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "version": {
                        "type": "string",
                        "description": "Specific version (default: latest)",
                    },
                    "activate": {
                        "type": "boolean",
                        "description": "Activate after install",
                        "default": True,
                    },
                    "from_zip": {
                        "type": "string",
                        "description": "Local ZIP path instead of slug",
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_sandbox_uninstall_plugin",
            description="Uninstall a plugin from the sandbox",
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
            name="wpguard_sandbox_request",
            description="Execute an HTTP request against the sandbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                    },
                    "path": {
                        "type": "string",
                        "description": "URL path",
                    },
                    "data": {
                        "type": "object",
                        "description": "POST body or query params",
                    },
                    "auth": {
                        "type": "string",
                        "description": "Role to authenticate as, or null for unauth",
                        "enum": ["subscriber", "contributor", "author", "admin"],
                    },
                    "headers": {
                        "type": "object",
                        "description": "Additional HTTP headers",
                    },
                },
                "required": ["method", "path"],
            },
        ),
        Tool(
            name="wpguard_sandbox_wp_cli",
            description="Execute a WP-CLI command in the sandbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "WP-CLI command without 'wp' prefix",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="wpguard_sandbox_get_nonce",
            description="Generate a WordPress nonce for a given action",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Nonce action name",
                    },
                    "auth": {
                        "type": "string",
                        "description": "Role to authenticate as",
                        "enum": ["subscriber", "contributor", "author", "admin"],
                    },
                },
                "required": ["action"],
            },
        ),
        Tool(
            name="wpguard_sandbox_get_emails",
            description="Get captured emails from Mailpit (all wp_mail output)",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Search to/from/subject/body"},
                    "limit": {"type": "integer", "description": "Max emails to return", "default": 50},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_get_email_body",
            description="Get full email body by message ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "message_id": {"type": "string", "description": "Message ID from wpguard_sandbox_get_emails"},
                },
                "required": ["message_id"],
            },
        ),
        Tool(
            name="wpguard_sandbox_delete_emails",
            description="Delete all captured emails from Mailpit",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_list_endpoints",
            description="List registered REST API endpoints in the sandbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Filter by REST namespace",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_map_nonces",
            description="Crawl admin pages at each auth level, extract all nonces",
            inputSchema={
                "type": "object",
                "properties": {
                    "extra_pages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional page paths to crawl",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_regression_check",
            description="Re-run existing PoC scripts to detect incomplete patches",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin or theme slug",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_target_score",
            description="Score plugin/theme research priority (installs, CVEs, audit history)",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Single slug to score",
                    },
                    "slugs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Multiple slugs to score and rank",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output dir",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_semgrep_scan",
            description="Run semgrep WordPress security rules against source code",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_dir": {"type": "string", "description": "Path to source code directory"},
                    "category": {"type": "string", "description": "Filter by category", "enum": ["missing-auth", "sqli", "file-ops", "priv-esc", "idor", "crypto", "incomplete-fix"]},
                    "severity": {"type": "string", "description": "Minimum severity", "enum": ["INFO", "WARNING", "ERROR"], "default": "WARNING"},
                    "output_dir": {"type": "string", "description": "Save results to dir (JSON + markdown)"},
                },
                "required": ["target_dir"],
            },
        ),
        Tool(
            name="wpguard_progpilot_scan",
            description="Run progpilot PHP taint analysis in sandbox container",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_dir": {"type": "string", "description": "Path to source code on host"},
                    "timeout": {"type": "integer", "description": "Scan timeout in seconds", "default": 600},
                    "output_dir": {"type": "string", "description": "Save results to dir (JSON + markdown)"},
                },
                "required": ["target_dir"],
            },
        ),
        Tool(
            name="wpguard_agent_checkpoint",
            description="Save agent progress. Call FIRST (start), after every finding + every 3-5 files (progress), when done (complete/partial). Returns turn warnings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["start", "progress", "complete", "partial"], "description": "Checkpoint action"},
                    "agent_name": {"type": "string", "description": "Agent name"},
                    "plugin_slug": {"type": "string", "description": "Plugin slug"},
                    "files_analyzed": {"type": "array", "items": {"type": "string"}, "description": "Files fully analyzed since last checkpoint"},
                    "files_partial": {"type": "array", "items": {"type": "string"}, "description": "Files partially analyzed"},
                    "files_remaining": {"type": "array", "items": {"type": "string"}, "description": "Known files not yet analyzed"},
                    "findings_created": {"type": "array", "items": {"type": "string"}, "description": "Finding IDs created"},
                    "notes": {"type": "array", "items": {"type": "string"}, "description": "Observations to preserve"},
                    "priority_targets": {"type": "array", "items": {"type": "string"}, "description": "Initial targets (start only)"},
                    "output_dir": {"type": "string", "description": "Output dir", "default": DEFAULT_OUTPUT_DIR},
                },
                "required": ["action", "agent_name", "plugin_slug"],
            },
        ),
        Tool(
            name="wpguard_bounty_estimate",
            description="Estimate Wordfence bug bounty reward for a vulnerability",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": "Vulnerability type",
                        "enum": ["rce", "arbitrary_file_upload", "arbitrary_file_read", "arbitrary_file_deletion", "arbitrary_options_update", "authorization_bypass_admin", "privilege_escalation_admin", "sql_injection", "stored_xss", "reflected_xss", "csrf", "missing_authorization", "ssrf", "php_object_injection", "insecure_direct_object_reference", "file_inclusion", "privilege_escalation_non_admin", "authorization_bypass_non_admin", "information_disclosure", "backdoor"],
                    },
                    "install_count": {
                        "type": "integer",
                        "description": "Active installations",
                    },
                    "auth_level": {
                        "type": "string",
                        "description": "Auth level",
                        "enum": ["none", "low", "mid", "high"],
                        "default": "none",
                    },
                    "researcher_tier": {
                        "type": "integer",
                        "description": "0=Standard, 1=1337, 2=Resourceful",
                        "default": 0,
                    },
                },
                "required": ["vuln_type", "install_count"],
            },
        ),
        Tool(
            name="wpguard_finding_check_duplicate",
            description="Check for duplicate findings by file, function, and vuln type",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {"type": "string", "description": "Plugin slug"},
                    "affected_file": {"type": "string", "description": "Affected file path"},
                    "affected_function": {"type": "string", "description": "Affected function name"},
                    "vuln_type": {"type": "string", "description": "Vulnerability type"},
                    "output_dir": {"type": "string", "description": "Output dir", "default": DEFAULT_OUTPUT_DIR},
                },
                "required": ["plugin_slug", "affected_file"],
            },
        ),
        # Sandbox Management Tools
        Tool(
            name="wpguard_sandbox_start",
            description="Start the sandbox Docker containers (builds if needed)",
            inputSchema={
                "type": "object",
                "properties": {
                    "wait_ready": {
                        "type": "boolean",
                        "description": "Wait for WordPress to be ready",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait",
                        "default": 120,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_stop",
            description="Stop the sandbox Docker containers",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_restart",
            description="Restart the sandbox (stop then start)",
            inputSchema={
                "type": "object",
                "properties": {
                    "wait_ready": {
                        "type": "boolean",
                        "description": "Wait for WordPress to be ready",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_destroy",
            description="Destroy sandbox and remove all volumes (full reset)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_set_core_version",
            description=(
                "Pin the sandbox WordPress core to a specific version "
                "(wp core update --force, works for upgrade and downgrade) and "
                "reliably disable core auto-update so it stays pinned"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string",
                        "description": "Target core version, e.g. '6.9.4'",
                    },
                    "disable_auto_update": {
                        "type": "boolean",
                        "description": "Bake AUTOMATIC_UPDATER_DISABLED/WP_AUTO_UPDATE_CORE into wp-config.php",
                        "default": True,
                    },
                },
                "required": ["version"],
            },
        ),
        # Wordfence Scope Validation Tools
        Tool(
            name="wpguard_scope_check_plugin",
            description="Check if a plugin is eligible for Wordfence bounty scope",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "active_installs": {
                        "type": "integer",
                        "description": "Active installations",
                    },
                    "author": {
                        "type": "string",
                        "description": "Author name (vendor exclusion check)",
                    },
                    "is_available": {
                        "type": "boolean",
                        "description": "Available for download",
                        "default": True,
                    },
                },
                "required": ["plugin_slug", "active_installs"],
            },
        ),
        Tool(
            name="wpguard_scope_check_finding",
            description="Validate if a finding is eligible for Wordfence bounty",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "active_installs": {
                        "type": "integer",
                        "description": "Active installations",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Vulnerability type",
                    },
                    "auth_level": {
                        "type": "string",
                        "description": "Required auth level",
                        "enum": ["unauthenticated", "subscriber", "customer", "contributor", "author", "editor", "administrator"],
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "CVSS 3.1 score",
                    },
                    "author": {
                        "type": "string",
                        "description": "Plugin author name",
                    },
                },
                "required": ["plugin_slug", "active_installs", "vuln_type", "auth_level", "cvss_score"],
            },
        ),
        Tool(
            name="wpguard_scope_get_vulns",
            description="Get in-scope vulnerability types for an install count",
            inputSchema={
                "type": "object",
                "properties": {
                    "active_installs": {
                        "type": "integer",
                        "description": "Active installations",
                    },
                },
                "required": ["active_installs"],
            },
        ),
        # Finding Persistence Tools
        Tool(
            name="wpguard_finding_create",
            description="Create a new vulnerability finding",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {"type": "string", "description": "Plugin slug"},
                    "plugin_version": {"type": "string", "description": "Plugin version"},
                    "active_installs": {"type": "integer", "description": "Active installations"},
                    "vuln_type": {"type": "string", "description": "Vulnerability type"},
                    "title": {"type": "string", "description": "Finding title"},
                    "description": {"type": "string", "description": "Detailed description"},
                    "auth_level": {
                        "type": "string",
                        "description": "Required auth level",
                        "enum": ["unauthenticated", "subscriber", "customer", "contributor", "author", "editor", "administrator"],
                    },
                    "cvss_score": {"type": "number", "description": "CVSS 3.1 score"},
                    "cvss_vector": {"type": "string", "description": "CVSS vector string"},
                    "affected_file": {"type": "string", "description": "Affected file path"},
                    "affected_function": {"type": "string", "description": "Affected function name"},
                    "affected_line": {"type": "integer", "description": "Line number"},
                    "poc_path": {"type": "string", "description": "Path to PoC script"},
                    "tier": {"type": "string", "description": "Bounty tier"},
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": ["plugin_slug", "plugin_version", "active_installs", "vuln_type", "title", "description", "auth_level", "cvss_score", "cvss_vector", "affected_file"],
            },
        ),
        Tool(
            name="wpguard_finding_update",
            description="Update an existing finding",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "status": {
                        "type": "string",
                        "description": "New status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "validation_notes": {"type": "string", "description": "Validation notes"},
                    "submission_id": {"type": "string", "description": "Submission ID"},
                    "poc_path": {"type": "string", "description": "Path to PoC script"},
                    "auth_level": {
                        "type": "string",
                        "description": "Updated auth level",
                        "enum": ["unauthenticated", "subscriber", "customer", "contributor", "author", "editor", "administrator"],
                    },
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_finding_get",
            description="Get finding details by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_finding_list",
            description="List findings with optional filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {"type": "string", "description": "Filter by plugin slug"},
                    "status": {
                        "type": "string",
                        "description": "Filter by status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "vuln_type": {"type": "string", "description": "Filter by vuln type"},
                    "min_cvss": {"type": "number", "description": "Minimum CVSS score"},
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_finding_delete",
            description="Delete a finding by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_finding_stats",
            description="Get aggregate finding statistics",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": [],
            },
        ),
        # ── Audit History Tools ───────────────────────────────
        Tool(
            name="wpguard_audit_record",
            description="Record completed audit in history",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {"type": "string", "description": "Plugin or theme slug"},
                    "version": {"type": "string", "description": "Version audited"},
                    "asset_type": {"type": "string", "description": "Asset type", "enum": ["plugin", "theme"], "default": "plugin"},
                    "active_installs": {"type": "integer", "description": "Active installations", "default": 0},
                    "findings_count": {"type": "integer", "description": "Total findings", "default": 0},
                    "validated_count": {"type": "integer", "description": "Validated findings", "default": 0},
                    "status": {"type": "string", "description": "Audit status", "enum": ["completed", "partial", "skipped"], "default": "completed"},
                    "notes": {"type": "string", "description": "Audit notes", "default": ""},
                    "output_dir": {"type": "string", "description": "Output dir", "default": DEFAULT_OUTPUT_DIR},
                },
                "required": ["slug", "version"],
            },
        ),
        Tool(
            name="wpguard_audit_check",
            description="Check if slug was previously audited",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {"type": "string", "description": "Plugin or theme slug"},
                    "output_dir": {"type": "string", "description": "Output dir", "default": DEFAULT_OUTPUT_DIR},
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_audit_list",
            description="List all previously audited plugins/themes",
            inputSchema={
                "type": "object",
                "properties": {
                    "asset_type": {"type": "string", "description": "Filter by type", "enum": ["plugin", "theme"]},
                    "output_dir": {"type": "string", "description": "Output dir", "default": DEFAULT_OUTPUT_DIR},
                },
                "required": [],
            },
        ),
        # Discord Notification Tools
        Tool(
            name="wpguard_discord_notify_finding",
            description="Send a finding notification to Discord",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "title_prefix": {
                        "type": "string",
                        "description": "Title prefix",
                    },
                    "mention": {
                        "type": "string",
                        "description": "Discord mention string",
                    },
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_discord_notify_summary",
            description="Send findings summary to Discord",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Summary title",
                    },
                    "status_filter": {
                        "type": "string",
                        "description": "Filter by status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "output_dir": {"type": "string", "description": "Output dir"},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_discord_send_message",
            description="Send a text message to Discord",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message content"},
                },
                "required": ["message"],
            },
        ),
        # Project Initialization
        Tool(
            name="wpguard_init_research",
            description="Initialize a wpguard research project (agents, commands, dirs)",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Project directory",
                        "default": "./wpguard-research",
                    },
                },
                "required": [],
            },
        ),
        # Wordfence CVE Database Tools
        Tool(
            name="wpguard_cve_download",
            description="Download/refresh the Wordfence vulnerability database",
            inputSchema={
                "type": "object",
                "properties": {
                    "force": {
                        "type": "boolean",
                        "description": "Force re-download even if cache is fresh",
                        "default": False,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_cve_search",
            description="Search Wordfence CVE database by slug or keyword",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug for CVE lookup",
                    },
                    "query": {
                        "type": "string",
                        "description": "Search title and description",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Filter by vulnerability type",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results",
                        "default": 50,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_cve_get",
            description="Get detailed CVE info by Wordfence ID or CVE ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_id": {
                        "type": "string",
                        "description": "Wordfence UUID or CVE ID",
                    },
                },
                "required": ["vuln_id"],
            },
        ),
        Tool(
            name="wpguard_cve_stats",
            description="Get Wordfence vulnerability database statistics",
            inputSchema={
                "type": "object",
                "properties": {},
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
    # Coerce string values to int for integer-typed params (MCP clients may send strings)
    _tool_schemas = {t.name: t.inputSchema for t in (await list_tools())}
    schema = _tool_schemas.get(name, {})
    for param, prop in schema.get("properties", {}).items():
        if prop.get("type") == "integer" and param in arguments:
            try:
                arguments[param] = int(arguments[param])
            except (ValueError, TypeError):
                pass

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

    elif name == "wpguard_watch_global":
        return await _watch_global(
            arguments.get("min_installs", 1000),
            arguments.get("max_pages", 2),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_watch_new":
        return await _watch_new(
            arguments.get("min_installs", 0),
            arguments.get("max_pages", 2),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    # Theme tools
    elif name == "wpguard_theme_info":
        return await _theme_info(arguments["slug"])

    elif name == "wpguard_theme_search":
        return await _theme_search(
            arguments.get("query"),
            arguments.get("page", 1),
            arguments.get("browse"),
        )

    elif name == "wpguard_theme_download":
        return await _theme_download(
            arguments["slug"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
            arguments.get("extract", True),
        )

    elif name == "wpguard_theme_svn_log":
        return await _theme_svn_log(
            arguments["slug"],
            arguments.get("limit", 10),
        )

    elif name == "wpguard_theme_svn_diff":
        return await _theme_svn_diff(
            arguments["slug"],
            arguments["old_rev"],
            arguments.get("new_rev", "HEAD"),
            arguments.get("show_diff", False),
        )

    elif name == "wpguard_watch_global_themes":
        return await _watch_global_themes(
            arguments.get("min_installs", 1000),
            arguments.get("max_pages", 2),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_watch_new_themes":
        return await _watch_new_themes(
            arguments.get("min_installs", 0),
            arguments.get("max_pages", 2),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    # Plugin SVN tools
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

    # Core tools
    elif name == "wpguard_core_versions":
        return await _core_versions(arguments.get("limit", 25))

    elif name == "wpguard_core_download":
        return await _core_download(
            arguments["version"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_core_svn_diff":
        return await _core_svn_diff(
            arguments["from_version"],
            arguments["to_version"],
            arguments.get("show_diff", False),
        )

    elif name == "wpguard_state_info":
        return await _state_info(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    # WordPress Sandbox Tools
    elif name == "wpguard_sandbox_status":
        return await _sandbox_status()

    elif name == "wpguard_sandbox_install_plugin":
        return await _sandbox_install_plugin(
            arguments["slug"],
            arguments.get("version"),
            arguments.get("activate", True),
            arguments.get("from_zip"),
        )

    elif name == "wpguard_sandbox_uninstall_plugin":
        return await _sandbox_uninstall_plugin(arguments["slug"])

    elif name == "wpguard_sandbox_request":
        return await _sandbox_request(
            arguments["method"],
            arguments["path"],
            arguments.get("data"),
            arguments.get("auth"),
            arguments.get("headers"),
        )

    elif name == "wpguard_sandbox_wp_cli":
        return await _sandbox_wp_cli(
            arguments["command"],
            arguments.get("timeout", 60),
        )

    elif name == "wpguard_sandbox_get_nonce":
        return await _sandbox_get_nonce(
            arguments["action"],
            arguments.get("auth"),
        )

    elif name == "wpguard_sandbox_get_emails":
        return await _sandbox_get_emails(arguments.get("search"), arguments.get("limit", 50))

    elif name == "wpguard_sandbox_get_email_body":
        return await _sandbox_get_email_body(arguments["message_id"])

    elif name == "wpguard_sandbox_delete_emails":
        return await _sandbox_delete_emails()

    elif name == "wpguard_sandbox_list_endpoints":
        return await _sandbox_list_endpoints(arguments.get("namespace"))

    elif name == "wpguard_sandbox_map_nonces":
        return await _sandbox_map_nonces(arguments.get("extra_pages"))

    elif name == "wpguard_regression_check":
        return await _regression_check(
            arguments["slug"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_target_score":
        return await _target_score(
            arguments.get("slug"),
            arguments.get("slugs"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_semgrep_scan":
        return await _semgrep_scan(
            arguments["target_dir"],
            arguments.get("category"),
            arguments.get("severity", "WARNING"),
            arguments.get("output_dir"),
        )

    elif name == "wpguard_progpilot_scan":
        return await _progpilot_scan(
            arguments["target_dir"],
            arguments.get("timeout", 600),
            arguments.get("output_dir"),
        )

    elif name == "wpguard_agent_checkpoint":
        return await _agent_checkpoint(
            arguments["action"],
            arguments["agent_name"],
            arguments["plugin_slug"],
            arguments.get("files_analyzed"),
            arguments.get("files_partial"),
            arguments.get("files_remaining"),
            arguments.get("findings_created"),
            arguments.get("notes"),
            arguments.get("priority_targets"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_bounty_estimate":
        return await _bounty_estimate(
            arguments["vuln_type"],
            arguments["install_count"],
            arguments.get("auth_level", "none"),
            arguments.get("researcher_tier", 0),
        )

    elif name == "wpguard_finding_check_duplicate":
        return await _finding_check_duplicate(
            arguments["plugin_slug"],
            arguments["affected_file"],
            arguments.get("affected_function", ""),
            arguments.get("vuln_type", ""),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    # Sandbox Management Tools
    elif name == "wpguard_sandbox_start":
        return await _sandbox_start(
            arguments.get("wait_ready", True),
            arguments.get("timeout", 120),
        )

    elif name == "wpguard_sandbox_stop":
        return await _sandbox_stop()

    elif name == "wpguard_sandbox_restart":
        return await _sandbox_restart(arguments.get("wait_ready", True))

    elif name == "wpguard_sandbox_destroy":
        return await _sandbox_destroy()

    elif name == "wpguard_sandbox_set_core_version":
        return await _sandbox_set_core_version(
            arguments["version"],
            arguments.get("disable_auto_update", True),
        )

    # Wordfence Scope Validation Tools
    elif name == "wpguard_scope_check_plugin":
        return await _scope_check_plugin(
            arguments["plugin_slug"],
            arguments["active_installs"],
            arguments.get("author"),
            arguments.get("is_available", True),
        )

    elif name == "wpguard_scope_check_finding":
        return await _scope_check_finding(
            arguments["plugin_slug"],
            arguments["active_installs"],
            arguments["vuln_type"],
            arguments["auth_level"],
            arguments["cvss_score"],
            arguments.get("author"),
        )

    elif name == "wpguard_scope_get_vulns":
        return await _scope_get_vulns(arguments["active_installs"])

    # Finding Persistence Tools
    elif name == "wpguard_finding_create":
        return await _finding_create(
            arguments["plugin_slug"],
            arguments["plugin_version"],
            arguments["active_installs"],
            arguments["vuln_type"],
            arguments["title"],
            arguments["description"],
            arguments["auth_level"],
            arguments["cvss_score"],
            arguments["cvss_vector"],
            arguments["affected_file"],
            arguments.get("affected_function", ""),
            arguments.get("affected_line", 0),
            arguments.get("poc_path", ""),
            arguments.get("tier", ""),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_finding_update":
        return await _finding_update(
            arguments["finding_id"],
            arguments.get("status"),
            arguments.get("validation_notes"),
            arguments.get("submission_id"),
            arguments.get("poc_path"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
            auth_level=arguments.get("auth_level"),
        )

    elif name == "wpguard_finding_get":
        return await _finding_get(
            arguments["finding_id"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_finding_list":
        return await _finding_list(
            arguments.get("plugin_slug"),
            arguments.get("status"),
            arguments.get("vuln_type"),
            arguments.get("min_cvss"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_finding_delete":
        return await _finding_delete(
            arguments["finding_id"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_finding_stats":
        return await _finding_stats(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    # Audit History Tools
    elif name == "wpguard_audit_record":
        return await _audit_record(
            arguments["slug"],
            arguments["version"],
            arguments.get("asset_type", "plugin"),
            arguments.get("active_installs", 0),
            arguments.get("findings_count", 0),
            arguments.get("validated_count", 0),
            arguments.get("status", "completed"),
            arguments.get("notes", ""),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_audit_check":
        return await _audit_check(
            arguments["slug"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_audit_list":
        return await _audit_list(
            arguments.get("asset_type"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    # Discord Notification Tools
    elif name == "wpguard_discord_notify_finding":
        return await _discord_notify_finding(
            arguments["finding_id"],
            arguments.get("title_prefix", ""),
            arguments.get("mention"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_discord_notify_summary":
        return await _discord_notify_summary(
            arguments.get("title", "Security Research Summary"),
            arguments.get("status_filter"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_discord_send_message":
        return await _discord_send_message(arguments["message"])

    # Project Initialization
    elif name == "wpguard_init_research":
        return await _init_research(arguments.get("output_dir", "./wpguard-research"))

    # Wordfence CVE Database Tools
    elif name == "wpguard_cve_download":
        return await _cve_download(arguments.get("force", False))

    elif name == "wpguard_cve_search":
        return await _cve_search(
            arguments.get("slug"),
            arguments.get("query"),
            arguments.get("vuln_type"),
            arguments.get("limit", 50),
        )

    elif name == "wpguard_cve_get":
        return await _cve_get(arguments["vuln_id"])

    elif name == "wpguard_cve_stats":
        return await _cve_stats()

    else:
        raise ValueError(f"Unknown tool: {name}")


# Tool implementations


def _plugin_info_sync(slug: str) -> dict[str, Any]:
    """Get detailed plugin information (sync version)."""
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


async def _plugin_info(slug: str) -> dict[str, Any]:
    """Get detailed plugin information."""
    return await run_in_executor(_plugin_info_sync, slug)


def _search_sync(query: str, page: int, per_page: int) -> dict[str, Any]:
    """Search for plugins (sync version)."""
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


async def _search(query: str, page: int, per_page: int) -> dict[str, Any]:
    """Search for plugins."""
    return await run_in_executor(_search_sync, query, page, per_page)


def _download_sync(
    slug: str, output_dir: str, extract: bool, svn: bool
) -> dict[str, Any]:
    """Download a single plugin (sync version)."""
    api = WordPressPluginAPI()
    plugin = api.get_plugin_info(slug)

    if not plugin:
        return {"error": f"Plugin '{slug}' not found"}

    # Check SVN availability if requested
    if svn and not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion"}

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


async def _download(
    slug: str, output_dir: str, extract: bool, svn: bool
) -> dict[str, Any]:
    """Download a single plugin."""
    return await run_in_executor(_download_sync, slug, output_dir, extract, svn)


def _bulk_download_sync(
    search: str | None,
    min_installs: int,
    max_installs: int | None,
    count: int,
    browse: str | None,
    output_dir: str,
    extract: bool,
) -> dict[str, Any]:
    """Bulk download plugins (sync version)."""
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
    return await run_in_executor(
        _bulk_download_sync, search, min_installs, max_installs, count, browse, output_dir, extract
    )


def _watch_add_sync(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Add plugins to watchlist (sync version)."""
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


async def _watch_add(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Add plugins to watchlist."""
    return await run_in_executor(_watch_add_sync, slugs, output_dir)


def _watch_remove_sync(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Remove plugins from watchlist (sync version)."""
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


async def _watch_remove(slugs: list[str], output_dir: str) -> dict[str, Any]:
    """Remove plugins from watchlist."""
    return await run_in_executor(_watch_remove_sync, slugs, output_dir)


def _watch_list_sync(output_dir: str) -> dict[str, Any]:
    """List watched plugins (sync version)."""
    watcher = PluginWatcher(output_dir=output_dir)
    plugins = watcher.list_watched()

    return {
        "count": len(plugins),
        "last_check": watcher.state.get("last_check"),
        "plugins": plugins,
    }


async def _watch_list(output_dir: str) -> dict[str, Any]:
    """List watched plugins."""
    return await run_in_executor(_watch_list_sync, output_dir)


def _watch_check_sync(output_dir: str) -> dict[str, Any]:
    """Check for plugin updates (sync version)."""
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


async def _watch_check(output_dir: str) -> dict[str, Any]:
    """Check for plugin updates."""
    return await run_in_executor(_watch_check_sync, output_dir)


def _watch_global_sync(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check global WordPress plugin updates (sync version)."""
    watcher = PluginWatcher(output_dir=output_dir)
    return watcher.check_global_updates(min_installs=min_installs, max_pages=max_pages)


async def _watch_global(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check global WordPress plugin updates."""
    return await run_in_executor(_watch_global_sync, min_installs, max_pages, output_dir)


def _watch_new_sync(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check for newly added WordPress plugins (sync version)."""
    watcher = PluginWatcher(output_dir=output_dir)
    return watcher.check_new_plugins(min_installs=min_installs, max_pages=max_pages)


async def _watch_new(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check for newly added WordPress plugins."""
    return await run_in_executor(_watch_new_sync, min_installs, max_pages, output_dir)


# ── Theme handler functions ──────────────────────────────

def _theme_info_sync(slug: str) -> dict[str, Any]:
    """Get theme info (sync version)."""
    api = WordPressThemeAPI()
    theme = api.get_theme_info(slug)
    if not theme:
        return {"error": f"Theme '{slug}' not found"}
    return theme.to_dict()


async def _theme_info(slug: str) -> dict[str, Any]:
    """Get theme info."""
    return await run_in_executor(_theme_info_sync, slug)


def _theme_search_sync(query: str | None, page: int, browse: str | None) -> dict[str, Any]:
    """Search themes (sync version)."""
    api = WordPressThemeAPI()
    themes, total_pages = api.query_themes(search=query, browse=browse, page=page)
    return {
        "themes": [t.to_dict() for t in themes],
        "total_pages": total_pages,
        "page": page,
        "count": len(themes),
    }


async def _theme_search(query: str | None, page: int, browse: str | None) -> dict[str, Any]:
    """Search themes."""
    return await run_in_executor(_theme_search_sync, query, page, browse)


def _theme_download_sync(slug: str, output_dir: str, extract: bool) -> dict[str, Any]:
    """Download a theme (sync version)."""
    from wpguard.config import WP_THEMES_SVN, THEMES_SUBDIR

    api = WordPressThemeAPI()
    theme = api.get_theme_info(slug)
    if not theme:
        return {"error": f"Theme '{slug}' not found"}

    if not theme.download_link:
        return {"error": f"No download link for theme '{slug}'"}

    themes_dir = Path(output_dir) / "targets"
    themes_dir.mkdir(parents=True, exist_ok=True)

    theme_dir = themes_dir / slug
    theme_dir.mkdir(parents=True, exist_ok=True)

    # Download ZIP
    import requests as req
    zip_path = theme_dir / f"{slug}.{theme.version}.zip"
    try:
        r = req.get(theme.download_link, stream=True, timeout=60)
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    except req.RequestException as e:
        return {"error": f"Download failed: {e}"}

    result = {
        "slug": slug,
        "version": theme.version,
        "zip_path": str(zip_path),
        "active_installs": theme.active_installs,
    }

    # Extract if requested
    if extract:
        import zipfile
        extracted_dir = theme_dir / "extracted"
        extracted_dir.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extracted_dir)
            result["extracted_path"] = str(extracted_dir)
        except zipfile.BadZipFile as e:
            result["extract_error"] = str(e)

    return result


async def _theme_download(slug: str, output_dir: str, extract: bool) -> dict[str, Any]:
    """Download a theme."""
    return await run_in_executor(_theme_download_sync, slug, output_dir, extract)


def _theme_svn_log_sync(slug: str, limit: int) -> dict[str, Any]:
    """Get SVN log for a theme (sync version)."""
    from wpguard.config import WP_THEMES_SVN

    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion", "entries": []}

    svn = SVNClient(svn_base=WP_THEMES_SVN)
    entries = svn.get_log(slug, limit=limit)

    if not entries:
        return {"error": f"No SVN log entries found for theme '{slug}'", "entries": []}

    return {
        "slug": slug,
        "type": "theme",
        "entries_count": len(entries),
        "entries": entries,
    }


async def _theme_svn_log(slug: str, limit: int) -> dict[str, Any]:
    """Get SVN log for a theme."""
    return await run_in_executor(_theme_svn_log_sync, slug, limit)


def _theme_svn_diff_sync(slug: str, old_rev: str, new_rev: str, show_diff: bool) -> dict[str, Any]:
    """Get SVN diff between revisions for a theme (sync version)."""
    from wpguard.config import WP_THEMES_SVN

    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion"}

    svn = SVNClient(svn_base=WP_THEMES_SVN)
    change_info = svn.compare_revisions(slug, old_rev, new_rev)

    result = {
        "slug": slug,
        "type": "theme",
        "old_revision": change_info.old_revision,
        "new_revision": change_info.new_revision,
        "changed_files": change_info.changed_files,
        "added_files": change_info.added_files,
        "removed_files": change_info.removed_files,
        "total_changes": change_info.total_changes,
        "log_entries": change_info.log_entries[:10],
    }

    if show_diff:
        result["diff"] = change_info.diff_output

    return result


async def _theme_svn_diff(slug: str, old_rev: str, new_rev: str, show_diff: bool) -> dict[str, Any]:
    """Get SVN diff between revisions for a theme."""
    return await run_in_executor(_theme_svn_diff_sync, slug, old_rev, new_rev, show_diff)


def _watch_global_themes_sync(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check global WordPress theme updates (sync version)."""
    from wpguard.config import WP_THEMES_SVN

    api = WordPressThemeAPI()
    limit = max_pages * 250
    themes = api.fetch_all_themes(browse="updated", min_installs=min_installs, limit=limit)

    # Load/init state
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    state_file = output_path / "state.json"
    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    if "global_theme_monitor" not in state:
        state["global_theme_monitor"] = {"last_checked": None, "seen_versions": {}}

    seen = state["global_theme_monitor"]["seen_versions"]
    new_updates = []

    for theme in themes:
        if seen.get(theme.slug) != theme.version:
            update = {
                "slug": theme.slug,
                "name": theme.name,
                "version": theme.version,
                "active_installs": theme.active_installs,
                "last_updated": theme.last_updated,
                "download_link": theme.download_link,
                "short_description": theme.short_description,
                "changelog": "",
                "svn_log": [],
            }
            # Enrich themes with >= 10k installs
            if theme.active_installs >= 10000:
                changelog_html = api.get_theme_changelog(theme.slug)
                if changelog_html:
                    from wpguard.core.watcher import PluginWatcher
                    update["changelog"] = PluginWatcher._extract_latest_changelog(changelog_html)
                try:
                    svn = SVNClient(svn_base=WP_THEMES_SVN)
                    update["svn_log"] = svn.get_log(theme.slug, limit=5)
                except Exception:
                    pass

            new_updates.append(update)
            seen[theme.slug] = theme.version

    now = datetime.now(timezone.utc).isoformat()
    state["global_theme_monitor"]["last_checked"] = now
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    result = {
        "last_checked": now,
        "new_updates": new_updates,
        "total_new": len(new_updates),
        "type": "themes",
    }

    # Write recently_updated_themes.json
    with open(output_path / "recently_updated_themes.json", "w") as f:
        json.dump(result, f, indent=2)

    return result


async def _watch_global_themes(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check global WordPress theme updates."""
    return await run_in_executor(_watch_global_themes_sync, min_installs, max_pages, output_dir)


def _watch_new_themes_sync(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check for newly added WordPress themes (sync version)."""
    api = WordPressThemeAPI()
    limit = max_pages * 250
    themes = api.fetch_all_themes(browse="new", min_installs=min_installs, limit=limit)

    # Load/init state
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    state_file = output_path / "state.json"
    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    if "new_themes_monitor" not in state:
        state["new_themes_monitor"] = {"last_checked": None, "seen_slugs": []}

    seen = set(state["new_themes_monitor"]["seen_slugs"])
    new_themes = []

    for theme in themes:
        if theme.slug not in seen:
            new_themes.append({
                "slug": theme.slug,
                "name": theme.name,
                "version": theme.version,
                "active_installs": theme.active_installs,
                "last_updated": theme.last_updated,
                "download_link": theme.download_link,
                "short_description": theme.short_description,
            })
            seen.add(theme.slug)

    now = datetime.now(timezone.utc).isoformat()
    state["new_themes_monitor"]["last_checked"] = now
    state["new_themes_monitor"]["seen_slugs"] = sorted(seen)
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    result = {
        "last_checked": now,
        "new_themes": new_themes,
        "total_new": len(new_themes),
        "type": "themes",
    }

    with open(output_path / "new_themes.json", "w") as f:
        json.dump(result, f, indent=2)

    return result


async def _watch_new_themes(min_installs: int, max_pages: int, output_dir: str) -> dict[str, Any]:
    """Check for newly added WordPress themes."""
    return await run_in_executor(_watch_new_themes_sync, min_installs, max_pages, output_dir)


# ── Plugin SVN handler functions ─────────────────────────

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


def _plugin_versions_sync(slug: str) -> dict[str, Any]:
    """Get all available versions for a plugin (sync version)."""
    api = WordPressPluginAPI()
    versions = api.get_plugin_versions(slug)

    if not versions:
        return {"error": f"Could not get versions for '{slug}'", "versions": []}

    return {
        "slug": slug,
        "versions_count": len(versions),
        "versions": versions,
    }


async def _plugin_versions(slug: str) -> dict[str, Any]:
    """Get all available versions for a plugin."""
    return await run_in_executor(_plugin_versions_sync, slug)


# ── Core handler functions ───────────────────────────────

def _core_versions_sync(limit: int) -> dict[str, Any]:
    """List WordPress core versions (sync version)."""
    api = WordPressCoreAPI()
    versions = api.list_versions()

    if not versions:
        return {"error": "Could not list core versions", "versions": []}

    latest = api.get_latest()

    return {
        "type": "core",
        "latest": latest.version if latest else "",
        "versions_count": len(versions),
        "security_releases": [v.version for v in versions if v.is_security_release],
        "versions": [v.to_dict() for v in versions[:limit]],
    }


async def _core_versions(limit: int) -> dict[str, Any]:
    """List WordPress core versions."""
    return await run_in_executor(_core_versions_sync, limit)


def _core_download_sync(version: str, output_dir: str) -> dict[str, Any]:
    """Download a WordPress core version (sync version)."""
    if not _check_svn_available():
        # SVN unavailable — CoreDownloader falls back to the release ZIP
        print("[*] SVN unavailable, core download will use ZIP fallback", file=sys.stderr)

    targets_dir = Path(output_dir) / "targets"
    downloader = CoreDownloader(targets_dir)

    result = downloader.download(version)

    if not result.extracted_path:
        return {"error": f"Failed to download core '{version}'"}

    return {
        "type": "core",
        "version": result.version,
        "source": result.source,
        "extracted_path": str(result.extracted_path),
        "zip_path": str(result.zip_path) if result.zip_path else None,
        "success": result.extracted_path is not None,
    }


async def _core_download(version: str, output_dir: str) -> dict[str, Any]:
    """Download a WordPress core version."""
    return await run_in_executor(_core_download_sync, version, output_dir)


def _core_svn_diff_sync(
    from_version: str, to_version: str, show_diff: bool
) -> dict[str, Any]:
    """Diff two core version tags (sync version)."""
    if not _check_svn_available():
        return {"error": "SVN is not installed. Install with: apt install subversion"}

    downloader = CoreDownloader()
    change_info = downloader.svn_diff(from_version, to_version)

    result = {
        "type": "core",
        "from_version": from_version,
        "to_version": to_version,
        "changed_files": change_info.changed_files,
        "added_files": change_info.added_files,
        "removed_files": change_info.removed_files,
        "total_changes": change_info.total_changes,
    }

    if show_diff:
        diff = change_info.diff_output
        if len(diff) > 50000:
            diff = diff[:50000] + "\n... [truncated]"
        result["diff_output"] = diff

    return result


async def _core_svn_diff(
    from_version: str, to_version: str, show_diff: bool
) -> dict[str, Any]:
    """Diff two core version tags."""
    return await run_in_executor(
        _core_svn_diff_sync, from_version, to_version, show_diff
    )


def _state_info_sync(output_dir: str) -> dict[str, Any]:
    """Get current state information (sync version)."""
    watcher = PluginWatcher(output_dir=output_dir)
    return watcher.get_state_info()


async def _state_info(output_dir: str) -> dict[str, Any]:
    """Get current state information."""
    return await run_in_executor(_state_info_sync, output_dir)


# WordPress Sandbox Tool Implementations

# Singleton sandbox instance for session management
_sandbox_instance: WordPressSandbox | None = None


def _get_sandbox() -> WordPressSandbox:
    """Get or create the sandbox instance."""
    global _sandbox_instance
    if _sandbox_instance is None:
        _sandbox_instance = WordPressSandbox()
    return _sandbox_instance


def _sandbox_status_sync() -> dict[str, Any]:
    """Check sandbox status (sync version)."""
    sandbox = _get_sandbox()
    status = sandbox.check_connection()

    # Add WordPress info if accessible
    if status["all_ok"]:
        wp_info = sandbox.get_wordpress_info()
        status["wordpress_version"] = wp_info.get("version")
        status["site_url"] = wp_info.get("site_url")

        # Get installed plugins
        plugins = sandbox.get_plugin_list()
        status["installed_plugins"] = len(plugins)
        status["active_plugins"] = len([p for p in plugins if p.get("status") == "active"])

    return status


async def _sandbox_status() -> dict[str, Any]:
    """Check sandbox status."""
    return await run_in_executor(_sandbox_status_sync)


def _sandbox_install_plugin_sync(
    slug: str,
    version: str | None,
    activate: bool,
    from_zip: str | None,
) -> dict[str, Any]:
    """Install plugin in sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.install_plugin(
        slug=slug,
        version=version,
        activate=activate,
        from_zip=from_zip,
    )


async def _sandbox_install_plugin(
    slug: str,
    version: str | None,
    activate: bool,
    from_zip: str | None,
) -> dict[str, Any]:
    """Install plugin in sandbox."""
    return await run_in_executor(
        _sandbox_install_plugin_sync, slug, version, activate, from_zip
    )


def _sandbox_uninstall_plugin_sync(slug: str) -> dict[str, Any]:
    """Uninstall plugin from sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.uninstall_plugin(slug)


async def _sandbox_uninstall_plugin(slug: str) -> dict[str, Any]:
    """Uninstall plugin from sandbox."""
    return await run_in_executor(_sandbox_uninstall_plugin_sync, slug)


def _sandbox_request_sync(
    method: str,
    path: str,
    data: dict[str, Any] | None,
    auth: str | None,
    headers: dict[str, str] | None,
) -> dict[str, Any]:
    """Execute HTTP request against sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.request(
        method=method,
        path=path,
        data=data,
        auth=auth,
        headers=headers,
    )


async def _sandbox_request(
    method: str,
    path: str,
    data: dict[str, Any] | None,
    auth: str | None,
    headers: dict[str, str] | None,
) -> dict[str, Any]:
    """Execute HTTP request against sandbox."""
    return await run_in_executor(
        _sandbox_request_sync, method, path, data, auth, headers
    )


def _sandbox_wp_cli_sync(command: str, timeout: int) -> dict[str, Any]:
    """Execute WP-CLI command in sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.wp_cli(command, timeout=timeout)


async def _sandbox_wp_cli(command: str, timeout: int) -> dict[str, Any]:
    """Execute WP-CLI command in sandbox."""
    return await run_in_executor(_sandbox_wp_cli_sync, command, timeout)


def _sandbox_get_nonce_sync(action: str, auth: str | None) -> dict[str, Any]:
    """Get WordPress nonce (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.get_nonce(action=action, auth=auth)


async def _sandbox_get_nonce(action: str, auth: str | None) -> dict[str, Any]:
    """Get WordPress nonce."""
    return await run_in_executor(_sandbox_get_nonce_sync, action, auth)


# Sandbox Management Tool Implementations

def _sandbox_start_sync(wait_ready: bool, timeout: int) -> dict[str, Any]:
    """Start sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.sandbox_start(wait_ready=wait_ready, timeout=timeout)


async def _sandbox_start(wait_ready: bool, timeout: int) -> dict[str, Any]:
    """Start the WordPress sandbox."""
    return await run_in_executor(_sandbox_start_sync, wait_ready, timeout)


def _sandbox_stop_sync() -> dict[str, Any]:
    """Stop sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.sandbox_stop()


async def _sandbox_stop() -> dict[str, Any]:
    """Stop the WordPress sandbox."""
    return await run_in_executor(_sandbox_stop_sync)


def _sandbox_restart_sync(wait_ready: bool) -> dict[str, Any]:
    """Restart sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.sandbox_restart(wait_ready=wait_ready)


async def _sandbox_restart(wait_ready: bool) -> dict[str, Any]:
    """Restart the WordPress sandbox."""
    return await run_in_executor(_sandbox_restart_sync, wait_ready)


def _sandbox_destroy_sync() -> dict[str, Any]:
    """Destroy sandbox (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.sandbox_destroy()


async def _sandbox_destroy() -> dict[str, Any]:
    """Destroy the WordPress sandbox."""
    return await run_in_executor(_sandbox_destroy_sync)


def _sandbox_set_core_version_sync(version: str, disable_auto_update: bool) -> dict[str, Any]:
    """Pin sandbox core version (sync version)."""
    sandbox = _get_sandbox()
    return sandbox.set_core_version(version, disable_auto_update=disable_auto_update)


async def _sandbox_set_core_version(version: str, disable_auto_update: bool) -> dict[str, Any]:
    """Pin the sandbox WordPress core to a specific version and disable auto-update."""
    return await run_in_executor(_sandbox_set_core_version_sync, version, disable_auto_update)


# Wordfence Scope Validation Tool Implementations

# Singleton validator instance
_scope_validator: WorkfenceScopeValidator | None = None


def _get_scope_validator() -> WorkfenceScopeValidator:
    """Get or create the scope validator instance."""
    global _scope_validator
    if _scope_validator is None:
        _scope_validator = WorkfenceScopeValidator()
    return _scope_validator


def _scope_check_plugin_sync(
    plugin_slug: str,
    active_installs: int,
    author: str | None,
    is_available: bool,
) -> dict[str, Any]:
    """Check plugin eligibility (sync version)."""
    validator = _get_scope_validator()
    result = validator.validate_plugin_eligibility(
        plugin_slug=plugin_slug,
        active_installs=active_installs,
        author=author,
        is_available=is_available,
    )
    return result.to_dict()


async def _scope_check_plugin(
    plugin_slug: str,
    active_installs: int,
    author: str | None,
    is_available: bool,
) -> dict[str, Any]:
    """Check plugin eligibility."""
    return await run_in_executor(
        _scope_check_plugin_sync, plugin_slug, active_installs, author, is_available
    )


def _scope_check_finding_sync(
    plugin_slug: str,
    active_installs: int,
    vuln_type: str,
    auth_level: str,
    cvss_score: float,
    author: str | None,
) -> dict[str, Any]:
    """Check finding eligibility (sync version)."""
    validator = _get_scope_validator()
    result = validator.validate_finding_eligibility(
        plugin_slug=plugin_slug,
        active_installs=active_installs,
        vuln_type=vuln_type,
        auth_level=auth_level,
        cvss_score=cvss_score,
        author=author,
    )
    return result.to_dict()


async def _scope_check_finding(
    plugin_slug: str,
    active_installs: int,
    vuln_type: str,
    auth_level: str,
    cvss_score: float,
    author: str | None,
) -> dict[str, Any]:
    """Check finding eligibility."""
    return await run_in_executor(
        _scope_check_finding_sync,
        plugin_slug,
        active_installs,
        vuln_type,
        auth_level,
        cvss_score,
        author,
    )


def _scope_get_vulns_sync(active_installs: int) -> dict[str, Any]:
    """Get in-scope vulnerabilities (sync version)."""
    validator = _get_scope_validator()
    vulns = validator.get_in_scope_vulns_for_installs(active_installs)
    return {
        "active_installs": active_installs,
        "in_scope_vulnerabilities": vulns,
        "total_vuln_types": sum(len(v) for v in vulns.values()),
    }


async def _scope_get_vulns(active_installs: int) -> dict[str, Any]:
    """Get in-scope vulnerabilities."""
    return await run_in_executor(_scope_get_vulns_sync, active_installs)


# Finding Persistence Tool Implementations

def _finding_create_sync(
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
    affected_function: str,
    affected_line: int,
    poc_path: str,
    tier: str,
    output_dir: str,
) -> dict[str, Any]:
    """Create a new finding (sync version)."""
    manager = FindingsManager(output_dir)
    finding = manager.create_finding(
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
        tier=tier,
    )
    return {
        "success": True,
        "finding_id": finding.id,
        "finding": finding.to_dict(),
    }


async def _finding_create(
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
    affected_function: str,
    affected_line: int,
    poc_path: str,
    tier: str,
    output_dir: str,
) -> dict[str, Any]:
    """Create a new finding."""
    return await run_in_executor(
        _finding_create_sync,
        plugin_slug, plugin_version, active_installs, vuln_type, title,
        description, auth_level, cvss_score, cvss_vector, affected_file,
        affected_function, affected_line, poc_path, tier, output_dir,
    )


def _finding_update_sync(
    finding_id: str,
    status: str | None,
    validation_notes: str | None,
    submission_id: str | None,
    poc_path: str | None,
    output_dir: str,
    auth_level: str | None = None,
) -> dict[str, Any]:
    """Update a finding (sync version)."""
    manager = FindingsManager(output_dir)
    kwargs = {}
    if auth_level is not None:
        kwargs["auth_level"] = auth_level
    finding = manager.update_finding(
        finding_id=finding_id,
        status=status,
        validation_notes=validation_notes,
        submission_id=submission_id,
        poc_path=poc_path,
        **kwargs,
    )
    if finding:
        return {"success": True, "finding": finding.to_dict()}
    return {"success": False, "error": f"Finding {finding_id} not found"}


async def _finding_update(
    finding_id: str,
    status: str | None,
    validation_notes: str | None,
    submission_id: str | None,
    poc_path: str | None,
    output_dir: str,
    auth_level: str | None = None,
) -> dict[str, Any]:
    """Update a finding."""
    return await run_in_executor(
        _finding_update_sync, finding_id, status, validation_notes,
        submission_id, poc_path, output_dir, auth_level,
    )


def _finding_get_sync(finding_id: str, output_dir: str) -> dict[str, Any]:
    """Get a finding (sync version)."""
    manager = FindingsManager(output_dir)
    finding = manager.get_finding(finding_id)
    if finding:
        return {"success": True, "finding": finding.to_dict()}
    return {"success": False, "error": f"Finding {finding_id} not found"}


async def _finding_get(finding_id: str, output_dir: str) -> dict[str, Any]:
    """Get a finding."""
    return await run_in_executor(_finding_get_sync, finding_id, output_dir)


def _finding_list_sync(
    plugin_slug: str | None,
    status: str | None,
    vuln_type: str | None,
    min_cvss: float | None,
    output_dir: str,
) -> dict[str, Any]:
    """List findings (sync version)."""
    manager = FindingsManager(output_dir)
    findings = manager.list_findings(
        plugin_slug=plugin_slug,
        status=status,
        vuln_type=vuln_type,
        min_cvss=min_cvss,
    )
    return {
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


async def _finding_list(
    plugin_slug: str | None,
    status: str | None,
    vuln_type: str | None,
    min_cvss: float | None,
    output_dir: str,
) -> dict[str, Any]:
    """List findings."""
    return await run_in_executor(
        _finding_list_sync, plugin_slug, status, vuln_type, min_cvss, output_dir,
    )


def _finding_delete_sync(finding_id: str, output_dir: str) -> dict[str, Any]:
    """Delete a finding (sync version)."""
    manager = FindingsManager(output_dir)
    deleted = manager.delete_finding(finding_id)
    if deleted:
        return {"success": True, "message": f"Finding {finding_id} deleted"}
    return {"success": False, "error": f"Finding {finding_id} not found"}


async def _finding_delete(finding_id: str, output_dir: str) -> dict[str, Any]:
    """Delete a finding."""
    return await run_in_executor(_finding_delete_sync, finding_id, output_dir)


def _finding_stats_sync(output_dir: str) -> dict[str, Any]:
    """Get finding statistics (sync version)."""
    manager = FindingsManager(output_dir)
    return manager.get_stats()


async def _finding_stats(output_dir: str) -> dict[str, Any]:
    """Get finding statistics."""
    return await run_in_executor(_finding_stats_sync, output_dir)



# ── Audit History Implementations ─────────────────────

def _audit_record_sync(
    slug: str, version: str, asset_type: str, active_installs: int,
    findings_count: int, validated_count: int, status: str, notes: str,
    output_dir: str,
) -> dict[str, Any]:
    """Record an audit (sync version)."""
    from wpguard.core.audit_history import AuditHistoryManager
    manager = AuditHistoryManager(output_dir)
    record = manager.record_audit(
        slug=slug, version=version, asset_type=asset_type,
        active_installs=active_installs, findings_count=findings_count,
        validated_count=validated_count, status=status, notes=notes,
    )
    return {"success": True, "slug": slug, "iterations": record["iterations"]}


async def _audit_record(*args: Any) -> dict[str, Any]:
    """Record an audit."""
    return await run_in_executor(_audit_record_sync, *args)


def _audit_check_sync(slug: str, output_dir: str) -> dict[str, Any]:
    """Check audit history for a slug (sync version)."""
    from wpguard.core.audit_history import AuditHistoryManager
    manager = AuditHistoryManager(output_dir)
    return manager.check_audit(slug)


async def _audit_check(slug: str, output_dir: str) -> dict[str, Any]:
    """Check audit history for a slug."""
    return await run_in_executor(_audit_check_sync, slug, output_dir)


def _audit_list_sync(asset_type: str | None, output_dir: str) -> dict[str, Any]:
    """List audit history (sync version)."""
    from wpguard.core.audit_history import AuditHistoryManager
    manager = AuditHistoryManager(output_dir)
    audits = manager.list_audits(asset_type=asset_type)
    stats = manager.get_stats()
    return {"audits": audits, "stats": stats}


async def _audit_list(asset_type: str | None, output_dir: str) -> dict[str, Any]:
    """List audit history."""
    return await run_in_executor(_audit_list_sync, asset_type, output_dir)


# ── Sandbox Email (Mailpit) Implementations ───────────

def _sandbox_get_emails_sync(search: str | None, limit: int) -> dict[str, Any]:
    sandbox = _get_sandbox()
    emails = sandbox.get_emails(search=search, limit=limit)
    return {"emails": emails, "count": len(emails)}


async def _sandbox_get_emails(search: str | None, limit: int) -> dict[str, Any]:
    return await run_in_executor(_sandbox_get_emails_sync, search, limit)


def _sandbox_get_email_body_sync(message_id: str) -> dict[str, Any]:
    sandbox = _get_sandbox()
    return sandbox.get_email_body(message_id)


async def _sandbox_get_email_body(message_id: str) -> dict[str, Any]:
    return await run_in_executor(_sandbox_get_email_body_sync, message_id)


def _sandbox_delete_emails_sync() -> dict[str, Any]:
    sandbox = _get_sandbox()
    success = sandbox.delete_emails()
    return {"success": success}


async def _sandbox_delete_emails() -> dict[str, Any]:
    return await run_in_executor(_sandbox_delete_emails_sync)


# ── Sandbox Discovery Implementations ─────────────────

def _sandbox_list_endpoints_sync(namespace: str | None) -> dict[str, Any]:
    """List REST endpoints (sync version)."""
    sandbox = _get_sandbox()
    endpoints = sandbox.list_rest_endpoints(namespace=namespace)
    return {
        "endpoints": endpoints,
        "count": len(endpoints),
        "namespace_filter": namespace,
    }


async def _sandbox_list_endpoints(namespace: str | None) -> dict[str, Any]:
    return await run_in_executor(_sandbox_list_endpoints_sync, namespace)


def _sandbox_map_nonces_sync(extra_pages: list[str] | None) -> dict[str, Any]:
    """Map nonces across auth levels (sync version)."""
    sandbox = _get_sandbox()
    nonces = sandbox.map_nonces(extra_pages=extra_pages)
    return {
        "nonces": nonces,
        "count": len(nonces),
        "auth_levels_scanned": ["unauthenticated", "subscriber", "contributor", "author"],
    }


async def _sandbox_map_nonces(extra_pages: list[str] | None) -> dict[str, Any]:
    return await run_in_executor(_sandbox_map_nonces_sync, extra_pages)


# ── Regression Testing Implementations ────────────────

def _regression_check_sync(slug: str, output_dir: str) -> dict[str, Any]:
    """Run regression check (sync version)."""
    from wpguard.core.regression import RegressionChecker
    sandbox = _get_sandbox()
    checker = RegressionChecker(output_dir)
    return checker.check(slug, sandbox)


async def _regression_check(slug: str, output_dir: str) -> dict[str, Any]:
    return await run_in_executor(_regression_check_sync, slug, output_dir)


# ── Target Scoring Implementations ────────────────────

def _target_score_sync(slug: str | None, slugs: list[str] | None, output_dir: str) -> dict[str, Any]:
    """Score targets (sync version)."""
    from wpguard.core.scoring import TargetScorer
    scorer = TargetScorer(output_dir)
    if slugs:
        return {"rankings": scorer.rank(slugs)}
    elif slug:
        return scorer.score(slug)
    else:
        return {"error": "Provide either 'slug' or 'slugs' parameter"}


async def _target_score(slug: str | None, slugs: list[str] | None, output_dir: str) -> dict[str, Any]:
    return await run_in_executor(_target_score_sync, slug, slugs, output_dir)


# ── Semgrep Scan Implementation ───────────────────────

def _semgrep_scan_sync(target_dir: str, category: str | None, severity: str, output_dir: str | None = None) -> dict[str, Any]:
    """Run semgrep WordPress security scan (sync version)."""
    from wpguard.semgrep_rules import RULES_FILE

    # Check semgrep is installed
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, timeout=10)
    except (subprocess.SubprocessError, FileNotFoundError):
        return {"error": "semgrep not installed. Install with: pip install semgrep"}

    if not Path(target_dir).exists():
        return {"error": f"Target directory not found: {target_dir}"}

    if not RULES_FILE.exists():
        return {"error": f"Rules file not found: {RULES_FILE}"}

    cmd = [
        "semgrep", "--config", str(RULES_FILE), "--json", "--no-git-ignore", "--quiet",
        "--include=*.php", "--exclude=vendor", "--exclude=node_modules", "--exclude=lib",
        str(target_dir),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        data = json.loads(result.stdout) if result.stdout else {"results": [], "errors": []}
    except subprocess.TimeoutExpired:
        return {"error": "Semgrep scan timed out after 120s"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse semgrep output", "stderr": result.stderr[:500]}

    results = data.get("results", [])

    # Filter by category
    if category:
        results = [r for r in results if r.get("extra", {}).get("metadata", {}).get("category") == category]

    # Filter by severity
    sev_order = {"INFO": 0, "WARNING": 1, "ERROR": 2}
    min_sev = sev_order.get(severity, 1)
    results = [r for r in results if sev_order.get(r.get("extra", {}).get("severity", "INFO"), 0) >= min_sev]

    # Sort by severity desc, then cvss_estimate desc
    results.sort(key=lambda r: (
        -sev_order.get(r.get("extra", {}).get("severity", "INFO"), 0),
        -float(r.get("extra", {}).get("metadata", {}).get("cvss_estimate", 0)),
    ))

    # Build summary
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in results:
        cat = r.get("extra", {}).get("metadata", {}).get("category", "unknown")
        sev = r.get("extra", {}).get("severity", "INFO")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Simplify results for output
    findings = []
    for r in results[:50]:  # Cap at 50
        # Extract actual matched source code
        snippet = r.get("extra", {}).get("lines", "")
        if not snippet:
            # Fallback: build from matched content
            snippet = r.get("extra", {}).get("metavars", {}).get("$X", {}).get("abstract_content", "")
        findings.append({
            "rule_id": r.get("check_id", "").split(".")[-1],
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
            "severity": r.get("extra", {}).get("severity", ""),
            "message": r.get("extra", {}).get("message", ""),
            "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
            "cvss_estimate": r.get("extra", {}).get("metadata", {}).get("cvss_estimate", "0"),
            "code_snippet": snippet.strip()[:300],
        })

    result_data = {
        "total_findings": len(results),
        "findings": findings,
        "summary": {"by_category": by_category, "by_severity": by_severity},
        "errors": [e.get("message", "") for e in data.get("errors", [])][:5],
    }

    # Save to disk if output_dir provided
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        # JSON
        with open(out / "semgrep_scan.json", "w") as f:
            json.dump(result_data, f, indent=2)
        # Markdown summary for expert consumption
        md = ["# Semgrep Scan Results\n"]
        for sev in ["ERROR", "WARNING", "INFO"]:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if sev_findings:
                md.append(f"\n## {sev} ({len(sev_findings)})\n")
                md.append("| # | File | Line | Category | Rule | Message | Code |")
                md.append("|---|------|------|----------|------|---------|------|")
                for i, f in enumerate(sev_findings, 1):
                    code = f["code_snippet"].replace("\n", " ")[:80]
                    md.append(f"| {i} | {f['file']} | {f['line']} | {f['category']} | {f['rule_id']} | {f['message'][:60]} | `{code}` |")
        md.append(f"\n## Recommended Experts\nBased on categories: {', '.join(f'{k} ({v})' for k,v in by_category.items())}")
        with open(out / "semgrep_scan.md", "w") as f:
            f.write("\n".join(md))
        result_data["saved_to"] = str(out)

    return result_data


async def _semgrep_scan(target_dir: str, category: str | None, severity: str, output_dir: str | None = None) -> dict[str, Any]:
    return await run_in_executor(_semgrep_scan_sync, target_dir, category, severity, output_dir)


# ── Progpilot Scan Implementation ─────────────────────

def _progpilot_scan_sync(target_dir: str, timeout: int, output_dir: str | None = None) -> dict[str, Any]:
    """Run progpilot taint analysis inside the sandbox container (sync version)."""
    from wpguard.config import WP_CONTAINER_NAME

    target = Path(target_dir)
    if not target.exists():
        return {"error": f"Target directory not found: {target_dir}"}

    # Check container is running
    try:
        check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", WP_CONTAINER_NAME],
            capture_output=True, text=True, timeout=10,
        )
        if "true" not in check.stdout.lower():
            return {"error": f"Container {WP_CONTAINER_NAME} is not running. Start sandbox first."}
    except (subprocess.SubprocessError, FileNotFoundError):
        return {"error": "Docker not available"}

    # Copy source into container, excluding vendor/node_modules
    container_scan_dir = "/tmp/progpilot_scan"
    subprocess.run(
        ["docker", "exec", WP_CONTAINER_NAME, "rm", "-rf", container_scan_dir],
        capture_output=True, timeout=10,
    )
    copy_result = subprocess.run(
        ["docker", "cp", str(target.resolve()), f"{WP_CONTAINER_NAME}:{container_scan_dir}"],
        capture_output=True, text=True, timeout=60,
    )
    if copy_result.returncode != 0:
        return {"error": f"Failed to copy source to container: {copy_result.stderr}"}

    # Remove vendor/node_modules inside container to speed up scan
    for exclude in ["vendor", "node_modules", "lib", "assets"]:
        subprocess.run(
            ["docker", "exec", WP_CONTAINER_NAME, "rm", "-rf", f"{container_scan_dir}/{exclude}"],
            capture_output=True, timeout=10,
        )

    # Copy WordPress-specific config and JSON data files
    from wpguard.semgrep_rules import RULES_DIR
    pp_config = RULES_DIR / "progpilot-wordpress.yml"
    container_config = "/tmp/progpilot-wordpress.yml"
    if pp_config.exists():
        subprocess.run(
            ["docker", "cp", str(pp_config), f"{WP_CONTAINER_NAME}:{container_config}"],
            capture_output=True, timeout=10,
        )
        # Copy JSON config files referenced by the YAML (sources, sinks, sanitizers)
        for json_file in ["progpilot-wp-sources.json", "progpilot-wp-sinks.json", "progpilot-wp-sanitizers.json"]:
            json_path = RULES_DIR / json_file
            if json_path.exists():
                subprocess.run(
                    ["docker", "cp", str(json_path), f"{WP_CONTAINER_NAME}:/tmp/{json_file}"],
                    capture_output=True, timeout=10,
                )

    # Run progpilot with WordPress config
    pp_cmd = ["docker", "exec", WP_CONTAINER_NAME, "php", "/usr/local/bin/progpilot"]
    if pp_config.exists():
        pp_cmd.extend(["--configuration", container_config])
    pp_cmd.append(container_scan_dir)

    try:
        result = subprocess.run(pp_cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Clean up on timeout
        subprocess.run(
            ["docker", "exec", WP_CONTAINER_NAME, "rm", "-rf", container_scan_dir],
            capture_output=True, timeout=10,
        )
        return {"error": f"Progpilot scan timed out after {timeout}s. Try targeting a subdirectory."}

    # Clean up
    subprocess.run(
        ["docker", "exec", WP_CONTAINER_NAME, "rm", "-rf", container_scan_dir],
        capture_output=True, timeout=10,
    )

    # Parse JSON output
    try:
        findings = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return {"error": "Failed to parse progpilot output", "raw": result.stdout[:1000]}

    if not isinstance(findings, list):
        findings = []

    # Map progpilot's actual JSON structure correctly
    # source_name/source_file/source_line/source_column are ARRAYS (multiple taint sources per finding)
    # sink_name/sink_file/sink_line/sink_column are scalars
    # tainted_flow is only present when outputs.tainted_flow=true in config
    # tainted_flow is array of arrays, each inner array has steps with flow_name/flow_line/flow_file/flow_column
    results = []
    for f in findings[:100]:
        # source fields are arrays — take first element
        src_names = f.get("source_name", [])
        src_files = f.get("source_file", [])
        src_lines = f.get("source_line", [])
        src_name = src_names[0] if src_names else ""
        src_file = src_files[0] if src_files else ""
        src_line = src_lines[0] if src_lines else 0
        if isinstance(src_file, str):
            src_file = src_file.replace(container_scan_dir + "/", "")

        # sink fields are scalars
        sink_file = f.get("sink_file", "")
        if isinstance(sink_file, str):
            sink_file = sink_file.replace(container_scan_dir + "/", "")

        # Build readable taint flow from tainted_flow array (nested: array of arrays of steps)
        flow_steps = []
        for flow_chain in f.get("tainted_flow", []):
            if not isinstance(flow_chain, list):
                continue
            for step in flow_chain:
                step_file = step.get("flow_file", "")
                if isinstance(step_file, str):
                    step_file = step_file.replace(container_scan_dir + "/", "")
                flow_steps.append(f"{step.get('flow_name', '')} ({step_file}:{step.get('flow_line', '')})")

        results.append({
            "vuln_type": f.get("vuln_name", "unknown"),
            "vuln_cwe": f.get("vuln_cwe", ""),
            "source": src_name,
            "source_file": src_file,
            "source_line": src_line,
            "sink": f.get("sink_name", ""),
            "sink_file": sink_file,
            "sink_line": f.get("sink_line", 0),
            "taint_flow": " → ".join(flow_steps) if flow_steps else f"{src_name} → {f.get('sink_name', '')}",
        })

    # Summary
    by_type: dict[str, int] = {}
    for r in results:
        by_type[r["vuln_type"]] = by_type.get(r["vuln_type"], 0) + 1

    result_data = {
        "total_findings": len(results),
        "findings": results,
        "summary": by_type,
    }

    # Save to disk if output_dir provided
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "progpilot_scan.json", "w") as f:
            json.dump(result_data, f, indent=2)
        # Markdown summary
        md = ["# Progpilot Taint Analysis Results\n"]
        if results:
            md.append("| # | Source → Sink | File:Line | Type | Flow |")
            md.append("|---|-------------|-----------|------|------|")
            for i, r in enumerate(results, 1):
                md.append(f"| {i} | {r['source']} → {r['sink']} | {r['sink_file']}:{r['sink_line']} | {r['vuln_type']} | {r['taint_flow'][:80]} |")
        else:
            md.append("No taint flows detected.")
        md.append(f"\n## Summary\n{', '.join(f'{k} ({v})' for k,v in by_type.items())}")
        with open(out / "progpilot_scan.md", "w") as f:
            f.write("\n".join(md))
        result_data["saved_to"] = str(out)

    return result_data


async def _progpilot_scan(target_dir: str, timeout: int, output_dir: str | None = None) -> dict[str, Any]:
    return await run_in_executor(_progpilot_scan_sync, target_dir, timeout, output_dir)


# ── Agent Checkpoint Implementation ───────────────────

def _agent_checkpoint_sync(
    action: str, agent_name: str, plugin_slug: str,
    files_analyzed: list[str] | None, files_partial: list[str] | None,
    files_remaining: list[str] | None, findings_created: list[str] | None,
    notes: list[str] | None, priority_targets: list[str] | None,
    output_dir: str,
) -> dict[str, Any]:
    from wpguard.core.checkpoint import CheckpointManager
    mgr = CheckpointManager(output_dir)

    if action == "start":
        return mgr.start(agent_name, plugin_slug, priority_targets)
    elif action == "progress":
        return mgr.progress(agent_name, plugin_slug, files_analyzed, files_partial, files_remaining, findings_created, notes)
    elif action == "complete":
        return mgr.complete(agent_name, plugin_slug, notes)
    elif action == "partial":
        return mgr.partial(agent_name, plugin_slug, files_remaining, notes)
    else:
        return {"error": f"Unknown action: {action}"}


async def _agent_checkpoint(
    action: str, agent_name: str, plugin_slug: str,
    files_analyzed: list[str] | None, files_partial: list[str] | None,
    files_remaining: list[str] | None, findings_created: list[str] | None,
    notes: list[str] | None, priority_targets: list[str] | None,
    output_dir: str,
) -> dict[str, Any]:
    return await run_in_executor(
        _agent_checkpoint_sync, action, agent_name, plugin_slug,
        files_analyzed, files_partial, files_remaining,
        findings_created, notes, priority_targets, output_dir,
    )


# ── Bounty Estimator Implementation ───────────────────

def _bounty_estimate_sync(vuln_type: str, install_count: int, auth_level: str, researcher_tier: int) -> dict[str, Any]:
    """Estimate bounty (sync version)."""
    from wpguard.core.bounty import BountyEstimator
    estimator = BountyEstimator()
    return estimator.estimate(vuln_type, install_count, auth_level, researcher_tier)


async def _bounty_estimate(vuln_type: str, install_count: int, auth_level: str, researcher_tier: int) -> dict[str, Any]:
    return await run_in_executor(_bounty_estimate_sync, vuln_type, install_count, auth_level, researcher_tier)


# ── Findings Dedup Implementation ─────────────────────

def _finding_check_duplicate_sync(
    plugin_slug: str, affected_file: str, affected_function: str,
    vuln_type: str, output_dir: str,
) -> dict[str, Any]:
    """Check for duplicate findings (sync version)."""
    manager = FindingsManager(output_dir)
    matches = manager.check_duplicate(
        plugin_slug=plugin_slug,
        affected_file=affected_file,
        affected_function=affected_function,
        vuln_type=vuln_type,
    )
    return {
        "potential_duplicates": matches,
        "count": len(matches),
        "has_exact_match": any(m["similarity"] == "exact" for m in matches),
    }


async def _finding_check_duplicate(
    plugin_slug: str, affected_file: str, affected_function: str,
    vuln_type: str, output_dir: str,
) -> dict[str, Any]:
    return await run_in_executor(
        _finding_check_duplicate_sync, plugin_slug, affected_file,
        affected_function, vuln_type, output_dir,
    )


# Discord Notification Tool Implementations

def _discord_notify_finding_sync(
    finding_id: str,
    title_prefix: str,
    mention: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Send finding notification to Discord (sync version)."""
    if not DISCORD_WEBHOOK_URL:
        return {
            "success": False,
            "error": "Discord webhook URL not configured. Set DISCORD_WEBHOOK_URL environment variable.",
        }

    manager = FindingsManager(output_dir)
    finding = manager.get_finding(finding_id)

    if not finding:
        return {"success": False, "error": f"Finding {finding_id} not found"}

    notifier = DiscordNotifier(DISCORD_WEBHOOK_URL)
    success = notifier.send_finding(finding, title_prefix=title_prefix, mention=mention)

    return {
        "success": success,
        "finding_id": finding_id,
        "message": "Notification sent" if success else "Failed to send notification",
    }


async def _discord_notify_finding(
    finding_id: str,
    title_prefix: str,
    mention: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Send finding notification to Discord."""
    return await run_in_executor(
        _discord_notify_finding_sync, finding_id, title_prefix, mention, output_dir,
    )


def _discord_notify_summary_sync(
    title: str,
    status_filter: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Send findings summary to Discord (sync version)."""
    if not DISCORD_WEBHOOK_URL:
        return {
            "success": False,
            "error": "Discord webhook URL not configured. Set DISCORD_WEBHOOK_URL environment variable.",
        }

    manager = FindingsManager(output_dir)
    findings = manager.list_findings(status=status_filter)

    if not findings:
        return {
            "success": True,
            "message": "No findings to summarize",
            "findings_count": 0,
        }

    notifier = DiscordNotifier(DISCORD_WEBHOOK_URL)
    success = notifier.send_finding_summary(findings, title=title)

    return {
        "success": success,
        "findings_count": len(findings),
        "message": "Summary sent" if success else "Failed to send summary",
    }


async def _discord_notify_summary(
    title: str,
    status_filter: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Send findings summary to Discord."""
    return await run_in_executor(
        _discord_notify_summary_sync, title, status_filter, output_dir,
    )


def _discord_send_message_sync(message: str) -> dict[str, Any]:
    """Send simple message to Discord (sync version)."""
    if not DISCORD_WEBHOOK_URL:
        return {
            "success": False,
            "error": "Discord webhook URL not configured. Set DISCORD_WEBHOOK_URL environment variable.",
        }

    notifier = DiscordNotifier(DISCORD_WEBHOOK_URL)
    success = notifier.send_message(message)

    return {
        "success": success,
        "message": "Message sent" if success else "Failed to send message",
    }


async def _discord_send_message(message: str) -> dict[str, Any]:
    """Send simple message to Discord."""
    return await run_in_executor(_discord_send_message_sync, message)


# Project Initialization Tool Implementation

def _init_research_sync(output_dir: str) -> dict[str, Any]:
    """Initialize research project (sync version)."""
    from wpguard.core.init import initialize_research_project

    return initialize_research_project(output_dir)


async def _init_research(output_dir: str) -> dict[str, Any]:
    """Initialize research project directory with agent instructions."""
    return await run_in_executor(_init_research_sync, output_dir)


# Wordfence CVE Database Tool Implementations

# Singleton instance for CVE database
_wordfence_db: "WorkfenceVulnDB | None" = None


def _get_wordfence_db():
    """Get or create the Wordfence vulnerability database instance."""
    global _wordfence_db
    if _wordfence_db is None:
        from wpguard.api.wordfence import WorkfenceVulnDB
        _wordfence_db = WorkfenceVulnDB()
    return _wordfence_db


def _cve_download_sync(force: bool) -> dict[str, Any]:
    """Download CVE database (sync version)."""
    db = _get_wordfence_db()
    return db.download(force=force)


async def _cve_download(force: bool) -> dict[str, Any]:
    """Download CVE database."""
    return await run_in_executor(_cve_download_sync, force)


def _cve_search_sync(
    slug: str | None,
    query: str | None,
    vuln_type: str | None,
    limit: int,
) -> dict[str, Any]:
    """Search CVE database (sync version)."""
    db = _get_wordfence_db()

    # If slug is provided, get all vulns for that plugin
    if slug:
        vulns = db.get_vulns_for_slug(slug)
        return {
            "search_type": "by_slug",
            "slug": slug,
            "results_count": len(vulns),
            "results": vulns[:limit],
        }

    # Otherwise, do keyword/type search
    vulns = db.search_vulns(query=query, vuln_type=vuln_type, limit=limit)
    return {
        "search_type": "by_query",
        "query": query,
        "vuln_type": vuln_type,
        "results_count": len(vulns),
        "results": vulns,
    }


async def _cve_search(
    slug: str | None,
    query: str | None,
    vuln_type: str | None,
    limit: int,
) -> dict[str, Any]:
    """Search CVE database."""
    return await run_in_executor(_cve_search_sync, slug, query, vuln_type, limit)


def _cve_get_sync(vuln_id: str) -> dict[str, Any]:
    """Get CVE by ID (sync version)."""
    db = _get_wordfence_db()

    # Check if it's a CVE ID (starts with CVE-)
    if vuln_id.upper().startswith("CVE-"):
        vuln = db.get_vuln_by_cve(vuln_id)
    else:
        vuln = db.get_vuln_by_id(vuln_id)

    if vuln:
        return {"success": True, "vulnerability": vuln}
    return {"success": False, "error": f"Vulnerability '{vuln_id}' not found"}


async def _cve_get(vuln_id: str) -> dict[str, Any]:
    """Get CVE by ID."""
    return await run_in_executor(_cve_get_sync, vuln_id)


def _cve_stats_sync() -> dict[str, Any]:
    """Get CVE database stats (sync version)."""
    db = _get_wordfence_db()
    return db.get_stats()


async def _cve_stats() -> dict[str, Any]:
    """Get CVE database stats."""
    return await run_in_executor(_cve_stats_sync)


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
