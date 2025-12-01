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
    PLUGINS_SUBDIR,
    WP_PLUGINS_SVN,
    WP_PLUGINS_URL,
)
from wpguard.core.downloader import PluginDownloader, SVNClient

# MCP-specific default: use current directory so tools work in initialized project root
# CLI uses DEFAULT_OUTPUT_DIR from config (./wpguard_output) for standalone usage
DEFAULT_OUTPUT_DIR = "."
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
        # WordPress Sandbox Tools
        Tool(
            name="wpguard_sandbox_status",
            description="Check WordPress sandbox connectivity (HTTP, Docker container, WP-CLI)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_install_plugin",
            description="Install a plugin in the WordPress sandbox for PoC testing",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug from WordPress.org",
                    },
                    "version": {
                        "type": "string",
                        "description": "Specific version to install (optional, defaults to latest)",
                    },
                    "activate": {
                        "type": "boolean",
                        "description": "Activate the plugin after installation (default: true)",
                        "default": True,
                    },
                    "from_zip": {
                        "type": "string",
                        "description": "Install from local ZIP file path instead of slug",
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_sandbox_uninstall_plugin",
            description="Uninstall a plugin from the WordPress sandbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug to uninstall",
                    },
                },
                "required": ["slug"],
            },
        ),
        Tool(
            name="wpguard_sandbox_request",
            description="Execute an HTTP request against the WordPress sandbox (for PoC testing)",
            inputSchema={
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, DELETE)",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                    },
                    "path": {
                        "type": "string",
                        "description": "URL path (e.g., '/wp-admin/admin-ajax.php')",
                    },
                    "data": {
                        "type": "object",
                        "description": "Request data (POST body or query params)",
                    },
                    "auth": {
                        "type": "string",
                        "description": "Role to authenticate as (subscriber, contributor, author, admin) or null for unauthenticated",
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
            description="Execute a WP-CLI command in the WordPress sandbox container",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "WP-CLI command without 'wp' prefix (e.g., 'plugin list', 'user list')",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Command timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="wpguard_sandbox_get_nonce",
            description="Get a WordPress nonce for an action (needed for protected AJAX calls)",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Nonce action name",
                    },
                    "auth": {
                        "type": "string",
                        "description": "Role to authenticate as for nonce generation",
                        "enum": ["subscriber", "contributor", "author", "admin"],
                    },
                },
                "required": ["action"],
            },
        ),
        # Sandbox Management Tools
        Tool(
            name="wpguard_sandbox_start",
            description="Start the WordPress sandbox Docker containers (builds if needed). Use this if sandbox_status shows the sandbox is not running.",
            inputSchema={
                "type": "object",
                "properties": {
                    "wait_ready": {
                        "type": "boolean",
                        "description": "Wait for WordPress to be fully ready (default: true)",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait for WordPress to be ready (default: 120)",
                        "default": 120,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_stop",
            description="Stop the WordPress sandbox Docker containers",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_restart",
            description="Restart the WordPress sandbox (stop then start)",
            inputSchema={
                "type": "object",
                "properties": {
                    "wait_ready": {
                        "type": "boolean",
                        "description": "Wait for WordPress to be fully ready (default: true)",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_sandbox_destroy",
            description="Stop and remove all sandbox data (volumes). This completely resets WordPress.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        # Wordfence Scope Validation Tools
        Tool(
            name="wpguard_scope_check_plugin",
            description="Check if a plugin is eligible for Wordfence bounty research (vendor exclusion, install count, availability)",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {
                        "type": "string",
                        "description": "Plugin slug to check",
                    },
                    "active_installs": {
                        "type": "integer",
                        "description": "Number of active installations",
                    },
                    "author": {
                        "type": "string",
                        "description": "Plugin author name (for vendor exclusion check)",
                    },
                    "is_available": {
                        "type": "boolean",
                        "description": "Whether plugin is available for download (default: true)",
                        "default": True,
                    },
                },
                "required": ["plugin_slug", "active_installs"],
            },
        ),
        Tool(
            name="wpguard_scope_check_finding",
            description="Validate if a vulnerability finding is eligible for Wordfence bounty submission",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {
                        "type": "string",
                        "description": "Plugin slug",
                    },
                    "active_installs": {
                        "type": "integer",
                        "description": "Number of active installations",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Vulnerability type (e.g., 'sql_injection', 'stored_xss', 'rce')",
                    },
                    "auth_level": {
                        "type": "string",
                        "description": "Required authentication level",
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
            description="Get all in-scope vulnerability types for a given install count",
            inputSchema={
                "type": "object",
                "properties": {
                    "active_installs": {
                        "type": "integer",
                        "description": "Number of active installations",
                    },
                },
                "required": ["active_installs"],
            },
        ),
        # Finding Persistence Tools
        Tool(
            name="wpguard_finding_create",
            description="Create a new security vulnerability finding",
            inputSchema={
                "type": "object",
                "properties": {
                    "plugin_slug": {"type": "string", "description": "Plugin slug"},
                    "plugin_version": {"type": "string", "description": "Plugin version"},
                    "active_installs": {"type": "integer", "description": "Active installations"},
                    "vuln_type": {"type": "string", "description": "Vulnerability type (e.g., sql_injection, stored_xss)"},
                    "title": {"type": "string", "description": "Finding title"},
                    "description": {"type": "string", "description": "Detailed description"},
                    "auth_level": {
                        "type": "string",
                        "description": "Required auth level",
                        "enum": ["unauthenticated", "subscriber", "customer", "contributor", "author", "editor", "administrator"],
                    },
                    "cvss_score": {"type": "number", "description": "CVSS 3.1 score"},
                    "cvss_vector": {"type": "string", "description": "CVSS vector string"},
                    "affected_file": {"type": "string", "description": "Path to affected file"},
                    "affected_function": {"type": "string", "description": "Affected function name"},
                    "affected_line": {"type": "integer", "description": "Line number"},
                    "poc_path": {"type": "string", "description": "Path to PoC script"},
                    "tier": {"type": "string", "description": "Bounty tier"},
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": ["plugin_slug", "plugin_version", "active_installs", "vuln_type", "title", "description", "auth_level", "cvss_score", "cvss_vector", "affected_file"],
            },
        ),
        Tool(
            name="wpguard_finding_update",
            description="Update an existing finding (status, validation notes, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID to update"},
                    "status": {
                        "type": "string",
                        "description": "New status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "validation_notes": {"type": "string", "description": "Validation notes"},
                    "submission_id": {"type": "string", "description": "Submission ID if submitted"},
                    "poc_path": {"type": "string", "description": "Path to PoC script"},
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_finding_get",
            description="Get a finding by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
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
                    "plugin_slug": {"type": "string", "description": "Filter by plugin"},
                    "status": {
                        "type": "string",
                        "description": "Filter by status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "vuln_type": {"type": "string", "description": "Filter by vulnerability type"},
                    "min_cvss": {"type": "number", "description": "Minimum CVSS score"},
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_finding_delete",
            description="Delete a finding",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID to delete"},
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_finding_stats",
            description="Get statistics about all findings",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_scan_state",
            description="Get or update scan state (current plugin, pending plugins, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "current_plugin": {"type": "string", "description": "Set currently scanning plugin"},
                    "add_scanned": {"type": "string", "description": "Add plugin to scanned list"},
                    "add_pending": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Add plugins to pending list",
                    },
                    "remove_pending": {"type": "string", "description": "Remove plugin from pending"},
                    "clear_pending": {"type": "boolean", "description": "Clear all pending plugins"},
                    "stage_completed": {
                        "type": "string",
                        "description": "Signal pipeline stage completion (target-research, security-research, qa-triage). Pipeline will kill tmux session and proceed to next stage.",
                    },
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": [],
            },
        ),
        # Discord Notification Tools
        Tool(
            name="wpguard_discord_notify_finding",
            description="Send a finding notification to Discord (use when a finding is validated and ready for review)",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID to notify about"},
                    "title_prefix": {
                        "type": "string",
                        "description": "Optional title prefix (e.g., 'NEW: ', 'VALIDATED: ')",
                    },
                    "mention": {
                        "type": "string",
                        "description": "Optional mention (e.g., '@everyone', '<@user_id>')",
                    },
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="wpguard_discord_notify_summary",
            description="Send a summary of findings to Discord",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Summary title (default: 'Security Research Summary')",
                    },
                    "status_filter": {
                        "type": "string",
                        "description": "Filter findings by status",
                        "enum": ["draft", "validated", "submitted", "rejected", "duplicate"],
                    },
                    "output_dir": {"type": "string", "description": f"Output directory (default: {DEFAULT_OUTPUT_DIR})"},
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_discord_send_message",
            description="Send a simple text message to Discord",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message content to send"},
                },
                "required": ["message"],
            },
        ),
        # Project Initialization
        Tool(
            name="wpguard_init_research",
            description="Initialize a new wpguard research project with agent instructions and directory structure. Creates CLAUDE.md, slash commands, and folders for targets/reports.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to create research project in (default: ./wpguard-research)",
                        "default": "./wpguard-research",
                    },
                },
                "required": [],
            },
        ),
        # Wordfence CVE Database Tools
        Tool(
            name="wpguard_cve_download",
            description="Download/refresh the Wordfence vulnerability database (cached in /tmp/wordfence_vulns.json)",
            inputSchema={
                "type": "object",
                "properties": {
                    "force": {
                        "type": "boolean",
                        "description": "Force re-download even if cache is fresh (default: false)",
                        "default": False,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_cve_search",
            description="Search Wordfence CVE database by plugin slug or keyword. Use this to find known vulnerabilities for target plugins.",
            inputSchema={
                "type": "object",
                "properties": {
                    "slug": {
                        "type": "string",
                        "description": "Plugin slug to get all CVEs for (e.g., 'contact-form-7')",
                    },
                    "query": {
                        "type": "string",
                        "description": "Search term (searches title and description)",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Filter by vulnerability type (e.g., 'XSS', 'SQL Injection')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 50)",
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
                        "description": "Wordfence vulnerability ID (UUID) or CVE ID (e.g., 'CVE-2024-1234')",
                    },
                },
                "required": ["vuln_id"],
            },
        ),
        Tool(
            name="wpguard_cve_stats",
            description="Get statistics about the Wordfence vulnerability database",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        # Pipeline Automation Tools
        Tool(
            name="wpguard_pipeline_start",
            description="Start the security research pipeline daemon. Spawns Claude workers in tmux sessions for target-research -> security-research -> qa-triage.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["continuous", "single", "targets-only"],
                        "description": "Pipeline mode: 'continuous' (loop), 'single' (one cycle), 'targets-only' (just find targets)",
                        "default": "continuous",
                    },
                    "target_count": {
                        "type": "integer",
                        "description": "Number of targets per cycle (default: 5)",
                        "default": 5,
                    },
                    "restart_mode": {
                        "type": "string",
                        "enum": ["deeper", "next", "configurable"],
                        "description": "How to handle security-research restarts: 'deeper' (same plugin), 'next' (move on), 'configurable' (auto)",
                        "default": "deeper",
                    },
                    "max_restarts": {
                        "type": "integer",
                        "description": "Max restarts per plugin for security-research (default: 3)",
                        "default": 3,
                    },
                    "target_criteria": {
                        "type": "string",
                        "description": "Custom criteria/arguments to pass to /target-research (e.g., 'browse:updated min_installs:1000')",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_stop",
            description="Stop the pipeline daemon. Set force=true for immediate stop.",
            inputSchema={
                "type": "object",
                "properties": {
                    "force": {
                        "type": "boolean",
                        "description": "Force immediate stop without cleanup (default: false)",
                        "default": False,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_status",
            description="Get current pipeline status: daemon state, worker progress, metrics.",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_logs": {
                        "type": "boolean",
                        "description": "Include recent worker output (default: false)",
                        "default": False,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_pause",
            description="Pause the pipeline. Current stage completes, next won't start.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_resume",
            description="Resume a paused pipeline.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_config",
            description="Get or update pipeline configuration.",
            inputSchema={
                "type": "object",
                "properties": {
                    "restart_mode": {
                        "type": "string",
                        "enum": ["deeper", "next", "configurable"],
                        "description": "Update restart mode",
                    },
                    "max_restarts": {
                        "type": "integer",
                        "description": "Update max restarts",
                    },
                    "notify_discord": {
                        "type": "boolean",
                        "description": "Enable/disable Discord notifications",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="wpguard_pipeline_logs",
            description="Get logs from a worker session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "stage": {
                        "type": "string",
                        "enum": ["target-research", "security-research", "qa-triage"],
                        "description": "Pipeline stage to get logs for",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines to return (default: 100)",
                        "default": 100,
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["stage"],
            },
        ),
        Tool(
            name="wpguard_pipeline_attach",
            description="Get the tmux attach command for a stage. Use to manually watch a worker.",
            inputSchema={
                "type": "object",
                "properties": {
                    "stage": {
                        "type": "string",
                        "enum": ["target-research", "security-research", "qa-triage"],
                        "description": "Pipeline stage",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": f"Project directory (default: {DEFAULT_OUTPUT_DIR})",
                        "default": DEFAULT_OUTPUT_DIR,
                    },
                },
                "required": ["stage"],
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

    elif name == "wpguard_scan_state":
        return await _scan_state(
            arguments.get("current_plugin"),
            arguments.get("add_scanned"),
            arguments.get("add_pending"),
            arguments.get("remove_pending"),
            arguments.get("clear_pending", False),
            arguments.get("stage_completed"),
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

    # Pipeline Automation Tools
    elif name == "wpguard_pipeline_start":
        return await _pipeline_start(
            arguments.get("mode", "continuous"),
            arguments.get("target_count", 5),
            arguments.get("restart_mode", "deeper"),
            arguments.get("max_restarts", 3),
            arguments.get("target_criteria"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_pipeline_stop":
        return await _pipeline_stop(
            arguments.get("force", False),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_pipeline_status":
        return await _pipeline_status(
            arguments.get("include_logs", False),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_pipeline_pause":
        return await _pipeline_pause(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    elif name == "wpguard_pipeline_resume":
        return await _pipeline_resume(arguments.get("output_dir", DEFAULT_OUTPUT_DIR))

    elif name == "wpguard_pipeline_config":
        return await _pipeline_config(
            arguments.get("restart_mode"),
            arguments.get("max_restarts"),
            arguments.get("notify_discord"),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_pipeline_logs":
        return await _pipeline_logs(
            arguments["stage"],
            arguments.get("lines", 100),
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

    elif name == "wpguard_pipeline_attach":
        return await _pipeline_attach(
            arguments["stage"],
            arguments.get("output_dir", DEFAULT_OUTPUT_DIR),
        )

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
) -> dict[str, Any]:
    """Update a finding (sync version)."""
    manager = FindingsManager(output_dir)
    finding = manager.update_finding(
        finding_id=finding_id,
        status=status,
        validation_notes=validation_notes,
        submission_id=submission_id,
        poc_path=poc_path,
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
) -> dict[str, Any]:
    """Update a finding."""
    return await run_in_executor(
        _finding_update_sync, finding_id, status, validation_notes,
        submission_id, poc_path, output_dir,
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


def _scan_state_sync(
    current_plugin: str | None,
    add_scanned: str | None,
    add_pending: list[str] | None,
    remove_pending: str | None,
    clear_pending: bool,
    stage_completed: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Get or update scan state (sync version)."""
    manager = FindingsManager(output_dir)

    # If no updates, just get current state
    if all(x is None for x in [current_plugin, add_scanned, add_pending, remove_pending, stage_completed]) and not clear_pending:
        return manager.get_scan_state()

    return manager.update_scan_state(
        current_plugin=current_plugin,
        add_scanned=add_scanned,
        add_pending=add_pending,
        remove_pending=remove_pending,
        clear_pending=clear_pending,
        stage_completed=stage_completed,
    )


async def _scan_state(
    current_plugin: str | None,
    add_scanned: str | None,
    add_pending: list[str] | None,
    remove_pending: str | None,
    clear_pending: bool,
    stage_completed: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Get or update scan state."""
    return await run_in_executor(
        _scan_state_sync, current_plugin, add_scanned, add_pending,
        remove_pending, clear_pending, stage_completed, output_dir,
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


# Pipeline Automation Tool Implementations

def _pipeline_start_sync(
    mode: str,
    target_count: int,
    restart_mode: str,
    max_restarts: int,
    target_criteria: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Start pipeline daemon (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.start(
        mode=mode,
        target_count=target_count,
        restart_mode=restart_mode,
        max_restarts=max_restarts,
        target_criteria=target_criteria,
    )


async def _pipeline_start(
    mode: str,
    target_count: int,
    restart_mode: str,
    max_restarts: int,
    target_criteria: str | None,
    output_dir: str,
) -> dict[str, Any]:
    """Start pipeline daemon."""
    return await run_in_executor(
        _pipeline_start_sync, mode, target_count, restart_mode, max_restarts, target_criteria, output_dir
    )


def _pipeline_stop_sync(force: bool, output_dir: str) -> dict[str, Any]:
    """Stop pipeline daemon (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.stop(force=force)


async def _pipeline_stop(force: bool, output_dir: str) -> dict[str, Any]:
    """Stop pipeline daemon."""
    return await run_in_executor(_pipeline_stop_sync, force, output_dir)


def _pipeline_status_sync(include_logs: bool, output_dir: str) -> dict[str, Any]:
    """Get pipeline status (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.get_status(include_logs=include_logs)


async def _pipeline_status(include_logs: bool, output_dir: str) -> dict[str, Any]:
    """Get pipeline status."""
    return await run_in_executor(_pipeline_status_sync, include_logs, output_dir)


def _pipeline_pause_sync(output_dir: str) -> dict[str, Any]:
    """Pause pipeline (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.pause()


async def _pipeline_pause(output_dir: str) -> dict[str, Any]:
    """Pause pipeline."""
    return await run_in_executor(_pipeline_pause_sync, output_dir)


def _pipeline_resume_sync(output_dir: str) -> dict[str, Any]:
    """Resume pipeline (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.resume()


async def _pipeline_resume(output_dir: str) -> dict[str, Any]:
    """Resume pipeline."""
    return await run_in_executor(_pipeline_resume_sync, output_dir)


def _pipeline_config_sync(
    restart_mode: str | None,
    max_restarts: int | None,
    notify_discord: bool | None,
    output_dir: str,
) -> dict[str, Any]:
    """Get or update pipeline config (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)

    # If no updates, just return current config
    updates = {}
    if restart_mode is not None:
        updates["restart_mode"] = restart_mode
    if max_restarts is not None:
        updates["max_restarts"] = max_restarts
    if notify_discord is not None:
        updates["notify_discord"] = notify_discord

    if updates:
        return {"config": daemon.update_config(**updates), "updated": True}
    return {"config": daemon.get_config(), "updated": False}


async def _pipeline_config(
    restart_mode: str | None,
    max_restarts: int | None,
    notify_discord: bool | None,
    output_dir: str,
) -> dict[str, Any]:
    """Get or update pipeline config."""
    return await run_in_executor(
        _pipeline_config_sync, restart_mode, max_restarts, notify_discord, output_dir
    )


def _pipeline_logs_sync(stage: str, lines: int, output_dir: str) -> dict[str, Any]:
    """Get worker logs (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.get_worker_logs(stage, lines=lines)


async def _pipeline_logs(stage: str, lines: int, output_dir: str) -> dict[str, Any]:
    """Get worker logs."""
    return await run_in_executor(_pipeline_logs_sync, stage, lines, output_dir)


def _pipeline_attach_sync(stage: str, output_dir: str) -> dict[str, Any]:
    """Get attach command (sync version)."""
    from wpguard.core.pipeline import PipelineDaemon
    daemon = PipelineDaemon(output_dir)
    return daemon.get_attach_command(stage)


async def _pipeline_attach(stage: str, output_dir: str) -> dict[str, Any]:
    """Get attach command."""
    return await run_in_executor(_pipeline_attach_sync, stage, output_dir)


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
