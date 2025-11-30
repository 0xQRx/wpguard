"""
Initialize research project directories with agent instructions.

Templates are loaded from the templates/ directory for easy modification.
"""

import json
from pathlib import Path

from wpguard.core.findings import FINDINGS_FILENAME, SCAN_STATE_FILENAME


# Template directory relative to this file
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# All wpguard MCP tools for permissions
WPGUARD_MCP_TOOLS = [
    "mcp__wpguard__wpguard_plugin_info",
    "mcp__wpguard__wpguard_search",
    "mcp__wpguard__wpguard_download",
    "mcp__wpguard__wpguard_bulk_download",
    "mcp__wpguard__wpguard_watch_add",
    "mcp__wpguard__wpguard_watch_remove",
    "mcp__wpguard__wpguard_watch_list",
    "mcp__wpguard__wpguard_watch_check",
    "mcp__wpguard__wpguard_svn_log",
    "mcp__wpguard__wpguard_svn_diff",
    "mcp__wpguard__wpguard_svn_revision",
    "mcp__wpguard__wpguard_plugin_versions",
    "mcp__wpguard__wpguard_state_info",
    "mcp__wpguard__wpguard_sandbox_status",
    "mcp__wpguard__wpguard_sandbox_install_plugin",
    "mcp__wpguard__wpguard_sandbox_uninstall_plugin",
    "mcp__wpguard__wpguard_sandbox_request",
    "mcp__wpguard__wpguard_sandbox_wp_cli",
    "mcp__wpguard__wpguard_sandbox_get_nonce",
    "mcp__wpguard__wpguard_scope_check_plugin",
    "mcp__wpguard__wpguard_scope_check_finding",
    "mcp__wpguard__wpguard_scope_get_vulns",
    "mcp__wpguard__wpguard_finding_create",
    "mcp__wpguard__wpguard_finding_update",
    "mcp__wpguard__wpguard_finding_get",
    "mcp__wpguard__wpguard_finding_list",
    "mcp__wpguard__wpguard_finding_delete",
    "mcp__wpguard__wpguard_finding_stats",
    "mcp__wpguard__wpguard_scan_state",
    "mcp__wpguard__wpguard_discord_notify_finding",
    "mcp__wpguard__wpguard_discord_notify_summary",
    "mcp__wpguard__wpguard_discord_send_message",
    "mcp__wpguard__wpguard_init_research",
]


def _load_template(name: str) -> str:
    """
    Load a template file from the templates directory.

    Args:
        name: Template filename (e.g., 'CLAUDE.md', 'target-research.md')

    Returns:
        Template content as string

    Raises:
        FileNotFoundError: If template doesn't exist
    """
    template_path = TEMPLATES_DIR / name
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    return template_path.read_text()


def get_main_claude_md() -> str:
    """Get the main CLAUDE.md template content."""
    return _load_template("CLAUDE.md")


def get_target_researcher_instructions() -> str:
    """Get target researcher agent instructions."""
    return _load_template("target-research.md")


def get_security_researcher_instructions() -> str:
    """Get security researcher agent instructions."""
    return _load_template("security-research.md")


def get_qa_triager_instructions() -> str:
    """Get QA/triager agent instructions."""
    return _load_template("qa-triage.md")


def initialize_research_project(output_dir: str) -> dict:
    """
    Create research project with agent instructions.

    Args:
        output_dir: Directory to create/initialize

    Returns:
        dict with success status and created structure
    """
    root = Path(output_dir).expanduser().resolve()

    try:
        # Create directories
        root.mkdir(parents=True, exist_ok=True)
        (root / "targets").mkdir(exist_ok=True)
        (root / "reports").mkdir(exist_ok=True)
        (root / ".claude" / "commands").mkdir(parents=True, exist_ok=True)

        # Write main CLAUDE.md
        (root / "CLAUDE.md").write_text(get_main_claude_md())

        # Write slash commands
        (root / ".claude" / "commands" / "target-research.md").write_text(
            get_target_researcher_instructions()
        )
        (root / ".claude" / "commands" / "security-research.md").write_text(
            get_security_researcher_instructions()
        )
        (root / ".claude" / "commands" / "qa-triage.md").write_text(
            get_qa_triager_instructions()
        )

        # Write settings.local.json with MCP tool permissions
        settings_local = {
            "permissions": {
                "allow": WPGUARD_MCP_TOOLS,
                "deny": [],
                "ask": [],
            }
        }
        (root / ".claude" / "settings.local.json").write_text(
            json.dumps(settings_local, indent=2)
        )

        # Initialize empty scan state file (matches FindingsManager schema)
        initial_state = {
            "current_plugin": None,
            "plugins_scanned": [],
            "plugins_pending": [],
            "last_activity": None,
            "session_start": None,
        }
        (root / SCAN_STATE_FILENAME).write_text(json.dumps(initial_state, indent=2))

        # Initialize empty findings file (matches FindingsManager schema)
        initial_findings = {
            "version": "1.0",
            "updated_at": None,
            "total_findings": 0,
            "findings": [],
        }
        (root / FINDINGS_FILENAME).write_text(json.dumps(initial_findings, indent=2))

        return {
            "success": True,
            "path": str(root),
            "message": f"Research project initialized at {root}",
            "structure": {
                "claude_md": str(root / "CLAUDE.md"),
                "commands": ["/target-research", "/security-research", "/qa-triage"],
                "directories": [
                    "targets/",
                    "targets/{plugin_slug}/",
                    "reports/",
                    "reports/{plugin_slug}/",
                    ".claude/",
                    ".claude/commands/",
                ],
                "files": [
                    SCAN_STATE_FILENAME,
                    FINDINGS_FILENAME,
                    ".claude/settings.local.json",
                ],
            },
        }

    except OSError as e:
        return {
            "success": False,
            "path": str(root),
            "message": f"Failed to initialize project: {e}",
            "error": str(e),
        }
