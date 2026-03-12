"""
Initialize research project directories with agent instructions.

Templates are loaded from the templates/ directory for easy modification.
"""

import json
from pathlib import Path

from wpguard.core.findings import FINDINGS_FILENAME


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
    # Sandbox management tools
    "mcp__wpguard__wpguard_sandbox_start",
    "mcp__wpguard__wpguard_sandbox_stop",
    "mcp__wpguard__wpguard_sandbox_restart",
    "mcp__wpguard__wpguard_sandbox_destroy",
    "mcp__wpguard__wpguard_scope_check_plugin",
    "mcp__wpguard__wpguard_scope_check_finding",
    "mcp__wpguard__wpguard_scope_get_vulns",
    "mcp__wpguard__wpguard_finding_create",
    "mcp__wpguard__wpguard_finding_update",
    "mcp__wpguard__wpguard_finding_get",
    "mcp__wpguard__wpguard_finding_list",
    "mcp__wpguard__wpguard_finding_delete",
    "mcp__wpguard__wpguard_finding_stats",
    "mcp__wpguard__wpguard_discord_notify_finding",
    "mcp__wpguard__wpguard_discord_notify_summary",
    "mcp__wpguard__wpguard_discord_send_message",
    "mcp__wpguard__wpguard_init_research",
    # Wordfence CVE database tools
    "mcp__wpguard__wpguard_cve_download",
    "mcp__wpguard__wpguard_cve_search",
    "mcp__wpguard__wpguard_cve_get",
    "mcp__wpguard__wpguard_cve_stats",
]

# Slash commands for agent workflows
WPGUARD_SLASH_COMMANDS = [
    "SlashCommand(/target-research)",
    "SlashCommand(/security-research)",
    "SlashCommand(/file-rce-expert)",
    "SlashCommand(/sqli-expert)",
    "SlashCommand(/xss-expert)",
    "SlashCommand(/auth-expert)",
    "SlashCommand(/object-injection-expert)",
    "SlashCommand(/ssrf-expert)",
    "SlashCommand(/race-condition-expert)",
    "SlashCommand(/csrf-expert)",
    "SlashCommand(/lfi-rfi-expert)",
    "SlashCommand(/xxe-expert)",
    "SlashCommand(/deserialization-expert)",
    "SlashCommand(/logic-flaw-expert)",
    "SlashCommand(/info-disclosure-expert)",
    "SlashCommand(/qa-triage)",
    "SlashCommand(/poc-creator)",
]

# Common bash commands needed for research
WPGUARD_BASH_COMMANDS = [
    "Bash(mkdir:*)",
    "Bash(curl:*)",
    "Bash(python3:*)",
    "Bash(ls:*)",
    "Bash(grep:*)",
    "Bash(cd:*)",
    "Bash(cat:*)",
    "Bash(svn:*)",
]

# Core Claude tools needed for autonomous operation
WPGUARD_CORE_TOOLS = [
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "Task",
    "WebFetch",
    "WebSearch",
    "TodoWrite",
    "NotebookEdit",
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


def get_poc_creator_instructions() -> str:
    """Get PoC creator agent instructions for changelog analysis."""
    return _load_template("poc-creator.md")


def get_file_rce_expert_instructions() -> str:
    """Get file operations & RCE expert agent instructions."""
    return _load_template("file-rce-expert.md")


def get_sqli_expert_instructions() -> str:
    """Get SQL injection expert agent instructions."""
    return _load_template("sqli-expert.md")


def get_xss_expert_instructions() -> str:
    """Get XSS expert agent instructions."""
    return _load_template("xss-expert.md")


def get_auth_expert_instructions() -> str:
    """Get authentication/authorization expert agent instructions."""
    return _load_template("auth-expert.md")


def get_object_injection_expert_instructions() -> str:
    """Get object injection expert agent instructions."""
    return _load_template("object-injection-expert.md")


def get_ssrf_expert_instructions() -> str:
    """Get SSRF expert agent instructions."""
    return _load_template("ssrf-expert.md")


def get_race_condition_expert_instructions() -> str:
    """Get race condition expert agent instructions."""
    return _load_template("race-condition-expert.md")


def get_csrf_expert_instructions() -> str:
    """Get CSRF expert agent instructions."""
    return _load_template("csrf-expert.md")


def get_lfi_rfi_expert_instructions() -> str:
    """Get LFI/RFI expert agent instructions."""
    return _load_template("lfi-rfi-expert.md")


def get_xxe_expert_instructions() -> str:
    """Get XXE expert agent instructions."""
    return _load_template("xxe-expert.md")


def get_deserialization_expert_instructions() -> str:
    """Get deserialization expert agent instructions."""
    return _load_template("deserialization-expert.md")


def get_logic_flaw_expert_instructions() -> str:
    """Get business logic flaw expert agent instructions."""
    return _load_template("logic-flaw-expert.md")


def get_info_disclosure_expert_instructions() -> str:
    """Get information disclosure expert agent instructions."""
    return _load_template("info-disclosure-expert.md")


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
        (root / ".claude" / "commands" / "poc-creator.md").write_text(
            get_poc_creator_instructions()
        )

        # Write expert agent slash commands
        (root / ".claude" / "commands" / "file-rce-expert.md").write_text(
            get_file_rce_expert_instructions()
        )
        (root / ".claude" / "commands" / "sqli-expert.md").write_text(
            get_sqli_expert_instructions()
        )
        (root / ".claude" / "commands" / "xss-expert.md").write_text(
            get_xss_expert_instructions()
        )
        (root / ".claude" / "commands" / "auth-expert.md").write_text(
            get_auth_expert_instructions()
        )
        (root / ".claude" / "commands" / "object-injection-expert.md").write_text(
            get_object_injection_expert_instructions()
        )
        (root / ".claude" / "commands" / "ssrf-expert.md").write_text(
            get_ssrf_expert_instructions()
        )
        (root / ".claude" / "commands" / "race-condition-expert.md").write_text(
            get_race_condition_expert_instructions()
        )
        (root / ".claude" / "commands" / "csrf-expert.md").write_text(
            get_csrf_expert_instructions()
        )
        (root / ".claude" / "commands" / "lfi-rfi-expert.md").write_text(
            get_lfi_rfi_expert_instructions()
        )
        (root / ".claude" / "commands" / "xxe-expert.md").write_text(
            get_xxe_expert_instructions()
        )
        (root / ".claude" / "commands" / "deserialization-expert.md").write_text(
            get_deserialization_expert_instructions()
        )
        (root / ".claude" / "commands" / "logic-flaw-expert.md").write_text(
            get_logic_flaw_expert_instructions()
        )
        (root / ".claude" / "commands" / "info-disclosure-expert.md").write_text(
            get_info_disclosure_expert_instructions()
        )

        # Write settings.local.json with MCP tool permissions
        settings_local = {
            "permissions": {
                "allow": WPGUARD_CORE_TOOLS + WPGUARD_MCP_TOOLS + WPGUARD_SLASH_COMMANDS + WPGUARD_BASH_COMMANDS,
                "deny": [],
                "ask": [],
            }
        }
        (root / ".claude" / "settings.local.json").write_text(
            json.dumps(settings_local, indent=2)
        )

        # Initialize empty findings file (matches FindingsManager schema)
        initial_findings = {
            "version": "1.0",
            "updated_at": None,
            "total_findings": 0,
            "findings": [],
        }
        (root / FINDINGS_FILENAME).write_text(json.dumps(initial_findings, indent=2))

        # Download Wordfence vulnerability database (non-blocking, cached)
        wordfence_status = None
        try:
            from wpguard.api.wordfence import WorkfenceVulnDB
            wf_db = WorkfenceVulnDB()
            wordfence_status = wf_db.download()
        except Exception as e:
            wordfence_status = {"success": False, "error": str(e)}

        return {
            "success": True,
            "path": str(root),
            "message": f"Research project initialized at {root}",
            "wordfence_db": wordfence_status,
            "structure": {
                "claude_md": str(root / "CLAUDE.md"),
                "commands": [
                    "/target-research",
                    "/security-research",
                    "/file-rce-expert",
                    "/sqli-expert",
                    "/xss-expert",
                    "/auth-expert",
                    "/object-injection-expert",
                    "/ssrf-expert",
                    "/race-condition-expert",
                    "/csrf-expert",
                    "/lfi-rfi-expert",
                    "/xxe-expert",
                    "/deserialization-expert",
                    "/logic-flaw-expert",
                    "/info-disclosure-expert",
                    "/qa-triage",
                    "/poc-creator",
                ],
                "directories": [
                    "targets/",
                    "targets/{plugin_slug}/",
                    "reports/",
                    "reports/{plugin_slug}/",
                    ".claude/",
                    ".claude/commands/",
                ],
                "files": [
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
