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
    "SlashCommand(/pm)",
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

# Agent definitions: (template_name, agent_dir_name)
EXPERT_AGENTS = [
    "file-rce-expert",
    "sqli-expert",
    "xss-expert",
    "auth-expert",
    "object-injection-expert",
    "ssrf-expert",
    "race-condition-expert",
    "csrf-expert",
    "lfi-rfi-expert",
    "xxe-expert",
    "deserialization-expert",
    "logic-flaw-expert",
    "info-disclosure-expert",
]

SUPPORT_AGENTS = [
    "qa-triage",
    "poc-creator",
    "poc-writer",
    "poc-runner",
    "sandbox-admin",
]

ALL_AGENTS = EXPERT_AGENTS + SUPPORT_AGENTS


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


def get_pm_instructions() -> str:
    """Get PM/orchestrator slash command instructions."""
    return _load_template("pm.md")


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

        # Create agent directories and write agent definitions
        for agent_name in ALL_AGENTS:
            agent_dir = root / ".claude" / "agents" / agent_name
            agent_dir.mkdir(parents=True, exist_ok=True)
            agent_content = _load_template(f"{agent_name}.md")
            (agent_dir / "agent.md").write_text(agent_content)

        # Write main CLAUDE.md
        (root / "CLAUDE.md").write_text(get_main_claude_md())

        # Write PM plan template to project root
        (root / "pm-plan.md").write_text(_load_template("pm-plan.md"))

        # Write slash commands (only pm and target-research)
        (root / ".claude" / "commands" / "target-research.md").write_text(
            get_target_researcher_instructions()
        )
        (root / ".claude" / "commands" / "pm.md").write_text(
            get_pm_instructions()
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

        # Write per-project devrag config
        devrag_config = {
            "document_patterns": [
                "/home/groot/Desktop/Projects/PentestResources/WebPentestRAG",
                str(root / "specs"),
                str(root / "reports"),
            ],
            "db_path": str(root / ".devrag" / "vectors.db"),
            "chunk_size": 500,
            "search_top_k": 5,
            "update_check": True,
            "compute": {
                "device": "auto",
                "fallback_to_cpu": True,
            },
            "model": {
                "name": "multilingual-e5-small",
                "dimensions": 384,
            },
        }
        devrag_dir = root / ".devrag"
        devrag_dir.mkdir(exist_ok=True)
        (devrag_dir / "config.json").write_text(json.dumps(devrag_config, indent=2))

        # Write .mcp.json with all MCP servers
        mcp_config = {
            "mcpServers": {
                "playwright": {
                    "command": "npx",
                    "args": ["@playwright/mcp@latest"],
                },
                "wpguard": {
                    "type": "stdio",
                    "command": "wpguard-mcp",
                    "args": [],
                },
                "devrag": {
                    "type": "stdio",
                    "command": "/home/groot/Desktop/Tools/devrag/bin/devrag",
                    "args": ["--config", str(devrag_dir / "config.json")],
                },
            }
        }
        (root / ".mcp.json").write_text(json.dumps(mcp_config, indent=2))

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
                    "/pm",
                    "/target-research",
                ],
                "agents": [f"{name}" for name in ALL_AGENTS],
                "directories": [
                    "targets/",
                    "targets/{plugin_slug}/",
                    "reports/",
                    "reports/{plugin_slug}/",
                    ".claude/",
                    ".claude/commands/",
                    ".claude/agents/",
                ],
                "files": [
                    FINDINGS_FILENAME,
                    ".claude/settings.local.json",
                    ".mcp.json",
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
