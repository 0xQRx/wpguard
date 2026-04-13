"""
Initialize research project directories with agent instructions.

Templates are loaded from the templates/ directory for easy modification.
"""

import json
import os
import re
import shutil
from pathlib import Path

from wpguard.core.audit_history import AUDIT_HISTORY_FILENAME
from wpguard.core.findings import FINDINGS_FILENAME


# Template directory relative to this file
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# MCP tool permissions — wildcard per server
MCP_TOOLS = [
    "mcp__wpguard__*",
    "mcp__playwright__*",
    "mcp__plugin_claude-mem_mcp-search__*",
    "mcp__devrag__*",
    "mcp__veloria__*",
]

# Slash commands for agent workflows
WPGUARD_SLASH_COMMANDS = [
    "SlashCommand(/target-research)",
    "SlashCommand(/pm)",
    "SlashCommand(/status)",
    "SlashCommand(/recon)",
    "SlashCommand(/findings)",
    "SlashCommand(/nday)",
    "SlashCommand(/watch)",
    "SlashCommand(/diff)",
    "SlashCommand(/patrol)",
]


# Core Claude tools needed for autonomous operation
WPGUARD_CORE_TOOLS = [
    "Bash",
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "Agent",
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
    "missing-auth-expert",
    "idor-expert",
    "priv-esc-expert",
    "object-injection-expert",
    "ssrf-expert",
    "race-condition-expert",
    "csrf-expert",
    "critical-thinker",
    "data-flow-expert",
    "lfi-rfi-expert",
    "xxe-expert",
    "deserialization-expert",
    "logic-flaw-expert",
    "info-disclosure-expert",
    "code-injection-expert",
    "open-redirect-expert",
]

SUPPORT_AGENTS = [
    "qa-triage",
    "poc-creator",
    "poc-writer",
    "poc-runner",
    "poc-recorder",
    "sandbox-admin",
    "surface-mapper",
    "impact-assessor",
    "vuln-escalator",
    "bb-submission",
]

ALL_AGENTS = EXPERT_AGENTS + SUPPORT_AGENTS


def _process_includes(content: str) -> str:
    """Replace {{include:filename|key=value,...}} with file contents and variable substitution."""

    def replace_include(match: re.Match) -> str:
        parts = match.group(1).split("|", 1)
        include_name = parts[0].strip()

        variables: dict[str, str] = {}
        if len(parts) > 1:
            for pair in parts[1].split("|"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    variables[k.strip()] = v.strip()

        include_path = TEMPLATES_DIR / include_name
        if not include_path.exists():
            raise FileNotFoundError(f"Include template not found: {include_path}")

        included = include_path.read_text()
        for k, v in variables.items():
            included = included.replace("{{" + k + "}}", v)
        return included

    return re.sub(r"\{\{include:([^}]+)\}\}", replace_include, content)


def _load_template(name: str) -> str:
    """
    Load a template file from the templates directory.

    Supports {{include:filename|key=value}} directives for shared partials.

    Args:
        name: Template filename (e.g., 'CLAUDE.md', 'target-research.md')

    Returns:
        Template content as string (with includes resolved)

    Raises:
        FileNotFoundError: If template doesn't exist
    """
    template_path = TEMPLATES_DIR / name
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    content = template_path.read_text()
    return _process_includes(content)


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


def get_missing_auth_expert_instructions() -> str:
    """Get missing authorization expert agent instructions."""
    return _load_template("missing-auth-expert.md")


def get_idor_expert_instructions() -> str:
    """Get IDOR expert agent instructions."""
    return _load_template("idor-expert.md")


def get_priv_esc_expert_instructions() -> str:
    """Get privilege escalation expert agent instructions."""
    return _load_template("priv-esc-expert.md")


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


def get_critical_thinker_instructions() -> str:
    """Get critical thinker cross-domain chain builder agent instructions."""
    return _load_template("critical-thinker.md")


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


def get_code_injection_expert_instructions() -> str:
    """Get code injection expert agent instructions."""
    return _load_template("code-injection-expert.md")


def get_open_redirect_expert_instructions() -> str:
    """Get open redirect expert agent instructions."""
    return _load_template("open-redirect-expert.md")


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
        # Detect if this is a fresh init or update of existing project
        is_update = (root / FINDINGS_FILENAME).exists() or (root / "CLAUDE.md").exists()

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

        # Copy PoC templates
        poc_templates_src = TEMPLATES_DIR / "poc-templates"
        if poc_templates_src.exists():
            poc_templates_dst = root / "poc-templates"
            poc_templates_dst.mkdir(exist_ok=True)
            for template_file in poc_templates_src.glob("*.py"):
                shutil.copy2(template_file, poc_templates_dst / template_file.name)

        # Write slash commands
        (root / ".claude" / "commands" / "target-research.md").write_text(
            get_target_researcher_instructions()
        )
        (root / ".claude" / "commands" / "pm.md").write_text(
            get_pm_instructions()
        )
        (root / ".claude" / "commands" / "status.md").write_text(
            _load_template("status.md")
        )
        (root / ".claude" / "commands" / "recon.md").write_text(
            _load_template("recon.md")
        )
        (root / ".claude" / "commands" / "findings.md").write_text(
            _load_template("findings.md")
        )
        (root / ".claude" / "commands" / "nday.md").write_text(
            _load_template("nday.md")
        )
        (root / ".claude" / "commands" / "watch.md").write_text(
            _load_template("watch.md")
        )
        (root / ".claude" / "commands" / "diff.md").write_text(
            _load_template("diff.md")
        )
        (root / ".claude" / "commands" / "patrol.md").write_text(
            _load_template("patrol.md")
        )

        # Write settings.local.json with MCP tool permissions
        settings_local = {
            "permissions": {
                "allow": WPGUARD_CORE_TOOLS + MCP_TOOLS + WPGUARD_SLASH_COMMANDS,
                "deny": [],
                "ask": [],
            }
        }
        (root / ".claude" / "settings.local.json").write_text(
            json.dumps(settings_local, indent=2)
        )

        # Initialize empty findings file only if it doesn't exist
        # (preserve existing findings on re-init / update)
        findings_path = root / FINDINGS_FILENAME
        if not findings_path.exists():
            initial_findings = {
                "version": "1.0",
                "updated_at": None,
                "total_findings": 0,
                "findings": [],
            }
            findings_path.write_text(json.dumps(initial_findings, indent=2))

        # Initialize empty audit history only if it doesn't exist
        # (preserve existing history on re-init / update)
        audit_history_path = root / AUDIT_HISTORY_FILENAME
        if not audit_history_path.exists():
            audit_history_path.write_text(json.dumps({
                "version": "1.0",
                "audits": {},
            }, indent=2))

        # Write per-project devrag config
        rag_docs_dir = os.environ.get("WPGUARD_RAG_DOCS")
        doc_patterns = [
            str(root / "reports"),
        ]
        if rag_docs_dir and Path(rag_docs_dir).exists():
            doc_patterns.insert(0, rag_docs_dir)

        devrag_config = {
            "document_patterns": doc_patterns,
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
        devrag_bin = shutil.which("devrag") or "devrag"
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
                    "command": devrag_bin,
                    "args": ["--config", str(devrag_dir / "config.json")],
                },
                "veloria": {
                    "type": "http",
                    "url": "https://veloria.dev/mcp",
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

        action = "updated" if is_update else "initialized"

        return {
            "success": True,
            "path": str(root),
            "is_update": is_update,
            "message": f"Research project {action} at {root}",
            "wordfence_db": wordfence_status,
            "structure": {
                "claude_md": str(root / "CLAUDE.md"),
                "commands": [
                    "/pm",
                    "/target-research",
                    "/status",
                    "/recon",
                    "/findings",
                    "/nday",
                    "/watch",
                    "/diff",
                    "/patrol",
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
