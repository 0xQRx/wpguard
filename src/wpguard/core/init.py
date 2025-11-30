"""
Initialize research project directories with agent instructions.

Templates are loaded from the templates/ directory for easy modification.
"""

import json
from pathlib import Path

from wpguard.core.findings import FINDINGS_FILENAME, SCAN_STATE_FILENAME


# Template directory relative to this file
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


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
                    ".claude/commands/",
                ],
                "files": [SCAN_STATE_FILENAME, FINDINGS_FILENAME],
            },
        }

    except OSError as e:
        return {
            "success": False,
            "path": str(root),
            "message": f"Failed to initialize project: {e}",
            "error": str(e),
        }
