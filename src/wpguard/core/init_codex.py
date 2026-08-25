"""
Codex CLI compatibility layer.

Translates the Claude Code project layout produced by ``core.init`` into the
equivalent OpenAI Codex CLI layout, from the same markdown templates:

    CLAUDE.md                  -> AGENTS.md              (+ Codex usage preamble)
    .claude/agents/<a>/agent.md-> .codex/agents/<a>.toml (name/description/
                                                          developer_instructions)
    .claude/commands/<c>.md    -> .agents/skills/<c>/SKILL.md (+ references/)
    .mcp.json                  -> .codex/config.toml     ([mcp_servers.*])
    .claude/settings.local.json-> .codex/config.toml     (approval/sandbox)

Nothing here is a second source of truth: every artifact is derived from the
templates in ``wpguard/templates/``.
"""

import os
import re
from pathlib import Path


# Where Codex looks for things
CODEX_DIR = ".codex"
CODEX_AGENTS_DIR = f"{CODEX_DIR}/agents"
CODEX_SKILLS_DIR = ".agents/skills"  # $REPO_ROOT/.agents/skills

# Codex loads the skill *list* into every session (budgeted to ~2% of context /
# 8000 chars), so a SKILL.md body larger than this is moved to references/ and
# pulled in on demand.
SKILL_INLINE_LIMIT = 3500

# Codex merges AGENTS.md files from git root down to cwd and caps the result
# (project_doc_max_bytes, 32 KiB default). Warn before we silently blow it.
AGENTS_MD_MAX_BYTES = 32 * 1024

# Claude model tiers -> Codex reasoning effort.
#
# Deliberately no default model id: Codex model names move fast and a wrong id
# breaks every agent, so we only set `model_reasoning_effort` (stable, and the
# part that actually matters for these agents) and let the model come from
# config.toml / the parent agent. Override per tier with
# WPGUARD_CODEX_MODEL_OPUS / WPGUARD_CODEX_MODEL_SONNET / _HAIKU if you want a
# pinned model in the generated TOML.
REASONING_EFFORT = {
    "opus": "high",
    "sonnet": "medium",
    "haiku": "low",
}
DEFAULT_EFFORT = "high"

# Environment variables the wpguard MCP server needs forwarded from the shell.
WPGUARD_ENV_VARS = [
    "WORDFENCE_API_KEY",
    "WPGUARD_RAG_DOCS",
    "DISCORD_WEBHOOK_URL",
    "WP_SANDBOX_HOST",
    "WP_SANDBOX_PORT",
    "WPGUARD_SANDBOX_DIR",
]

# Slash commands have no frontmatter, so their skill descriptions live here.
# The description is what Codex matches a user request against.
COMMAND_DESCRIPTIONS = {
    "pm": (
        "PM orchestrator for WordPress plugin/theme security research. Use for any "
        "audit request — plans the audit, delegates to expert agents, drives the "
        "verification pipeline end to end."
    ),
    "target-research": (
        "Find and scope WordPress plugins/themes worth auditing — install counts, "
        "CVE history, Wordfence bounty scope."
    ),
    "status": "Dashboard of current audit progress across targets and findings.",
    "recon": (
        "Lightweight assessment of a single plugin before a full audit — installs, "
        "CVE history, scope check, attack surface summary."
    ),
    "findings": "List all recorded findings with status, severity and verification state.",
    "nday": "N-day research — build PoCs for known/patched WordPress CVEs.",
    "watch": "Plugin update monitor — global ecosystem scan plus watchlist changes.",
    "diff": "Security-focused diff of a plugin/theme between two versions or SVN revisions.",
    "patrol": (
        "Watchdog pass for cron loops — checks audit progress, re-triggers stalled "
        "work, picks the next target."
    ),
}

# Slash commands become skills on Codex: `/pm` -> `$pm`. Anchored so it can only
# fire on a bare command reference — a preceding word char, slash, dot or dash
# (i.e. a path like `reports/status` or a URL) blocks the match, as does a
# trailing word char, slash or dash.
_COMMAND_SYNTAX_RE = re.compile(
    r"(?<![\w/.\-])/(" + "|".join(sorted(COMMAND_DESCRIPTIONS, key=len, reverse=True)) + r")(?![\w/\-])"
)


# `/loop` is a Claude Code built-in with no Codex counterpart, so it cannot be
# rewritten the way a wpguard command can. Anything that mentions it gets this
# appended instead, so a Codex reader is not left with a command that does not
# exist.
CODEX_SCHEDULING_NOTE = """

## Scheduling on Codex

Codex has no `/loop`. Drive the same thing from your own scheduler (cron, a
systemd timer) using non-interactive mode:

```
0 */6 * * *  cd /path/to/project && codex exec --approve-for-me "$watch core"
```

`codex exec` takes a prompt, runs it, and exits — add `--json` for a parseable
event stream. `--approve-for-me` is required: plain `codex exec` runs with
`approval: never`, and every MCP tool call then fails with "requires approval,
but approval policy is never".
"""


def to_codex_syntax(text: str) -> str:
    """
    Rewrite Claude slash-command references as Codex skill mentions, and
    append a scheduling note wherever `/loop` is referenced.
    """
    rewritten = _COMMAND_SYNTAX_RE.sub(r"$\1", text)
    if "/loop" in rewritten:
        rewritten = rewritten.rstrip() + "\n" + CODEX_SCHEDULING_NOTE
    return rewritten


CODEX_PREAMBLE = """# Codex usage

This project was generated for both Claude Code and Codex. On Codex:

- **Skills replace slash commands.** Workflows are written below as `$pm`,
  `$recon`, `$diff`, `$watch`, `$status`, `$findings`, `$nday`, `$patrol`,
  `$target-research`. Run `/skills` to list them, or mention one by name.
- **Agents are Codex subagents.** They live in `.codex/agents/*.toml`. Spawn one
  by name in a prompt ("spawn the sqli-expert agent to review ..."); use
  `/agent` to inspect and switch between running agent threads.
- **MCP tools** come from `.codex/config.toml`. The `wpguard` server exposes
  every `wpguard_*` tool referenced below.
- **Sandbox.** Auditing needs network access (wordpress.org, Wordfence, SVN) and
  Docker control of the `wp_app` container. `.codex/config.toml` sets
  `sandbox_mode = "workspace-write"` with `network_access = true`. MCP tool
  calls still need an approval route: `codex exec` sets `approval: never`, which
  blocks them outright, so unattended runs need `--approve-for-me` (auto-review
  under the workspace-write sandbox). `--dangerously-bypass-approvals-and-sandbox`
  also works but gives up the sandbox entirely.

Project-scoped `.codex/config.toml` is only read for trusted projects — run
`codex` once in this directory and trust it, or copy the `[mcp_servers.*]`
tables into `~/.codex/config.toml`.

---

"""


# --------------------------------------------------------------------------
# Frontmatter + TOML helpers
# --------------------------------------------------------------------------

_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n?", re.DOTALL)


def parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    """
    Split a template into (frontmatter dict, body).

    Agent templates use a flat ``key: value`` frontmatter — no nesting, no
    lists — so this deliberately avoids a YAML dependency. Templates without
    frontmatter return ``({}, content)``.
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}, content

    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        meta[key.strip()] = value

    return meta, content[match.end():]


def _toml_basic_string(value: str) -> str:
    """Single-line TOML basic string."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def toml_multiline_string(value: str) -> str:
    """
    TOML multi-line string for a markdown body.

    Prefers a literal string (''' ... ''') so markdown backslashes and quotes
    survive untouched. Falls back to an escaped basic string when the body
    contains ``'''`` — which would otherwise terminate the literal early and
    produce a corrupt agent definition.
    """
    body = value if value.endswith("\n") else value + "\n"

    if "'''" not in body:
        # A leading newline directly after the opening delimiter is trimmed by
        # TOML, so this round-trips exactly.
        return "'''\n" + body + "'''"

    escaped = body.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return '"""\n' + escaped + '"""'


# --------------------------------------------------------------------------
# Agents:  .claude/agents/<name>/agent.md  ->  .codex/agents/<name>.toml
# --------------------------------------------------------------------------


def build_agent_toml(agent_name: str, content: str) -> str:
    """
    Render one expert/support agent template as a Codex custom-agent TOML.

    Required Codex fields: name, description, developer_instructions.
    Optional: model, model_reasoning_effort.

    ``maxTurns`` and ``memory`` have no Codex equivalent; ``maxTurns`` is
    carried into the instructions as an explicit budget rather than dropped,
    since it is the only thing bounding a runaway expert.
    """
    meta, body = parse_frontmatter(content)

    name = meta.get("name", agent_name)
    description = meta.get("description", f"{agent_name} agent")
    tier = meta.get("model", "opus").strip().lower()

    max_turns = meta.get("maxTurns", "").strip()
    if max_turns:
        body = (
            body.rstrip()
            + "\n\n## Turn budget\n\n"
            + f"Work within roughly {max_turns} tool-using turns. When you approach "
            + "that budget, stop exploring, call `wpguard_agent_checkpoint("
            + "action='partial')`, and report what you have.\n"
        )

    lines = [
        f"# Generated by wpguard from templates/{agent_name}.md — do not edit by hand.",
        f"name = {_toml_basic_string(name)}",
        f"description = {_toml_basic_string(description)}",
    ]

    model = os.environ.get(f"WPGUARD_CODEX_MODEL_{tier.upper()}")
    if model:
        lines.append(f"model = {_toml_basic_string(model)}")

    effort = REASONING_EFFORT.get(tier, DEFAULT_EFFORT)
    lines.append(f"model_reasoning_effort = {_toml_basic_string(effort)}")
    lines.append("")
    lines.append(
        f"developer_instructions = {toml_multiline_string(to_codex_syntax(body.lstrip()))}"
    )

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Commands:  .claude/commands/<cmd>.md  ->  .agents/skills/<cmd>/SKILL.md
# --------------------------------------------------------------------------


def _yaml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _first_paragraph(body: str) -> str:
    """First non-heading, non-empty paragraph of a markdown body."""
    for block in re.split(r"\n\s*\n", body.strip()):
        block = block.strip()
        if block and not block.startswith(("#", "---", "|", "```")):
            return " ".join(block.split())
    return ""


def build_skill(command_name: str, content: str) -> dict[str, str]:
    """
    Render a slash-command template as a Codex skill.

    Returns a ``{relative_path: file_content}`` map rooted at the skill
    directory. Bodies over ``SKILL_INLINE_LIMIT`` are split: SKILL.md keeps the
    frontmatter and a pointer, the full procedure moves to
    ``references/instructions.md``.
    """
    _, body = parse_frontmatter(content)
    body = to_codex_syntax(body.strip())

    description = COMMAND_DESCRIPTIONS.get(
        command_name, _first_paragraph(body) or f"{command_name} workflow"
    )

    frontmatter = (
        "---\n"
        f"name: {command_name}\n"
        f"description: {_yaml_quote(description)}\n"
        "---\n\n"
    )

    openai_yaml = (
        f"display_name: {_yaml_quote(command_name)}\n"
        "allow_implicit_invocation: true\n"
    )

    if len(body) <= SKILL_INLINE_LIMIT:
        return {
            "SKILL.md": frontmatter + body + "\n",
            "agents/openai.yaml": openai_yaml,
        }

    summary = _first_paragraph(body)
    skill_md = (
        frontmatter
        + f"# {command_name}\n\n"
        + (summary + "\n\n" if summary else "")
        + "This workflow is long and order-sensitive. Read "
        + "`references/instructions.md` in full **before** taking any action, "
        + "then follow it exactly — do not summarize, reorder, or skip steps.\n"
    )

    return {
        "SKILL.md": skill_md,
        "references/instructions.md": body + "\n",
        "agents/openai.yaml": openai_yaml,
    }


# --------------------------------------------------------------------------
# .mcp.json -> .codex/config.toml
# --------------------------------------------------------------------------


def _toml_array(values: list[str]) -> str:
    return "[" + ", ".join(_toml_basic_string(v) for v in values) + "]"


def build_codex_config(mcp_servers: dict[str, dict]) -> str:
    """
    Render ``.codex/config.toml``: MCP servers plus the sandbox/approval preset
    an audit actually needs (network on, workspace write).
    """
    lines = [
        "# Generated by wpguard — project-scoped Codex configuration.",
        "# Only read for trusted projects: run `codex` here once and trust the",
        "# directory, or copy the [mcp_servers.*] tables into ~/.codex/config.toml.",
        "",
        "# Auditing needs outbound network (wordpress.org, Wordfence, SVN) and",
        "# Docker control of the wp_app sandbox container.",
        'approval_policy = "on-request"',
        'sandbox_mode = "workspace-write"',
        "",
        "[sandbox_workspace_write]",
        "network_access = true",
        "",
    ]

    for name, server in mcp_servers.items():
        lines.append(f"[mcp_servers.{name}]")

        if server.get("type") == "http" or "url" in server:
            lines.append(f"url = {_toml_basic_string(server['url'])}")
            # Auth is server-specific; add `auth = "oauth"` and run
            # `codex mcp login <name>` if the endpoint requires it.
        else:
            lines.append(f"command = {_toml_basic_string(server['command'])}")
            if server.get("args"):
                lines.append(f"args = {_toml_array(server['args'])}")
            # Without this every wpguard_* call prompts individually — 60+ tools
            # across a full audit makes that unusable.
            lines.append('default_tools_approval_mode = "auto"')
            if name == "wpguard":
                # env_vars forwards from the parent environment; env would set
                # literal values, which is wrong for secrets like the
                # Wordfence API key.
                lines.append(f"env_vars = {_toml_array(WPGUARD_ENV_VARS)}")

        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Deployment
# --------------------------------------------------------------------------


def build_agents_md(claude_md: str) -> str:
    """AGENTS.md = the shared project doc, in Codex syntax, with a preamble."""
    return CODEX_PREAMBLE + to_codex_syntax(claude_md)


def deploy_codex(
    root: Path,
    load_template,
    claude_md: str,
    agents: list[str],
    commands: list[str],
    mcp_servers: dict[str, dict],
) -> dict:
    """
    Write the full Codex layout under ``root``.

    Args:
        root: project directory (already created)
        load_template: callable(name) -> template text, with includes resolved
        claude_md: rendered shared project doc
        agents: agent template stems (no .md)
        commands: slash-command template stems (no .md)
        mcp_servers: the same dict written to .mcp.json

    Returns:
        dict describing what was written, plus any non-fatal warnings.
    """
    warnings: list[str] = []

    # AGENTS.md
    agents_md = build_agents_md(claude_md)
    size = len(agents_md.encode("utf-8"))
    if size > AGENTS_MD_MAX_BYTES:
        warnings.append(
            f"AGENTS.md is {size} bytes, over Codex's {AGENTS_MD_MAX_BYTES}-byte "
            "project_doc_max_bytes default — it will be truncated."
        )
    (root / "AGENTS.md").write_text(agents_md)

    # Agents
    agents_dir = root / CODEX_AGENTS_DIR
    agents_dir.mkdir(parents=True, exist_ok=True)
    for agent_name in agents:
        content = load_template(f"{agent_name}.md")
        (agents_dir / f"{agent_name}.toml").write_text(
            build_agent_toml(agent_name, content)
        )

    # Skills
    skills_root = root / CODEX_SKILLS_DIR
    skills_root.mkdir(parents=True, exist_ok=True)
    split_skills: list[str] = []
    for command_name in commands:
        content = load_template(f"{command_name}.md")
        files = build_skill(command_name, content)
        if "references/instructions.md" in files:
            split_skills.append(command_name)
        for rel_path, text in files.items():
            dest = skills_root / command_name / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text)

    # config.toml
    codex_dir = root / CODEX_DIR
    codex_dir.mkdir(parents=True, exist_ok=True)
    (codex_dir / "config.toml").write_text(build_codex_config(mcp_servers))

    return {
        "agents_md": str(root / "AGENTS.md"),
        "agents_dir": str(agents_dir),
        "skills_dir": str(skills_root),
        "config": str(codex_dir / "config.toml"),
        "agent_count": len(agents),
        "skill_count": len(commands),
        "split_skills": split_skills,
        "warnings": warnings,
    }
