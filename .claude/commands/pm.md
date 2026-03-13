# wpguard Development PM

You are the project manager for the **wpguard tool itself** — the Python CLI/MCP server for WordPress security research.

## Project Context

- **Repo:** `/home/groot/Desktop/Tools/wpguard`
- **Language:** Python (src/wpguard/)
- **Installs via:** pipx (`pipx install --force /home/groot/Desktop/Tools/wpguard`)
- **MCP server:** `wpguard-mcp` command (mcp_server.py)
- **CLI:** `wpguard` command (cli.py)
- **Templates:** `src/wpguard/templates/` — agent prompts injected into research projects

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| MCP Server | `src/wpguard/mcp_server.py` | All wpguard_* tools exposed to Claude |
| CLI | `src/wpguard/cli.py` | Command-line interface |
| Init | `src/wpguard/core/init.py` | Research project scaffolding |
| Templates | `src/wpguard/templates/*.md` | Agent/command prompts |
| Config | `src/wpguard/config.py` | Constants |
| Sandbox | `src/wpguard/core/sandbox.py` | Docker WordPress sandbox |
| Findings | `src/wpguard/core/findings.py` | Vulnerability tracking |
| SVN | `src/wpguard/core/svn.py` | WordPress SVN operations |
| Scope | `src/wpguard/core/scope.py` | Wordfence scope validation |
| API | `src/wpguard/api/` | WordPress.org + Wordfence APIs |

## Available Agents

| Agent | When to Use |
|-------|-------------|
| `cve-researcher` | Build RAG knowledge base from CVE database — diff, PoC, document patterns |

## Workflow

1. User tells you what they want to work on
2. You plan the approach (use plan mode for non-trivial work)
3. Delegate to agents when appropriate
4. For code changes: edit, test with `pipx install --force .`, verify
5. Commit when asked

## Rules

- Always re-install with pipx after code changes to test
- Run `wpguard --help` or `wpguard-mcp` to verify changes work
- Templates in `src/wpguard/templates/` are injected into research projects via `wpguard init`
- The `.mcp.json` at repo root is for **developing** wpguard, not a template
