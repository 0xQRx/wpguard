# wpguard — Development Guide

Agentic security research framework for WordPress plugins and themes. 60+ MCP tools, 20+ specialized agents, Docker sandbox.

## Quick Reference

```bash
# Install (development)
pipx install -e .

# Reinstall after changes
pipx install -e . --force

# Run MCP server standalone
wpguard-mcp

# Run CLI
wpguard --help
```

## Architecture

```
src/wpguard/
  __init__.py              # Version (__version__), public exports
  cli.py                   # Click CLI (wpguard command)
  config.py                # Constants, env vars, API endpoints
  mcp_server.py            # MCP server (wpguard-mcp) — all 60+ tool defs + handlers
  api/
    wordpress.py           # WordPress Plugin API client
    themes.py              # WordPress Theme API client
    wordfence.py           # Wordfence CVE database client
  core/
    audit_history.py       # Tracks audited plugins/themes (wpguard_audit_history.json)
    downloader.py          # PluginDownloader, SVNClient, SVNChangeInfo
    findings.py            # FindingsManager (wpguard_findings.json)
    init.py                # Project initializer — deploys agents, commands, CLAUDE.md
    models.py              # PluginInfo, ThemeInfo, ChangeReport, Finding dataclasses
    sandbox.py             # WordPressSandbox — Docker container management, WP-CLI
    scope_validator.py     # Wordfence bounty scope rules
    watcher.py             # PluginWatcher — watch, global monitor, new plugin detection
  notifications/
    discord.py             # Discord webhook notifications
  templates/
    CLAUDE.md              # Deployed to research projects (not this file)
    _expert-shared.md      # Shared partial included in all expert agents
    pm.md                  # PM orchestrator slash command
    watch.md               # /watch slash command
    surface-mapper.md      # Surface mapper agent
    bb-submission.md       # BB submission agent
    *.md                   # All other agent + command templates
    poc-video-recording-spec.md  # Video PoC reference spec
  wordpress_instance/
    Dockerfile             # PHP 8.5 WordPress sandbox image
    docker-compose.yaml    # WordPress + MySQL 9.6 stack
    custom-entrypoint.sh   # Sandbox init (users, settings, permalinks)
    php-custom.ini         # Permissive PHP config for PoC testing
  utils/
    helpers.py             # Utility functions
```

## Key Patterns

### Adding a new MCP tool

1. Add `Tool()` definition in `mcp_server.py` → `list_tools()`
2. Add `elif name == "wpguard_new_tool":` in `_execute_tool()`
3. Add `_new_tool_sync()` (blocking) and `async _new_tool()` (executor wrapper) functions
4. All blocking work goes in `_sync` function, wrapped via `run_in_executor()`

### Adding a new agent

1. Create `src/wpguard/templates/{agent-name}.md` with frontmatter (name, description, model, maxTurns)
2. Add to `EXPERT_AGENTS` or `SUPPORT_AGENTS` list in `core/init.py`
3. Add to expert table in `templates/pm.md` and `templates/CLAUDE.md`
4. If it uses shared patterns: `{{include:_expert-shared.md|validation_example=...}}`

### Adding a slash command

1. Create `src/wpguard/templates/{command}.md`
2. Add `"SlashCommand(/{command})"` to `WPGUARD_SLASH_COMMANDS` in `core/init.py`
3. Add file creation in `initialize_research_project()` in `core/init.py`
4. Add to commands list in return structure and `templates/CLAUDE.md`

### Template include system

Templates support `{{include:filename|key=value}}` for shared partials. Processed by `_process_includes()` in `core/init.py`. The `_expert-shared.md` partial is included in all expert agents.

## Versioning

Version is defined in `src/wpguard/__init__.py` as `__version__`. `pyproject.toml` reads it dynamically. When releasing:

1. Update `__version__` in `src/wpguard/__init__.py`
2. Commit
3. Tag: `git tag v{version}`
4. Push: `git push && git push --tags`

## Conventions

- **MCP tool names**: `wpguard_{category}_{action}` (e.g., `wpguard_theme_download`)
- **Agent templates**: frontmatter with `name`, `description`, `model`, `maxTurns`
- **State files**: JSON in project root, preserved across `wpguard_init_research` re-runs
- **Sandbox WP-CLI**: runs as `www-data` user (not root) to maintain correct file ownership
- **SVNClient**: accepts `svn_base` param — defaults to plugins SVN, pass `WP_THEMES_SVN` for themes
- **Docker Compose**: auto-detects V2 plugin (`docker compose`) vs V1 standalone (`docker-compose`)

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `WORDFENCE_API_KEY` | For CVE tools | Wordfence Intelligence API |
| `WPGUARD_RAG_DOCS` | For devrag | Path to web pentesting knowledge base |
| `DISCORD_WEBHOOK_URL` | For notifications | Discord webhook |
| `WP_SANDBOX_HOST` | No (default: 172.17.0.1) | Sandbox Docker host |
| `WP_SANDBOX_PORT` | No (default: 8000) | Sandbox port |
| `WPGUARD_SANDBOX_DIR` | No | Custom sandbox compose directory |

## Testing Changes

After modifying templates or MCP tools:

```bash
# Reinstall
pipx install -e . --force

# Verify MCP server loads
python -c "from wpguard.mcp_server import server; print('OK')"

# Verify templates resolve (includes work)
python -c "from wpguard.core.init import _load_template; _load_template('sqli-expert.md'); print('OK')"

# Verify sandbox
docker exec --user www-data wp_app wp core version
```
