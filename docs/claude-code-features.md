# Claude Code Feature Guide — Complete Reference

## Slash Commands vs Skills vs Agents

These three are **different layers** that work together:

| | Slash Commands | Skills | Agents |
|---|---|---|---|
| **What** | Quick actions you type with `/` | Reusable instruction sets | Isolated AI workers |
| **Where** | Built-in + `.claude/commands/*.md` | `.claude/skills/*/SKILL.md` | `.claude/agents/*/agent.md` |
| **Who runs it** | You type `/name` | You type `/name` OR Claude auto-invokes | Claude delegates when task matches |
| **Context** | Runs in main conversation | Can fork to isolated context | Always isolated context |
| **Can write code** | Yes (expands to prompt) | Yes | Yes |
| **Persistent memory** | No | No | Yes (optional) |

---

## 1. Slash Commands

### Built-in Commands

`/help`, `/compact`, `/init`, `/memory`, `/hooks`, `/agents`, `/mcp`, `/status`, `/cost`, `/btw`, `/vim`, `/debug`, `/simplify`, `/batch`, `/loop`, `/claude-api`, `/clear`, `/checkpoint`, `/rewind`

### Custom Commands

Create `.claude/commands/my-command.md`:

```markdown
# My Command

$ARGUMENTS

Instructions for Claude...
```

Invoke with `/my-command some arguments`. `$ARGUMENTS` gets replaced with everything after the command name.

### Argument Substitution

| Variable | Expands to |
|----------|-----------|
| `$ARGUMENTS` | All passed arguments |
| `$0`, `$1`, `$2` | Individual arguments (0-indexed) |

---

## 2. Skills (Evolved Commands)

Skills live in `.claude/skills/*/SKILL.md` and have **frontmatter superpowers** that plain commands lack.

### Frontmatter Fields

```markdown
---
name: my-skill
description: When Claude should auto-invoke this
user-invocable: true
disable-model-invocation: false
allowed-tools: Read, Grep, Glob
model: sonnet
context: fork
agent: Explore
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "./validate.sh"
---
```

| Field | Default | Purpose |
|-------|---------|---------|
| `name` | Directory name | Slash command name |
| `description` | First paragraph | When Claude should auto-invoke |
| `disable-model-invocation` | `false` | Prevent Claude from auto-triggering |
| `user-invocable` | `true` | Show in `/` menu |
| `allowed-tools` | All | Restrict tool access |
| `model` | Inherit | Run on specific model (`sonnet`, `haiku`, `opus`) |
| `context` | Inline | `fork` = run in isolated subagent context |
| `agent` | general-purpose | Subagent type when forked |
| `hooks` | None | Lifecycle hooks scoped to skill |

### Dynamic Context Injection

Shell commands execute BEFORE the skill runs:

```markdown
Current diff: !`git diff --cached`
Open issues: !`gh issue list --limit 5`
```

### Skill Location Hierarchy

| Scope | Path | Shared? |
|-------|------|---------|
| Enterprise | System directory | Yes (IT-deployed) |
| Personal | `~/.claude/skills/<name>/SKILL.md` | No |
| Project | `.claude/skills/<name>/SKILL.md` | Yes (git) |
| Plugin | Plugin's `skills/` directory | Yes |

### Supporting Files

```text
my-skill/
├── SKILL.md           (required)
├── reference.md       (detailed docs)
├── examples.md        (usage examples)
└── scripts/
    └── validate.sh    (utility script)
```

---

## 3. Custom Agents (Persistent Workers)

Agents live in `.claude/agents/*/agent.md` and have isolated context, optional persistent memory, and can run in background.

### Agent Definition

```markdown
---
name: code-reviewer
description: Reviews code proactively after changes
tools: Read, Grep, Glob, Bash
model: sonnet
memory: project
isolation: worktree
maxTurns: 20
background: true
permissionMode: plan
skills:
  - api-conventions
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "./validate.sh"
---

You are a senior code reviewer...
```

### Agent Frontmatter Fields

| Field | Purpose |
|-------|---------|
| `name` | Unique identifier |
| `description` | When Claude should delegate to this agent |
| `tools` | Allowed tools (default: inherit all) |
| `disallowedTools` | Tools to deny |
| `model` | Model to use |
| `permissionMode` | `default`, `acceptEdits`, `plan`, etc. |
| `maxTurns` | Max agentic turns before stopping |
| `skills` | Skills to preload (full content injected) |
| `mcpServers` | MCP servers available to agent |
| `hooks` | Lifecycle hooks scoped to agent |
| `memory` | `user`, `project`, or `local` |
| `background` | Always run as background task |
| `isolation` | `worktree` for isolated git worktree |

### Agent Memory Scopes

| Scope | Path | Shared? |
|-------|------|---------|
| `user` | `~/.claude/agent-memory/<name>/` | No (all projects) |
| `project` | `.claude/agent-memory/<name>/` | Yes (git) |
| `local` | `.claude/agent-memory-local/<name>/` | No (this project) |

Agents with memory maintain their own `MEMORY.md` and learn across sessions.

### Agent Locations

| Location | Scope |
|----------|-------|
| `.claude/agents/` | Current project |
| `~/.claude/agents/` | All projects (personal) |
| Plugin's `agents/` | Where plugin is enabled |

### Built-in Agent Types

| Type | Model | Tools | Purpose |
|------|-------|-------|---------|
| `Explore` | Haiku | Read-only | Fast codebase exploration |
| `Plan` | Inherit | Read-only | Research in plan mode |
| `general-purpose` | Inherit | All | Complex multi-step tasks |
| `claude-code-guide` | Haiku | All | Claude Code documentation |
| `statusline-setup` | Sonnet | All | Status line configuration |

---

## 4. Hooks — Deterministic Automation

Hooks are shell commands, HTTP calls, or LLM prompts that fire at lifecycle points. Configure in settings files.

### Hook Events

| Event | When | Use Case |
|-------|------|----------|
| `SessionStart` | Session begins/resumes | Inject context, set env vars |
| `UserPromptSubmit` | User sends prompt | Validate input, inject context |
| `PreToolUse` | Before tool executes | Block dangerous commands |
| `PostToolUse` | After tool succeeds | Auto-format, run linters |
| `PostToolUseFailure` | After tool fails | Log errors, cleanup |
| `PermissionRequest` | Permission dialog | Auto-approve/deny |
| `Notification` | Claude needs input | Desktop notifications |
| `Stop` | Claude finishes response | Verify task completion |
| `PreCompact` | Before context compression | Re-inject critical info |
| `SubagentStart/Stop` | Agent lifecycle | Setup/cleanup |
| `ConfigChange` | Config changes | Audit trail |
| `SessionEnd` | Session closes | Cleanup, logging |

### Hook Configuration

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "npx prettier --write $(jq -r '.tool_input.file_path')"
          }
        ]
      }
    ]
  }
}
```

### Hook Types

| Type | Description |
|------|-------------|
| `command` | Shell command (receives JSON on stdin) |
| `http` | POST to URL (JSON in body) |
| `prompt` | LLM makes yes/no decision |
| `agent` | Spawn subagent to verify |

### Exit Codes

- `0` = proceed
- `2` = **block the action**
- Other = proceed, stderr logged

### Matcher Patterns

Regex patterns matching tool names or event subtypes:
- `Bash` — matches Bash tool
- `Edit|Write` — matches either
- `mcp__.*` — matches all MCP tools
- `startup`, `resume`, `compact` — SessionStart subtypes

---

## 5. Context Window Management

### Compaction

- **`/compact`** — manually compress conversation
- **Auto-compaction** at 95% capacity (configurable: `CLAUDE_CODE_AUTOCOMPACT_PCT_OVERRIDE=50`)
- **`PreCompact` hook** — re-inject critical context before compression
- CLAUDE.md and memory survive compaction automatically

### Checkpoints

- **`/checkpoint`** — list saved checkpoints
- **`/checkpoint save "name"`** — save named restore point
- **`/rewind`** — revert to a checkpoint (conversation only, not file changes)

### Strategies to Save Context

1. Use subagents for verbose operations (output stays in agent context)
2. Move instructions to CLAUDE.md (loaded once, not repeated)
3. Use skills with `context: fork` to isolate work
4. Enable MCP Tool Search to defer unused tool definitions

---

## 6. Settings Hierarchy

Settings cascade (higher overrides lower):

| Priority | Scope | Location | Shared? |
|----------|-------|----------|---------|
| 1 | Managed | `/etc/claude-code/managed-settings.json` | Yes (IT) |
| 2 | CLI flags | Command line | No |
| 3 | Local project | `.claude/settings.local.json` | No |
| 4 | Project | `.claude/settings.json` | Yes (git) |
| 5 | User | `~/.claude/settings.json` | No |

### Key Settings

```json
{
  "model": "claude-sonnet-4-6",
  "permissions": {
    "allow": ["Bash(npm run *)"],
    "deny": ["Read(./.env*)"],
    "ask": ["Bash(git push *)"]
  },
  "hooks": { ... },
  "env": { "NODE_ENV": "development" },
  "autoMemoryEnabled": true
}
```

### Permission Modes

| Mode | Behavior |
|------|----------|
| `default` | Prompts for each action |
| `acceptEdits` | Auto-approves file edits |
| `plan` | Read-only exploration |
| `dontAsk` | Auto-deny (allowed rules still work) |
| `bypassPermissions` | No prompts at all |

Cycle with `Shift+Tab`.

### Permission Rule Syntax

```
Tool                    — all uses of tool
Tool(pattern)           — specific pattern
Bash(npm run *)         — glob matching
Read(./src/**)          — recursive glob
mcp__github__*          — MCP tool pattern
```

Evaluation: deny → ask → allow → default deny.

---

## 7. CLAUDE.md Files

### Loading Hierarchy

1. Managed policy (`/etc/claude-code/CLAUDE.md`) — locked
2. User (`~/.claude/CLAUDE.md`) — personal, all projects
3. Project ancestors (walk up directory tree)
4. Current directory (`./CLAUDE.md` or `./.claude/CLAUDE.md`)
5. Subdirectories (lazy-loaded when Claude reads files there)

### Modular Rules

`.claude/rules/*.md` — split large CLAUDE.md into topic files:

```markdown
---
paths:
  - "src/api/**/*.ts"
---

# API Rules (only loaded for API files)

- Validate all inputs
- Use standard error format
```

Rules without `paths:` load unconditionally.

### Importing Files

```markdown
See @README for overview.
Details: @docs/architecture.md
```

---

## 8. Memory System

### Auto Memory

Claude saves learnings across sessions in `~/.claude/projects/<project>/memory/`.

Structure:
```text
memory/
├── MEMORY.md          (index, first 200 lines loaded)
├── user_role.md       (user profile)
├── feedback_*.md      (corrections/preferences)
├── project_*.md       (project state)
└── reference_*.md     (external system pointers)
```

Toggle: `/memory`

### Agent Memory

Agents with `memory: project` maintain their own knowledge base at `.claude/agent-memory/<name>/`.

---

## 9. MCP Servers

### Installation

```bash
# HTTP (remote)
claude mcp add --transport http github https://api.githubcopilot.com/mcp/

# Stdio (local process)
claude mcp add --transport stdio mydb -- npx -y db-server

# Scoped
claude mcp add --scope project ...  # shared with team
claude mcp add --scope user ...     # personal, all projects
```

### Project Config (`.mcp.json`)

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@anthropic/mcp-playwright"]
    }
  }
}
```

### MCP Resources

Reference with `@`:
```text
Analyze @github:issue://123
```

### Tool Search

Auto-defers unused MCP tools when they exceed 10% of context. Configure: `ENABLE_TOOL_SEARCH=auto:5`

---

## 10. Keybindings

Configure in `~/.claude/keybindings.json`:

```json
{
  "bindings": [
    {
      "context": "Chat",
      "bindings": {
        "ctrl+e": "chat:externalEditor",
        "ctrl+l": "chat:submit",
        "ctrl+u": null
      }
    }
  ]
}
```

### Key Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Submit prompt |
| `Shift+Tab` | Cycle permission mode |
| `Ctrl+C` | Interrupt |
| `Ctrl+D` | Exit |
| `Ctrl+B` | Background current task |
| `Ctrl+G` | Open external editor |
| `Ctrl+S` | Stash input |
| `Ctrl+T` | Toggle tasks |
| `Ctrl+R` | History search |
| `Ctrl+O` | Toggle transcript |
| `Cmd+P` | Model picker |
| `Cmd+T` | Toggle thinking |

### Chord Sequences

```text
ctrl+k ctrl+s   (Press Ctrl+K, release, then Ctrl+S)
```

---

## 11. Power-User Features

| Feature | How | Use Case |
|---|---|---|
| `/loop 5m /command` | Recurring execution | Poll deploys, watch logs |
| `!command` in chat | Run bash inline | Quick checks |
| `/vim` | Vim keybindings | Vim users |
| `/rewind` | Revert to checkpoint | Undo bad direction |
| `Ctrl+B` | Background task | Keep working while tests run |
| `Ctrl+G` | External editor | Write long prompts |
| `/cost` | Token usage | Monitor spending |
| `--worktree name` | Parallel sessions | Multiple Claude instances |
| `claude -p "prompt"` | Headless mode | CI/CD automation |
| `context: fork` | Isolated skill execution | Protect main context |
| `@file` in CLAUDE.md | Import docs | Reference external files |
| Path-scoped rules | `.claude/rules/*.md` | Different rules per directory |
| Agent memory | `memory: project` | Agents learn across sessions |
| `PreCompact` hook | Re-inject context | Survive compaction |
| Extended thinking | `Cmd+T` | Complex reasoning |
| Fast mode | `/fast` | Lower cost, faster responses |

---

## 12. IDE Integrations

### VS Code

- Install "Claude Code" extension
- Chat alongside editor
- Reference files in prompts
- `/` command palette

### JetBrains (IntelliJ, WebStorm)

- Install from Plugins marketplace
- Sidebar or floating chat
- WSL and remote dev support

---

## Decision Guide: When to Use What

| Need | Use |
|------|-----|
| Quick action I type manually | Slash command (`.claude/commands/`) |
| Reusable instructions Claude can auto-invoke | Skill (`.claude/skills/`) |
| Isolated worker with memory | Agent (`.claude/agents/`) |
| Auto-format/validate after actions | Hook (`PostToolUse`) |
| Block dangerous operations | Hook (`PreToolUse`, exit code 2) |
| Persistent project instructions | CLAUDE.md / `.claude/rules/` |
| External tool integration | MCP server |
| Different rules for different dirs | Path-scoped rules |
| Parallel safe work | Agent with `isolation: worktree` |
| Long-running background work | Agent with `background: true` |
