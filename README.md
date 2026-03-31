# WordPressGuard

An agentic security research framework for WordPress plugins and themes. Built for the [Wordfence Bug Bounty Program](https://www.wordfence.com/threat-intel/bug-bounty-program/), wpguard orchestrates 20+ specialized AI agents through Claude Code to find, verify, and report vulnerabilities at scale.

> **This is not a scanner.** wpguard is an autonomous research system — it downloads source code, maps attack surfaces, delegates deep analysis to expert agents, verifies findings in a live sandbox, and prepares submission-ready reports.

> [!CAUTION]
> **Run wpguard in a VM or dedicated host only.** This tool grants broad permissions to autonomous AI agents — filesystem access, Docker control, shell execution, network requests, and process management. Agents operate with the full privileges of the user running Claude Code. Running on your personal machine or a shared server risks unintended file modifications, data loss, or system damage. Use a disposable VM or a dedicated research box.
>
> **Not suitable for running inside Docker.** wpguard itself spawns Docker containers (WordPress sandbox) and requires Docker socket access. Running inside a container creates Docker-in-Docker complexity and breaks sandbox networking. Install directly on the VM host.

## How It Works

```
You: /pm audit flavor-starter (a WordPress theme with 50k installs)

PM Orchestrator
 |
 +--> Downloads theme, checks Wordfence scope, rebuilds sandbox
 +--> Delegates to surface-mapper (2-min grep recon)
 |     Returns: 12 SQLi candidates, 8 XSS candidates, 3 auth gaps
 |
 +--> Launches experts in parallel (each gets prioritized file targets):
 |     sqli-expert          --> finds blind SQLi in search handler
 |     xss-expert           --> finds stored XSS in theme options
 |     missing-auth-expert  --> finds unprotected AJAX endpoint
 |     data-flow-expert     --> finds option-write -> include() chain
 |     critical-thinker     --> chains CSRF + option write -> LFI
 |
 +--> Verification pipeline (mandatory for every finding):
 |     poc-writer    --> writes standalone PoC scripts
 |     poc-runner    --> executes against sandbox, catches false positives
 |     qa-triage     --> scope check, CVSS, writeup, Discord notification
 |     impact-assessor --> rejects obscure impact, downgrades inflated CVSS
 |     bb-submission --> clean sandbox repro, Wordfence submission format
 |
 +--> Discord: "3 validated findings for flavor-starter"
```

## Features

### Agentic Research Pipeline

- **20+ specialized agents** — each expert covers a specific vulnerability class with deep domain knowledge
- **PM orchestrator** (`/pm`) — coordinates the entire research lifecycle, never skips phases
- **Surface mapper** — fast grep-based recon that prioritizes file:line targets for each expert
- **Context survival protocol** — agents save progress incrementally, checkpoint every 10 tool calls, survive context exhaustion
- **Mandatory verification** — every finding passes through PoC writer -> PoC runner -> QA triage -> impact assessor -> BB submission

### Vulnerability Experts

| Agent | Focus |
|-------|-------|
| `sqli-expert` | SQL injection (UNION, blind, second-order, identifier injection) |
| `xss-expert` | Stored, reflected, DOM-based XSS |
| `file-rce-expert` | File upload/read/write/delete, path traversal, RCE |
| `missing-auth-expert` | Missing capability checks on AJAX/REST/admin endpoints |
| `idor-expert` | Insecure Direct Object Reference |
| `priv-esc-expert` | Privilege escalation, options update chains, role manipulation |
| `object-injection-expert` | PHP object injection, phar deserialization |
| `ssrf-expert` | Server-side request forgery, cloud metadata |
| `race-condition-expert` | TOCTOU, database races, limit bypass |
| `csrf-expert` | CSRF, missing nonce validation |
| `data-flow-expert` | Cross-feature data flows — writes in one feature consumed unsafely by another |
| `critical-thinker` | Cross-domain chains, second-order bugs, multi-step vulns |
| `lfi-rfi-expert` | Local/remote file inclusion |
| `xxe-expert` | XML external entity injection |
| `deserialization-expert` | JSON/YAML parsing, type juggling |
| `logic-flaw-expert` | Business logic bugs, payment bypass |
| `info-disclosure-expert` | Sensitive data exposure, debug endpoints |
| `code-injection-expert` | eval, call_user_func, dynamic dispatch |
| `open-redirect-expert` | wp_redirect, header Location, JS redirects |

### Plugin & Theme Support

Full research support for both WordPress plugins and themes:

- **Download & extract** source code from wordpress.org
- **SVN integration** — commit history, diffs between revisions, remote diffing (no local downloads needed)
- **Global monitoring** — track recently updated and newly added plugins/themes across the ecosystem
- **Changelog enrichment** — parsed changelogs and SVN commit logs for high-value updates

### WordPress Sandbox

Docker-based WordPress instance for live exploitation testing:

- **Authenticated requests** at any role level (subscriber, contributor, author)
- **Nonce extraction** from pages/endpoints accessible at the attacker's auth level
- **Plugin/theme installation** via WP-CLI
- **Mandatory rebuild** between audits — no artifact contamination
- **Ecosystem setup** — WooCommerce, BuddyPress, Elementor environments with test data

### Wordfence Scope Validation

Built-in rules for the Wordfence Bug Bounty Program:

- Automatic eligibility checking by install count and vulnerability type
- Auth level validation (subscriber through author, editor/admin out of scope)
- Excluded vendor detection
- CVSS scoring guidance

### Ecosystem Monitoring (`/watch`)

Track the entire WordPress ecosystem for research opportunities:

```
/watch                    # One-time scan
/loop 30m /watch          # Continuous monitoring every 30 minutes
```

- **Global plugin updates** — recently updated plugins with changelog + SVN log
- **Global theme updates** — recently updated themes with changelog + SVN log
- **New plugins** — freshly added to wordpress.org (zero prior scrutiny)
- **New themes** — freshly added themes
- **Watchlist** — SVN-level change tracking for specific slugs
- **Dedup** — only surfaces new changes since last check

## Architecture

```
                        Claude Code
                    (PM Orchestrator)
                          |
               /pm  /watch  /recon  /nday  ...
                          |
                    MCP Protocol (stdio)
                          |
          +---------------+---------------+
          |                               |
    wpguard MCP Server              Playwright MCP
      (60+ tools)                  (browser automation)
          |
    +-----+-----+-----+-----+
    |     |     |     |     |
  Plugin Theme  SVN  Sandbox Findings
   API   API  Client (Docker) Manager
    |     |     |     |     |
    v     v     v     v     v
  WordPress.org   plugins.svn    wp_app     state.json
  Plugins API     themes.svn    container   findings.json
  Themes API                    (Docker)
```

### MCP Tools (60+)

| Category | Tools | Description |
|----------|-------|-------------|
| **Plugin Discovery** | `wpguard_plugin_info`, `wpguard_search`, `wpguard_download`, `wpguard_bulk_download` | Search, inspect, and download plugins |
| **Theme Discovery** | `wpguard_theme_info`, `wpguard_theme_search`, `wpguard_theme_download` | Search, inspect, and download themes |
| **Plugin SVN** | `wpguard_svn_log`, `wpguard_svn_diff`, `wpguard_svn_revision` | Plugin commit history and diffs |
| **Theme SVN** | `wpguard_theme_svn_log`, `wpguard_theme_svn_diff` | Theme commit history and diffs |
| **Watch (Plugins)** | `wpguard_watch_add`, `wpguard_watch_check`, `wpguard_watch_global`, `wpguard_watch_new` | Plugin monitoring and global updates |
| **Watch (Themes)** | `wpguard_watch_global_themes`, `wpguard_watch_new_themes` | Theme monitoring and global updates |
| **Sandbox** | `wpguard_sandbox_start`, `wpguard_sandbox_request`, `wpguard_sandbox_wp_cli`, `wpguard_sandbox_get_nonce`, `wpguard_sandbox_list_endpoints`, `wpguard_sandbox_map_nonces` | Docker WordPress instance, REST discovery, nonce mapping |
| **Scope** | `wpguard_scope_check_plugin`, `wpguard_scope_check_finding`, `wpguard_scope_get_vulns` | Wordfence bounty eligibility |
| **Findings** | `wpguard_finding_create`, `wpguard_finding_update`, `wpguard_finding_list`, `wpguard_finding_stats` | Vulnerability tracking and management |
| **CVE Database** | `wpguard_cve_search`, `wpguard_cve_get`, `wpguard_cve_stats` | Wordfence vulnerability database |
| **Discord** | `wpguard_discord_notify_finding`, `wpguard_discord_notify_summary` | Real-time notifications |
| **Scoring** | `wpguard_target_score` | Priority scoring for target selection (installs, CVEs, audit history) |
| **Regression** | `wpguard_regression_check` | Re-run previous PoCs to detect incomplete patches |
| **Dedup** | `wpguard_finding_check_duplicate` | Check for duplicate findings before creation |
| **Project** | `wpguard_init_research` | Initialize research project with all agents and commands |

## Installation

### Prerequisites

| Requirement | Purpose | Install |
|-------------|---------|---------|
| **Python 3.11+** | Runtime | `apt install python3` / `brew install python` |
| **pipx** | Isolated install | `apt install pipx` / `pip install pipx` |
| **[Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI** | Agent orchestration | `npm install -g @anthropic-ai/claude-code` |
| **Docker + Compose** | WordPress sandbox | `apt install docker.io docker-compose-plugin` |
| **SVN** | Plugin/theme version history | `apt install subversion` |
| **Node.js 18+** | Playwright MCP, svg-term-cli | `apt install nodejs` / `brew install node` |
| **asciinema** | Terminal PoC video recording | `pipx install asciinema` |
| **Playwright** (Python) | Browser PoC video recording with `record_video_dir` | `pip install playwright && playwright install chromium` |
| **ffmpeg** | Video format conversion (webm/cast → gif) | `apt install ffmpeg` |
| **svg-term-cli** (optional) | Convert terminal recordings to animated SVG | `npx svg-term-cli` |

**API Keys:**

| Key | Purpose | How to Get |
|-----|---------|------------|
| **Anthropic API key** | Claude Code agents | [console.anthropic.com](https://console.anthropic.com) |
| **Wordfence API key** | CVE database search (`wpguard_cve_search`) | [wordfence.com/threat-intel](https://www.wordfence.com/threat-intel/) — free tier available |
| **Discord webhook** (optional) | Finding notifications | Server Settings > Integrations > Webhooks |

```bash
# Set API keys
export WORDFENCE_API_KEY="your-key-here"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."  # optional

# Point to your web pentesting knowledge base for RAG-powered agent assistance
export WPGUARD_RAG_DOCS="/path/to/WebPentestRAG"
```

### Install wpguard

```bash
# From GitHub (recommended)
pipx install git+https://github.com/0xQRx/wpguard.git

# Development
git clone https://github.com/0xQRx/wpguard.git
cd wpguard
pipx install -e .
```

### Setup MCP Servers

wpguard uses three MCP servers — wpguard itself (required), Playwright (required for PoC verification), and devrag (optional but recommended):

```bash
# Required: wpguard tools (plugin/theme API, sandbox, findings, scope validation)
claude mcp add wpguard -s user -- wpguard-mcp

# Required: Playwright (browser automation for XSS/CSRF PoC verification)
claude mcp add playwright -s user -- npx @playwright/mcp@latest

# Optional but recommended: devrag (RAG over security knowledge base)
# Build from web pentesting resources — PayloadsAllTheThings, HackTricks, OWASP, etc.
# See: https://github.com/0xQRx/devrag
claude mcp add devrag -s user -- /path/to/devrag --config /path/to/devrag/config.json

# Verify all MCP servers
claude mcp list
```

**devrag** provides RAG-powered search over curated security research documents. When configured with resources like [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), [HackTricks](https://book.hacktricks.wiki/), and OWASP guides, it gives agents access to bypass techniques, payload lists, and exploitation patterns during analysis. Not required, but significantly improves expert agent effectiveness.

## Quick Start

### Initialize a Research Project

```bash
mkdir my-research && cd my-research

# In Claude Code:
# > Use wpguard_init_research to set up this directory
```

This creates the full project structure: CLAUDE.md, all agent definitions, slash commands, MCP config, and permissions.

### Run Your First Audit

```
/pm audit flavor starter theme with 50k installs
```

The PM orchestrator handles everything — download, scope check, sandbox setup, surface mapping, expert delegation, verification pipeline, and submission prep.

### Slash Commands

| Command | Purpose |
|---------|---------|
| `/pm` | PM orchestrator — start all research here |
| `/watch` | Ecosystem monitor — scan for updated plugins/themes |
| `/target-research` | Find and scope plugins/themes for analysis |
| `/recon` | Lightweight assessment before full audit |
| `/status` | Dashboard of current audit progress |
| `/findings` | List all findings with status and severity |
| `/nday` | N-day research — PoCs for known/patched CVEs |
| `/diff` | Security-focused version diff — flag dangerous code changes |

### CLI Commands

```bash
# Plugin operations
wpguard info akismet
wpguard search "gallery" --per-page 50
wpguard download --search backup --min-installs 50000 --count 10 --extract

# Watch operations
wpguard watch add akismet wordfence contact-form-7
wpguard watch check
wpguard watch --interval 30m --send-report

# SVN operations
wpguard svn log akismet --limit 20
wpguard svn diff akismet 3000000 3001000 --show-diff
```

## Research Workflow

### Full Audit (Plugin or Theme)

```
1. Download         wpguard_download / wpguard_theme_download
2. Scope check      wpguard_scope_check_plugin
3. CVE history      wpguard_cve_search
4. Sandbox rebuild  wpguard_sandbox_destroy + wpguard_sandbox_start
5. Surface map      surface-mapper agent (grep recon, file:line targets)
6. Expert analysis  Parallel expert agents with specific targets
7. Escalation       vuln-escalator tests lower auth levels
8. PoC writing      poc-writer for each finding
9. PoC execution    poc-runner against sandbox
10. QA validation   qa-triage (scope, CVSS, writeup)
11. Impact review   impact-assessor (mandatory — rejects obscure impact)
12. Submission      bb-submission (clean repro, Wordfence format)
```

### Context Survival Protocol

Large codebases exhaust agent context. wpguard agents are designed to survive:

1. **Save-first** — create progress report scaffold within first 3 tool calls
2. **Checkpoint** — update progress every 10 tool calls
3. **Immediate saves** — findings saved as drafts the moment they're discovered
4. **Relaunchable** — PM detects partial analysis and relaunches with progress context

### Scope Quick Reference (Wordfence)

| Min Installs | Vulnerability Types | Max Auth Level |
|--------------|---------------------|----------------|
| 25 | RCE, File Upload/Read/Delete, Options Update, Auth Bypass, Priv Esc | Author |
| 500 | SQL Injection, Stored XSS | Author |
| 50,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, Object Injection | Author |

## Project Structure

```
research-project/
+-- CLAUDE.md                          # Project instructions for agents
+-- .claude/
|   +-- commands/                      # Slash commands (/pm, /watch, /recon, ...)
|   +-- agents/                        # 20+ agent definitions
|   |   +-- sqli-expert/agent.md
|   |   +-- xss-expert/agent.md
|   |   +-- data-flow-expert/agent.md
|   |   +-- ...
|   +-- settings.local.json            # MCP tool permissions
+-- .mcp.json                          # MCP server config
+-- targets/{slug}/extracted/          # Plugin/theme source code
+-- reports/{slug}/
|   +-- PLAN.md                        # Audit plan and progress
|   +-- surface_map.md                 # Attack surface report
|   +-- progress_{agent}.md            # Per-agent progress
|   +-- {finding_id}/
|       +-- poc.py                     # PoC script
|       +-- writeup.md                 # Vulnerability writeup
+-- wpguard_findings.json              # Findings database
+-- recently_updated.json              # Plugin update monitor output
+-- recently_updated_themes.json       # Theme update monitor output
+-- state.json                         # Watch state
```

## Autonomous Loop Examples

Combine `/loop` with slash commands for fully autonomous operation. These run inside Claude Code.

### Continuous Research Loop (Fully Autonomous)

```
/loop 15m /pm Check active research → if running check on progress, ensure
plan is being followed, if stalled re-trigger, if complete archive+mark DONE
→ Pick next target by highest historical vuln count (list empty?
Auto-Discover+rank+pick) → Initialize a plan for a plugin. Launch full audit
(each phase needs confirmed output before next unlocks).

RULES: no parallel audits, no skipped/abbreviated phases, no DONE without
confirmation that full plan was covered. If watch returns recently updated
plugins (recently_updated.json), prioritize those into queue with main focus
on latest changes.

Focus on High Threat Tier vulnerabilities:
- 25+ installs
- Unauth, Customer, Subscriber roles
- RCE, File Upload/Read/Delete, Options Update, Auth Bypass to admin, Priv Esc to admin

Best strategy: plugins with frontend user interaction and 5-15 CVEs, never idle.
```

This creates a self-driving research loop that:
- Checks progress every 15 minutes
- Detects stalled audits and re-triggers them
- Picks the next highest-value target when done
- Auto-discovers new targets when the queue is empty
- Prioritizes recently updated plugins from `/watch` output
- Never sits idle

### Ecosystem Monitor

```
/loop 30m /watch
```

Scans WordPress.org every 30 minutes for plugin and theme updates. Results saved to `recently_updated.json` and `recently_updated_themes.json`. The research loop above picks these up automatically.

### Context Compaction

```
/loop 2h /compact
```

Compresses conversation context every 2 hours to prevent context exhaustion during long autonomous sessions.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `WORDFENCE_API_KEY` | Wordfence Intelligence API key (for CVE database) |
| `WPGUARD_RAG_DOCS` | Path to web pentesting knowledge base for devrag (PayloadsAllTheThings, HackTricks, etc.) |
| `DISCORD_WEBHOOK_URL` | Discord webhook for finding notifications |
| `WP_SANDBOX_HOST` | Sandbox host (default: `172.17.0.1`) |
| `WP_SANDBOX_PORT` | Sandbox port (default: `8000`) |
| `WPGUARD_SANDBOX_DIR` | Custom sandbox Docker Compose directory |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for authorized security research within the Wordfence Bug Bounty Program. All analysis is performed on downloaded source code and controlled sandbox environments. Always respect WordPress.org terms of service and individual plugin/theme licenses.

**wpguard grants autonomous AI agents broad system access including filesystem writes, Docker management, shell execution, and network requests. Always run in an isolated environment (VM or dedicated host). The authors are not responsible for damage caused by running this tool on production or personal systems.**
