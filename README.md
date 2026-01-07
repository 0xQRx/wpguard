# WordPressGuard

A defensive security research tool for downloading, monitoring, and analyzing WordPress plugins from the official repository.

## Features

- **Download Plugins**: Bulk download plugins filtered by active installations, search terms, or categories
- **Watch Mode**: Track specific plugins and get notified when updates are released
- **SVN-Based Change Detection**: Use SVN diff to see exact code changes between versions, with commit logs
- **Hash-Based Fallback**: Compare file hashes when SVN is unavailable
- **Discord Notifications**: Receive real-time alerts when watched plugins are updated
- **Local Reports**: JSON reports saved locally for each detected update
- **Continuous Monitoring**: Background watch mode with tmux support
- **SVN Commands**: Direct access to SVN log and diff for any plugin
- **MCP Server**: Integration with Claude Code and other AI assistants via Model Context Protocol
- **WordPress Sandbox**: Docker-based WordPress instance for PoC testing with authenticated requests
- **Wordfence Scope Validation**: Automatic bounty eligibility checking for plugins and findings
- **Finding Management**: Track and manage vulnerability findings with CVSS scores
- **CVE Database**: Search Wordfence vulnerability database for known issues
- **Automated Pipeline**: Multi-stage research pipeline with Claude Code agents

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│              (Orchestrator / Decision Maker)                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │ MCP Protocol
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     wpguard MCP Server                           │
│                        (49 tools)                                │
│                                                                  │
│  Plugin Tools    Sandbox Tools    Finding Tools    Pipeline      │
│  - search        - status         - create         - start       │
│  - download      - install        - update         - stop        │
│  - svn_log       - request        - list           - status      │
│  - watch_*       - wp_cli         - stats          - logs        │
│                                                                  │
│  Scope Tools     Discord Tools    CVE Tools                      │
│  - check_plugin  - notify         - download                     │
│  - check_finding - summary        - search                       │
│  - get_vulns     - message        - get/stats                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  WordPress   │  │    JSON      │  │   Discord    │
│   Sandbox    │  │    State     │  │   Webhook    │
│   (Docker)   │  │    Files     │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
```

## Installation

### From GitHub (via pipx - recommended)

```bash
pipx install git+https://github.com/0xqrx/WordPressGuard.git
```

### From GitHub (via pip)

```bash
pip install git+https://github.com/0xqrx/WordPressGuard.git
```

### Development Installation

```bash
git clone https://github.com/0xqrx/WordPressGuard.git
cd WordPressGuard
pip install -e ".[dev]"
```

## Quick Start

```bash
# Download 10 plugins with 100k+ active installs
wpguard download --min-installs 100000 --count 10

# Get info about a specific plugin
wpguard info akismet

# Search for security plugins
wpguard search "security"

# Add plugins to watchlist
wpguard watch add akismet wordfence contact-form-7

# Check once for updates
wpguard watch check

# Start continuous monitoring with Discord notifications
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
wpguard watch --send-report --interval 30m
```

## Commands

### download

Download plugins from the WordPress repository.

```bash
wpguard download [OPTIONS]

Options:
  --search, -s TEXT       Search term for plugins
  --min-installs INTEGER  Minimum active installations (default: 0)
  --max-installs INTEGER  Maximum active installations
  --count, -n TEXT        Number of plugins or 'all' (default: 10)
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --svn                   Also checkout from SVN (in addition to ZIP)
  --extract, -x           Extract ZIP files after download
  --delay INTEGER         Delay between downloads in seconds (default: 1)
  --browse TEXT           Browse category: popular, new, updated
```

**Examples:**

```bash
# Download top 5 security plugins with 50k+ installs
wpguard download --search security --min-installs 50000 --count 5

# Download all plugins with 1M+ installs
wpguard download --min-installs 1000000 --count all

# Download and extract popular plugins with custom delay
wpguard download --browse popular --count 20 --extract --delay 2

# Download ZIP + SVN for version history access
wpguard download --search backup --count 3 --svn --extract
```

### info

Get detailed information about a specific plugin.

```bash
wpguard info <slug>
```

**Example:**

```bash
wpguard info wordfence
```

### search

Search for plugins in the WordPress repository.

```bash
wpguard search <query> [OPTIONS]

Options:
  --page, -p INTEGER     Page number (default: 1)
  --per-page INTEGER     Results per page, max 250 (default: 20)
```

**Example:**

```bash
wpguard search "ecommerce" --per-page 50
```

### watch

Unified command for plugin monitoring. Manages watchlist and runs continuous monitoring.

#### watch add

Add plugins to the watchlist.

```bash
wpguard watch add <slugs...> [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --discord-webhook URL   Discord webhook URL
```

**Example:**

```bash
wpguard watch add akismet jetpack woocommerce
```

#### watch remove

Remove plugins from watchlist.

```bash
wpguard watch remove <slugs...> [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
```

#### watch list

List all watched plugins.

```bash
wpguard watch list [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
```

#### watch check

Check watched plugins for updates once (no continuous loop).

```bash
wpguard watch check [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --send-report           Send report to Discord
  --discord-webhook URL   Discord webhook URL
```

#### watch (continuous monitoring)

Run `wpguard watch` without a subcommand to start continuous monitoring.

```bash
wpguard watch [OPTIONS]

Options:
  --output-dir, -o PATH    Output directory (default: ./wpguard_output)
  --interval, -i DURATION  Check interval (default: 5m)
                           Formats: 30s, 5m, 1h, 1h30m, 1h30m45s, or integer seconds
  --send-report            Send reports to Discord
  --discord-webhook URL    Discord webhook URL
  --tmux                   Start in tmux session
  --tmux-session NAME      Tmux session name (default: wpguard)
```

**Examples:**

```bash
# Watch mode in foreground with 10 minute interval
wpguard watch --interval 10m

# Watch mode with 1 hour 30 minute interval
wpguard watch --interval 1h30m

# Watch mode with Discord notifications
wpguard watch --interval 30m --send-report

# Watch mode in tmux (for remote servers)
wpguard watch --tmux --tmux-session wp-monitor --send-report
```

### svn

SVN operations for viewing plugin history and changes.

#### svn log

View commit history for a plugin.

```bash
wpguard svn log <slug> [OPTIONS]

Options:
  --limit, -l INTEGER    Number of entries (default: 10)
```

**Example:**

```bash
wpguard svn log akismet --limit 20
```

#### svn diff

Compare changes between SVN revisions.

```bash
wpguard svn diff <slug> <old_rev> [new_rev] [OPTIONS]

Options:
  --show-diff            Show full diff output
  --output-file, -o      Save diff to file
```

**Examples:**

```bash
# Show changes from revision 1000000 to HEAD
wpguard svn diff akismet 1000000

# Show changes between two specific revisions
wpguard svn diff akismet 1000000 1000500

# Show full diff and save to file
wpguard svn diff akismet 1000000 --show-diff --output-file changes.diff
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Discord webhook URL for notifications |

All other settings (output directory, intervals) are controlled via CLI flags only.

## Directory Structure

All output goes under a single base directory (default: `./wpguard_output`):

```
./wpguard_output/                    # Base directory (--output-dir)
├── plugins/                         # Downloaded plugins
│   ├── akismet/
│   │   ├── zip/
│   │   │   ├── 5.3.zip             # Version-named ZIP files
│   │   │   └── 5.2.zip             # Old versions preserved
│   │   ├── extracted/
│   │   │   ├── 5.3/                # Version-named directories
│   │   │   │   ├── akismet.php
│   │   │   │   └── ...
│   │   │   └── 5.2/
│   │   └── svn/                    # SVN working copy (trunk)
│   │       ├── .svn/
│   │       └── ...
│   └── wordfence/
│       └── ...
├── reports/                         # Change reports
│   └── akismet/
│       └── 5.2_to_5.3_2024-01-15_103000.json
└── state.json                       # Watchlist state file
```

This structure allows:
- **Version history**: Multiple versions of the same plugin stored side-by-side
- **Easy comparison**: Compare different versions using diff tools
- **SVN access**: Full SVN working copy for `svn log`, `svn diff`, etc.
- **No conflicts**: ZIP, extracted, and SVN versions don't overwrite each other
- **Local reports**: JSON reports for each detected update

## Change Reports

When a watched plugin is updated, WordPressGuard generates a detailed change report including:

- **Modified Files**: Files that changed between versions (from SVN diff)
- **Added Files**: New files in the updated version
- **Removed Files**: Files deleted in the updated version
- **SVN Commit Log**: Recent commit messages explaining the changes
- **Download Commands**: Ready-to-use wget and svn commands

### Console Output

```
======================================================================
PLUGIN UPDATE: Akismet Anti-Spam (akismet)
Version: 5.0 -> 5.1
======================================================================

[Modified Files] (3)
   M akismet.php
   M class.akismet.php
   M readme.txt

[Added Files] (1)
   A includes/new-feature.php

[Download Commands]
   wget "https://downloads.wordpress.org/plugin/akismet.5.1.zip"
   svn checkout https://plugins.svn.wordpress.org/akismet/trunk/
======================================================================

[SVN Commit Log]
   r3000001 - Updated security checks for PHP 8.2 compatibility
   r3000000 - Added new spam detection algorithm
   r2999999 - Version bump for 5.1 release
```

### Local JSON Report

Reports are saved to `{output_dir}/reports/{slug}/`:

```json
{
  "plugin_slug": "akismet",
  "plugin_name": "Akismet Anti-Spam",
  "old_version": "5.2",
  "new_version": "5.3",
  "timestamp": "2024-01-15T10:30:00Z",
  "svn_old_revision": "2987000",
  "svn_new_revision": "2987654",
  "changed_files": ["akismet.php", "class.akismet.php"],
  "added_files": ["includes/new-feature.php"],
  "removed_files": [],
  "svn_log": [
    {"revision": "2987654", "author": "dev", "date": "...", "message": "..."}
  ],
  "download_commands": {
    "wget": "wget \"https://...\"",
    "svn": "svn checkout https://..."
  }
}
```

### Discord Notification

Reports are sent as rich embeds with:
- Plugin name and version change
- Categorized file lists
- Copy-paste download commands

## Use Cases

### Security Research

Monitor popular plugins for code changes that might indicate:
- Supply chain compromises
- Backdoor insertions
- Vulnerability patches

```bash
# Monitor top security plugins
wpguard watch add wordfence sucuri-scanner ithemes-security
wpguard watch --send-report --interval 5m
```

### Plugin Development

Track competitor plugins or dependencies:

```bash
# Monitor specific plugins
wpguard watch add advanced-custom-fields elementor
wpguard watch check
```

### Bulk Analysis

Download plugins for static analysis:

```bash
# Download all plugins with 500k+ installs
wpguard download --min-installs 500000 --count all --extract

# Download security-related plugins
wpguard download --search security --count all --min-installs 10000
```

## MCP Server (Claude Code Integration)

WordPressGuard includes an MCP (Model Context Protocol) server that exposes all functionality as tools for AI assistants like Claude Code.

### Adding to Claude Code

```bash
# Add for current user (available in all projects)
claude mcp add wpguard -s user -- wpguard-mcp

# Or add to current project only
claude mcp add wpguard -- wpguard-mcp
```

Verify it was added:

```bash
claude mcp list
```

### Manual Configuration

Add to `~/.claude/settings.json` (user) or `.claude/settings.json` (project):

```json
{
  "mcpServers": {
    "wpguard": {
      "command": "wpguard-mcp"
    }
  }
}
```

### Available MCP Tools

#### Plugin Discovery & Information (6 tools)

| Tool | Description |
|------|-------------|
| `wpguard_search` | Search for WordPress plugins in the official repository |
| `wpguard_plugin_info` | Get detailed information about a specific plugin |
| `wpguard_download` | Download a WordPress plugin (ZIP and optionally SVN) |
| `wpguard_bulk_download` | Download multiple plugins with filtering by active installations |
| `wpguard_plugin_versions` | Get all available versions for a WordPress plugin |
| `wpguard_state_info` | Get current state information (watched plugins count, last check) |

#### SVN Operations (3 tools)

| Tool | Description |
|------|-------------|
| `wpguard_svn_log` | Get SVN commit history for a WordPress plugin |
| `wpguard_svn_diff` | Compare changes between SVN revisions for a plugin |
| `wpguard_svn_revision` | Get the latest SVN revision number for a plugin |

#### Watch/Monitor (4 tools)

| Tool | Description |
|------|-------------|
| `wpguard_watch_add` | Add plugins to the watchlist for update monitoring |
| `wpguard_watch_remove` | Remove plugins from the watchlist |
| `wpguard_watch_list` | List all plugins currently being watched |
| `wpguard_watch_check` | Check watched plugins for updates (single check) |

#### WordPress Sandbox (10 tools)

| Tool | Description |
|------|-------------|
| `wpguard_sandbox_status` | Check WordPress sandbox connectivity |
| `wpguard_sandbox_start` | Start the WordPress sandbox Docker containers |
| `wpguard_sandbox_stop` | Stop the WordPress sandbox Docker containers |
| `wpguard_sandbox_restart` | Restart the WordPress sandbox |
| `wpguard_sandbox_destroy` | Stop and remove all sandbox data (volumes) |
| `wpguard_sandbox_install_plugin` | Install a plugin in the WordPress sandbox |
| `wpguard_sandbox_uninstall_plugin` | Uninstall a plugin from the WordPress sandbox |
| `wpguard_sandbox_request` | Execute an HTTP request against the WordPress sandbox |
| `wpguard_sandbox_wp_cli` | Execute a WP-CLI command in the sandbox container |
| `wpguard_sandbox_get_nonce` | Get a WordPress nonce for an action |

#### Wordfence Scope Validation (3 tools)

| Tool | Description |
|------|-------------|
| `wpguard_scope_check_plugin` | Check if a plugin is eligible for Wordfence bounty research |
| `wpguard_scope_check_finding` | Validate if a vulnerability finding is eligible for bounty |
| `wpguard_scope_get_vulns` | Get all in-scope vulnerability types for a given install count |

#### Finding Management (7 tools)

| Tool | Description |
|------|-------------|
| `wpguard_finding_create` | Create a new security vulnerability finding |
| `wpguard_finding_update` | Update an existing finding (status, validation notes) |
| `wpguard_finding_get` | Get a finding by ID |
| `wpguard_finding_list` | List findings with optional filters |
| `wpguard_finding_delete` | Delete a finding |
| `wpguard_finding_stats` | Get statistics about all findings |
| `wpguard_scan_state` | Get or update scan state (current plugin, pending plugins) |

#### Discord Notifications (3 tools)

| Tool | Description |
|------|-------------|
| `wpguard_discord_notify_finding` | Send a finding notification to Discord |
| `wpguard_discord_notify_summary` | Send a summary of findings to Discord |
| `wpguard_discord_send_message` | Send a simple text message to Discord |

#### CVE Database (4 tools)

| Tool | Description |
|------|-------------|
| `wpguard_cve_download` | Download/refresh the Wordfence vulnerability database |
| `wpguard_cve_search` | Search Wordfence CVE database by plugin slug or keyword |
| `wpguard_cve_get` | Get detailed CVE info by Wordfence ID or CVE ID |
| `wpguard_cve_stats` | Get statistics about the Wordfence vulnerability database |

#### Pipeline Automation (9 tools)

| Tool | Description |
|------|-------------|
| `wpguard_pipeline_start` | Start the security research pipeline daemon |
| `wpguard_pipeline_stop` | Stop the pipeline daemon |
| `wpguard_pipeline_status` | Get current pipeline status and metrics |
| `wpguard_pipeline_pause` | Pause the pipeline |
| `wpguard_pipeline_resume` | Resume a paused pipeline |
| `wpguard_pipeline_config` | Get or update pipeline configuration |
| `wpguard_pipeline_logs` | Get logs from a worker session |
| `wpguard_pipeline_attach` | Get the tmux attach command for a stage |
| `wpguard_init_research` | Initialize a new wpguard research project |

### Running the MCP Server Standalone

```bash
wpguard-mcp
```

## Automated Security Research Pipeline

WordPressGuard includes a fully automated pipeline for continuous WordPress plugin vulnerability research using Claude Code agents.

### Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Pipeline Daemon                          │
│                  (Background Process)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
    Sequential Stage Execution (per plugin)
                      │
    ┌─────────────────┼─────────────────────────────────────┐
    ▼                 ▼                                     ▼
┌──────────┐    ┌──────────┐    ┌────────────────────┐  ┌──────────┐
│ /target- │ → │/security-│ → │   Expert Stages    │→ │/qa-triage│
│ research │    │ research │    │   (6 specialists)  │  │          │
└──────────┘    └──────────┘    └────────────────────┘  └──────────┘
                                         │
                   ┌─────────────────────┼─────────────────────┐
                   ▼                     ▼                     ▼
            ┌────────────┐        ┌────────────┐        ┌────────────┐
            │/file-rce-  │   →    │/sqli-expert│   →    │/xss-expert │
            │  expert    │        │            │        │            │
            └────────────┘        └────────────┘        └────────────┘
                   │                     │                     │
                   ▼                     ▼                     ▼
            ┌────────────┐        ┌────────────┐        ┌────────────┐
            │/auth-expert│   →    │/object-    │   →    │/ssrf-expert│
            │            │        │injection-  │        │            │
            └────────────┘        │expert      │        └────────────┘
                                  └────────────┘
```

### Nine Stages (Sequential Per Plugin)

1. **Target Research**: Find WordPress plugins matching criteria, verify Wordfence eligibility, download source code
2. **Security Research**: General vulnerability analysis - hooks, patterns, data flows
3. **File/RCE Expert**: File upload, read, write, delete, path traversal, phar deserialization → RCE
4. **SQLi Expert**: SQL injection in all forms - UNION, blind, second-order, identifier injection
5. **XSS Expert**: Stored, reflected, DOM XSS with context-aware escaping analysis
6. **Auth Expert**: Auth bypass, privilege escalation, IDOR, missing authorization checks
7. **Object Injection Expert**: PHP object injection, phar deserialization, gadget chain construction
8. **SSRF Expert**: Server-side request forgery, cloud metadata access, internal network scanning
9. **QA/Triage**: Validate findings, verify CVSS scores, reproduce vulnerabilities, send Discord notifications

### Expert Agent Philosophy

All expert agents operate with an **elite hacker mindset**:
- **Assume vulnerable** - Every plugin IS vulnerable until YOU personally prove otherwise
- **Never give up** - Exhaust ALL bypass techniques before marking anything "secure"
- **Die on that hill** - If defenses exist, find the edge case that breaks them
- **Deep expertise** - Each expert knows every bypass, every edge case, every obscure technique for their domain

### Pipeline Modes

| Mode | Description |
|------|-------------|
| `continuous` | Loop forever: targets → research → QA → repeat |
| `single` | One complete cycle through target batch, then stop |
| `targets-only` | Just find and download targets, no analysis |

### Pipeline Quick Start

```bash
# Initialize research project
wpguard_init_research()

# Start pipeline
wpguard_pipeline_start(mode="continuous", target_count=5)

# Monitor progress
wpguard_pipeline_status(include_logs=True)

# View live worker
wpguard_pipeline_attach(stage="security-research")
```

### Pipeline Control Commands

```bash
wpguard_pipeline_pause()              # Pause after current stage completes
wpguard_pipeline_resume()             # Resume paused pipeline
wpguard_pipeline_stop()               # Graceful stop
wpguard_pipeline_stop(force=True)     # Force kill all workers
```

### Target Criteria Examples

```bash
# By install count
"plugins with 500-5000 active installs"
"plugins with 10000+ installs"

# By category
"gallery plugins with 1000+ installs"
"e-commerce plugins, avoid WooCommerce, 500+ installs"

# By features (high-value targets)
"plugins with file upload functionality"
"plugins with user registration features"
"plugins with AJAX endpoints"
```

### Pipeline Directory Structure

```
project/
├── .claude/commands/           # Slash command templates
│   ├── target-research.md      # Target discovery agent
│   ├── security-research.md    # General security analysis
│   ├── file-rce-expert.md      # File ops & RCE specialist
│   ├── sqli-expert.md          # SQL injection specialist
│   ├── xss-expert.md           # XSS specialist
│   ├── auth-expert.md          # Auth/authz specialist
│   ├── object-injection-expert.md  # PHP object injection specialist
│   ├── ssrf-expert.md          # SSRF specialist
│   ├── qa-triage.md            # Validation & submission
│   └── poc-creator.md          # Changelog → PoC creator
├── targets/                    # Downloaded plugins
│   └── {plugin-slug}/extracted/
├── reports/                    # Findings and PoCs
│   └── {plugin-slug}/
├── wpguard_findings.json       # Vulnerability findings
├── wpguard_scan_state.json     # Scan progress
├── wpguard_pipeline_state.json # Pipeline state
└── CLAUDE.md                   # Project instructions
```

### Available Slash Commands

| Command | Description |
|---------|-------------|
| `/target-research` | Find and scope WordPress plugins for analysis |
| `/security-research` | General vulnerability analysis (hooks, patterns, data flows) |
| `/file-rce-expert` | File upload, read, write, delete, path traversal → RCE |
| `/sqli-expert` | SQL injection in all forms (UNION, blind, second-order) |
| `/xss-expert` | Stored, reflected, DOM XSS |
| `/auth-expert` | Auth bypass, privilege escalation, IDOR, missing authz |
| `/object-injection-expert` | PHP object injection, phar deserialization |
| `/ssrf-expert` | Server-side request forgery, cloud metadata access |
| `/qa-triage` | Validate and submit findings |
| `/poc-creator` | Analyze changelogs for security fixes and create PoCs |

## Three-Phase Workflow

### Phase 1: Target Research

Find plugins worth analyzing:
1. `wpguard_search(query="...", min_installs=500)`
2. `wpguard_plugin_info(slug="...")` for each result
3. `wpguard_scope_check_plugin(...)` to verify Wordfence eligibility
4. `wpguard_download(slug="...", extract=true)` for eligible plugins
5. `wpguard_scan_state(add_pending=[...])` to queue for analysis

### Phase 2: Security Research

Find and validate vulnerabilities:
1. `wpguard_scan_state(current_plugin="...")` to track progress
2. Read PHP files looking for:
   - SQL injection (unsanitized `$wpdb->query`)
   - XSS (unescaped output)
   - File upload (missing validation)
   - Auth bypass (missing capability checks)
3. When finding is discovered:
   - `wpguard_finding_create(...)` with CVSS details
   - `wpguard_sandbox_install_plugin(slug, version)`
   - `wpguard_sandbox_request(method, path, data, auth)` to test PoC
4. `wpguard_scan_state(add_scanned="...")` when complete

### Phase 3: QA & Notification

Validate and report findings:
1. `wpguard_finding_list(status="draft")`
2. For each finding:
   - Verify CVSS score calculation
   - Reproduce in sandbox
   - `wpguard_scope_check_finding(...)` for final eligibility
   - `wpguard_finding_update(finding_id, status="validated")`
3. `wpguard_discord_notify_finding(finding_id, mention="@everyone")`
4. `wpguard_discord_notify_summary(title="Daily Summary")`

## Wordfence Bounty Scope

### Vulnerability Tiers & Installation Requirements

| Tier | Min Installs | Vulnerabilities |
|------|--------------|-----------------|
| **High Threat** | 25 | RCE, File Upload/Read/Delete, Options Update, Auth Bypass → Admin, Priv Esc → Admin |
| **Common/Dangerous** | 500 | SQL Injection, Stored XSS |
| **Standard** | 50,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, PHP Object Injection |
| **Resourceful** | 10,000 | Same as Standard |
| **1337** | 500 | Same as Standard |

### Authentication Constraints

**In Scope:** Unauthenticated, Subscriber, Customer, Contributor, Author

**Out of Scope:** Editor, Administrator

### Excluded Vendors

WordPress Core, Automattic (Jetpack, WooCommerce, Akismet), Facebook, Google, Siteground, Yoast

See [WORDFENCE_SCOPE.md](WORDFENCE_SCOPE.md) for complete program rules.

## Requirements

- Python 3.9+
- `requests` library
- `mcp` library (for MCP server functionality)
- `svn` command-line tool (optional, for SVN downloads and change tracking)
- `tmux` (required for pipeline automation and background watch mode)
- `Docker` (required for WordPress sandbox testing)
- `claude` CLI (required for pipeline automation)

## Playwright MCP Integration (Browser Automation)

For browser-based PoC testing (XSS validation, UI interactions), you can integrate the Playwright MCP plugin with Claude Code.

### Installation

```bash
# Install the Playwright MCP plugin globally
npm install -g @anthropic/mcp-plugin-playwright

# Install Playwright browsers
npx playwright install chromium
```

### ARM64/aarch64 Workaround (Raspberry Pi, Apple Silicon, etc.)

Chrome is not available for aarch64 architecture. Use Chromium instead and create a symlink so Playwright can find it:

```bash
# Install Chromium via system package manager
# On Debian/Ubuntu/Raspberry Pi OS:
sudo apt install chromium-browser

# On Arch Linux:
sudo pacman -S chromium

# On macOS with Homebrew (Apple Silicon):
brew install --cask chromium
```

Create symlink to make Chromium available where Playwright expects Chrome:

```bash
# Find where Chromium is installed
which chromium-browser  # Debian/Ubuntu
which chromium          # Arch/other

# Create the /opt directory structure Playwright expects
sudo mkdir -p /opt/google/chrome

# Create symlink (adjust source path based on your system)
# For Debian/Ubuntu/Raspberry Pi:
sudo ln -s /usr/bin/chromium-browser /opt/google/chrome/chrome

# For Arch Linux:
sudo ln -s /usr/bin/chromium /opt/google/chrome/chrome

# For macOS (Apple Silicon):
sudo mkdir -p /opt/google/chrome
sudo ln -s /Applications/Chromium.app/Contents/MacOS/Chromium /opt/google/chrome/chrome
```

Set environment variable to use the system Chromium:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/google/chrome/chrome

# Or set in Claude Code's environment
export CHROME_PATH=/opt/google/chrome/chrome
```

Verify the setup:

```bash
# Check symlink works
/opt/google/chrome/chrome --version

# Test Playwright can find it
npx playwright install chromium --dry-run
```

### Creating the Symlink for MCP Plugin

The Playwright MCP plugin may install to a location that Claude Code can't find. Create a symlink to make it accessible:

```bash
# Find where npm installed the plugin
npm root -g
# Example output: /home/user/.nvm/versions/node/v20.10.0/lib/node_modules

# Create symlink in a standard location
sudo ln -s $(npm root -g)/@anthropic/mcp-plugin-playwright/dist/index.js /usr/local/bin/mcp-plugin-playwright

# Or add to PATH in your shell config (~/.bashrc or ~/.zshrc)
export PATH="$PATH:$(npm root -g)/@anthropic/mcp-plugin-playwright/dist"
```

### Adding to Claude Code

```bash
# Add Playwright MCP to Claude Code
claude mcp add playwright -s user -- npx @anthropic/mcp-plugin-playwright

# Verify it was added
claude mcp list
```

### Manual Configuration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@anthropic/mcp-plugin-playwright"]
    }
  }
}
```

### Allow Playwright Tools

Add Playwright tools to your project's `.claude/settings.local.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__plugin_playwright_playwright__browser_navigate",
      "mcp__plugin_playwright_playwright__browser_snapshot",
      "mcp__plugin_playwright_playwright__browser_click",
      "mcp__plugin_playwright_playwright__browser_type",
      "mcp__plugin_playwright_playwright__browser_fill_form",
      "mcp__plugin_playwright_playwright__browser_take_screenshot",
      "mcp__plugin_playwright_playwright__browser_evaluate",
      "mcp__plugin_playwright_playwright__browser_console_messages",
      "mcp__plugin_playwright_playwright__browser_network_requests",
      "mcp__plugin_playwright_playwright__browser_close",
      "mcp__plugin_playwright_playwright__browser_wait_for",
      "mcp__plugin_playwright_playwright__browser_tabs",
      "mcp__plugin_playwright_playwright__browser_install"
    ]
  }
}
```

### Available Playwright Tools

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to a URL |
| `browser_snapshot` | Capture accessibility snapshot (better than screenshot) |
| `browser_click` | Click on an element |
| `browser_type` | Type text into an element |
| `browser_fill_form` | Fill multiple form fields |
| `browser_take_screenshot` | Take a screenshot |
| `browser_evaluate` | Execute JavaScript in page context |
| `browser_console_messages` | Get console messages |
| `browser_network_requests` | Get network requests |
| `browser_wait_for` | Wait for text or timeout |
| `browser_tabs` | Manage browser tabs |
| `browser_close` | Close the browser |
| `browser_install` | Install browser if not present |

### Use Cases for Security Research

1. **XSS Validation**: Navigate to page, inject payload, check for alert/console messages
2. **CSRF PoC**: Fill forms, capture requests, verify token handling
3. **UI-Based Auth Testing**: Test login flows, session handling
4. **Screenshot Evidence**: Capture visual proof of vulnerabilities

### Example: XSS Validation

```python
# Navigate to vulnerable page
browser_navigate(url="http://sandbox:8000/vulnerable-page")

# Take snapshot to find form elements
browser_snapshot()

# Fill form with XSS payload
browser_type(
    element="Search input",
    ref="input#search",
    text="<script>alert('XSS')</script>"
)

# Submit form
browser_click(element="Submit button", ref="button[type=submit]")

# Check for XSS execution
browser_console_messages(level="error")  # Check for CSP violations
browser_evaluate(function="() => window.xssTriggered")  # Check for custom flag
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for legitimate security research and defensive purposes only. Always respect the WordPress plugin repository terms of service and the licenses of individual plugins.
