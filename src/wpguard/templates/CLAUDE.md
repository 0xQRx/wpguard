# WordPressGuard Security Research Project

This is a wpguard security research project for the Wordfence Bug Bounty Program.

## Available Slash Commands

- `/target-research` - Find and scope WordPress plugins for analysis
- `/security-research` - Analyze plugins for vulnerabilities
- `/qa-triage` - Validate and submit findings
- `/poc-creator` - Analyze changelogs for security fixes and create PoCs for patched vulnerabilities

## MCP Tools Available

All `wpguard_*` tools are available via MCP:

### Plugin Discovery
- `wpguard_search` - Search WordPress plugin repository
- `wpguard_plugin_info` - Get detailed plugin information
- `wpguard_download` - Download a plugin
- `wpguard_bulk_download` - Download multiple plugins
- `wpguard_svn_log` - View SVN commit history
- `wpguard_plugin_versions` - List all available versions

### Sandbox Testing
- `wpguard_sandbox_status` - Check WordPress sandbox connectivity
- `wpguard_sandbox_install_plugin` - Install plugin in sandbox
- `wpguard_sandbox_uninstall_plugin` - Remove plugin from sandbox
- `wpguard_sandbox_request` - Execute HTTP request against sandbox
- `wpguard_sandbox_wp_cli` - Run WP-CLI commands
- `wpguard_sandbox_get_nonce` - Get WordPress nonce for actions

### Scope Validation
- `wpguard_scope_check_plugin` - Check if plugin is in scope
- `wpguard_scope_check_finding` - Validate finding eligibility
- `wpguard_scope_get_vulns` - Get in-scope vuln types for install count

### Finding Management
- `wpguard_finding_create` - Create a new finding
- `wpguard_finding_update` - Update finding status/details
- `wpguard_finding_get` - Get finding by ID
- `wpguard_finding_list` - List findings with filters
- `wpguard_finding_delete` - Delete a finding
- `wpguard_finding_stats` - Get finding statistics
- `wpguard_scan_state` - Manage scan progress state

### Discord Notifications
- `wpguard_discord_notify_finding` - Send finding alert
- `wpguard_discord_notify_summary` - Send findings summary
- `wpguard_discord_send_message` - Send simple message

## Directory Structure

```
project/
├── targets/                    # Downloaded plugin source code
│   └── {plugin_slug}/
│       └── extracted/
├── reports/                    # Vulnerability reports and PoCs
│   └── {plugin_slug}/
│       ├── finding_001.md      # Vulnerability report
│       └── poc.py              # Proof of concept script
├── wpguard_scan_state.json     # Scan state (progress tracking)
└── wpguard_findings.json       # All findings database
```

## Quick Start

```bash
# Start target research
/target-research

# Or manually search and analyze
"Search for file upload plugins with 500+ installs and analyze for SQLi"

# Check scan state
"Show current scan state and pending plugins"
```

## Environment Requirements

- WordPress sandbox at 172.17.0.1:8000 (container: wp_app)
- DISCORD_WEBHOOK_URL environment variable (optional, for notifications)

## Wordfence Bounty Tiers

| Tier | Min Installs | Vulnerability Types |
|------|--------------|---------------------|
| High Threat | 25 | RCE, File Upload/Read/Delete, Options Update, Auth Bypass, Priv Esc |
| Common/Dangerous | 500 | SQL Injection, Stored XSS |
| Standard | 50,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, Object Injection |

## Authentication Levels to Audit

**IMPORTANT: Audit ALL vulnerabilities for ALL authentication levels from Unauthenticated up to Author.**

| Level | Username | Password | In Scope | Notes |
|-------|----------|----------|----------|-------|
| Unauthenticated | - | - | YES | Highest priority |
| Subscriber | subscriber | subscriber | YES | Default registered user |
| Customer | customer | customer | YES | WooCommerce customer role |
| Contributor | contributor | contributor | YES | Can write posts (not publish) |
| Author | author | author | YES | Can publish own posts |
| Editor | - | - | NO | Out of scope |
| Administrator | - | - | NO | Out of scope |

**Key Point:** Always test each vulnerability at EVERY applicable auth level. A finding exploitable by Author is still valuable - document it with the correct auth_level.
