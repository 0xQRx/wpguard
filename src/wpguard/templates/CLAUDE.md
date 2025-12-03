# WordPressGuard Security Research Project

This is a wpguard security research project for the Wordfence Bug Bounty Program.

## Available Slash Commands

### Core Workflow
- `/target-research` - Find and scope WordPress plugins for analysis
- `/security-research` - Analyze plugins for vulnerabilities (general)
- `/qa-triage` - Validate and submit findings
- `/poc-creator` - Analyze changelogs for security fixes and create PoCs for patched vulnerabilities

### Expert Agents (Deep-Dive Specialists)
- `/file-rce-expert` - File upload, read, write, delete, path traversal → RCE
- `/sqli-expert` - SQL injection in all forms (UNION, blind, second-order)
- `/xss-expert` - Stored, reflected, DOM XSS
- `/auth-expert` - Auth bypass, privilege escalation, IDOR, missing authz
- `/object-injection-expert` - PHP object injection, phar deserialization
- `/ssrf-expert` - Server-side request forgery, cloud metadata access
- `/race-condition-expert` - TOCTOU, database races, double-spend, limit bypass
- `/csrf-expert` - Cross-Site Request Forgery, missing nonce validation
- `/lfi-rfi-expert` - Local/Remote File Inclusion, path traversal
- `/xxe-expert` - XML External Entity injection, SVG/XML processing
- `/deserialization-expert` - JSON/YAML parsing, property injection, type juggling
- `/logic-flaw-expert` - Business logic bugs, payment bypass, workflow manipulation
- `/info-disclosure-expert` - Sensitive data exposure, debug endpoints, user enumeration

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

### Sandbox Management
- `wpguard_sandbox_start` - Start sandbox Docker containers (builds if needed)
- `wpguard_sandbox_stop` - Stop sandbox containers
- `wpguard_sandbox_restart` - Restart sandbox
- `wpguard_sandbox_destroy` - Reset sandbox (removes all data)

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

### Wordfence CVE Database
- `wpguard_cve_download` - Download/refresh vulnerability database
- `wpguard_cve_search` - Search CVEs by plugin slug or keyword
- `wpguard_cve_get` - Get detailed CVE info by ID
- `wpguard_cve_stats` - Get database statistics

### Pipeline Automation
- `wpguard_pipeline_start` - Start automated research pipeline daemon
- `wpguard_pipeline_stop` - Stop the pipeline daemon
- `wpguard_pipeline_status` - Get current pipeline status and progress
- `wpguard_pipeline_pause` - Pause after current stage completes
- `wpguard_pipeline_resume` - Resume paused pipeline
- `wpguard_pipeline_config` - Get/update pipeline configuration
- `wpguard_pipeline_logs` - Get worker output logs
- `wpguard_pipeline_attach` - Get tmux attach command for a stage

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
| Standard Researchers | 50,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, Object Injection |
| Resourceful Researchers | 10,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, Object Injection |
| 1337 Researchers | 500 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, Object Injection |

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

## Pipeline Automation

The pipeline automates the full research workflow with expert agents:

```
target-research → security-research → file-rce-expert → sqli-expert → xss-expert → auth-expert → object-injection-expert → ssrf-expert → race-condition-expert → csrf-expert → lfi-rfi-expert → xxe-expert → deserialization-expert → logic-flaw-expert → info-disclosure-expert → qa-triage
```

Each plugin goes through ALL 13 expert stages sequentially for maximum coverage.

### Starting the Pipeline

```python
# Start overnight continuous run
wpguard_pipeline_start(
    mode="continuous",     # Loop: find targets -> research -> qa -> repeat
    target_count=10,       # Plugins per cycle
    num_iterations=2       # Run security-research + experts twice per plugin (default: 2)
)

# Single cycle (one batch of targets)
wpguard_pipeline_start(mode="single", target_count=5)

# Just find targets (no analysis)
wpguard_pipeline_start(mode="targets-only", target_count=20)

# More thorough analysis (3 iterations)
wpguard_pipeline_start(num_iterations=3)
```

### Monitoring Progress

```python
# Check status
wpguard_pipeline_status()

# Get detailed status with recent worker output
wpguard_pipeline_status(include_logs=True)

# Get logs for a specific stage
wpguard_pipeline_logs(stage="security-research", lines=100)

# Attach to watch a worker live (returns tmux command)
wpguard_pipeline_attach(stage="security-research")
# Then in terminal: tmux attach -t wpguard_security_research_abc123
```

### Controlling the Pipeline

```python
# Pause (current stage finishes, next won't start)
wpguard_pipeline_pause()

# Resume paused pipeline
wpguard_pipeline_resume()

# Change configuration mid-run
wpguard_pipeline_config(num_iterations=3)

# Stop the pipeline
wpguard_pipeline_stop()

# Force stop (kills workers immediately)
wpguard_pipeline_stop(force=True)
```

### Configuration Options

#### `num_iterations` (default: 2)

Number of times to run security-research + all 13 experts per plugin:
- **`num_iterations=1`**: Single pass (faster, less thorough)
- **`num_iterations=2`**: Two passes (default, good balance)
- **`num_iterations=3`**: Three passes (more thorough)

#### `deferred_qa` (default: true)

Controls when QA runs:
- **`deferred_qa=true`** (default): QA runs once after all iterations complete
- **`deferred_qa=false`**: QA runs after each iteration

### Pipeline Flow

With `num_iterations=2, deferred_qa=true` (default):
```
Iteration 1: security-research → all 13 experts
Iteration 2: security-research → all 13 experts
Final:       qa-triage (runs once, reviews all findings)
→ Next plugin
```

### Pipeline State Files

- `wpguard_pipeline_state.json` - Daemon state, worker status, progress
- `wpguard_daemon.pid` - Process ID file
- `wpguard_pipeline_logs/` - Command scripts and daemon logs
