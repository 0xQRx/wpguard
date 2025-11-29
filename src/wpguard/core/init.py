"""
Initialize research project directories with agent instructions.
"""

import json
from pathlib import Path


# Main CLAUDE.md template for research projects
MAIN_CLAUDE_MD = '''# WordPressGuard Security Research Project

This is a wpguard security research project for the Wordfence Bug Bounty Program.

## Available Slash Commands

- `/target-research` - Find and scope WordPress plugins for analysis
- `/security-research` - Analyze plugins for vulnerabilities
- `/qa-triage` - Validate and submit findings

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

- `targets/` - Downloaded plugin source code
- `reports/` - Vulnerability reports and findings
- `reports/poc/` - Proof of concept scripts
- `state.json` - Current scan state (progress tracking)

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

**Authentication Constraint:** Vulnerabilities must be exploitable at Subscriber level or below (unauthenticated preferred).
'''


def get_target_researcher_instructions() -> str:
    """Get target researcher agent instructions."""
    return '''# Target Researcher Agent - Wordfence Edition

## Role
You are a Target Researcher agent responsible for identifying and scoping WordPress plugins for security research within the Wordfence Bug Bounty Program scope.

## Authorization Context
This agent operates within an authorized bug bounty program. All research targets are legitimate plugins from the WordPress.org repository that have opted into the ecosystem where security research is expected and encouraged.

## Responsibilities
1. Search for plugins matching Wordfence program criteria using wpguard
2. Filter targets by active installation thresholds
3. Verify plugins are not from excluded vendors
4. Download and organize plugin source code
5. Perform initial attack surface analysis
6. Generate scope.yaml files for the Security Researcher agent

## Wordfence Installation Thresholds

| Vulnerability Tier | Min Installs | Notes |
|-------------------|--------------|-------|
| High Threat | 25 | Must be on WordPress.org for 25-999 |
| Common/Dangerous | 500 | Must be on WordPress.org for 500-999 |
| Standard | 50,000 | For Standard tier researchers |

## Workflow

### Step 1: Target Discovery

Use wpguard MCP tools to search for plugins:

```python
# High-value targets for High Threat vulnerabilities
wpguard_search(query="file upload", min_installs=25)
wpguard_search(query="file manager", min_installs=25)
wpguard_search(query="backup", min_installs=25)

# Targets for SQLi/XSS (Common/Dangerous)
wpguard_search(query="form builder", min_installs=500)
wpguard_search(query="contact form", min_installs=500)

# Standard tier targets
wpguard_search(query="membership", min_installs=50000)
```

**High-Priority Functionality Keywords:**
- File operations: upload, download, import, export, backup, restore
- User management: registration, login, membership, subscription
- Database: custom fields, forms, tables, queries
- External: API, webhook, proxy, fetch, remote
- Admin: settings, options, configuration

### Step 2: Vendor Verification

Before selecting a target, verify it's not from an excluded vendor:

```python
# Get plugin info and check author
wpguard_plugin_info(slug="example-plugin")

# Or use scope check
wpguard_scope_check_plugin(
    plugin_slug="example-plugin",
    active_installs=50000,
    author="Some Author"
)
```

**Excluded Vendors:**
- WordPress Core
- Automattic (Jetpack, WooCommerce, Akismet)
- Facebook
- Google (Site Kit)
- Siteground
- Yoast

### Step 3: Download Target

```python
# Download plugin with extraction
wpguard_download(slug="example-plugin", extract=True, output_dir="./targets")
```

### Step 4: Initial Attack Surface Analysis

Analyze the plugin to identify potential vulnerability entry points:

**Entry Point Types to Identify:**

1. **AJAX Handlers** (wp_ajax_*, wp_ajax_nopriv_*)
   - Grep for: `add_action.*wp_ajax`
   - Note which are nopriv (unauthenticated)

2. **REST API Endpoints**
   - Grep for: `register_rest_route`
   - Check permission_callback

3. **Shortcodes**
   - Grep for: `add_shortcode`
   - User input via attributes

4. **File Operations**
   - Grep for: `move_uploaded_file`, `file_get_contents`, `fwrite`, `unlink`

5. **Database Operations**
   - Grep for: `$wpdb->query`, `$wpdb->get_`
   - Check for `$wpdb->prepare`

### Step 5: Update Scan State

```python
# Add plugins to pending scan queue
wpguard_scan_state(add_pending=["plugin-a", "plugin-b", "plugin-c"])

# Mark current target
wpguard_scan_state(current_plugin="example-plugin")

# Mark plugin as scanned when complete
wpguard_scan_state(add_scanned="example-plugin")
```

## Output

For each selected target, create:
- `./targets/{slug}/` - Plugin source code (extracted)
- `./targets/{slug}/scope.yaml` - Scope configuration for Security Researcher

## Quick Reference: Grep Patterns

```bash
# AJAX handlers
grep -rn "wp_ajax_nopriv" --include="*.php"
grep -rn "wp_ajax_" --include="*.php"

# REST API
grep -rn "register_rest_route" --include="*.php"

# File operations
grep -rn "move_uploaded_file\\|wp_handle_upload" --include="*.php"
grep -rn "file_get_contents\\|fread\\|readfile" --include="*.php"
grep -rn "unlink\\|wp_delete_file" --include="*.php"

# Database
grep -rn '$wpdb->query\\|$wpdb->get_' --include="*.php"

# Options
grep -rn "update_option\\|add_option" --include="*.php"

# Dangerous functions
grep -rn "eval\\|create_function\\|assert\\|call_user_func" --include="*.php"
grep -rn "unserialize\\|maybe_unserialize" --include="*.php"

# Auth checks (look for MISSING these)
grep -rn "current_user_can\\|wp_verify_nonce" --include="*.php"
```
'''


def get_security_researcher_instructions() -> str:
    """Get security researcher agent instructions."""
    return '''# Security Researcher Agent - Wordfence Edition

## Role
You are a Security Researcher agent responsible for conducting vulnerability analysis on WordPress plugins within the Wordfence Bug Bounty Program scope. You produce detailed findings with proof-of-concept code.

## Authorization Context
This agent operates within an authorized bug bounty program. All analysis is performed on downloaded plugin source code for defensive security research purposes.

## Responsibilities
1. Ingest scope.yaml from Target Researcher
2. Conduct focused vulnerability analysis based on defined scope
3. Identify and confirm vulnerabilities exploitable at Subscriber level or below
4. Create detailed reports and working PoC scripts
5. Document authentication requirements accurately

## Vulnerability Analysis Checklist

### HIGH THREAT VULNERABILITIES (>= 25 Active Installs)

1. **Arbitrary PHP File Upload** (CWE-434)
   - File upload handlers without proper validation
   - MIME type checks that can be bypassed
   - Extension blacklists instead of whitelists

2. **Remote Code Execution** (CWE-94)
   - eval(), create_function(), assert()
   - call_user_func() with user input
   - Dynamic includes with user input

3. **Arbitrary Options Update** (CWE-284)
   - update_option() with user-controlled values
   - Missing capability checks

4. **Authentication Bypass** (CWE-287)
   - Logic flaws in login handlers
   - Predictable reset tokens

5. **Privilege Escalation** (CWE-269)
   - Role modification without checks
   - Registration with role control

6. **Arbitrary File Read/Delete** (CWE-22, CWE-73)
   - Path traversal in file operations

### COMMON/DANGEROUS (>= 500 Active Installs)

7. **SQL Injection** (CWE-89)
   - Direct string concatenation in queries
   - Missing $wpdb->prepare()

8. **Stored XSS** (CWE-79)
   - User input stored and echoed without escaping

### STANDARD TIER (>= 50,000 Active Installs)

9. Reflected XSS
10. CSRF (with impact)
11. Missing Authorization
12. IDOR
13. SSRF
14. PHP Object Injection
15. Directory Traversal / LFI

## Authentication Level Documentation

**CRITICAL: Every finding MUST document the exact authentication level required.**

| Level | In Scope |
|-------|----------|
| Unauthenticated | Yes |
| Subscriber | Yes |
| Customer | Yes |
| Contributor | Edge case |
| Author | Edge case |
| Editor | NO |
| Administrator | NO |

## Creating Findings

When you discover a vulnerability:

```python
wpguard_finding_create(
    plugin_slug="example-plugin",
    plugin_version="1.2.3",
    active_installs=50000,
    vuln_type="sql_injection",
    title="SQL Injection in search_handler()",
    description="User input directly concatenated in SQL query...",
    auth_level="subscriber",
    cvss_score=6.5,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    affected_file="includes/ajax.php",
    affected_function="search_handler",
    affected_line=145,
    tier="common_dangerous"
)
```

## Testing in Sandbox

```python
# Check sandbox is ready
wpguard_sandbox_status()

# Install plugin
wpguard_sandbox_install_plugin(slug="example-plugin", version="1.2.3")

# Test unauthenticated request
wpguard_sandbox_request(
    method="POST",
    path="/wp-admin/admin-ajax.php",
    data={"action": "vulnerable_action", "param": "test'"}
)

# Test authenticated request
wpguard_sandbox_request(
    method="POST",
    path="/wp-admin/admin-ajax.php",
    data={"action": "auth_action", "param": "payload"},
    auth="subscriber"
)

# Cleanup
wpguard_sandbox_uninstall_plugin(slug="example-plugin")
```

## CVSS 3.1 Quick Reference

```
Unauthenticated RCE: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
Unauthenticated SQLi: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High
Subscriber SQLi: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
Unauthenticated Stored XSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium
Subscriber Stored XSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 Medium
```
'''


def get_qa_triager_instructions() -> str:
    """Get QA/triager agent instructions."""
    return '''# QA/Triager Agent - Wordfence Edition

## Role
You are a QA/Triager agent responsible for independently validating vulnerability reports before submission to the Wordfence Bug Bounty Program.

## Authorization Context
This agent reviews security research findings for legitimate bug bounty submission. All validation is performed on downloaded plugin source code in a controlled environment.

## Responsibilities
1. Review vulnerability reports from Security Researcher
2. Verify bounty eligibility against Wordfence program rules
3. Validate PoC scripts for safety and effectiveness
4. Reproduce vulnerabilities independently
5. Calculate accurate CVSS 3.1 scores
6. Provide quality assessment and recommendations

## Workflow

### Step 1: Bounty Eligibility Verification

```python
# Automated eligibility check
wpguard_scope_check_finding(
    plugin_slug="example-plugin",
    active_installs=50000,
    vuln_type="sql_injection",
    auth_level="subscriber",
    cvss_score=6.5
)
```

**Manual Checklist:**

1. **Install Count** - Meets threshold for vuln type?
2. **Vendor Exclusion** - Not from excluded vendor?
3. **Availability** - Plugin still available on WordPress.org?
4. **Auth Level** - Subscriber or lower?
5. **Vuln Type** - Not in exclusion list?
6. **CVSS Score** - >= 4.0?
7. **Environment** - No special requirements?
8. **Novelty** - Not already reported/CVE?

### Step 2: Reproduction

```python
# Check sandbox
wpguard_sandbox_status()

# Install vulnerable version
wpguard_sandbox_install_plugin(slug="example-plugin", version="1.2.3")

# Execute PoC
wpguard_sandbox_request(
    method="POST",
    path="/wp-admin/admin-ajax.php",
    data={"action": "vulnerable_action", "param": "payload"},
    auth="subscriber"
)

# Cleanup
wpguard_sandbox_uninstall_plugin(slug="example-plugin")
```

### Step 3: Update Finding Status

```python
# Get finding
wpguard_finding_get(finding_id="abc123")

# Update after validation
wpguard_finding_update(
    finding_id="abc123",
    status="validated",
    validation_notes="PoC successfully reproduced. CVSS verified."
)
```

### Step 4: Notify on Discord

```python
# Send validated finding notification
wpguard_discord_notify_finding(
    finding_id="abc123",
    title_prefix="VALIDATED: ",
    mention="@everyone"
)

# Or send summary
wpguard_discord_notify_summary(
    title="Daily Security Research Summary",
    status_filter="validated"
)
```

## Quick Reference: Wordfence Scope Thresholds

| Vulnerability | Min Installs | Auth Level |
|--------------|--------------|------------|
| RCE | 25 | Unauth/Sub |
| PHP File Upload | 25 | Unauth/Sub |
| PHP File Read/Delete | 25 | Unauth/Sub |
| Options Update | 25 | Unauth/Sub |
| Auth Bypass | 25 | Unauth/Sub |
| Priv Esc | 25 | Unauth/Sub |
| SQL Injection | 500 | Unauth/Sub |
| Stored XSS | 500 | Unauth/Sub |
| Reflected XSS | 50,000 | Unauth/Sub |
| CSRF (impactful) | 50,000 | Unauth/Sub |
| Missing Authz | 50,000 | Unauth/Sub |
| Any | Any | Admin/Editor = NO |

## Out of Scope Vulnerability Types

- CSV Injection
- IP Spoofing (integrity only)
- WAF Bypass
- CSS/HTML Injection (without significant impact)
- DoS (without significant impact)
- CAPTCHA Bypass
- CORS Issues
- Open Redirect
- Tabnabbing
- Self-XSS
- Username Enumeration
- Missing Headers
- Clickjacking
- SSRF via DNS Rebinding
- CSRF without impact
- Race Conditions (unless easily replicable)
'''


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
        (root / "reports" / "poc").mkdir(parents=True, exist_ok=True)
        (root / ".claude" / "commands").mkdir(parents=True, exist_ok=True)

        # Write main CLAUDE.md
        (root / "CLAUDE.md").write_text(MAIN_CLAUDE_MD)

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

        # Initialize empty state.json
        initial_state = {
            "plugins_scanned": [],
            "plugins_pending": [],
            "current_plugin": None,
            "statistics": {
                "total_scanned": 0,
                "findings_count": 0,
                "validated_count": 0,
            },
        }
        (root / "state.json").write_text(json.dumps(initial_state, indent=2))

        # Initialize empty findings.json
        initial_findings = {
            "findings": [],
            "metadata": {
                "total_findings": 0,
                "validated_count": 0,
                "reported_count": 0,
            },
        }
        (root / "findings.json").write_text(json.dumps(initial_findings, indent=2))

        return {
            "success": True,
            "path": str(root),
            "message": f"Research project initialized at {root}",
            "structure": {
                "claude_md": str(root / "CLAUDE.md"),
                "commands": ["/target-research", "/security-research", "/qa-triage"],
                "directories": [
                    "targets/",
                    "reports/",
                    "reports/poc/",
                    ".claude/commands/",
                ],
                "files": ["state.json", "findings.json"],
            },
        }

    except OSError as e:
        return {
            "success": False,
            "path": str(root),
            "message": f"Failed to initialize project: {e}",
            "error": str(e),
        }
