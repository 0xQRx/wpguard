How WordPressGuard Works - Complete Workflow

  System Architecture

  ┌─────────────────────────────────────────────────────────────────┐
  │                        Claude Code                               │
  │              (Orchestrator / Decision Maker)                     │
  │                                                                  │
  │  Uses CLAUDE.md instructions from:                               │
  │  - security-research/agents/target-researcher/CLAUDE.md          │
  │  - security-research/agents/security-researcher/CLAUDE.md        │
  │  - security-research/agents/qa-triager/CLAUDE.md                 │
  └─────────────────────────┬───────────────────────────────────────┘
                            │
                            │ MCP Protocol
                            ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                     wpguard MCP Server                           │
  │                   (32 tools available)                           │
  │                                                                  │
  │  Plugin Tools:        Sandbox Tools:       Finding Tools:        │
  │  - search             - status             - create              │
  │  - plugin_info        - install_plugin     - update              │
  │  - download           - uninstall_plugin   - get                 │
  │  - bulk_download      - request            - list                │
  │  - svn_log            - wp_cli             - delete              │
  │  - plugin_versions    - get_nonce          - stats               │
  │                                                                  │
  │  Scope Tools:         Discord Tools:       State Tools:          │
  │  - check_plugin       - notify_finding     - scan_state          │
  │  - check_finding      - notify_summary     - watch_*             │
  │  - get_vulns          - send_message                             │
  └─────────────────────────┬───────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  WordPress   │  │   JSON       │  │   Discord    │
  │  Sandbox     │  │   State      │  │   Webhook    │
  │  (Docker)    │  │   Files      │  │              │
  │ 172.17.0.1   │  │ findings.json│  │  Alerts &    │
  │    :8000     │  │ state.json   │  │  Summaries   │
  └──────────────┘  └──────────────┘  └──────────────┘

  The Three-Phase Workflow

  Phase 1: Target Research

  Goal: Find plugins worth analyzing

  You: "Find plugins with file upload functionality, min 500 installs"

  Claude Code will:
  1. wpguard_search(query="file upload", min_installs=500)
  2. wpguard_plugin_info(slug="...") for each result
  3. wpguard_scope_check_plugin(...) to verify Wordfence eligibility
  4. wpguard_download(slug="...", extract=true) for eligible plugins
  5. wpguard_scan_state(add_pending=["plugin-a", "plugin-b"])
  6. Read code and identify entry points (AJAX, REST API, forms)
  7. Generate scope.yaml for security analysis

  Phase 2: Security Research

  Goal: Find and validate vulnerabilities

  Claude Code will:
  1. wpguard_scan_state(current_plugin="example-plugin")
  2. Read PHP files looking for:
     - SQL injection (unsanitized $wpdb->query)
     - XSS (unescaped output)
     - File upload (missing validation)
     - Auth bypass (missing capability checks)
  3. When finding is discovered:
     - wpguard_finding_create(...) with details
     - Test PoC against sandbox:
       - wpguard_sandbox_install_plugin(slug, version)
       - wpguard_sandbox_request(method, path, data, auth)
  4. wpguard_scan_state(add_scanned="example-plugin")

  Phase 3: QA & Notification

  Goal: Validate and report findings

  Claude Code will:
  1. wpguard_finding_list(status="draft")
  2. For each finding:
     - Verify CVSS score calculation
     - Reproduce in sandbox
     - wpguard_scope_check_finding(...) for final eligibility
     - wpguard_finding_update(finding_id, status="validated")
  3. wpguard_discord_notify_finding(finding_id, mention="@everyone")
  4. wpguard_discord_notify_summary(title="Daily Summary")

  ---
  How to Kick Off a Test Workflow

  Prerequisites

  1. WordPress sandbox running at 172.17.0.1:8000 (container: wp_app)
  2. DISCORD_WEBHOOK_URL environment variable set
  3. wpguard MCP server configured in Claude Code

  Option 1: Full Automated Research

  claude "You are a security researcher for the Wordfence Bug Bounty Program. 
  Search for WordPress plugins with 'contact form' functionality that have 
  500-5000 active installs. For each eligible plugin:
  1. Download and analyze the source code
  2. Look for SQL injection and stored XSS vulnerabilities  
  3. Test any findings against the WordPress sandbox
  4. Create findings for confirmed vulnerabilities
  5. Notify me on Discord when you find something validated"

  Option 2: Single Plugin Analysis

  claude "Analyze the WordPress plugin 'example-plugin-slug' for security 
  vulnerabilities. Check if it's in scope for Wordfence bounty, download it,
  analyze for SQL injection, XSS, and file upload vulnerabilities. Test any 
  findings in the sandbox and create finding reports."

  Option 3: Quick Test of the System

  # Test individual MCP tools to verify everything works:
  claude "Test the wpguard system:
  1. Search for 'security' plugins with wpguard_search
  2. Check sandbox status with wpguard_sandbox_status  
  3. Get scope info for 500 installs with wpguard_scope_get_vulns
  4. Show current scan state with wpguard_scan_state
  5. Send a test message to Discord"

  Option 4: Resume Previous Scan

  claude "Check the current scan state and continue analyzing any pending 
  plugins. For each plugin in the pending queue, perform security analysis 
  and update the state when complete."

  ---
  Quick Reference: Key MCP Tools

  | Task               | Tool                                                |
  |--------------------|-----------------------------------------------------|
  | Find plugins       | wpguard_search(query, min_installs)                 |
  | Check eligibility  | wpguard_scope_check_plugin(slug, installs, author)  |
  | Download plugin    | wpguard_download(slug, extract=true)                |
  | Install to sandbox | wpguard_sandbox_install_plugin(slug, version)       |
  | Test HTTP request  | wpguard_sandbox_request(method, path, data, auth)   |
  | Save finding       | wpguard_finding_create(plugin_slug, vuln_type, ...) |
  | Notify Discord     | wpguard_discord_notify_finding(finding_id)          |
  | Track progress     | wpguard_scan_state(current_plugin="...")            |
