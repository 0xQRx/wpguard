# Multi-Agent Security Research System - Wordfence Edition

A three-stage pipeline for WordPress plugin vulnerability research aligned with the **Wordfence Bug Bounty Program** scope.

```
Target Researcher → Security Researcher → Report QA/Triager
```

## Quick Start

```bash
# 1. Search for targets
./security-research/run_pipeline.sh search "file upload" --min-installs 25

# 2. Run full pipeline on a plugin
./security-research/run_pipeline.sh pipeline my-plugin --tier high_threat

# 3. Or run stages individually
./security-research/run_pipeline.sh download my-plugin
./security-research/run_pipeline.sh analyze my-plugin
./security-research/run_pipeline.sh validate my-plugin
```

---

## Wordfence Bounty Scope Summary

### Vulnerability Tiers & Installation Requirements

| Tier | Min Installs | Vulnerabilities | Priority |
|------|--------------|-----------------|----------|
| **High Threat** | 25 | RCE, PHP File Upload/Read/Delete, Options Update, Auth Bypass → Admin, Priv Esc → Admin | Highest Bounty |
| **Common/Dangerous** | 500 | SQL Injection, Stored XSS | High Bounty |
| **Standard** | 50,000 | Reflected XSS, CSRF, Missing Auth, IDOR, SSRF, PHP Object Injection, Path Traversal, LFI/RFI, Info Disclosure | Standard Bounty |

### Authentication Constraints

**In Scope:**
- Unauthenticated (no login required)
- Subscriber (WordPress default minimal role)
- Customer (WooCommerce customer role)

**Out of Scope (PR:H):**
- Editor, Shop Manager, Administrator
- Any capability requiring `unfiltered_html`

### Excluded Vendors
- WordPress Core
- Automattic (Jetpack, WooCommerce, Akismet)
- Facebook, Google, Siteground, Yoast

See `WORDFENCE_SCOPE.md` for complete program rules.

---

## Directory Structure

```
/security-research/
├── agents/
│   ├── target-researcher/
│   │   └── CLAUDE.md           # Target discovery & scoping
│   ├── security-researcher/
│   │   └── CLAUDE.md           # Vulnerability analysis
│   └── qa-triager/
│       └── CLAUDE.md           # Report validation
├── targets/
│   └── {plugin-slug}/
│       ├── extracted/{version}/ # Plugin source code
│       ├── svn/                 # SVN checkout
│       └── scope.yaml           # Analysis scope
├── reports/
│   └── {plugin-slug}/
│       ├── vulnerability_report.md
│       ├── technical_analysis.md
│       ├── poc/                 # Proof-of-concept scripts
│       └── validation/          # QA validation results
├── config/
│   ├── wordfence_scope.yaml     # Machine-readable scope
│   └── excluded_vendors.txt     # Vendor exclusion list
└── run_pipeline.sh              # Pipeline orchestration
```

---

## Agent Overview

### Agent 1: Target Researcher

**Role:** Identify and scope WordPress plugins for security research.

**Responsibilities:**
1. Search plugins using wpguard with install count filters
2. Verify plugins are not from excluded vendors
3. Download plugin source code (ZIP + SVN)
4. Perform initial attack surface analysis
5. Generate scope.yaml for Security Researcher

**wpguard Integration:**
```bash
# Search for high-threat targets (>=25 installs)
wpguard search "file upload" --min-installs 25

# Download for analysis
wpguard download {slug} --svn --extract
```

**Output:** `./targets/{slug}/scope.yaml`

See: `security-research/agents/target-researcher/CLAUDE.md`

---

### Agent 2: Security Researcher

**Role:** Conduct vulnerability analysis and produce findings with PoC.

**Responsibilities:**
1. Ingest scope.yaml from Target Researcher
2. Analyze for in-scope vulnerability types
3. Document authentication requirements accurately
4. Create detailed reports and working PoC scripts

**Vulnerability Checklist:**

#### High Threat (>=25 installs)
- Arbitrary PHP File Upload/Read/Delete
- Remote Code Execution
- Arbitrary Options Update
- Authentication Bypass to Admin
- Privilege Escalation to Admin

#### Common/Dangerous (>=500 installs)
- SQL Injection
- Stored XSS

#### Standard (>=50,000 installs)
- Reflected XSS, CSRF, Missing Authorization
- IDOR, SSRF, PHP Object Injection
- Path Traversal, LFI/RFI, Information Disclosure

**Output:**
- `./reports/{slug}/vulnerability_report.md`
- `./reports/{slug}/technical_analysis.md`
- `./reports/{slug}/poc/poc.py`

See: `security-research/agents/security-researcher/CLAUDE.md`

---

### Agent 3: QA/Triager

**Role:** Validate reports and verify bounty eligibility.

**Responsibilities:**
1. Complete bounty eligibility checklist
2. Verify CVSS 3.1 score accuracy
3. Review PoC for safety and effectiveness
4. Reproduce vulnerabilities independently
5. Provide quality assessment

**Bounty Eligibility Checklist:**
```
[ ] Install count meets threshold for vuln type
[ ] Plugin not from excluded vendor
[ ] Plugin available for download
[ ] Auth level is Subscriber/Customer or lower
[ ] Vulnerability type is in scope
[ ] CVSS score >= 4.0
[ ] Works on standard WordPress config
[ ] Not a known/duplicate CVE
```

**Output:** `./reports/{slug}/validation/validation_report.md`

See: `security-research/agents/qa-triager/CLAUDE.md`

---

## Workflow

### Option 1: Full Pipeline

```bash
./security-research/run_pipeline.sh pipeline {plugin-slug} --tier {tier}
```

Runs all three stages automatically:
1. Download plugin with wpguard
2. Generate scope and analyze for vulnerabilities
3. Validate findings and check bounty eligibility

### Option 2: Manual Stages

```bash
# Stage 1: Target Research
cd security-research/agents/target-researcher
claude "Find WordPress plugins with file upload functionality, min 25 installs"

# Stage 2: Security Analysis
cd security-research/agents/security-researcher
claude "Analyze ./targets/my-plugin/ for vulnerabilities per scope.yaml"

# Stage 3: QA/Triage
cd security-research/agents/qa-triager
claude "Validate report at ./reports/my-plugin/"
```

### Option 3: Using MCP Tools Directly

When running with Claude Code's MCP integration:

```bash
# Search for targets
wpguard_search("file upload", min_installs=25)

# Get plugin info
wpguard_plugin_info("my-plugin")

# Download plugin
wpguard_download("my-plugin", svn=True, extract=True)

# Check SVN history
wpguard_svn_log("my-plugin", limit=10)
```

---

## Report Formats

### Vulnerability Report Template

```markdown
# Vulnerability Report: {Plugin Name}

## Summary
| Field | Value |
|-------|-------|
| Plugin | {name} |
| Slug | {slug} |
| Version | {version} |
| Active Installs | {count} |
| Vulnerability Type | {type} |
| Severity | {Critical/High/Medium} |
| CVSS 3.1 Score | {score} |
| CVSS Vector | CVSS:3.1/AV:N/AC:L/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{} |
| Authentication Required | None / Subscriber / Customer |

## Description
{Clear description}

## Affected Component
- File: {path}
- Function: {name}
- Line: {number}

## Root Cause
{Technical explanation}

## Proof of Concept
{PoC details and usage}

## Impact
{Security impact}

## Remediation
{Fix recommendation}
```

### Scope File Template (scope.yaml)

```yaml
target:
  slug: "plugin-slug"
  version: "1.0.0"
  active_installs: 50000
  source_path: "./targets/plugin-slug/extracted/1.0.0/"

initial_analysis:
  entry_points:
    - path: "includes/ajax.php"
      type: "ajax_nopriv"
      auth_required: false

  dangerous_sinks:
    - file: "includes/db.php"
      sink_type: "sql_query"
      sanitization: "none"

scope:
  applicable_tiers:
    - common_dangerous
    - standard
  vulnerability_families:
    - sql_injection
    - stored_xss
    - reflected_xss
  auth_constraint: "subscriber_or_lower"

output:
  report_path: "./reports/plugin-slug/"
```

---

## CVSS 3.1 Quick Reference

### Common WordPress Vectors

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| Unauth RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| Unauth SQLi | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 High |
| Subscriber SQLi | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 Medium |
| Unauth Stored XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 Medium |
| Subscriber Stored XSS | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 Medium |
| Unauth File Upload | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |

### Minimum Score Requirement
**CVSS 3.1 Score >= 4.0** required for bounty eligibility.

---

## Out of Scope (Do Not Report)

- CSV Injection
- IP Spoofing (integrity only)
- WAF Bypasses
- CSS/HTML Injection (without impact)
- DoS (without significant impact)
- CAPTCHA Bypass
- CORS Issues
- Open Redirect
- Tabnabbing
- Self-XSS
- Username Enumeration
- Missing Security Headers
- Clickjacking
- SSRF via DNS Rebinding
- CSRF without security impact
- Vulnerabilities requiring Admin/Editor
- Vulnerabilities requiring outdated software

---

## Commands Reference

### Pipeline Script

```bash
# Show help
./run_pipeline.sh --help

# Search plugins
./run_pipeline.sh search "contact form" --min-installs 500

# Download plugin
./run_pipeline.sh download my-plugin

# Analyze plugin
./run_pipeline.sh analyze my-plugin --tier common_dangerous

# Validate report
./run_pipeline.sh validate my-plugin

# Full pipeline
./run_pipeline.sh pipeline my-plugin --tier high_threat

# Check status
./run_pipeline.sh status
```

### Claude Agent Commands

```bash
# Target Researcher
claude "Research WordPress plugins with file upload functionality for Wordfence scope"

# Security Researcher
claude "Analyze ./targets/my-plugin/ for SQL injection vulnerabilities"

# QA/Triager
claude "Validate vulnerability report at ./reports/my-plugin/"
```

### wpguard CLI

```bash
# Search
wpguard search "ecommerce" --min-installs 50000

# Download
wpguard download my-plugin --svn --extract

# Plugin info
wpguard info my-plugin

# SVN history
wpguard svn log my-plugin --limit 20

# SVN diff between versions
wpguard svn diff my-plugin --old-rev 12345 --new-rev HEAD
```

---

## Configuration Files

### wordfence_scope.yaml
Machine-readable Wordfence program scope including:
- Vulnerability tiers and thresholds
- In-scope/out-of-scope vulnerability types
- Excluded vendors
- Authentication level constraints
- wpguard command templates

### excluded_vendors.txt
List of vendors excluded from bounty:
- WordPress Core
- Automattic products (Jetpack, WooCommerce, Akismet)
- Facebook, Google, Siteground, Yoast

---

## Best Practices

1. **Always verify bounty eligibility BEFORE deep analysis**
   - Check install count meets threshold
   - Verify not from excluded vendor
   - Confirm auth level is in scope

2. **Document authentication requirements precisely**
   - "Unauthenticated" vs "Subscriber" matters for severity
   - Test with actual subscriber account, not admin

3. **Create safe PoCs**
   - Include `--verify` mode that doesn't cause harm
   - No destructive operations
   - Parameterize target URL

4. **Calculate CVSS accurately**
   - Subscriber = PR:L (Low privileges)
   - Score must be >= 4.0 for bounty

5. **Check for duplicates**
   - Search WPScan database
   - Search Wordfence blog
   - Search CVE database
