# Scope Auto-Validation Specification

## Overview
Automatically detect and handle out-of-scope vulnerabilities, reducing manual triage time.

---

## 1. Admin-Only Auto-Detection

### Problem
~50% of findings require administrator authentication and are out of scope. Researchers waste time documenting these before realizing they're ineligible.

### Solution
Auto-detect auth level during finding creation and flag/reject admin-only findings.

### API Changes

```python
wpguard_finding_create(
    ...
    auto_scope_check: bool = True,  # NEW: auto-validate scope
    auto_reject_admin: bool = True,  # NEW: auto-reject admin+ findings
)
```

### Scope Rules (from Wordfence)

| Auth Level | In Scope | Notes |
|------------|----------|-------|
| unauthenticated | YES | Highest priority |
| subscriber | YES | Default WP role |
| customer | YES | WooCommerce role |
| contributor | YES | Can write posts |
| author | YES | Can publish posts |
| editor | NO | Out of scope |
| administrator | NO | Out of scope |

### Implementation

```python
OUT_OF_SCOPE_AUTH_LEVELS = {"editor", "administrator"}

def create_finding(params, auto_scope_check=True, auto_reject_admin=True):
    finding = Finding(**params)

    if auto_scope_check:
        # Check auth level
        if finding.auth_level in OUT_OF_SCOPE_AUTH_LEVELS:
            finding.title = f"[OUT OF SCOPE] {finding.title}"
            finding.validation_notes = (
                f"Auto-flagged: Requires {finding.auth_level} authentication, "
                f"which is OUT OF SCOPE for Wordfence Bug Bounty Program."
            )

            if auto_reject_admin:
                finding.status = "rejected"

        # Check install count vs vuln type
        scope_result = check_finding_scope(
            finding.plugin_slug,
            finding.active_installs,
            finding.vuln_type,
            finding.auth_level,
            finding.cvss_score
        )

        if not scope_result["eligible"]:
            finding.validation_notes += f"\n\nScope check: {scope_result['reason']}"
            if auto_reject_admin:
                finding.status = "rejected"

    return save_finding(finding)
```

### Vuln Type + Install Count Matrix

```python
SCOPE_MATRIX = {
    # vuln_type: min_installs
    "rce": 25,
    "file_upload": 25,
    "file_read": 25,
    "file_delete": 25,
    "options_update": 25,
    "auth_bypass": 25,
    "privilege_escalation": 25,
    "sql_injection": 500,
    "stored_xss": 500,
    "reflected_xss": 50000,  # Standard tier
    "csrf": 50000,
    "missing_authorization": 500,  # 1337 tier
    "idor": 500,
    "ssrf": 500,
    "object_injection": 500,
    "information_disclosure": 500,
}

# 1337/Elite tier overrides
ELITE_TIER_THRESHOLD = 500  # 1337 researchers: 500 installs for most vulns

def check_vuln_scope(vuln_type: str, installs: int, tier: str = "elite_1337") -> bool:
    if tier == "elite_1337":
        # Most vulns eligible at 500 installs
        if vuln_type in ["reflected_xss", "csrf"]:
            return installs >= 500  # Lower threshold for elite
        return installs >= SCOPE_MATRIX.get(vuln_type, 500)
    else:
        return installs >= SCOPE_MATRIX.get(vuln_type, 50000)
```

---

## 2. Capability Pattern Scanner

### Problem
Manual code review to identify auth requirements is time-consuming.

### Solution
New MCP tool to automatically scan plugin for authentication patterns.

### New MCP Tool

```python
wpguard_analyze_auth_patterns(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Analyzes plugin code for authentication and authorization patterns.

    Returns:
    {
        "plugin": "extensions-for-cf7",
        "version": "3.4.0",
        "summary": {
            "total_ajax_handlers": 15,
            "unauthenticated_ajax": 3,
            "authenticated_ajax": 12,
            "rest_endpoints": 5,
            "capability_checks": 28
        },
        "unauthenticated_entry_points": [
            {
                "type": "ajax",
                "action": "extcf7_public_action",
                "file": "includes/class-ajax.php",
                "line": 45,
                "handler": "public_action_handler",
                "risk": "high"
            }
        ],
        "authenticated_entry_points": [
            {
                "type": "ajax",
                "action": "extcf7_admin_action",
                "file": "admin/class-admin-ajax.php",
                "line": 30,
                "handler": "admin_action_handler",
                "capability_check": "manage_options",
                "nonce_check": true
            }
        ],
        "rest_endpoints": [
            {
                "route": "/extcf7/v1/forms",
                "methods": ["GET", "POST"],
                "permission_callback": "current_user_can('edit_posts')",
                "file": "includes/rest-api.php",
                "line": 55
            }
        ],
        "potential_issues": [
            {
                "type": "missing_capability_check",
                "action": "extcf7_view_formdata",
                "file": "includes/class-ajax-actions.php",
                "line": 34,
                "description": "Nonce check present but no capability check"
            },
            {
                "type": "nonce_only_protection",
                "action": "extcf7_delete_entry",
                "file": "admin/class-admin.php",
                "line": 120,
                "description": "Relies on nonce for authorization (potential CSRF if nonce leaked)"
            }
        ],
        "recommendations": [
            "3 AJAX handlers lack capability checks - review for auth bypass",
            "5 handlers use nonce-only protection - potential CSRF issues"
        ]
    }
    """
```

### Implementation

```python
import re
from pathlib import Path

class AuthPatternAnalyzer:
    # Patterns to detect
    AJAX_NOPRIV = re.compile(r"add_action\s*\(\s*['\"]wp_ajax_nopriv_(\w+)['\"]")
    AJAX_PRIV = re.compile(r"add_action\s*\(\s*['\"]wp_ajax_(\w+)['\"]")
    CAPABILITY_CHECK = re.compile(r"current_user_can\s*\(\s*['\"](\w+)['\"]")
    NONCE_CHECK = re.compile(r"(wp_verify_nonce|check_ajax_referer|wp_nonce_field)")
    REST_ROUTE = re.compile(r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]")
    PERMISSION_CALLBACK = re.compile(r"['\"]permission_callback['\"]\s*=>\s*(.+?)(?:,|\])")

    def analyze(self, plugin_path: Path) -> dict:
        results = {
            "unauthenticated_entry_points": [],
            "authenticated_entry_points": [],
            "rest_endpoints": [],
            "potential_issues": [],
            "capability_checks": []
        }

        for php_file in plugin_path.rglob("*.php"):
            content = php_file.read_text(errors='ignore')
            self._analyze_file(php_file, content, results)

        return self._summarize(results)

    def _analyze_file(self, filepath: Path, content: str, results: dict):
        lines = content.split('\n')

        # Find AJAX handlers
        for match in self.AJAX_NOPRIV.finditer(content):
            action = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            results["unauthenticated_entry_points"].append({
                "type": "ajax",
                "action": action,
                "file": str(filepath),
                "line": line_num,
                "risk": "high"
            })

        for match in self.AJAX_PRIV.finditer(content):
            action = match.group(1)
            if f"wp_ajax_nopriv_{action}" not in content:  # Not also nopriv
                line_num = content[:match.start()].count('\n') + 1

                # Check for capability check in handler
                handler_content = self._extract_handler(content, action)
                has_cap_check = bool(self.CAPABILITY_CHECK.search(handler_content))
                has_nonce = bool(self.NONCE_CHECK.search(handler_content))

                entry = {
                    "type": "ajax",
                    "action": action,
                    "file": str(filepath),
                    "line": line_num,
                    "capability_check": has_cap_check,
                    "nonce_check": has_nonce
                }
                results["authenticated_entry_points"].append(entry)

                if not has_cap_check and has_nonce:
                    results["potential_issues"].append({
                        "type": "missing_capability_check",
                        "action": action,
                        "file": str(filepath),
                        "line": line_num,
                        "description": "Nonce check present but no capability check"
                    })

    def _extract_handler(self, content: str, action: str) -> str:
        # Try to find the handler function
        # This is simplified - real implementation would use AST
        pattern = rf"function\s+\w*{action}\w*\s*\([^)]*\)\s*\{{([^}}]+)\}}"
        match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
        return match.group(1) if match else ""
```

---

## 3. Pre-Research Scope Check

### Problem
Time wasted researching plugins that are out of scope (vendor exclusion, low installs).

### Solution
Run scope check before downloading/analyzing plugin.

### New MCP Tool

```python
wpguard_quick_scope_check(
    slug: str
) -> dict:
    """
    Quick eligibility check before deep research.

    Returns:
    {
        "slug": "plugin-name",
        "eligible": true,
        "install_count": 6000,
        "author": "Developer Name",
        "vendor_excluded": false,
        "eligible_vuln_types": [
            "sql_injection",
            "stored_xss",
            "missing_authorization",
            "idor",
            "ssrf",
            "object_injection"
        ],
        "recommendations": [
            "Focus on SQLi and Stored XSS (500+ installs)",
            "Auth bypass findings require 25+ installs only"
        ]
    }
    """
```

### Pipeline Integration

```python
def target_research_stage():
    for slug in candidate_slugs:
        scope = wpguard_quick_scope_check(slug)

        if not scope["eligible"]:
            logger.info(f"Skipping {slug}: {scope['reason']}")
            continue

        # Add to queue with scope context
        add_to_queue(slug, scope_context=scope)
```

---

## 4. Batch Scope Validation

### Problem
After research, need to validate all findings are in scope before submission.

### Solution
Batch validate all findings for a plugin.

### New MCP Tool

```python
wpguard_validate_findings_scope(
    plugin_slug: str = None,  # Filter by plugin
    status: str = None,  # Filter by status
    auto_reject: bool = False  # Auto-reject out of scope
) -> dict:
    """
    Batch validate findings against scope rules.

    Returns:
    {
        "total_findings": 10,
        "in_scope": 3,
        "out_of_scope": 7,
        "findings": [
            {
                "id": "abc123",
                "title": "SQLi in search",
                "in_scope": true,
                "reason": "SQLi eligible at 500+ installs"
            },
            {
                "id": "def456",
                "title": "Admin SQLi",
                "in_scope": false,
                "reason": "Requires administrator auth (out of scope)"
            }
        ],
        "summary": {
            "rejected_reasons": {
                "admin_only": 5,
                "low_installs": 2
            }
        }
    }
    """
```

---

## Testing Requirements

1. Unit tests for scope matrix logic
2. Test auth pattern detection with known vulnerable plugins
3. Integration test: auto-reject admin findings
4. Test capability check detection accuracy
5. Test REST endpoint permission parsing
