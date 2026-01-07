# New MCP Tools Specification

## Overview
Additional MCP tools for enhanced plugin analysis and vulnerability detection.

---

## 1. Plugin Hooks Analyzer

### Purpose
List all WordPress hooks (actions/filters) registered by a plugin.

### MCP Tool

```python
wpguard_plugin_hooks(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Extract all hooks registered by a plugin.

    Returns:
    {
        "plugin": "plugin-name",
        "version": "1.0.0",
        "hooks": {
            "actions": [
                {
                    "hook": "init",
                    "callback": "MyPlugin::init",
                    "file": "includes/class-main.php",
                    "line": 45,
                    "priority": 10
                },
                {
                    "hook": "wp_ajax_my_action",
                    "callback": "handle_ajax",
                    "file": "includes/ajax.php",
                    "line": 20,
                    "priority": 10,
                    "auth_required": true
                },
                {
                    "hook": "wp_ajax_nopriv_public_action",
                    "callback": "handle_public",
                    "file": "includes/ajax.php",
                    "line": 35,
                    "priority": 10,
                    "auth_required": false
                }
            ],
            "filters": [
                {
                    "hook": "the_content",
                    "callback": "modify_content",
                    "file": "includes/content.php",
                    "line": 100,
                    "priority": 10
                }
            ]
        },
        "summary": {
            "total_actions": 25,
            "total_filters": 10,
            "ajax_authenticated": 8,
            "ajax_unauthenticated": 3,
            "rest_routes": 5
        }
    }
    """
```

### Implementation

```python
import re
from pathlib import Path

class HookAnalyzer:
    # Patterns for hook detection
    ADD_ACTION = re.compile(
        r"add_action\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(?:array\s*\(\s*\$this\s*,\s*)?['\"]?(\w+)['\"]?",
        re.MULTILINE
    )
    ADD_FILTER = re.compile(
        r"add_filter\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(?:array\s*\(\s*\$this\s*,\s*)?['\"]?(\w+)['\"]?",
        re.MULTILINE
    )

    def analyze(self, plugin_path: Path) -> dict:
        hooks = {"actions": [], "filters": []}

        for php_file in plugin_path.rglob("*.php"):
            content = php_file.read_text(errors='ignore')
            self._extract_hooks(php_file, content, hooks)

        return {
            "hooks": hooks,
            "summary": self._summarize(hooks)
        }

    def _extract_hooks(self, filepath: Path, content: str, hooks: dict):
        # Extract actions
        for match in self.ADD_ACTION.finditer(content):
            hook_name = match.group(1)
            callback = match.group(2)
            line = content[:match.start()].count('\n') + 1

            action = {
                "hook": hook_name,
                "callback": callback,
                "file": str(filepath),
                "line": line,
                "priority": self._extract_priority(content, match.end())
            }

            # Check if AJAX hook
            if hook_name.startswith("wp_ajax_"):
                action["auth_required"] = not hook_name.startswith("wp_ajax_nopriv_")

            hooks["actions"].append(action)

        # Extract filters
        for match in self.ADD_FILTER.finditer(content):
            hooks["filters"].append({
                "hook": match.group(1),
                "callback": match.group(2),
                "file": str(filepath),
                "line": content[:match.start()].count('\n') + 1
            })

    def _summarize(self, hooks: dict) -> dict:
        ajax_auth = sum(1 for a in hooks["actions"]
                       if a["hook"].startswith("wp_ajax_") and a.get("auth_required", True))
        ajax_noauth = sum(1 for a in hooks["actions"]
                         if a["hook"].startswith("wp_ajax_nopriv_"))

        return {
            "total_actions": len(hooks["actions"]),
            "total_filters": len(hooks["filters"]),
            "ajax_authenticated": ajax_auth,
            "ajax_unauthenticated": ajax_noauth
        }
```

---

## 2. AJAX Endpoints Extractor

### Purpose
Extract all AJAX handlers with detailed auth analysis.

### MCP Tool

```python
wpguard_plugin_ajax_endpoints(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Extract all AJAX endpoints with security analysis.

    Returns:
    {
        "plugin": "plugin-name",
        "endpoints": [
            {
                "action": "my_ajax_action",
                "handler": "handle_ajax",
                "file": "includes/ajax.php",
                "line": 20,
                "auth": {
                    "authenticated_only": true,
                    "capability_check": "manage_options",
                    "nonce_check": true,
                    "nonce_action": "my_nonce_action"
                },
                "parameters": [
                    {"name": "id", "sanitization": "intval"},
                    {"name": "data", "sanitization": "none"}
                ],
                "risk_level": "low"
            },
            {
                "action": "public_action",
                "handler": "handle_public",
                "file": "includes/ajax.php",
                "line": 50,
                "auth": {
                    "authenticated_only": false,
                    "capability_check": null,
                    "nonce_check": false
                },
                "parameters": [
                    {"name": "input", "sanitization": "sanitize_text_field"}
                ],
                "risk_level": "high",
                "warnings": [
                    "Unauthenticated access",
                    "No nonce verification"
                ]
            }
        ],
        "summary": {
            "total_endpoints": 10,
            "high_risk": 2,
            "medium_risk": 3,
            "low_risk": 5
        }
    }
    """
```

---

## 3. REST API Endpoints Extractor

### Purpose
Extract all REST API routes with permission analysis.

### MCP Tool

```python
wpguard_plugin_rest_endpoints(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Extract all REST API endpoints with permission analysis.

    Returns:
    {
        "plugin": "plugin-name",
        "namespace": "myplugin/v1",
        "endpoints": [
            {
                "route": "/items",
                "methods": ["GET", "POST"],
                "file": "includes/rest-api.php",
                "line": 30,
                "permission_callback": "__return_true",
                "auth_required": false,
                "risk_level": "high",
                "warnings": ["Unauthenticated access via __return_true"]
            },
            {
                "route": "/items/(?P<id>\\d+)",
                "methods": ["GET", "PUT", "DELETE"],
                "file": "includes/rest-api.php",
                "line": 45,
                "permission_callback": "current_user_can('edit_posts')",
                "auth_required": true,
                "minimum_capability": "edit_posts",
                "risk_level": "medium"
            }
        ],
        "summary": {
            "total_routes": 8,
            "public_routes": 2,
            "authenticated_routes": 6
        }
    }
    """
```

### Implementation

```python
class RestApiAnalyzer:
    REGISTER_ROUTE = re.compile(
        r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        re.MULTILINE
    )
    PERMISSION_CALLBACK = re.compile(
        r"['\"]permission_callback['\"]\s*=>\s*(.+?)(?:,|\]|\))",
        re.DOTALL
    )

    def analyze(self, plugin_path: Path) -> dict:
        endpoints = []

        for php_file in plugin_path.rglob("*.php"):
            content = php_file.read_text(errors='ignore')
            endpoints.extend(self._extract_routes(php_file, content))

        return {"endpoints": endpoints, "summary": self._summarize(endpoints)}

    def _extract_routes(self, filepath: Path, content: str) -> list:
        routes = []

        for match in self.REGISTER_ROUTE.finditer(content):
            namespace = match.group(1)
            route = match.group(2)
            line = content[:match.start()].count('\n') + 1

            # Find the full register_rest_route call
            call_content = self._extract_call(content, match.start())

            # Extract permission callback
            perm_match = self.PERMISSION_CALLBACK.search(call_content)
            permission = perm_match.group(1).strip() if perm_match else "not_found"

            # Analyze permission
            auth_required, risk = self._analyze_permission(permission)

            routes.append({
                "route": route,
                "namespace": namespace,
                "file": str(filepath),
                "line": line,
                "permission_callback": permission,
                "auth_required": auth_required,
                "risk_level": risk
            })

        return routes

    def _analyze_permission(self, permission: str) -> tuple:
        """Returns (auth_required, risk_level)"""
        permission = permission.lower()

        if "__return_true" in permission:
            return False, "high"
        elif "is_user_logged_in" in permission:
            return True, "medium"
        elif "current_user_can" in permission:
            if "manage_options" in permission or "administrator" in permission:
                return True, "low"
            elif "edit_posts" in permission:
                return True, "medium"
            else:
                return True, "medium"
        else:
            return True, "low"  # Custom callback, assume safe
```

---

## 4. Database Query Analyzer

### Purpose
Find all database queries and flag unsafe patterns.

### MCP Tool

```python
wpguard_plugin_db_queries(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Extract all database queries with security analysis.

    Returns:
    {
        "plugin": "plugin-name",
        "queries": [
            {
                "type": "select",
                "method": "$wpdb->get_results",
                "file": "includes/data.php",
                "line": 45,
                "query_pattern": "SELECT * FROM {$table} WHERE id = %d",
                "uses_prepare": true,
                "placeholders": ["%d"],
                "risk_level": "safe"
            },
            {
                "type": "select",
                "method": "$wpdb->query",
                "file": "includes/search.php",
                "line": 78,
                "query_pattern": "SELECT * FROM wp_posts WHERE title LIKE '%{$search}%'",
                "uses_prepare": false,
                "user_input_detected": true,
                "risk_level": "critical",
                "warnings": [
                    "Direct variable interpolation without prepare()",
                    "User input detected in query",
                    "LIKE clause without esc_like()"
                ]
            }
        ],
        "summary": {
            "total_queries": 25,
            "safe": 20,
            "risky": 3,
            "critical": 2
        },
        "recommendations": [
            "2 queries use direct variable interpolation - high SQLi risk",
            "3 queries use esc_sql() on identifiers - ineffective"
        ]
    }
    """
```

### Dangerous Patterns

```python
DANGEROUS_PATTERNS = [
    {
        "pattern": r"\$wpdb->(query|get_results|get_var|get_row)\s*\([^)]*\$_(GET|POST|REQUEST)",
        "risk": "critical",
        "description": "Direct user input in query without prepare()"
    },
    {
        "pattern": r"\$wpdb->(query|get_results)\s*\([^)]*\"[^\"]*\{?\$\w+",
        "risk": "high",
        "description": "Variable interpolation in query"
    },
    {
        "pattern": r"ORDER\s+BY\s+[^\"]*\$",
        "risk": "high",
        "description": "Dynamic ORDER BY clause"
    },
    {
        "pattern": r"esc_sql\s*\([^)]+\).*ORDER\s+BY",
        "risk": "medium",
        "description": "esc_sql() on ORDER BY - may be insufficient"
    },
    {
        "pattern": r"LIKE\s+['\"]%[^%]*\$",
        "risk": "medium",
        "description": "LIKE clause with variable - needs esc_like()"
    }
]
```

---

## 5. File Operations Analyzer

### Purpose
Find all file read/write/upload operations.

### MCP Tool

```python
wpguard_plugin_file_ops(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Extract all file operations with security analysis.

    Returns:
    {
        "plugin": "plugin-name",
        "operations": [
            {
                "type": "write",
                "function": "file_put_contents",
                "file": "includes/export.php",
                "line": 89,
                "path_source": "user_input",
                "content_source": "user_input",
                "risk_level": "critical",
                "warnings": [
                    "Path derived from user input",
                    "No path traversal protection",
                    "Could write to any location"
                ]
            },
            {
                "type": "upload",
                "function": "wp_handle_upload",
                "file": "includes/upload.php",
                "line": 45,
                "allowed_types": ["image/jpeg", "image/png"],
                "validates_type": true,
                "risk_level": "low"
            },
            {
                "type": "include",
                "function": "include",
                "file": "includes/loader.php",
                "line": 20,
                "path_source": "user_input",
                "risk_level": "critical",
                "warnings": ["LFI/RFI vulnerability - user controls include path"]
            }
        ],
        "summary": {
            "total_operations": 15,
            "file_writes": 3,
            "file_reads": 8,
            "includes": 2,
            "uploads": 2,
            "critical_issues": 2
        }
    }
    """
```

---

## 6. Version Comparison Tool

### Purpose
Compare two versions of a plugin to identify security-relevant changes.

### MCP Tool

```python
wpguard_compare_versions(
    slug: str,
    old_version: str,
    new_version: str = "latest",
    output_dir: str = "."
) -> dict:
    """
    Compare plugin versions for security changes.

    Returns:
    {
        "plugin": "plugin-name",
        "old_version": "1.0.0",
        "new_version": "1.0.1",
        "security_changes": [
            {
                "type": "fix",
                "file": "includes/ajax.php",
                "description": "Added capability check to AJAX handler",
                "diff": "...",
                "likely_cve": true
            },
            {
                "type": "fix",
                "file": "includes/query.php",
                "description": "Added $wpdb->prepare() to query",
                "diff": "...",
                "likely_cve": true
            },
            {
                "type": "new_feature",
                "file": "includes/api.php",
                "description": "New REST endpoint added",
                "potential_attack_surface": true
            }
        ],
        "statistics": {
            "files_changed": 15,
            "security_fixes": 3,
            "new_features": 2,
            "potential_attack_surface_additions": 2
        },
        "recommendations": [
            "3 security fixes detected - check if patches are complete",
            "New REST endpoint - review permission callbacks"
        ]
    }
    """
```

### Security Change Detection

```python
SECURITY_PATTERNS = {
    "capability_added": {
        "added": [r"current_user_can\s*\(", r"wp_verify_nonce"],
        "description": "Authorization check added"
    },
    "prepare_added": {
        "added": [r"\$wpdb->prepare\s*\("],
        "removed": [r"\$wpdb->(query|get_results)\s*\([^)]*\$"],
        "description": "SQL preparation added"
    },
    "escaping_added": {
        "added": [r"esc_(html|attr|url|sql)\s*\(", r"wp_kses"],
        "description": "Output escaping added"
    },
    "sanitization_added": {
        "added": [r"sanitize_(text_field|email|file_name)\s*\(", r"intval\s*\(", r"absint\s*\("],
        "description": "Input sanitization added"
    }
}
```

---

## Summary: All New MCP Tools

| Tool | Purpose | Priority |
|------|---------|----------|
| `wpguard_plugin_hooks` | List all hooks (actions/filters) | P1 |
| `wpguard_plugin_ajax_endpoints` | Extract AJAX handlers with auth | P0 |
| `wpguard_plugin_rest_endpoints` | Extract REST routes with perms | P0 |
| `wpguard_plugin_db_queries` | Find unsafe SQL patterns | P0 |
| `wpguard_plugin_file_ops` | Find file operations | P1 |
| `wpguard_compare_versions` | Diff versions for security | P1 |
| `wpguard_analyze_auth_patterns` | Comprehensive auth analysis | P0 |
| `wpguard_quick_scope_check` | Fast eligibility check | P1 |
| `wpguard_cve_patch_analysis` | Patch bypass detection | P1 |
| `wpguard_plugin_risk_score` | Calculate risk score | P2 |
| `wpguard_research_guidance` | CVE-based research hints | P2 |

---

## Testing Requirements

1. Test each analyzer with known vulnerable plugins
2. Benchmark analysis speed on large plugins
3. Test false positive rates
4. Compare results with manual analysis
5. Test version diff accuracy
