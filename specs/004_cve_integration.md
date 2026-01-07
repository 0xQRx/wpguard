# Enhanced CVE Integration Specification

## Overview
Leverage the Wordfence CVE database for patch bypass detection, pattern matching, and historical analysis.

---

## 1. Patch Bypass Detection

### Problem
Many CVE "fixes" are incomplete. Current workflow requires manual comparison of patched code vs CVE description.

### Solution
Automated analysis comparing current plugin code against known CVE patches.

### New MCP Tool

```python
wpguard_cve_patch_analysis(
    slug: str,
    cve_id: str = None,  # Specific CVE or analyze all for plugin
    version: str = None  # Compare specific version
) -> dict:
    """
    Analyzes if CVE patches are complete or bypassable.

    Returns:
    {
        "plugin": "extensions-for-cf7",
        "current_version": "3.4.0",
        "cves_analyzed": [
            {
                "cve_id": "CVE-2025-24695",
                "title": "SSRF via Mailchimp API",
                "patched_version": "3.2.1",
                "patch_status": "incomplete",
                "analysis": {
                    "original_sink": "wp_remote_get()",
                    "patched_sink": "wp_safe_remote_get()",
                    "bypass_possible": true,
                    "bypass_methods": [
                        "169.254.169.254 not blocked by wp_safe_remote_get()",
                        "DNS rebinding possible",
                        "IPv6 bypass not blocked"
                    ],
                    "affected_file": "admin/include/class.cf7-mailchimp-map.php",
                    "affected_line": 66
                },
                "recommendation": "SSRF still exploitable via cloud metadata IP"
            }
        ],
        "summary": {
            "complete_patches": 2,
            "incomplete_patches": 1,
            "bypass_opportunities": 1
        }
    }
    """
```

### Implementation Strategy

```python
class PatchAnalyzer:
    # Known incomplete patch patterns
    INCOMPLETE_PATTERNS = {
        "ssrf": {
            "weak_fixes": [
                ("wp_remote_get", "wp_safe_remote_get", "169.254.169.254 still accessible"),
                ("filter_var.*FILTER_VALIDATE_URL", None, "Doesn't block internal IPs"),
            ],
            "bypass_ips": ["169.254.169.254", "127.0.0.1", "0.0.0.0", "::1"]
        },
        "sqli": {
            "weak_fixes": [
                ("esc_sql", None, "Doesn't prevent ORDER BY/identifier injection"),
                ("intval", None, "Type juggling bypass possible"),
                ("sanitize_text_field", None, "Doesn't sanitize SQL"),
            ]
        },
        "xss": {
            "weak_fixes": [
                ("esc_html", "esc_attr", "Wrong context escaping"),
                ("strip_tags", None, "Bypassable, doesn't handle attributes"),
                ("htmlspecialchars.*ENT_QUOTES", None, "Check if charset specified"),
            ]
        },
        "file_upload": {
            "weak_fixes": [
                ("mime_content_type", None, "Can be spoofed"),
                ("pathinfo.*extension", None, "Double extension bypass"),
                ("getimagesize", None, "Polyglot bypass possible"),
            ]
        }
    }

    def analyze_patch(self, cve: dict, current_code: str) -> dict:
        vuln_type = self._categorize_vuln(cve["title"])
        patterns = self.INCOMPLETE_PATTERNS.get(vuln_type, {})

        bypass_methods = []
        for old_pattern, new_pattern, bypass_desc in patterns.get("weak_fixes", []):
            if new_pattern and new_pattern in current_code:
                bypass_methods.append(bypass_desc)
            elif old_pattern in current_code and not new_pattern:
                bypass_methods.append(f"Uses {old_pattern}: {bypass_desc}")

        return {
            "bypass_possible": len(bypass_methods) > 0,
            "bypass_methods": bypass_methods,
            "patch_status": "incomplete" if bypass_methods else "complete"
        }
```

---

## 2. Historical Pattern Matching

### Problem
Plugins with prior CVEs often repeat the same mistakes. Need to identify similar patterns.

### Solution
Match current code against known vulnerability patterns from CVE database.

### New MCP Tool

```python
wpguard_cve_pattern_match(
    slug: str,
    output_dir: str = "."
) -> dict:
    """
    Finds code patterns similar to known CVEs.

    Returns:
    {
        "plugin": "new-plugin",
        "matches": [
            {
                "pattern": "unsanitized_order_by",
                "similar_cves": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "plugin": "other-plugin",
                        "cvss": 7.2,
                        "description": "SQLi via ORDER BY"
                    }
                ],
                "current_code": {
                    "file": "includes/query.php",
                    "line": 45,
                    "snippet": "$order = $_GET['order']; $query .= \"ORDER BY $order\""
                },
                "confidence": "high",
                "recommendation": "Apply same fix as CVE-2024-1234"
            }
        ],
        "risk_score": 8.5,
        "recommendations": [
            "3 patterns match known SQLi CVEs - prioritize review",
            "Author has 5 prior CVEs - expect more issues"
        ]
    }
    """
```

### Pattern Database

```python
# Build from CVE descriptions and affected code
VULN_PATTERNS = {
    "unsanitized_order_by": {
        "regex": r"\$_(GET|POST|REQUEST)\[['\"]order['\"].*ORDER\s+BY",
        "vuln_type": "sql_injection",
        "severity": "high",
        "cve_examples": ["CVE-2024-1234", "CVE-2023-5678"]
    },
    "esc_sql_in_like": {
        "regex": r"esc_sql.*LIKE.*%",
        "vuln_type": "sql_injection",
        "severity": "medium",
        "description": "esc_sql doesn't escape LIKE wildcards"
    },
    "unserialize_user_input": {
        "regex": r"(unserialize|maybe_unserialize)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "vuln_type": "object_injection",
        "severity": "critical"
    },
    "file_put_contents_user_path": {
        "regex": r"file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)",
        "vuln_type": "arbitrary_file_write",
        "severity": "critical"
    },
    "include_user_input": {
        "regex": r"(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)",
        "vuln_type": "lfi_rfi",
        "severity": "critical"
    },
    "wp_remote_get_user_url": {
        "regex": r"wp_remote_get\s*\(\s*\$_(GET|POST|REQUEST)",
        "vuln_type": "ssrf",
        "severity": "high"
    },
    "echo_unescaped": {
        "regex": r"echo\s+\$_(GET|POST|REQUEST)\[",
        "vuln_type": "xss",
        "severity": "medium"
    },
    "nonce_without_capability": {
        "regex": r"wp_verify_nonce.*\n(?!.*current_user_can)",
        "vuln_type": "missing_authorization",
        "severity": "medium",
        "description": "Nonce check without capability check"
    }
}
```

---

## 3. Plugin Risk Scoring

### Problem
Need to prioritize which plugins to research first based on historical data.

### Solution
Calculate risk score based on CVE history and code patterns.

### New MCP Tool

```python
wpguard_plugin_risk_score(
    slug: str
) -> dict:
    """
    Calculate security risk score for a plugin.

    Returns:
    {
        "plugin": "profilegrid",
        "risk_score": 9.2,
        "risk_level": "critical",
        "factors": {
            "cve_history": {
                "total_cves": 44,
                "critical": 5,
                "high": 12,
                "score_contribution": 3.5
            },
            "repeat_patterns": {
                "sqli_cves": 8,
                "object_injection_cves": 4,
                "score_contribution": 2.5
            },
            "recent_activity": {
                "cves_last_year": 12,
                "score_contribution": 2.0
            },
            "code_quality": {
                "dangerous_patterns_found": 15,
                "score_contribution": 1.2
            }
        },
        "recommendations": [
            "HIGH PRIORITY: 44 prior CVEs indicate systemic security issues",
            "Focus on SQLi - 8 previous SQLi CVEs, likely more exist",
            "Check for object injection - 4 prior CVEs in this category"
        ],
        "similar_plugins": [
            {"slug": "other-vulnerable-plugin", "same_author": true, "cves": 12}
        ]
    }
    """
```

### Scoring Algorithm

```python
def calculate_risk_score(slug: str) -> float:
    cves = get_cves_for_plugin(slug)
    plugin_info = get_plugin_info(slug)

    score = 0.0

    # CVE History (max 4 points)
    cve_count = len(cves)
    if cve_count >= 20:
        score += 4.0
    elif cve_count >= 10:
        score += 3.0
    elif cve_count >= 5:
        score += 2.0
    elif cve_count >= 1:
        score += 1.0

    # Severity Distribution (max 2 points)
    critical_count = sum(1 for c in cves if c.cvss >= 9.0)
    high_count = sum(1 for c in cves if 7.0 <= c.cvss < 9.0)
    score += min(2.0, (critical_count * 0.5) + (high_count * 0.2))

    # Recency (max 2 points)
    recent_cves = sum(1 for c in cves if c.published_date > one_year_ago)
    if recent_cves >= 5:
        score += 2.0
    elif recent_cves >= 2:
        score += 1.0

    # Pattern Repetition (max 2 points)
    vuln_types = Counter(c.vuln_type for c in cves)
    if vuln_types.most_common(1)[0][1] >= 5:  # Same vuln type 5+ times
        score += 2.0
    elif vuln_types.most_common(1)[0][1] >= 3:
        score += 1.0

    return min(10.0, score)
```

---

## 4. CVE-Guided Research

### Problem
Researchers don't know which vuln types to focus on for a specific plugin.

### Solution
Generate research guidance based on CVE history.

### New MCP Tool

```python
wpguard_research_guidance(
    slug: str
) -> dict:
    """
    Generate research guidance based on plugin's CVE history.

    Returns:
    {
        "plugin": "profilegrid",
        "focus_areas": [
            {
                "vuln_type": "sql_injection",
                "priority": "critical",
                "prior_cves": 8,
                "patterns_to_look_for": [
                    "Direct $wpdb->query() calls",
                    "esc_sql() on dynamic columns",
                    "ORDER BY with user input"
                ],
                "files_to_review": [
                    "includes/class-query.php",
                    "includes/class-search.php"
                ]
            },
            {
                "vuln_type": "object_injection",
                "priority": "high",
                "prior_cves": 4,
                "patterns_to_look_for": [
                    "maybe_unserialize() calls",
                    "unserialize() with user data"
                ]
            }
        ],
        "expert_agents_recommended": [
            "sqli-expert",
            "object-injection-expert",
            "auth-expert"
        ],
        "skip_agents": [
            "xxe-expert",  # No XML processing found
            "race-condition-expert"  # Out of scope
        ]
    }
    """
```

---

## 5. Auto-Refresh CVE Database

### Enhancement to Existing Tool

```python
wpguard_cve_download(
    force: bool = False,
    auto_schedule: bool = True,  # NEW: Enable auto-refresh
    refresh_interval_hours: int = 24  # NEW: Refresh every 24 hours
)
```

### Background Refresh

```python
# In pipeline daemon
async def check_cve_freshness():
    cve_cache = Path("/tmp/wordfence_vulns.json")
    if not cve_cache.exists():
        await download_cve_database()
        return

    cache_age = time.time() - cve_cache.stat().st_mtime
    if cache_age > config.cve_refresh_interval_hours * 3600:
        logger.info("CVE database stale, refreshing...")
        await download_cve_database()
```

---

## Testing Requirements

1. Test patch analysis with known incomplete fixes
2. Test pattern matching accuracy
3. Test risk scoring with various CVE counts
4. Test research guidance generation
5. Benchmark CVE database queries
