# Expert Agent Improvements Specification

## Overview
Optimizations for the 13 expert agents to improve efficiency and reduce noise.

---

## 1. Conditional Expert Skipping

### Problem
All 13 experts run for every plugin, even when irrelevant (e.g., XXE expert on plugin with no XML processing).

### Solution
Smart expert selection based on plugin analysis.

### Implementation

```python
class ExpertSelector:
    """Determine which experts to run based on plugin characteristics."""

    EXPERT_TRIGGERS = {
        "file-rce-expert": {
            "patterns": [
                r"file_put_contents|file_get_contents|fopen|fwrite",
                r"move_uploaded_file|wp_handle_upload",
                r"include|require|include_once|require_once",
                r"unlink|rmdir|mkdir|copy|rename"
            ],
            "file_types": [".php"]
        },
        "sqli-expert": {
            "patterns": [
                r"\$wpdb->",
                r"SELECT|INSERT|UPDATE|DELETE|UNION",
                r"->query\(|->get_results\(|->get_var\("
            ],
            "always_run": True  # SQLi is common, always check
        },
        "xss-expert": {
            "patterns": [
                r"echo|print|printf",
                r"<script|onclick|onerror",
                r"wp_kses|esc_html|esc_attr"
            ],
            "always_run": True  # XSS is common, always check
        },
        "auth-expert": {
            "patterns": [
                r"current_user_can|wp_verify_nonce",
                r"wp_ajax_|wp_ajax_nopriv_",
                r"register_rest_route",
                r"is_user_logged_in|is_admin"
            ],
            "always_run": True
        },
        "object-injection-expert": {
            "patterns": [
                r"unserialize|maybe_unserialize",
                r"__wakeup|__destruct|__toString",
                r"phar://"
            ]
        },
        "ssrf-expert": {
            "patterns": [
                r"wp_remote_get|wp_remote_post|wp_safe_remote",
                r"file_get_contents\s*\([^)]*http",
                r"curl_init|curl_exec"
            ]
        },
        "race-condition-expert": {
            "patterns": [
                r"move_uploaded_file|wp_handle_upload",  # File upload races
                r"unlink.*\$|delete.*file",  # Delete after check
                r"file_exists.*include|is_file.*require",  # TOCTOU on includes
                r"check.*then.*write|verify.*then.*execute"  # Generic TOCTOU
            ],
            "high_impact_only": True,  # Only run for potential RCE scenarios
            "reason": "Race conditions only in scope when leading to RCE/critical impact"
        },
        "csrf-expert": {
            "patterns": [
                r"wp_nonce|check_ajax_referer",
                r"wp_ajax_(?!nopriv)"  # Authenticated AJAX
            ],
            "min_installs": 50000  # CSRF only in scope for 50k+
        },
        "lfi-rfi-expert": {
            "patterns": [
                r"include|require|include_once|require_once",
                r"file_get_contents|readfile|fopen",
                r"__DIR__|__FILE__|ABSPATH"
            ]
        },
        "xxe-expert": {
            "patterns": [
                r"simplexml|DOMDocument|XMLReader",
                r"xml_parse|libxml",
                r"\.xml|\.svg"
            ]
        },
        "deserialization-expert": {
            "patterns": [
                r"json_decode|yaml_parse",
                r"unserialize|maybe_unserialize"
            ]
        },
        "logic-flaw-expert": {
            "patterns": [
                r"woocommerce|payment|checkout",
                r"subscription|membership|premium",
                r"discount|coupon|price"
            ]
        },
        "info-disclosure-expert": {
            "patterns": [
                r"phpinfo|var_dump|print_r|error_log",
                r"debug|WP_DEBUG",
                r"\.log|\.bak|\.sql"
            ],
            "always_run": True
        }
    }

    def select_experts(self, plugin_path: Path, plugin_info: dict) -> list:
        """Return list of experts to run for this plugin."""
        content = self._read_all_php(plugin_path)
        installs = plugin_info.get("active_installs", 0)

        selected = []

        for expert, config in self.EXPERT_TRIGGERS.items():
            # Check skip conditions
            if config.get("skip_always"):
                continue

            if config.get("min_installs") and installs < config["min_installs"]:
                continue

            # Check if should always run
            if config.get("always_run"):
                selected.append(expert)
                continue

            # Check patterns
            patterns = config.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    selected.append(expert)
                    break

        return selected
```

### Pipeline Integration

```python
async def run_experts_for_plugin(slug: str):
    plugin_path = get_plugin_path(slug)
    plugin_info = await get_plugin_info(slug)

    if config.smart_expert_selection:
        experts = expert_selector.select_experts(plugin_path, plugin_info)
        logger.info(f"Selected {len(experts)} experts for {slug}: {experts}")
    else:
        experts = ALL_EXPERTS

    for expert in experts:
        await run_expert(expert, slug)
```

### Config Option

```python
wpguard_pipeline_config(
    smart_expert_selection: bool = True,  # NEW
    always_run_experts: list = ["sqli-expert", "xss-expert", "auth-expert"],  # NEW
    skip_experts: list = ["race-condition-expert"]  # NEW
)
```

---

## 2. Expert Deduplication

### Problem
Multiple experts find same vulnerability (e.g., auth-expert and info-disclosure-expert both find missing auth).

### Solution
Cross-expert deduplication during finding creation.

### Implementation

```python
async def create_finding_with_dedupe(finding_data: dict) -> dict:
    """Create finding with automatic deduplication."""

    # Get existing findings for this plugin
    existing = await list_findings(plugin_slug=finding_data["plugin_slug"])

    # Check for duplicates
    dupe_check = check_duplicate(finding_data, existing, threshold=0.8)

    if dupe_check["is_duplicate"]:
        # Merge into existing finding instead of creating new
        primary_id = dupe_check["duplicate_of"]
        logger.info(f"Merging duplicate finding into {primary_id}")

        return await merge_findings(
            primary_id=primary_id,
            new_finding=finding_data,
            source_expert=finding_data.get("source_expert")
        )
    else:
        return await create_finding(finding_data)

def check_duplicate(new: dict, existing: list, threshold: float) -> dict:
    """Check if finding is duplicate."""
    for existing_finding in existing:
        # Skip different vuln types
        if existing_finding["vuln_type"] != new["vuln_type"]:
            continue

        similarity = calculate_similarity(new, existing_finding)

        if similarity >= threshold:
            return {
                "is_duplicate": True,
                "duplicate_of": existing_finding["id"],
                "similarity": similarity
            }

    return {"is_duplicate": False}

def calculate_similarity(a: dict, b: dict) -> float:
    """Calculate similarity score between two findings."""
    score = 0.0

    # Same file = 0.4
    if a.get("affected_file") == b.get("affected_file"):
        score += 0.4

    # Same function = 0.3
    if a.get("affected_function") == b.get("affected_function"):
        score += 0.3

    # Same line (within 5) = 0.2
    line_diff = abs(a.get("affected_line", 0) - b.get("affected_line", 0))
    if line_diff <= 5:
        score += 0.2

    # Similar title = 0.1
    title_sim = fuzz.ratio(a.get("title", ""), b.get("title", "")) / 100
    score += title_sim * 0.1

    return score
```

---

## 3. Expert Context Sharing

### Problem
Each expert starts fresh without knowing what previous experts found.

### Solution
Share context between experts via scan state.

### Implementation

```python
# After each expert completes
async def on_expert_complete(expert: str, slug: str, findings: list):
    scan_state = await load_scan_state()

    # Initialize plugin context if needed
    if "plugin_context" not in scan_state:
        scan_state["plugin_context"] = {}
    if slug not in scan_state["plugin_context"]:
        scan_state["plugin_context"][slug] = {
            "experts_completed": [],
            "findings_summary": [],
            "flagged_files": [],
            "flagged_functions": []
        }

    context = scan_state["plugin_context"][slug]

    # Update context
    context["experts_completed"].append(expert)

    for finding in findings:
        context["findings_summary"].append({
            "id": finding["id"],
            "type": finding["vuln_type"],
            "file": finding["affected_file"],
            "function": finding.get("affected_function")
        })
        context["flagged_files"].append(finding["affected_file"])
        if finding.get("affected_function"):
            context["flagged_functions"].append(finding["affected_function"])

    await save_scan_state(scan_state)

# In expert prompt, include context
def build_expert_prompt(expert: str, slug: str) -> str:
    context = get_plugin_context(slug)

    prompt = EXPERT_PROMPTS[expert]

    if context:
        prompt += f"""

## Previous Expert Findings

The following experts have already analyzed this plugin:
{', '.join(context['experts_completed'])}

Already identified issues:
{json.dumps(context['findings_summary'], indent=2)}

Already flagged files (prioritize review):
{json.dumps(list(set(context['flagged_files'])), indent=2)}

IMPORTANT: Do not create duplicate findings for issues already identified.
Focus on finding NEW vulnerabilities not covered by previous experts.
"""

    return prompt
```

---

## 4. Expert Timeout Configuration

### Problem
Some experts take too long on complex plugins.

### Solution
Configurable per-expert timeouts.

### Config

```python
EXPERT_TIMEOUTS = {
    "file-rce-expert": 10,  # minutes
    "sqli-expert": 15,
    "xss-expert": 15,
    "auth-expert": 15,
    "object-injection-expert": 10,
    "ssrf-expert": 10,
    "race-condition-expert": 5,  # Skipped anyway
    "csrf-expert": 10,
    "lfi-rfi-expert": 10,
    "xxe-expert": 5,
    "deserialization-expert": 10,
    "logic-flaw-expert": 15,
    "info-disclosure-expert": 10
}

wpguard_pipeline_config(
    expert_timeouts: dict = EXPERT_TIMEOUTS,  # NEW
    default_expert_timeout: int = 15  # NEW
)
```

---

## 5. Quick Wins Implementation

### 5.1 Race Condition Expert - High Impact Only

Race conditions are generally out of scope, but exceptions exist for critical impact:

```python
# Only run race-condition-expert when high-impact patterns detected
RACE_CONDITION_TRIGGERS = [
    # File upload race → RCE
    r"move_uploaded_file|wp_handle_upload",
    # TOCTOU on file includes → RCE
    r"file_exists.*include|is_file.*require",
    # Delete after check → arbitrary file delete
    r"unlink.*\$.*file_exists|delete.*check"
]

def should_run_race_expert(plugin_content: str) -> bool:
    """Only run if potential RCE-level race condition."""
    for pattern in RACE_CONDITION_TRIGGERS:
        if re.search(pattern, plugin_content, re.IGNORECASE):
            return True
    return False

# In expert selector
if expert == "race-condition-expert":
    if not should_run_race_expert(content):
        logger.info("Skipping race-condition-expert (no high-impact patterns)")
        continue
    logger.info("Running race-condition-expert (file upload/TOCTOU pattern detected)")
```

**Valid Race Condition Scenarios:**
- File upload → execute before validation completes → RCE
- Check file exists → include before deletion → LFI/RCE
- Verify permission → execute before revocation → Privilege escalation
- Check balance → deduct before double-spend → Financial impact

### 5.2 Default Iterations = 1

```python
# Current default is 2, change to 1
wpguard_pipeline_start(
    num_iterations: int = 1,  # Changed from 2
    ...
)
```

### 5.3 Discord Alerts for Validated Only

```python
# In finding update
async def on_finding_validated(finding: dict):
    if config.discord_notify_validated_only:
        await discord_notify_finding(finding["id"])
```

### 5.4 Auto-Tag Out of Scope

```python
# In finding create
def auto_tag_out_of_scope(finding: dict) -> dict:
    if finding["auth_level"] in ["editor", "administrator"]:
        if not finding["title"].startswith("[OUT OF SCOPE]"):
            finding["title"] = f"[OUT OF SCOPE] {finding['title']}"
        finding["status"] = "rejected"
        finding["validation_notes"] = (
            f"Auto-rejected: Requires {finding['auth_level']} auth, "
            "which is out of Wordfence Bug Bounty scope."
        )
    return finding
```

---

## 6. Expert Performance Metrics

### Track Expert Effectiveness

```python
wpguard_expert_metrics() -> dict:
    """
    Get performance metrics for each expert.

    Returns:
    {
        "experts": {
            "sqli-expert": {
                "total_runs": 50,
                "findings_created": 25,
                "findings_validated": 15,
                "findings_rejected": 10,
                "avg_runtime_minutes": 8.5,
                "effectiveness_score": 0.6
            },
            "race-condition-expert": {
                "total_runs": 0,
                "status": "disabled",
                "reason": "Out of scope"
            }
        },
        "recommendations": [
            "sqli-expert has highest success rate (60%)",
            "xxe-expert rarely finds issues (5%) - consider skipping for small plugins"
        ]
    }
    """
```

---

## Testing Requirements

1. Test expert selection accuracy
2. Test deduplication threshold tuning
3. Test context sharing between experts
4. Test timeout behavior
5. Measure performance improvement with smart selection
6. Track false positive rates per expert
