# Reporting Enhancements Specification

## Overview
Automated report generation, submission preparation, and finding deduplication.

---

## 1. Auto-Generate Summary Reports

### Problem
Must manually create summary reports after completing plugin analysis.

### Solution
Automated report generation from findings database.

### New MCP Tool

```python
wpguard_generate_report(
    plugin_slug: str,
    format: str = "markdown",  # "markdown", "json", "html"
    output_path: str = None,  # Auto-generate if not provided
    include_rejected: bool = False,
    include_poc_code: bool = True
) -> dict:
    """
    Generate comprehensive report for a plugin.

    Returns:
    {
        "success": true,
        "output_path": "reports/plugin-name/SUMMARY.md",
        "findings_included": 5,
        "sections": ["summary", "findings", "timeline", "references"]
    }
    """
```

### Report Template (Markdown)

```markdown
# {plugin_name} - Security Research Summary

**Plugin:** {plugin_name} ({slug})
**Version:** {version}
**Active Installs:** {installs:,}
**Analyzed:** {date}

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Findings | {total} |
| Validated | {validated} |
| Draft | {draft} |
| Rejected | {rejected} |

### Severity Distribution

| Severity | Count | Findings |
|----------|-------|----------|
| Critical (9.0+) | {critical_count} | {critical_ids} |
| High (7.0-8.9) | {high_count} | {high_ids} |
| Medium (4.0-6.9) | {medium_count} | {medium_ids} |
| Low (0.1-3.9) | {low_count} | {low_ids} |

## Validated Findings

{for finding in validated_findings}
### {finding.id}: {finding.title}

| Field | Value |
|-------|-------|
| Type | {finding.vuln_type} |
| CVSS | {finding.cvss_score} ({finding.cvss_vector}) |
| Auth Level | {finding.auth_level} |
| Affected | {finding.affected_file}:{finding.affected_line} |

**Description:**
{finding.description}

**PoC:** `{finding.poc_path}`

---
{endfor}

## Draft Findings (Needs Review)

{for finding in draft_findings}
- **{finding.id}**: {finding.title} (CVSS {finding.cvss_score})
{endfor}

## Rejected Findings

{for finding in rejected_findings}
- **{finding.id}**: {finding.title} - {finding.validation_notes}
{endfor}

## Timeline

| Date | Event |
|------|-------|
{for event in timeline}
| {event.date} | {event.description} |
{endfor}

## Files

- Reports: `reports/{slug}/`
- PoC Scripts: `reports/{slug}/poc_*.py`
- Findings Database: `wpguard_findings.json`
```

### Implementation

```python
from jinja2 import Template
from pathlib import Path

class ReportGenerator:
    def __init__(self):
        self.templates = {
            "markdown": self._load_template("report.md.j2"),
            "html": self._load_template("report.html.j2"),
            "json": None  # Direct serialization
        }

    def generate(self, plugin_slug: str, format: str = "markdown",
                 output_path: str = None, **options) -> dict:
        # Load findings
        findings = load_findings(plugin_slug=plugin_slug)
        plugin_info = get_plugin_info(plugin_slug)

        # Categorize findings
        validated = [f for f in findings if f["status"] == "validated"]
        draft = [f for f in findings if f["status"] == "draft"]
        rejected = [f for f in findings if f["status"] == "rejected"]

        # Prepare context
        context = {
            "plugin_name": plugin_info["name"],
            "slug": plugin_slug,
            "version": plugin_info["version"],
            "installs": plugin_info["active_installs"],
            "date": datetime.now().strftime("%Y-%m-%d"),
            "total": len(findings),
            "validated": len(validated),
            "draft": len(draft),
            "rejected": len(rejected),
            "validated_findings": validated,
            "draft_findings": draft if options.get("include_rejected") else [],
            "rejected_findings": rejected if options.get("include_rejected") else [],
            "severity_distribution": self._calculate_severity(validated),
            "timeline": self._build_timeline(findings)
        }

        # Generate output
        if format == "json":
            content = json.dumps(context, indent=2, default=str)
        else:
            template = self.templates[format]
            content = template.render(**context)

        # Write to file
        if not output_path:
            output_path = f"reports/{plugin_slug}/SUMMARY.{format}"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(content)

        return {
            "success": True,
            "output_path": output_path,
            "findings_included": len(validated) + len(draft)
        }
```

---

## 2. Wordfence Submission Draft

### Problem
Preparing findings for Wordfence submission requires specific formatting.

### Solution
Generate submission-ready reports.

### New MCP Tool

```python
wpguard_prepare_submission(
    finding_id: str,
    output_path: str = None
) -> dict:
    """
    Prepare finding for Wordfence submission.

    Returns:
    {
        "success": true,
        "finding_id": "abc123",
        "submission": {
            "title": "Plugin Name <= 1.0.0 - Auth Level - Vulnerability Type",
            "description": "...",
            "cvss_score": 7.5,
            "cvss_justification": "...",
            "affected_versions": "<= 1.0.0",
            "poc_steps": [...],
            "remediation": "..."
        },
        "output_path": "reports/plugin/submission_abc123.md"
    }
    """
```

### Submission Format

```markdown
# Wordfence Submission: {title}

## Vulnerability Title
{plugin_name} <= {version} - {auth_level} - {vuln_type_readable}

## Affected Software
- **Plugin:** {plugin_name}
- **Slug:** {slug}
- **Affected Versions:** <= {version}
- **Patched Version:** Not patched (0-day) / {patched_version}

## Vulnerability Type
{vuln_type_readable} (CWE-{cwe_id})

## CVSS Score
**{cvss_score}** ({severity})

### CVSS Vector
`{cvss_vector}`

### Justification
- **Attack Vector (AV):** {av_justification}
- **Attack Complexity (AC):** {ac_justification}
- **Privileges Required (PR):** {pr_justification}
- **User Interaction (UI):** {ui_justification}
- **Scope (S):** {s_justification}
- **Confidentiality (C):** {c_justification}
- **Integrity (I):** {i_justification}
- **Availability (A):** {a_justification}

## Description
{detailed_description}

## Proof of Concept

### Prerequisites
1. WordPress installation with {plugin_name} version {version}
2. {auth_level} account (if applicable)
3. {other_prerequisites}

### Steps to Reproduce
1. {step_1}
2. {step_2}
3. {step_3}
...

### Expected Result
{expected_result}

### Actual Result
{actual_result}

### PoC Script
```python
{poc_code}
```

## Impact
{impact_description}

## Remediation
{remediation_recommendation}

## References
- {reference_1}
- {reference_2}

## Timeline
| Date | Action |
|------|--------|
| {discovery_date} | Vulnerability discovered |
| {submission_date} | Submitted to Wordfence |
```

### CVSS Justification Generator

```python
CVSS_JUSTIFICATIONS = {
    "AV": {
        "N": "Network - Exploitable remotely via HTTP requests",
        "A": "Adjacent - Requires same network segment",
        "L": "Local - Requires local access",
        "P": "Physical - Requires physical access"
    },
    "AC": {
        "L": "Low - No special conditions required",
        "H": "High - Requires specific conditions or race"
    },
    "PR": {
        "N": "None - Unauthenticated attack",
        "L": "Low - Requires subscriber/customer account",
        "H": "High - Requires admin/editor account"
    },
    "UI": {
        "N": "None - No user interaction required",
        "R": "Required - Victim must click link or visit page"
    },
    "S": {
        "U": "Unchanged - Impact limited to vulnerable component",
        "C": "Changed - Impact extends beyond vulnerable component"
    },
    "C": {
        "N": "None - No confidentiality impact",
        "L": "Low - Some data exposed",
        "H": "High - All data potentially exposed"
    },
    "I": {
        "N": "None - No integrity impact",
        "L": "Low - Some data can be modified",
        "H": "High - All data can be modified"
    },
    "A": {
        "N": "None - No availability impact",
        "L": "Low - Partial degradation",
        "H": "High - Complete denial of service"
    }
}

def generate_cvss_justification(vector: str) -> dict:
    """Parse CVSS vector and generate justifications."""
    parts = vector.replace("CVSS:3.1/", "").split("/")
    justifications = {}

    for part in parts:
        metric, value = part.split(":")
        justifications[f"{metric}_justification"] = CVSS_JUSTIFICATIONS[metric][value]

    return justifications
```

---

## 3. Finding Deduplication

### Problem
Multiple expert agents may find the same vulnerability, creating duplicates.

### Solution
Automatic deduplication during finding creation.

### Enhanced Finding Create

```python
wpguard_finding_create(
    ...
    dedupe_check: bool = True,  # NEW
    dedupe_threshold: float = 0.8  # NEW: Similarity threshold
)
```

### Deduplication Logic

```python
def check_duplicate(new_finding: dict, existing_findings: list,
                    threshold: float = 0.8) -> dict:
    """
    Check if finding is duplicate of existing one.

    Returns:
    {
        "is_duplicate": true,
        "duplicate_of": "abc123",
        "similarity": 0.95,
        "matching_factors": ["same_file", "same_function", "similar_title"]
    }
    """
    for existing in existing_findings:
        if existing["plugin_slug"] != new_finding["plugin_slug"]:
            continue

        similarity = 0.0
        matching_factors = []

        # Same file
        if existing["affected_file"] == new_finding["affected_file"]:
            similarity += 0.3
            matching_factors.append("same_file")

        # Same function
        if existing.get("affected_function") == new_finding.get("affected_function"):
            similarity += 0.3
            matching_factors.append("same_function")

        # Same vuln type
        if existing["vuln_type"] == new_finding["vuln_type"]:
            similarity += 0.2
            matching_factors.append("same_vuln_type")

        # Similar line number (within 10 lines)
        if abs(existing.get("affected_line", 0) - new_finding.get("affected_line", 0)) <= 10:
            similarity += 0.1
            matching_factors.append("similar_line")

        # Title similarity
        title_sim = fuzz.ratio(existing["title"], new_finding["title"]) / 100
        similarity += title_sim * 0.1

        if similarity >= threshold:
            return {
                "is_duplicate": True,
                "duplicate_of": existing["id"],
                "similarity": round(similarity, 2),
                "matching_factors": matching_factors
            }

    return {"is_duplicate": False}
```

### Merge Duplicate Information

```python
def merge_findings(primary_id: str, duplicate_id: str) -> dict:
    """Merge duplicate finding info into primary."""
    primary = get_finding(primary_id)
    duplicate = get_finding(duplicate_id)

    # Merge descriptions (append unique info)
    if duplicate["description"] not in primary["description"]:
        primary["description"] += f"\n\n---\n**Additional Analysis:**\n{duplicate['description']}"

    # Keep higher CVSS
    if duplicate["cvss_score"] > primary["cvss_score"]:
        primary["cvss_score"] = duplicate["cvss_score"]
        primary["cvss_vector"] = duplicate["cvss_vector"]

    # Add validation notes
    primary["validation_notes"] += f"\nMerged from duplicate finding {duplicate_id}"

    # Mark duplicate as rejected
    update_finding(duplicate_id, status="duplicate", validation_notes=f"Duplicate of {primary_id}")

    return update_finding(primary_id, **primary)
```

---

## 4. Batch Report Generation

### Problem
Need to generate reports for multiple plugins at once.

### Solution
Batch report generation tool.

### New MCP Tool

```python
wpguard_generate_batch_reports(
    plugin_slugs: list = None,  # None = all scanned plugins
    format: str = "markdown",
    output_dir: str = "reports"
) -> dict:
    """
    Generate reports for multiple plugins.

    Returns:
    {
        "success": true,
        "reports_generated": 5,
        "reports": [
            {"slug": "plugin-1", "path": "reports/plugin-1/SUMMARY.md"},
            {"slug": "plugin-2", "path": "reports/plugin-2/SUMMARY.md"}
        ]
    }
    """
```

---

## 5. Research Session Summary

### Problem
No overview of entire research session results.

### Solution
Session-level summary report.

### New MCP Tool

```python
wpguard_session_summary(
    output_path: str = None
) -> dict:
    """
    Generate summary of entire research session.

    Returns comprehensive statistics and findings overview.
    """
```

### Session Summary Template

```markdown
# Security Research Session Summary

**Session:** {session_id}
**Started:** {start_time}
**Duration:** {duration}

## Plugins Analyzed

| Plugin | Installs | Findings | Status |
|--------|----------|----------|--------|
{for plugin in plugins}
| {plugin.name} | {plugin.installs:,} | {plugin.findings} | {plugin.status} |
{endfor}

## Findings Summary

| Category | Count |
|----------|-------|
| Total Findings | {total} |
| Validated | {validated} |
| Rejected (Admin-only) | {rejected_admin} |
| Rejected (Other) | {rejected_other} |
| Draft | {draft} |

## Top Findings by CVSS

{for finding in top_findings[:10]}
1. **{finding.cvss_score}** - {finding.plugin}: {finding.title}
{endfor}

## Vulnerability Type Distribution

| Type | Count | Avg CVSS |
|------|-------|----------|
{for vtype, stats in vuln_types.items()}
| {vtype} | {stats.count} | {stats.avg_cvss:.1f} |
{endfor}

## Bounty Eligibility

| Tier | Eligible Findings | Est. Value |
|------|-------------------|------------|
| High Threat | {high_threat} | ${high_value:,} |
| Standard | {standard} | ${standard_value:,} |
| 1337 | {elite} | ${elite_value:,} |

**Total Estimated Bounty:** ${total_value:,}
```

---

## Testing Requirements

1. Test report generation for various finding combinations
2. Test submission format compliance
3. Test deduplication accuracy
4. Test CVSS justification generation
5. Test batch report generation
6. Test session summary statistics
