# Target List Auto-Sync Specification

## Overview
Automatically synchronize research results with the vulnerability_targets.json file.

---

## 1. Auto-Sync After Scan Complete

### Problem
After completing plugin analysis, must manually update vulnerability_targets.json with:
- scan_status
- scanned_at date
- findings_count
- notes

### Solution
New MCP tool to auto-sync findings database with target list.

### New MCP Tool

```python
wpguard_sync_targets(
    targets_file: str,  # Path to vulnerability_targets.json
    output_dir: str = ".",  # wpguard project directory
    dry_run: bool = False  # Preview changes without writing
) -> dict:
    """
    Synchronizes wpguard findings with vulnerability targets JSON.

    Returns:
    {
        "success": true,
        "targets_file": "/path/to/vulnerability_targets.json",
        "changes": [
            {
                "slug": "extensions-for-cf7",
                "field": "scan_status",
                "old": "pending",
                "new": "completed"
            },
            {
                "slug": "extensions-for-cf7",
                "field": "findings_count",
                "old": 0,
                "new": 2
            }
        ],
        "summary": {
            "plugins_updated": 3,
            "new_completions": 2,
            "findings_synced": 5
        }
    }
    """
```

### Implementation

```python
import json
from datetime import date
from pathlib import Path

def sync_targets(targets_file: str, output_dir: str = ".", dry_run: bool = False) -> dict:
    targets_path = Path(targets_file)
    findings_path = Path(output_dir) / "wpguard_findings.json"
    scan_state_path = Path(output_dir) / "wpguard_scan_state.json"

    # Load data
    targets = json.loads(targets_path.read_text())
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else {"findings": []}
    scan_state = json.loads(scan_state_path.read_text()) if scan_state_path.exists() else {}

    changes = []

    # Build findings summary per plugin
    findings_by_plugin = {}
    for finding in findings.get("findings", []):
        slug = finding["plugin_slug"]
        if slug not in findings_by_plugin:
            findings_by_plugin[slug] = {
                "total": 0,
                "validated": 0,
                "rejected": 0,
                "draft": 0,
                "findings": []
            }
        findings_by_plugin[slug]["total"] += 1
        findings_by_plugin[slug][finding["status"]] = findings_by_plugin[slug].get(finding["status"], 0) + 1
        findings_by_plugin[slug]["findings"].append(finding)

    # Get scanned plugins from scan_state
    scanned_plugins = set(scan_state.get("plugins_scanned", []))
    pending_plugins = set(scan_state.get("plugins_pending", []))

    # Update each target
    for target in targets["targets"]:
        slug = target["slug"]
        original = target.copy()

        # Determine scan status
        if slug in scanned_plugins:
            if target.get("scan_status") != "completed":
                target["scan_status"] = "completed"
                target["scanned_at"] = date.today().isoformat()
        elif slug in pending_plugins:
            if target.get("scan_status") != "queued":
                target["scan_status"] = "queued"
        elif slug == scan_state.get("current_plugin"):
            target["scan_status"] = "in_progress"
            target["scanned_at"] = date.today().isoformat()

        # Update findings count
        if slug in findings_by_plugin:
            plugin_findings = findings_by_plugin[slug]
            validated_count = plugin_findings.get("validated", 0)

            if target.get("findings_count") != validated_count:
                target["findings_count"] = validated_count

            # Generate notes
            notes_parts = []
            if validated_count > 0:
                notes_parts.append(f"{validated_count} validated")

                # Summarize finding types
                vuln_types = {}
                for f in plugin_findings["findings"]:
                    if f["status"] == "validated":
                        vtype = f["vuln_type"]
                        vuln_types[vtype] = vuln_types.get(vtype, 0) + 1

                type_summary = ", ".join(f"{count} {vtype}" for vtype, count in vuln_types.items())
                notes_parts.append(f"({type_summary})")

            draft_count = plugin_findings.get("draft", 0)
            if draft_count > 0:
                notes_parts.append(f"{draft_count} draft")

            rejected_count = plugin_findings.get("rejected", 0)
            if rejected_count > 0:
                notes_parts.append(f"{rejected_count} rejected")

            target["notes"] = " + ".join(notes_parts) if notes_parts else ""

        # Track changes
        for field in ["scan_status", "scanned_at", "findings_count", "notes"]:
            if target.get(field) != original.get(field):
                changes.append({
                    "slug": slug,
                    "field": field,
                    "old": original.get(field),
                    "new": target.get(field)
                })

    # Write changes
    if not dry_run and changes:
        targets_path.write_text(json.dumps(targets, indent=2))

    return {
        "success": True,
        "targets_file": str(targets_file),
        "changes": changes,
        "dry_run": dry_run,
        "summary": {
            "plugins_updated": len(set(c["slug"] for c in changes)),
            "total_changes": len(changes)
        }
    }
```

---

## 2. Pipeline Integration

### Auto-Sync on Completion

```python
# In pipeline daemon, after QA-triage completes for a plugin
def on_plugin_complete(slug: str):
    # ... existing completion logic ...

    # Auto-sync if targets file configured
    if config.targets_file:
        sync_targets(
            targets_file=config.targets_file,
            output_dir=config.output_dir
        )
```

### Config Option

```python
wpguard_pipeline_config(
    targets_file: str = None,  # NEW: Path to vulnerability_targets.json
    auto_sync_targets: bool = True  # NEW: Sync after each plugin completes
)
```

---

## 3. Status Values

### Supported Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Not yet analyzed |
| `queued` | In pipeline queue, waiting |
| `in_progress` | Currently being analyzed |
| `completed` | Analysis finished |
| `failed` | Analysis failed/errored |
| `skipped` | Intentionally skipped (out of scope, etc.) |

---

## 4. Notes Generation

### Auto-Generated Notes Format

```
{validated_count} validated ({type_summary}) + {draft_count} draft + {rejected_count} rejected
```

### Examples

```
"2 validated (1 sqli, 1 xss) + 3 draft + 5 rejected"
"8 validated (1 object_injection, 6 idor, 1 info_disclosure) + 4 draft"
"0 validated + 6 rejected (all admin-only)"
```

### Custom Notes Preservation

If target already has custom notes (not auto-generated pattern), append instead of replace:

```python
def update_notes(target, new_notes):
    existing = target.get("notes", "")

    # Check if existing notes are auto-generated
    if re.match(r"^\d+ validated", existing):
        # Replace auto-generated notes
        target["notes"] = new_notes
    elif existing:
        # Append to custom notes
        target["notes"] = f"{existing}. {new_notes}"
    else:
        target["notes"] = new_notes
```

---

## 5. Bidirectional Sync

### Import Targets to Pending Queue

```python
wpguard_import_targets(
    targets_file: str,
    status_filter: str = "pending",  # Only import pending targets
    limit: int = 10,
    output_dir: str = "."
) -> dict:
    """
    Import targets from JSON to wpguard pending queue.

    Returns:
    {
        "imported": 10,
        "slugs": ["plugin1", "plugin2", ...],
        "skipped": 5,
        "skip_reasons": {
            "already_scanned": 3,
            "already_queued": 2
        }
    }
    """
```

### Implementation

```python
def import_targets(targets_file: str, status_filter: str = "pending",
                   limit: int = 10, output_dir: str = ".") -> dict:
    targets = json.loads(Path(targets_file).read_text())
    scan_state = load_scan_state(output_dir)

    already_scanned = set(scan_state.get("plugins_scanned", []))
    already_pending = set(scan_state.get("plugins_pending", []))

    imported = []
    skipped = {"already_scanned": 0, "already_queued": 0}

    for target in targets["targets"]:
        if len(imported) >= limit:
            break

        slug = target["slug"]

        if target.get("scan_status") != status_filter:
            continue

        if slug in already_scanned:
            skipped["already_scanned"] += 1
            continue

        if slug in already_pending:
            skipped["already_queued"] += 1
            continue

        imported.append(slug)

    # Add to pending queue
    scan_state["plugins_pending"].extend(imported)
    save_scan_state(scan_state, output_dir)

    return {
        "imported": len(imported),
        "slugs": imported,
        "skipped": sum(skipped.values()),
        "skip_reasons": skipped
    }
```

---

## 6. CLI Integration

### Sync Command

```bash
# Sync findings to targets file
wpguard sync-targets --targets ~/Projects/vulnerability_targets.json

# Dry run
wpguard sync-targets --targets ~/Projects/vulnerability_targets.json --dry-run

# Import pending targets to queue
wpguard import-targets --targets ~/Projects/vulnerability_targets.json --limit 10
```

---

## Testing Requirements

1. Test sync with empty findings
2. Test sync with mixed statuses
3. Test notes generation formats
4. Test custom notes preservation
5. Test bidirectional sync
6. Test concurrent access (locking)
