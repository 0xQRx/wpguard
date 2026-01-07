# WPGuard Enhancement Specifications

## Overview

This directory contains detailed specifications for wpguard tool improvements based on real-world security research experience.

## Specification Files

| # | File | Description | Priority |
|---|------|-------------|----------|
| 001 | [pipeline_enhancements.md](001_pipeline_enhancements.md) | Pipeline automation improvements | P0 |
| 002 | [scope_auto_validation.md](002_scope_auto_validation.md) | Automatic scope checking | P0 |
| 003 | [target_sync.md](003_target_sync.md) | Target list synchronization | P0 |
| 004 | [cve_integration.md](004_cve_integration.md) | Enhanced CVE database usage | P1 |
| 005 | [sandbox_improvements.md](005_sandbox_improvements.md) | Sandbox testing enhancements | P1 |
| 006 | [process_management.md](006_process_management.md) | Process & health monitoring | P0 |
| 007 | [reporting_enhancements.md](007_reporting_enhancements.md) | Automated reporting | P1 |
| 008 | [new_mcp_tools.md](008_new_mcp_tools.md) | New MCP analysis tools | P0 |
| 009 | [expert_agent_improvements.md](009_expert_agent_improvements.md) | Expert agent optimizations | P1 |

## Priority Legend

- **P0**: Critical - Implement immediately, high impact on efficiency
- **P1**: Important - Significant improvement, implement soon
- **P2**: Nice to have - Implement when time permits

## Quick Reference: New MCP Tools

### Analysis Tools (P0)
| Tool | Purpose |
|------|---------|
| `wpguard_plugin_ajax_endpoints` | Extract AJAX handlers with auth analysis |
| `wpguard_plugin_rest_endpoints` | Extract REST routes with permissions |
| `wpguard_plugin_db_queries` | Find unsafe SQL patterns |
| `wpguard_analyze_auth_patterns` | Comprehensive auth analysis |

### Automation Tools (P0)
| Tool | Purpose |
|------|---------|
| `wpguard_sync_targets` | Sync findings with target list |
| `wpguard_cleanup_processes` | Kill stale processes |
| `wpguard_resource_status` | Monitor resource usage |

### Research Tools (P1)
| Tool | Purpose |
|------|---------|
| `wpguard_plugin_hooks` | List all hooks (actions/filters) |
| `wpguard_plugin_file_ops` | Find file operations |
| `wpguard_compare_versions` | Diff versions for security |
| `wpguard_cve_patch_analysis` | Detect incomplete patches |
| `wpguard_plugin_risk_score` | Calculate plugin risk |

### Sandbox Tools (P1)
| Tool | Purpose |
|------|---------|
| `wpguard_sandbox_run_poc` | Execute PoC scripts |
| `wpguard_sandbox_health` | Health check with auto-heal |
| `wpguard_sandbox_test_auth_levels` | Multi-auth testing |

### Reporting Tools (P1)
| Tool | Purpose |
|------|---------|
| `wpguard_generate_report` | Auto-generate reports |
| `wpguard_prepare_submission` | Format for Wordfence submission |

## Quick Reference: Config Options

### Pipeline Config
```python
wpguard_pipeline_config(
    # Existing
    num_iterations=1,
    deferred_qa=True,

    # New - Pipeline
    source="pending_queue",  # Read from pending queue
    skip_target_research_for_explicit_slugs=True,
    targets_file="/path/to/vulnerability_targets.json",
    auto_sync_targets=True,

    # New - Health
    health_observer_enabled=True,
    health_check_interval_minutes=5,
    auto_restart_stuck_workers=True,
    auto_heal_sandbox=True,

    # New - Experts
    smart_expert_selection=True,
    skip_experts=["race-condition-expert"],  # Unless high-impact patterns
    expert_timeouts={"sqli-expert": 15, ...},

    # New - Sandbox
    auto_install_plugin=True,
    auto_uninstall_after=True,

    # New - Findings
    auto_scope_check=True,
    auto_reject_admin=True,
    dedupe_findings=True
)
```

## Implementation Order

### Phase 1: Critical Efficiency (Week 1)
1. Auto-sync targets (`wpguard_sync_targets`)
2. Admin-only auto-rejection
3. Skip target-research for explicit slugs
4. Process cleanup (`wpguard_cleanup_processes`)
5. Health observer agent

### Phase 2: Analysis Enhancement (Week 2)
1. AJAX endpoint extractor
2. REST endpoint extractor
3. DB query analyzer
4. Auth pattern analyzer

### Phase 3: Automation (Week 3)
1. PoC auto-execution
2. Sandbox health/auto-heal
3. Report generation
4. Submission preparation

### Phase 4: Intelligence (Week 4)
1. CVE patch bypass detection
2. Plugin risk scoring
3. Research guidance
4. Version comparison

## Metrics to Track

After implementation, measure:

1. **Time saved per plugin**: Target 30% reduction
2. **False positive rate**: Target <10%
3. **Duplicate findings**: Target <5%
4. **Admin-only findings caught early**: Target 100%
5. **Pipeline uptime**: Target 99%
6. **Memory usage**: Target <2GB sustained

## Files Modified

Implementation will modify:

- `wpguard/mcp_server.py` - New MCP tools
- `wpguard/pipeline.py` - Pipeline enhancements
- `wpguard/health.py` - New health monitoring
- `wpguard/analyzers/` - New analysis modules
- `wpguard/reports/` - Report generation
- `.claude/commands/` - New slash commands

## Testing Strategy

1. Unit tests for each new analyzer
2. Integration tests for pipeline changes
3. End-to-end test with known vulnerable plugin
4. Performance benchmarks before/after
5. False positive/negative tracking
