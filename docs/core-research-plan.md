# WordPress Core Research — wpguard Extension Plan

Status: **in progress** (branch `feature/core-research`)
Owner: security research
Verification model: **live** — drive real tools against the sandbox and real core SVN/API. No unit-test directory.

---

## Motivation

wpguard is built around one assumption baked into every layer: a target = a wordpress.org
plugin/theme slug, scored by install count, submitted to Wordfence. WordPress **core** breaks all
three, so it needs a parallel target type that reuses the analysis engine.

The trigger case was the wp2shell pre-auth REST batch route-confusion SQLi (fixed in 6.9.4→7.0.2).
It was findable by **diffing the security release**. That is the pattern this extension is built to
exploit.

| Assumption | Plugin/theme today | Core |
|---|---|---|
| Acquisition | `WP_PLUGINS_SVN` / `WP_THEMES_SVN` by slug (`core/downloader.py`) | `core.svn.wordpress.org` by version tag |
| Scoping | `TIER_MIN_INSTALLS` by active installs (`scope_validator.py`) | No install tiers — core is always "max" |
| Program | Wordfence BB; `EXCLUDED_VENDORS` blocks `wordpress`/`automattic` | HackerOne "WordPress" program — different rules/format |
| Analysis | grep-map one small plugin (`surface-mapper.md`) | Thousands of files — must be **subsystem-scoped** |
| Realistic edge | Greenfield 0-day in under-reviewed plugins | **N-day / variant / incomplete-fix off security releases** |

## Guardrails

- **Sandbox-only.** Core testing runs only against the local sandbox (`wp_app`, `172.17.0.1:8000`).
  Never scan wordpress.org or any live site. Written into every core agent's authorization header.
- **Subsystem-scoped analysis.** Never turn an expert loose on all of core — always scope to a
  named subsystem, or context/budget blows up.
- **Lead with diff, not greenfield.** Core 0-day is contested; the edge is n-day/variant work.

---

## Phases

### Phase 1 — Acquire & Diff  *(MVP, highest ROI, self-contained)*
- `config.py`: `WP_CORE_SVN`, core version-check/stable-check API, `WP_CORE_DOWNLOAD`, `CORE_SUBDIR`.
- `api/wordpress_core.py` (new): list versions, latest/stable, release dates, flag security releases.
- `core/models.py`: `CoreVersionInfo`.
- `core/downloader.py`: reuse `SVNClient` against core SVN → fetch a version tag into
  `targets/core-{version}/extracted/`.
- MCP tools: `wpguard_core_versions`, `wpguard_core_download`, `wpguard_core_svn_diff`.
- Reuse `/diff` and `/nday` unchanged.
- **Live verification:** list real versions; download `6.9.4`; diff `6.9.4`→`7.0.2` and confirm the
  REST batch controller change appears.

### Phase 2 — Sandbox core control  *(fixes the auto-update pain we hit)*
- `core/sandbox.py`: `set_core_version(v)` (`wp core update --version=X --force`), reliable
  auto-update kill (`AUTOMATIC_UPDATER_DISABLED` baked into image/wp-config), `reset_to_version`,
  optional multisite provisioning.
- MCP tool: `wpguard_sandbox_set_core_version`.
- **Live verification:** pin sandbox to 6.9.4, confirm it stays pinned, confirm auto-update disabled.

### Phase 3 — Core scope & submission
- `core/scope_validator.py`: `program="core"` mode — no install tiers, core OOS list, bypass
  `EXCLUDED_VENDORS` for core, multisite super-admin auth model.
- `core/findings.py` + `qa-triage.md` + `bb-submission.md`: core metadata, HackerOne submission
  format, core CVSS norms.
- MCP tool: `wpguard_core_scope_check`.

### Phase 4 — Core-aware analysis flow
- `templates/core-subsystems.md` (new): high-value surfaces (REST + batch controller, WP_Query /
  meta_query SQL builders, shortcodes, wp_kses, XML-RPC, phar/deserialization, auth/nonce/cap,
  multisite).
- `templates/protocol-confusion-expert.md` (new): dispatch/validation-desync lens.
- Reframe `critical-thinker.md` + `data-flow-expert.md`: audit core dispatch primitive invariants.
- `pm.md` core mode: subsystem-driven delegation.

### Phase 5 — Continuous monitoring & variant hunting
- `core/watcher.py`: watch core releases; a new security release auto-triggers Phase 1 diff.
- Variant hunt: wire veloria WordPress-wide search to find plugins replicating a freshly-patched
  core pattern → in-scope Wordfence findings.

---

## Reference endpoints

- Core SVN: `https://core.svn.wordpress.org/` (`tags/{version}`, `branches/`, `trunk/`)
- Version check: `https://api.wordpress.org/core/version-check/1.7/`
- Stable check: `https://api.wordpress.org/core/stable-check/1.0/`
- Release zip: `https://wordpress.org/wordpress-{version}.zip`

## Progress log

- [x] Phase 1 — Acquire & Diff (commit `d994db9`) — live-verified: 7.0.1→7.0.2 diff = 6 files isolating the wp2shell fix
- [x] Phase 2 — Sandbox core control (commit `007112f`) — sandbox pinned 6.9.4, auto-update reliably disabled (anchor-failure fallback)
- [x] Phase 3 — Core scope & submission (commit `c1cf6a2`) — CoreScopeValidator, target_type on findings, HackerOne submission sections; back-compat verified
- [ ] Phase 4 — Core-aware analysis flow
- [ ] Phase 5 — Continuous monitoring & variant hunting
