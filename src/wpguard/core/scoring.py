"""
Target scoring for prioritizing plugin/theme research.
"""

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.core.audit_history import AuditHistoryManager


class TargetScorer:
    """Scores plugins/themes by research priority."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = Path(output_dir)
        self.api = WordPressPluginAPI()
        self.audit_history = AuditHistoryManager(output_dir)

    def score(self, slug: str) -> dict[str, Any]:
        """
        Score a plugin/theme by research priority.

        Higher score = higher priority target.
        """
        plugin = self.api.get_plugin_info(slug)
        if not plugin:
            return {"slug": slug, "error": "Plugin not found", "score": 0}

        # Install score: log10 of active installs (0-7 range)
        installs = max(plugin.active_installs, 1)
        install_score = math.log10(installs) * 3

        # CVE history score
        cve_count = 0
        try:
            from wpguard.api.wordfence import WorkfenceVulnDB
            wf = WorkfenceVulnDB()
            results = wf.search(slug)
            cve_count = len(results) if results else 0
        except Exception:
            pass

        # Sweet spot: 5-20 CVEs = highest score, 0 = good (unaudited), 50+ = diminishing
        if cve_count == 0:
            cve_score = 15  # Unaudited = high value
        elif 5 <= cve_count <= 20:
            cve_score = 20  # Sweet spot
        elif cve_count < 5:
            cve_score = cve_count * 2
        else:
            cve_score = max(20 - (cve_count - 20) * 0.5, 5)

        # Freshness: days since last audit (never audited = max)
        audit_info = self.audit_history.check_audit(slug)
        if audit_info.get("previously_audited"):
            last = audit_info.get("last_audited", "")
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - last_dt).days
                freshness_score = min(days * 0.5, 20)
            except (ValueError, TypeError):
                freshness_score = 20
            # Penalize if same version was already audited
            versions = audit_info.get("versions_audited", [])
            if plugin.version in versions:
                freshness_score *= 0.3  # Heavy penalty for same version
        else:
            freshness_score = 25  # Never audited = highest priority

        total = install_score + cve_score + freshness_score

        return {
            "slug": slug,
            "score": round(total, 1),
            "breakdown": {
                "install_score": round(install_score, 1),
                "cve_score": round(cve_score, 1),
                "freshness_score": round(freshness_score, 1),
            },
            "raw": {
                "active_installs": plugin.active_installs,
                "cve_count": cve_count,
                "previously_audited": audit_info.get("previously_audited", False),
                "versions_audited": audit_info.get("versions_audited", []),
                "current_version": plugin.version,
            },
        }

    def rank(self, slugs: list[str]) -> list[dict[str, Any]]:
        """Score and rank multiple slugs by priority."""
        scores = [self.score(slug) for slug in slugs]
        scores.sort(key=lambda s: s.get("score", 0), reverse=True)
        return scores
