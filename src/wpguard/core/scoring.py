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

        # Sweet spot: 2-6 CVEs = highest (confirmed by 100+ audit data)
        # 0 = unaudited = high value, 20+ = well-hardened = diminishing
        if cve_count == 0:
            cve_score = 15  # Never scrutinized
        elif 2 <= cve_count <= 6:
            cve_score = 25  # Sweet spot — incomplete fixes likely
        elif cve_count < 2:
            cve_score = cve_count * 4
        elif 7 <= cve_count <= 15:
            cve_score = 18  # Still productive
        elif 16 <= cve_count <= 20:
            cve_score = 12  # Diminishing
        else:
            cve_score = max(10 - (cve_count - 20) * 0.5, 0)  # 20+ = likely hardened

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

        # Category score based on plugin type heuristics
        category_score = self._category_score(plugin, cve_count)

        total = install_score + cve_score + freshness_score + category_score

        return {
            "slug": slug,
            "score": round(total, 1),
            "breakdown": {
                "install_score": round(install_score, 1),
                "category_score": round(category_score, 1),
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

    @staticmethod
    def _category_score(plugin: Any, cve_count: int) -> float:
        """Score based on plugin category heuristics from 100+ audit data."""
        score = 0.0
        text = f"{plugin.name} {plugin.slug} {plugin.short_description}".lower()

        # Productive patterns (positive)
        productive = [
            (["membership", "member", "role", "user role", "capability"], 8),
            (["payment", "webhook", "stripe", "paypal", "woocommerce", "checkout"], 8),
            (["booking", "appointment", "reservation", "calendar"], 6),
            (["form", "submit", "upload", "frontend"], 6),
            (["crm", "contact", "lead", "customer"], 6),
            (["import", "export", "csv", "migration"], 5),
            (["multivendor", "marketplace", "vendor"], 7),
            (["registration", "signup", "login", "password"], 6),
        ]
        for keywords, boost in productive:
            if any(kw in text for kw in keywords):
                score += boost
                break  # Only count best match

        # 0-CVE complex plugin = never scrutinized
        if cve_count == 0 and plugin.active_installs >= 5000:
            score += 8

        # Unproductive patterns (negative)
        unproductive = [
            (["cache", "performance", "speed", "minify", "optimize", "autoptimize"], -8),
            (["admin dashboard", "admin menu", "admin bar", "admin tool"], -6),
            (["theme", "starter theme", "starter sites"], -5),
            (["analytics", "tracking", "statistics", "google analytics"], -5),
            (["backup", "restore", "clone", "migrate"], -3),  # Only slight penalty — some have vulns
        ]
        for keywords, penalty in unproductive:
            if any(kw in text for kw in keywords):
                score += penalty
                break

        # 20+ CVEs = well-hardened, steep penalty
        if cve_count >= 20:
            score -= 10

        return max(score, -15)  # Floor at -15

    def rank(self, slugs: list[str]) -> list[dict[str, Any]]:
        """Score and rank multiple slugs by priority."""
        scores = [self.score(slug) for slug in slugs]
        scores.sort(key=lambda s: s.get("score", 0), reverse=True)
        return scores
