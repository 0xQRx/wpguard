"""
Wordfence Bug Bounty Estimator.

Calculates estimated bounty rewards based on the official calculator config
from https://www.wordfence.com/api/threat-intel/bounty-calculator-config

Config is fetched live and cached. Formula:
  bounty = vuln_value × install_mult / auth_div × threat_mult × impact × tier_mult
  Minimum: $5
"""

import json
import math
import sys
import time
from pathlib import Path
from typing import Any

import requests


CONFIG_URL = "https://www.wordfence.com/api/threat-intel/bounty-calculator-config"
CACHE_FILENAME = "bounty_calculator_config.json"
CACHE_TTL = 86400  # 24 hours


class BountyEstimator:
    """Estimates Wordfence bug bounty rewards."""

    def __init__(self, cache_dir: str | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.config: dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load config from cache or fetch from API."""
        # Try cache first
        if self.cache_dir:
            cache_path = self.cache_dir / CACHE_FILENAME
            if cache_path.exists():
                try:
                    data = json.loads(cache_path.read_text())
                    if data.get("_cached_at", 0) + CACHE_TTL > time.time():
                        self.config = data
                        return
                except (json.JSONDecodeError, IOError):
                    pass

        # Fetch from API
        try:
            r = requests.get(CONFIG_URL, timeout=15)
            r.raise_for_status()
            self.config = r.json()
            self.config["_cached_at"] = time.time()

            # Save to cache
            if self.cache_dir:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                (self.cache_dir / CACHE_FILENAME).write_text(
                    json.dumps(self.config, indent=2)
                )
        except requests.RequestException as e:
            print(f"[WARN] Could not fetch bounty config: {e}", file=sys.stderr)

    def estimate(
        self,
        vuln_type: str,
        install_count: int,
        auth_level: str = "none",
        researcher_tier: int = 0,
    ) -> dict[str, Any]:
        """
        Estimate bounty for a vulnerability.

        Args:
            vuln_type: Vulnerability type key (e.g., "rce", "sql_injection", "stored_xss")
            install_count: Active installations
            auth_level: "none", "low" (subscriber), "mid" (contributor/author), "high" (admin)
            researcher_tier: 0=Standard, 1=1337, 2=Resourceful

        Returns:
            Dict with min/max bounty, breakdown, and scope status
        """
        if not self.config:
            return {"error": "Bounty config not loaded"}

        # Resolve vulnerability type
        vuln_types = self.config.get("vulnerability_types", {})
        vuln = vuln_types.get(vuln_type)
        if not vuln:
            return {"error": f"Unknown vuln type: {vuln_type}", "valid_types": list(vuln_types.keys())}

        # Resolve auth level
        auth_levels = self.config.get("authentication_levels", {})
        auth = auth_levels.get(auth_level)
        if not auth:
            return {"error": f"Unknown auth level: {auth_level}", "valid_levels": list(auth_levels.keys())}

        # Check vuln-specific auth level restrictions
        # Some vulns (e.g., shortcode execution) only allow specific auth levels
        allowed_auths = vuln.get("authentication_levels", [])
        if allowed_auths and auth_level not in allowed_auths:
            return {
                "vuln_type": vuln["description"],
                "auth_level": auth["description"],
                "in_scope": False,
                "reason": f"This vulnerability type only allows auth levels: {allowed_auths}",
                "min_bounty": 0,
                "max_bounty": 0,
            }

        # Auth-agnostic vulns (reflected XSS, CSRF) ignore auth level entirely
        if vuln.get("authentication_agnostic"):
            auth_divisor = 1.0
        else:
            auth_divisor = auth.get("divisor")
            if auth_divisor is None:
                return {
                    "vuln_type": vuln["description"],
                    "auth_level": auth["description"],
                    "in_scope": False,
                    "reason": "High-level authentication is out of scope for this vulnerability type",
                    "min_bounty": 0,
                    "max_bounty": 0,
                }

        # Resolve install count tier
        install_tier = self._get_install_tier(install_count, researcher_tier)
        if not install_tier:
            return {
                "vuln_type": vuln["description"],
                "auth_level": auth["description"],
                "in_scope": False,
                "reason": f"Install count {install_count} is below minimum threshold",
                "min_bounty": 0,
                "max_bounty": 0,
            }

        install_mult = install_tier["multiplier"]
        if install_mult == 0:
            return {
                "vuln_type": vuln["description"],
                "auth_level": auth["description"],
                "in_scope": False,
                "reason": "Install count tier has zero multiplier (< 25 installs)",
                "min_bounty": 0,
                "max_bounty": 0,
            }

        # Check minimum install requirements for auth level + vuln type
        min_install_reqs = vuln.get("authentication_level_min_install_counts", {})
        if min_install_reqs:
            for min_count_str, allowed_auths in min_install_reqs.items():
                if auth_level in allowed_auths:
                    if install_count < int(min_count_str):
                        return {
                            "vuln_type": vuln["description"],
                            "auth_level": auth["description"],
                            "in_scope": False,
                            "reason": f"Requires {min_count_str}+ installs for {auth_level} auth",
                            "min_bounty": 0,
                            "max_bounty": 0,
                        }

        # Resolve threat level multiplier (promo)
        threat_mult = 1.0
        threat_level = vuln.get("threat_level")
        if threat_level:
            threat_mults = self.config.get("threat_level_multipliers", {}).get(threat_level, {})
            if threat_mults:
                # The promo keys represent min install thresholds. If the tier's
                # min_count exceeds the highest promo key, no promo applies
                # (e.g., 5M+ tier excluded from promo that only covers up to 1M)
                max_promo_key = max(int(k) for k in threat_mults.keys())
                tier_min = install_tier.get("min_count", 0) if install_tier else 0
                if tier_min <= max_promo_key:
                    for min_str in sorted(threat_mults.keys(), key=int, reverse=True):
                        if install_count >= int(min_str):
                            threat_mult = threat_mults[min_str]
                            break

        # Researcher tier multiplier
        tier_mult = 1.0
        tiers = self.config.get("researcher_tiers", [])
        if researcher_tier < len(tiers):
            tier = tiers[researcher_tier]
            if tier.get("bounty_multiplier"):
                tier_mult = 1 + float(tier["bounty_multiplier"])

        # Global multiplier
        global_mult = self.config.get("global_multiplier", 1)
        global_min = self.config.get("global_minimum", 5)

        # Calculate range (impact low=0.25 to critical=1.0)
        base = vuln["value"] * install_mult / auth_divisor * threat_mult * tier_mult * global_mult
        min_bounty = max(math.ceil(base * 0.25), global_min)
        max_bounty = max(math.ceil(base * 1.0), global_min)

        return {
            "vuln_type": vuln["description"],
            "auth_level": auth["description"],
            "install_count": install_count,
            "in_scope": True,
            "min_bounty": min_bounty,
            "max_bounty": max_bounty,
            "bounty_range": f"${min_bounty:,} – ${max_bounty:,}",
            "breakdown": {
                "vuln_base_value": vuln["value"],
                "install_multiplier": install_mult,
                "auth_divisor": auth_divisor,
                "threat_multiplier": threat_mult,
                "tier_multiplier": tier_mult,
                "threat_level": threat_level,
            },
        }

    def _get_install_tier(self, install_count: int, researcher_tier: int = 0) -> dict | None:
        """Get the install count tier for a given count."""
        tiers = self.config.get("researcher_tiers", [])
        if researcher_tier < len(tiers):
            tier_installs = tiers[researcher_tier].get("install_count_multipliers", {})
        else:
            tier_installs = self.config.get("install_count_tiers", {})

        for key, tier in tier_installs.items():
            min_c = tier.get("min_count", 0)
            max_c = tier.get("max_count")
            if max_c is None:
                if install_count >= min_c:
                    return tier
            elif min_c <= install_count <= max_c:
                return tier
        return None

    def estimate_all_types(
        self,
        install_count: int,
        auth_level: str = "none",
        researcher_tier: int = 0,
    ) -> list[dict[str, Any]]:
        """Estimate bounty for all vulnerability types at given install/auth."""
        results = []
        for vtype in self.config.get("vulnerability_types", {}):
            est = self.estimate(vtype, install_count, auth_level, researcher_tier)
            results.append(est)
        # Sort by max bounty descending
        results.sort(key=lambda r: r.get("max_bounty", 0), reverse=True)
        return results
