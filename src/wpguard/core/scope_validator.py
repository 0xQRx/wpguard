"""
Wordfence Bug Bounty Scope Validator.

Validates plugins and vulnerabilities against Wordfence bounty program rules.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnerabilityTier(Enum):
    """Wordfence vulnerability tier classification."""

    HIGH_THREAT = "high_threat"
    COMMON_DANGEROUS = "common_dangerous"
    STANDARD = "standard"  # >= 50,000 installs
    RESOURCEFUL = "resourceful"  # >= 10,000 installs
    ELITE_1337 = "elite_1337"  # >= 500 installs


class AuthLevel(Enum):
    """WordPress authentication levels."""

    UNAUTHENTICATED = "unauthenticated"
    SUBSCRIBER = "subscriber"
    CUSTOMER = "customer"
    CONTRIBUTOR = "contributor"
    AUTHOR = "author"
    EDITOR = "editor"
    SHOP_MANAGER = "shop_manager"
    ADMINISTRATOR = "administrator"


# In-scope authentication levels for bounty eligibility
# All levels up to and including Author are in scope for Wordfence
IN_SCOPE_AUTH_LEVELS = {
    AuthLevel.UNAUTHENTICATED,
    AuthLevel.SUBSCRIBER,
    AuthLevel.CUSTOMER,
    AuthLevel.CONTRIBUTOR,
    AuthLevel.AUTHOR,
}

# Minimum install requirements per tier
TIER_MIN_INSTALLS = {
    VulnerabilityTier.HIGH_THREAT: 25,
    VulnerabilityTier.COMMON_DANGEROUS: 500,
    VulnerabilityTier.STANDARD: 50000,  # Standard Researchers
    VulnerabilityTier.RESOURCEFUL: 10000,  # Resourceful Researchers
    VulnerabilityTier.ELITE_1337: 500,  # 1337 Researchers
}

# Vulnerability types per tier
HIGH_THREAT_VULNS = {
    "arbitrary_php_file_upload",
    "arbitrary_php_file_read",
    "arbitrary_php_file_deletion",
    "arbitrary_options_update",
    "remote_code_execution",
    "authentication_bypass_admin",
    "privilege_escalation_admin",
}

COMMON_DANGEROUS_VULNS = {
    "sql_injection",
    "stored_xss",
}

# Standard tier vulns (also apply to Resourceful and 1337 tiers)
STANDARD_VULNS = {
    "reflected_xss",
    "csrf",
    "missing_authorization",
    "arbitrary_content_deletion",
    "idor",
    "arbitrary_file_download",
    "lfi_rfi",
    "directory_traversal",
    "privilege_escalation_non_admin",
    "authentication_bypass_non_admin",
    "information_disclosure",
    "ssrf",
    "php_object_injection",
    "intentional_backdoor",
}

# Resourceful and 1337 tiers use the same vuln types as Standard
RESOURCEFUL_VULNS = STANDARD_VULNS
ELITE_1337_VULNS = STANDARD_VULNS

# Out of scope vulnerability types
OUT_OF_SCOPE_VULNS = {
    # Core OOS types
    "csv_injection",
    "ip_spoofing",
    "waf_bypass",
    "css_injection",
    "html_injection",
    "dos",
    "captcha_bypass",
    "cors",
    "open_redirect",
    "tabnabbing",
    "self_xss",
    "username_enumeration",
    "missing_headers",
    "clickjacking",
    "ssrf_dns_rebinding",
    "full_path_disclosure",
    "csrf_no_impact",
    # Extended OOS — from full Wordfence program rules
    "plaintext_secrets_db_only",     # 2FA secrets in DB without exploitable vuln
    "vulnerable_dependency",         # Unverifiably exploitable dependency
    "cache_poisoning",               # Unless considerable impact
    "toctou_not_replicable",         # Race condition not easily replicable
    "api_key_overwrite",             # API key updates/overwrites/reads
    "theoretical_vulnerability",     # No demonstrable exploit path
    "file_upload_client_scripts",    # PDF/file with embedded XSS
    "double_extension_upload",       # .php.png attacks
    "uploaded_file_no_compromise",   # Public uploads not leading to full compromise
    "private_post_access",           # Private/hidden/draft/password protected posts
    "eol_software_only",             # Only exploitable on EOL PHP/MySQL/etc
    "disabled_magic_quotes_sqli",    # SQLi requiring wp_magic_quotes disabled
    "local_access_required",         # Requires local server access
    "admin_granted_access",          # Admin explicitly granting access to lower user
    "excessive_brute_force",         # Requires excessive brute force
}

# Excluded vendors/products
EXCLUDED_VENDORS = {
    "wordpress",
    "automattic",
    "jetpack",
    "woocommerce",
    "akismet",
    "facebook",
    "google",
    "site-kit-by-google",
    "siteground",
    "yoast",
    "wordpress-seo",
}


@dataclass
class ValidationResult:
    """Result of bounty eligibility validation."""

    eligible: bool
    checks: dict[str, bool] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tier: VulnerabilityTier | None = None
    estimated_severity: str | None = None
    # Which bounty program this result applies to. Defaults to "plugin" for
    # back-compat with the Wordfence plugin/theme validator; the core validator
    # sets this to "core".
    program: str = "plugin"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "eligible": self.eligible,
            "checks": self.checks,
            "messages": self.messages,
            "warnings": self.warnings,
            "tier": self.tier.value if self.tier else None,
            "estimated_severity": self.estimated_severity,
            "program": self.program,
        }


class WorkfenceScopeValidator:
    """Validates plugins and vulnerabilities against Wordfence bounty scope."""

    def __init__(self):
        """Initialize the scope validator."""
        pass

    def get_applicable_tier(
        self, vuln_type: str, active_installs: int
    ) -> VulnerabilityTier | None:
        """
        Determine which tier a vulnerability falls into based on type and installs.

        Args:
            vuln_type: Vulnerability type identifier
            active_installs: Number of active installations

        Returns:
            VulnerabilityTier if eligible, None if out of scope
        """
        # Normalize vuln type
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

        # Check high threat first (lowest install requirement)
        if vuln_type in HIGH_THREAT_VULNS:
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.HIGH_THREAT]:
                return VulnerabilityTier.HIGH_THREAT

        # Check common/dangerous
        if vuln_type in COMMON_DANGEROUS_VULNS:
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.COMMON_DANGEROUS]:
                return VulnerabilityTier.COMMON_DANGEROUS

        # Check standard tier vulns - assign to best applicable tier based on installs
        if vuln_type in STANDARD_VULNS:
            # Standard Researchers: >= 50,000
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.STANDARD]:
                return VulnerabilityTier.STANDARD
            # Resourceful Researchers: >= 10,000
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.RESOURCEFUL]:
                return VulnerabilityTier.RESOURCEFUL
            # 1337 Researchers: >= 500
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.ELITE_1337]:
                return VulnerabilityTier.ELITE_1337

        return None

    def check_vendor_exclusion(self, plugin_slug: str, author: str | None = None) -> bool:
        """
        Check if a plugin is from an excluded vendor.

        Args:
            plugin_slug: Plugin slug
            author: Plugin author name

        Returns:
            True if excluded (NOT eligible), False if allowed
        """
        slug_lower = plugin_slug.lower()
        author_lower = (author or "").lower()

        # Check slug against excluded products
        if slug_lower in EXCLUDED_VENDORS:
            return True

        # Check if slug starts with excluded vendor
        for vendor in EXCLUDED_VENDORS:
            if slug_lower.startswith(f"{vendor}-") or slug_lower.startswith(f"{vendor}_"):
                return True

        # Check author
        for vendor in EXCLUDED_VENDORS:
            if vendor in author_lower:
                return True

        return False

    def check_auth_level(self, auth_level: str | AuthLevel) -> bool:
        """
        Check if authentication level is in scope.

        Args:
            auth_level: Authentication level required for vulnerability

        Returns:
            True if in scope, False if out of scope (PR:H)
        """
        if isinstance(auth_level, str):
            try:
                auth_level = AuthLevel(auth_level.lower())
            except ValueError:
                return False

        return auth_level in IN_SCOPE_AUTH_LEVELS

    def check_vuln_type_in_scope(self, vuln_type: str) -> bool:
        """
        Check if vulnerability type is in scope.

        Args:
            vuln_type: Vulnerability type identifier

        Returns:
            True if in scope, False if out of scope
        """
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

        # Check if explicitly out of scope
        if vuln_type in OUT_OF_SCOPE_VULNS:
            return False

        # Check if in any tier
        all_in_scope = HIGH_THREAT_VULNS | COMMON_DANGEROUS_VULNS | STANDARD_VULNS
        return vuln_type in all_in_scope

    def validate_plugin_eligibility(
        self,
        plugin_slug: str,
        active_installs: int,
        author: str | None = None,
        is_available: bool = True,
    ) -> ValidationResult:
        """
        Validate if a plugin is eligible for bounty research.

        Args:
            plugin_slug: Plugin slug
            active_installs: Number of active installations
            author: Plugin author name
            is_available: Whether plugin is available for download

        Returns:
            ValidationResult with eligibility status
        """
        result = ValidationResult(eligible=True)

        # Check 1: Vendor exclusion
        is_excluded = self.check_vendor_exclusion(plugin_slug, author)
        result.checks["vendor_not_excluded"] = not is_excluded
        if is_excluded:
            result.eligible = False
            result.messages.append(f"Plugin '{plugin_slug}' is from an excluded vendor")

        # Check 2: Availability
        result.checks["plugin_available"] = is_available
        if not is_available:
            result.eligible = False
            result.messages.append("Plugin is not available for download")

        # Check 3: Minimum installs for any tier
        meets_min = active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.HIGH_THREAT]
        result.checks["meets_minimum_installs"] = meets_min
        if not meets_min:
            result.eligible = False
            result.messages.append(
                f"Active installs ({active_installs}) below minimum threshold (25)"
            )

        # Determine applicable tiers based on installs
        applicable_tiers = []
        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.HIGH_THREAT]:
            applicable_tiers.append(VulnerabilityTier.HIGH_THREAT)
        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.COMMON_DANGEROUS]:
            applicable_tiers.append(VulnerabilityTier.COMMON_DANGEROUS)
        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.STANDARD]:
            applicable_tiers.append(VulnerabilityTier.STANDARD)
        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.RESOURCEFUL]:
            applicable_tiers.append(VulnerabilityTier.RESOURCEFUL)
        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.ELITE_1337]:
            applicable_tiers.append(VulnerabilityTier.ELITE_1337)

        if applicable_tiers:
            result.tier = applicable_tiers[0]  # Best tier
            result.messages.append(
                f"Eligible tiers: {[t.value for t in applicable_tiers]}"
            )

        # Check 4: WP.org listing requirement for low install counts
        if 25 <= active_installs < 1000:
            result.warnings.append(
                "Plugins with 25-999 installs MUST be listed on WordPress.org"
            )

        return result

    def validate_finding_eligibility(
        self,
        plugin_slug: str,
        active_installs: int,
        vuln_type: str,
        auth_level: str,
        cvss_score: float,
        author: str | None = None,
        is_available: bool = True,
    ) -> ValidationResult:
        """
        Validate if a vulnerability finding is eligible for bounty submission.

        Args:
            plugin_slug: Plugin slug
            active_installs: Number of active installations
            vuln_type: Vulnerability type identifier
            auth_level: Required authentication level
            cvss_score: CVSS 3.1 score
            author: Plugin author
            is_available: Whether plugin is available

        Returns:
            ValidationResult with full eligibility status
        """
        # Start with plugin eligibility
        result = self.validate_plugin_eligibility(
            plugin_slug, active_installs, author, is_available
        )

        # Check 5: Authentication level
        auth_in_scope = self.check_auth_level(auth_level)
        result.checks["auth_level_in_scope"] = auth_in_scope
        if not auth_in_scope:
            result.eligible = False
            result.messages.append(
                f"Authentication level '{auth_level}' is out of scope (requires Editor+ / PR:H)"
            )

        # Check 6: Vulnerability type in scope
        vuln_in_scope = self.check_vuln_type_in_scope(vuln_type)
        result.checks["vuln_type_in_scope"] = vuln_in_scope
        if not vuln_in_scope:
            result.eligible = False
            result.messages.append(f"Vulnerability type '{vuln_type}' is out of scope")

        # Check 7: CVSS score meets minimum
        cvss_ok = cvss_score >= 4.0
        result.checks["cvss_minimum_met"] = cvss_ok
        if not cvss_ok:
            result.eligible = False
            result.messages.append(
                f"CVSS score ({cvss_score}) below minimum threshold (4.0)"
            )

        # Check 8: Tier eligibility for this vuln type
        tier = self.get_applicable_tier(vuln_type, active_installs)
        result.checks["tier_eligible"] = tier is not None
        if tier:
            result.tier = tier
            result.messages.append(f"Vulnerability qualifies for {tier.value} tier")
        elif vuln_in_scope:
            result.eligible = False
            result.messages.append(
                f"Install count ({active_installs}) insufficient for {vuln_type}"
            )

        # Estimate severity
        if cvss_score >= 9.0:
            result.estimated_severity = "Critical"
        elif cvss_score >= 7.0:
            result.estimated_severity = "High"
        elif cvss_score >= 4.0:
            result.estimated_severity = "Medium"
        else:
            result.estimated_severity = "Low"

        return result

    def get_in_scope_vulns_for_installs(
        self, active_installs: int
    ) -> dict[str, list[str]]:
        """
        Get all in-scope vulnerability types for a given install count.

        Args:
            active_installs: Number of active installations

        Returns:
            Dict mapping tier to list of vulnerability types
        """
        result: dict[str, list[str]] = {}

        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.HIGH_THREAT]:
            result["high_threat"] = sorted(HIGH_THREAT_VULNS)

        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.COMMON_DANGEROUS]:
            result["common_dangerous"] = sorted(COMMON_DANGEROUS_VULNS)

        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.STANDARD]:
            result["standard"] = sorted(STANDARD_VULNS)

        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.RESOURCEFUL]:
            result["resourceful"] = sorted(RESOURCEFUL_VULNS)

        if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.ELITE_1337]:
            result["elite_1337"] = sorted(ELITE_1337_VULNS)

        return result

    def get_minimum_installs_for_vuln(self, vuln_type: str) -> int | None:
        """
        Get minimum install count required for a vulnerability type.

        Args:
            vuln_type: Vulnerability type identifier

        Returns:
            Minimum installs required, or None if out of scope
        """
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

        if vuln_type in HIGH_THREAT_VULNS:
            return TIER_MIN_INSTALLS[VulnerabilityTier.HIGH_THREAT]
        if vuln_type in COMMON_DANGEROUS_VULNS:
            return TIER_MIN_INSTALLS[VulnerabilityTier.COMMON_DANGEROUS]
        # Standard vulns now eligible at 1337/Resourceful tier (500 installs minimum)
        if vuln_type in STANDARD_VULNS:
            return TIER_MIN_INSTALLS[VulnerabilityTier.ELITE_1337]

        return None


# ---------------------------------------------------------------------------
# WordPress Core bounty program
# ---------------------------------------------------------------------------
#
# WordPress *core* is a separate bounty program from Wordfence (which covers
# plugins/themes). Core findings are submitted to the HackerOne "WordPress"
# program, NOT to Wordfence. The rules below are the parts we can encode with
# confidence; anything program-specific that we are NOT certain of (exact payout
# tables, precise policy clauses) is deliberately left out and flagged for the
# researcher to verify against the current program policy.

# Submission destination for core findings.
# NOTE: verify current policy — program URL/scope may change.
CORE_SUBMISSION_TARGET = (
    "HackerOne WordPress program (https://hackerone.com/wordpress) — NOT Wordfence. "
    "Verify current program policy before submitting."
)

# Attacker auth levels that are IN scope for core.
# Same low-privilege attacker model as plugins: unauth -> subscriber ->
# contributor -> author. Admin and multisite network/super-admin are privileged
# by design and therefore OUT OF SCOPE.
CORE_IN_SCOPE_AUTH_LEVELS = {
    AuthLevel.UNAUTHENTICATED,
    AuthLevel.SUBSCRIBER,
    AuthLevel.CUSTOMER,
    AuthLevel.CONTRIBUTOR,
    AuthLevel.AUTHOR,
}

# Auth levels that are explicitly OUT OF SCOPE for core (privileged by design).
CORE_OUT_OF_SCOPE_AUTH_LEVELS = {
    AuthLevel.EDITOR,
    AuthLevel.SHOP_MANAGER,
    AuthLevel.ADMINISTRATOR,
}

# Vulnerability types that are IN scope for core. Core has no install tiers, so
# any real memory-safety / logic / injection / authz class qualifies regardless
# of "installs". This reuses the same vuln-type vocabulary as the plugin program
# (minus the tier gating).
CORE_IN_SCOPE_VULNS = (
    HIGH_THREAT_VULNS | COMMON_DANGEROUS_VULNS | STANDARD_VULNS
)


class CoreScopeValidator:
    """
    Validates WordPress **core** vulnerabilities against the core bounty program.

    Key differences from :class:`WorkfenceScopeValidator`:

    * **No install tiers.** Core affects effectively the entire WordPress
      population, so any in-scope vuln type qualifies regardless of installs.
    * **Vendor exclusion is bypassed.** ``wordpress``/``automattic`` are excluded
      for the *plugin* program but ARE the target here.
    * **Multisite super-admin / network-admin is OOS** (privileged by design),
      as is single-site admin.
    * **Different submission target** — the HackerOne WordPress program, not
      Wordfence (see :data:`CORE_SUBMISSION_TARGET`).
    """

    submission_target: str = CORE_SUBMISSION_TARGET

    def __init__(self):
        """Initialize the core scope validator."""
        pass

    def check_auth_level(self, auth_level: str | AuthLevel) -> bool:
        """
        Check if an attacker auth level is in scope for core.

        Args:
            auth_level: Authentication level required for the vulnerability.

        Returns:
            True if in scope (unauth..author), False otherwise (editor/admin/
            super-admin are privileged by design => OOS).
        """
        if isinstance(auth_level, str):
            try:
                auth_level = AuthLevel(auth_level.lower())
            except ValueError:
                return False

        return auth_level in CORE_IN_SCOPE_AUTH_LEVELS

    def check_vuln_type_in_scope(self, vuln_type: str) -> bool:
        """
        Check if a vulnerability type is in scope for core.

        Args:
            vuln_type: Vulnerability type identifier.

        Returns:
            True if in scope, False if on the shared out-of-scope list or not a
            recognized in-scope class.
        """
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

        # Shared obviously-OOS list (self-XSS, open redirect, username
        # enumeration, missing headers, clickjacking, DoS-without-impact, ...).
        if vuln_type in OUT_OF_SCOPE_VULNS:
            return False

        return vuln_type in CORE_IN_SCOPE_VULNS

    def validate_core_finding(
        self,
        vuln_type: str,
        auth_level: str,
        *,
        is_multisite_only: bool = False,
        cvss_score: float | None = None,
    ) -> ValidationResult:
        """
        Validate whether a core vulnerability finding is eligible for the
        WordPress core (HackerOne) bounty program.

        Unlike the plugin validator, there is no install count / tier gating —
        core affects the whole population, so eligibility hinges on the vuln type
        and the attacker auth level only.

        Args:
            vuln_type: Vulnerability type identifier.
            auth_level: Required attacker authentication level.
            is_multisite_only: True if the issue is only reachable in a multisite
                network context. Multisite network/super-admin privilege is OOS;
                a network-admin-only issue is therefore not eligible.
            cvss_score: Optional CVSS 3.1 score. If provided, the 4.0 minimum is
                enforced and an estimated severity is attached.

        Returns:
            ValidationResult with eligibility status. ``program`` is "core" and a
            message records the HackerOne submission target.
        """
        result = ValidationResult(eligible=True, program="core")

        # Record submission target so downstream tooling / agents route correctly.
        result.messages.append(f"Submission target: {CORE_SUBMISSION_TARGET}")

        # Check 1: no install tiers — always satisfied for core.
        result.checks["no_install_tier_gating"] = True

        # Check 2: vendor exclusion is intentionally bypassed for core.
        result.checks["vendor_exclusion_bypassed"] = True

        # Check 3: attacker auth level in scope (admin / super-admin OOS).
        auth_in_scope = self.check_auth_level(auth_level)
        result.checks["auth_level_in_scope"] = auth_in_scope
        if not auth_in_scope:
            result.eligible = False
            result.messages.append(
                f"Authentication level '{auth_level}' is out of scope for core "
                "(admin / multisite super-admin are privileged by design)"
            )

        # Check 4: multisite-only network-admin issues are OOS.
        if is_multisite_only:
            # Multisite-only issues that require the network/super-admin context
            # are privileged by design. Flag as a warning; combined with an
            # elevated auth level this is a hard reject above.
            result.warnings.append(
                "Issue reported as multisite-only — confirm it is NOT a "
                "network/super-admin-only capability (super-admin is OOS)"
            )
            result.checks["multisite_only"] = True

        # Check 5: vulnerability type in scope.
        vuln_in_scope = self.check_vuln_type_in_scope(vuln_type)
        result.checks["vuln_type_in_scope"] = vuln_in_scope
        if not vuln_in_scope:
            result.eligible = False
            result.messages.append(
                f"Vulnerability type '{vuln_type}' is out of scope for core"
            )

        # Check 6: optional CVSS minimum (only enforced when supplied).
        if cvss_score is not None:
            cvss_ok = cvss_score >= 4.0
            result.checks["cvss_minimum_met"] = cvss_ok
            if not cvss_ok:
                result.eligible = False
                result.messages.append(
                    f"CVSS score ({cvss_score}) below minimum threshold (4.0)"
                )
            if cvss_score >= 9.0:
                result.estimated_severity = "Critical"
            elif cvss_score >= 7.0:
                result.estimated_severity = "High"
            elif cvss_score >= 4.0:
                result.estimated_severity = "Medium"
            else:
                result.estimated_severity = "Low"

        if result.eligible:
            result.messages.append(
                "Eligible for the WordPress core program — no install-tier gating."
            )

        return result

    def get_in_scope_vulns(self) -> list[str]:
        """
        Get all in-scope vulnerability types for core (no tier gating).

        Returns:
            Sorted list of in-scope vulnerability type identifiers.
        """
        return sorted(CORE_IN_SCOPE_VULNS)
