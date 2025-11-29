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
    STANDARD = "standard"


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
IN_SCOPE_AUTH_LEVELS = {
    AuthLevel.UNAUTHENTICATED,
    AuthLevel.SUBSCRIBER,
    AuthLevel.CUSTOMER,
}

# Minimum install requirements per tier
TIER_MIN_INSTALLS = {
    VulnerabilityTier.HIGH_THREAT: 25,
    VulnerabilityTier.COMMON_DANGEROUS: 500,
    VulnerabilityTier.STANDARD: 50000,
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

# Out of scope vulnerability types
OUT_OF_SCOPE_VULNS = {
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "eligible": self.eligible,
            "checks": self.checks,
            "messages": self.messages,
            "warnings": self.warnings,
            "tier": self.tier.value if self.tier else None,
            "estimated_severity": self.estimated_severity,
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

        # Check standard tier
        if vuln_type in STANDARD_VULNS:
            if active_installs >= TIER_MIN_INSTALLS[VulnerabilityTier.STANDARD]:
                return VulnerabilityTier.STANDARD

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
        if vuln_type in STANDARD_VULNS:
            return TIER_MIN_INSTALLS[VulnerabilityTier.STANDARD]

        return None
