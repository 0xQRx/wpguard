"""
Data models for WordPress plugin information and change reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from wpguard.config import WP_PLUGINS_SVN, WP_THEMES_SVN, WP_CORE_SVN


@dataclass
class ThemeInfo:
    """Represents WordPress theme information from the API."""

    slug: str
    name: str
    version: str
    active_installs: int
    last_updated: str
    download_link: str
    author: str = ""
    rating: float = 0.0
    num_ratings: int = 0
    requires: str = ""
    requires_php: str = ""
    screenshot_url: str = ""
    short_description: str = ""

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "ThemeInfo":
        """Create ThemeInfo from WordPress API response."""
        description = data.get("description", "") or ""
        # Strip HTML tags for short description
        import re
        clean = re.sub(r"<[^>]+>", "", description)
        return cls(
            slug=data.get("slug", ""),
            name=data.get("name", ""),
            version=data.get("version", ""),
            active_installs=data.get("active_installs", 0),
            last_updated=data.get("last_updated", "") or data.get("last_updated_time", ""),
            download_link=data.get("download_link", ""),
            author=data.get("author", ""),
            rating=data.get("rating", 0.0),
            num_ratings=data.get("num_ratings", 0),
            requires=data.get("requires", "") or "",
            requires_php=data.get("requires_php", "") or "",
            screenshot_url=data.get("screenshot_url", ""),
            short_description=clean[:200] if clean else "",
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "slug": self.slug,
            "name": self.name,
            "version": self.version,
            "active_installs": self.active_installs,
            "last_updated": self.last_updated,
            "download_link": self.download_link,
            "author": self.author,
            "rating": self.rating,
            "num_ratings": self.num_ratings,
            "requires": self.requires,
            "requires_php": self.requires_php,
            "screenshot_url": self.screenshot_url,
            "short_description": self.short_description,
        }

    @property
    def svn_url(self) -> str:
        """Get SVN repository URL for this theme."""
        return f"{WP_THEMES_SVN}{self.slug}/"

    @property
    def svn_trunk_url(self) -> str:
        """Get SVN trunk URL for this theme."""
        return f"{WP_THEMES_SVN}{self.slug}/"


@dataclass
class PluginInfo:
    """Represents WordPress plugin information from the API."""

    slug: str
    name: str
    version: str
    active_installs: int
    last_updated: str
    download_link: str
    author: str = ""
    rating: float = 0.0
    num_ratings: int = 0
    requires: str = ""
    tested: str = ""
    requires_php: str = ""
    short_description: str = ""

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "PluginInfo":
        """Create PluginInfo from WordPress API response."""
        description = data.get("short_description", "") or ""
        return cls(
            slug=data.get("slug", ""),
            name=data.get("name", ""),
            version=data.get("version", ""),
            active_installs=data.get("active_installs", 0),
            last_updated=data.get("last_updated", ""),
            download_link=data.get("download_link", ""),
            author=data.get("author", ""),
            rating=data.get("rating", 0.0),
            num_ratings=data.get("num_ratings", 0),
            requires=data.get("requires", "") or "",
            tested=data.get("tested", "") or "",
            requires_php=data.get("requires_php", "") or "",
            short_description=description[:200] if description else "",
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "slug": self.slug,
            "name": self.name,
            "version": self.version,
            "active_installs": self.active_installs,
            "last_updated": self.last_updated,
            "download_link": self.download_link,
            "author": self.author,
            "rating": self.rating,
            "num_ratings": self.num_ratings,
            "requires": self.requires,
            "tested": self.tested,
            "requires_php": self.requires_php,
            "short_description": self.short_description,
        }

    @property
    def svn_url(self) -> str:
        """Get SVN repository URL for this plugin."""
        return f"{WP_PLUGINS_SVN}{self.slug}/"

    @property
    def svn_trunk_url(self) -> str:
        """Get SVN trunk URL for this plugin."""
        return f"{WP_PLUGINS_SVN}{self.slug}/trunk/"


@dataclass
class CoreVersionInfo:
    """Represents a WordPress core release from the stable/version-check API."""

    version: str
    branch: str = ""
    release_date: str = ""
    is_security_release: bool = False
    status: str = ""  # latest, outdated, insecure
    download_link: str = ""

    @classmethod
    def from_stable_check(cls, version: str, status: str) -> "CoreVersionInfo":
        """
        Create CoreVersionInfo from a stable-check entry.

        The stable-check endpoint maps each version to a status string:
            "latest"   — current stable release
            "outdated" — superseded, but not a security concern
            "insecure" — a later security release exists (vulnerable)
        """
        branch = ".".join(version.split(".")[:2])
        from wpguard.config import WP_CORE_DOWNLOAD
        return cls(
            version=version,
            branch=branch,
            release_date="",
            is_security_release=(status == "insecure"),
            status=status or "",
            download_link=WP_CORE_DOWNLOAD.format(version=version),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "branch": self.branch,
            "release_date": self.release_date,
            "is_security_release": self.is_security_release,
            "status": self.status,
            "download_link": self.download_link,
        }

    @property
    def svn_tag_url(self) -> str:
        """Get SVN tag URL for this core version."""
        return f"{WP_CORE_SVN}tags/{self.version}/"


@dataclass
class ChangeReport:
    """Represents changes detected in a plugin update."""

    plugin_slug: str
    plugin_name: str
    old_version: str
    new_version: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    changed_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    removed_files: list[str] = field(default_factory=list)
    download_link: str = ""
    svn_url: str = ""

    def __post_init__(self):
        """Set SVN URL if not provided."""
        if not self.svn_url:
            self.svn_url = f"{WP_PLUGINS_SVN}{self.plugin_slug}/trunk/"

    @property
    def total_changes(self) -> int:
        """Total number of file changes."""
        return len(self.changed_files) + len(self.added_files) + len(self.removed_files)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return self.total_changes > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "plugin_slug": self.plugin_slug,
            "plugin_name": self.plugin_name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "timestamp": self.timestamp,
            "changed_files": self.changed_files,
            "added_files": self.added_files,
            "removed_files": self.removed_files,
            "download_link": self.download_link,
            "svn_url": self.svn_url,
        }

    def format_console_report(self) -> str:
        """Format the report for console output."""
        lines = [
            "",
            "=" * 70,
            f"PLUGIN UPDATE: {self.plugin_name} ({self.plugin_slug})",
            f"Version: {self.old_version} -> {self.new_version}",
            "=" * 70,
        ]

        if self.changed_files:
            lines.append(f"\n[Modified Files] ({len(self.changed_files)})")
            for f in self.changed_files[:20]:
                lines.append(f"   * {f}")
            if len(self.changed_files) > 20:
                lines.append(f"   ... and {len(self.changed_files) - 20} more")

        if self.added_files:
            lines.append(f"\n[Added Files] ({len(self.added_files)})")
            for f in self.added_files[:20]:
                lines.append(f"   + {f}")
            if len(self.added_files) > 20:
                lines.append(f"   ... and {len(self.added_files) - 20} more")

        if self.removed_files:
            lines.append(f"\n[Removed Files] ({len(self.removed_files)})")
            for f in self.removed_files[:20]:
                lines.append(f"   - {f}")
            if len(self.removed_files) > 20:
                lines.append(f"   ... and {len(self.removed_files) - 20} more")

        lines.extend(
            [
                "\n[Download Commands]",
                f'   wget "{self.download_link}"',
                f"   svn checkout {self.svn_url}",
                "=" * 70,
                "",
            ]
        )

        return "\n".join(lines)


@dataclass
class Finding:
    """Represents a security vulnerability finding."""

    id: str
    plugin_slug: str
    plugin_version: str
    active_installs: int
    vuln_type: str
    title: str
    description: str
    auth_level: str
    cvss_score: float
    cvss_vector: str
    affected_file: str
    affected_function: str = ""
    affected_line: int = 0
    poc_path: str = ""
    status: str = "draft"  # draft, validated, submitted, rejected, duplicate
    tier: str = ""  # high_threat, common_dangerous, standard
    # Which bounty program / target class this finding belongs to.
    # "plugin" (default, back-compat) => Wordfence; "core" => HackerOne WordPress
    # program. "theme" is also Wordfence. Absent in older JSON => defaults to
    # "plugin" on load.
    target_type: str = "plugin"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    validation_notes: str = ""
    submission_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "plugin_slug": self.plugin_slug,
            "plugin_version": self.plugin_version,
            "active_installs": self.active_installs,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "description": self.description,
            "auth_level": self.auth_level,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "affected_file": self.affected_file,
            "affected_function": self.affected_function,
            "affected_line": self.affected_line,
            "poc_path": self.poc_path,
            "status": self.status,
            "tier": self.tier,
            "target_type": self.target_type,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "validation_notes": self.validation_notes,
            "submission_id": self.submission_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create Finding from dictionary."""
        return cls(
            id=data["id"],
            plugin_slug=data["plugin_slug"],
            plugin_version=data["plugin_version"],
            active_installs=data.get("active_installs", 0),
            vuln_type=data["vuln_type"],
            title=data["title"],
            description=data.get("description", ""),
            auth_level=data["auth_level"],
            cvss_score=data["cvss_score"],
            cvss_vector=data.get("cvss_vector", ""),
            affected_file=data["affected_file"],
            affected_function=data.get("affected_function", ""),
            affected_line=data.get("affected_line", 0),
            poc_path=data.get("poc_path", ""),
            status=data.get("status", "draft"),
            tier=data.get("tier", ""),
            target_type=data.get("target_type", "plugin"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            validation_notes=data.get("validation_notes", ""),
            submission_id=data.get("submission_id", ""),
        )

    @property
    def severity(self) -> str:
        """Get severity based on CVSS score."""
        if self.cvss_score >= 9.0:
            return "Critical"
        elif self.cvss_score >= 7.0:
            return "High"
        elif self.cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"

    @property
    def is_eligible(self) -> bool:
        """Check if finding meets basic eligibility criteria."""
        return (
            self.cvss_score >= 4.0
            and self.auth_level in ("unauthenticated", "subscriber", "customer")
            and self.status not in ("rejected", "duplicate")
        )
