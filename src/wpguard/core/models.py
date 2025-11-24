"""
Data models for WordPress plugin information and change reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from wpguard.config import WP_PLUGINS_SVN


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
