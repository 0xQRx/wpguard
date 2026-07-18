"""
WordPress Core API client.
"""

import sys

import requests

from wpguard.config import (
    WP_CORE_STABLE_CHECK,
    WP_CORE_VERSION_CHECK,
    DEFAULT_TIMEOUT,
    USER_AGENT,
)
from wpguard.core.models import CoreVersionInfo


class WordPressCoreAPI:
    """Client for the WordPress Core version/stable-check APIs."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def list_versions(self) -> list[CoreVersionInfo]:
        """
        List all known WordPress core versions from the stable-check endpoint.

        The endpoint returns a mapping of version -> status, where status is one
        of "latest", "outdated", or "insecure" ("insecure" means a later
        security release exists).

        Returns:
            List of CoreVersionInfo, newest version first.
        """
        try:
            response = self.session.get(WP_CORE_STABLE_CHECK, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                versions = [
                    CoreVersionInfo.from_stable_check(version, status)
                    for version, status in data.items()
                ]
                versions.sort(key=lambda v: _version_key(v.version), reverse=True)
                return versions
        except requests.RequestException as e:
            print(f"[ERROR] Failed to list core versions: {e}", file=sys.stderr)
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response from stable-check API: {e}", file=sys.stderr)

        return []

    def get_latest(self) -> CoreVersionInfo | None:
        """
        Get the latest available core release from the version-check endpoint.

        Returns:
            CoreVersionInfo for the newest offered release or None.
        """
        offer = self._get_current_offer()
        if not offer:
            return None

        version = offer.get("current") or offer.get("version", "")
        if not version:
            return None

        info = CoreVersionInfo.from_stable_check(version, "latest")
        if offer.get("download"):
            info.download_link = offer["download"]
        return info

    def get_stable(self) -> CoreVersionInfo | None:
        """
        Get the current stable core release.

        The version-check `1.7/` endpoint's first offer is the recommended
        stable release, so this mirrors get_latest().

        Returns:
            CoreVersionInfo for the current stable release or None.
        """
        return self.get_latest()

    def _get_current_offer(self) -> dict | None:
        """Fetch offers[0] from the version-check endpoint."""
        try:
            response = self.session.get(WP_CORE_VERSION_CHECK, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            offers = data.get("offers", [])
            if offers:
                return offers[0]
        except requests.RequestException as e:
            print(f"[ERROR] Failed to get core version-check: {e}", file=sys.stderr)
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response from version-check API: {e}", file=sys.stderr)

        return None


def _version_key(version: str) -> tuple:
    """Return a sortable tuple for a dotted version string."""
    parts = []
    for chunk in version.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return tuple(parts)
