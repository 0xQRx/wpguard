"""
WordPress Theme API client.
"""

import sys
import time
from typing import Callable

import requests

from wpguard.config import WP_THEMES_API_BASE, MAX_PER_PAGE, DEFAULT_TIMEOUT, USER_AGENT
from wpguard.core.models import ThemeInfo


class WordPressThemeAPI:
    """Client for the WordPress Theme API."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def get_theme_info(self, slug: str) -> ThemeInfo | None:
        """
        Get information about a specific theme.

        Args:
            slug: Theme slug (e.g., "astra")

        Returns:
            ThemeInfo object or None if not found
        """
        params = {"action": "theme_information", "slug": slug}

        try:
            response = self.session.get(WP_THEMES_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if data and "slug" in data:
                # theme_information doesn't return active_installs,
                # so we do a query_themes lookup to get it
                installs = self._get_active_installs(slug)
                data["active_installs"] = installs
                return ThemeInfo.from_api_response(data)
        except requests.RequestException as e:
            print(f"[ERROR] Failed to get theme info for {slug}: {e}", file=sys.stderr)
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response for theme {slug}: {e}", file=sys.stderr)

        return None

    def _get_active_installs(self, slug: str) -> int:
        """Fetch active_installs for a theme via query_themes."""
        params = {
            "action": "query_themes",
            "request[search]": slug,
            "request[per_page]": 10,
            "request[fields][active_installs]": 1,
        }
        try:
            response = self.session.get(WP_THEMES_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            for theme in data.get("themes", []):
                if theme.get("slug") == slug:
                    return theme.get("active_installs", 0)
        except (requests.RequestException, ValueError, KeyError):
            pass
        return 0

    def query_themes(
        self,
        search: str | None = None,
        browse: str | None = None,
        page: int = 1,
        per_page: int = MAX_PER_PAGE,
    ) -> tuple[list[ThemeInfo], int]:
        """
        Query themes with optional search and pagination.

        Args:
            search: Search term
            browse: Browse category (popular, new, updated)
            page: Page number (1-indexed)
            per_page: Results per page (max 250)

        Returns:
            Tuple of (list of ThemeInfo, total pages)
        """
        params: dict[str, str | int] = {
            "action": "query_themes",
            "request[per_page]": min(per_page, MAX_PER_PAGE),
            "request[page]": page,
            "request[fields][active_installs]": 1,
            "request[fields][last_updated]": 1,
            "request[fields][rating]": 1,
            "request[fields][num_ratings]": 1,
            "request[fields][requires]": 1,
            "request[fields][requires_php]": 1,
            "request[fields][description]": 1,
        }

        if search:
            params["request[search]"] = search
        if browse:
            params["request[browse]"] = browse

        try:
            response = self.session.get(WP_THEMES_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            themes = [ThemeInfo.from_api_response(t) for t in data.get("themes", [])]
            total_pages = data.get("info", {}).get("pages", 1)

            return themes, total_pages
        except requests.RequestException as e:
            print(f"[ERROR] Failed to query themes: {e}", file=sys.stderr)
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response from API: {e}", file=sys.stderr)

        return [], 0

    def fetch_all_themes(
        self,
        search: str | None = None,
        min_installs: int = 0,
        max_installs: int | None = None,
        limit: int | None = None,
        browse: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
        rate_limit_delay: float = 0.5,
    ) -> list[ThemeInfo]:
        """
        Fetch all themes matching criteria with pagination.

        Args:
            search: Search term
            min_installs: Minimum active installations
            max_installs: Maximum active installations (None for unlimited)
            limit: Maximum number of themes to return (None for all)
            browse: Browse category (popular, new, updated)
            progress_callback: Callback for progress updates
            rate_limit_delay: Delay between API requests in seconds

        Returns:
            List of ThemeInfo objects matching criteria
        """
        all_themes: list[ThemeInfo] = []
        page = 1

        while True:
            if progress_callback:
                progress_callback(f"Fetching page {page}...")

            themes, total_pages = self.query_themes(
                search=search, browse=browse, page=page
            )

            if not themes:
                break

            for theme in themes:
                if theme.active_installs >= min_installs:
                    if max_installs is None or theme.active_installs <= max_installs:
                        all_themes.append(theme)

                        if limit and len(all_themes) >= limit:
                            return all_themes

            if page >= total_pages:
                break

            page += 1
            time.sleep(rate_limit_delay)

        return all_themes

    def get_theme_changelog(self, slug: str) -> str:
        """
        Get changelog HTML for a theme.

        Args:
            slug: Theme slug

        Returns:
            Changelog HTML string, or empty string if not available
        """
        params = {"action": "theme_information", "slug": slug}

        try:
            response = self.session.get(WP_THEMES_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("sections", {}).get("changelog", "")
        except (requests.RequestException, ValueError, KeyError):
            return ""
