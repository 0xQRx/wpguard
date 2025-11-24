"""
WordPress Plugin API client.
"""

import time
from typing import Callable

import requests

from wpguard.config import WP_API_BASE, MAX_PER_PAGE, DEFAULT_TIMEOUT, USER_AGENT
from wpguard.core.models import PluginInfo


class WordPressPluginAPI:
    """Client for the WordPress Plugin API."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize the API client.

        Args:
            timeout: Request timeout in seconds
        """
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.timeout = timeout

    def get_plugin_info(self, slug: str) -> PluginInfo | None:
        """
        Get information about a specific plugin.

        Args:
            slug: Plugin slug (e.g., "akismet")

        Returns:
            PluginInfo object or None if not found
        """
        params = {"action": "plugin_information", "slug": slug}

        try:
            response = self.session.get(WP_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if data and "slug" in data:
                return PluginInfo.from_api_response(data)
        except requests.RequestException as e:
            print(f"[ERROR] Failed to get plugin info for {slug}: {e}")
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response for plugin {slug}: {e}")

        return None

    def query_plugins(
        self,
        search: str | None = None,
        browse: str | None = None,
        page: int = 1,
        per_page: int = MAX_PER_PAGE,
    ) -> tuple[list[PluginInfo], int]:
        """
        Query plugins with optional search and pagination.

        Args:
            search: Search term
            browse: Browse category (popular, new, updated)
            page: Page number (1-indexed)
            per_page: Results per page (max 250)

        Returns:
            Tuple of (list of PluginInfo, total pages)
        """
        params: dict[str, str | int] = {
            "action": "query_plugins",
            "request[per_page]": min(per_page, MAX_PER_PAGE),
            "request[page]": page,
            "request[fields][active_installs]": 1,
            "request[fields][last_updated]": 1,
            "request[fields][rating]": 1,
            "request[fields][num_ratings]": 1,
            "request[fields][requires]": 1,
            "request[fields][tested]": 1,
            "request[fields][requires_php]": 1,
            "request[fields][short_description]": 1,
        }

        if search:
            params["request[search]"] = search
        if browse:
            params["request[browse]"] = browse

        try:
            response = self.session.get(WP_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            plugins = [PluginInfo.from_api_response(p) for p in data.get("plugins", [])]
            total_pages = data.get("info", {}).get("pages", 1)

            return plugins, total_pages
        except requests.RequestException as e:
            print(f"[ERROR] Failed to query plugins: {e}")
        except (ValueError, KeyError) as e:
            print(f"[ERROR] Invalid response from API: {e}")

        return [], 0

    def fetch_all_plugins(
        self,
        search: str | None = None,
        min_installs: int = 0,
        max_installs: int | None = None,
        limit: int | None = None,
        browse: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
        rate_limit_delay: float = 0.5,
    ) -> list[PluginInfo]:
        """
        Fetch all plugins matching criteria with pagination.

        Args:
            search: Search term
            min_installs: Minimum active installations
            max_installs: Maximum active installations (None for unlimited)
            limit: Maximum number of plugins to return (None for all)
            browse: Browse category (popular, new, updated)
            progress_callback: Callback for progress updates
            rate_limit_delay: Delay between API requests in seconds

        Returns:
            List of PluginInfo objects matching criteria
        """
        all_plugins: list[PluginInfo] = []
        page = 1

        while True:
            if progress_callback:
                progress_callback(f"Fetching page {page}...")

            plugins, total_pages = self.query_plugins(
                search=search, browse=browse, page=page
            )

            if not plugins:
                break

            # Filter by install count
            for plugin in plugins:
                if plugin.active_installs >= min_installs:
                    if max_installs is None or plugin.active_installs <= max_installs:
                        all_plugins.append(plugin)

                        if limit and len(all_plugins) >= limit:
                            return all_plugins

            if page >= total_pages:
                break

            page += 1
            time.sleep(rate_limit_delay)

        return all_plugins

    def get_plugin_versions(self, slug: str) -> list[str]:
        """
        Get available versions for a plugin.

        Args:
            slug: Plugin slug

        Returns:
            List of version strings
        """
        params = {
            "action": "plugin_information",
            "slug": slug,
            "request[fields][versions]": 1,
        }

        try:
            response = self.session.get(WP_API_BASE, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            versions = data.get("versions", {})
            if isinstance(versions, dict):
                return list(versions.keys())
        except (requests.RequestException, ValueError, KeyError):
            pass

        return []
