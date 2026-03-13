"""
Wordfence Intelligence API client for CVE/vulnerability data (v3).

Downloads and caches the Wordfence vulnerability database for searching
known CVEs by plugin slug. Requires WORDFENCE_API_KEY env var.
"""

import json
import sys
import time
from pathlib import Path
from typing import Any

import requests

from wpguard.config import (
    DEFAULT_TIMEOUT,
    USER_AGENT,
    WORDFENCE_API_BASE,
    WORDFENCE_API_KEY,
)

# v3 production feed endpoint
WORDFENCE_VULNS_URL = f"{WORDFENCE_API_BASE}/vulnerabilities/production"

# Cache settings
DEFAULT_CACHE_PATH = Path("/tmp/wordfence_vulns.json")
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours


class WorkfenceVulnDB:
    """
    Client for Wordfence vulnerability database.

    Downloads the full vulnerability feed and provides search/filter methods
    for finding CVEs by plugin slug or keyword.
    """

    def __init__(
        self,
        cache_path: Path = DEFAULT_CACHE_PATH,
        timeout: int = DEFAULT_TIMEOUT,
        api_key: str | None = None,
    ):
        """
        Initialize the Wordfence vulnerability database client.

        Args:
            cache_path: Path to cache the downloaded JSON file
            timeout: Request timeout in seconds (increased for large download)
            api_key: Wordfence API key (falls back to WORDFENCE_API_KEY env var)
        """
        self.cache_path = cache_path
        self.timeout = max(timeout, 120)  # At least 2 minutes for large file
        self.api_key = api_key or WORDFENCE_API_KEY
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if self.api_key:
            self.session.headers.update(
                {"Authorization": f"Bearer {self.api_key}"}
            )
        self._data: dict[str, Any] | None = None

    def _is_cache_valid(self) -> bool:
        """Check if cached file exists and is fresh."""
        if not self.cache_path.exists():
            return False

        cache_age = time.time() - self.cache_path.stat().st_mtime
        return cache_age < CACHE_TTL_SECONDS

    def _load_cache(self) -> dict[str, Any] | None:
        """Load vulnerability data from cache file."""
        try:
            with open(self.cache_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARN] Failed to load cache: {e}", file=sys.stderr)
            return None

    def _save_cache(self, data: dict[str, Any]) -> bool:
        """Save vulnerability data to cache file."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w") as f:
                json.dump(data, f)
            return True
        except OSError as e:
            print(f"[WARN] Failed to save cache: {e}", file=sys.stderr)
            return False

    def download(self, force: bool = False) -> dict[str, Any]:
        """
        Download vulnerability database (uses cache if fresh).

        Args:
            force: Force re-download even if cache is fresh

        Returns:
            dict with status and statistics about the database
        """
        # Check API key — allow cache fallback if missing
        if not self.api_key:
            if self.cache_path.exists():
                self._data = self._load_cache()
                if self._data:
                    return {
                        "success": True,
                        "source": "cache",
                        "warning": "WORDFENCE_API_KEY not set — using stale cache. Set key to refresh.",
                        "cache_path": str(self.cache_path),
                        "total_vulnerabilities": len(self._data),
                    }
            return {
                "success": False,
                "error": (
                    "WORDFENCE_API_KEY environment variable is not set. "
                    "The Wordfence Intelligence v3 API requires authentication. "
                    "Get a free key: pip install wordfence && wordfence register"
                ),
            }

        # Check cache first
        if not force and self._is_cache_valid():
            self._data = self._load_cache()
            if self._data:
                return {
                    "success": True,
                    "source": "cache",
                    "cache_path": str(self.cache_path),
                    "total_vulnerabilities": len(self._data),
                }

        # Download fresh data from v3 API
        try:
            print("[INFO] Downloading Wordfence vulnerability database (v3 API)...", file=sys.stderr)
            response = self.session.get(
                WORDFENCE_VULNS_URL,
                timeout=self.timeout,
                stream=True,
            )
            response.raise_for_status()

            # The API returns a JSON object where keys are vulnerability IDs
            self._data = response.json()

            # Save to cache
            self._save_cache(self._data)

            return {
                "success": True,
                "source": "download",
                "cache_path": str(self.cache_path),
                "total_vulnerabilities": len(self._data),
            }

        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                return {
                    "success": False,
                    "error": (
                        "401 Unauthorized — WORDFENCE_API_KEY is invalid or expired. "
                        "Get a new key: pip install wordfence && wordfence register"
                    ),
                }
            return {"success": False, "error": str(e)}
        except requests.RequestException as e:
            print(f"[ERROR] Failed to download Wordfence DB: {e}", file=sys.stderr)
            return {"success": False, "error": str(e)}
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON from Wordfence API: {e}", file=sys.stderr)
            return {"success": False, "error": f"Invalid JSON response: {e}"}

    def _ensure_loaded(self) -> bool:
        """Ensure data is loaded (from cache or download)."""
        if self._data is not None:
            return True

        # Try loading from cache
        if self._is_cache_valid():
            self._data = self._load_cache()
            if self._data:
                return True

        # Download if not available
        result = self.download()
        return result.get("success", False)

    def get_vulns_for_slug(self, slug: str) -> list[dict[str, Any]]:
        """
        Get all vulnerabilities for a specific plugin slug.

        Args:
            slug: Plugin slug (e.g., 'contact-form-7')

        Returns:
            List of vulnerability records matching the slug
        """
        if not self._ensure_loaded():
            return []

        results = []
        slug_lower = slug.lower()

        for vuln_id, vuln in self._data.items():
            # Check software entries for matching slug
            software = vuln.get("software", [])
            for sw in software:
                if sw.get("type") == "plugin" and sw.get("slug", "").lower() == slug_lower:
                    results.append({
                        "id": vuln_id,
                        "title": vuln.get("title", ""),
                        "cve": vuln.get("cve"),
                        "cvss": vuln.get("cvss", {}),
                        "description": vuln.get("description", ""),
                        "references": vuln.get("references", []),
                        "published": vuln.get("published"),
                        "updated": vuln.get("updated"),
                        "affected_versions": sw.get("affected_versions", {}),
                        "patched_versions": sw.get("patched_versions", []),
                        "software": sw,
                    })
                    break

        return results

    def search_vulns(
        self,
        query: str | None = None,
        vuln_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search vulnerabilities by keyword or type.

        Args:
            query: Search term (searches title and description)
            vuln_type: Filter by vulnerability type (e.g., 'XSS', 'SQL Injection')
            limit: Maximum number of results to return

        Returns:
            List of matching vulnerability records
        """
        if not self._ensure_loaded():
            return []

        results = []
        query_lower = query.lower() if query else None
        type_lower = vuln_type.lower() if vuln_type else None

        for vuln_id, vuln in self._data.items():
            # Check if it's a WordPress plugin vulnerability
            software = vuln.get("software", [])
            is_plugin = any(sw.get("type") == "plugin" for sw in software)
            if not is_plugin:
                continue

            # Filter by query
            if query_lower:
                title = vuln.get("title", "").lower()
                description = vuln.get("description", "").lower()
                if query_lower not in title and query_lower not in description:
                    continue

            # Filter by vulnerability type (uses CWE name)
            cwe = vuln.get("cwe", {})
            cwe_name = cwe.get("name", "") if isinstance(cwe, dict) else ""
            if type_lower:
                if type_lower not in cwe_name.lower():
                    continue

            # Get plugin info
            plugin_sw = next((sw for sw in software if sw.get("type") == "plugin"), None)

            results.append({
                "id": vuln_id,
                "title": vuln.get("title", ""),
                "cve": vuln.get("cve"),
                "cvss": vuln.get("cvss", {}),
                "cwe": cwe,
                "published": vuln.get("published"),
                "plugin_slug": plugin_sw.get("slug") if plugin_sw else None,
                "plugin_name": plugin_sw.get("name") if plugin_sw else None,
            })

            if len(results) >= limit:
                break

        return results

    def get_vuln_by_id(self, vuln_id: str) -> dict[str, Any] | None:
        """
        Get detailed vulnerability info by Wordfence ID.

        Args:
            vuln_id: Wordfence vulnerability ID (UUID format)

        Returns:
            Full vulnerability record or None if not found
        """
        if not self._ensure_loaded():
            return None

        vuln = self._data.get(vuln_id)
        if vuln:
            return {
                "id": vuln_id,
                **vuln,
            }
        return None

    def get_vuln_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Get vulnerability info by CVE ID.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')

        Returns:
            Full vulnerability record or None if not found
        """
        if not self._ensure_loaded():
            return None

        cve_upper = cve_id.upper()
        for vuln_id, vuln in self._data.items():
            vuln_cve = vuln.get("cve")
            if vuln_cve and vuln_cve.upper() == cve_upper:
                return {
                    "id": vuln_id,
                    **vuln,
                }
        return None

    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about the vulnerability database.

        Returns:
            dict with database statistics
        """
        if not self._ensure_loaded():
            return {"error": "Database not loaded"}

        plugin_vulns = 0
        cwe_types: dict[str, int] = {}

        for vuln in self._data.values():
            software = vuln.get("software", [])
            if any(sw.get("type") == "plugin" for sw in software):
                plugin_vulns += 1
                cwe = vuln.get("cwe", {})
                if isinstance(cwe, dict) and cwe.get("name"):
                    cwe_name = cwe["name"]
                    cwe_types[cwe_name] = cwe_types.get(cwe_name, 0) + 1

        return {
            "total_vulnerabilities": len(self._data),
            "plugin_vulnerabilities": plugin_vulns,
            "cwe_types": dict(sorted(cwe_types.items(), key=lambda x: -x[1])[:20]),
            "cache_path": str(self.cache_path),
            "cache_valid": self._is_cache_valid(),
        }
