"""
Plugin downloading functionality for ZIP and SVN sources.
"""

import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import requests

from wpguard.config import DEFAULT_OUTPUT_DIR, PLUGINS_SUBDIR, WP_PLUGINS_SVN, USER_AGENT
from wpguard.core.models import PluginInfo


@dataclass
class SVNChangeInfo:
    """Information about changes between SVN revisions."""

    slug: str
    old_revision: str
    new_revision: str
    changed_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    removed_files: list[str] = field(default_factory=list)
    diff_output: str = ""
    log_entries: list[dict] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.changed_files) + len(self.added_files) + len(self.removed_files)


class SVNClient:
    """SVN operations for WordPress plugin/theme repository."""

    def __init__(self, svn_base: str = WP_PLUGINS_SVN):
        self.svn_base = svn_base
        self._check_svn_installed()

    def _check_svn_installed(self) -> bool:
        """Check if SVN is installed."""
        try:
            subprocess.run(
                ["svn", "--version"], capture_output=True, check=True, timeout=10
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def get_latest_revision(self, slug: str) -> str | None:
        """Get the latest SVN revision for a slug."""
        svn_url = f"{self.svn_base}{slug}/"
        try:
            result = subprocess.run(
                ["svn", "info", "--show-item", "revision", svn_url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        return None

    def get_log(
        self, slug: str, limit: int = 10, start_rev: str | None = None
    ) -> list[dict]:
        """
        Get SVN log entries for a plugin.

        Args:
            slug: Plugin slug
            limit: Maximum number of entries
            start_rev: Starting revision (optional)

        Returns:
            List of log entry dictionaries
        """
        svn_url = f"{self.svn_base}{slug}/"
        cmd = ["svn", "log", "-l", str(limit), "--xml"]
        if start_rev:
            cmd.extend(["-r", f"{start_rev}:HEAD"])
        cmd.append(svn_url)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return self._parse_svn_log_xml(result.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        return []

    def _parse_svn_log_xml(self, xml_output: str) -> list[dict]:
        """Parse SVN log XML output."""
        import xml.etree.ElementTree as ET

        entries = []
        try:
            root = ET.fromstring(xml_output)
            for logentry in root.findall("logentry"):
                entry = {
                    "revision": logentry.get("revision", ""),
                    "author": "",
                    "date": "",
                    "message": "",
                }
                author = logentry.find("author")
                if author is not None:
                    entry["author"] = author.text or ""
                date = logentry.find("date")
                if date is not None:
                    entry["date"] = date.text or ""
                msg = logentry.find("msg")
                if msg is not None:
                    entry["message"] = msg.text or ""
                entries.append(entry)
        except ET.ParseError:
            pass
        return entries

    def get_diff(
        self, slug: str, old_rev: str, new_rev: str = "HEAD"
    ) -> tuple[str, list[str], list[str], list[str]]:
        """
        Get diff between two revisions.

        Args:
            slug: Plugin slug
            old_rev: Old revision
            new_rev: New revision (default: HEAD)

        Returns:
            Tuple of (diff_output, changed_files, added_files, removed_files)
        """
        svn_url = f"{self.svn_base}{slug}/trunk/"

        # Get diff summary first
        cmd_summary = [
            "svn", "diff", "--summarize",
            "-r", f"{old_rev}:{new_rev}",
            svn_url
        ]

        changed, added, removed = [], [], []

        try:
            result = subprocess.run(
                cmd_summary, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    status = line[0]
                    # Extract filename from URL
                    filepath = line.split()[-1] if line.split() else ""
                    if filepath.startswith(svn_url):
                        filepath = filepath[len(svn_url):]

                    if status == "M":
                        changed.append(filepath)
                    elif status == "A":
                        added.append(filepath)
                    elif status == "D":
                        removed.append(filepath)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        # Get actual diff (can be large, so we might truncate)
        cmd_diff = ["svn", "diff", "-r", f"{old_rev}:{new_rev}", svn_url]
        diff_output = ""

        try:
            result = subprocess.run(
                cmd_diff, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                diff_output = result.stdout
                # Truncate if too large
                if len(diff_output) > 100000:
                    diff_output = diff_output[:100000] + "\n... [truncated]"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        return diff_output, changed, added, removed

    def compare_revisions(
        self, slug: str, old_rev: str, new_rev: str = "HEAD"
    ) -> SVNChangeInfo:
        """
        Compare two SVN revisions and return change info.

        Args:
            slug: Plugin slug
            old_rev: Old revision
            new_rev: New revision

        Returns:
            SVNChangeInfo with all change details
        """
        diff_output, changed, added, removed = self.get_diff(slug, old_rev, new_rev)
        log_entries = self.get_log(slug, limit=50, start_rev=old_rev)

        return SVNChangeInfo(
            slug=slug,
            old_revision=old_rev,
            new_revision=new_rev if new_rev != "HEAD" else self.get_latest_revision(slug) or "HEAD",
            changed_files=changed,
            added_files=added,
            removed_files=removed,
            diff_output=diff_output,
            log_entries=log_entries,
        )


@dataclass
class DownloadResult:
    """Result of a plugin download operation."""

    slug: str
    version: str
    zip_path: Path | None = None
    extracted_path: Path | None = None
    svn_path: Path | None = None
    plugin_dir: Path | None = None  # Actual plugin files location


class PluginDownloader:
    """
    Handles downloading plugins from WordPress repository.

    Directory structure:
        {download_dir}/
        └── {slug}/
            ├── zip/
            │   └── {version}.zip
            ├── extracted/
            │   └── {version}/
            │       └── {plugin files}
            └── svn/
                └── {plugin files from trunk}
    """

    def __init__(self, download_dir: str | Path | None = None):
        """
        Initialize the downloader.

        Args:
            download_dir: Base directory for all plugin downloads.
                         Defaults to {DEFAULT_OUTPUT_DIR}/plugins/
        """
        if download_dir is None:
            download_dir = Path(DEFAULT_OUTPUT_DIR) / PLUGINS_SUBDIR
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def _get_plugin_dir(self, slug: str) -> Path:
        """Get the base directory for a plugin."""
        plugin_dir = self.download_dir / slug
        plugin_dir.mkdir(parents=True, exist_ok=True)
        return plugin_dir

    def _get_zip_dir(self, slug: str) -> Path:
        """Get the ZIP storage directory for a plugin."""
        zip_dir = self._get_plugin_dir(slug) / "zip"
        zip_dir.mkdir(parents=True, exist_ok=True)
        return zip_dir

    def _get_extracted_dir(self, slug: str) -> Path:
        """Get the extracted versions directory for a plugin."""
        extracted_dir = self._get_plugin_dir(slug) / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        return extracted_dir

    def _get_svn_dir(self, slug: str) -> Path:
        """Get the SVN checkout directory for a plugin."""
        svn_dir = self._get_plugin_dir(slug) / "svn"
        return svn_dir

    def download_zip(
        self, plugin: PluginInfo, version: str | None = None, timeout: int = 60
    ) -> Path | None:
        """
        Download plugin as ZIP file.

        Args:
            plugin: PluginInfo object
            version: Specific version to download (default: latest)
            timeout: Download timeout in seconds

        Returns:
            Path to downloaded ZIP file or None on failure
        """
        target_version = version or plugin.version
        download_url = plugin.download_link

        # Modify URL for specific version if requested
        if version and version != plugin.version:
            download_url = download_url.replace(
                f".{plugin.version}.zip", f".{version}.zip"
            )

        # Store as {slug}/zip/{version}.zip
        zip_dir = self._get_zip_dir(plugin.slug)
        filepath = zip_dir / f"{target_version}.zip"

        # Skip if already downloaded
        if filepath.exists():
            print(f"[*] ZIP already exists: {filepath}", file=sys.stderr)
            return filepath

        try:
            print(f"[*] Downloading {plugin.slug} v{target_version}...", file=sys.stderr)
            response = self.session.get(download_url, stream=True, timeout=timeout)
            response.raise_for_status()

            # Get total size if available
            total_size = int(response.headers.get("content-length", 0))

            with open(filepath, "wb") as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        percent = (downloaded / total_size) * 100
                        print(f"\r[*] Progress: {percent:.1f}%", end="", flush=True, file=sys.stderr)

            if total_size:
                print(file=sys.stderr)  # Newline after progress

            print(f"[+] Downloaded: {filepath}", file=sys.stderr)
            return filepath

        except requests.RequestException as e:
            print(f"[ERROR] Failed to download {plugin.slug}: {e}", file=sys.stderr)
            return None
        except IOError as e:
            print(f"[ERROR] Failed to save {plugin.slug}: {e}", file=sys.stderr)
            return None

    def download_zip_by_url(
        self, url: str, slug: str, version: str, timeout: int = 60
    ) -> Path | None:
        """
        Download a ZIP file by direct URL.

        Args:
            url: Direct download URL
            slug: Plugin slug
            version: Version string for naming
            timeout: Download timeout in seconds

        Returns:
            Path to downloaded file or None on failure
        """
        zip_dir = self._get_zip_dir(slug)
        filepath = zip_dir / f"{version}.zip"

        if filepath.exists():
            print(f"[*] ZIP already exists: {filepath}", file=sys.stderr)
            return filepath

        try:
            print(f"[*] Downloading {slug} v{version}...", file=sys.stderr)
            response = self.session.get(url, stream=True, timeout=timeout)
            response.raise_for_status()

            with open(filepath, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"[+] Downloaded: {filepath}", file=sys.stderr)
            return filepath

        except (requests.RequestException, IOError) as e:
            print(f"[ERROR] Failed to download {slug}: {e}", file=sys.stderr)
            return None

    def download_svn(
        self, slug: str, revision: str | None = None, branch: str = "trunk"
    ) -> Path | None:
        """
        Download plugin from SVN repository.

        Args:
            slug: Plugin slug
            revision: Specific SVN revision (optional)
            branch: SVN branch (default: trunk)

        Returns:
            Path to checked out directory or None on failure
        """
        svn_url = f"{WP_PLUGINS_SVN}{slug}/{branch}/"
        dest_dir = self._get_svn_dir(slug)

        try:
            # Remove existing SVN directory for fresh checkout
            if dest_dir.exists():
                shutil.rmtree(dest_dir)

            dest_dir.mkdir(parents=True, exist_ok=True)

            cmd = ["svn", "checkout", "--non-interactive"]
            if revision:
                cmd.extend(["-r", revision])
            cmd.extend([svn_url, str(dest_dir)])

            print(f"[*] SVN checkout {slug} ({branch})...", file=sys.stderr)
            subprocess.run(
                cmd, check=True, capture_output=True, text=True, timeout=300
            )

            print(f"[+] SVN checkout complete: {dest_dir}", file=sys.stderr)
            return dest_dir

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] SVN checkout failed for {slug}: {e.stderr}", file=sys.stderr)
            return None
        except subprocess.TimeoutExpired:
            print(f"[ERROR] SVN checkout timed out for {slug}", file=sys.stderr)
            return None
        except FileNotFoundError:
            print("[ERROR] SVN not installed. Install with: apt install subversion", file=sys.stderr)
            return None

    def download_svn_tag(self, slug: str, tag: str) -> Path | None:
        """
        Download a specific tagged version from SVN.

        Args:
            slug: Plugin slug
            tag: Version tag

        Returns:
            Path to checked out directory or None on failure
        """
        return self.download_svn(slug, branch=f"tags/{tag}")

    def extract_zip(
        self, zip_path: Path, slug: str, version: str
    ) -> Path | None:
        """
        Extract ZIP file to versioned directory.

        Args:
            zip_path: Path to ZIP file
            slug: Plugin slug
            version: Version string for directory naming

        Returns:
            Path to extracted plugin files or None on failure
        """
        extracted_dir = self._get_extracted_dir(slug)
        version_dir = extracted_dir / version

        # Skip if already extracted
        if version_dir.exists():
            print(f"[*] Already extracted: {version_dir}", file=sys.stderr)
            return self.get_plugin_files_dir(version_dir, slug)

        try:
            print(f"[*] Extracting {zip_path.name}...", file=sys.stderr)

            # Extract to temp location first
            temp_extract = extracted_dir / f"_temp_{version}"
            if temp_extract.exists():
                shutil.rmtree(temp_extract)

            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_extract)

            # WordPress ZIPs extract to a subfolder named after the plugin
            # Move contents to version directory
            extracted_contents = list(temp_extract.iterdir())
            if len(extracted_contents) == 1 and extracted_contents[0].is_dir():
                # Single directory inside - this is the plugin folder
                shutil.move(str(extracted_contents[0]), str(version_dir))
                temp_extract.rmdir()
            else:
                # Multiple items or files - move the whole temp dir
                shutil.move(str(temp_extract), str(version_dir))

            print(f"[+] Extracted to: {version_dir}", file=sys.stderr)
            return version_dir

        except zipfile.BadZipFile:
            print(f"[ERROR] Invalid ZIP file: {zip_path}", file=sys.stderr)
            return None
        except IOError as e:
            print(f"[ERROR] Failed to extract {zip_path}: {e}", file=sys.stderr)
            return None

    def get_plugin_files_dir(self, extracted_path: Path, slug: str) -> Path:
        """
        Get the actual plugin files directory after extraction.

        Args:
            extracted_path: Path to extracted version directory
            slug: Plugin slug

        Returns:
            Path to the plugin files directory
        """
        # Check if plugin directory exists as subdirectory
        plugin_subdir = extracted_path / slug
        if plugin_subdir.exists():
            return plugin_subdir

        # Check for single subdirectory
        subdirs = [d for d in extracted_path.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]

        # Return the extracted path itself
        return extracted_path

    def download_plugin(
        self,
        plugin: PluginInfo,
        extract: bool = True,
        svn: bool = False,
        version: str | None = None,
    ) -> DownloadResult:
        """
        Download a plugin with all requested formats.

        Args:
            plugin: PluginInfo object
            extract: Whether to extract the ZIP
            svn: Whether to also checkout from SVN
            version: Specific version (default: latest)

        Returns:
            DownloadResult with paths to all downloaded content
        """
        target_version = version or plugin.version

        result = DownloadResult(
            slug=plugin.slug,
            version=target_version,
        )

        # Always download ZIP
        result.zip_path = self.download_zip(plugin, version=version)

        # Extract if requested
        if extract and result.zip_path:
            result.extracted_path = self.extract_zip(
                result.zip_path, plugin.slug, target_version
            )
            if result.extracted_path:
                result.plugin_dir = result.extracted_path

        # SVN checkout if requested
        if svn:
            result.svn_path = self.download_svn(plugin.slug)
            # If no extracted path, use SVN as plugin_dir
            if not result.plugin_dir and result.svn_path:
                result.plugin_dir = result.svn_path

        return result

    def list_downloaded_versions(self, slug: str) -> list[str]:
        """
        List all downloaded versions of a plugin.

        Args:
            slug: Plugin slug

        Returns:
            List of version strings
        """
        versions = []

        # Check ZIP directory
        zip_dir = self._get_plugin_dir(slug) / "zip"
        if zip_dir.exists():
            for zip_file in zip_dir.glob("*.zip"):
                versions.append(zip_file.stem)

        return sorted(set(versions), reverse=True)

    def get_extracted_version_path(self, slug: str, version: str) -> Path | None:
        """
        Get path to an extracted version if it exists.

        Args:
            slug: Plugin slug
            version: Version string

        Returns:
            Path to extracted version or None
        """
        version_dir = self._get_extracted_dir(slug) / version
        if version_dir.exists():
            return version_dir
        return None
