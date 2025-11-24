"""Core functionality module."""

from wpguard.core.models import PluginInfo, ChangeReport
from wpguard.core.downloader import PluginDownloader, DownloadResult, SVNClient, SVNChangeInfo
from wpguard.core.watcher import PluginWatcher

__all__ = [
    "PluginInfo",
    "ChangeReport",
    "PluginDownloader",
    "DownloadResult",
    "SVNClient",
    "SVNChangeInfo",
    "PluginWatcher",
]
