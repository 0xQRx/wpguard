"""
WordPressGuard - WordPress Plugin Security Research Tool

A defensive security research tool for downloading, monitoring, and analyzing
WordPress plugins from the official repository.
"""

__version__ = "1.0.0"
__author__ = "Security Research"

from wpguard.core.models import PluginInfo, ChangeReport
from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.core.downloader import PluginDownloader
from wpguard.core.watcher import PluginWatcher

__all__ = [
    "PluginInfo",
    "ChangeReport",
    "WordPressPluginAPI",
    "PluginDownloader",
    "PluginWatcher",
    "__version__",
]
