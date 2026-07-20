"""
WordPressGuard - WordPress Plugin Security Research Tool

A defensive security research tool for downloading, monitoring, and analyzing
WordPress plugins from the official repository.
"""

__version__ = "2.7.1"
__author__ = "0xQRx"

from wpguard.core.models import PluginInfo, ThemeInfo, ChangeReport
from wpguard.api.wordpress import WordPressPluginAPI
from wpguard.api.themes import WordPressThemeAPI
from wpguard.core.downloader import PluginDownloader
from wpguard.core.watcher import PluginWatcher

__all__ = [
    "PluginInfo",
    "ThemeInfo",
    "ChangeReport",
    "WordPressPluginAPI",
    "WordPressThemeAPI",
    "PluginDownloader",
    "PluginWatcher",
    "__version__",
]
