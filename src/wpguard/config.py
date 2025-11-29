"""
Configuration constants and Discord webhook from environment.
"""

import os

# API endpoints
WP_API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
WP_PLUGINS_SVN = "https://plugins.svn.wordpress.org/"
WP_PLUGINS_URL = "https://wordpress.org/plugins/"

# WordPress Sandbox Settings
WP_SANDBOX_HOST = os.environ.get("WP_SANDBOX_HOST", "172.17.0.1")
WP_SANDBOX_PORT = int(os.environ.get("WP_SANDBOX_PORT", "8000"))
WP_CONTAINER_NAME = os.environ.get("WP_CONTAINER_NAME", "wp_app")

# WordPress Test Credentials (role -> (username, password))
WP_CREDENTIALS: dict[str, tuple[str, str]] = {
    "admin": ("admin", "admin"),
    "author": ("author", "author"),
    "contributor": ("contributor", "contributor"),
    "subscriber": ("subscriber", "subscriber"),
}

# API limits
MAX_PER_PAGE = 250

# Default paths - all under single output directory
DEFAULT_OUTPUT_DIR = "./wpguard_output"
PLUGINS_SUBDIR = "plugins"
REPORTS_SUBDIR = "reports"
STATE_FILENAME = "state.json"

# Discord - only env var supported
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

# Watch mode
DEFAULT_WATCH_INTERVAL = 300  # 5 minutes (in seconds)

# HTTP settings
DEFAULT_TIMEOUT = 30
USER_AGENT = "WordPressGuard/1.0 (Security Research Tool)"


def get_discord_webhook(cli_webhook: str | None = None) -> str | None:
    """Get Discord webhook URL from CLI or environment."""
    return cli_webhook or DISCORD_WEBHOOK_URL
