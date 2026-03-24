"""
Configuration constants and Discord webhook from environment.
"""

import os
from pathlib import Path

# API endpoints — Plugins
WP_API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
WP_PLUGINS_SVN = "https://plugins.svn.wordpress.org/"
WP_PLUGINS_URL = "https://wordpress.org/plugins/"

# API endpoints — Themes
WP_THEMES_API_BASE = "https://api.wordpress.org/themes/info/1.2/"
WP_THEMES_SVN = "https://themes.svn.wordpress.org/"
WP_THEMES_URL = "https://wordpress.org/themes/"

# WordPress Sandbox Settings
WP_SANDBOX_HOST = os.environ.get("WP_SANDBOX_HOST", "172.17.0.1")
WP_SANDBOX_PORT = int(os.environ.get("WP_SANDBOX_PORT", "8000"))
WP_CONTAINER_NAME = os.environ.get("WP_CONTAINER_NAME", "wp_app")

# WordPress Sandbox Docker Compose directory
def _get_sandbox_dir() -> Path:
    """Get WordPress sandbox directory with fallback logic."""
    # Environment override (highest priority)
    env_path = os.environ.get("WPGUARD_SANDBOX_DIR")
    if env_path and Path(env_path).exists():
        return Path(env_path)

    # Package location (installed mode)
    pkg_path = Path(__file__).parent / "wordpress_instance"
    if pkg_path.exists():
        return pkg_path

    # Development fallback (running from source tree)
    dev_path = Path(__file__).parent.parent.parent / "wordpress_instance"
    if dev_path.exists():
        return dev_path

    # Return package path even if missing (will fail with clear error)
    return pkg_path

WP_SANDBOX_COMPOSE_DIR = _get_sandbox_dir()

# WordPress Test Credentials (role -> (username, password))
# All roles up to Author are IN SCOPE for Wordfence Bug Bounty
WP_CREDENTIALS: dict[str, tuple[str, str]] = {
    "admin": ("admin", "admin"),           # OUT OF SCOPE
    "editor": ("editor", "editor"),         # OUT OF SCOPE
    "author": ("author", "author"),         # IN SCOPE - can publish own posts
    "contributor": ("contributor", "contributor"),  # IN SCOPE - can write posts (not publish)
    "customer": ("customer", "customer"),   # IN SCOPE - WooCommerce customer role
    "subscriber": ("subscriber", "subscriber"),  # IN SCOPE - default registered user
}

# API limits
MAX_PER_PAGE = 250

# Default paths - all under single output directory
DEFAULT_OUTPUT_DIR = "./wpguard_output"
PLUGINS_SUBDIR = "plugins"
THEMES_SUBDIR = "themes"
REPORTS_SUBDIR = "reports"
STATE_FILENAME = "state.json"

# Wordfence Intelligence API
WORDFENCE_API_KEY = os.environ.get("WORDFENCE_API_KEY")
WORDFENCE_API_BASE = "https://www.wordfence.com/api/intelligence/v3"

# Discord - only env var supported
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

# RAG knowledge base — path to web pentesting resources (PayloadsAllTheThings, HackTricks, etc.)
WPGUARD_RAG_DOCS = os.environ.get("WPGUARD_RAG_DOCS")

# Watch mode
DEFAULT_WATCH_INTERVAL = 300  # 5 minutes (in seconds)
RECENTLY_UPDATED_FILENAME = "recently_updated.json"
NEW_PLUGINS_FILENAME = "new_plugins.json"

# HTTP settings
DEFAULT_TIMEOUT = 30
USER_AGENT = "WordPressGuard/1.0 (Security Research Tool)"


def get_discord_webhook(cli_webhook: str | None = None) -> str | None:
    """Get Discord webhook URL from CLI or environment."""
    return cli_webhook or DISCORD_WEBHOOK_URL


