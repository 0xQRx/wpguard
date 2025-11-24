# WordPressGuard

A defensive security research tool for downloading, monitoring, and analyzing WordPress plugins from the official repository.

## Features

- **Download Plugins**: Bulk download plugins filtered by active installations, search terms, or categories
- **Watch Mode**: Track specific plugins and get notified when updates are released
- **SVN-Based Change Detection**: Use SVN diff to see exact code changes between versions, with commit logs
- **Hash-Based Fallback**: Compare file hashes when SVN is unavailable
- **Discord Notifications**: Receive real-time alerts when watched plugins are updated
- **Local Reports**: JSON reports saved locally for each detected update
- **Continuous Monitoring**: Background watch mode with tmux support
- **SVN Commands**: Direct access to SVN log and diff for any plugin

## Installation

### From GitHub (via pipx - recommended)

```bash
pipx install git+https://github.com/USERNAME/WordPressGuard.git
```

### From GitHub (via pip)

```bash
pip install git+https://github.com/USERNAME/WordPressGuard.git
```

### Development Installation

```bash
git clone https://github.com/USERNAME/WordPressGuard.git
cd WordPressGuard
pip install -e ".[dev]"
```

## Quick Start

```bash
# Download 10 plugins with 100k+ active installs
wpguard download --min-installs 100000 --count 10

# Get info about a specific plugin
wpguard info akismet

# Search for security plugins
wpguard search "security"

# Add plugins to watchlist
wpguard watch add akismet wordfence contact-form-7

# Check once for updates
wpguard watch check

# Start continuous monitoring with Discord notifications
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
wpguard watch --send-report --interval 30m
```

## Commands

### download

Download plugins from the WordPress repository.

```bash
wpguard download [OPTIONS]

Options:
  --search, -s TEXT       Search term for plugins
  --min-installs INTEGER  Minimum active installations (default: 0)
  --max-installs INTEGER  Maximum active installations
  --count, -n TEXT        Number of plugins or 'all' (default: 10)
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --svn                   Also checkout from SVN (in addition to ZIP)
  --extract, -x           Extract ZIP files after download
  --delay INTEGER         Delay between downloads in seconds (default: 1)
  --browse TEXT           Browse category: popular, new, updated
```

**Examples:**

```bash
# Download top 5 security plugins with 50k+ installs
wpguard download --search security --min-installs 50000 --count 5

# Download all plugins with 1M+ installs
wpguard download --min-installs 1000000 --count all

# Download and extract popular plugins with custom delay
wpguard download --browse popular --count 20 --extract --delay 2

# Download ZIP + SVN for version history access
wpguard download --search backup --count 3 --svn --extract
```

### info

Get detailed information about a specific plugin.

```bash
wpguard info <slug>
```

**Example:**

```bash
wpguard info wordfence
```

### search

Search for plugins in the WordPress repository.

```bash
wpguard search <query> [OPTIONS]

Options:
  --page, -p INTEGER     Page number (default: 1)
  --per-page INTEGER     Results per page, max 250 (default: 20)
```

**Example:**

```bash
wpguard search "ecommerce" --per-page 50
```

### watch

Unified command for plugin monitoring. Manages watchlist and runs continuous monitoring.

#### watch add

Add plugins to the watchlist.

```bash
wpguard watch add <slugs...> [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --discord-webhook URL   Discord webhook URL
```

**Example:**

```bash
wpguard watch add akismet jetpack woocommerce
```

#### watch remove

Remove plugins from watchlist.

```bash
wpguard watch remove <slugs...> [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
```

#### watch list

List all watched plugins.

```bash
wpguard watch list [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
```

#### watch check

Check watched plugins for updates once (no continuous loop).

```bash
wpguard watch check [OPTIONS]

Options:
  --output-dir, -o PATH   Output directory (default: ./wpguard_output)
  --send-report           Send report to Discord
  --discord-webhook URL   Discord webhook URL
```

#### watch (continuous monitoring)

Run `wpguard watch` without a subcommand to start continuous monitoring.

```bash
wpguard watch [OPTIONS]

Options:
  --output-dir, -o PATH    Output directory (default: ./wpguard_output)
  --interval, -i DURATION  Check interval (default: 5m)
                           Formats: 30s, 5m, 1h, 1h30m, 1h30m45s, or integer seconds
  --send-report            Send reports to Discord
  --discord-webhook URL    Discord webhook URL
  --tmux                   Start in tmux session
  --tmux-session NAME      Tmux session name (default: wpguard)
```

**Examples:**

```bash
# Watch mode in foreground with 10 minute interval
wpguard watch --interval 10m

# Watch mode with 1 hour 30 minute interval
wpguard watch --interval 1h30m

# Watch mode with Discord notifications
wpguard watch --interval 30m --send-report

# Watch mode in tmux (for remote servers)
wpguard watch --tmux --tmux-session wp-monitor --send-report
```

### svn

SVN operations for viewing plugin history and changes.

#### svn log

View commit history for a plugin.

```bash
wpguard svn log <slug> [OPTIONS]

Options:
  --limit, -l INTEGER    Number of entries (default: 10)
```

**Example:**

```bash
wpguard svn log akismet --limit 20
```

#### svn diff

Compare changes between SVN revisions.

```bash
wpguard svn diff <slug> <old_rev> [new_rev] [OPTIONS]

Options:
  --show-diff            Show full diff output
  --output-file, -o      Save diff to file
```

**Examples:**

```bash
# Show changes from revision 1000000 to HEAD
wpguard svn diff akismet 1000000

# Show changes between two specific revisions
wpguard svn diff akismet 1000000 1000500

# Show full diff and save to file
wpguard svn diff akismet 1000000 --show-diff --output-file changes.diff
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Discord webhook URL for notifications |

All other settings (output directory, intervals) are controlled via CLI flags only.

## Directory Structure

All output goes under a single base directory (default: `./wpguard_output`):

```
./wpguard_output/                    # Base directory (--output-dir)
├── plugins/                         # Downloaded plugins
│   ├── akismet/
│   │   ├── zip/
│   │   │   ├── 5.3.zip             # Version-named ZIP files
│   │   │   └── 5.2.zip             # Old versions preserved
│   │   ├── extracted/
│   │   │   ├── 5.3/                # Version-named directories
│   │   │   │   ├── akismet.php
│   │   │   │   └── ...
│   │   │   └── 5.2/
│   │   └── svn/                    # SVN working copy (trunk)
│   │       ├── .svn/
│   │       └── ...
│   └── wordfence/
│       └── ...
├── reports/                         # Change reports
│   └── akismet/
│       └── 5.2_to_5.3_2024-01-15_103000.json
└── state.json                       # Watchlist state file
```

This structure allows:
- **Version history**: Multiple versions of the same plugin stored side-by-side
- **Easy comparison**: Compare different versions using diff tools
- **SVN access**: Full SVN working copy for `svn log`, `svn diff`, etc.
- **No conflicts**: ZIP, extracted, and SVN versions don't overwrite each other
- **Local reports**: JSON reports for each detected update

## Change Reports

When a watched plugin is updated, WordPressGuard generates a detailed change report including:

- **Modified Files**: Files that changed between versions (from SVN diff)
- **Added Files**: New files in the updated version
- **Removed Files**: Files deleted in the updated version
- **SVN Commit Log**: Recent commit messages explaining the changes
- **Download Commands**: Ready-to-use wget and svn commands

### Console Output

```
======================================================================
PLUGIN UPDATE: Akismet Anti-Spam (akismet)
Version: 5.0 -> 5.1
======================================================================

[Modified Files] (3)
   M akismet.php
   M class.akismet.php
   M readme.txt

[Added Files] (1)
   A includes/new-feature.php

[Download Commands]
   wget "https://downloads.wordpress.org/plugin/akismet.5.1.zip"
   svn checkout https://plugins.svn.wordpress.org/akismet/trunk/
======================================================================

[SVN Commit Log]
   r3000001 - Updated security checks for PHP 8.2 compatibility
   r3000000 - Added new spam detection algorithm
   r2999999 - Version bump for 5.1 release
```

### Local JSON Report

Reports are saved to `{output_dir}/reports/{slug}/`:

```json
{
  "plugin_slug": "akismet",
  "plugin_name": "Akismet Anti-Spam",
  "old_version": "5.2",
  "new_version": "5.3",
  "timestamp": "2024-01-15T10:30:00Z",
  "svn_old_revision": "2987000",
  "svn_new_revision": "2987654",
  "changed_files": ["akismet.php", "class.akismet.php"],
  "added_files": ["includes/new-feature.php"],
  "removed_files": [],
  "svn_log": [
    {"revision": "2987654", "author": "dev", "date": "...", "message": "..."}
  ],
  "download_commands": {
    "wget": "wget \"https://...\"",
    "svn": "svn checkout https://..."
  }
}
```

### Discord Notification

Reports are sent as rich embeds with:
- Plugin name and version change
- Categorized file lists
- Copy-paste download commands

## Use Cases

### Security Research

Monitor popular plugins for code changes that might indicate:
- Supply chain compromises
- Backdoor insertions
- Vulnerability patches

```bash
# Monitor top security plugins
wpguard watch add wordfence sucuri-scanner ithemes-security
wpguard watch --send-report --interval 5m
```

### Plugin Development

Track competitor plugins or dependencies:

```bash
# Monitor specific plugins
wpguard watch add advanced-custom-fields elementor
wpguard watch check
```

### Bulk Analysis

Download plugins for static analysis:

```bash
# Download all plugins with 500k+ installs
wpguard download --min-installs 500000 --count all --extract

# Download security-related plugins
wpguard download --search security --count all --min-installs 10000
```

## Requirements

- Python 3.9+
- `requests` library
- `svn` command-line tool (optional, for SVN downloads and change tracking)
- `tmux` (optional, for background watch mode)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for legitimate security research and defensive purposes only. Always respect the WordPress plugin repository terms of service and the licenses of individual plugins.
