"""
Dependency checker and installer for wpguard (Linux only).
"""

import os
import shutil
import subprocess
import sys
from typing import Any


def _check(cmd: list[str], timeout: int = 10) -> bool:
    """Check if a command runs successfully."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _run(cmd: str, desc: str) -> bool:
    """Run a shell command, printing status."""
    print(f"  [*] {desc}...")
    result = subprocess.run(cmd, shell=True)
    if result.returncode == 0:
        print(f"  [+] {desc} — OK")
        return True
    else:
        print(f"  [!] {desc} — FAILED (exit {result.returncode})")
        return False


def check_all() -> list[dict[str, Any]]:
    """Check all dependencies and return status list."""
    deps = [
        {
            "name": "Docker",
            "check": lambda: _check(["docker", "--version"]),
            "install": "sudo apt install -y docker.io",
            "required": True,
        },
        {
            "name": "Docker Compose",
            "check": lambda: _check(["docker", "compose", "version"]) or _check(["docker-compose", "--version"]),
            "install": "sudo apt install -y docker-compose-plugin",
            "required": True,
        },
        {
            "name": "SVN",
            "check": lambda: _check(["svn", "--version"]),
            "install": "sudo apt install -y subversion",
            "required": True,
        },
        {
            "name": "ffmpeg",
            "check": lambda: _check(["ffmpeg", "-version"]),
            "install": "sudo apt install -y ffmpeg",
            "required": True,
        },
        {
            "name": "Node.js",
            "check": lambda: _check(["node", "--version"]),
            "install": 'curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && nvm install 24',
            "required": True,
        },
        {
            "name": "asciinema",
            "check": lambda: _check(["asciinema", "--version"]),
            "install": "pipx install asciinema",
            "required": False,
        },
        {
            "name": "Playwright (Python)",
            "check": lambda: _check([sys.executable, "-c", "from playwright.sync_api import sync_playwright"]),
            "install": "pip install playwright && playwright install chromium",
            "required": False,
        },
        {
            "name": "Claude Code CLI",
            "check": lambda: _check(["claude", "--version"]),
            "install": "npm install -g @anthropic-ai/claude-code",
            "required": True,
        },
    ]

    for dep in deps:
        dep["installed"] = dep["check"]()

    return deps


def install_deps(dry_run: bool = False, setup_mcp: bool = False) -> int:
    """
    Check and install missing dependencies.

    Args:
        dry_run: If True, only show what would be installed
        setup_mcp: If True, also configure Claude Code MCP servers

    Returns:
        0 on success, 1 on failure
    """
    print("\n[*] wpguard dependency checker (Linux)")
    print("=" * 50)

    deps = check_all()

    # Report status
    installed = [d for d in deps if d["installed"]]
    missing = [d for d in deps if not d["installed"]]
    missing_required = [d for d in missing if d["required"]]
    missing_optional = [d for d in missing if not d["required"]]

    print(f"\n  Installed ({len(installed)}):")
    for d in installed:
        print(f"    [OK] {d['name']}")

    if missing_required:
        print(f"\n  Missing — required ({len(missing_required)}):")
        for d in missing_required:
            print(f"    [!!] {d['name']}")
            print(f"         {d['install']}")

    if missing_optional:
        print(f"\n  Missing — optional ({len(missing_optional)}):")
        for d in missing_optional:
            print(f"    [--] {d['name']}")
            print(f"         {d['install']}")

    if not missing:
        print("\n[+] All dependencies installed!")
        if setup_mcp:
            return _setup_mcp(dry_run)
        return 0

    if dry_run:
        print(f"\n[*] Dry run — {len(missing)} package(s) would be installed")
        if setup_mcp:
            print("[*] Dry run — MCP servers would be configured")
        return 0

    # Install missing dependencies
    print(f"\n[*] Installing {len(missing)} missing package(s)...\n")

    failed = []
    for dep in missing:
        if not _run(dep["install"], f"Installing {dep['name']}"):
            failed.append(dep["name"])

    # Special: Playwright needs browser install after pip install
    if any(d["name"] == "Playwright (Python)" for d in missing):
        _run("playwright install chromium", "Installing Chromium for Playwright")

    print("\n" + "=" * 50)
    if failed:
        print(f"[!] {len(failed)} package(s) failed: {', '.join(failed)}")
        print("[*] You may need to install these manually")
    else:
        print(f"[+] All {len(missing)} package(s) installed successfully!")

    if setup_mcp:
        return _setup_mcp(dry_run=False)

    return 1 if failed else 0


def _setup_mcp(dry_run: bool = False) -> int:
    """Configure Claude Code MCP servers."""
    print("\n[*] Setting up Claude Code MCP servers...")

    commands = [
        ("wpguard MCP", "claude mcp add wpguard -s user -- wpguard-mcp"),
        ("Playwright MCP", "claude mcp add playwright -s user -- npx @playwright/mcp@latest"),
    ]

    # Check if devrag is available
    devrag_bin = shutil.which("devrag")
    if devrag_bin:
        commands.append(("devrag MCP", f"claude mcp add devrag -s user -- {devrag_bin}"))

    if dry_run:
        for name, cmd in commands:
            print(f"  [*] Would run: {cmd}")
        return 0

    failed = []
    for name, cmd in commands:
        if not _run(cmd, f"Configuring {name}"):
            failed.append(name)

    return 1 if failed else 0
