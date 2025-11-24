"""
Utility functions for file operations and hashing.
"""

import hashlib
from pathlib import Path


def compute_file_hash(filepath: Path, algorithm: str = "md5") -> str:
    """
    Compute hash of a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm to use (md5, sha1, sha256)

    Returns:
        Hex digest of the file hash
    """
    hash_func = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def compute_directory_hashes(
    directory: Path, algorithm: str = "md5", ignore_patterns: list[str] | None = None
) -> dict[str, str]:
    """
    Compute hashes for all files in a directory.

    Args:
        directory: Directory to scan
        algorithm: Hash algorithm to use
        ignore_patterns: List of patterns to ignore (e.g., [".svn", "__pycache__"])

    Returns:
        Dictionary mapping relative file paths to their hashes
    """
    ignore_patterns = ignore_patterns or [".svn", ".git", "__pycache__", ".DS_Store"]
    hashes: dict[str, str] = {}

    for filepath in directory.rglob("*"):
        if filepath.is_file():
            # Skip ignored patterns
            should_skip = False
            for pattern in ignore_patterns:
                if pattern in str(filepath):
                    should_skip = True
                    break
            if should_skip:
                continue

            try:
                rel_path = str(filepath.relative_to(directory))
                hashes[rel_path] = compute_file_hash(filepath, algorithm)
            except (OSError, IOError):
                # Skip files we can't read
                pass

    return hashes


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    # Replace problematic characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, "_")
    return name.strip()


def parse_duration(value: str) -> int:
    """
    Parse duration string to seconds.

    Formats:
        30s       -> 30 seconds
        5m        -> 5 minutes (300 seconds)
        1h        -> 1 hour (3600 seconds)
        1h30m     -> 1 hour 30 minutes (5400 seconds)
        1h30m45s  -> 1 hour 30 minutes 45 seconds (5445 seconds)
        300       -> 300 seconds (plain integer)

    Args:
        value: Duration string or plain integer

    Returns:
        Duration in seconds

    Raises:
        ValueError: If format is invalid
    """
    import re

    value = value.strip()

    # If plain integer, return as seconds
    if value.isdigit():
        return int(value)

    # Parse duration components
    pattern = r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$"
    match = re.fullmatch(pattern, value.lower())

    if not match or not any(match.groups()):
        raise ValueError(
            f"Invalid duration format: '{value}'. "
            "Use formats like: 30s, 5m, 1h, 1h30m, 1h30m45s, or plain integer (seconds)"
        )

    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)

    return hours * 3600 + minutes * 60 + seconds
