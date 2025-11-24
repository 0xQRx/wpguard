"""
Entry point for running wpguard as a module: python -m wpguard
"""

import sys

from wpguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
