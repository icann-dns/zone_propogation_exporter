#!/usr/bin/env python3
"""Compatibility runner.

This script simply delegates to the package CLI entry point.
Prefer invoking via `python -m propogation_exporter` or the console script.
"""

from propogation_exporter.cli import main


if __name__ == "__main__":
    main()

