#!/usr/bin/env python3
"""Setup script for building wheels with custom Python tags."""

from setuptools import setup, find_packages

# Read dependencies from pyproject.toml is handled automatically by setuptools
# This setup.py is primarily for building wheels with custom tags

setup(
    packages=find_packages(),
    python_requires='>=3.6',
)
