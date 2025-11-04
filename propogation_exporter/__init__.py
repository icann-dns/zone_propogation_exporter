"""Propagation exporter package.

Provides journal parsing, DNS checks, metrics, and CLI entry point.
"""

from .dns_utils import DNSChecker  # noqa: F401
from .zone import ZoneManager, DEFAULT_ZONE_STATS_REGEX, ZoneInfo, ZoneConfig  # noqa: F401
