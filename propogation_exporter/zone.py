import logging
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Union

import yaml

from .dns_utils import DNSChecker
from . import metrics

logger = logging.getLogger(__name__)

# Default regex used to parse journal "[STATS]" lines for zone updates.
# Example line:
# [STATS] example.com 2024072826 RR[count=4 time=0(sec)] ...
DEFAULT_ZONE_STATS_REGEX = re.compile(
    r"^\[STATS\]\s+(?P<zone>\S+)\s+(?P<serial>\d+)\s+RR\[count=(?P<rr_count>\d+)"
)


class ZoneInfo(object):
    """Information about a DNS zone and its nameserver."""

    def __init__(
        self,
        name: str,
        serial: int,
        update_time: datetime,
        name_server: str = "",
    ) -> None:
        self.name: str = name
        self.serial: int = serial
        self.update_time: datetime = update_time
        self.name_server: str = name_server
        # Resolve DNS name for metrics labels if possible
        self.dns_name: str = (
            DNSChecker.get_dns_name(self.name_server)
            if self.name_server else self.name_server
        )


class ZoneConfig(object):
    def __init__(
        self,
        name: str,
        rr_count: int,
        primary_nameserver: ZoneInfo,
        downstream_nameservers: List[ZoneInfo],
        synced: bool = False,
    ) -> None:
        self.name = name
        self.rr_count = rr_count
        self.primary_nameserver = primary_nameserver
        self.downstream_nameservers = downstream_nameservers
        self.synced = synced
        self.has_rr_count = False  # Track if we've parsed the RR count from journal

    def check_downstream_propagation(self) -> None:
        """Check if the zone is properly propagated to all downstream nameservers."""
        zone = self.name
        primary_serial = self.primary_nameserver.serial
        primary_update_time = self.primary_nameserver.update_time
        self.synced = False

        from time import sleep
        from datetime import datetime as _dt

        while True:
            current_time = _dt.now()

            for ns in self.downstream_nameservers:
                # Skip if this nameserver has already synced (its serial matches primary)
                if ns.serial == primary_serial:
                    continue

                logger.debug(
                    "Checking propagation for zone %s on nameserver %s",
                    zone, ns.name_server
                )
                downstream_serial = DNSChecker.resolve_soa_serial(zone, ns.name_server)

                if downstream_serial is None:
                    logger.warning(
                        "No serial obtained from %s for %s", ns.name_server, zone
                    )
                    continue

                logger.info(
                    "Zone %s: %s serial=%s (primary=%s)",
                    zone, ns.name_server, downstream_serial, primary_serial
                )
                if downstream_serial != primary_serial:
                    logger.warning(
                        "Downstream %s does not match %s: downstream=%s != primary=%s",
                        ns.name_server,
                        zone,
                        downstream_serial,
                        primary_serial,
                    )
                    ns.serial = downstream_serial
                    ns.update_time = _dt.now()

                    # Update propagation delay metric (still propagating)
                    propagation_delay = (current_time - primary_update_time).total_seconds()
                    metrics.zone_propagation_delay.labels(
                        zone=zone,
                        nameserver=ns.dns_name,
                        serial=str(primary_serial)
                    ).set(propagation_delay)
                    continue

                # Nameserver is now synced - record the delay at this moment
                logger.info(
                    "Downstream %s is synced for %s: downstream=%s == primary=%s",
                    ns.name_server,
                    zone,
                    downstream_serial,
                    primary_serial,
                )
                ns.serial = downstream_serial
                ns.update_time = _dt.now()

                # Calculate and set the final propagation delay for this nameserver
                propagation_delay = (ns.update_time - primary_update_time).total_seconds()
                metrics.zone_propagation_delay.labels(
                    zone=zone,
                    nameserver=ns.dns_name,
                    serial=str(primary_serial)
                ).set(propagation_delay)
                logger.info(
                    "Zone %s: %s propagation delay: %.2f seconds",
                    zone, ns.dns_name, propagation_delay
                )

            # Check if all nameservers have synced by comparing serials
            self.synced = all(ns.serial == primary_serial for ns in self.downstream_nameservers)
            logger.debug("Zone %s synced flag set to %s", zone, self.synced)

            # Update the sync status metric
            metrics.zone_in_sync.labels(zone=zone).set(1 if self.synced else 0)

            if self.synced:
                break
            sleep(0.5)


class ZoneManager(object):
    """Manages zone configurations and propagation worker threads."""

    def __init__(
        self,
        zones: Dict[str, ZoneConfig],
        *,
        zone_stats_regex: Optional[Union[str, Pattern[str]]] = None
    ) -> None:
        self.zones = zones
        self.workers: Dict[str, threading.Thread] = {}
        self._metrics_thread: Optional[threading.Thread] = None
        # Regex used to parse journal entries for zone updates
        if zone_stats_regex is None:
            self.zone_stats_regex = DEFAULT_ZONE_STATS_REGEX
        elif isinstance(zone_stats_regex, str):
            self.zone_stats_regex = re.compile(zone_stats_regex)
        else:
            self.zone_stats_regex = zone_stats_regex

    @staticmethod
    def load_from_file(
        config_file: Path,
        *,
        zone_stats_regex: Optional[Union[str, Pattern[str]]] = None
    ) -> 'ZoneManager':
        """Load zone configuration from a YAML file and return a ZoneManager."""
        zones_config = yaml.safe_load(config_file.read_text())
        zones: Dict[str, ZoneConfig] = {}
        for zone, config in zones_config['zones'].items():
            logger.debug(f"Loaded zone configuration for {zone}: {config}")
            zones[zone] = ZoneConfig(
                name=zone,
                rr_count=0,
                primary_nameserver=ZoneInfo(
                    name=zone,
                    serial=0,
                    update_time=datetime.min,
                    name_server=config['primary_nameserver'],
                ),
                downstream_nameservers=[
                    ZoneInfo(
                        name=zone,
                        serial=0,
                        update_time=datetime.min,
                        name_server=ns,
                    ) for ns in config.get('downstream_nameservers', [])
                ],
            )
        return ZoneManager(zones, zone_stats_regex=zone_stats_regex)

    def start_propagation_check(self, zone_config: ZoneConfig) -> None:
        """Start or restart a propagation check thread for a zone."""
        name = zone_config.name
        t = self.workers.get(name)
        if t is None or not t.is_alive():
            worker = threading.Thread(
                target=zone_config.check_downstream_propagation,
                name=f"propagate-{name}",
                daemon=True,
            )
            self.workers[name] = worker
            worker.start()
            logger.debug("Started propagation worker for zone %s", name)
        else:
            logger.debug("Propagation worker already running for zone %s", name)

    def parse_zone_info(self, entry: Dict[str, Any]) -> ZoneConfig:
        """Parse zone information from a journal message."""
        # Expected example payload (but now parsed with regex):
        # [STATS] example.com 2024072826 RR[count=4 time=0(sec)] ...
        message = entry.get('MESSAGE', '')
        match = self.zone_stats_regex.search(message)
        if not match:
            raise ValueError(f"Journal entry did not match stats regex: {message}")

        zone = match.group('zone')
        serial = match.group('serial')
        rr_count = int(match.group('rr_count'))

        if zone not in self.zones:
            raise ValueError(f"Zone {zone} not found in zone configurations")

        update_time = entry['__REALTIME_TIMESTAMP']

        zone_config = self.zones[zone]
        zone_config.rr_count = rr_count
        zone_config.has_rr_count = True  # Mark that we have a valid RR count
        zone_config.synced = False
        zone_config.primary_nameserver.serial = int(serial)
        zone_config.primary_nameserver.update_time = update_time

        # Update Prometheus metrics
        metrics.zone_rr_count.labels(zone=zone).set(zone_config.rr_count)
        # Mark as not synced initially when zone is updated
        metrics.zone_in_sync.labels(zone=zone).set(0)

        return zone_config

    def update_metrics(self) -> None:
        """Update Prometheus metrics for all zones."""
        for zone_name, zone_config in self.zones.items():
            # Only export RR count metric if we've parsed it from the journal
            if zone_config.has_rr_count:
                metrics.zone_rr_count.labels(zone=zone_name).set(zone_config.rr_count)
                metrics.zone_in_sync.labels(zone=zone_name).set(1 if zone_config.synced else 0)
                logger.debug(
                    "Updated metric for zone %s: rr_count=%d, synced=%s",
                    zone_name, zone_config.rr_count, zone_config.synced
                )
            else:
                logger.debug("Skipping metrics for zone %s: no RR count parsed yet", zone_name)

    def start_metrics_updater(self, interval: int = 60) -> None:
        """Start a background thread to update Prometheus metrics periodically."""
        from time import sleep

        def metrics_updater():
            while True:
                sleep(interval)
                self.update_metrics()

        if self._metrics_thread is None or not self._metrics_thread.is_alive():
            self._metrics_thread = threading.Thread(
                target=metrics_updater,
                name="metrics-updater",
                daemon=True,
            )
            self._metrics_thread.start()
            logger.info("Started Prometheus metrics updater (interval: %ds)", interval)
