#!/usr/bin/env python3
import logging
import select
import socket
import threading
import re

from datetime import datetime
from argparse import ArgumentParser, Namespace
from time import sleep
from typing import Dict, List, Optional, Any, Pattern, Union
from pathlib import Path

import yaml
import dns.resolver
import dns.exception
from systemd.journal import Reader, LOG_INFO, APPEND
from prometheus_client import Gauge, start_http_server


logger = logging.getLogger(__name__)

# Prometheus metrics
zone_rr_count = Gauge('zone_rr_count', 'Number of resource records in zone', ['zone'])
zone_in_sync = Gauge('zone_in_sync', 'Whether the zone is synchronized across all nameservers (1=synced, 0=not synced)', ['zone'])
zone_propagation_delay = Gauge('zone_propagation_delay_seconds', 'Time in seconds since zone was updated on primary', ['zone', 'nameserver', 'serial'])


# Default regex used to parse journal "[STATS]" lines for zone updates.
# Example line:
# [STATS] example.com 2024072826 RR[count=4 time=0(sec)] ...
DEFAULT_JOURNAL_PATTERN: Pattern[str] = re.compile(
    r"^\[STATS\]\s+(?P<zone>\S+)\s+(?P<serial>\d+)\s+RR\[count=(?P<rr_count>\d+)"
)


class DNSChecker(object):
    """Helper class for DNS SOA serial queries."""

    @staticmethod
    def get_dns_name(ip_address: str) -> str:
        """Get the DNS name for an IP address via reverse DNS lookup.

        Args:
            ip_address: IP address to resolve

        Returns:
            DNS name if found, otherwise the original IP address
        """
        try:
            dns_name = socket.gethostbyaddr(ip_address)[0]
            logger.debug("Resolved %s to %s", ip_address, dns_name)
            return dns_name
        except (socket.herror, socket.gaierror, OSError) as e:
            logger.debug("Could not resolve %s to DNS name: %s", ip_address, e)
            return ip_address

    @staticmethod
    def resolve_soa_serial(
        zone: str,
        nameserver: str,
        *,
        port: int = 53,
        timeout: float = 3.0,
        tcp: bool = True,
    ) -> Optional[int]:
        """Resolve the SOA record for a zone on a specific nameserver and return its serial.

        Args:
            zone: DNS zone name (e.g., example.com.)
            nameserver: Downstream nameserver IP or hostname
            port: DNS port (default 53)
            timeout: Overall resolver lifetime in seconds
            tcp: Force TCP for the query (default UDP)

        Returns:
            The SOA serial as an integer, or None if not available.
        """
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.port = port
        resolver.lifetime = timeout
        resolver.timeout = timeout

        try:
            # dnspython 1.x API uses query(); resolve() is 2.x+
            answer = resolver.query(zone, "SOA", tcp=tcp)
        except (dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            logger.warning("DNS query failed for %s at %s: %s", zone, nameserver, e)
            return None
        except dns.exception.DNSException as e:
            logger.error("Unexpected DNS error for %s at %s: %s", zone, nameserver, e)
            return None

        if getattr(answer, 'rrset', None) is None or len(answer) == 0:
            logger.debug("No SOA answer for %s from %s", zone, nameserver)
            return None

        try:
            # Typically a single SOA record; take the first
            return int(answer[0].serial)
        except Exception as e:
            logger.error("Failed to parse SOA serial for %s from %s: %s", zone, nameserver, e)
            return None


class ZoneInfo(object):
    def __init__(self, name: str, serial: int, update_time: datetime, name_server: str = "") -> None:
        self.name = name
        self.serial = serial
        self.update_time = update_time
        self.name_server = name_server  # IP address or hostname for querying
        self.dns_name = DNSChecker.get_dns_name(name_server)  # DNS name for metrics


class ZoneConfig(object):
    def __init__(
        self,
        name: str,
        rr_count: int,
        primary_nameserver: 'ZoneInfo',
        downstream_nameservers: List['ZoneInfo'],
        synced: bool = False,
    ) -> None:
        self.name = name
        self.rr_count = rr_count
        self.primary_nameserver = primary_nameserver
        self.downstream_nameservers = downstream_nameservers
        self.synced = synced
        self.has_rr_count = False  # Track if we've parsed the RR count from journal

    def check_downstream_propagation(self) -> None:
        """Check if the zone is properly propagated to all downstream nameservers.

        Polls each downstream nameserver's SOA serial and compares it to the
        primary nameserver's serial. Only when all downstreams match the primary
        will self.synced be set to True and the method will return.
        """
        zone = self.name
        primary_serial = self.primary_nameserver.serial
        primary_update_time = self.primary_nameserver.update_time
        self.synced = False

        while True:
            current_time = datetime.now()

            for ns in self.downstream_nameservers:
                # Skip if this nameserver has already synced (its serial matches primary)
                if ns.serial == primary_serial:
                    continue

                logger.debug("Checking propagation for zone %s on nameserver %s", zone, ns.name_server)
                downstream_serial = DNSChecker.resolve_soa_serial(zone, ns.name_server)

                if downstream_serial is None:
                    logger.warning("No serial obtained from %s for %s", ns.name_server, zone)
                    continue

                logger.info("Zone %s: %s serial=%s (primary=%s)", zone, ns.name_server, downstream_serial, primary_serial)
                if downstream_serial != primary_serial:
                    logger.warning(
                        "Downstream %s does not match %s: downstream=%s != primary=%s",
                        ns.name_server,
                        zone,
                        downstream_serial,
                        primary_serial,
                    )
                    ns.serial = downstream_serial
                    ns.update_time = datetime.now()

                    # Update propagation delay metric (still propagating)
                    propagation_delay = (current_time - primary_update_time).total_seconds()
                    zone_propagation_delay.labels(
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
                ns.update_time = datetime.now()

                # Calculate and set the final propagation delay for this nameserver
                propagation_delay = (ns.update_time - primary_update_time).total_seconds()
                zone_propagation_delay.labels(
                    zone=zone,
                    nameserver=ns.dns_name,
                    serial=str(primary_serial)
                ).set(propagation_delay)
                logger.info("Zone %s: %s propagation delay: %.2f seconds", zone, ns.dns_name, propagation_delay)

            # Check if all nameservers have synced by comparing serials
            self.synced = all(ns.serial == primary_serial for ns in self.downstream_nameservers)
            logger.debug("Zone %s synced flag set to %s", zone, self.synced)

            # Update the sync status metric
            zone_in_sync.labels(zone=zone).set(1 if self.synced else 0)

            if self.synced:
                break
            sleep(0.5)


class ZoneManager(object):
    """Manages zone configurations and propagation worker threads."""

    def __init__(self, zones: Dict[str, ZoneConfig], *, journal_pattern: Optional[Union[str, Pattern[str]]] = None) -> None:
        self.zones = zones
        self.workers: Dict[str, threading.Thread] = {}
        self._metrics_thread: Optional[threading.Thread] = None
        # Regex used to parse journal entries for zone updates
        if journal_pattern is None:
            self.zone_stats_regex = DEFAULT_JOURNAL_PATTERN
        elif isinstance(journal_pattern, str):
            self.zone_stats_regex = re.compile(journal_pattern)
        else:
            self.zone_stats_regex = journal_pattern

    @staticmethod
    def load_from_file(config_file: Path) -> 'ZoneManager':
        """Load zone configuration from a YAML file and return a ZoneManager.

        Args:
            config_file: Path to the configuration file.

        Returns:
            ZoneManager instance with loaded zones.
        """
        zones_config = yaml.safe_load(config_file.read_text())
        journal_pattern = zones_config.get('journal_stats_pattern', DEFAULT_JOURNAL_PATTERN)
        zones = {}
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
        return ZoneManager(zones, journal_pattern=journal_pattern)

    def start_propagation_check(self, zone_config: ZoneConfig) -> None:
        """Start or restart a propagation check thread for a zone.

        Args:
            zone_config: The zone configuration to check.
        """
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
        """Parse zone information from a journal message.

        Args:
            entry: The journal message dictionary.

        Returns:
            ZoneConfig: The updated zone configuration.

        Raises:
            ValueError: If zone is not found in configurations.
        """
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
        zone_rr_count.labels(zone=zone).set(zone_config.rr_count)
        zone_in_sync.labels(zone=zone).set(0)  # Mark as not synced initially when zone is updated

        return zone_config

    def update_metrics(self) -> None:
        """Update Prometheus metrics for all zones."""
        for zone_name, zone_config in self.zones.items():
            # Only export RR count metric if we've parsed it from the journal
            if zone_config.has_rr_count:
                zone_rr_count.labels(zone=zone_name).set(zone_config.rr_count)
                zone_in_sync.labels(zone=zone_name).set(1 if zone_config.synced else 0)
                logger.debug("Updated metric for zone %s: rr_count=%d, synced=%s", zone_name, zone_config.rr_count, zone_config.synced)
            else:
                logger.debug("Skipping metrics for zone %s: no RR count parsed yet", zone_name)

    def start_metrics_updater(self, interval: int = 60) -> None:
        """Start a background thread to update Prometheus metrics periodically.

        Args:
            interval: Update interval in seconds (default: 60)
        """
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


class JournalReader(object):
    """Reads and processes systemd journal entries."""

    def __init__(self, zone_manager: ZoneManager, pattern: str = "[STATS]") -> None:
        self.zone_manager = zone_manager
        self.pattern = pattern

    def run(self) -> None:
        """Read and process journal entries for opendnssec-signer service."""
        journal = Reader()
        journal.log_level(LOG_INFO)

        journal.add_match(_SYSTEMD_UNIT="opendnssec-signer.service")
        journal.seek_tail()
        journal.get_previous()

        poller = select.poll()
        poller.register(journal, journal.get_events())

        logger.info("Journal reader started, monitoring opendnssec-signer.service")

        while poller.poll():
            if journal.process() != APPEND:
                continue

            for entry in journal:
                if entry['MESSAGE'].startswith(self.pattern):
                    logger.debug(f"Matched entry: {entry['MESSAGE']}")
                    try:
                        zone_config = self.zone_manager.parse_zone_info(entry)
                    except ValueError as error:
                        logger.error(f"Error parsing zone info: {error}")
                        continue
                    logger.info(f"Extracted ZoneConfig: {zone_config}")
                    self.zone_manager.start_propagation_check(zone_config)


def get_log_level(args_level: int) -> int:  # pragma: no cover
    """Convert an integer to a logging log level.

      Arguments:
          args_level (int): The log level as an integer

      Returns:
          int: the logging loglevel
    """
    return {
        0: logging.ERROR,
        1: logging.WARN,
        2: logging.INFO,
        3: logging.DEBUG,
    }.get(args_level, logging.DEBUG)


def get_args() -> Namespace:  # pragma: no cover
    """Parse and return the arguments.

    Returns:
        Namespace: The parsed argument namespace
    """
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-c', '--config-file', type=Path, default=Path('/etc/coralogix-exporter/zones.yaml'),
                        help='Path to the zone configuration file')
    # Ad-hoc SOA check mode (no systemd required)
    parser.add_argument('--zone', help='DNS zone to check (e.g., example.com.)')
    parser.add_argument('--ns', dest='nameservers', action='append', default=[],
                        help='Downstream nameserver (IP or host). Repeat for multiple.')
    parser.add_argument('--port', type=int, default=53, help='DNS port (default: 53)')
    parser.add_argument('--timeout', type=float, default=3.0, help='DNS timeout seconds (default: 3.0)')
    parser.add_argument('--tcp', action='store_true', help='Use TCP for DNS queries (default: UDP)')
    parser.add_argument('--metrics-port', type=int, default=8000,
                        help='Prometheus metrics HTTP server port (default: 8000)')
    return parser.parse_args()


def configure_logging(log_level: int) -> None:
    """Configure logging with thread names for better debugging."""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(threadName)-15s - %(levelname)-8s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    args = get_args()
    log_level = get_log_level(args.verbose)
    configure_logging(log_level)

    # Quick SOA check mode if --zone and at least one --ns provided
    if args.zone and args.nameservers:
        zone = args.zone
        # Ensure zone ends with a dot for absolute queries
        if not zone.endswith('.'):
            zone = zone + '.'
        logging.info("Checking SOA serial for %s on %d nameserver(s)...", zone, len(args.nameservers))
        for ns in args.nameservers:
            serial = DNSChecker.resolve_soa_serial(zone, ns, port=args.port, timeout=args.timeout, tcp=args.tcp)
            if serial is None:
                print("%s\tNO_ANSWER" % ns)
            else:
                print("%s\t%s" % (ns, serial))
        return

    logging.info("Starting Prometheus metrics server on port %d...", args.metrics_port)
    start_http_server(args.metrics_port)

    logging.info("Starting systemd journal reader in background thread...")
    zone_manager = ZoneManager.load_from_file(args.config_file)
    journal_reader = JournalReader(zone_manager)

    # Start metrics updater thread
    zone_manager.start_metrics_updater()

    journal_thread = threading.Thread(
        target=journal_reader.run,
        name="journal-reader",
        daemon=True,
    )
    journal_thread.start()

    # Keep the main thread alive while background threads run
    try:
        journal_thread.join()
    except KeyboardInterrupt:
        logging.info("Shutting down on user interrupt...")


if __name__ == "__main__":
    main()
