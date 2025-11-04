import logging
import select

from systemd.journal import APPEND, LOG_INFO, Reader  # type: ignore[import-untyped]

from .zone import ZoneManager

logger = logging.getLogger(__name__)


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
                message = entry.get('MESSAGE', '')
                if message.startswith(self.pattern):
                    logger.debug(f"Matched entry: {message}")
                    try:
                        zone_config = self.zone_manager.parse_zone_info(entry)
                    except ValueError as error:
                        logger.error(f"Error parsing zone info: {error}")
                        continue
                    logger.info(f"Extracted ZoneConfig: {zone_config}")
                    self.zone_manager.start_propagation_check(zone_config)
