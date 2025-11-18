import logging
import socket
from typing import Optional

import dns.resolver  # type: ignore[import-untyped]
import dns.exception  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


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
        except (
            dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers
        ) as e:
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
            logger.error(
                "Failed to parse SOA serial for %s from %s: %s", zone, nameserver, e
            )
            return None
