import socket
from unittest.mock import MagicMock, patch

from propagation_exporter.dns_utils import DNSChecker


class TestGetDnsName:
    def test_returns_dns_name_on_success(self):
        with patch.object(socket, "gethostbyaddr", return_value=("ns1.example.com", [], [])) as pha:
            result = DNSChecker.get_dns_name("192.0.2.1")
            assert result == "ns1.example.com"
            pha.assert_called_once_with("192.0.2.1")

    def test_returns_ip_when_reverse_fails(self):
        with patch.object(socket, "gethostbyaddr", side_effect=socket.herror("not found")):
            assert DNSChecker.get_dns_name("192.0.2.2") == "192.0.2.2"
        with patch.object(socket, "gethostbyaddr", side_effect=socket.gaierror("bad")):
            assert DNSChecker.get_dns_name("192.0.2.3") == "192.0.2.3"


class TestResolveSoaSerial:
    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_success_parses_serial(self, MockResolver: MagicMock):
        resolver = MockResolver.return_value
        # Mock answer object
        answer = MagicMock()
        answer.__len__.return_value = 1
        answer.rrset = True
        record = MagicMock()
        record.serial = 2025010101
        answer.__getitem__.return_value = record
        resolver.query.return_value = answer

        serial = DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10")
        assert serial == 2025010101
        # Ensure resolver configured correctly
        assert resolver.nameservers == ["192.0.2.10"]
        assert resolver.port == 53

    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_no_rrset_or_empty_returns_none(self, MockResolver: MagicMock):
        resolver = MockResolver.return_value
        answer = MagicMock()
        answer.__len__.return_value = 0
        answer.rrset = None
        resolver.query.return_value = answer
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_serial_parse_error_returns_none(self, MockResolver: MagicMock):
        resolver = MockResolver.return_value
        answer = MagicMock()
        answer.__len__.return_value = 1
        answer.rrset = True
        record = MagicMock()
        record.serial = "not-an-int"
        answer.__getitem__.return_value = record
        resolver.query.return_value = answer
    assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_known_dns_errors_return_none(self, MockResolver: MagicMock):
        import propagation_exporter.dns_utils as du
        resolver = MockResolver.return_value

        resolver.query.side_effect = du.dns.exception.Timeout()
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

        resolver.query.side_effect = du.dns.resolver.NXDOMAIN()
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

        resolver.query.side_effect = du.dns.resolver.NoAnswer()
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

        resolver.query.side_effect = du.dns.resolver.NoNameservers()
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_unexpected_dns_exception_returns_none(self, MockResolver: MagicMock):
        import propagation_exporter.dns_utils as du
        resolver = MockResolver.return_value
        resolver.query.side_effect = du.dns.exception.DNSException("boom")
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None

    @patch("propagation_exporter.dns_utils.dns.resolver.Resolver")
    def test_generic_exception_during_serial_parse_returns_none(self, MockResolver: MagicMock):
        """Test that any exception during serial parsing returns None (covers lines 81-85)."""
        resolver = MockResolver.return_value
        answer = MagicMock()
        answer.__len__.return_value = 1
        answer.rrset = True
        # Make answer[0].serial raise an exception
        answer.__getitem__.side_effect = Exception("Unexpected error")
        resolver.query.return_value = answer
        assert DNSChecker.resolve_soa_serial("example.com.", "192.0.2.10") is None
