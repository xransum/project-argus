"""Unit tests for IPService — all six service methods."""

import socket
from unittest.mock import patch

import pytest

from project_argus.services.ip_service import IPService


@pytest.mark.asyncio
class TestIPServiceGetIPInfo:
    """Tests for IPService.get_ip_info()"""

    async def test_returns_ip_info_response_with_hostname(self):
        with patch("socket.gethostbyaddr", return_value=("reverse.example.com", [], ["8.8.8.8"])):
            result = await IPService().get_ip_info("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.hostname == "reverse.example.com"
        assert result.asn == "Unknown"
        assert result.organization == "Unknown"
        assert result.isp == "Unknown"

    async def test_returns_none_hostname_on_herror(self):
        with patch("socket.gethostbyaddr", side_effect=socket.herror):
            result = await IPService().get_ip_info("1.2.3.4")

        assert result.ip == "1.2.3.4"
        assert result.hostname is None

    async def test_returns_none_hostname_on_gaierror(self):
        with patch("socket.gethostbyaddr", side_effect=socket.gaierror):
            result = await IPService().get_ip_info("1.2.3.4")

        assert result.hostname is None

    async def test_returns_none_hostname_on_os_error(self):
        with patch("socket.gethostbyaddr", side_effect=OSError):
            result = await IPService().get_ip_info("1.2.3.4")

        assert result.hostname is None


@pytest.mark.asyncio
class TestIPServiceGetDNSRecords:
    """Tests for IPService.get_dns_records()"""

    async def test_successful_reverse_dns(self):
        with patch("socket.gethostbyaddr", return_value=("dns.google", [], ["8.8.8.8"])):
            result = await IPService().get_dns_records("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.hostname == "dns.google"

    async def test_herror_returns_none_hostname(self):
        with patch("socket.gethostbyaddr", side_effect=socket.herror):
            result = await IPService().get_dns_records("1.2.3.4")

        assert result.ip == "1.2.3.4"
        assert result.hostname is None

    async def test_gaierror_returns_none_hostname(self):
        with patch("socket.gethostbyaddr", side_effect=socket.gaierror):
            result = await IPService().get_dns_records("1.2.3.4")

        assert result.hostname is None

    async def test_os_error_returns_none_hostname(self):
        with patch("socket.gethostbyaddr", side_effect=OSError):
            result = await IPService().get_dns_records("1.2.3.4")

        assert result.hostname is None


@pytest.mark.asyncio
class TestIPServiceGetGeoIP:
    """Tests for IPService.get_geoip()"""

    async def test_returns_geoip_response(self):
        result = await IPService().get_geoip("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.country == "Unknown"
        assert result.city == "Unknown"
        assert result.latitude == 0.0
        assert result.longitude == 0.0

    async def test_returns_geoip_for_any_ip(self):
        result = await IPService().get_geoip("1.1.1.1")
        assert result.ip == "1.1.1.1"


@pytest.mark.asyncio
class TestIPServiceCheckReputation:
    """Tests for IPService.check_reputation()"""

    async def test_returns_reputation_response(self):
        result = await IPService().check_reputation("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.score == 75
        assert result.is_safe is True
        assert result.categories == []

    async def test_is_safe_flag_true(self):
        result = await IPService().check_reputation("1.1.1.1")
        assert result.is_safe is True


@pytest.mark.asyncio
class TestIPServiceCheckBlacklist:
    """Tests for IPService.check_blacklist()"""

    async def test_returns_blacklist_response(self):
        result = await IPService().check_blacklist("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.is_blacklisted is False
        assert result.blacklists == []

    async def test_not_blacklisted_by_default(self):
        result = await IPService().check_blacklist("1.1.1.1")
        assert result.is_blacklisted is False


@pytest.mark.asyncio
class TestIPServiceGetWHOIS:
    """Tests for IPService.get_whois()"""

    async def test_returns_whois_response(self):
        result = await IPService().get_whois("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.asn == "Unknown"
        assert result.organization == "Unknown"
        assert result.network == "Unknown"

    async def test_returns_whois_for_different_ip(self):
        result = await IPService().get_whois("1.1.1.1")
        assert result.ip == "1.1.1.1"
