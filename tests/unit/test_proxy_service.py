"""Unit tests for services/proxy_service.py"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from project_argus.models.proxy_models import ProxyCheckResponse, ProxyProtocolResult
from project_argus.services.proxy_service import ProxyService, _check_protocol, _proxy_url


class TestProxyUrl:
    def test_http_proxy_url(self):
        assert _proxy_url("http", "1.2.3.4", 8080) == "http://1.2.3.4:8080"

    def test_https_proxy_url(self):
        assert _proxy_url("https", "1.2.3.4", 443) == "https://1.2.3.4:443"

    def test_socks4_proxy_url(self):
        assert _proxy_url("socks4", "1.2.3.4", 1080) == "socks4://1.2.3.4:1080"

    def test_socks5_proxy_url(self):
        assert _proxy_url("socks5", "1.2.3.4", 1080) == "socks5://1.2.3.4:1080"


class TestCheckProtocol:
    @pytest.mark.asyncio
    async def test_returns_working_on_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is True
        assert result.protocol == "http"
        assert result.response_time_ms is not None
        assert result.error is None

    @pytest.mark.asyncio
    async def test_returns_not_working_on_500(self):
        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "HTTP 500"

    @pytest.mark.asyncio
    async def test_returns_not_working_on_exception(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("socks5", "1.2.3.4", 1080)

        assert result.working is False
        assert result.protocol == "socks5"
        assert "Connection refused" in (result.error or "")

    @pytest.mark.asyncio
    async def test_all_protocols_attempted(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        protocols_checked = []

        async def check(proto, ip, port):  # type: ignore[no-untyped-def]
            protocols_checked.append(proto)
            return ProxyProtocolResult(protocol=proto, working=True, response_time_ms=10.0)

        service = ProxyService()
        with patch("project_argus.services.proxy_service._check_protocol", side_effect=check):
            result = await service.check("1.2.3.4", 8080)

        assert set(protocols_checked) == {"http", "https", "socks4", "socks5"}
        assert result.ip == "1.2.3.4"
        assert result.port == 8080


class TestProxyService:
    @pytest.mark.asyncio
    async def test_is_open_true_when_any_protocol_works(self):
        async def check(proto, ip, port):  # type: ignore[no-untyped-def]
            working = proto == "http"
            return ProxyProtocolResult(protocol=proto, working=working)

        service = ProxyService()
        with patch("project_argus.services.proxy_service._check_protocol", side_effect=check):
            result = await service.check("1.2.3.4", 8080)

        assert result.is_open is True

    @pytest.mark.asyncio
    async def test_is_open_false_when_no_protocol_works(self):
        async def check(proto, ip, port):  # type: ignore[no-untyped-def]
            return ProxyProtocolResult(protocol=proto, working=False, error="timeout")

        service = ProxyService()
        with patch("project_argus.services.proxy_service._check_protocol", side_effect=check):
            result = await service.check("1.2.3.4", 9999)

        assert result.is_open is False
        assert all(not r.working for r in result.protocols)

    @pytest.mark.asyncio
    async def test_returns_proxy_check_response(self):
        async def check(proto, ip, port):  # type: ignore[no-untyped-def]
            return ProxyProtocolResult(protocol=proto, working=True, response_time_ms=5.0)

        service = ProxyService()
        with patch("project_argus.services.proxy_service._check_protocol", side_effect=check):
            result = await service.check("8.8.8.8", 3128)

        assert isinstance(result, ProxyCheckResponse)
        assert result.ip == "8.8.8.8"
        assert result.port == 3128
        assert len(result.protocols) == 4

    @pytest.mark.asyncio
    async def test_protocol_results_contain_all_four(self):
        async def check(proto, ip, port):  # type: ignore[no-untyped-def]
            return ProxyProtocolResult(protocol=proto, working=False)

        service = ProxyService()
        with patch("project_argus.services.proxy_service._check_protocol", side_effect=check):
            result = await service.check("1.1.1.1", 80)

        proto_names = {r.protocol for r in result.protocols}
        assert proto_names == {"http", "https", "socks4", "socks5"}
