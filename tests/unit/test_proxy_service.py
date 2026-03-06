"""Unit tests for services/proxy_service.py"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from project_argus.models.proxy_models import ProxyCheckResponse, ProxyProtocolResult
from project_argus.services.proxy_service import (
    ProxyService,
    _check_protocol,
    _parse_egress_ip,
    _proxy_url,
)


def _make_mock_client(status_code: int, origin: str = "") -> AsyncMock:
    """Return a mock AsyncClient whose .get() yields a response with the given
    status code and an httpbin-style JSON body {"origin": origin}."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json = MagicMock(return_value={"origin": origin})

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)
    return mock_client


class TestProxyUrl:
    def test_http_proxy_url(self):
        assert _proxy_url("http", "1.2.3.4", 8080) == "http://1.2.3.4:8080"

    def test_https_proxy_url(self):
        assert _proxy_url("https", "1.2.3.4", 443) == "https://1.2.3.4:443"

    def test_socks4_proxy_url(self):
        assert _proxy_url("socks4", "1.2.3.4", 1080) == "socks4://1.2.3.4:1080"

    def test_socks5_proxy_url(self):
        assert _proxy_url("socks5", "1.2.3.4", 1080) == "socks5://1.2.3.4:1080"


class TestParseEgressIp:
    def test_single_ip(self):
        assert _parse_egress_ip({"origin": "1.2.3.4"}) == "1.2.3.4"

    def test_multiple_ips_returns_first(self):
        # httpbin may return comma-separated IPs when hops are present
        assert _parse_egress_ip({"origin": "1.2.3.4, 5.6.7.8"}) == "1.2.3.4"

    def test_leading_trailing_whitespace_stripped(self):
        assert _parse_egress_ip({"origin": "  1.2.3.4  "}) == "1.2.3.4"

    def test_missing_origin_key_raises(self):
        with pytest.raises(KeyError):
            _parse_egress_ip({})


class TestCheckProtocol:
    # ------------------------------------------------------------------
    # 200 + valid origin = working, egress_ip stored
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_200_valid_origin_returns_working(self):
        mock_client = _make_mock_client(200, origin="1.2.3.4")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is True
        assert result.protocol == "http"
        assert result.egress_ip == "1.2.3.4"
        assert result.response_time_ms is not None
        assert result.error is None

    @pytest.mark.asyncio
    async def test_200_valid_origin_https(self):
        # https:// proxies previously failed with SSL cert errors on the proxy
        # tunnel leg; now wired via httpcore.AsyncHTTPProxy with proxy_ssl_context
        mock_client = _make_mock_client(200, origin="1.2.3.4")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("https", "1.2.3.4", 443)

        assert result.working is True
        assert result.protocol == "https"
        assert result.egress_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_200_valid_origin_socks5(self):
        mock_client = _make_mock_client(200, origin="1.2.3.4")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("socks5", "1.2.3.4", 1080)

        assert result.working is True
        assert result.protocol == "socks5"
        assert result.egress_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_200_origin_with_multiple_hops_first_stored(self):
        # httpbin may return comma-separated IPs; first token is stored
        mock_client = _make_mock_client(200, origin="1.2.3.4, 9.9.9.9")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is True
        assert result.egress_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_200_different_egress_ip_still_working(self):
        # Pooled/NAT proxies egress from a different IP — still marked working
        mock_client = _make_mock_client(200, origin="9.9.9.9")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is True
        assert result.egress_ip == "9.9.9.9"
        assert result.error is None

    # ------------------------------------------------------------------
    # Non-200 status = not working
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_non_200_returns_not_working(self):
        mock_client = _make_mock_client(403, origin="")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert "403" in (result.error or "")

    @pytest.mark.asyncio
    async def test_500_returns_not_working(self):
        mock_client = _make_mock_client(500, origin="")
        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("https", "1.2.3.4", 8080)

        assert result.working is False
        assert "500" in (result.error or "")

    # ------------------------------------------------------------------
    # JSON parse failure = not working
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_missing_origin_key_returns_not_working(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={})  # no "origin" key

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "invalid response body"

    @pytest.mark.asyncio
    async def test_json_raises_returns_not_working(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(side_effect=ValueError("not json"))

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "invalid response body"

    # ------------------------------------------------------------------
    # Connection / transport exception = not working
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_connection_refused_returns_not_working(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.protocol == "http"
        assert "Connection refused" in (result.error or "")

    @pytest.mark.asyncio
    async def test_timeout_returns_not_working(self):
        import httpx

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("socks5", "1.2.3.4", 1080)

        assert result.working is False
        assert result.protocol == "socks5"

    @pytest.mark.asyncio
    async def test_socks_error_returns_not_working(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception(b"socks4"))

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient", return_value=mock_client
        ):
            result = await _check_protocol("socks4", "1.2.3.4", 1080)

        assert result.working is False
        assert result.protocol == "socks4"

    # ------------------------------------------------------------------
    # All protocols are exercised
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_all_protocols_attempted(self):
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
