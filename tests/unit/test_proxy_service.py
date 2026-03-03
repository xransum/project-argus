"""Unit tests for services/proxy_service.py"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from project_argus.models.proxy_models import ProxyCheckResponse, ProxyProtocolResult
from project_argus.services.proxy_service import (
    _AUTH_PATTERNS,
    ProxyService,
    _check_protocol,
    _proxy_url,
)


def _make_mock_client(status_code: int, body: str) -> AsyncMock:
    """Return a mock AsyncClient whose .get() yields a response with the given
    status code and text body."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = body

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


class TestAuthPatterns:
    def test_auth_patterns_is_non_empty_list(self):
        assert isinstance(_AUTH_PATTERNS, list)
        assert len(_AUTH_PATTERNS) > 0

    def test_auth_patterns_are_lowercase(self):
        for pattern in _AUTH_PATTERNS:
            assert pattern == pattern.lower(), f"Pattern {pattern!r} is not lowercase"


class TestCheckProtocol:
    # ------------------------------------------------------------------
    # IP match — the happy path
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_ip_match_returns_working(self):
        body = json.dumps({"origin": "1.2.3.4"})
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is True
        assert result.protocol == "http"
        assert result.response_time_ms is not None
        assert result.error is None

    # ------------------------------------------------------------------
    # IP mismatch — proxy forwards but origin differs
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_ip_mismatch_returns_not_working(self):
        body = json.dumps({"origin": "9.9.9.9"})
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error is not None
        assert "ip mismatch" in result.error
        assert "9.9.9.9" in result.error

    # ------------------------------------------------------------------
    # Valid JSON but missing "origin" key
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_no_origin_key_returns_not_working(self):
        body = json.dumps({"foo": "bar"})
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "unexpected response body"

    # ------------------------------------------------------------------
    # Non-JSON body — auth/login patterns
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_auth_pattern_login_detected(self):
        body = "<html><body><h1>Please Login</h1></body></html>"
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error is not None
        assert result.error.startswith("restricted:")

    @pytest.mark.asyncio
    async def test_auth_pattern_unauthorized_detected(self):
        body = "<html><body>401 Unauthorized</body></html>"
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("https", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error is not None
        assert result.error.startswith("restricted:")

    @pytest.mark.asyncio
    async def test_auth_pattern_access_denied_detected(self):
        body = "<html><body>Access Denied — please sign in</body></html>"
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("socks5", "1.2.3.4", 1080)

        assert result.working is False
        assert result.error is not None
        assert result.error.startswith("restricted:")

    @pytest.mark.asyncio
    async def test_auth_pattern_captcha_detected(self):
        body = "<html><body>Please complete the captcha to continue</body></html>"
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error is not None
        assert result.error.startswith("restricted:")

    # ------------------------------------------------------------------
    # Non-JSON body — no recognisable pattern
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_non_json_no_pattern_returns_unexpected_content(self):
        body = "<html><body><h1>Welcome to the proxy!</h1></body></html>"
        mock_client = _make_mock_client(200, body)

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "unexpected content"

    # ------------------------------------------------------------------
    # HTTP 5xx
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_returns_not_working_on_500(self):
        mock_client = _make_mock_client(500, "")

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("http", "1.2.3.4", 8080)

        assert result.working is False
        assert result.error == "HTTP 500"

    # ------------------------------------------------------------------
    # Connection / transport exception
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_returns_not_working_on_exception(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

        with patch(
            "project_argus.services.proxy_service.httpx.AsyncClient",
            return_value=mock_client,
        ):
            result = await _check_protocol("socks5", "1.2.3.4", 1080)

        assert result.working is False
        assert result.protocol == "socks5"
        assert "Connection refused" in (result.error or "")

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
