"""Unit tests for URLService.check_status redirect handling and get_headers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from project_argus.services.url_service import MAX_REDIRECTS, URLService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(status: int, location: str | None = None) -> MagicMock:
    """Build a minimal fake httpx.Response."""
    r = MagicMock()
    r.status_code = status
    headers: dict[str, str] = {}
    if location is not None:
        headers["location"] = location
    r.headers = headers
    return r


def _make_client(*responses: MagicMock) -> MagicMock:
    """
    Return a mock async context manager whose .get() side_effect yields
    each response in order, then raises StopAsyncIteration if called again.
    """
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=list(responses))
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCheckStatusNoRedirect:
    """Direct 200 — no redirect at all."""

    async def test_status_code_is_final(self):
        cm = _make_client(_resp(200))
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://example.com")

        assert result.status_code == 200
        assert result.is_reachable is True
        assert result.redirect_count == 0
        assert result.redirect_chain == []
        assert result.redirect_loop is False
        assert result.redirect_limit_reached is False
        assert result.final_url is None  # same as input → omitted

    async def test_404_not_reachable(self):
        cm = _make_client(_resp(404))
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://example.com/missing")

        assert result.status_code == 404
        assert result.is_reachable is False
        assert result.redirect_count == 0


@pytest.mark.asyncio
class TestCheckStatusSingleRedirect:
    """301 → 200 — one redirect hop."""

    async def test_follows_redirect(self):
        cm = _make_client(
            _resp(301, location="https://www.example.com"),
            _resp(200),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://example.com")

        assert result.status_code == 200
        assert result.is_reachable is True
        assert result.redirect_count == 1
        assert result.final_url == "https://www.example.com"

    async def test_chain_contains_both_hops(self):
        cm = _make_client(
            _resp(301, location="https://www.example.com"),
            _resp(200),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://example.com")

        assert len(result.redirect_chain) == 2
        assert result.redirect_chain[0].url == "https://example.com"
        assert result.redirect_chain[0].status_code == 301
        assert result.redirect_chain[0].location == "https://www.example.com"
        assert result.redirect_chain[1].url == "https://www.example.com"
        assert result.redirect_chain[1].status_code == 200
        assert result.redirect_chain[1].location is None

    async def test_relative_location_resolved(self):
        """A relative Location like /new-path should be resolved against the base."""
        cm = _make_client(
            _resp(302, location="/new-path"),
            _resp(200),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://example.com/old")

        assert result.final_url == "https://example.com/new-path"
        assert result.redirect_count == 1


@pytest.mark.asyncio
class TestCheckStatusMultiHop:
    """A → B → C — two redirects, three hops."""

    async def test_full_chain_recorded(self):
        cm = _make_client(
            _resp(301, location="https://b.example.com"),
            _resp(302, location="https://c.example.com"),
            _resp(200),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        assert result.redirect_count == 2
        assert result.status_code == 200
        assert result.final_url == "https://c.example.com"
        urls = [h.url for h in result.redirect_chain]
        assert urls == [
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com",
        ]

    async def test_all_redirect_codes_followed(self):
        """307 and 308 are also redirect codes and should be followed."""
        cm = _make_client(
            _resp(307, location="https://b.example.com"),
            _resp(308, location="https://c.example.com"),
            _resp(200),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        assert result.redirect_count == 2
        assert result.status_code == 200


@pytest.mark.asyncio
class TestCheckStatusRedirectLoop:
    """A → B → A (loop)."""

    async def test_loop_detected(self):
        cm = _make_client(
            _resp(301, location="https://b.example.com"),
            _resp(302, location="https://a.example.com"),  # back to A
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        assert result.redirect_loop is True
        assert result.redirect_limit_reached is False

    async def test_loop_stops_immediately(self):
        """Once the loop is detected no further requests should be attempted."""
        cm = _make_client(
            _resp(301, location="https://b.example.com"),
            _resp(302, location="https://a.example.com"),
            # A third response here would mean the guard didn't fire
            _resp(200),
        )
        with patch(
            "project_argus.services.url_service.httpx.AsyncClient", return_value=cm
        ) as patched:
            result = await URLService().check_status("https://a.example.com")

        # Only 2 real HTTP calls should have been made
        assert patched.return_value.__aenter__.return_value.get.call_count == 2
        assert result.redirect_loop is True

    async def test_loop_chain_includes_repeated_url(self):
        """The chain should record the revisited URL as the last entry."""
        cm = _make_client(
            _resp(301, location="https://b.example.com"),
            _resp(302, location="https://a.example.com"),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        last = result.redirect_chain[-1]
        assert last.url == "https://a.example.com"
        assert last.status_code == 0  # sentinel — no request was made

    async def test_self_redirect_loop(self):
        """A → A (immediate self-redirect)."""
        cm = _make_client(
            _resp(301, location="https://a.example.com"),
        )
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        assert result.redirect_loop is True
        assert result.redirect_count == 1


@pytest.mark.asyncio
class TestCheckStatusRedirectLimit:
    """Hit MAX_REDIRECTS without a loop."""

    async def _build_chain_client(self, length: int) -> MagicMock:
        """Build a mock that returns `length` redirects pointing to distinct URLs."""
        responses = []
        for i in range(length):
            responses.append(_resp(301, location=f"https://hop{i + 1}.example.com"))
        # one final 200 that should never be reached if limit fires first
        responses.append(_resp(200))
        return _make_client(*responses)

    async def test_limit_fires_at_max(self):
        cm = await self._build_chain_client(MAX_REDIRECTS)
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://start.example.com")

        assert result.redirect_limit_reached is True
        assert result.redirect_loop is False

    async def test_limit_stops_before_final_200(self):
        """The 200 after MAX_REDIRECTS hops should never be fetched."""
        cm = await self._build_chain_client(MAX_REDIRECTS)
        with patch(
            "project_argus.services.url_service.httpx.AsyncClient", return_value=cm
        ) as patched:
            await URLService().check_status("https://start.example.com")

        assert patched.return_value.__aenter__.return_value.get.call_count == MAX_REDIRECTS

    async def test_chain_length_at_limit(self):
        cm = await self._build_chain_client(MAX_REDIRECTS)
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://start.example.com")

        assert len(result.redirect_chain) == MAX_REDIRECTS

    async def test_below_limit_not_flagged(self):
        """MAX_REDIRECTS - 1 hops should complete normally."""
        cm = await self._build_chain_client(MAX_REDIRECTS - 1)
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://start.example.com")

        assert result.redirect_limit_reached is False
        assert result.status_code == 200


@pytest.mark.asyncio
class TestCheckStatusNetworkError:
    """Network-level failures should return a structured error response."""

    async def test_connection_error(self):
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
        cm.__aexit__ = AsyncMock(return_value=False)
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://unreachable.example.com")

        assert result.status_code == 0
        assert result.is_reachable is False
        assert result.error is not None
        assert "Connection refused" in result.error

    async def test_error_mid_chain(self):
        """An error after one redirect should still record the partial chain."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _resp(301, location="https://b.example.com"),
                Exception("Timeout"),
            ]
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://a.example.com")

        assert result.status_code == 0
        assert result.is_reachable is False
        assert result.error is not None
        # The first hop (301) should still be in the chain
        assert len(result.redirect_chain) == 1
        assert result.redirect_chain[0].status_code == 301


@pytest.mark.asyncio
class TestCheckStatusClientSideRedirect:
    """Client-side redirects via meta-refresh or JS location."""

    def _resp_html(self, status: int, html: str, content_type: str = "text/html") -> MagicMock:
        r = MagicMock()
        r.status_code = status
        r.headers = {"content-type": content_type}
        r.text = html
        return r

    async def test_meta_refresh_followed(self):
        """A 200 page with a meta-refresh should be followed as a client redirect."""
        html_redirect = (
            '<html><head><meta http-equiv="refresh" content="0; url=https://dest.example.com">'
            "</head></html>"
        )
        final_resp = MagicMock()
        final_resp.status_code = 200
        final_resp.headers = {"content-type": "text/html"}
        final_resp.text = "<html><body>Done</body></html>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                self._resp_html(200, html_redirect),
                final_resp,
            ]
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://src.example.com")

        assert result.final_url == "https://dest.example.com"
        assert result.status_code == 200
        # The chain should show at least 2 hops
        assert len(result.redirect_chain) >= 2

    async def test_non_html_content_not_parsed(self):
        """Binary/JSON responses should not attempt client-side redirect extraction."""
        r = MagicMock()
        r.status_code = 200
        r.headers = {"content-type": "application/json"}
        r.text = '{"key": "value"}'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=r)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://api.example.com")

        # Should stop immediately — no client redirect parsed
        assert result.status_code == 200
        assert result.redirect_count == 0

    async def test_client_redirect_to_already_seen_url_stops(self):
        """If the client-side redirect points to an already-visited URL, we stop."""
        seen_html = (
            '<html><head><meta http-equiv="refresh" content="0; url=https://src.example.com">'
            "</head></html>"
        )
        r = self._resp_html(200, seen_html)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=r)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().check_status("https://src.example.com")

        # Should stop — the meta-refresh URL is the same as the source
        assert result.status_code == 200


@pytest.mark.asyncio
class TestGetHeaders:
    """Tests for URLService.get_headers()"""

    async def test_returns_headers_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html", "server": "nginx"}

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().get_headers("https://example.com")

        assert result.url == "https://example.com"
        assert result.status_code == 200
        assert result.headers["content-type"] == "text/html"
        assert result.headers["server"] == "nginx"

    async def test_uses_head_method(self):
        """Verify that get_headers uses the HEAD method (not GET)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            await URLService().get_headers("https://example.com")

        mock_client.head.assert_called_once_with("https://example.com")

    async def test_headers_dict_conversion(self):
        """Response headers should be converted to a plain dict."""
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {"location": "https://www.example.com"}

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("project_argus.services.url_service.httpx.AsyncClient", return_value=cm):
            result = await URLService().get_headers("https://example.com")

        assert isinstance(result.headers, dict)
        assert result.status_code == 301
