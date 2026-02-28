"""Unit tests for utils/http.py — client-side redirect extraction utilities."""

from bs4 import BeautifulSoup

from project_argus.utils.http import (
    DEFAULT_REQUEST_HEADERS,
    DEFAULT_USER_AGENT,
    USER_AGENT_LIST,
    _extract_js_location,
    _extract_meta_refresh,
    extract_client_redirect,
    random_ua,
)

# ---------------------------------------------------------------------------
# random_ua
# ---------------------------------------------------------------------------


class TestRandomUA:
    def test_returns_string(self):
        ua = random_ua()
        assert isinstance(ua, str)

    def test_returns_value_from_list(self):
        ua = random_ua()
        assert ua in USER_AGENT_LIST

    def test_default_user_agent_in_list(self):
        assert DEFAULT_USER_AGENT in USER_AGENT_LIST

    def test_default_request_headers_has_user_agent(self):
        assert "User-Agent" in DEFAULT_REQUEST_HEADERS
        assert DEFAULT_REQUEST_HEADERS["User-Agent"] == DEFAULT_USER_AGENT


# ---------------------------------------------------------------------------
# _extract_meta_refresh
# ---------------------------------------------------------------------------


class TestExtractMetaRefresh:
    def _soup(self, html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "lxml")

    def test_no_meta_tag_returns_none(self):
        soup = self._soup("<html><head></head><body>Hello</body></html>")
        assert _extract_meta_refresh(soup) is None

    def test_meta_refresh_with_url(self):
        soup = self._soup(
            '<html><head><meta http-equiv="refresh" content="0; url=https://example.com"></head></html>'
        )
        result = _extract_meta_refresh(soup)
        assert result == "https://example.com"

    def test_meta_refresh_uppercase_http_equiv(self):
        soup = self._soup(
            '<html><head><meta http-equiv="Refresh" content="5; URL=https://example.com/page"></head></html>'
        )
        result = _extract_meta_refresh(soup)
        assert result == "https://example.com/page"

    def test_meta_refresh_with_quotes_around_url(self):
        soup = self._soup(
            '<html><head><meta http-equiv="refresh" content=\'0; url="https://example.com"\''
            "></head></html>"
        )
        result = _extract_meta_refresh(soup)
        assert result == "https://example.com"

    def test_meta_refresh_no_url_part_returns_none(self):
        soup = self._soup('<html><head><meta http-equiv="refresh" content="30"></head></html>')
        result = _extract_meta_refresh(soup)
        assert result is None

    def test_meta_refresh_empty_url_returns_none(self):
        soup = self._soup('<html><head><meta http-equiv="refresh" content="0; url="></head></html>')
        result = _extract_meta_refresh(soup)
        assert result is None

    def test_meta_refresh_no_content_attr(self):
        soup = self._soup('<html><head><meta http-equiv="refresh"></head></html>')
        result = _extract_meta_refresh(soup)
        assert result is None


# ---------------------------------------------------------------------------
# _extract_js_location
# ---------------------------------------------------------------------------


class TestExtractJSLocation:
    def _soup(self, html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "lxml")

    def test_no_script_returns_none(self):
        soup = self._soup("<html><body>No scripts here</body></html>")
        assert _extract_js_location(soup) is None

    def test_script_without_redirect_returns_none(self):
        soup = self._soup("<html><body><script>var x = 1; console.log(x);</script></body></html>")
        assert _extract_js_location(soup) is None

    def test_window_location_assignment(self):
        soup = self._soup(
            "<html><body><script>window.location = 'https://example.com';</script></body></html>"
        )
        result = _extract_js_location(soup)
        assert result == "https://example.com"

    def test_window_location_href_assignment(self):
        soup = self._soup(
            '<html><body><script>window.location.href = "https://redirect.example.com";</script></body></html>'
        )
        result = _extract_js_location(soup)
        assert result == "https://redirect.example.com"

    def test_location_replace(self):
        soup = self._soup(
            "<html><body><script>window.location.replace('https://new.example.com');</script></body></html>"
        )
        result = _extract_js_location(soup)
        assert result == "https://new.example.com"

    def test_location_href_without_window(self):
        soup = self._soup(
            "<html><body><script>location.href = 'https://target.com';</script></body></html>"
        )
        result = _extract_js_location(soup)
        assert result == "https://target.com"

    def test_empty_script_returns_none(self):
        soup = self._soup("<html><body><script></script></body></html>")
        assert _extract_js_location(soup) is None

    def test_multiple_scripts_first_match_returned(self):
        soup = self._soup(
            "<html><body>"
            "<script>var x = 1;</script>"
            "<script>window.location = 'https://first.example.com';</script>"
            "<script>window.location = 'https://second.example.com';</script>"
            "</body></html>"
        )
        result = _extract_js_location(soup)
        assert result == "https://first.example.com"


# ---------------------------------------------------------------------------
# extract_client_redirect
# ---------------------------------------------------------------------------


class TestExtractClientRedirect:
    def test_no_redirect_returns_none_none(self):
        html = "<html><head></head><body>Plain page</body></html>"
        url, rtype = extract_client_redirect(html)
        assert url is None
        assert rtype is None

    def test_meta_refresh_detected(self):
        html = (
            '<html><head><meta http-equiv="refresh" content="0; url=https://example.com"></head>'
            "<body></body></html>"
        )
        url, rtype = extract_client_redirect(html)
        assert url == "https://example.com"
        assert rtype == "meta-refresh"

    def test_js_location_detected(self):
        html = (
            "<html><head></head><body>"
            "<script>window.location = 'https://js-redirect.example.com';</script>"
            "</body></html>"
        )
        url, rtype = extract_client_redirect(html)
        assert url == "https://js-redirect.example.com"
        assert rtype == "js-location"

    def test_meta_refresh_takes_priority_over_js(self):
        """If both meta refresh and JS redirect exist, meta-refresh wins."""
        html = (
            '<html><head><meta http-equiv="refresh" content="0; url=https://meta.example.com"></head>'
            "<body><script>window.location = 'https://js.example.com';</script></body></html>"
        )
        url, rtype = extract_client_redirect(html)
        assert url == "https://meta.example.com"
        assert rtype == "meta-refresh"

    def test_empty_html_returns_none_none(self):
        url, rtype = extract_client_redirect("")
        assert url is None
        assert rtype is None

    def test_plain_text_no_redirect(self):
        url, rtype = extract_client_redirect("Just plain text, no HTML")
        assert url is None
        assert rtype is None
