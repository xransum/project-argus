"""Shared HTTP utilities for outbound requests."""

import re
import random
from datetime import datetime
from typing import Optional, Tuple

from bs4 import BeautifulSoup

NOW = datetime.utcnow()

USER_AGENT_LIST = [
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/48.0.2564.116 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML,"
        " like Gecko) Version/13.1.1 Safari/605.1.15"
    ),
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/%s Firefox/77.0"
    % NOW.strftime("%Y%m%d"),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/83.0.4103.97 Safari/537.36"
    ),
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/%s Firefox/77.0"
    % NOW.strftime("%Y%m%d"),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like"
        " Gecko) Chrome/83.0.4103.97 Safari/537.36"
    ),
]


def random_ua() -> str:
    """Return a random user agent string from the pool."""
    return random.choice(USER_AGENT_LIST)


DEFAULT_USER_AGENT = random_ua()

DEFAULT_REQUEST_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.8",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "User-Agent": DEFAULT_USER_AGENT,
}


# ---------------------------------------------------------------------------
# Client-side redirect detection
# ---------------------------------------------------------------------------

# Matches: window.location = "url", window.location.href = "url",
#          window.location.replace("url"), location.href = "url", etc.
_JS_LOCATION_RE = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]"""
    r"""|(?:window\.)?location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)


def _extract_meta_refresh(soup: BeautifulSoup) -> Optional[str]:
    """Return the URL from a <meta http-equiv="refresh"> tag, or None."""
    tag = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
    if tag is None:
        return None
    content = tag.get("content", "")
    parts = re.split(r"url=", content, maxsplit=1, flags=re.IGNORECASE)
    if len(parts) < 2:
        return None
    url = re.sub(r"""[\"']""", "", parts[1]).strip()
    return url or None


def _extract_js_location(soup: BeautifulSoup) -> Optional[str]:
    """Return the first JS window.location / location.href redirect URL, or None."""
    for script in soup.find_all("script"):
        text = script.get_text() or ""
        m = _JS_LOCATION_RE.search(text)
        if m:
            return m.group(1) or m.group(2)
    return None


def extract_client_redirect(html: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse *html* and return ``(url, redirect_type)`` for the first
    client-side redirect found, or ``(None, None)`` if there is none.

    *redirect_type* is one of ``"meta-refresh"`` or ``"js-location"``.
    """
    soup = BeautifulSoup(html, "lxml")

    url = _extract_meta_refresh(soup)
    if url:
        return url, "meta-refresh"

    url = _extract_js_location(soup)
    if url:
        return url, "js-location"

    return None, None
