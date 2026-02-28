"""URL models for Project Argus API"""

from typing import Dict, List, Optional

from pydantic import BaseModel


class RedirectHop(BaseModel):
    """A single hop in a redirect chain."""

    url: str
    status_code: int
    location: Optional[str] = None
    redirect_type: Optional[str] = None
    """How the redirect was triggered: 'http' (3xx), 'meta-refresh', or 'js-location'."""


class URLStatusResponse(BaseModel):
    url: str
    """The original URL that was checked."""

    final_url: Optional[str] = None
    """The URL reached after following all redirects (None if unreachable)."""

    status_code: int
    """HTTP status code of the *final* response (0 on network error)."""

    is_reachable: bool
    response_time_ms: float

    redirect_count: int = 0
    """Number of redirects followed."""

    redirect_chain: List[RedirectHop] = []
    """Ordered list of every redirect hop (empty when there are none)."""

    redirect_loop: bool = False
    """True when a URL appeared more than once in the chain (loop detected)."""

    redirect_limit_reached: bool = False
    """True when the redirect cap was hit before reaching a non-redirect response."""

    error: Optional[str] = None


class URLHeadersResponse(BaseModel):
    url: str
    headers: Dict[str, str]
    status_code: int
