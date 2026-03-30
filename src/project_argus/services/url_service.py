"""URL service for Project Argus API"""

import asyncio
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from ..models.url_models import RedirectHop, URLHeadersResponse, URLStatusResponse
from ..utils.http import DEFAULT_REQUEST_HEADERS, extract_client_redirect

# Maximum number of redirects to follow before giving up.
MAX_REDIRECTS = 10

# Redirect status codes we actively chase.
REDIRECT_CODES = {301, 302, 303, 307, 308}
URL_PROBE_CEILING = 10.0


def _resolve_location(base_url: str, location: str) -> str:
    """Turn a (possibly relative) Location header into an absolute URL."""
    if urlparse(location).scheme:
        return location
    return urljoin(base_url, location)


class URLService:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(10.0)

    async def check_status(self, url: str) -> URLStatusResponse:
        """Check the HTTP status of a URL, manually following redirects.

        Builds a full redirect chain and detects:
        - redirect loops  (same URL seen twice)
        - redirect limit  (more than MAX_REDIRECTS hops)
        """
        start_time = time.time()
        chain: list[RedirectHop] = []
        seen_urls: set[str] = set()
        redirect_loop = False
        redirect_limit_reached = False
        current_url = url
        final_url: Optional[str] = None
        final_status = 0

        async def _fetch(client: httpx.AsyncClient, target_url: str) -> httpx.Response:
            return await client.get(target_url)

        try:
            # follow_redirects=False so we can intercept every hop ourselves
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,
                headers=DEFAULT_REQUEST_HEADERS,
            ) as client:
                while True:
                    # --- loop guard ---
                    if current_url in seen_urls:
                        redirect_loop = True
                        chain.append(
                            RedirectHop(
                                url=current_url,
                                status_code=0,
                                location=None,
                            )
                        )
                        break

                    # --- cap guard ---
                    if len(chain) >= MAX_REDIRECTS:
                        redirect_limit_reached = True
                        break

                    seen_urls.add(current_url)
                    response = await asyncio.wait_for(
                        _fetch(client, current_url),
                        timeout=URL_PROBE_CEILING,
                    )
                    location = response.headers.get("location")

                    chain.append(
                        RedirectHop(
                            url=current_url,
                            status_code=response.status_code,
                            location=location or None,
                        )
                    )

                    if response.status_code in REDIRECT_CODES and location:
                        chain[-1].redirect_type = "http"
                        current_url = _resolve_location(current_url, location)
                    else:
                        content_type = response.headers.get("content-type", "")
                        is_html = "html" in content_type or "plain" in content_type
                        client_url, client_type = (
                            extract_client_redirect(response.text) if is_html else (None, None)
                        )
                        if client_url and client_url not in seen_urls:
                            chain[-1].redirect_type = client_type
                            current_url = _resolve_location(current_url, client_url)
                        else:
                            final_url = current_url
                            final_status = response.status_code
                            break

            response_time = (time.time() - start_time) * 1000

            if final_status == 0 and chain:
                final_url = chain[-1].url
                final_status = chain[-1].status_code

            hops = chain if len(chain) > 1 or redirect_loop or redirect_limit_reached else []
            redirect_count = max(0, len(chain) - 1)

            return URLStatusResponse(
                url=url,
                final_url=final_url if final_url != url else None,
                status_code=final_status,
                is_reachable=0 < final_status < 400,
                response_time_ms=round(response_time, 2),
                redirect_count=redirect_count,
                redirect_chain=hops,
                redirect_loop=redirect_loop,
                redirect_limit_reached=redirect_limit_reached,
            )
        except Exception as exc:
            response_time = (time.time() - start_time) * 1000
            error_text = str(exc) or "request timed out"
            return URLStatusResponse(
                url=url,
                final_url=None,
                status_code=0,
                is_reachable=False,
                response_time_ms=round(response_time, 2),
                redirect_count=len(chain),
                redirect_chain=chain,
                redirect_loop=redirect_loop,
                redirect_limit_reached=redirect_limit_reached,
                error=error_text,
            )

    async def get_headers(self, url: str) -> URLHeadersResponse:
        """Fetch the headers of a URL"""

        async def _run_headers() -> URLHeadersResponse:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers=DEFAULT_REQUEST_HEADERS,
            ) as client:
                response = await client.head(url)
                return URLHeadersResponse(
                    url=url,
                    headers=dict(response.headers),
                    status_code=response.status_code,
                )

        return await asyncio.wait_for(_run_headers(), timeout=URL_PROBE_CEILING)
