"""URL service for Project Argus API"""

import time

import httpx

from ..models.url_models import URLHeadersResponse, URLStatusResponse


class URLService:
    def __init__(self):
        self.timeout = httpx.Timeout(10.0)

    async def check_status(self, url: str) -> URLStatusResponse:
        """Check the status of a URL"""
        try:
            start_time = time.time()
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                response_time = (time.time() - start_time) * 1000

                return URLStatusResponse(
                    url=url,
                    status_code=response.status_code,
                    is_reachable=response.status_code < 400,
                    response_time_ms=round(response_time, 2),
                )
        except Exception as e:
            return URLStatusResponse(
                url=url,
                status_code=0,
                is_reachable=False,
                response_time_ms=0,
                error=str(e),
            )

    async def get_headers(self, url: str) -> URLHeadersResponse:
        """Fetch the headers of a URL"""
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.head(url)
            return URLHeadersResponse(
                url=url,
                headers=dict(response.headers),
                status_code=response.status_code,
            )
