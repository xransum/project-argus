"""Proxy checking service — tests HTTP, HTTPS, SOCKS4, and SOCKS5 proxies."""

import time
from typing import List

import httpx

from ..models.proxy_models import (
    PROXY_PROTOCOLS,
    ProxyCheckResponse,
    ProxyProtocol,
    ProxyProtocolResult,
)

# The URL we probe *through* the proxy to verify it works.
# httpbin returns the caller's IP in JSON — lightweight and reliable.
_PROBE_URL = "http://httpbin.org/ip"

# Per-protocol connect + read timeout (seconds).
_TIMEOUT = 10.0


def _proxy_url(protocol: ProxyProtocol, ip: str, port: int) -> str:
    """Build the proxy URL string for httpx."""
    # httpx accepts socks4:// and socks5:// natively when socksio is installed.
    return f"{protocol}://{ip}:{port}"


async def _check_protocol(
    protocol: ProxyProtocol,
    ip: str,
    port: int,
) -> ProxyProtocolResult:
    """Attempt a single request through the proxy using *protocol*.

    Returns a :class:`ProxyProtocolResult` with timing on success or an error
    message on failure.
    """
    proxy_url = _proxy_url(protocol, ip, port)
    # httpx 0.27+ removed the `proxies` kwarg; use the `mounts` API instead.
    mounts = {
        "http://": httpx.AsyncHTTPTransport(proxy=proxy_url),
        "https://": httpx.AsyncHTTPTransport(proxy=proxy_url),
    }

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            mounts=mounts,
            timeout=_TIMEOUT,
            follow_redirects=True,
            verify=False,  # skip cert verification — we're just probing reachability
        ) as client:
            response = await client.get(_PROBE_URL)
            elapsed_ms = (time.perf_counter() - start) * 1000
            if response.status_code < 500:
                return ProxyProtocolResult(
                    protocol=protocol,
                    working=True,
                    response_time_ms=round(elapsed_ms, 2),
                )
            return ProxyProtocolResult(
                protocol=protocol,
                working=False,
                error=f"HTTP {response.status_code}",
            )
    except Exception as exc:
        return ProxyProtocolResult(
            protocol=protocol,
            working=False,
            error=str(exc),
        )


class ProxyService:
    """Check whether a proxy is reachable via HTTP, HTTPS, SOCKS4, and SOCKS5."""

    async def check(self, ip: str, port: int) -> ProxyCheckResponse:
        """Run all four protocol probes against *ip*:*port* concurrently.

        Returns a :class:`ProxyCheckResponse` summarising per-protocol results.
        """
        import asyncio

        results: List[ProxyProtocolResult] = await asyncio.gather(
            *[_check_protocol(proto, ip, port) for proto in PROXY_PROTOCOLS]
        )

        return ProxyCheckResponse(
            ip=ip,
            port=port,
            is_open=any(r.working for r in results),
            protocols=list(results),
        )
