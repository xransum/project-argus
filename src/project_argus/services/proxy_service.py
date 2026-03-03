"""Proxy checking service — tests HTTP, HTTPS, SOCKS4, and SOCKS5 proxies."""

import json
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

# Patterns that indicate an intercepting login/auth wall rather than a real
# proxy response.  Checked case-insensitively against the response body text.
_AUTH_PATTERNS = [
    "login",
    "sign in",
    "sign-in",
    "unauthorized",
    "unauthenticated",
    "authentication required",
    "please authenticate",
    "access denied",
    "forbidden",
    "captcha",
    "credentials",
    "password",
]


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

    Validation logic:
    - If the response body is valid JSON with ``"origin" == ip`` → working.
    - If ``"origin"`` is present but doesn't match → ip mismatch (closed).
    - If the body is not JSON and contains auth/login patterns → restricted.
    - Anything else → unexpected content (closed).
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

            if response.status_code >= 500:
                return ProxyProtocolResult(
                    protocol=protocol,
                    working=False,
                    error=f"HTTP {response.status_code}",
                )

            # Validate against expected httpbin JSON shape.
            try:
                body = json.loads(response.text)
                origin = body.get("origin")
                if origin is None:
                    return ProxyProtocolResult(
                        protocol=protocol,
                        working=False,
                        error="unexpected response body",
                    )
                if origin != ip:
                    return ProxyProtocolResult(
                        protocol=protocol,
                        working=False,
                        error=f"ip mismatch: got {origin}",
                    )
                return ProxyProtocolResult(
                    protocol=protocol,
                    working=True,
                    response_time_ms=round(elapsed_ms, 2),
                )
            except (json.JSONDecodeError, ValueError):
                body_lower = response.text.lower()
                for pattern in _AUTH_PATTERNS:
                    if pattern in body_lower:
                        return ProxyProtocolResult(
                            protocol=protocol,
                            working=False,
                            error=f"restricted: {pattern}",
                        )
                return ProxyProtocolResult(
                    protocol=protocol,
                    working=False,
                    error="unexpected content",
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
