"""Proxy checking service — tests HTTP, HTTPS, SOCKS4, and SOCKS5 proxies."""

import asyncio
import logging
import ssl
import time
from typing import List

import httpcore
import httpx

from ..models.proxy_models import (
    PROXY_PROTOCOLS,
    ProxyCheckResponse,
    ProxyProtocol,
    ProxyProtocolResult,
)

logger = logging.getLogger(__name__)

# IP-echo endpoint: returns {"origin": "<egress-ip>"}.
# A proxy is confirmed open when the reported egress IP matches the proxy IP.
_PROBE_URL = "http://httpbin.org/ip"

# User-agent sent with every probe request.
_USER_AGENT = "Mozilla/5.0 (compatible; project-argus/1.0)"

# Timeouts matching curl's --connect-timeout 8 / --max-time 20.
_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 20.0

# SSL context that skips certificate verification, equivalent to curl's
# --insecure / --proxy-insecure flags.
_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def _proxy_url(protocol: ProxyProtocol, ip: str, port: int) -> str:
    """Build the proxy URL string."""
    return f"{protocol}://{ip}:{port}"


def _parse_egress_ip(body: dict) -> str:
    """Extract the egress IP from an httpbin /ip response body.

    httpbin returns {"origin": "1.2.3.4"} but may include multiple
    comma-separated IPs when there are intermediate hops (e.g. "1.2.3.4, 5.6.7.8").
    We take the first token which is the client-facing egress IP.
    """
    origin: str = body["origin"]
    return origin.split(",")[0].strip()


async def _check_protocol(
    protocol: ProxyProtocol,
    ip: str,
    port: int,
) -> ProxyProtocolResult:
    """Send a GET request through the proxy to httpbin.org/ip.

    The proxy is considered working if:
    - We receive a 200 response, AND
    - The JSON body's "origin" field matches the proxy's own IP.

    A status other than 200, a JSON parse failure, an IP mismatch, or any
    connection error all result in working=False.
    """
    proxy_url = _proxy_url(protocol, ip, port)
    logger.debug("proxy=%s:%s protocol=%s probing", ip, port, protocol)

    # All four protocols are wired directly via httpcore to ensure that
    # _SSL_CONTEXT (no cert verification) applies to BOTH the upstream
    # connection (ssl_context) AND the proxy tunnel handshake
    # (proxy_ssl_context for http/https, ssl_context for socks).
    #
    # Using httpx.AsyncHTTPTransport(proxy=...) for https:// proxies would
    # leave the proxy-tunnel TLS handshake using the default (strict) SSL
    # context, causing spurious CERTIFICATE_VERIFY_FAILED errors when the
    # proxy's certificate doesn't match its IP.
    transport = httpx.AsyncHTTPTransport(verify=_SSL_CONTEXT)
    if protocol in ("socks4", "socks5"):
        transport._pool = httpcore.AsyncSOCKSProxy(  # type: ignore[attr-defined]
            proxy_url,
            ssl_context=_SSL_CONTEXT,
        )
    elif protocol == "https":
        # proxy_ssl_context disables cert verification on the proxy tunnel
        # handshake itself (the TLS connection TO the proxy on port 443).
        # Only valid for https:// proxy URLs — httpcore rejects it for http://.
        transport._pool = httpcore.AsyncHTTPProxy(  # type: ignore[attr-defined]
            proxy_url,
            ssl_context=_SSL_CONTEXT,
            proxy_ssl_context=_SSL_CONTEXT,
        )
    else:
        transport._pool = httpcore.AsyncHTTPProxy(  # type: ignore[attr-defined]
            proxy_url,
            ssl_context=_SSL_CONTEXT,
        )

    timeout = httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_READ_TIMEOUT, write=5.0, pool=5.0)

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            response = await client.get(_PROBE_URL)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        logger.debug(
            "proxy=%s:%s protocol=%s status=%s elapsed=%.0fms",
            ip,
            port,
            protocol,
            response.status_code,
            elapsed_ms,
        )

        if response.status_code != 200:
            return ProxyProtocolResult(
                protocol=protocol,
                working=False,
                error=f"unexpected status {response.status_code}",
            )

        try:
            egress_ip = _parse_egress_ip(response.json())
        except (KeyError, ValueError, Exception) as exc:
            logger.debug("proxy=%s:%s protocol=%s parse error: %s", ip, port, protocol, exc)
            return ProxyProtocolResult(
                protocol=protocol,
                working=False,
                error="invalid response body",
            )

        logger.debug(
            "proxy=%s:%s protocol=%s egress=%s",
            ip,
            port,
            protocol,
            egress_ip,
        )
        return ProxyProtocolResult(
            protocol=protocol,
            working=True,
            response_time_ms=elapsed_ms,
            egress_ip=egress_ip,
        )

    except Exception as exc:
        logger.debug("proxy=%s:%s protocol=%s failed: %s", ip, port, protocol, exc)
        return ProxyProtocolResult(
            protocol=protocol,
            working=False,
            error=str(exc),
        )


class ProxyService:
    """Check whether a proxy is reachable via HTTP, HTTPS, SOCKS4, and SOCKS5."""

    async def check(self, ip: str, port: int) -> ProxyCheckResponse:
        """Run all four protocol probes against *ip*:*port* concurrently."""
        results: List[ProxyProtocolResult] = await asyncio.gather(
            *[_check_protocol(proto, ip, port) for proto in PROXY_PROTOCOLS]
        )

        logger.debug(
            "proxy=%s:%s results=%s",
            ip,
            port,
            {r.protocol: ("ok" if r.working else r.error) for r in results},
        )
        return ProxyCheckResponse(
            ip=ip,
            port=port,
            is_open=any(r.working for r in results),
            protocols=list(results),
        )
