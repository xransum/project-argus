"""Pydantic models for proxy checking."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

ProxyProtocol = Literal["http", "https", "socks4", "socks5"]

PROXY_PROTOCOLS: List[ProxyProtocol] = ["http", "https", "socks4", "socks5"]


class ProxyTarget(BaseModel):
    """A single proxy to be checked."""

    ip: str = Field(..., description="IP address of the proxy server")
    port: int = Field(..., ge=1, le=65535, description="Port number of the proxy server")


class ProxyBulkRequest(BaseModel):
    proxies: List[ProxyTarget] = Field(..., min_length=1, description="List of proxies to check")


class ProxyProtocolResult(BaseModel):
    """Result of checking a single protocol against a proxy."""

    protocol: ProxyProtocol
    working: bool
    response_time_ms: Optional[float] = None
    error: Optional[str] = None


class ProxyCheckResponse(BaseModel):
    """Aggregated check result for one proxy across all protocols."""

    ip: str
    port: int
    is_open: bool
    """True if at least one protocol succeeded."""

    protocols: List[ProxyProtocolResult]
    """Per-protocol results."""
