"""Pydantic models for proxy checking."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

ProxyProtocol = Literal["http", "https", "socks4", "socks5"]

PROXY_PROTOCOLS: List[ProxyProtocol] = ["http", "https", "socks4", "socks5"]


class ProxyBulkRequest(BaseModel):
    proxies: List[str] = Field(..., min_length=1, description="List of proxies in ip:port format")

    @field_validator("proxies", mode="before")
    @classmethod
    def validate_proxy_strings(cls, values: list) -> list:
        for entry in values:
            if not isinstance(entry, str) or ":" not in entry:
                raise ValueError(f"invalid proxy format {entry!r}: expected ip:port")
            ip, _, port_str = entry.rpartition(":")
            if not ip:
                raise ValueError(f"missing ip in {entry!r}")
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"invalid port in {entry!r}: {port_str!r} is not an integer")
            if not (1 <= port <= 65535):
                raise ValueError(f"invalid port in {entry!r}: {port} is out of range 1-65535")
        return values


class ProxyProtocolResult(BaseModel):
    """Result of checking a single protocol against a proxy."""

    protocol: ProxyProtocol
    working: bool
    response_time_ms: Optional[float] = None
    egress_ip: Optional[str] = None
    """Egress IP reported by httpbin.org/ip when the probe succeeded."""
    error: Optional[str] = None


class ProxyCheckResponse(BaseModel):
    """Aggregated check result for one proxy across all protocols."""

    ip: str
    port: int
    is_open: bool
    """True if at least one protocol succeeded."""

    protocols: List[ProxyProtocolResult]
    """Per-protocol results."""
