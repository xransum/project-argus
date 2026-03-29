"""Executor routing and job execution helpers."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Iterable, cast

from ...models.domain_models import (
    BlacklistResponse,
    GeoIPResponse,
    ReputationResponse,
    WHOISResponse,
)
from ...models.ip_models import (
    IPBlacklistResponse,
    IPDNSResponse,
    IPGeoResponse,
    IPReputationResponse,
    IPWHOISResponse,
)
from ...services.domain_service import DomainService
from ...services.ip_service import IPService
from ...services.proxy_service import ProxyService
from ...services.url_service import URLService

Handler = Callable[[str], Awaitable[dict[str, Any]]]

_url_service = URLService()
_domain_service = DomainService()
_ip_service = IPService()
_proxy_service = ProxyService()


async def _http_status(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _url_service.check_status(item)).model_dump())


async def _http_headers(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _url_service.get_headers(item)).model_dump())


async def _domain_info(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.get_domain_info(item)).model_dump())


async def _domain_dns(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.get_dns_records(item)).model_dump())


async def _domain_whois(item: str) -> dict[str, Any]:
    response: WHOISResponse = await _domain_service.get_whois(item)
    return cast(dict[str, Any], response.model_dump())


async def _domain_geoip(item: str) -> dict[str, Any]:
    response: GeoIPResponse = await _domain_service.get_geoip(item)
    return cast(dict[str, Any], response.model_dump())


async def _domain_reputation(item: str) -> dict[str, Any]:
    response: ReputationResponse = await _domain_service.check_reputation(item)
    return cast(dict[str, Any], response.model_dump())


async def _domain_blacklist(item: str) -> dict[str, Any]:
    response: BlacklistResponse = await _domain_service.check_blacklist(item)
    return cast(dict[str, Any], response.model_dump())


async def _domain_ssl(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.check_ssl(item)).model_dump())


async def _domain_ssl_certificate(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.get_ssl_certificate(item)).model_dump())


async def _domain_subdomains(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.get_subdomains(item)).model_dump())


async def _domain_hosting(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _domain_service.get_hosting_info(item)).model_dump())


async def _ip_info(item: str) -> dict[str, Any]:
    return cast(dict[str, Any], (await _ip_service.get_ip_info(item)).model_dump())


async def _ip_dns(item: str) -> dict[str, Any]:
    response: IPDNSResponse = await _ip_service.get_dns_records(item)
    return cast(dict[str, Any], response.model_dump())


async def _ip_whois(item: str) -> dict[str, Any]:
    response: IPWHOISResponse = await _ip_service.get_whois(item)
    return cast(dict[str, Any], response.model_dump())


async def _ip_geoip(item: str) -> dict[str, Any]:
    response: IPGeoResponse = await _ip_service.get_geoip(item)
    return cast(dict[str, Any], response.model_dump())


async def _ip_reputation(item: str) -> dict[str, Any]:
    response: IPReputationResponse = await _ip_service.check_reputation(item)
    return cast(dict[str, Any], response.model_dump())


async def _ip_blacklist(item: str) -> dict[str, Any]:
    response: IPBlacklistResponse = await _ip_service.check_blacklist(item)
    return cast(dict[str, Any], response.model_dump())


async def _proxy_check(item: str) -> dict[str, Any]:
    ip, port_str = item.rsplit(":", 1)
    return cast(dict[str, Any], (await _proxy_service.check(ip, int(port_str))).model_dump())


HANDLERS: dict[str, dict[str, Handler]] = {
    "http": {
        "status": _http_status,
        "headers": _http_headers,
    },
    "domain": {
        "info": _domain_info,
        "dns": _domain_dns,
        "whois": _domain_whois,
        "geoip": _domain_geoip,
        "reputation": _domain_reputation,
        "blacklist": _domain_blacklist,
        "ssl": _domain_ssl,
        "ssl-certificate": _domain_ssl_certificate,
        "subdomains": _domain_subdomains,
        "hosting": _domain_hosting,
    },
    "ip": {
        "info": _ip_info,
        "dns": _ip_dns,
        "whois": _ip_whois,
        "geoip": _ip_geoip,
        "reputation": _ip_reputation,
        "blacklist": _ip_blacklist,
    },
    "proxy": {
        "check": _proxy_check,
    },
}


def get_handler(family: str, operation: str) -> Handler:
    try:
        return HANDLERS[family][operation]
    except KeyError as exc:
        raise ValueError(f"Unsupported operation {family}/{operation}") from exc


def list_operations(family: str) -> Iterable[str]:
    return HANDLERS.get(family, {}).keys()
