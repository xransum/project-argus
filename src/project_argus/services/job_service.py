"""Job service — enqueues jobs and runs background workers."""

import asyncio
import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List

from ..db import (
    create_job,
    get_db,
    get_pending_results,
    set_result_done,
    set_result_error,
    set_result_running,
)
from ..services.domain_service import DomainService
from ..services.ip_service import IPService
from ..services.url_service import URLService

logger = logging.getLogger(__name__)

_url_service = URLService()
_domain_service = DomainService()
_ip_service = IPService()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ip(value: str) -> bool:
    """Return True if *value* is a valid IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Dispatcher: maps job_type -> async callable(input) -> dict
# ---------------------------------------------------------------------------

# Each handler receives a single validated string and returns a JSON-
# serialisable dict.  We use pydantic's .model_dump() to convert responses.


# HTTP / URL
async def _http_status(item: str) -> Dict[str, Any]:
    r = await _url_service.check_status(item)
    return r.model_dump()


async def _http_headers(item: str) -> Dict[str, Any]:
    r = await _url_service.get_headers(item)
    return r.model_dump()


# DNS — unified: IP → reverse DNS, domain → forward DNS
async def _dns_lookup(item: str) -> Dict[str, Any]:
    if _is_ip(item):
        r = await _ip_service.get_dns_records(item)
    else:
        r = await _domain_service.get_dns_records(item)
    return r.model_dump()


# WHOIS — unified: IP or domain
async def _whois_lookup(item: str) -> Dict[str, Any]:
    if _is_ip(item):
        r = await _ip_service.get_whois(item)
    else:
        r = await _domain_service.get_whois(item)
    return r.model_dump()


# GeoIP — unified: IP or domain
async def _geoip_lookup(item: str) -> Dict[str, Any]:
    if _is_ip(item):
        r = await _ip_service.get_geoip(item)
    else:
        r = await _domain_service.get_geoip(item)
    return r.model_dump()


# Reputation — unified: IP or domain
async def _reputation_check(item: str) -> Dict[str, Any]:
    if _is_ip(item):
        r = await _ip_service.check_reputation(item)
    else:
        r = await _domain_service.check_reputation(item)
    return r.model_dump()


# Blacklist — unified: IP or domain
async def _blacklist_check(item: str) -> Dict[str, Any]:
    if _is_ip(item):
        r = await _ip_service.check_blacklist(item)
    else:
        r = await _domain_service.check_blacklist(item)
    return r.model_dump()


# SSL — domain-specific
async def _ssl_info(item: str) -> Dict[str, Any]:
    r = await _domain_service.check_ssl(item)
    return r.model_dump()


async def _ssl_certificate(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_ssl_certificate(item)
    return r.model_dump()


# Domain-specific
async def _domain_info(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_domain_info(item)
    return r.model_dump()


async def _domain_subdomains(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_subdomains(item)
    return r.model_dump()


async def _domain_hosting(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_hosting_info(item)
    return r.model_dump()


# IP-specific
async def _ip_info(item: str) -> Dict[str, Any]:
    r = await _ip_service.get_ip_info(item)
    return r.model_dump()


# job_type -> handler
HANDLERS: Dict[str, Callable[[str], Coroutine[Any, Any, Dict[str, Any]]]] = {
    # HTTP
    "http/status": _http_status,
    "http/headers": _http_headers,
    # DNS
    "dns/lookup": _dns_lookup,
    # WHOIS
    "whois/lookup": _whois_lookup,
    # GeoIP
    "geoip/lookup": _geoip_lookup,
    # Reputation
    "reputation/check": _reputation_check,
    # Blacklist
    "blacklist/check": _blacklist_check,
    # SSL
    "ssl/info": _ssl_info,
    "ssl/certificate": _ssl_certificate,
    # Domain-specific
    "domain/info": _domain_info,
    "domain/subdomains": _domain_subdomains,
    "domain/hosting": _domain_hosting,
    # IP-specific
    "ip/info": _ip_info,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def enqueue_job(job_type: str, inputs: List[str]) -> str:
    """Create a job in the DB and kick off a background worker.

    Returns the new job_id.
    """
    if job_type not in HANDLERS:
        raise ValueError(f"Unknown job type: {job_type!r}")

    job_id = str(uuid.uuid4())
    now = _now()

    async with get_db() as conn:
        await create_job(conn, job_id, job_type, inputs, now)

    # Fire-and-forget background task
    asyncio.create_task(_run_job(job_id, job_type))
    return job_id


async def _run_job(job_id: str, job_type: str) -> None:
    """Process all pending result rows for a job, one at a time."""
    handler = HANDLERS.get(job_type)
    if handler is None:
        logger.error("No handler for job_type=%r, job_id=%s", job_type, job_id)
        return

    async with get_db() as conn:
        pending = await get_pending_results(conn, job_id)

    for row in pending:
        result_id: int = row["id"]
        item: str = row["input"]
        now = _now()

        async with get_db() as conn:
            await set_result_running(conn, result_id, now)

        try:
            result = await handler(item)
            now = _now()
            async with get_db() as conn:
                await set_result_done(conn, result_id, job_id, result, now)
        except Exception as exc:
            logger.warning("job=%s item=%r error=%s", job_id, item, exc)
            now = _now()
            async with get_db() as conn:
                await set_result_error(conn, result_id, job_id, str(exc), now)
