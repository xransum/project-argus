"""Job service — enqueues jobs and runs background workers."""

import asyncio
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
# Dispatcher: maps job_type -> async callable(input) -> dict
# ---------------------------------------------------------------------------

# Each handler receives a single validated string and returns a JSON-
# serialisable dict.  We use pydantic's .model_dump() to convert responses.


async def _url_status(item: str) -> Dict[str, Any]:
    r = await _url_service.check_status(item)
    return r.model_dump()


async def _url_headers(item: str) -> Dict[str, Any]:
    r = await _url_service.get_headers(item)
    return r.model_dump()


async def _domain_info(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_domain_info(item)
    return r.model_dump()


async def _domain_ssl(item: str) -> Dict[str, Any]:
    r = await _domain_service.check_ssl(item)
    return r.model_dump()


async def _domain_dns(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_dns_records(item)
    return r.model_dump()


async def _domain_whois(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_whois(item)
    return r.model_dump()


async def _domain_geoip(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_geoip(item)
    return r.model_dump()


async def _domain_reputation(item: str) -> Dict[str, Any]:
    r = await _domain_service.check_reputation(item)
    return r.model_dump()


async def _domain_blacklist(item: str) -> Dict[str, Any]:
    r = await _domain_service.check_blacklist(item)
    return r.model_dump()


async def _domain_ssl_certificate(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_ssl_certificate(item)
    return r.model_dump()


async def _domain_subdomains(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_subdomains(item)
    return r.model_dump()


async def _domain_hosting(item: str) -> Dict[str, Any]:
    r = await _domain_service.get_hosting_info(item)
    return r.model_dump()


async def _ip_info(item: str) -> Dict[str, Any]:
    r = await _ip_service.get_ip_info(item)
    return r.model_dump()


async def _ip_dns(item: str) -> Dict[str, Any]:
    r = await _ip_service.get_dns_records(item)
    return r.model_dump()


async def _ip_geoip(item: str) -> Dict[str, Any]:
    r = await _ip_service.get_geoip(item)
    return r.model_dump()


async def _ip_reputation(item: str) -> Dict[str, Any]:
    r = await _ip_service.check_reputation(item)
    return r.model_dump()


async def _ip_blacklist(item: str) -> Dict[str, Any]:
    r = await _ip_service.check_blacklist(item)
    return r.model_dump()


async def _ip_whois(item: str) -> Dict[str, Any]:
    r = await _ip_service.get_whois(item)
    return r.model_dump()


# job_type -> handler
HANDLERS: Dict[str, Callable[[str], Coroutine[Any, Any, Dict[str, Any]]]] = {
    "url/status": _url_status,
    "url/headers": _url_headers,
    "domain/info": _domain_info,
    "domain/ssl": _domain_ssl,
    "domain/dns": _domain_dns,
    "domain/whois": _domain_whois,
    "domain/geoip": _domain_geoip,
    "domain/reputation": _domain_reputation,
    "domain/blacklist": _domain_blacklist,
    "domain/ssl-certificate": _domain_ssl_certificate,
    "domain/subdomains": _domain_subdomains,
    "domain/hosting": _domain_hosting,
    "ip/info": _ip_info,
    "ip/dns": _ip_dns,
    "ip/geoip": _ip_geoip,
    "ip/reputation": _ip_reputation,
    "ip/blacklist": _ip_blacklist,
    "ip/whois": _ip_whois,
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
