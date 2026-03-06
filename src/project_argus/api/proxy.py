"""Proxy checker bulk API endpoint."""

import logging

from fastapi import APIRouter, HTTPException

from ..models.job_models import JobCreatedResponse
from ..models.proxy_models import ProxyBulkRequest
from ..services.job_service import enqueue_job
from ..utils.validators import validate_ip

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Proxy"])


@router.post("/check", response_model=JobCreatedResponse, status_code=202)
async def bulk_proxy_check(body: ProxyBulkRequest) -> JobCreatedResponse:
    """Check a list of proxies (HTTP, HTTPS, SOCKS4, SOCKS5) and return a job ID."""
    errors = []
    validated: list[str] = []

    for i, proxy in enumerate(body.proxies):
        ip, _, port_str = proxy.rpartition(":")
        try:
            validate_ip(ip)
        except ValueError as exc:
            errors.append({"index": i, "proxy": proxy, "error": str(exc)})
            continue
        validated.append(proxy)

    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})

    job_id = await enqueue_job("proxy/check", validated)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="proxy/check",
        status="pending",
        total=len(validated),
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )
