"""Proxy checker bulk API endpoint."""

import logging

from fastapi import APIRouter, HTTPException

from ..models.job_models import JobCreatedResponse
from ..models.proxy_models import ProxyBulkRequest
from ..services.job_service import enqueue_job
from ..utils.validators import validate_ip

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Proxy"])


def _encode_proxy(ip: str, port: int) -> str:
    """Encode a proxy target as the canonical ``ip:port`` string used internally."""
    return f"{ip}:{port}"


@router.post("/check", response_model=JobCreatedResponse, status_code=202)
async def bulk_proxy_check(body: ProxyBulkRequest) -> JobCreatedResponse:
    """Check a list of proxies (HTTP, HTTPS, SOCKS4, SOCKS5) and return a job ID."""
    errors = []
    encoded: list[str] = []

    for i, proxy in enumerate(body.proxies):
        try:
            validate_ip(proxy.ip)
        except ValueError as exc:
            errors.append({"index": i, "ip": proxy.ip, "port": proxy.port, "error": str(exc)})
            continue
        encoded.append(_encode_proxy(proxy.ip, proxy.port))

    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})

    job_id = await enqueue_job("proxy/check", encoded)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="proxy/check",
        status="pending",
        total=len(encoded),
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )
