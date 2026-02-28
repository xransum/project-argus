"""IP bulk API endpoints — all operations accept POST with a list of IP addresses."""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from ..models.job_models import IPBulkRequest, JobCreatedResponse
from ..services.job_service import enqueue_job
from ..utils.validators import IPValidator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["IP"])


def _validate_ips(ips: list) -> list:
    """Validate each IP address and return the sanitised list.

    Raises HTTPException(400) listing every failing entry.
    """
    sanitised = []
    errors = []
    for i, raw in enumerate(ips):
        try:
            sanitised.append(IPValidator(ip=raw).ip)
        except (ValidationError, ValueError) as exc:
            msg = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            errors.append({"index": i, "ip": raw, "error": msg})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitised


@router.post("/info", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_info(body: IPBulkRequest) -> JobCreatedResponse:
    """Fetch host/ASN info for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/info", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/info",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/dns", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_dns(body: IPBulkRequest) -> JobCreatedResponse:
    """Fetch reverse DNS records for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/dns", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/dns",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/geoip", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_geoip(body: IPBulkRequest) -> JobCreatedResponse:
    """Fetch GeoIP data for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/geoip", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/geoip",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/reputation", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_reputation(body: IPBulkRequest) -> JobCreatedResponse:
    """Check reputation for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/reputation", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/reputation",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/blacklist", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_blacklist(body: IPBulkRequest) -> JobCreatedResponse:
    """Check blacklist status for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/blacklist", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/blacklist",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/whois", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_whois(body: IPBulkRequest) -> JobCreatedResponse:
    """Fetch WHOIS records for a list of IP addresses."""
    sanitised = _validate_ips(body.ips)
    job_id = await enqueue_job("ip/whois", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ip/whois",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )
