"""IP-specific bulk API endpoints — accepts POST with a list of IP addresses."""

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
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )
