"""SSL/TLS Check bulk API endpoints — domain-specific, accepts POST with a list of domains."""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from ..models.job_models import DomainBulkRequest, JobCreatedResponse
from ..services.job_service import enqueue_job
from ..utils.validators import DomainValidator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["SSL"])


def _validate_domains(domains: list) -> list:
    """Validate each domain and return the sanitised list."""
    sanitised = []
    errors = []
    for i, raw in enumerate(domains):
        try:
            sanitised.append(DomainValidator(domain=raw).domain)
        except (ValidationError, ValueError) as exc:
            msg = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            errors.append({"index": i, "domain": raw, "error": msg})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitised


@router.post("/info", response_model=JobCreatedResponse, status_code=202)
async def bulk_ssl_info(body: DomainBulkRequest) -> JobCreatedResponse:
    """Check SSL certificate validity for a list of domains and return a job ID."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("ssl/info", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ssl/info",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )


@router.post("/certificate", response_model=JobCreatedResponse, status_code=202)
async def bulk_ssl_certificate(body: DomainBulkRequest) -> JobCreatedResponse:
    """Fetch full SSL certificate details for a list of domains and return a job ID."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("ssl/certificate", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="ssl/certificate",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )
