"""WHOIS Lookup bulk API endpoints — accepts POST with a list of domains or IPs."""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from ..models.job_models import JobCreatedResponse, TargetBulkRequest
from ..services.job_service import enqueue_job
from ..utils.validators import TargetValidator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WHOIS"])


def _validate_targets(targets: list) -> list:
    """Validate each target (domain or IP) and return the sanitised list."""
    sanitised = []
    errors = []
    for i, raw in enumerate(targets):
        try:
            sanitised.append(TargetValidator(target=raw).target)
        except (ValidationError, ValueError) as exc:
            msg = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            errors.append({"index": i, "target": raw, "error": msg})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitised


@router.post("/lookup", response_model=JobCreatedResponse, status_code=202)
async def bulk_whois_lookup(body: TargetBulkRequest) -> JobCreatedResponse:
    """Perform WHOIS lookups for a list of domains or IPs and return a job ID."""
    sanitised = _validate_targets(body.targets)
    job_id = await enqueue_job("whois/lookup", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="whois/lookup",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /api/jobs/{job_id} for progress.",
    )
