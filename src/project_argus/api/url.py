"""URL bulk API endpoints — all operations accept POST with a list of URLs."""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from ..models.job_models import JobCreatedResponse, URLBulkRequest
from ..services.job_service import enqueue_job
from ..utils.validators import URLValidator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["URL"])


def _validate_urls(urls: list) -> list:
    """Validate each URL and return the sanitised list.

    Raises HTTPException(400) if any URL fails validation, including the
    index and reason so the caller can fix the payload.
    """
    sanitised = []
    errors = []
    for i, raw in enumerate(urls):
        try:
            sanitised.append(URLValidator(url=raw).url)
        except (ValidationError, ValueError) as exc:
            msg = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            errors.append({"index": i, "url": raw, "error": msg})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitised


@router.post("/status", response_model=JobCreatedResponse, status_code=202)
async def bulk_url_status(body: URLBulkRequest) -> JobCreatedResponse:
    """Check HTTP status for a list of URLs and return a job ID."""
    sanitised = _validate_urls(body.urls)
    job_id = await enqueue_job("url/status", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="url/status",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/headers", response_model=JobCreatedResponse, status_code=202)
async def bulk_url_headers(body: URLBulkRequest) -> JobCreatedResponse:
    """Fetch HTTP headers for a list of URLs and return a job ID."""
    sanitised = _validate_urls(body.urls)
    job_id = await enqueue_job("url/headers", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="url/headers",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )
