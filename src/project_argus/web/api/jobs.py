"""Jobs family routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ...models.job_models import JobStatusResponse
from .common import get_job_results, get_job_status

router = APIRouter(tags=["Jobs"])


@router.get("/{job_id}", response_model=JobStatusResponse)
async def job_status(job_id: str) -> JobStatusResponse:
    try:
        payload = get_job_status(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    validated: JobStatusResponse = JobStatusResponse.model_validate(payload)
    return validated


@router.get("/{job_id}/results")
async def job_results(job_id: str) -> dict[str, Any]:
    try:
        return get_job_results(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
