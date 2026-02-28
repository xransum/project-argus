"""Jobs API — status and paginated results for async bulk jobs."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..db import get_db, get_job, get_results_page
from ..models.job_models import JobResultItem, JobResultsResponse, JobStatusResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Jobs"])

PAGE_SIZE = 100


@router.get("/{job_id}/status", response_model=JobStatusResponse)
async def get_job_status(job_id: str) -> JobStatusResponse:
    """Return current status and progress counters for a job."""
    async with get_db() as conn:
        job = await get_job(conn, job_id)

    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")

    pending_count = job["total"] - job["completed"] - job["failed"]
    return JobStatusResponse(
        job_id=job["id"],
        job_type=job["job_type"],
        status=job["status"],
        total=job["total"],
        completed=job["completed"],
        failed=job["failed"],
        pending=max(pending_count, 0),
        created_at=job["created_at"],
        updated_at=job["updated_at"],
    )


@router.get("/{job_id}/results", response_model=JobResultsResponse)
async def get_job_results(
    job_id: str,
    nextToken: Optional[str] = Query(
        default=None,
        description="Opaque pagination cursor returned by the previous page",
    ),
) -> JobResultsResponse:
    """Return up to 100 result items for a job, with keyset pagination.

    Pass the `next_token` from a previous response as `?nextToken=<value>` to
    fetch the following page.  When `next_token` is absent the results are
    exhausted.
    """
    # Decode cursor — it is simply the last seen row id encoded as a string
    try:
        after_id = int(nextToken) if nextToken else 0
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid nextToken value") from None

    async with get_db() as conn:
        job = await get_job(conn, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")

        rows = await get_results_page(conn, job_id, after_id=after_id, limit=PAGE_SIZE)

    items = [
        JobResultItem(
            id=r["id"],
            input=r["input"],
            status=r["status"],
            result=r.get("result"),
            error=r.get("error"),
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]

    # Build next_token: the id of the last row in this page, if there may be more
    next_token: Optional[str] = None
    if len(rows) == PAGE_SIZE:
        next_token = str(rows[-1]["id"])

    return JobResultsResponse(
        job_id=job_id,
        items=items,
        count=len(items),
        next_token=next_token,
    )
