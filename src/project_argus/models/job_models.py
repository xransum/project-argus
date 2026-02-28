"""Pydantic models for job tracking."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Job status literals
# ---------------------------------------------------------------------------

JobStatus = Literal["pending", "running", "completed", "failed"]
ResultStatus = Literal["pending", "running", "completed", "failed"]

# ---------------------------------------------------------------------------
# Request payloads  (POST /api/<resource>/<operation>)
# ---------------------------------------------------------------------------


class URLBulkRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, description="List of URLs to process")


class DomainBulkRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1, description="List of domains to process")


class IPBulkRequest(BaseModel):
    ips: List[str] = Field(..., min_length=1, description="List of IP addresses to process")


# ---------------------------------------------------------------------------
# Job response shapes
# ---------------------------------------------------------------------------


class JobCreatedResponse(BaseModel):
    job_id: str
    job_type: str
    status: JobStatus
    total: int
    message: str


class JobStatusResponse(BaseModel):
    job_id: str
    job_type: str
    status: JobStatus
    total: int
    completed: int
    failed: int
    pending: int
    created_at: str
    updated_at: str


class JobResultItem(BaseModel):
    id: int
    input: str
    status: ResultStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str


class JobResultsResponse(BaseModel):
    job_id: str
    items: List[JobResultItem]
    count: int
    next_token: Optional[str] = Field(
        None,
        description="Opaque cursor — pass as ?nextToken=<value> to retrieve the next page",
    )
