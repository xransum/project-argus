"""Pydantic models for job tracking."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

JobStatus = Literal["pending", "running", "completed", "partial", "failed"]
ResultStatus = Literal["pending", "running", "completed", "failed"]


class URLBulkRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, description="List of URLs to process")


class DomainBulkRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1, description="List of domains to process")


class IPBulkRequest(BaseModel):
    ips: List[str] = Field(..., min_length=1, description="List of IP addresses to process")


class TargetBulkRequest(BaseModel):
    targets: List[str] = Field(
        ..., min_length=1, description="List of domains or IP addresses to process"
    )


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
    progress_message: Optional[str] = None
    last_error: Optional[str] = None
    error_samples: List[str] = Field(default_factory=list)
    progress_pct: float = 0.0
