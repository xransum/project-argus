"""Shared job contracts between web and Lambda handlers."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

JobState = Literal["pending", "running", "completed", "partial", "failed"]
JobFamily = Literal["http", "domain", "ip", "proxy"]


class JobSubmitRequest(BaseModel):
    family: JobFamily
    operation: str
    inputs: list[str] = Field(..., min_length=1)


class JobSubmittedResponse(BaseModel):
    job_id: str
    job_type: str
    status: JobState
    total: int
    message: str


class JobQueueMessage(BaseModel):
    job_id: str
    family: JobFamily
    operation: str
    inputs: list[str]


class JobRecord(BaseModel):
    job_id: str
    job_family: JobFamily
    operation: str
    status: JobState
    total: int
    completed: int
    failed: int
    pending: int
    created_at: str
    updated_at: str
    expires_at: int
    result_key: str | None = None
    progress_message: str | None = None
    last_error: str | None = None
    error_samples: list[str] = Field(default_factory=list)


class JobResultsPayload(BaseModel):
    job_id: str
    job_type: str
    status: JobState
    total: int
    completed: int
    failed: int
    items: list[dict[str, Any]]
