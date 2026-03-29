"""HTTP family routes."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter

from ...models.job_models import JobCreatedResponse, URLBulkRequest
from ...utils.validators import URLValidator
from .common import submit_job, validate_many

router = APIRouter(tags=["HTTP"])


def _validate(urls: list[str]) -> list[str]:
    return validate_many(urls, "url", lambda raw: URLValidator(url=raw).url)


@router.post("/status", response_model=JobCreatedResponse, status_code=202)
async def bulk_http_status(body: URLBulkRequest) -> JobCreatedResponse:
    response = submit_job("http", "status", _validate(body.urls))
    return cast(JobCreatedResponse, JobCreatedResponse.model_validate(response.model_dump()))


@router.post("/headers", response_model=JobCreatedResponse, status_code=202)
async def bulk_http_headers(body: URLBulkRequest) -> JobCreatedResponse:
    response = submit_job("http", "headers", _validate(body.urls))
    return cast(JobCreatedResponse, JobCreatedResponse.model_validate(response.model_dump()))
