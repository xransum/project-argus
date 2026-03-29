"""IP family routes."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter

from ...models.job_models import IPBulkRequest, JobCreatedResponse
from ...utils.validators import IPValidator
from .common import submit_job, validate_many

router = APIRouter(tags=["IP"])


def _validate(ips: list[str]) -> list[str]:
    return validate_many(ips, "ip", lambda raw: IPValidator(ip=raw).ip)


def _submit(operation: str, ips: list[str]) -> JobCreatedResponse:
    response = submit_job("ip", operation, _validate(ips))
    return cast(JobCreatedResponse, JobCreatedResponse.model_validate(response.model_dump()))


@router.post("/info", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_info(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("info", body.ips)


@router.post("/dns", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_dns(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("dns", body.ips)


@router.post("/whois", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_whois(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("whois", body.ips)


@router.post("/geoip", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_geoip(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("geoip", body.ips)


@router.post("/reputation", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_reputation(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("reputation", body.ips)


@router.post("/blacklist", response_model=JobCreatedResponse, status_code=202)
async def bulk_ip_blacklist(body: IPBulkRequest) -> JobCreatedResponse:
    return _submit("blacklist", body.ips)
