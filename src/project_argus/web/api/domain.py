"""Domain family routes."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter

from ...models.job_models import DomainBulkRequest, JobCreatedResponse
from ...utils.validators import DomainValidator
from .common import submit_job, validate_many

router = APIRouter(tags=["Domain"])


def _validate(domains: list[str]) -> list[str]:
    return validate_many(domains, "domain", lambda raw: DomainValidator(domain=raw).domain)


def _submit(operation: str, domains: list[str]) -> JobCreatedResponse:
    response = submit_job("domain", operation, _validate(domains))
    return cast(JobCreatedResponse, JobCreatedResponse.model_validate(response.model_dump()))


@router.post("/info", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_info(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("info", body.domains)


@router.post("/dns", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_dns(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("dns", body.domains)


@router.post("/whois", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_whois(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("whois", body.domains)


@router.post("/geoip", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_geoip(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("geoip", body.domains)


@router.post("/reputation", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_reputation(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("reputation", body.domains)


@router.post("/blacklist", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_blacklist(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("blacklist", body.domains)


@router.post("/ssl", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_ssl(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("ssl", body.domains)


@router.post("/ssl-certificate", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_ssl_certificate(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("ssl-certificate", body.domains)


@router.post("/subdomains", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_subdomains(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("subdomains", body.domains)


@router.post("/hosting", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_hosting(body: DomainBulkRequest) -> JobCreatedResponse:
    return _submit("hosting", body.domains)
