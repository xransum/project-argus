"""Domain bulk API endpoints — all operations accept POST with a list of domains."""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from ..models.job_models import DomainBulkRequest, JobCreatedResponse
from ..services.job_service import enqueue_job
from ..utils.validators import DomainValidator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Domain"])


def _validate_domains(domains: list) -> list:
    """Validate each domain and return the sanitised list.

    Raises HTTPException(400) listing every failing entry.
    """
    sanitised = []
    errors = []
    for i, raw in enumerate(domains):
        try:
            sanitised.append(DomainValidator(domain=raw).domain)
        except (ValidationError, ValueError) as exc:
            msg = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            errors.append({"index": i, "domain": raw, "error": msg})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitised


@router.post("/info", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_info(body: DomainBulkRequest) -> JobCreatedResponse:
    """Fetch registrar / creation-date info for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/info", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/info",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/ssl", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_ssl(body: DomainBulkRequest) -> JobCreatedResponse:
    """Check SSL status for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/ssl", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/ssl",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/dns", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_dns(body: DomainBulkRequest) -> JobCreatedResponse:
    """Look up DNS records (default record type: A) for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/dns", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/dns",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/whois", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_whois(body: DomainBulkRequest) -> JobCreatedResponse:
    """Fetch WHOIS records for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/whois", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/whois",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/geoip", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_geoip(body: DomainBulkRequest) -> JobCreatedResponse:
    """Resolve GeoIP data for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/geoip", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/geoip",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/reputation", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_reputation(body: DomainBulkRequest) -> JobCreatedResponse:
    """Check reputation scores for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/reputation", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/reputation",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/blacklist", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_blacklist(body: DomainBulkRequest) -> JobCreatedResponse:
    """Check blacklist status for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/blacklist", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/blacklist",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/ssl-certificate", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_ssl_certificate(body: DomainBulkRequest) -> JobCreatedResponse:
    """Fetch full SSL certificate details for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/ssl-certificate", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/ssl-certificate",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/subdomains", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_subdomains(body: DomainBulkRequest) -> JobCreatedResponse:
    """Enumerate subdomains for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/subdomains", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/subdomains",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )


@router.post("/hosting", response_model=JobCreatedResponse, status_code=202)
async def bulk_domain_hosting(body: DomainBulkRequest) -> JobCreatedResponse:
    """Fetch hosting / ASN information for a list of domains."""
    sanitised = _validate_domains(body.domains)
    job_id = await enqueue_job("domain/hosting", sanitised)
    return JobCreatedResponse(
        job_id=job_id,
        job_type="domain/hosting",
        status="pending",
        total=len(sanitised),
        message="Job enqueued. Poll /jobs/{job_id}/status for progress.",
    )
