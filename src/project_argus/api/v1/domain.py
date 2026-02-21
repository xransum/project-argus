"""Domain API endpoints for Project Argus"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing_extensions import Annotated

from ...models.domain_models import (
    BlacklistResponse,
    DNSRecordResponse,
    DomainInfoResponse,
    GeoIPResponse,
    HostingInfoResponse,
    ReputationResponse,
    SSLCertificateResponse,
    SSLStatusResponse,
    SubdomainResponse,
    WHOISResponse,
)
from ...services.domain_service import DomainService
from ...utils.validators import validate_domain

router = APIRouter()
service = DomainService()


@router.get("/info", response_model=DomainInfoResponse)
async def get_domain_info(domain: Annotated[str, Depends(validate_domain)]) -> DomainInfoResponse:
    """Fetch information about a domain"""
    try:
        return await service.get_domain_info(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/ssl", response_model=SSLStatusResponse)
async def check_ssl(domain: Annotated[str, Depends(validate_domain)]) -> SSLStatusResponse:
    """Check the SSL status of a domain"""
    try:
        return await service.check_ssl(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/dns", response_model=DNSRecordResponse)
async def get_dns_records(
    domain: Annotated[str, Depends(validate_domain)],
    record_type: str = Query(default="A"),
) -> DNSRecordResponse:
    """Fetch DNS records of a domain"""
    try:
        return await service.get_dns_records(domain, record_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/whois", response_model=WHOISResponse)
async def get_whois(domain: Annotated[str, Depends(validate_domain)]) -> WHOISResponse:
    """Fetch WHOIS information of a domain"""
    try:
        return await service.get_whois(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip", response_model=GeoIPResponse)
async def get_geoip(domain: Annotated[str, Depends(validate_domain)]) -> GeoIPResponse:
    """Fetch geolocation information of a domain"""
    try:
        return await service.get_geoip(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/reputation", response_model=ReputationResponse)
async def check_reputation(domain: Annotated[str, Depends(validate_domain)]) -> ReputationResponse:
    """Check the reputation of a domain"""
    try:
        return await service.check_reputation(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/blacklist", response_model=BlacklistResponse)
async def check_blacklist(domain: Annotated[str, Depends(validate_domain)]) -> BlacklistResponse:
    """Check if a domain is blacklisted"""
    try:
        return await service.check_blacklist(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/ssl-certificate", response_model=SSLCertificateResponse)
async def get_ssl_certificate(
    domain: Annotated[str, Depends(validate_domain)],
) -> SSLCertificateResponse:
    """Fetch SSL certificate information of a domain"""
    try:
        return await service.get_ssl_certificate(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/subdomains", response_model=SubdomainResponse)
async def get_subdomains(domain: Annotated[str, Depends(validate_domain)]) -> SubdomainResponse:
    """Fetch subdomains of a domain"""
    try:
        return await service.get_subdomains(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/hosting", response_model=HostingInfoResponse)
async def get_hosting_info(domain: Annotated[str, Depends(validate_domain)]) -> HostingInfoResponse:
    """Fetch hosting information of a domain"""
    try:
        return await service.get_hosting_info(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
