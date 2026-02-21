"""IP API endpoints for Project Argus"""

from fastapi import APIRouter, Depends, HTTPException
from typing_extensions import Annotated

from ...models.ip_models import (
    IPBlacklistResponse,
    IPDNSResponse,
    IPGeoResponse,
    IPInfoResponse,
    IPReputationResponse,
    IPWHOISResponse,
)
from ...services.ip_service import IPService
from ...utils.validators import validate_ip

router = APIRouter()
service = IPService()


@router.get("/info", response_model=IPInfoResponse)
async def get_ip_info(ip: Annotated[str, Depends(validate_ip)]) -> IPInfoResponse:
    """Fetch information about an IP address"""
    try:
        return await service.get_ip_info(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/dns", response_model=IPDNSResponse)
async def get_dns_records(ip: Annotated[str, Depends(validate_ip)]) -> IPDNSResponse:
    """Fetch DNS records of an IP address"""
    try:
        return await service.get_dns_records(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip", response_model=IPGeoResponse)
async def get_geoip(ip: Annotated[str, Depends(validate_ip)]) -> IPGeoResponse:
    """Fetch geolocation information of an IP address"""
    try:
        return await service.get_geoip(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/reputation", response_model=IPReputationResponse)
async def check_reputation(ip: Annotated[str, Depends(validate_ip)]) -> IPReputationResponse:
    """Check the reputation of an IP address"""
    try:
        return await service.check_reputation(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/blacklist", response_model=IPBlacklistResponse)
async def check_blacklist(ip: Annotated[str, Depends(validate_ip)]) -> IPBlacklistResponse:
    """Check if an IP address is blacklisted"""
    try:
        return await service.check_blacklist(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/whois", response_model=IPWHOISResponse)
async def get_whois(ip: Annotated[str, Depends(validate_ip)]) -> IPWHOISResponse:
    """Fetch WHOIS information of an IP address"""
    try:
        return await service.get_whois(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
