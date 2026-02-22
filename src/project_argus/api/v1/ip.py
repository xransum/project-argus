"""IP address validation and analysis API endpoints"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from ...models.ip_models import (
    IPBlacklistResponse,
    IPDNSResponse,
    IPGeoResponse,
    IPInfoResponse,
    IPReputationResponse,
    IPWHOISResponse,
)
from ...services.ip_service import IPService
from ...utils.validators import IPValidator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ip", tags=["ip"])
service = IPService()


@router.get("/validate")
async def validate_ip_endpoint(
    ip: str = Query(..., description="IP address to validate")
) -> Dict[str, Any]:
    """
    Validate an IP address format.

    Args:
        ip: IP address to validate

    Returns:
        Validation result with sanitized IP

    Raises:
        HTTPException: If IP is invalid
    """
    try:
        validator = IPValidator(ip=ip)
        return {
            "valid": True,
            "ip": validator.ip,
            "message": "IP address is valid",
        }
    except ValidationError as e:
        error_msg = e.errors()[0]["msg"]
        logger.warning(f"Invalid IP validation: {ip} - {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)
    except Exception as e:
        logger.error(f"Unexpected error validating IP: {ip} - {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/info")
async def get_ip_info(
    ip: str = Query(..., description="IP address to get info for")
) -> Dict[str, Any]:
    """
    Get information about an IP address.

    Args:
        ip: IP address

    Returns:
        IP address information
    """
    try:
        validator = IPValidator(ip=ip)
        sanitized_ip = validator.ip

        # Add your IP info logic here (geolocation, ASN, etc.)
        return {
            "ip": sanitized_ip,
            "valid": True,
            # Add additional IP information as needed
        }
    except ValidationError as e:
        error_msg = e.errors()[0]["msg"]
        raise HTTPException(status_code=400, detail=error_msg)


@router.get("/dns", response_model=IPDNSResponse)
async def get_dns_records(
    ip: str = Query(..., description="IP address to fetch DNS records for")
) -> IPDNSResponse:
    """Fetch DNS records of an IP address"""
    try:
        return await service.get_dns_records(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip", response_model=IPGeoResponse)
async def get_geoip(
    ip: str = Query(..., description="IP address to fetch geolocation for")
) -> IPGeoResponse:
    """Fetch geolocation information of an IP address"""
    try:
        return await service.get_geoip(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/reputation", response_model=IPReputationResponse)
async def check_reputation(
    ip: str = Query(..., description="IP address to check reputation for")
) -> IPReputationResponse:
    """Check the reputation of an IP address"""
    try:
        return await service.check_reputation(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/blacklist", response_model=IPBlacklistResponse)
async def check_blacklist(
    ip: str = Query(..., description="IP address to check blacklist status for")
) -> IPBlacklistResponse:
    """Check if an IP address is blacklisted"""
    try:
        return await service.check_blacklist(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/whois", response_model=IPWHOISResponse)
async def get_whois(
    ip: str = Query(..., description="IP address to fetch WHOIS information for")
) -> IPWHOISResponse:
    """Fetch WHOIS information of an IP address"""
    try:
        return await service.get_whois(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
