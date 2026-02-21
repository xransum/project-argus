"""IP-related data models for Project Argus API"""

from typing import List, Optional

from pydantic import BaseModel


class IPInfoResponse(BaseModel):
    """Response model for IP information"""

    ip: str
    hostname: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None


class IPDNSResponse(BaseModel):
    """Response model for IP DNS records"""

    ip: str
    ptr_records: List[str] = []
    hostname: Optional[str] = None


class IPGeoResponse(BaseModel):
    """Response model for IP geolocation"""

    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    region: Optional[str] = None
    timezone: Optional[str] = None


class IPReputationResponse(BaseModel):
    """Response model for IP reputation check"""

    ip: str
    score: int
    is_safe: bool
    threat_level: Optional[str] = None
    categories: List[str] = []


class IPBlacklistResponse(BaseModel):
    """Response model for IP blacklist check"""

    ip: str
    is_blacklisted: bool
    blacklists: List[str] = []
    total_lists_checked: int = 0


class IPWHOISResponse(BaseModel):
    """Response model for IP WHOIS information"""

    ip: str
    asn: Optional[str] = None
    organization: Optional[str] = None
    network: Optional[str] = None
    country: Optional[str] = None
    registrar: Optional[str] = None
    abuse_contact: Optional[str] = None
