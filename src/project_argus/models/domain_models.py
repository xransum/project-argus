"""Domain models for Project Argus API"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel


class DomainInfoResponse(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    name_servers: List[str] = []


class SSLStatusResponse(BaseModel):
    domain: str
    has_ssl: bool
    valid: bool
    issuer: Optional[str] = None
    expiry_date: Optional[datetime] = None
    days_until_expiry: Optional[int] = None


class DNSRecordResponse(BaseModel):
    domain: str
    record_type: str
    records: List[str]


class WHOISResponse(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = []
    status: List[str] = []
    registrant: Optional[Dict[str, str]] = None


class GeoIPResponse(BaseModel):
    domain: str
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None


class ReputationResponse(BaseModel):
    domain: str
    score: int  # 0-100
    is_safe: bool
    categories: List[str] = []


class BlacklistResponse(BaseModel):
    domain: str
    is_blacklisted: bool
    blacklists: List[str] = []


class SSLCertificateResponse(BaseModel):
    domain: str
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_size: int


class SubdomainResponse(BaseModel):
    domain: str
    subdomains: List[str]


class HostingInfoResponse(BaseModel):
    domain: str
    ip_address: str
    hosting_provider: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
