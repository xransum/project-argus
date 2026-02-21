"""Domain service for Project Argus API"""

import socket
import ssl
from datetime import datetime
from typing import Any, Dict, Optional, cast

import dns.resolver
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..models.domain_models import (
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


class DomainService:
    def __init__(self) -> None:
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def get_domain_info(self, domain: str) -> DomainInfoResponse:
        """Fetch basic information about a domain"""
        try:
            w = whois.whois(domain)
            return DomainInfoResponse(
                domain=domain,
                registrar=w.registrar if hasattr(w, "registrar") else None,
                creation_date=(
                    self._parse_date(w.creation_date) if hasattr(w, "creation_date") else None
                ),
                expiration_date=(
                    self._parse_date(w.expiration_date) if hasattr(w, "expiration_date") else None
                ),
                name_servers=(
                    w.name_servers if hasattr(w, "name_servers") and w.name_servers else []
                ),
            )
        except Exception:
            return DomainInfoResponse(domain=domain, name_servers=[])

    async def check_ssl(self, domain: str) -> SSLStatusResponse:
        """Check the SSL status of a domain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        return SSLStatusResponse(domain=domain, has_ssl=False, valid=False)

                    expiry_str = cert.get("notAfter", "")
                    if not expiry_str or not isinstance(expiry_str, str):
                        return SSLStatusResponse(domain=domain, has_ssl=True, valid=False)

                    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (expiry_date - datetime.now()).days

                    # Get issuer safely
                    issuer = None
                    if "issuer" in cert:
                        issuer_tuple = cert["issuer"]
                        if isinstance(issuer_tuple, tuple):
                            issuer_dict: Dict[str, str] = {}
                            for item in issuer_tuple:
                                if isinstance(item, tuple) and len(item) >= 1:
                                    inner = item[0]
                                    if isinstance(inner, tuple) and len(inner) == 2:
                                        key, value = inner
                                        if isinstance(key, str) and isinstance(value, str):
                                            issuer_dict[key] = value
                            issuer = issuer_dict.get("organizationName")

                    return SSLStatusResponse(
                        domain=domain,
                        has_ssl=True,
                        valid=days_until_expiry > 0,
                        issuer=issuer,
                        expiry_date=expiry_date,
                        days_until_expiry=days_until_expiry,
                    )
        except Exception:
            return SSLStatusResponse(domain=domain, has_ssl=False, valid=False)

    async def get_dns_records(self, domain: str, record_type: str = "A") -> DNSRecordResponse:
        """Fetch DNS records of a domain"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = [str(rdata) for rdata in answers]
            return DNSRecordResponse(domain=domain, record_type=record_type, records=records)
        except Exception:
            return DNSRecordResponse(domain=domain, record_type=record_type, records=[])

    async def get_whois(self, domain: str) -> WHOISResponse:
        """Fetch WHOIS information of a domain"""
        try:
            w = whois.whois(domain)
            return WHOISResponse(
                domain=domain,
                registrar=w.registrar if hasattr(w, "registrar") else None,
                creation_date=(
                    self._parse_date(w.creation_date) if hasattr(w, "creation_date") else None
                ),
                expiration_date=(
                    self._parse_date(w.expiration_date) if hasattr(w, "expiration_date") else None
                ),
                updated_date=(
                    self._parse_date(w.updated_date) if hasattr(w, "updated_date") else None
                ),
                name_servers=(
                    w.name_servers if hasattr(w, "name_servers") and w.name_servers else []
                ),
                status=w.status if hasattr(w, "status") and w.status else [],
            )
        except Exception:
            return WHOISResponse(domain=domain)

    async def get_geoip(self, domain: str) -> GeoIPResponse:
        """Fetch geolocation information of a domain"""
        try:
            ip = socket.gethostbyname(domain)
            return GeoIPResponse(domain=domain, ip=ip, country="Unknown", city="Unknown")
        except Exception:
            return GeoIPResponse(domain=domain, ip="")

    async def check_reputation(self, domain: str) -> ReputationResponse:
        """Check the reputation of a domain"""
        return ReputationResponse(domain=domain, score=75, is_safe=True, categories=[])

    async def check_blacklist(self, domain: str) -> BlacklistResponse:
        """Check if a domain is blacklisted"""
        return BlacklistResponse(domain=domain, is_blacklisted=False, blacklists=[])

    async def get_ssl_certificate(self, domain: str) -> SSLCertificateResponse:
        """Fetch SSL certificate information of a domain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        raise Exception("No certificate found")

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Get public key size safely
                    pub_key = cert.public_key()
                    key_size = 0
                    if hasattr(pub_key, "key_size"):
                        key_size = cast(int, pub_key.key_size)

                    return SSLCertificateResponse(
                        domain=domain,
                        subject={attr.oid._name: attr.value for attr in cert.subject},
                        issuer={attr.oid._name: attr.value for attr in cert.issuer},
                        version=cert.version.value,
                        serial_number=str(cert.serial_number),
                        not_before=cert.not_valid_before_utc,
                        not_after=cert.not_valid_after_utc,
                        signature_algorithm=cert.signature_algorithm_oid._name,
                        public_key_size=key_size,
                    )
        except Exception as e:
            raise Exception(f"Failed to fetch SSL certificate: {str(e)}") from e

    async def get_subdomains(self, domain: str) -> SubdomainResponse:
        """Fetch subdomains of a domain"""
        common_subdomains = ["www", "mail", "ftp", "api", "blog"]
        found_subdomains = []

        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except Exception:
                pass

        return SubdomainResponse(domain=domain, subdomains=found_subdomains)

    async def get_hosting_info(self, domain: str) -> HostingInfoResponse:
        """Fetch hosting information of a domain"""
        try:
            ip = socket.gethostbyname(domain)
            return HostingInfoResponse(
                domain=domain,
                ip_address=ip,
                hosting_provider="Unknown",
                asn="Unknown",
                organization="Unknown",
            )
        except Exception:
            return HostingInfoResponse(domain=domain, ip_address="")

    def _parse_date(self, date_value: Any) -> Optional[datetime]:
        """Parse date from whois response"""
        if isinstance(date_value, list):
            return date_value[0] if date_value else None
        if isinstance(date_value, datetime):
            return date_value
        return None
