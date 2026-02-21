"""Validation utilities for Project Argus API - Security-focused validation"""

import ipaddress
import re
from urllib.parse import unquote, urlparse

import idna
from fastapi import HTTPException, Query
from pydantic import BaseModel, field_validator
from typing_extensions import Annotated


class URLValidator(BaseModel):
    """Validate and sanitize URL format with security checks"""

    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")

        # Remove whitespace and common obfuscation
        url = v.strip()

        # Decode URL-encoded characters
        try:
            url = unquote(url)
        except Exception:
            pass

        # Handle missing scheme
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url

        # Parse and validate
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Unable to parse URL: {str(e)}") from e

        if not parsed.scheme or parsed.scheme not in ["http", "https", "ftp"]:
            raise ValueError("URL must use http, https, or ftp scheme")

        if not parsed.netloc:
            raise ValueError("URL must contain a valid domain/host")

        # Check for suspicious patterns
        hostname = parsed.hostname or parsed.netloc

        # Detect IP addresses in hostname
        try:
            ipaddress.ip_address(hostname)
            # It's an IP address, which is valid but note it
        except ValueError:
            # It's a domain name, validate it
            if not cls._is_valid_hostname(hostname):
                raise ValueError("Invalid hostname format") from None

        # Check for overly long URLs (potential DoS)
        if len(url) > 2048:
            raise ValueError("URL exceeds maximum length (2048 characters)")

        # Check for null bytes (security risk)
        if "\x00" in url:
            raise ValueError("URL contains null bytes")

        # Check for SSRF attempts (localhost, private IPs)
        if cls._is_suspicious_host(hostname):
            raise ValueError("URL targets suspicious or internal resource")

        return url

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Validate hostname format"""
        if not hostname or len(hostname) > 253:
            return False

        # Handle internationalized domain names (IDN)
        try:
            hostname = idna.decode(hostname)
        except Exception:
            pass

        # Validate each label
        labels = hostname.split(".")
        if len(labels) < 2:  # Need at least domain.tld
            return False

        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label, re.IGNORECASE):
                return False

        # Validate TLD
        tld = labels[-1]
        if not re.match(r"^[a-z]{2,}$", tld, re.IGNORECASE):
            return False

        return True

    @staticmethod
    def _is_suspicious_host(hostname: str) -> bool:
        """Check for SSRF and internal resource access attempts"""
        suspicious_patterns = [
            "localhost",
            "127.",
            "0.0.0.0",
            "[::]",
            "::1",
        ]

        hostname_lower = hostname.lower()

        # Check for localhost variants
        for pattern in suspicious_patterns:
            if pattern in hostname_lower:
                return True

        # Check if it's a private IP
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        except ValueError:
            pass

        # Check for private IP ranges in domain names
        private_ranges = ["10.", "172.16.", "172.31.", "192.168."]
        for private in private_ranges:
            if hostname_lower.startswith(private):
                return True

        return False


class DomainValidator(BaseModel):
    """Validate domain name format with security checks"""

    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Domain cannot be empty")

        # Remove whitespace
        domain = v.strip().lower()

        # Remove protocol if present
        domain = re.sub(r"^https?://", "", domain)
        domain = re.sub(r"^ftp://", "", domain)

        # Remove path, query, fragment
        domain = domain.split("/")[0]
        domain = domain.split("?")[0]
        domain = domain.split("#")[0]

        # Remove port
        if ":" in domain and not domain.startswith("["):  # Not IPv6
            domain = domain.split(":")[0]

        # Remove brackets from IPv6 (if any)
        domain = domain.strip("[]")

        # Check if it's actually an IP address
        try:
            ipaddress.ip_address(domain)
            raise ValueError(f"Expected domain name, got IP address: {domain}") from None
        except ValueError as e:
            if "Expected domain" in str(e):
                raise
            # Not an IP, continue with domain validation

        # Handle internationalized domain names (IDN)
        try:
            domain = idna.decode(domain)
        except Exception:
            pass

        # Check length
        if len(domain) > 253:
            raise ValueError("Domain name exceeds maximum length (253 characters)")

        if len(domain) < 3:
            raise ValueError("Domain name too short")

        # Check for null bytes
        if "\x00" in domain:
            raise ValueError("Domain contains null bytes")

        # Validate domain structure
        labels = domain.split(".")
        if len(labels) < 2:
            raise ValueError("Domain must have at least two labels (domain.tld)")

        # Validate each label
        for label in labels:
            if not label:
                raise ValueError("Domain contains empty label")

            if len(label) > 63:
                raise ValueError(f"Domain label exceeds maximum length: {label}")

            if label.startswith("-") or label.endswith("-"):
                raise ValueError(f"Domain label cannot start or end with hyphen: {label}")

            if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label, re.IGNORECASE):
                raise ValueError(f"Invalid characters in domain label: {label}")

        # Validate TLD
        tld = labels[-1]
        if len(tld) < 2:
            raise ValueError("TLD must be at least 2 characters")

        if not re.match(r"^[a-z]{2,}$", tld, re.IGNORECASE):
            raise ValueError(f"Invalid TLD format: {tld}")

        # Check for suspicious/internal domains
        if cls._is_suspicious_domain(domain):
            raise ValueError("Domain appears to be internal or suspicious")

        return domain

    @staticmethod
    def _is_suspicious_domain(domain: str) -> bool:
        """Check for internal/suspicious domains"""
        suspicious = [
            "localhost",
            ".local",
            ".internal",
            ".corp",
            ".home",
            ".lan",
            ".test",
            ".example",
            ".invalid",
        ]

        domain_lower = domain.lower()
        for pattern in suspicious:
            if domain_lower == pattern.lstrip(".") or domain_lower.endswith(pattern):
                return True

        return False


class IPValidator(BaseModel):
    """Validate IP address format (IPv4 and IPv6) with security checks"""

    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("IP address cannot be empty")

        # Remove whitespace and brackets
        ip_str = v.strip().strip("[]")

        # Check for null bytes
        if "\x00" in ip_str:
            raise ValueError("IP address contains null bytes")

        # Validate IP address format
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address format: {str(e)}") from e

        # Security checks
        if ip.is_loopback:
            raise ValueError("Loopback addresses are not allowed")

        if ip.is_private:
            raise ValueError("Private IP addresses are not allowed")

        if ip.is_link_local:
            raise ValueError("Link-local addresses are not allowed")

        if ip.is_reserved:
            raise ValueError("Reserved IP addresses are not allowed")

        if ip.is_multicast:
            raise ValueError("Multicast addresses are not allowed")

        if ip.is_unspecified:
            raise ValueError("Unspecified addresses are not allowed")

        # IPv4 specific checks
        if isinstance(ip, ipaddress.IPv4Address):
            # Check for 0.0.0.0
            if str(ip) == "0.0.0.0":
                raise ValueError("0.0.0.0 is not allowed")

            # Check for broadcast
            if ip.is_global and str(ip).endswith(".255"):
                raise ValueError("Broadcast addresses are not allowed")

        # IPv6 specific checks
        if isinstance(ip, ipaddress.IPv6Address):
            # Check for IPv4-mapped IPv6 addresses
            if ip.ipv4_mapped:
                raise ValueError("IPv4-mapped IPv6 addresses are not allowed")

        return str(ip)


# FastAPI dependency functions
def validate_url(
    url: Annotated[str, Query(description="URL to check", min_length=1, max_length=2048)],
) -> str:
    """FastAPI dependency for URL validation"""
    try:
        validator = URLValidator(url=url)
        return validator.url
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}") from e


def validate_domain(
    domain: Annotated[
        str,
        Query(description="Domain name to check", min_length=3, max_length=253),
    ],
) -> str:
    """FastAPI dependency for domain validation"""
    try:
        validator = DomainValidator(domain=domain)
        return validator.domain
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid domain: {str(e)}") from e


def validate_ip(
    ip: Annotated[
        str,
        Query(description="IP address to check", min_length=7, max_length=45),
    ],
) -> str:
    """FastAPI dependency for IP validation"""
    try:
        validator = IPValidator(ip=ip)
        return validator.ip
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {str(e)}") from e
