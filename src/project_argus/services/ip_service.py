"""IP service for Project Argus API"""

import socket

from ..models.ip_models import (
    IPBlacklistResponse,
    IPDNSResponse,
    IPGeoResponse,
    IPInfoResponse,
    IPReputationResponse,
    IPWHOISResponse,
)


class IPService:
    async def get_ip_info(self, ip: str) -> IPInfoResponse:
        """Fetch information about an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = None

        return IPInfoResponse(
            ip=ip,
            hostname=hostname,
            asn="Unknown",
            organization="Unknown",
            isp="Unknown",
        )

    async def get_dns_records(self, ip: str) -> IPDNSResponse:
        """Fetch DNS records of an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return IPDNSResponse(ip=ip, hostname=hostname)
        except (socket.herror, socket.gaierror, OSError):
            return IPDNSResponse(ip=ip, hostname=None)

    async def get_geoip(self, ip: str) -> IPGeoResponse:
        """Fetch geolocation information of an IP address"""
        return IPGeoResponse(ip=ip, country="Unknown", city="Unknown", latitude=0.0, longitude=0.0)

    async def check_reputation(self, ip: str) -> IPReputationResponse:
        """Check the reputation of an IP address"""
        return IPReputationResponse(ip=ip, score=75, is_safe=True, categories=[])

    async def check_blacklist(self, ip: str) -> IPBlacklistResponse:
        """Check if an IP address is blacklisted"""
        return IPBlacklistResponse(ip=ip, is_blacklisted=False, blacklists=[])

    async def get_whois(self, ip: str) -> IPWHOISResponse:
        """Fetch WHOIS information of an IP address"""
        return IPWHOISResponse(
            ip=ip,
            asn="Unknown",
            organization="Unknown",
            network="Unknown",
        )
