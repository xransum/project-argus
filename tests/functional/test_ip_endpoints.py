"""Test IP-related endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestIPEndpoints:
    """Functional tests for IP validation endpoints"""

    def test_ip_info_endpoint(self, client: TestClient, sample_ip: str):
        """Test IP info endpoint"""
        response = client.get(f"/api/v1/ip/info?ip={sample_ip}")
        assert response.status_code == 200

    def test_ip_geoip_endpoint(self, client: TestClient, sample_ip: str):
        """Test IP geoip endpoint"""
        response = client.get(f"/api/v1/ip/geoip?ip={sample_ip}")
        assert response.status_code == 200
        assert "country" in response.json() or "location" in response.json()

    def test_ip_reputation_endpoint(self, client: TestClient, sample_ip: str):
        """Test IP reputation endpoint"""
        response = client.get(f"/api/v1/ip/reputation?ip={sample_ip}")
        assert response.status_code == 200
