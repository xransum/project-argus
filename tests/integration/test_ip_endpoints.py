"""Test IP-related endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestIPEndpoints:
    """Functional tests for IP endpoints (all POST with JSON body)"""

    def test_ip_info_endpoint(self, client: TestClient, sample_ip: str):
        """Test IP info endpoint returns a job"""
        response = client.post("/api/ip/info", json={"ips": [sample_ip]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "ip/info"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_ip_bulk_multiple(self, client: TestClient, valid_ips: list):
        """Test IP endpoint accepts multiple IPs"""
        response = client.post("/api/ip/info", json={"ips": valid_ips})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_ips)

    def test_ip_invalid_format(self, client: TestClient):
        """Test IP endpoint with invalid IP returns 400"""
        response = client.post("/api/ip/info", json={"ips": ["not-an-ip"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_ip_private_blocked(self, client: TestClient):
        """Test that private IPs are blocked"""
        response = client.post("/api/ip/info", json={"ips": ["192.168.1.1"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_ip_empty_list(self, client: TestClient):
        """Test IP endpoint with empty list returns 422"""
        response = client.post("/api/ip/info", json={"ips": []})
        assert response.status_code == 422
