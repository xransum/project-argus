"""Test Reputation Check API endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestReputationEndpoints:
    """Functional tests for reputation endpoints (POST with JSON body)"""

    def test_reputation_check_domain_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test reputation check endpoint with a domain returns a job"""
        response = client.post("/api/reputation/check", json={"targets": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "reputation/check"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_reputation_check_ip_endpoint(self, client: TestClient, sample_ip: str) -> None:
        """Test reputation check endpoint with an IP returns a job"""
        response = client.post("/api/reputation/check", json={"targets": [sample_ip]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "reputation/check"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_reputation_check_bulk_multiple(self, client: TestClient, valid_domains: list) -> None:
        """Test reputation check endpoint accepts multiple targets"""
        response = client.post("/api/reputation/check", json={"targets": valid_domains})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_domains)

    def test_reputation_check_invalid_target(self, client: TestClient) -> None:
        """Test reputation check endpoint with invalid target returns 400"""
        response = client.post("/api/reputation/check", json={"targets": ["invalid..target"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_reputation_check_private_ip_blocked(self, client: TestClient) -> None:
        """Test that private IPs are blocked"""
        response = client.post("/api/reputation/check", json={"targets": ["192.168.1.1"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_reputation_check_empty_list(self, client: TestClient) -> None:
        """Test reputation check endpoint with empty list returns 422"""
        response = client.post("/api/reputation/check", json={"targets": []})
        assert response.status_code == 422

    def test_reputation_check_missing_body(self, client: TestClient) -> None:
        """Test reputation check endpoint with missing body returns 422"""
        response = client.post("/api/reputation/check")
        assert response.status_code == 422
