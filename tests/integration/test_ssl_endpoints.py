"""Test SSL/TLS Check API endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestSSLEndpoints:
    """Functional tests for ssl endpoints (POST with JSON body)"""

    def test_ssl_info_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test ssl info endpoint returns a job"""
        response = client.post("/api/ssl/info", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "ssl/info"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_ssl_certificate_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test ssl certificate endpoint returns a job"""
        response = client.post("/api/ssl/certificate", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "ssl/certificate"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_ssl_info_bulk_multiple(self, client: TestClient, valid_domains: list) -> None:
        """Test ssl info endpoint accepts multiple domains"""
        response = client.post("/api/ssl/info", json={"domains": valid_domains})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_domains)

    def test_ssl_info_invalid_domain(self, client: TestClient) -> None:
        """Test ssl info endpoint with invalid domain returns 400"""
        response = client.post("/api/ssl/info", json={"domains": ["invalid..domain"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_ssl_info_internal_blocked(self, client: TestClient) -> None:
        """Test that internal domains are blocked"""
        response = client.post("/api/ssl/info", json={"domains": ["localhost"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_ssl_certificate_invalid_domain(self, client: TestClient) -> None:
        """Test ssl certificate endpoint with invalid domain returns 400"""
        response = client.post("/api/ssl/certificate", json={"domains": ["invalid..domain"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_ssl_info_empty_list(self, client: TestClient) -> None:
        """Test ssl info endpoint with empty list returns 422"""
        response = client.post("/api/ssl/info", json={"domains": []})
        assert response.status_code == 422

    def test_ssl_certificate_empty_list(self, client: TestClient) -> None:
        """Test ssl certificate endpoint with empty list returns 422"""
        response = client.post("/api/ssl/certificate", json={"domains": []})
        assert response.status_code == 422

    def test_ssl_info_missing_body(self, client: TestClient) -> None:
        """Test ssl info endpoint with missing body returns 422"""
        response = client.post("/api/ssl/info")
        assert response.status_code == 422
