"""Test cases for Domain API endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestDomainEndpoints:
    """Functional tests for domain endpoints (all POST with JSON body)"""

    def test_domain_info_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain info endpoint returns a job"""
        response = client.post("/api/domain/info", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/info"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_domain_ssl_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain SSL endpoint returns a job"""
        response = client.post("/api/domain/ssl", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/ssl"
        assert data["total"] == 1

    def test_domain_dns_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain DNS endpoint returns a job"""
        response = client.post("/api/domain/dns", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/dns"
        assert data["total"] == 1

    def test_domain_whois_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain WHOIS endpoint returns a job"""
        response = client.post("/api/domain/whois", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/whois"

    def test_domain_geoip_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain GeoIP endpoint returns a job"""
        response = client.post("/api/domain/geoip", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/geoip"

    def test_domain_reputation_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain reputation endpoint returns a job"""
        response = client.post("/api/domain/reputation", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/reputation"

    def test_domain_blacklist_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain blacklist endpoint returns a job"""
        response = client.post("/api/domain/blacklist", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/blacklist"

    def test_domain_ssl_certificate_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain SSL certificate endpoint returns a job"""
        response = client.post("/api/domain/ssl-certificate", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/ssl-certificate"

    def test_domain_subdomains_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain subdomains endpoint returns a job"""
        response = client.post("/api/domain/subdomains", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/subdomains"

    def test_domain_hosting_endpoint(self, client: TestClient, sample_domain: str) -> None:
        """Test domain hosting endpoint returns a job"""
        response = client.post("/api/domain/hosting", json={"domains": [sample_domain]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "domain/hosting"

    def test_domain_bulk_multiple(self, client: TestClient, valid_domains: list) -> None:
        """Test domain endpoint accepts multiple domains"""
        response = client.post("/api/domain/info", json={"domains": valid_domains})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_domains)

    def test_domain_invalid_format(self, client: TestClient) -> None:
        """Test domain endpoint with invalid domain returns 400"""
        response = client.post("/api/domain/info", json={"domains": ["invalid..domain"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_domain_internal_blocked(self, client: TestClient) -> None:
        """Test that internal domains are blocked"""
        response = client.post("/api/domain/info", json={"domains": ["localhost"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_domain_empty_list(self, client: TestClient) -> None:
        """Test domain endpoint with empty list returns 422"""
        response = client.post("/api/domain/info", json={"domains": []})
        assert response.status_code == 422
