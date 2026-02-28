"""Test URL endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestURLEndpoints:
    """Functional tests for URL endpoints (all POST with JSON body)"""

    def test_url_status_endpoint(self, client: TestClient, sample_url: str):
        """Test URL status endpoint returns a job"""
        response = client.post("/api/url/status", json={"urls": [sample_url]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "url/status"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_url_headers_endpoint(self, client: TestClient, sample_url: str):
        """Test URL headers endpoint returns a job"""
        response = client.post("/api/url/headers", json={"urls": [sample_url]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "url/headers"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_url_status_bulk(self, client: TestClient, valid_urls: list):
        """Test URL status endpoint accepts multiple URLs"""
        response = client.post("/api/url/status", json={"urls": valid_urls})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_urls)

    def test_url_status_invalid_url(self, client: TestClient):
        """Test URL status with invalid URL returns 400"""
        response = client.post("/api/url/status", json={"urls": ["not-valid-url"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_url_status_empty_list(self, client: TestClient):
        """Test URL status with empty list returns 422"""
        response = client.post("/api/url/status", json={"urls": []})
        assert response.status_code == 422

    def test_url_status_missing_body(self, client: TestClient):
        """Test URL status with missing body returns 422"""
        response = client.post("/api/url/status")
        assert response.status_code == 422
