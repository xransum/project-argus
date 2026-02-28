"""Test URL endpoints"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.functional
class TestURLEndpoints:
    """Functional tests for URL validation endpoints"""

    def test_url_status_endpoint(self, client: TestClient, sample_url: str):
        """Test URL status endpoint"""
        response = client.get(f"/api/url/status?url={sample_url}")
        assert response.status_code == 200
        assert "status_code" in response.json()

    def test_url_headers_endpoint(self, client: TestClient, sample_url: str):
        """Test URL headers endpoint"""
        response = client.get(f"/api/url/headers?url={sample_url}")
        assert response.status_code == 200
        assert "headers" in response.json()

    def test_url_status_invalid_url(self, client: TestClient):
        """Test URL status with invalid URL"""
        response = client.get("/api/url/status?url=invalid-url")
        assert response.status_code in [400, 422]
