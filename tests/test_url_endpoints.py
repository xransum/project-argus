"""Test URL endpoints"""

from fastapi.testclient import TestClient


def test_url_status_endpoint(client: TestClient, sample_url: str):
    """Test URL status endpoint"""
    response = client.get(f"/api/v1/url/status?url={sample_url}")
    assert response.status_code == 200
    assert "status_code" in response.json()


def test_url_headers_endpoint(client: TestClient, sample_url: str):
    """Test URL headers endpoint"""
    response = client.get(f"/api/v1/url/headers?url={sample_url}")
    assert response.status_code == 200
    assert "headers" in response.json()


def test_url_status_invalid_url(client: TestClient):
    """Test URL status with invalid URL"""
    response = client.get("/api/v1/url/status?url=invalid-url")
    assert response.status_code in [400, 422]
