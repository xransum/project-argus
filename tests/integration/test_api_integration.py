"""Integration tests for API endpoints using validators."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client."""
    from project_argus.main import app

    with TestClient(app) as c:
        yield c


class TestValidatorIntegration:
    """Test validators integrated with API endpoints."""

    def test_url_validation_rejects_localhost(self, client):
        """Localhost URLs should be rejected by the URL endpoint with HTTP 400."""
        response = client.post("/api/url/status", json={"urls": ["http://localhost"]})
        assert response.status_code == 400

    def test_domain_validation_rejects_ip_address(self, client):
        """IP addresses should be rejected by the domain endpoint with HTTP 400."""
        response = client.post("/api/domain/info", json={"domains": ["192.168.1.1"]})
        assert response.status_code == 400

    def test_ip_validation_rejects_private_ip(self, client):
        """Private IPs should be rejected by the IP endpoint with HTTP 400."""
        response = client.post("/api/ip/info", json={"ips": ["192.168.1.1"]})
        assert response.status_code == 400

    def test_url_validation_endpoint(self, client):
        """A valid URL list passes validation and returns a job (HTTP 202)."""
        from unittest.mock import AsyncMock, patch

        with patch(
            "project_argus.api.url.enqueue_job",
            new=AsyncMock(return_value="fake-job-id"),
        ):
            response = client.post("/api/url/status", json={"urls": ["https://example.com"]})

        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data

    def test_domain_validation_endpoint(self, client):
        """A valid domain list passes validation and returns a job (HTTP 202)."""
        from unittest.mock import AsyncMock, patch

        with patch(
            "project_argus.api.domain.enqueue_job",
            new=AsyncMock(return_value="fake-job-id"),
        ):
            response = client.post("/api/domain/info", json={"domains": ["example.com"]})

        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
