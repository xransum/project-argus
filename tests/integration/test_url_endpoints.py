"""Test HTTP/URL endpoints"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _submitted(job_type: str, total: int = 1) -> dict:
    return {
        "job_id": "job-123",
        "job_type": job_type,
        "status": "pending",
        "total": total,
        "message": "Job enqueued. Poll /api/jobs/{job_id} for progress.",
    }


@pytest.mark.functional
class TestHTTPEndpoints:
    """Functional tests for HTTP endpoints (all POST with JSON body)"""

    def test_http_status_endpoint(self, client: TestClient, sample_url: str):
        """Test HTTP status endpoint returns a job"""
        with patch(
            "project_argus.web.api.common.invoke_lambda", return_value=_submitted("http/status")
        ):
            response = client.post("/api/http/status", json={"urls": [sample_url]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "http/status"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_http_headers_endpoint(self, client: TestClient, sample_url: str):
        """Test HTTP headers endpoint returns a job"""
        with patch(
            "project_argus.web.api.common.invoke_lambda", return_value=_submitted("http/headers")
        ):
            response = client.post("/api/http/headers", json={"urls": [sample_url]})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["job_type"] == "http/headers"
        assert data["status"] == "pending"
        assert data["total"] == 1

    def test_http_status_bulk(self, client: TestClient, valid_urls: list):
        """Test HTTP status endpoint accepts multiple URLs"""
        with patch(
            "project_argus.web.api.common.invoke_lambda",
            return_value=_submitted("http/status", total=len(valid_urls)),
        ):
            response = client.post("/api/http/status", json={"urls": valid_urls})
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == len(valid_urls)

    def test_http_status_invalid_url(self, client: TestClient):
        """Test HTTP status with invalid URL returns 400"""
        response = client.post("/api/http/status", json={"urls": ["not-valid-url"]})
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "validation_errors" in data["detail"]

    def test_http_status_empty_list(self, client: TestClient):
        """Test HTTP status with empty list returns 422"""
        response = client.post("/api/http/status", json={"urls": []})
        assert response.status_code == 422

    def test_http_status_missing_body(self, client: TestClient):
        """Test HTTP status with missing body returns 422"""
        response = client.post("/api/http/status")
        assert response.status_code == 422
