"""Validation and routing tests for the migrated family-based API."""

from unittest.mock import patch


def _submitted(job_type: str, total: int = 1) -> dict:
    return {
        "job_id": "job-123",
        "job_type": job_type,
        "status": "pending",
        "total": total,
        "message": "Job enqueued. Poll /api/jobs/{job_id} for progress.",
    }


def test_http_status_route_invokes_orchestrator(client):
    with patch(
        "project_argus.web.api.common.invoke_lambda", return_value=_submitted("http/status")
    ) as mock_invoke:
        response = client.post("/api/http/status", json={"urls": ["https://example.com"]})

    assert response.status_code == 202
    assert response.json()["job_type"] == "http/status"
    mock_invoke.assert_called_once()


def test_domain_dns_route_invokes_orchestrator(client):
    with patch(
        "project_argus.web.api.common.invoke_lambda", return_value=_submitted("domain/dns")
    ) as mock_invoke:
        response = client.post("/api/domain/dns", json={"domains": ["example.com"]})

    assert response.status_code == 202
    assert response.json()["job_type"] == "domain/dns"
    mock_invoke.assert_called_once()


def test_ip_geoip_route_invokes_orchestrator(client):
    with patch(
        "project_argus.web.api.common.invoke_lambda", return_value=_submitted("ip/geoip")
    ) as mock_invoke:
        response = client.post("/api/ip/geoip", json={"ips": ["8.8.8.8"]})

    assert response.status_code == 202
    assert response.json()["job_type"] == "ip/geoip"
    mock_invoke.assert_called_once()


def test_proxy_check_route_invokes_orchestrator(client):
    with patch(
        "project_argus.web.api.common.invoke_lambda", return_value=_submitted("proxy/check")
    ) as mock_invoke:
        response = client.post("/api/proxy/check", json={"proxies": ["1.2.3.4:8080"]})

    assert response.status_code == 202
    assert response.json()["job_type"] == "proxy/check"
    mock_invoke.assert_called_once()


def test_domain_route_rejects_invalid_domain(client):
    response = client.post("/api/domain/info", json={"domains": ["invalid..domain"]})
    assert response.status_code == 400
    assert "validation_errors" in response.json()["detail"]


def test_ip_route_rejects_private_ip(client):
    response = client.post("/api/ip/info", json={"ips": ["192.168.1.1"]})
    assert response.status_code == 400


def test_http_route_rejects_localhost(client):
    response = client.post("/api/http/status", json={"urls": ["http://localhost"]})
    assert response.status_code == 400


def test_proxy_route_rejects_private_ip(client):
    response = client.post("/api/proxy/check", json={"proxies": ["10.0.0.1:8080"]})
    assert response.status_code == 400


def test_jobs_status_route_uses_jobs_lambda(client):
    payload = {
        "job_id": "job-123",
        "job_type": "http/status",
        "status": "running",
        "total": 3,
        "completed": 1,
        "failed": 0,
        "pending": 2,
        "created_at": "2024-01-01T00:00:00+00:00",
        "updated_at": "2024-01-01T00:00:01+00:00",
        "progress_message": "processed 1 of 3 items",
        "last_error": None,
        "error_samples": [],
        "progress_pct": 33.33,
    }
    with patch("project_argus.web.api.common.invoke_lambda", return_value=payload):
        response = client.get("/api/jobs/job-123")

    assert response.status_code == 200
    assert response.json()["progress_message"] == "processed 1 of 3 items"


def test_jobs_results_route_uses_results_lambda(client):
    payload = {"job_id": "job-123", "status": "completed", "items": []}
    with patch("project_argus.web.api.common.invoke_lambda", return_value=payload):
        response = client.get("/api/jobs/job-123/results")

    assert response.status_code == 200
    assert response.json()["job_id"] == "job-123"
