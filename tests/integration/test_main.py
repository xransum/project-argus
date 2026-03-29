"""Functional tests for core web routes."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from project_argus.main import app

    with TestClient(app) as c:
        yield c


class TestHealthCheck:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_healthy_status(self, client):
        response = client.get("/health")
        data = response.json()
        assert data == {"status": "healthy"}


class TestAPIRoot:
    def test_api_root_returns_200(self, client):
        response = client.get("/api")
        assert response.status_code == 200

    def test_api_root_has_message(self, client):
        data = client.get("/api").json()
        assert data["message"] == "Project Argus API"

    def test_api_root_has_version(self, client):
        data = client.get("/api").json()
        assert "version" in data

    def test_api_root_has_endpoints(self, client):
        data = client.get("/api").json()
        assert "endpoints" in data
        assert "http" in data["endpoints"]
        assert "domain" in data["endpoints"]
        assert "ip" in data["endpoints"]
        assert "proxy" in data["endpoints"]

    def test_api_root_has_jobs(self, client):
        data = client.get("/api").json()
        assert "jobs" in data
        assert "status" in data["jobs"]
        assert "results" in data["jobs"]

    def test_api_root_has_documentation_link(self, client):
        data = client.get("/api").json()
        assert "documentation" in data
        assert data["documentation"] == "/docs"


class TestIndexPage:
    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_returns_html(self, client):
        response = client.get("/")
        assert "text/html" in response.headers.get("content-type", "")


class TestAppAvailability:
    def test_app_accessible_after_startup(self, client):
        response = client.get("/health")
        assert response.status_code == 200
