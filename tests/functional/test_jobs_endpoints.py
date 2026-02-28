"""Functional tests for the /jobs API endpoints."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from project_argus.main import app

    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_job_row(
    job_id="job-abc",
    job_type="url/status",
    status="running",
    total=3,
    completed=1,
    failed=1,
    created_at="2024-01-01T00:00:00",
    updated_at="2024-01-01T01:00:00",
):
    return {
        "id": job_id,
        "job_type": job_type,
        "status": status,
        "total": total,
        "completed": completed,
        "failed": failed,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _make_result_rows(job_id="job-abc", count=2):
    import json

    rows = []
    for i in range(1, count + 1):
        rows.append(
            {
                "id": i,
                "job_id": job_id,
                "input": f"https://example{i}.com",
                "status": "completed",
                "result": json.dumps({"url": f"https://example{i}.com", "status_code": 200}),
                "error": None,
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T01:00:00",
            }
        )
    return rows


# ---------------------------------------------------------------------------
# GET /jobs/{job_id}/status
# ---------------------------------------------------------------------------


class TestGetJobStatus:
    def test_returns_200_with_job_found(self, client):
        job = _make_job_row()

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                response = client.get("/jobs/job-abc/status")

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == "job-abc"
        assert data["job_type"] == "url/status"
        assert data["status"] == "running"
        assert data["total"] == 3
        assert data["completed"] == 1
        assert data["failed"] == 1
        assert data["pending"] == 1  # total - completed - failed

    def test_returns_404_when_job_not_found(self, client):
        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=None):
                response = client.get("/jobs/nonexistent-id/status")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_pending_count_floored_at_zero(self, client):
        """pending = max(0, total - completed - failed) must not go negative."""
        job = _make_job_row(total=2, completed=2, failed=1)  # completed+failed > total

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                response = client.get("/jobs/job-abc/status")

        assert response.status_code == 200
        assert response.json()["pending"] == 0


# ---------------------------------------------------------------------------
# GET /jobs/{job_id}/results
# ---------------------------------------------------------------------------


class TestGetJobResults:
    def test_returns_200_with_results(self, client):
        job = _make_job_row()
        rows = _make_result_rows(count=2)

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                with patch(
                    "project_argus.api.jobs.get_results_page",
                    new_callable=AsyncMock,
                    return_value=rows,
                ):
                    response = client.get("/jobs/job-abc/results")

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == "job-abc"
        assert data["count"] == 2
        assert data["next_token"] is None
        assert len(data["items"]) == 2

    def test_returns_404_when_job_not_found(self, client):
        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=None):
                response = client.get("/jobs/missing-job/results")

        assert response.status_code == 404

    def test_returns_400_for_invalid_next_token(self, client):
        response = client.get("/jobs/job-abc/results?nextToken=not-a-number")
        assert response.status_code == 400
        assert "Invalid nextToken" in response.json()["detail"]

    def test_next_token_returned_when_full_page(self, client):
        """When rows == PAGE_SIZE, a next_token should be included."""
        from project_argus.api.jobs import PAGE_SIZE

        job = _make_job_row()
        # Create PAGE_SIZE rows
        rows = _make_result_rows(count=PAGE_SIZE)
        # Assign sequential IDs
        for i, r in enumerate(rows, start=1):
            r["id"] = i

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                with patch(
                    "project_argus.api.jobs.get_results_page",
                    new_callable=AsyncMock,
                    return_value=rows,
                ):
                    response = client.get("/jobs/job-abc/results")

        assert response.status_code == 200
        data = response.json()
        assert data["next_token"] == str(PAGE_SIZE)

    def test_accepts_valid_next_token(self, client):
        job = _make_job_row()
        rows = _make_result_rows(count=1)

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                with patch(
                    "project_argus.api.jobs.get_results_page",
                    new_callable=AsyncMock,
                    return_value=rows,
                ) as mock_page:
                    response = client.get("/jobs/job-abc/results?nextToken=50")

        assert response.status_code == 200
        # Verify after_id=50 was passed
        call_kwargs = mock_page.call_args
        assert call_kwargs[1].get("after_id") == 50 or call_kwargs[0][2] == 50

    def test_result_items_have_expected_fields(self, client):
        job = _make_job_row()
        rows = _make_result_rows(count=1)

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.api.jobs.get_db", side_effect=_fake_get_db):
            with patch("project_argus.api.jobs.get_job", new_callable=AsyncMock, return_value=job):
                with patch(
                    "project_argus.api.jobs.get_results_page",
                    new_callable=AsyncMock,
                    return_value=rows,
                ):
                    response = client.get("/jobs/job-abc/results")

        item = response.json()["items"][0]
        assert "id" in item
        assert "input" in item
        assert "status" in item
        assert "created_at" in item
        assert "updated_at" in item
