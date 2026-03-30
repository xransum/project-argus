"""Unit tests for monotonic job progress updates."""

from unittest.mock import MagicMock, patch

from project_argus.shared.jobs.contracts import JobRecord
from project_argus.shared.jobs.storage import update_job_progress


def _record(**overrides: object) -> JobRecord:
    payload = {
        "job_id": "job-123",
        "job_family": "http",
        "operation": "status",
        "status": "running",
        "total": 82,
        "completed": 20,
        "failed": 0,
        "pending": 62,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:10+00:00",
        "expires_at": 9999999999,
        "result_key": None,
        "progress_message": "processed 20 of 82 items",
        "last_error": None,
        "error_samples": [],
    }
    payload.update(overrides)
    return JobRecord.model_validate(payload)


def test_update_job_progress_ignores_regression():
    table = MagicMock()
    with patch("project_argus.shared.jobs.storage.get_job_record", return_value=_record()), patch(
        "project_argus.shared.jobs.storage._jobs_table", return_value=table
    ):
        update_job_progress(
            "job-123",
            status="running",
            completed=10,
            failed=0,
            pending=72,
            progress_message="processed 10 of 82 items",
        )

    table.put_item.assert_not_called()


def test_update_job_progress_preserves_completed_state_over_running_write():
    table = MagicMock()
    with patch(
        "project_argus.shared.jobs.storage.get_job_record",
        return_value=_record(
            status="completed",
            completed=82,
            pending=0,
            result_key="jobs/job-123/result.json",
            progress_message="job finished",
        ),
    ), patch("project_argus.shared.jobs.storage._jobs_table", return_value=table):
        update_job_progress(
            "job-123",
            status="running",
            completed=82,
            failed=0,
            pending=0,
            progress_message="processed 82 of 82 items",
        )

    table.put_item.assert_not_called()
