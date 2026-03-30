"""Unit tests for concurrent job orchestration behavior."""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from project_argus.shared.jobs.orchestration import execute_job


@pytest.mark.asyncio
async def test_execute_job_preserves_input_order_for_concurrent_batches():
    inputs = ["first", "second", "third"]
    delays = {"first": 0.03, "second": 0.0, "third": 0.01}

    async def handler(item: str) -> dict[str, str]:
        await asyncio.sleep(delays[item])
        return {"seen": item}

    progress_updates: list[dict[str, object]] = []

    def record_progress(job_id: str, **kwargs: object) -> None:
        progress_updates.append({"job_id": job_id, **kwargs})

    with patch("project_argus.shared.jobs.orchestration.get_handler", return_value=handler), patch(
        "project_argus.shared.jobs.orchestration.get_settings",
        return_value=SimpleNamespace(worker_concurrency=3),
    ), patch(
        "project_argus.shared.jobs.orchestration.update_job_progress", side_effect=record_progress
    ), patch(
        "project_argus.shared.jobs.orchestration.write_job_results",
        return_value="jobs/job-123/result.json",
    ):
        payload = await execute_job("domain", "dns", "job-123", inputs)

    assert [item["input"] for item in payload["items"]] == inputs
    assert [item["result"]["seen"] for item in payload["items"]] == inputs
    assert payload["completed"] == 3
    assert payload["failed"] == 0
    assert progress_updates[-1]["status"] == "completed"
