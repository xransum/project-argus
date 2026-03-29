"""Lambda entrypoint for job status reads."""

from __future__ import annotations

from typing import Any

from ...shared.jobs.orchestration import fetch_job_status


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return fetch_job_status(event["job_id"])
