"""Lambda entrypoint for final job result reads."""

from __future__ import annotations

from typing import Any

from ...shared.jobs.orchestration import fetch_job_results


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return fetch_job_results(event["job_id"])
