"""Lambda entrypoint for job orchestration."""

from __future__ import annotations

from typing import Any

from ...shared.jobs.contracts import JobSubmitRequest
from ...shared.jobs.orchestration import submit_job


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    request = JobSubmitRequest.model_validate(event)
    return submit_job(request)
