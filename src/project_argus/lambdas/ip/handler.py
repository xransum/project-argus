"""Lambda entrypoint for IP executor jobs."""

from __future__ import annotations

import json
from typing import Any

from ...shared.jobs.orchestration import execute_job_sync


def handler(event: dict[str, Any], _context: Any) -> dict[str, int]:
    results = []
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        results.append(
            execute_job_sync(
                message["family"], message["operation"], message["job_id"], message["inputs"]
            )
        )
    return {"records_processed": len(results)}
