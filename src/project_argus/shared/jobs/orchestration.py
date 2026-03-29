"""Orchestration helpers for Lambda dispatch and job execution."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, cast

from ..aws.clients import get_lambda_client, get_sqs_client
from ..aws.config import get_settings
from .contracts import (
    JobFamily,
    JobQueueMessage,
    JobRecord,
    JobResultsPayload,
    JobState,
    JobSubmitRequest,
)
from .dispatch import get_handler
from .storage import create_job_record, read_job_results, update_job_progress, write_job_results

QUEUE_URLS: dict[JobFamily, Any] = {
    "http": lambda settings: settings.http_queue_url,
    "domain": lambda settings: settings.domain_queue_url,
    "ip": lambda settings: settings.ip_queue_url,
    "proxy": lambda settings: settings.proxy_queue_url,
}


def submit_job(request: JobSubmitRequest) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    record = create_job_record(job_id, request.family, request.operation, len(request.inputs))
    message = JobQueueMessage(
        job_id=job_id,
        family=request.family,
        operation=request.operation,
        inputs=request.inputs,
    )
    settings = get_settings()
    queue_url = QUEUE_URLS[request.family](settings)
    if not queue_url:
        raise RuntimeError(f"Queue URL missing for family {request.family!r}")
    get_sqs_client().send_message(QueueUrl=queue_url, MessageBody=message.model_dump_json())
    return {
        "job_id": job_id,
        "job_type": f"{request.family}/{request.operation}",
        "status": record.status,
        "total": record.total,
        "message": "Job enqueued. Poll /api/jobs/{job_id} for progress.",
    }


def fetch_job_status(job_id: str) -> dict[str, Any]:
    record = get_required_job(job_id)
    return {
        "job_id": record.job_id,
        "job_type": f"{record.job_family}/{record.operation}",
        "status": record.status,
        "total": record.total,
        "completed": record.completed,
        "failed": record.failed,
        "pending": record.pending,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "progress_message": record.progress_message,
        "last_error": record.last_error,
        "error_samples": record.error_samples,
        "progress_pct": 0
        if record.total == 0
        else round(((record.completed + record.failed) / record.total) * 100, 2),
    }


def fetch_job_results(job_id: str) -> dict[str, Any]:
    record = get_required_job(job_id)
    if not record.result_key:
        return {
            "job_id": job_id,
            "status": record.status,
            "message": "Results are not ready yet.",
        }
    return read_job_results(job_id)


def invoke_lambda(function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = get_lambda_client().invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    raw_payload = response["Payload"].read().decode("utf-8")
    return cast(dict[str, Any], json.loads(raw_payload) if raw_payload else {})


async def execute_job(
    family: str, operation: str, job_id: str, inputs: list[str]
) -> dict[str, Any]:
    handler = get_handler(family, operation)
    update_job_progress(
        job_id,
        status="running",
        completed=0,
        failed=0,
        pending=len(inputs),
        progress_message=f"starting {family}/{operation}",
    )

    items: list[dict[str, Any]] = []
    completed = 0
    failed = 0
    error_samples: list[str] = []

    for index, item in enumerate(inputs, start=1):
        try:
            result = await handler(item)
            items.append({"input": item, "status": "completed", "result": result, "error": None})
            completed += 1
            last_error = None
        except Exception as exc:
            error_text = str(exc)
            items.append({"input": item, "status": "failed", "result": None, "error": error_text})
            failed += 1
            last_error = error_text
            if error_text not in error_samples:
                error_samples.append(error_text)

        pending = len(inputs) - completed - failed
        update_job_progress(
            job_id,
            status="running",
            completed=completed,
            failed=failed,
            pending=pending,
            progress_message=f"processed {index} of {len(inputs)} items",
            last_error=last_error,
            error_samples=error_samples,
        )

    final_status: JobState = (
        "failed" if failed == len(inputs) else "partial" if failed else "completed"
    )
    payload = JobResultsPayload(
        job_id=job_id,
        job_type=f"{family}/{operation}",
        status=final_status,
        total=len(inputs),
        completed=completed,
        failed=failed,
        items=items,
    )
    result_key = write_job_results(payload)
    update_job_progress(
        job_id,
        status=final_status,
        completed=completed,
        failed=failed,
        pending=0,
        progress_message="job finished",
        last_error=error_samples[-1] if error_samples else None,
        error_samples=error_samples,
        result_key=result_key,
    )
    return cast(dict[str, Any], payload.model_dump())


def execute_job_sync(family: str, operation: str, job_id: str, inputs: list[str]) -> dict[str, Any]:
    return asyncio.run(execute_job(family, operation, job_id, inputs))


def get_required_job(job_id: str) -> JobRecord:
    from .storage import get_job_record

    record = get_job_record(job_id)
    if record is None:
        raise KeyError(f"Job {job_id!r} not found")
    return record
