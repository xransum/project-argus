"""Job metadata and result persistence backed by DynamoDB and S3."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterable, cast

from ..aws.clients import get_dynamodb_resource, get_s3_client
from ..aws.config import get_settings
from .contracts import JobFamily, JobRecord, JobResultsPayload, JobState


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def expiry_timestamp(days: int = 90) -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())


def _jobs_table():
    settings = get_settings()
    return get_dynamodb_resource().Table(settings.jobs_table_name)


def result_key_for_job(job_id: str) -> str:
    return f"jobs/{job_id}/result.json"


def create_job_record(job_id: str, family: JobFamily, operation: str, total: int) -> JobRecord:
    now = utc_now_iso()
    record = JobRecord(
        job_id=job_id,
        job_family=family,
        operation=operation,
        status="pending",
        total=total,
        completed=0,
        failed=0,
        pending=total,
        created_at=now,
        updated_at=now,
        expires_at=expiry_timestamp(),
        progress_message="queued",
        error_samples=[],
    )
    _jobs_table().put_item(Item=record.model_dump())
    return record


def get_job_record(job_id: str) -> JobRecord | None:
    response = _jobs_table().get_item(Key={"job_id": job_id})
    item = response.get("Item")
    if not isinstance(item, dict):
        return None
    validated: JobRecord = JobRecord.model_validate(_normalize_numbers(item))
    return validated


def update_job_progress(
    job_id: str,
    *,
    status: JobState,
    completed: int,
    failed: int,
    pending: int,
    progress_message: str,
    last_error: str | None = None,
    error_samples: Iterable[str] | None = None,
    result_key: str | None = None,
) -> None:
    current = get_job_record(job_id)
    if current is None:
        raise KeyError(f"Job {job_id!r} not found")

    current_processed = current.completed + current.failed
    requested_processed = completed + failed
    if requested_processed < current_processed:
        return

    if current.result_key and result_key is None and status == "running":
        return

    if requested_processed == current_processed:
        completed = max(completed, current.completed)
        failed = max(failed, current.failed)
        pending = min(pending, current.pending)
        if current.result_key and result_key is None:
            result_key = current.result_key
        if current.status in {"completed", "partial", "failed"} and status == "running":
            status = current.status

    samples = list(error_samples or current.error_samples)[:5]
    updated = current.model_copy(
        update={
            "status": status,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "updated_at": utc_now_iso(),
            "progress_message": progress_message,
            "last_error": last_error,
            "error_samples": samples,
            "result_key": result_key or current.result_key,
        }
    )
    _jobs_table().put_item(Item=updated.model_dump())


def write_job_results(payload: JobResultsPayload) -> str:
    settings = get_settings()
    key = result_key_for_job(payload.job_id)
    get_s3_client().put_object(
        Bucket=settings.results_bucket_name,
        Key=key,
        Body=payload.model_dump_json(indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    return key


def read_job_results(job_id: str) -> dict[str, Any]:
    settings = get_settings()
    key = result_key_for_job(job_id)
    response = get_s3_client().get_object(Bucket=settings.results_bucket_name, Key=key)
    return cast(dict[str, Any], json.loads(response["Body"].read().decode("utf-8")))


def _normalize_numbers(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_numbers(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_numbers(item) for key, item in value.items()}
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    return value
