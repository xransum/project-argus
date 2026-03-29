"""Shared request validation and Lambda orchestration helpers."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException
from pydantic import ValidationError

from ...shared.aws.config import get_settings
from ...shared.jobs.contracts import JobFamily, JobSubmitRequest, JobSubmittedResponse
from ...shared.jobs.orchestration import invoke_lambda


def validate_many(values: list[str], label: str, validator: Callable[[str], str]) -> list[str]:
    sanitized: list[str] = []
    errors: list[dict[str, object]] = []
    for index, raw in enumerate(values):
        try:
            sanitized.append(validator(raw))
        except (ValidationError, ValueError) as exc:
            if isinstance(exc, ValidationError):
                message = exc.errors()[0]["msg"]
            else:
                message = str(exc)
            errors.append({"index": index, label: raw, "error": message})
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return sanitized


def submit_job(family: JobFamily, operation: str, inputs: list[str]) -> JobSubmittedResponse:
    settings = get_settings()
    payload = JobSubmitRequest(family=family, operation=operation, inputs=inputs).model_dump()
    response = invoke_lambda(settings.orchestrator_function_name, payload)
    validated: JobSubmittedResponse = JobSubmittedResponse.model_validate(response)
    return validated


def get_job_status(job_id: str) -> dict[str, Any]:
    settings = get_settings()
    return invoke_lambda(settings.jobs_function_name, {"job_id": job_id})


def get_job_results(job_id: str) -> dict[str, Any]:
    settings = get_settings()
    return invoke_lambda(settings.job_results_function_name, {"job_id": job_id})
