"""Proxy family routes."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, HTTPException

from ...models.job_models import JobCreatedResponse
from ...models.proxy_models import ProxyBulkRequest
from ...utils.validators import validate_ip
from .common import submit_job

router = APIRouter(tags=["Proxy"])


def _validate(proxies: list[str]) -> list[str]:
    errors = []
    validated = []
    for index, proxy in enumerate(proxies):
        ip, _, port_str = proxy.rpartition(":")
        try:
            validate_ip(ip)
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("Port must be in range 1-65535")
        except ValueError as exc:
            errors.append({"index": index, "proxy": proxy, "error": str(exc)})
            continue
        validated.append(proxy)
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    return validated


@router.post("/check", response_model=JobCreatedResponse, status_code=202)
async def bulk_proxy_check(body: ProxyBulkRequest) -> JobCreatedResponse:
    response = submit_job("proxy", "check", _validate(body.proxies))
    return cast(JobCreatedResponse, JobCreatedResponse.model_validate(response.model_dump()))
