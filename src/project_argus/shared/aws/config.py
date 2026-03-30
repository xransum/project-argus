"""AWS and local environment configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AwsSettings:
    region: str = os.getenv("AWS_REGION", "us-east-1")
    endpoint_url: str | None = os.getenv("AWS_ENDPOINT_URL") or None
    jobs_table_name: str = os.getenv("ARGUS_JOBS_TABLE", "project-argus-jobs")
    results_bucket_name: str = os.getenv("ARGUS_RESULTS_BUCKET", "project-argus-results")
    orchestrator_function_name: str = os.getenv(
        "ARGUS_ORCHESTRATOR_FUNCTION", "project-argus-orchestrator"
    )
    jobs_function_name: str = os.getenv("ARGUS_JOBS_FUNCTION", "project-argus-jobs")
    job_results_function_name: str = os.getenv(
        "ARGUS_JOB_RESULTS_FUNCTION", "project-argus-job-results"
    )
    http_queue_url: str = os.getenv("ARGUS_HTTP_QUEUE_URL", "")
    domain_queue_url: str = os.getenv("ARGUS_DOMAIN_QUEUE_URL", "")
    ip_queue_url: str = os.getenv("ARGUS_IP_QUEUE_URL", "")
    proxy_queue_url: str = os.getenv("ARGUS_PROXY_QUEUE_URL", "")
    worker_concurrency: int = int(os.getenv("ARGUS_WORKER_CONCURRENCY", "10"))


def get_settings() -> AwsSettings:
    return AwsSettings()
