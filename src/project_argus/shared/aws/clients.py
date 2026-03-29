"""Shared boto3 client factories for AWS and LocalStack."""

from __future__ import annotations

from functools import lru_cache

import boto3

from .config import get_settings


@lru_cache(maxsize=1)
def get_session() -> boto3.session.Session:
    settings = get_settings()
    return boto3.session.Session(region_name=settings.region)


def _client(service_name: str):
    settings = get_settings()
    return get_session().client(service_name, endpoint_url=settings.endpoint_url)


def get_lambda_client():
    return _client("lambda")


def get_s3_client():
    return _client("s3")


def get_sqs_client():
    return _client("sqs")


def get_dynamodb_resource():
    settings = get_settings()
    return get_session().resource("dynamodb", endpoint_url=settings.endpoint_url)
