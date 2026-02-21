"""Pytest fixtures for testing the Project Argus API endpoints"""

import pytest
from fastapi.testclient import TestClient

from project_argus.main import app  # noqa: E401  # pylint: disable=import-error


@pytest.fixture
def client():
    """FastAPI test client fixture"""
    return TestClient(app)


@pytest.fixture
def sample_url():
    """Sample URL for testing"""
    return "https://example.com"


@pytest.fixture
def sample_domain():
    """Sample domain for testing"""
    return "example.com"


@pytest.fixture
def sample_ip():
    """Sample IP address for testing"""
    return "8.8.8.8"
