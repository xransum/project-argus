"""Shared test fixtures and configuration for Project Argus tests"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client"""
    from project_argus.main import app

    return TestClient(app)


@pytest.fixture
def sample_url():
    """Single sample URL for testing"""
    return "https://example.com"


@pytest.fixture
def sample_domain():
    """Sample domain for testing"""
    return "example.com"


@pytest.fixture
def sample_ip():
    """Sample IP address for testing"""
    return "8.8.8.8"


@pytest.fixture
def valid_urls():
    """Fixture providing valid URL test cases"""
    return [
        "https://example.com",
        "http://subdomain.example.com/path",
        "https://example.com:8080/path?query=value",
    ]


@pytest.fixture
def invalid_urls():
    """Fixture providing invalid URL test cases"""
    return [
        "",
        "not-a-url",
        "http://localhost",
        "http://127.0.0.1",
        "http://192.168.1.1",
    ]


@pytest.fixture
def valid_domains():
    """Fixture providing valid domain test cases"""
    return [
        "example.com",
        "subdomain.example.com",
        "my-domain.co.uk",
    ]


@pytest.fixture
def invalid_domains():
    """Fixture providing invalid domain test cases"""
    return [
        "",
        "localhost",
        "domain.local",
        "192.168.1.1",
        "-invalid.com",
    ]


@pytest.fixture
def valid_ips():
    """Fixture providing valid IP test cases"""
    return [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ]


@pytest.fixture
def invalid_ips():
    """Fixture providing invalid IP test cases"""
    return [
        "",
        "192.168.1.1",  # Private
        "127.0.0.1",  # Loopback
        "999.999.999.999",  # Invalid format
    ]
