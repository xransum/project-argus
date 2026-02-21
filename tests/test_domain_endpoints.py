"""Test cases for Domain API endpoints"""

from fastapi.testclient import TestClient


def test_domain_info_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain info endpoint"""
    response = client.get(f"/api/v1/domain/info?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert data["domain"] == sample_domain


def test_domain_ssl_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain SSL endpoint"""
    response = client.get(f"/api/v1/domain/ssl?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "has_ssl" in data
    assert "valid" in data
    assert isinstance(data["has_ssl"], bool)
    assert isinstance(data["valid"], bool)


def test_domain_dns_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain DNS endpoint"""
    response = client.get(f"/api/v1/domain/dns?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "record_type" in data
    assert "records" in data
    assert isinstance(data["records"], list)


def test_domain_dns_endpoint_with_type(client: TestClient, sample_domain: str) -> None:
    """Test domain DNS endpoint with specific record type"""
    response = client.get(f"/api/v1/domain/dns?domain={sample_domain}&record_type=MX")
    assert response.status_code == 200
    data = response.json()
    assert data["record_type"] == "MX"


def test_domain_whois_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain WHOIS endpoint"""
    response = client.get(f"/api/v1/domain/whois?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data


def test_domain_geoip_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain GeoIP endpoint"""
    response = client.get(f"/api/v1/domain/geoip?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "ip" in data


def test_domain_reputation_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain reputation endpoint"""
    response = client.get(f"/api/v1/domain/reputation?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "score" in data
    assert "is_safe" in data


def test_domain_blacklist_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain blacklist endpoint"""
    response = client.get(f"/api/v1/domain/blacklist?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "is_blacklisted" in data
    assert "blacklists" in data


def test_domain_ssl_certificate_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain SSL certificate endpoint"""
    response = client.get(f"/api/v1/domain/ssl-certificate?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "subject" in data
    assert "issuer" in data


def test_domain_subdomains_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain subdomains endpoint"""
    response = client.get(f"/api/v1/domain/subdomains?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "subdomains" in data
    assert isinstance(data["subdomains"], list)


def test_domain_hosting_endpoint(client: TestClient, sample_domain: str) -> None:
    """Test domain hosting endpoint"""
    response = client.get(f"/api/v1/domain/hosting?domain={sample_domain}")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "ip_address" in data


def test_domain_invalid_format(client: TestClient) -> None:
    """Test domain endpoint with invalid domain format"""
    response = client.get("/api/v1/domain/info?domain=invalid..domain")
    assert response.status_code == 400


def test_domain_internal_blocked(client: TestClient) -> None:
    """Test that internal domains are blocked"""
    response = client.get("/api/v1/domain/info?domain=localhost")
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
