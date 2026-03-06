"""Integration tests for POST /api/proxy/check"""

from unittest.mock import AsyncMock, patch

from project_argus.models.proxy_models import ProxyCheckResponse, ProxyProtocolResult


def _make_proxy_response(ip: str, port: int, working: bool = False) -> ProxyCheckResponse:
    protocols = [
        ProxyProtocolResult(
            protocol=p,  # type: ignore[arg-type]
            working=working,
            response_time_ms=10.0 if working else None,
            error=None if working else "timeout",
        )
        for p in ("http", "https", "socks4", "socks5")
    ]
    return ProxyCheckResponse(ip=ip, port=port, is_open=working, protocols=protocols)


class TestProxyCheckEndpoint:
    def test_proxy_check_single(self, client):
        mock_result = _make_proxy_response("1.2.3.4", 8080, working=False)

        with patch(
            "project_argus.services.proxy_service.ProxyService.check",
            new=AsyncMock(return_value=mock_result),
        ):
            response = client.post(
                "/api/proxy/check",
                json={"proxies": ["1.2.3.4:8080"]},
            )

        assert response.status_code == 202
        data = response.json()
        assert data["job_type"] == "proxy/check"
        assert data["total"] == 1
        assert data["status"] == "pending"

    def test_proxy_check_multiple(self, client):
        mock_result = _make_proxy_response("1.2.3.4", 8080)

        with patch(
            "project_argus.services.proxy_service.ProxyService.check",
            new=AsyncMock(return_value=mock_result),
        ):
            response = client.post(
                "/api/proxy/check",
                json={"proxies": ["1.2.3.4:8080", "5.6.7.8:3128"]},
            )

        assert response.status_code == 202
        assert response.json()["total"] == 2

    def test_proxy_check_invalid_ip(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["192.168.1.1:8080"]},
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert "validation_errors" in detail

    def test_proxy_check_private_ip_blocked(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["10.0.0.1:1080"]},
        )
        assert response.status_code == 400

    def test_proxy_check_loopback_blocked(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["127.0.0.1:8080"]},
        )
        assert response.status_code == 400

    def test_proxy_check_invalid_port_too_high(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["1.2.3.4:99999"]},
        )
        assert response.status_code == 422

    def test_proxy_check_invalid_port_zero(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["1.2.3.4:0"]},
        )
        assert response.status_code == 422

    def test_proxy_check_malformed_entry(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["notanip"]},
        )
        assert response.status_code == 422

    def test_proxy_check_empty_list(self, client):
        response = client.post(
            "/api/proxy/check",
            json={"proxies": []},
        )
        assert response.status_code == 422

    def test_proxy_check_missing_body(self, client):
        response = client.post("/api/proxy/check")
        assert response.status_code == 422

    def test_proxy_check_returns_job_id(self, client):
        mock_result = _make_proxy_response("1.2.3.4", 8080)

        with patch(
            "project_argus.services.proxy_service.ProxyService.check",
            new=AsyncMock(return_value=mock_result),
        ):
            response = client.post(
                "/api/proxy/check",
                json={"proxies": ["1.2.3.4:8080"]},
            )

        data = response.json()
        assert "job_id" in data
        assert len(data["job_id"]) == 36  # UUID format

    def test_proxy_check_missing_ip(self, client):
        # ":8080" — empty IP part triggers the validator's missing-ip branch
        response = client.post(
            "/api/proxy/check",
            json={"proxies": [":8080"]},
        )
        assert response.status_code == 422

    def test_proxy_check_non_integer_port(self, client):
        # "1.2.3.4:abc" — non-integer port triggers the validator's port-parse branch
        response = client.post(
            "/api/proxy/check",
            json={"proxies": ["1.2.3.4:abc"]},
        )
        assert response.status_code == 422
