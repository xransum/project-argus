"""Unit tests for services/job_service.py — enqueue_job, _run_job, and handlers."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from project_argus.services.job_service import (
    HANDLERS,
    _blacklist_check,
    _dns_lookup,
    _domain_hosting,
    _domain_info,
    _domain_subdomains,
    _geoip_lookup,
    _http_headers,
    _http_status,
    _ip_info,
    _now,
    _reputation_check,
    _ssl_certificate,
    _ssl_info,
    _whois_lookup,
    enqueue_job,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_db_ctx():
    """Return an async context manager that yields a mock connection."""
    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.executemany = AsyncMock()
    conn.executescript = AsyncMock()
    conn.commit = AsyncMock()

    @asynccontextmanager
    async def _ctx():
        yield conn

    return _ctx(), conn


# ---------------------------------------------------------------------------
# _now helper
# ---------------------------------------------------------------------------


class TestNow:
    def test_returns_iso_format_string(self):
        result = _now()
        assert isinstance(result, str)
        assert "T" in result  # ISO-8601 format includes T


# ---------------------------------------------------------------------------
# HANDLERS registry
# ---------------------------------------------------------------------------


class TestHandlersRegistry:
    def test_all_expected_job_types_present(self):
        expected = {
            "http/status",
            "http/headers",
            "dns/lookup",
            "whois/lookup",
            "geoip/lookup",
            "reputation/check",
            "blacklist/check",
            "ssl/info",
            "ssl/certificate",
            "domain/info",
            "domain/subdomains",
            "domain/hosting",
            "ip/info",
            "proxy/check",
        }
        assert set(HANDLERS.keys()) == expected

    def test_all_handlers_are_callable(self):
        for key, handler in HANDLERS.items():
            assert callable(handler), f"Handler for {key!r} is not callable"


# ---------------------------------------------------------------------------
# enqueue_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEnqueueJob:
    async def test_returns_job_id_string(self):
        fake_ctx, conn = _fake_db_ctx()
        with patch("project_argus.services.job_service.get_db", return_value=fake_ctx):
            with patch("project_argus.services.job_service.create_job", new_callable=AsyncMock):
                with patch("asyncio.create_task", side_effect=lambda coro: coro.close()):
                    job_id = await enqueue_job("http/status", ["https://example.com"])

        assert isinstance(job_id, str)
        assert len(job_id) == 36  # UUID4 format

    async def test_raises_for_unknown_job_type(self):
        with pytest.raises(ValueError, match="Unknown job type"):
            await enqueue_job("nonexistent/type", ["input"])

    async def test_fires_background_task(self):
        fake_ctx, conn = _fake_db_ctx()
        with patch("project_argus.services.job_service.get_db", return_value=fake_ctx):
            with patch("project_argus.services.job_service.create_job", new_callable=AsyncMock):
                with patch(
                    "asyncio.create_task", side_effect=lambda coro: coro.close()
                ) as mock_create_task:
                    await enqueue_job("http/status", ["https://example.com"])

        mock_create_task.assert_called_once()

    async def test_creates_job_in_db(self):
        fake_ctx, conn = _fake_db_ctx()
        mock_create_job = AsyncMock()
        with patch("project_argus.services.job_service.get_db", return_value=fake_ctx):
            with patch("project_argus.services.job_service.create_job", mock_create_job):
                with patch("asyncio.create_task", side_effect=lambda coro: coro.close()):
                    job_id = await enqueue_job("domain/info", ["example.com"])

        mock_create_job.assert_called_once()
        call_args = mock_create_job.call_args
        # job_id, job_type, inputs, now
        assert call_args[0][1] == job_id
        assert call_args[0][2] == "domain/info"
        assert call_args[0][3] == ["example.com"]


# ---------------------------------------------------------------------------
# _run_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRunJob:
    async def _make_fake_get_db(self, pending_rows=None):
        """Return a patch-ready get_db that yields a mock conn with pending rows."""
        if pending_rows is None:
            pending_rows = []

        conn = AsyncMock()

        @asynccontextmanager
        async def _ctx():
            yield conn

        return _ctx, conn, pending_rows

    async def test_unknown_handler_logs_error(self):
        """_run_job with an unknown job_type should log and return without crashing."""
        from project_argus.services import job_service

        # Directly patch HANDLERS to exclude the type we're testing
        with patch.dict(job_service.HANDLERS, {}, clear=True):
            # Should not raise
            await job_service._run_job("some-job-id", "unknown/type")

    async def test_processes_pending_results_success(self):
        from project_argus.services import job_service

        pending = [{"id": 1, "input": "https://example.com"}]

        mock_set_running = AsyncMock()
        mock_set_done = AsyncMock()
        mock_get_pending = AsyncMock(return_value=pending)
        mock_handler = AsyncMock(return_value={"url": "https://example.com", "status_code": 200})

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.services.job_service.get_db", side_effect=_fake_get_db):
            with patch("project_argus.services.job_service.get_pending_results", mock_get_pending):
                with patch(
                    "project_argus.services.job_service.set_result_running", mock_set_running
                ):
                    with patch("project_argus.services.job_service.set_result_done", mock_set_done):
                        with patch.dict(job_service.HANDLERS, {"http/status": mock_handler}):
                            await job_service._run_job("job-123", "http/status")

        mock_handler.assert_called_once_with("https://example.com")
        mock_set_done.assert_called_once()

    async def test_processes_pending_results_failure(self):
        """When a handler raises, set_result_error should be called."""
        from project_argus.services import job_service

        pending = [{"id": 2, "input": "bad-input"}]

        mock_set_running = AsyncMock()
        mock_set_error = AsyncMock()
        mock_get_pending = AsyncMock(return_value=pending)
        mock_handler = AsyncMock(side_effect=RuntimeError("Handler failed"))

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.services.job_service.get_db", side_effect=_fake_get_db):
            with patch("project_argus.services.job_service.get_pending_results", mock_get_pending):
                with patch(
                    "project_argus.services.job_service.set_result_running", mock_set_running
                ):
                    with patch(
                        "project_argus.services.job_service.set_result_error", mock_set_error
                    ):
                        with patch.dict(job_service.HANDLERS, {"http/status": mock_handler}):
                            await job_service._run_job("job-456", "http/status")

        mock_set_error.assert_called_once()
        error_call_args = mock_set_error.call_args[0]
        assert "Handler failed" in error_call_args[3]

    async def test_empty_pending_list_does_nothing(self):
        from project_argus.services import job_service

        mock_get_pending = AsyncMock(return_value=[])
        mock_handler = AsyncMock()

        @asynccontextmanager
        async def _fake_get_db():
            conn = AsyncMock()
            yield conn

        with patch("project_argus.services.job_service.get_db", side_effect=_fake_get_db):
            with patch("project_argus.services.job_service.get_pending_results", mock_get_pending):
                with patch.dict(job_service.HANDLERS, {"http/status": mock_handler}):
                    await job_service._run_job("job-789", "http/status")

        mock_handler.assert_not_called()


# ---------------------------------------------------------------------------
# Individual handler functions (cover the private _* wrappers)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHandlerFunctions:
    """Each handler should call the matching service method and return a dict."""

    async def _mock_service_method(self, method_path: str, return_value):
        """Patch *method_path* to return a mock with .model_dump() -> return_value."""
        mock_resp = MagicMock()
        mock_resp.model_dump.return_value = return_value
        return patch(method_path, new=AsyncMock(return_value=mock_resp))

    async def test_http_status_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._url_service.check_status",
            {"url": "https://example.com", "status_code": 200},
        )
        with p:
            result = await _http_status("https://example.com")
        assert result["status_code"] == 200

    async def test_http_headers_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._url_service.get_headers",
            {"url": "https://example.com", "headers": {}},
        )
        with p:
            result = await _http_headers("https://example.com")
        assert "url" in result

    async def test_dns_lookup_domain_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_dns_records",
            {"domain": "example.com"},
        )
        with p:
            result = await _dns_lookup("example.com")
        assert "domain" in result

    async def test_dns_lookup_ip_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.get_dns_records",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _dns_lookup("8.8.8.8")
        assert "ip" in result

    async def test_whois_lookup_domain_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_whois",
            {"domain": "example.com"},
        )
        with p:
            result = await _whois_lookup("example.com")
        assert "domain" in result

    async def test_whois_lookup_ip_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.get_whois",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _whois_lookup("8.8.8.8")
        assert "ip" in result

    async def test_geoip_lookup_domain_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_geoip",
            {"domain": "example.com"},
        )
        with p:
            result = await _geoip_lookup("example.com")
        assert "domain" in result

    async def test_geoip_lookup_ip_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.get_geoip",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _geoip_lookup("8.8.8.8")
        assert "ip" in result

    async def test_reputation_check_domain_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.check_reputation",
            {"domain": "example.com"},
        )
        with p:
            result = await _reputation_check("example.com")
        assert "domain" in result

    async def test_reputation_check_ip_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.check_reputation",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _reputation_check("8.8.8.8")
        assert "ip" in result

    async def test_blacklist_check_domain_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.check_blacklist",
            {"domain": "example.com"},
        )
        with p:
            result = await _blacklist_check("example.com")
        assert "domain" in result

    async def test_blacklist_check_ip_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.check_blacklist",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _blacklist_check("8.8.8.8")
        assert "ip" in result

    async def test_ssl_info_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.check_ssl",
            {"domain": "example.com", "has_ssl": True},
        )
        with p:
            result = await _ssl_info("example.com")
        assert "domain" in result

    async def test_ssl_certificate_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_ssl_certificate",
            {"domain": "example.com"},
        )
        with p:
            result = await _ssl_certificate("example.com")
        assert "domain" in result

    async def test_domain_info_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_domain_info",
            {"domain": "example.com"},
        )
        with p:
            result = await _domain_info("example.com")
        assert "domain" in result

    async def test_domain_subdomains_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_subdomains",
            {"domain": "example.com"},
        )
        with p:
            result = await _domain_subdomains("example.com")
        assert "domain" in result

    async def test_domain_hosting_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._domain_service.get_hosting_info",
            {"domain": "example.com"},
        )
        with p:
            result = await _domain_hosting("example.com")
        assert "domain" in result

    async def test_ip_info_handler(self):
        p = await self._mock_service_method(
            "project_argus.services.job_service._ip_service.get_ip_info",
            {"ip": "8.8.8.8"},
        )
        with p:
            result = await _ip_info("8.8.8.8")
        assert "ip" in result
