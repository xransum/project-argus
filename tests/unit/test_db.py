"""Unit tests for db.py — SQLite database layer for Project Argus."""

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

import project_argus.db as db_module
from project_argus.db import (
    create_job,
    get_job,
    get_pending_results,
    get_results_page,
    init_db,
    set_result_done,
    set_result_error,
    set_result_running,
    update_job_counts,
)

# ---------------------------------------------------------------------------
# Fixtures — in-memory aiosqlite database
# ---------------------------------------------------------------------------


@pytest.fixture
async def mem_db():
    """Provide a fresh in-memory aiosqlite connection with the schema applied."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.executescript(db_module._DDL)
        await conn.commit()
        yield conn


# ---------------------------------------------------------------------------
# init_db
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestInitDB:
    async def test_init_db_creates_tables(self):
        """init_db should run without error and create the jobs/job_results tables."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tf:
            tmp_path = Path(tf.name)

        # Patch DB_PATH to use a temp file
        with patch.object(db_module, "DB_PATH", tmp_path):
            await init_db()

        # Verify tables exist
        conn = sqlite3.connect(str(tmp_path))
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        conn.close()
        tmp_path.unlink(missing_ok=True)

        assert "jobs" in tables
        assert "job_results" in tables

    async def test_init_db_idempotent(self):
        """Calling init_db twice should not raise (IF NOT EXISTS guards)."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tf:
            tmp_path = Path(tf.name)

        with patch.object(db_module, "DB_PATH", tmp_path):
            await init_db()
            await init_db()  # second call must not raise

        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# create_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCreateJob:
    async def test_creates_job_row(self, mem_db):
        await create_job(
            mem_db, "job-1", "url/status", ["https://example.com"], "2024-01-01T00:00:00"
        )

        async with mem_db.execute("SELECT * FROM jobs WHERE id = 'job-1'") as cur:
            row = await cur.fetchone()

        assert row is not None
        assert row["id"] == "job-1"
        assert row["job_type"] == "url/status"
        assert row["status"] == "pending"
        assert row["total"] == 1

    async def test_creates_result_rows(self, mem_db):
        inputs = ["https://a.example.com", "https://b.example.com"]
        await create_job(mem_db, "job-2", "url/status", inputs, "2024-01-01T00:00:00")

        async with mem_db.execute("SELECT * FROM job_results WHERE job_id = 'job-2'") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 2
        inputs_in_db = {r["input"] for r in rows}
        assert inputs_in_db == set(inputs)

    async def test_creates_job_with_empty_inputs(self, mem_db):
        await create_job(mem_db, "job-3", "domain/info", [], "2024-01-01T00:00:00")

        async with mem_db.execute("SELECT total FROM jobs WHERE id = 'job-3'") as cur:
            row = await cur.fetchone()

        assert row["total"] == 0


# ---------------------------------------------------------------------------
# get_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetJob:
    async def test_returns_job_dict(self, mem_db):
        await create_job(mem_db, "job-10", "url/status", ["https://example.com"], "2024-01-01")

        result = await get_job(mem_db, "job-10")
        assert result is not None
        assert result["id"] == "job-10"

    async def test_returns_none_for_missing_job(self, mem_db):
        result = await get_job(mem_db, "nonexistent-id")
        assert result is None


# ---------------------------------------------------------------------------
# update_job_counts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestUpdateJobCounts:
    async def _create_and_populate(self, conn, job_id, inputs, now="2024-01-01T00:00:00"):
        await create_job(conn, job_id, "url/status", inputs, now)
        # Fetch the result IDs
        async with conn.execute("SELECT id FROM job_results WHERE job_id = ?", (job_id,)) as cur:
            return [r["id"] for r in await cur.fetchall()]

    async def test_status_flips_to_completed_when_all_done(self, mem_db):
        result_ids = await self._create_and_populate(mem_db, "job-a", ["item1"])

        # Mark result as completed
        await mem_db.execute(
            "UPDATE job_results SET status='completed' WHERE id=?", (result_ids[0],)
        )
        await mem_db.commit()

        await update_job_counts(mem_db, "job-a", "2024-01-02T00:00:00")

        job = await get_job(mem_db, "job-a")
        assert job["status"] == "completed"
        assert job["completed"] == 1

    async def test_status_flips_to_failed_when_all_failed(self, mem_db):
        result_ids = await self._create_and_populate(mem_db, "job-b", ["item1"])

        await mem_db.execute("UPDATE job_results SET status='failed' WHERE id=?", (result_ids[0],))
        await mem_db.commit()

        await update_job_counts(mem_db, "job-b", "2024-01-02T00:00:00")

        job = await get_job(mem_db, "job-b")
        assert job["status"] == "failed"
        assert job["failed"] == 1

    async def test_status_stays_running_while_pending_exists(self, mem_db):
        await self._create_and_populate(mem_db, "job-c", ["item1", "item2"])

        # Mark one as completed, one stays pending
        await mem_db.execute(
            "UPDATE job_results SET status='completed' WHERE input='item1' AND job_id='job-c'"
        )
        await mem_db.commit()

        await update_job_counts(mem_db, "job-c", "2024-01-02T00:00:00")

        job = await get_job(mem_db, "job-c")
        assert job["status"] == "running"

    async def test_mixed_completed_and_failed_results_in_completed_status(self, mem_db):
        """If there are both completed and failed results (no pending), status='completed'."""
        result_ids = await self._create_and_populate(mem_db, "job-d", ["item1", "item2"])

        await mem_db.execute(
            "UPDATE job_results SET status='completed' WHERE id=?", (result_ids[0],)
        )
        await mem_db.execute("UPDATE job_results SET status='failed' WHERE id=?", (result_ids[1],))
        await mem_db.commit()

        await update_job_counts(mem_db, "job-d", "2024-01-02T00:00:00")

        job = await get_job(mem_db, "job-d")
        assert job["status"] == "completed"


# ---------------------------------------------------------------------------
# set_result_running
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetResultRunning:
    async def test_marks_result_running(self, mem_db):
        result_ids = []
        await create_job(mem_db, "job-r1", "url/status", ["item1"], "2024-01-01")
        async with mem_db.execute("SELECT id FROM job_results WHERE job_id='job-r1'") as cur:
            result_ids = [r["id"] for r in await cur.fetchall()]

        await set_result_running(mem_db, result_ids[0], "2024-01-01T01:00:00")

        async with mem_db.execute(
            "SELECT status FROM job_results WHERE id=?", (result_ids[0],)
        ) as cur:
            row = await cur.fetchone()

        assert row["status"] == "running"


# ---------------------------------------------------------------------------
# set_result_done
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetResultDone:
    async def test_marks_result_completed_and_stores_json(self, mem_db):
        await create_job(mem_db, "job-done", "url/status", ["item1"], "2024-01-01")
        async with mem_db.execute("SELECT id FROM job_results WHERE job_id='job-done'") as cur:
            result_id = (await cur.fetchone())["id"]

        result_data = {"url": "https://example.com", "status_code": 200}
        await set_result_done(mem_db, result_id, "job-done", result_data, "2024-01-01T02:00:00")

        async with mem_db.execute(
            "SELECT status, result FROM job_results WHERE id=?", (result_id,)
        ) as cur:
            row = await cur.fetchone()

        assert row["status"] == "completed"
        assert json.loads(row["result"]) == result_data


# ---------------------------------------------------------------------------
# set_result_error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetResultError:
    async def test_marks_result_failed_and_stores_error(self, mem_db):
        await create_job(mem_db, "job-err", "url/status", ["item1"], "2024-01-01")
        async with mem_db.execute("SELECT id FROM job_results WHERE job_id='job-err'") as cur:
            result_id = (await cur.fetchone())["id"]

        await set_result_error(
            mem_db, result_id, "job-err", "Connection refused", "2024-01-01T03:00:00"
        )

        async with mem_db.execute(
            "SELECT status, error FROM job_results WHERE id=?", (result_id,)
        ) as cur:
            row = await cur.fetchone()

        assert row["status"] == "failed"
        assert row["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# get_pending_results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetPendingResults:
    async def test_returns_all_pending(self, mem_db):
        await create_job(mem_db, "job-pend", "url/status", ["a", "b", "c"], "2024-01-01")

        rows = await get_pending_results(mem_db, "job-pend")
        assert len(rows) == 3
        assert all(r["status"] == "pending" for r in rows)

    async def test_excludes_non_pending(self, mem_db):
        await create_job(mem_db, "job-pend2", "url/status", ["a", "b"], "2024-01-01")
        async with mem_db.execute(
            "SELECT id FROM job_results WHERE job_id='job-pend2' AND input='a'"
        ) as cur:
            rid = (await cur.fetchone())["id"]

        await mem_db.execute("UPDATE job_results SET status='completed' WHERE id=?", (rid,))
        await mem_db.commit()

        rows = await get_pending_results(mem_db, "job-pend2")
        assert len(rows) == 1
        assert rows[0]["input"] == "b"

    async def test_empty_for_unknown_job(self, mem_db):
        rows = await get_pending_results(mem_db, "nonexistent-job")
        assert rows == []


# ---------------------------------------------------------------------------
# get_results_page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetResultsPage:
    async def test_returns_all_rows_for_new_job(self, mem_db):
        await create_job(mem_db, "job-page", "url/status", ["a", "b", "c"], "2024-01-01")

        rows = await get_results_page(mem_db, "job-page", after_id=0, limit=100)
        assert len(rows) == 3

    async def test_pagination_after_id(self, mem_db):
        await create_job(mem_db, "job-pg2", "url/status", ["a", "b", "c"], "2024-01-01")

        first_page = await get_results_page(mem_db, "job-pg2", after_id=0, limit=2)
        assert len(first_page) == 2

        last_id = first_page[-1]["id"]
        second_page = await get_results_page(mem_db, "job-pg2", after_id=last_id, limit=2)
        assert len(second_page) == 1

    async def test_json_result_parsed(self, mem_db):
        await create_job(mem_db, "job-json", "url/status", ["item"], "2024-01-01")
        async with mem_db.execute("SELECT id FROM job_results WHERE job_id='job-json'") as cur:
            rid = (await cur.fetchone())["id"]

        payload = {"url": "https://example.com", "status_code": 200}
        await set_result_done(mem_db, rid, "job-json", payload, "2024-01-01T04:00:00")

        rows = await get_results_page(mem_db, "job-json", after_id=0, limit=10)
        assert len(rows) == 1
        assert isinstance(rows[0]["result"], dict)
        assert rows[0]["result"]["status_code"] == 200

    async def test_invalid_json_result_kept_as_string(self, mem_db):
        """If the stored result is not valid JSON, it should be kept as-is."""
        await create_job(mem_db, "job-badjson", "url/status", ["item"], "2024-01-01")
        async with mem_db.execute("SELECT id FROM job_results WHERE job_id='job-badjson'") as cur:
            rid = (await cur.fetchone())["id"]

        # Write invalid JSON directly
        await mem_db.execute(
            "UPDATE job_results SET status='completed', result=? WHERE id=?",
            ("not-valid-json{{", rid),
        )
        await mem_db.commit()

        rows = await get_results_page(mem_db, "job-badjson", after_id=0, limit=10)
        assert len(rows) == 1
        # Should keep the raw string
        assert rows[0]["result"] == "not-valid-json{{"

    async def test_empty_for_unknown_job(self, mem_db):
        rows = await get_results_page(mem_db, "nonexistent", after_id=0, limit=10)
        assert rows == []
