"""SQLite database layer for Project Argus job tracking."""

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

import aiosqlite

DB_PATH = Path(__file__).resolve().parent.parent.parent / "argus.db"

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    job_type    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    total       INTEGER NOT NULL DEFAULT 0,
    completed   INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    input       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    result      TEXT,
    error       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_results_job_id ON job_results(job_id);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------


@asynccontextmanager
async def get_db() -> AsyncIterator[aiosqlite.Connection]:
    """Yield a connected, row-factory-enabled aiosqlite connection."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        yield conn


async def init_db() -> None:
    """Create tables if they do not already exist."""
    async with get_db() as conn:
        await conn.executescript(_DDL)
        await conn.commit()


# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------


async def create_job(
    conn: aiosqlite.Connection,
    job_id: str,
    job_type: str,
    inputs: List[str],
    now: str,
) -> None:
    """Insert a job row and all of its pending result rows atomically."""
    await conn.execute(
        """
        INSERT INTO jobs (id, job_type, status, total, completed, failed, created_at, updated_at)
        VALUES (?, ?, 'pending', ?, 0, 0, ?, ?)
        """,
        (job_id, job_type, len(inputs), now, now),
    )
    await conn.executemany(
        """
        INSERT INTO job_results (job_id, input, status, created_at, updated_at)
        VALUES (?, ?, 'pending', ?, ?)
        """,
        [(job_id, item, now, now) for item in inputs],
    )
    await conn.commit()


async def get_job(conn: aiosqlite.Connection, job_id: str) -> Optional[Dict[str, Any]]:
    """Return a job row as a dict, or None if not found."""
    async with conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)) as cur:
        row = await cur.fetchone()
        return dict(row) if row else None


async def update_job_counts(conn: aiosqlite.Connection, job_id: str, now: str) -> None:
    """Recompute completed/failed counts and flip status to done/failed."""
    await conn.execute(
        """
        UPDATE jobs
        SET completed  = (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'completed'),
            failed     = (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'failed'),
            updated_at = ?,
            status     = CASE
                WHEN (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'pending') = 0
                     AND (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'running') = 0
                THEN CASE
                    WHEN (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'failed') > 0
                         AND (SELECT COUNT(*) FROM job_results WHERE job_id = ? AND status = 'completed') = 0
                    THEN 'failed'
                    ELSE 'completed'
                END
                ELSE 'running'
            END
        WHERE id = ?
        """,
        (job_id, job_id, now, job_id, job_id, job_id, job_id, job_id),
    )
    await conn.commit()


async def set_result_running(conn: aiosqlite.Connection, result_id: int, now: str) -> None:
    await conn.execute(
        "UPDATE job_results SET status='running', updated_at=? WHERE id=?",
        (now, result_id),
    )
    await conn.commit()


async def set_result_done(
    conn: aiosqlite.Connection,
    result_id: int,
    job_id: str,
    result_data: Any,
    now: str,
) -> None:
    await conn.execute(
        """
        UPDATE job_results
        SET status='completed', result=?, error=NULL, updated_at=?
        WHERE id=?
        """,
        (json.dumps(result_data), now, result_id),
    )
    await update_job_counts(conn, job_id, now)


async def set_result_error(
    conn: aiosqlite.Connection,
    result_id: int,
    job_id: str,
    error_msg: str,
    now: str,
) -> None:
    await conn.execute(
        """
        UPDATE job_results
        SET status='failed', error=?, result=NULL, updated_at=?
        WHERE id=?
        """,
        (error_msg, now, result_id),
    )
    await update_job_counts(conn, job_id, now)


async def get_pending_results(conn: aiosqlite.Connection, job_id: str) -> List[Dict[str, Any]]:
    """Return all pending result rows for a job."""
    async with conn.execute(
        "SELECT * FROM job_results WHERE job_id = ? AND status = 'pending'",
        (job_id,),
    ) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def get_results_page(
    conn: aiosqlite.Connection,
    job_id: str,
    after_id: int,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return up to *limit* result rows with id > after_id (keyset pagination)."""
    async with conn.execute(
        """
        SELECT * FROM job_results
        WHERE job_id = ? AND id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (job_id, after_id, limit),
    ) as cur:
        rows = await cur.fetchall()
    results = []
    for row in rows:
        r = dict(row)
        if r.get("result"):
            try:
                r["result"] = json.loads(r["result"])
            except Exception:
                pass
        results.append(r)
    return results
