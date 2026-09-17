from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    hostname      TEXT,
    os_version    TEXT,
    agent_version TEXT,
    enrolled_at   REAL NOT NULL,
    last_seen_at  REAL,
    revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash      TEXT PRIMARY KEY,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    used_at         REAL,
    used_by_device  TEXT,
    created_by      TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id           TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    script           TEXT NOT NULL,
    timeout_seconds  INTEGER NOT NULL,
    state            TEXT NOT NULL,
    exit_code        INTEGER,
    stdout           TEXT,
    stderr           TEXT,
    duration_ms      INTEGER,
    stdout_truncated INTEGER DEFAULT 0,
    stderr_truncated INTEGER DEFAULT 0,
    error            TEXT,
    created_at       REAL NOT NULL,
    dispatched_at    REAL,
    completed_at     REAL,
    created_by       TEXT,
    idempotency_key  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency
    ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        REAL NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    device_id TEXT,
    job_id    TEXT,
    detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
"""


class Store:
    """SQLite persistence. Writes are small and synchronous; the lock keeps
    them safe across the event loop and any worker threads."""

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ---------- audit ----------

    def audit(self, actor: str, action: str, *, device_id: str | None = None,
              job_id: str | None = None, detail: dict | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_log (at, actor, action, device_id, job_id, detail)"
                " VALUES (?,?,?,?,?,?)",
                (time.time(), actor, action, device_id, job_id,
                 json.dumps(detail) if detail else None),
            )
            self._db.commit()

    def recent_audit(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT at, actor, action, device_id, job_id, detail"
                " FROM audit_log ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------- enrollment tokens ----------

    def create_enrollment_token(self, token_hash: str, ttl_seconds: int, created_by: str) -> float:
        now = time.time()
        expires = now + ttl_seconds
        with self._lock:
            self._db.execute(
                "INSERT INTO enrollment_tokens (token_hash, created_at, expires_at, created_by)"
                " VALUES (?,?,?,?)", (token_hash, now, expires, created_by)
            )
            self._db.commit()
        return expires

    def redeem_enrollment_token(self, token_hash: str, device_id: str) -> tuple[bool, str]:
        """Single-use redemption. Returns (ok, reason)."""
        now = time.time()
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?",
                (token_hash,)
            ).fetchone()
            if row is None:
                return False, "unknown token"
            if row["used_at"] is not None:
                return False, "token already used"
            if row["expires_at"] < now:
                return False, "token expired"

            self._db.execute(
                "UPDATE enrollment_tokens SET used_at = ?, used_by_device = ?"
                " WHERE token_hash = ? AND used_at IS NULL",
                (now, device_id, token_hash),
            )
            self._db.commit()
        return True, "ok"

    # ---------- devices ----------

    def upsert_device(self, device_id: str, public_key: str, hostname: str,
                      os_version: str, agent_version: str) -> None:
        """Re-enrolment of a known machine updates in place, so identity
        survives reinstall instead of creating a duplicate."""
        with self._lock:
            self._db.execute(
                "INSERT INTO devices (device_id, public_key, hostname, os_version,"
                " agent_version, enrolled_at, revoked) VALUES (?,?,?,?,?,?,0)"
                " ON CONFLICT(device_id) DO UPDATE SET"
                " public_key=excluded.public_key, hostname=excluded.hostname,"
                " os_version=excluded.os_version, agent_version=excluded.agent_version,"
                " enrolled_at=excluded.enrolled_at, revoked=0",
                (device_id, public_key, hostname, os_version, agent_version, time.time()),
            )
            self._db.commit()

    def get_device(self, device_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_devices(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM devices ORDER BY hostname"
            ).fetchall()
        return [dict(r) for r in rows]

    def touch_device(self, device_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
                (time.time(), device_id),
            )
            self._db.commit()

    def revoke_device(self, device_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE devices SET revoked = 1 WHERE device_id = ?", (device_id,)
            )
            self._db.commit()
        return cur.rowcount > 0

    # ---------- jobs ----------

    def insert_job(self, job: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO jobs (job_id, device_id, script, timeout_seconds, state,"
                " created_at, created_by, idempotency_key) VALUES (?,?,?,?,?,?,?,?)",
                (job["job_id"], job["device_id"], job["script"], job["timeout_seconds"],
                 job["state"], job["created_at"], job.get("created_by"),
                 job.get("idempotency_key")),
            )
            self._db.commit()

    def job_id_for_idempotency_key(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT job_id FROM jobs WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return row["job_id"] if row else None

    def mark_dispatched(self, job_id: str, at: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE jobs SET state='Dispatched', dispatched_at=? WHERE job_id=?",
                (at, job_id),
            )
            self._db.commit()

    def update_job_state(self, job_id: str, state: str) -> None:
        with self._lock:
            self._db.execute("UPDATE jobs SET state=? WHERE job_id=?", (state, job_id))
            self._db.commit()

    def complete_job(self, job_id: str, state: str, result: dict) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE jobs SET state=?, exit_code=?, stdout=?, stderr=?, duration_ms=?,"
                " stdout_truncated=?, stderr_truncated=?, error=?, completed_at=?"
                " WHERE job_id=?",
                (state, result.get("exitCode"), result.get("stdout"), result.get("stderr"),
                 result.get("durationMs"), int(bool(result.get("stdoutTruncated"))),
                 int(bool(result.get("stderrTruncated"))), result.get("error"),
                 time.time(), job_id),
            )
            self._db.commit()

    def get_job(self, job_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return dict(row) if row else None

    def recent_jobs(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def orphan_active_jobs(self) -> None:
        """Called at startup: a job that was in flight when we died can never
        report back, so it must not linger in a non-terminal state."""
        with self._lock:
            self._db.execute(
                "UPDATE jobs SET state='Failed', error='Control plane restarted"
                " while job was in flight.', completed_at=?"
                " WHERE state IN ('Queued','Dispatched','Running')", (time.time(),)
            )
            self._db.commit()
