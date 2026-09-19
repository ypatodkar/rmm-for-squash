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
    revoked       INTEGER NOT NULL DEFAULT 0,
    rebound_at    REAL,
    rebind_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash      TEXT PRIMARY KEY,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    used_at         REAL,
    used_by_device  TEXT,
    created_by      TEXT,
    -- A plain token may only register a device id that does not exist yet.
    -- Replacing an enrolled device's key is credential recovery and needs a
    -- token the operator deliberately marked for it.
    allow_rebind    INTEGER NOT NULL DEFAULT 0,
    -- Optionally pins the token to one device id, so a leaked recovery token
    -- cannot be aimed at a different machine.
    bound_device_id TEXT
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

CREATE TABLE IF NOT EXISTS device_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    event     TEXT NOT NULL,
    at        REAL NOT NULL,
    detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_events ON device_events(device_id, at DESC);

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

CREATE TABLE IF NOT EXISTS device_inventory (
    device_id     TEXT PRIMARY KEY,
    data          TEXT,    -- JSON from the last successful collection
    collected_at  REAL,    -- when that collection finished
    job_id        TEXT,    -- the job that produced it
    attempted_at  REAL,    -- the last attempt, successful or not
    error         TEXT     -- why the last attempt failed; NULL if it succeeded
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    problem          TEXT NOT NULL,
    status           TEXT NOT NULL,
    finding          TEXT,
    confidence       TEXT,
    error            TEXT,
    outcome          TEXT,
    created_by       TEXT NOT NULL,
    request_id       TEXT NOT NULL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
-- One request from one operator creates at most one investigation, so a
-- retried submission after an ambiguous network failure cannot double-run it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_investigations_dedup
    ON investigations(created_by, request_id);
CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at DESC);

CREATE TABLE IF NOT EXISTS investigation_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    at               REAL NOT NULL,
    message          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_events ON investigation_events(investigation_id, at);

CREATE TABLE IF NOT EXISTS investigation_evidence (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    at               REAL NOT NULL,
    diagnostic       TEXT NOT NULL,
    arguments        TEXT,
    check_succeeded  INTEGER NOT NULL,
    output           TEXT,
    note             TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_evidence ON investigation_evidence(investigation_id, at);

CREATE TABLE IF NOT EXISTS investigation_proposals (
    proposal_id       TEXT PRIMARY KEY,
    investigation_id  TEXT NOT NULL,
    decision          TEXT NOT NULL,
    repair            TEXT,
    arguments         TEXT,
    script            TEXT,
    script_sha256     TEXT,
    reasoning         TEXT,
    expected_effect   TEXT,
    risk              TEXT,
    verified_by       TEXT,
    refusal_reason    TEXT,
    proposal_hash     TEXT,
    created_at        REAL NOT NULL,
    expires_at        REAL,
    decided_at        REAL,
    decided_by        TEXT,
    decision_outcome  TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_proposals ON investigation_proposals(investigation_id, created_at DESC);
"""


class Store:
    """SQLite persistence. Writes are small and synchronous; the lock keeps
    them safe across the event loop and any worker threads."""

    def __init__(self, path: str | Path) -> None:
        # Applied to investigation text -- errors, events, notes, findings --
        # before it is stored. Supplied by the AI bridge, which owns the list
        # of secrets; identity until then.
        self.redact_text = lambda text: text
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()
            self._db.commit()

    def _migrate(self) -> None:
        """Adds columns introduced after a database was first created."""
        additions = {
            "enrollment_tokens": [
                ("allow_rebind", "INTEGER NOT NULL DEFAULT 0"),
                ("bound_device_id", "TEXT"),
            ],
            "devices": [
                ("rebound_at", "REAL"),
                ("rebind_count", "INTEGER NOT NULL DEFAULT 0"),
                # Unix seconds, UTC. Reported by the endpoint, so treated as a
                # claim about that machine rather than as authoritative time.
                ("last_boot_at", "REAL"),
                ("last_disconnect_at", "REAL"),
                # Uptime comes from a monotonic counter, so unlike a derived
                # boot time it is unaffected by the endpoint's clock. Paired
                # with the server time at which it was observed.
                ("last_uptime_seconds", "REAL"),
                ("last_uptime_observed_at", "REAL"),
                # Monotonic reading plus the process that took it. Elapsed time
                # is only trustworthy when both come from the running process.
                ("last_uptime_observed_monotonic", "REAL"),
                ("last_uptime_observer_epoch", "TEXT"),
            ],
        }
        for table, columns in additions.items():
            existing = {r["name"] for r in self._db.execute(f"PRAGMA table_info({table})")}
            for name, decl in columns:
                if name not in existing:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

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

    def create_enrollment_token(self, token_hash: str, ttl_seconds: int, created_by: str,
                                *, allow_rebind: bool = False,
                                bound_device_id: str | None = None) -> float:
        now = time.time()
        expires = now + ttl_seconds
        with self._lock:
            self._db.execute(
                "INSERT INTO enrollment_tokens (token_hash, created_at, expires_at,"
                " created_by, allow_rebind, bound_device_id) VALUES (?,?,?,?,?,?)",
                (token_hash, now, expires, created_by, int(allow_rebind), bound_device_id),
            )
            self._db.commit()
        return expires

    def redeem_enrollment_token(self, token_hash: str, device_id: str) -> tuple[bool, str, dict]:
        """Single-use redemption. Returns (ok, reason, grants). `grants` carries
        what this particular token is permitted to do, so the caller can decide
        between first enrolment and credential recovery."""
        now = time.time()
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at, used_at, allow_rebind, bound_device_id"
                " FROM enrollment_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                return False, "unknown token", {}
            if row["used_at"] is not None:
                return False, "token already used", {}
            if row["expires_at"] < now:
                return False, "token expired", {}
            if row["bound_device_id"] and row["bound_device_id"] != device_id:
                return False, "token is bound to a different device", {}

            self._db.execute(
                "UPDATE enrollment_tokens SET used_at = ?, used_by_device = ?"
                " WHERE token_hash = ? AND used_at IS NULL",
                (now, device_id, token_hash),
            )
            self._db.commit()
        return True, "ok", {"allow_rebind": bool(row["allow_rebind"]),
                            "bound_device_id": row["bound_device_id"]}

    # ---------- devices ----------

    def insert_device(self, device_id: str, public_key: str, hostname: str,
                      os_version: str, agent_version: str) -> bool:
        """First enrolment only. Returns False if the id is already claimed;
        an existing device's key is never silently replaced."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO devices (device_id, public_key, hostname, os_version,"
                    " agent_version, enrolled_at, revoked) VALUES (?,?,?,?,?,?,0)",
                    (device_id, public_key, hostname, os_version, agent_version, time.time()),
                )
            except sqlite3.IntegrityError:
                return False
            self._db.commit()
        return True

    def rebind_device(self, device_id: str, public_key: str, hostname: str,
                      os_version: str, agent_version: str) -> bool:
        """Credential recovery: replaces an enrolled device's key. Deliberately
        leaves `revoked` untouched, because re-enrolling must never be a way to
        undo a revocation."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE devices SET public_key=?, hostname=?, os_version=?,"
                " agent_version=?, enrolled_at=?, rebound_at=?,"
                " rebind_count=rebind_count+1"
                " WHERE device_id=? AND revoked=0",
                (public_key, hostname, os_version, agent_version,
                 time.time(), time.time(), device_id),
            )
            self._db.commit()
        return cur.rowcount > 0

    def unrevoke_device(self, device_id: str) -> bool:
        """Restoring a revoked device is an explicit operator decision."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE devices SET revoked = 0 WHERE device_id = ?", (device_id,)
            )
            self._db.commit()
        return cur.rowcount > 0

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

    # ---------- device events ----------

    def record_device_event(self, device_id: str, event: str, detail: dict | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO device_events (device_id, event, at, detail) VALUES (?,?,?,?)",
                (device_id, event, time.time(), json.dumps(detail) if detail else None),
            )
            self._db.commit()

    def device_events(self, device_id: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT event, at, detail FROM device_events"
                " WHERE device_id = ? ORDER BY at DESC LIMIT ?", (device_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def record_uptime(self, device_id: str, uptime_seconds: float | None,
                      boot_at: float | None, observed_at: float,
                      observed_monotonic: float, observer_epoch: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE devices SET last_uptime_seconds = ?, last_uptime_observed_at = ?,"
                " last_uptime_observed_monotonic = ?, last_uptime_observer_epoch = ?,"
                " last_boot_at = ? WHERE device_id = ?",
                (uptime_seconds, observed_at, observed_monotonic, observer_epoch,
                 boot_at, device_id))
            self._db.commit()

    def set_disconnected(self, device_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE devices SET last_disconnect_at = ? WHERE device_id = ?",
                (time.time(), device_id))
            self._db.commit()

    def clear_disconnected(self, device_id: str) -> None:
        """Closes a recorded outage. Leaving it set would let a later
        reconnection measure its duration from a stale timestamp."""
        with self._lock:
            self._db.execute(
                "UPDATE devices SET last_disconnect_at = NULL WHERE device_id = ?",
                (device_id,))
            self._db.commit()

    def update_device_details(self, device_id: str, hostname: str, os_version: str,
                              agent_version: str) -> dict:
        """Records what an authenticated device reports about itself on each
        connection, and returns the fields that changed as {field: [old, new]}.
        Enrolment used to be the only time these were written, so an upgraded
        or renamed machine kept showing what it was when it first enrolled."""
        with self._lock:
            row = self._db.execute(
                "SELECT hostname, os_version, agent_version FROM devices WHERE device_id = ?",
                (device_id,)).fetchone()
            if row is None:
                return {}
            new = {"hostname": hostname, "os_version": os_version,
                   "agent_version": agent_version}
            changed = {k: [row[k], v] for k, v in new.items() if row[k] != v}
            if changed:
                self._db.execute(
                    "UPDATE devices SET hostname = ?, os_version = ?, agent_version = ?"
                    " WHERE device_id = ?", (hostname, os_version, agent_version, device_id))
                self._db.commit()
            return changed

    # ---------- inventory ----------

    def get_inventory(self, device_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM device_inventory WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

    def all_inventory(self) -> dict[str, dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM device_inventory").fetchall()
        return {r["device_id"]: dict(r) for r in rows}

    def record_inventory(self, device_id: str, *, attempted_at: float,
                         data: dict | None = None, job_id: str | None = None,
                         error: str | None = None) -> None:
        """A success replaces the stored inventory. A failure records why, and
        keeps the last good inventory: one bad attempt must not erase what is
        known about a machine."""
        with self._lock:
            if data is not None:
                self._db.execute(
                    "INSERT INTO device_inventory (device_id, data, collected_at, job_id,"
                    " attempted_at, error) VALUES (?,?,?,?,?,NULL)"
                    " ON CONFLICT(device_id) DO UPDATE SET data=excluded.data,"
                    " collected_at=excluded.collected_at, job_id=excluded.job_id,"
                    " attempted_at=excluded.attempted_at, error=NULL",
                    (device_id, json.dumps(data), attempted_at, job_id, attempted_at))
            else:
                self._db.execute(
                    "INSERT INTO device_inventory (device_id, attempted_at, error, job_id)"
                    " VALUES (?,?,?,?)"
                    " ON CONFLICT(device_id) DO UPDATE SET attempted_at=excluded.attempted_at,"
                    " error=excluded.error",
                    (device_id, attempted_at, error, job_id))
            self._db.commit()

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

    def job_for_idempotency_key(self, key: str) -> dict | None:
        """The earlier request made under this key, so a reuse can be compared
        with it rather than trusted to be a retry."""
        with self._lock:
            row = self._db.execute(
                "SELECT job_id, device_id, script, timeout_seconds, created_by"
                " FROM jobs WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return dict(row) if row else None

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

    def page_jobs(self, page: int, page_size: int, *, state: str | None = None,
                  device_id: str | None = None, search: str = "") -> dict:
        clauses, params = [], []
        if state:
            clauses.append("state = ?")
            params.append(state)
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        if search.strip():
            # Literal substring matching: '%' and '_' are not wildcards.
            clauses.append("instr(lower(script), lower(?)) > 0")
            params.append(search.strip())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) FROM jobs" + where, params).fetchone()[0]
            total_pages = max(1, (total + page_size - 1) // page_size)
            page = min(max(1, page), total_pages)
            rows = self._db.execute(
                "SELECT * FROM jobs" + where +
                " ORDER BY created_at DESC, job_id DESC LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {"items": [dict(r) for r in rows], "total": total, "page": page,
                "pageSize": page_size, "totalPages": total_pages}

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

    # ---------- investigations ----------

    def create_investigation(self, investigation_id: str, device_id: str, problem: str,
                             created_by: str, request_id: str) -> tuple[dict | None, bool]:
        """Atomically deduplicates by (created_by, request_id): a retried
        submission after an ambiguous network failure returns the row that
        already exists rather than creating a second investigation. Returns
        (row, created) -- created is False when an existing row was returned."""
        now = time.time()
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO investigations (investigation_id, device_id, problem, status,"
                    " created_by, request_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (investigation_id, device_id, problem, "queued", created_by, request_id,
                     now, now),
                )
                self._db.commit()
                created = True
            except sqlite3.IntegrityError:
                created = False

            row = self._db.execute(
                "SELECT i.*, d.hostname AS hostname FROM investigations i"
                " LEFT JOIN devices d ON d.device_id = i.device_id"
                " WHERE i.created_by = ? AND i.request_id = ?",
                (created_by, request_id),
            ).fetchone()
        return (dict(row) if row else None), created

    def get_investigation(self, investigation_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT i.*, d.hostname AS hostname FROM investigations i"
                " LEFT JOIN devices d ON d.device_id = i.device_id"
                " WHERE i.investigation_id = ?", (investigation_id,)
            ).fetchone()
        return dict(row) if row else None

    _STATUS_GROUPS = {
        "active": ("queued", "investigating", "planning", "applying", "verifying"),
        "awaiting_approval": ("awaiting_approval",),
        "finished": ("completed", "resolved", "unresolved", "failed", "rejected", "cancelled"),
    }

    def list_investigations(self, page: int, page_size: int, *, search: str = "",
                            status: str | None = None) -> dict:
        clauses, params = [], []
        if status:
            statuses = self._STATUS_GROUPS.get(status, (status,))
            clauses.append(f"i.status IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
        if search.strip():
            clauses.append("(instr(lower(i.problem), lower(?)) > 0"
                           " OR instr(lower(coalesce(d.hostname,'')), lower(?)) > 0)")
            params.extend([search.strip(), search.strip()])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        base = ("FROM investigations i LEFT JOIN devices d ON d.device_id = i.device_id" + where)
        with self._lock:
            total = self._db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
            total_pages = max(1, (total + page_size - 1) // page_size)
            page = min(max(1, page), total_pages)
            rows = self._db.execute(
                f"SELECT i.*, d.hostname AS hostname {base}"
                " ORDER BY i.created_at DESC, i.investigation_id DESC LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {"items": [dict(r) for r in rows], "total": total, "page": page,
                "totalPages": total_pages}

    def set_investigation_status(self, investigation_id: str, status: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE investigations SET status = ?, updated_at = ? WHERE investigation_id = ?",
                (status, time.time(), investigation_id))
            self._db.commit()

    def set_investigation_finding(self, investigation_id: str, finding: str,
                                  confidence: str | None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE investigations SET finding = ?, confidence = ?, updated_at = ?"
                " WHERE investigation_id = ?",
                (self.redact_text(finding), confidence, time.time(), investigation_id))
            self._db.commit()

    def set_investigation_error(self, investigation_id: str, error: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE investigations SET error = ?, updated_at = ? WHERE investigation_id = ?",
                (self.redact_text(error), time.time(), investigation_id))
            self._db.commit()

    def set_investigation_outcome(self, investigation_id: str, outcome: dict) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE investigations SET outcome = ?, updated_at = ? WHERE investigation_id = ?",
                (self.redact_text(json.dumps(outcome)), time.time(), investigation_id))
            self._db.commit()

    def append_investigation_event(self, investigation_id: str, message: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigation_events (investigation_id, at, message) VALUES (?,?,?)",
                (investigation_id, time.time(), self.redact_text(message)))
            self._db.commit()

    def get_investigation_events(self, investigation_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT at, message FROM investigation_events"
                " WHERE investigation_id = ? ORDER BY at, id", (investigation_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def insert_investigation_evidence(self, investigation_id: str, diagnostic: str,
                                      arguments: dict, check_succeeded: bool,
                                      output: object, note: str | None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigation_evidence (investigation_id, at, diagnostic,"
                " arguments, check_succeeded, output, note) VALUES (?,?,?,?,?,?,?)",
                (investigation_id, time.time(), diagnostic, json.dumps(arguments),
                 int(check_succeeded), json.dumps(output), self.redact_text(note)))
            self._db.commit()

    def get_investigation_evidence(self, investigation_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT diagnostic, arguments, check_succeeded, output, note"
                " FROM investigation_evidence WHERE investigation_id = ? ORDER BY at, id",
                (investigation_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def create_proposal(self, proposal_id: str, investigation_id: str, *, decision: str,
                        repair: str | None, arguments: dict, script: str | None,
                        script_sha256: str | None, reasoning: str, expected_effect: str,
                        risk: str, verified_by: str, refusal_reason: str,
                        proposal_hash: str | None, expires_at: float | None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigation_proposals (proposal_id, investigation_id, decision,"
                " repair, arguments, script, script_sha256, reasoning, expected_effect, risk,"
                " verified_by, refusal_reason, proposal_hash, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (proposal_id, investigation_id, decision, repair, json.dumps(arguments), script,
                 script_sha256, reasoning, expected_effect, risk, verified_by, refusal_reason,
                 proposal_hash, time.time(), expires_at))
            self._db.commit()

    def get_current_proposal(self, investigation_id: str) -> dict | None:
        """One planning pass per investigation in this version, so the most
        recent proposal is the only one that can be current."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM investigation_proposals WHERE investigation_id = ?"
                " ORDER BY created_at DESC LIMIT 1", (investigation_id,)
            ).fetchone()
        return dict(row) if row else None

    def record_proposal_decision(self, proposal_id: str, decided_by: str,
                                 decision_outcome: str) -> tuple[dict | None, bool]:
        """Compare-and-set: only the first decision is recorded. The caller
        receives whether this call won the update, so an idempotent HTTP retry
        cannot schedule the same background work a second time."""
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "UPDATE investigation_proposals SET decided_at = ?, decided_by = ?,"
                " decision_outcome = ? WHERE proposal_id = ? AND decided_at IS NULL",
                (now, decided_by, decision_outcome, proposal_id))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM investigation_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        return (dict(row) if row else None), cursor.rowcount == 1

    def recover_investigations(self) -> list[tuple[str, str]]:
        """Makes interrupted background work runnable after a server restart.

        Diagnosis is read-only, so an interrupted diagnosis can safely restart
        from a clean evidence/proposal snapshot. An approved repair is resumed
        with the same proposal id; the repair dispatcher uses that id as its
        idempotency key, so a lost response cannot execute it twice.

        Returns ``(investigation_id, work_kind)`` where work_kind is ``start``
        or ``apply``. Investigations waiting for a human remain untouched.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT i.investigation_id, i.status,"
                " (SELECT p.decision_outcome FROM investigation_proposals p"
                "  WHERE p.investigation_id=i.investigation_id"
                "  ORDER BY p.created_at DESC LIMIT 1) AS decision_outcome"
                " FROM investigations i"
                " WHERE i.status IN ('queued','investigating','planning',"
                " 'awaiting_approval','applying','verifying')"
            ).fetchall()
            work: list[tuple[str, str]] = []
            now = time.time()
            for row in rows:
                investigation_id = row["investigation_id"]
                status = row["status"]
                decision = row["decision_outcome"]
                if status in ("queued", "investigating", "planning"):
                    if status != "queued":
                        self._db.execute(
                            "DELETE FROM investigation_evidence WHERE investigation_id=?",
                            (investigation_id,))
                        self._db.execute(
                            "DELETE FROM investigation_proposals WHERE investigation_id=?"
                            " AND decided_at IS NULL", (investigation_id,))
                        self._db.execute(
                            "UPDATE investigations SET status='queued', finding=NULL,"
                            " confidence=NULL, error=NULL, outcome=NULL, updated_at=?"
                            " WHERE investigation_id=?", (now, investigation_id))
                        self._db.execute(
                            "INSERT INTO investigation_events (investigation_id, at, message)"
                            " VALUES (?,?,?)", (investigation_id, now,
                            "Control plane restarted; restarting the read-only diagnosis."))
                    work.append((investigation_id, "start"))
                elif decision == "approve":
                    self._db.execute(
                        "UPDATE investigations SET status='applying', updated_at=?"
                        " WHERE investigation_id=?", (now, investigation_id))
                    self._db.execute(
                        "INSERT INTO investigation_events (investigation_id, at, message)"
                        " VALUES (?,?,?)", (investigation_id, now,
                        "Control plane restarted; resuming the approved repair."))
                    work.append((investigation_id, "apply"))
                elif decision == "reject":
                    self._db.execute(
                        "UPDATE investigations SET status='rejected', updated_at=?"
                        " WHERE investigation_id=?", (now, investigation_id))
                elif status in ("applying", "verifying"):
                    self._db.execute(
                        "UPDATE investigations SET status='failed', error=?, updated_at=?"
                        " WHERE investigation_id=?",
                        ("Repair state could not be recovered because its approval is missing.",
                         now, investigation_id))
            self._db.commit()
        return work

    def claim_queued_investigation(self, investigation_id: str) -> bool:
        """Only one worker may move a queued investigation into diagnosis."""
        with self._lock:
            cursor = self._db.execute(
                "UPDATE investigations SET status='investigating', updated_at=?"
                " WHERE investigation_id=? AND status='queued'",
                (time.time(), investigation_id))
            self._db.commit()
        return cursor.rowcount == 1
