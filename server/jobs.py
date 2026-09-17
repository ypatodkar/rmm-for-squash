from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field

from protocol import JobState
from store import Store


@dataclass
class JobRecord:
    job_id: str
    device_id: str
    script: str
    timeout_seconds: int
    max_output_bytes: int
    created_by: str
    created_at: float = field(default_factory=time.time)
    dispatched_at: float | None = None
    completed_at: float | None = None
    state: JobState = JobState.QUEUED
    result: dict | None = None
    completion: asyncio.Future = field(
        default_factory=lambda: asyncio.get_event_loop().create_future()
    )

    def view(self) -> dict:
        result = self.result or {}
        return {
            "jobId": self.job_id,
            "deviceId": self.device_id,
            "script": self.script,
            "state": self.state.value,
            "exitCode": result.get("exitCode"),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "durationMs": result.get("durationMs"),
            "roundTripMs": round_trip_ms(self.dispatched_at, self.completed_at),
            "stdoutTruncated": bool(result.get("stdoutTruncated")),
            "stderrTruncated": bool(result.get("stderrTruncated")),
            "error": result.get("error"),
            "createdAt": self.created_at,
        }


def round_trip_ms(dispatched_at: float | None, completed_at: float | None) -> int | None:
    """Server-measured dispatch-to-result latency. This is the number the
    speed requirement is about: it excludes however far away the operator
    happens to be, and includes everything the system itself contributes."""
    if dispatched_at is None or completed_at is None:
        return None
    return max(0, round((completed_at - dispatched_at) * 1000))


def row_to_view(row: dict) -> dict:
    return {
        "jobId": row["job_id"],
        "deviceId": row["device_id"],
        "script": row["script"],
        "state": row["state"],
        "exitCode": row["exit_code"],
        "stdout": row["stdout"] or "",
        "stderr": row["stderr"] or "",
        "durationMs": row["duration_ms"],
        "roundTripMs": round_trip_ms(row["dispatched_at"], row["completed_at"]),
        "stdoutTruncated": bool(row["stdout_truncated"]),
        "stderrTruncated": bool(row["stderr_truncated"]),
        "error": row["error"],
        "createdAt": row["created_at"],
    }


class JobStore:
    """In-memory coordination for in-flight jobs, written through to SQLite
    so history and the audit trail survive a restart."""

    def __init__(self, store: Store) -> None:
        self._jobs: dict[str, JobRecord] = {}
        self._store = store

    def create(self, device_id: str, script: str, timeout_seconds: int,
               max_output_bytes: int, created_by: str,
               idempotency_key: str | None = None) -> JobRecord:
        job = JobRecord(
            job_id=uuid.uuid4().hex,
            device_id=device_id,
            script=script,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            created_by=created_by,
        )
        self._jobs[job.job_id] = job
        self._store.insert_job({
            "job_id": job.job_id,
            "device_id": device_id,
            "script": script,
            "timeout_seconds": timeout_seconds,
            "state": job.state.value,
            "created_at": job.created_at,
            "created_by": created_by,
            "idempotency_key": idempotency_key,
        })
        return job

    def get(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)

    def view(self, job_id: str) -> dict | None:
        job = self._jobs.get(job_id)
        if job is not None:
            return job.view()
        row = self._store.get_job(job_id)
        return row_to_view(row) if row else None

    def active(self) -> list[JobRecord]:
        return [j for j in self._jobs.values() if not j.state.is_terminal]

    def recent(self, limit: int = 50) -> list[dict]:
        return [row_to_view(r) for r in self._store.recent_jobs(limit)]

    def page(self, page: int, page_size: int, **filters) -> dict:
        result = self._store.page_jobs(page, page_size, **filters)
        result["items"] = [row_to_view(row) for row in result["items"]]
        return result

    def mark_dispatched(self, job: JobRecord) -> None:
        job.state = JobState.DISPATCHED
        job.dispatched_at = time.time()
        self._store.mark_dispatched(job.job_id, job.dispatched_at)

    def mark_running(self, job: JobRecord) -> None:
        job.state = JobState.RUNNING
        self._store.update_job_state(job.job_id, job.state.value)

    def complete(self, job: JobRecord, result: dict, state: JobState) -> None:
        if job.state.is_terminal:
            return
        job.state = state
        job.result = result
        job.completed_at = time.time()
        self._store.complete_job(job.job_id, state.value, result)
        if not job.completion.done():
            job.completion.set_result(result)

    def fail(self, job: JobRecord, state: JobState, error: str) -> None:
        self.complete(job, {"jobId": job.job_id, "error": error}, state)
