"""Wire protocol shared with the C# Windows agent.

Field names are camelCase because the agent serializes with
JsonSerializerDefaults.Web. Do not rename without changing the agent.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any


class JobState(str, Enum):
    QUEUED = "Queued"
    DISPATCHED = "Dispatched"
    RUNNING = "Running"
    COMPLETED = "Completed"
    TIMED_OUT = "TimedOut"
    UNREACHABLE = "Unreachable"
    FAILED = "Failed"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = frozenset(
    {JobState.COMPLETED, JobState.TIMED_OUT, JobState.UNREACHABLE, JobState.FAILED}
)

_BY_ORDINAL = [
    JobState.QUEUED,
    JobState.DISPATCHED,
    JobState.RUNNING,
    JobState.COMPLETED,
    JobState.TIMED_OUT,
    JobState.UNREACHABLE,
    JobState.FAILED,
]


def parse_job_state(value: Any) -> JobState:
    """System.Text.Json may emit an enum as its ordinal or its name."""
    if isinstance(value, bool):
        raise ValueError(f"invalid job state: {value!r}")
    if isinstance(value, int):
        return _BY_ORDINAL[value]
    return JobState(value)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def result_attestation(job_id: str, script_sha256: str, exit_code: int | None,
                       duration_ms: int, stdout: str, stderr: str) -> bytes:
    """Must match JobResult.Attestation in the agent, byte for byte."""
    fields = [
        "squash-rmm-result-v1",
        job_id,
        script_sha256,
        "null" if exit_code is None else str(exit_code),
        str(duration_ms),
        sha256_hex(stdout),
        sha256_hex(stderr),
    ]
    return "|".join(fields).encode()


def job_dispatch(job_id: str, script: str, timeout_seconds: int, max_output_bytes: int) -> dict:
    return {
        "type": "job_dispatch",
        "job": {
            "jobId": job_id,
            "script": script,
            "timeoutSeconds": timeout_seconds,
            "maxOutputBytes": max_output_bytes,
            "scriptSha256": sha256_hex(script),
        },
    }


def hello_ack(device_id: str, heartbeat_interval_seconds: int) -> dict:
    return {
        "type": "hello_ack",
        "deviceId": device_id,
        "heartbeatIntervalSeconds": heartbeat_interval_seconds,
    }
