"""Wire protocol shared with the C# Windows agent.

Field names are camelCase because the agent serializes with
JsonSerializerDefaults.Web. Do not rename without changing the agent.
"""

from __future__ import annotations

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


def job_dispatch(job_id: str, script: str, timeout_seconds: int, max_output_bytes: int) -> dict:
    return {
        "type": "job_dispatch",
        "job": {
            "jobId": job_id,
            "script": script,
            "timeoutSeconds": timeout_seconds,
            "maxOutputBytes": max_output_bytes,
        },
    }


def hello_ack(device_id: str, heartbeat_interval_seconds: int) -> dict:
    return {
        "type": "hello_ack",
        "deviceId": device_id,
        "heartbeatIntervalSeconds": heartbeat_interval_seconds,
    }
