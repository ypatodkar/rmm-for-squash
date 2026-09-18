"""Wire protocol shared with the C# Windows agent.

Field names are camelCase because the agent serializes with
JsonSerializerDefaults.Web. Do not rename without changing the agent.
"""

from __future__ import annotations

import hashlib
import re
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


_CONTROL_CHARS = {c: None for c in range(0x20) if c not in (0x09,)}


def clean_endpoint_text(value: object, *, max_length: int = 128, fallback: str = "unknown") -> str:
    """Endpoint-supplied descriptive text (hostname, OS version) is untrusted.
    Bound it and strip control characters before it is stored or displayed, so
    a hostile device cannot smuggle markup, terminal escapes or unbounded data
    into an operator's console."""
    if not isinstance(value, str):
        return fallback
    cleaned = value.translate(_CONTROL_CHARS).strip()
    return cleaned[:max_length] or fallback


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


# ---------- restart ----------

DEFAULT_RESTART_REASON = "Restart requested from Squash RMM"
MIN_RESTART_DELAY_SECONDS = 5
MAX_RESTART_DELAY_SECONDS = 3600

# The reason is shown to whoever is sitting at the machine, and it is
# substituted into a command line. The character class is narrow on purpose:
# anything that could close the quote or start a new statement is refused
# rather than escaped, because escaping is a thing you can get subtly wrong
# and a whitelist is a thing you cannot.
_RESTART_REASON = re.compile(r"^[A-Za-z0-9 .,:!?'\-_()/]{1,200}$")


class RestartError(ValueError):
    """The requested restart is not one we are willing to build."""


def restart_script(delay_seconds: int, reason: str) -> str:
    """Builds the restart command.

    The delay is not decoration. The agent has to report the job result over
    the same machine that is about to go down, so a restart that begins
    immediately shows up to the operator as a failed job for an action that
    actually succeeded.
    """
    if isinstance(delay_seconds, bool) or not isinstance(delay_seconds, int):
        raise RestartError("delaySeconds must be a whole number of seconds")
    if not MIN_RESTART_DELAY_SECONDS <= delay_seconds <= MAX_RESTART_DELAY_SECONDS:
        raise RestartError(
            f"delaySeconds must be between {MIN_RESTART_DELAY_SECONDS} and "
            f"{MAX_RESTART_DELAY_SECONDS}")
    if not isinstance(reason, str) or not _RESTART_REASON.match(reason):
        raise RestartError(
            "reason may contain only letters, digits, spaces and . , : ! ? ' - _ ( ) / "
            "(1-200 characters)")
    return (f'shutdown.exe /r /t {delay_seconds} /c "{reason}"; '
            f'"restart scheduled in {delay_seconds}s"')
