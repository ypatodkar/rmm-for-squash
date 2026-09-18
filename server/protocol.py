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
        # A negative index is valid Python and would silently pick a state.
        if not 0 <= value < len(_BY_ORDINAL):
            raise ValueError(f"invalid job state: {value!r}")
        return _BY_ORDINAL[value]
    return JobState(value)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(utf8(value)).hexdigest()


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def utf8(value: str) -> bytes:
    """UTF-8 bytes the way the agent computes them. .NET replaces each
    unpaired surrogate with one U+FFFD where Python would raise, and a hash
    that raises on one side and succeeds on the other is a crash, not a
    mismatch. (JSON decoding has already joined every valid pair.)"""
    return _LONE_SURROGATE.sub("\ufffd", value).encode()


# ---------- dispatch limits ----------

# The agent hands a script to PowerShell as base64 of UTF-16 on the command
# line, and Windows caps a command line at 32,767 characters. With the agent's
# preamble and arguments that leaves about 12,170 UTF-16 code units of script;
# this keeps a margin. A longer script cannot start at all, so refusing it at
# the API gives the caller a clear answer instead of a failed job.
MAX_SCRIPT_CHARS = 12_000

# Both streams, JSON-escaped, travel in one WebSocket message, and the server
# accepts messages up to 16 MiB. Four MiB per stream keeps ordinary output
# comfortably inside that.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def script_length(script: str) -> int:
    """Length as PowerShell will receive it, in UTF-16 code units."""
    return len(script.encode("utf-16-le", "surrogatepass")) // 2


# ---------- job results ----------

# A result is untrusted input even when it is correctly signed: the device
# holds its own key and can sign anything. Every field is checked for type and
# range before it is stored or shown, because the stored form is what callers,
# the dashboard and the AI driver all read.
_INT32 = (-2**31, 2**31 - 1)
MAX_DURATION_MS = 7 * 24 * 3600 * 1000
MAX_ERROR_CHARS = 2000


class MalformedResult(ValueError):
    """The result does not have the shape the protocol defines."""


def _int_field(payload: dict, name: str, low: int, high: int, *, optional: bool) -> int | None:
    value = payload.get(name)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedResult(f"{name} must be a whole number")
    if not low <= value <= high:
        raise MalformedResult(f"{name} is out of range")
    return value


def _text_field(payload: dict, name: str) -> str:
    value = payload.get(name, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise MalformedResult(f"{name} must be text")
    # Keep what .NET would have hashed: an unpaired surrogate becomes U+FFFD.
    return utf8(value).decode()


def _flag_field(payload: dict, name: str) -> bool:
    value = payload.get(name, False)
    if not isinstance(value, bool):
        raise MalformedResult(f"{name} must be true or false")
    return value


def parse_result(payload: object) -> dict:
    """Returns a clean copy of an endpoint's job result, or raises
    MalformedResult. Only fields the protocol defines survive."""
    if not isinstance(payload, dict):
        raise MalformedResult("result must be an object")

    try:
        state = parse_job_state(payload.get("state", JobState.COMPLETED.value))
    except (ValueError, IndexError, TypeError):
        raise MalformedResult("state is not a job state") from None
    if not state.is_terminal:
        raise MalformedResult(f"a result cannot leave a job {state.value}")

    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise MalformedResult("error must be text")

    for name in ("scriptSha256", "signature"):
        if payload.get(name) is not None and not isinstance(payload[name], str):
            raise MalformedResult(f"{name} must be text")

    return {
        "jobId": payload.get("jobId"),
        "state": state,
        "exitCode": _int_field(payload, "exitCode", *_INT32, optional=True),
        "durationMs": _int_field(payload, "durationMs", 0, MAX_DURATION_MS, optional=True) or 0,
        "stdout": _text_field(payload, "stdout"),
        "stderr": _text_field(payload, "stderr"),
        "stdoutTruncated": _flag_field(payload, "stdoutTruncated"),
        "stderrTruncated": _flag_field(payload, "stderrTruncated"),
        "error": utf8(error).decode()[:MAX_ERROR_CHARS] if error else None,
        "scriptSha256": payload.get("scriptSha256"),
        "signature": payload.get("signature"),
    }


def limit_output(result: dict, max_bytes: int) -> dict:
    """Holds a result to the byte limit the job was dispatched with.

    Applied after the signature is checked, since the device signed what it
    sent. Output over the limit is cut at a character boundary and flagged
    rather than rejected: a caller that asked for at most N bytes gets at most
    N bytes and is told it was cut, which is the contract whether the agent
    honoured it or not.
    """
    limited = dict(result)
    for stream in ("stdout", "stderr"):
        encoded = limited[stream].encode()
        if len(encoded) > max_bytes:
            limited[stream] = encoded[:max_bytes].decode("utf-8", "ignore")
            limited[f"{stream}Truncated"] = True
    return limited


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
