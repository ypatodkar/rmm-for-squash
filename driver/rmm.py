"""Worker-side client for the RMM control plane.

Deliberately speaks only the public HTTP API with its own operator credential,
exactly as any external consumer would. It has no access to the control plane's
database, and every dispatch it makes is attributable to the ai-driver
principal in the audit trail.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass

import diagnostics
from diagnostics import ArgumentError

TERMINAL_STATES = {"Completed", "TimedOut", "Unreachable", "Failed"}


class RmmError(RuntimeError):
    """The control plane refused or could not service a request."""


class DeviceUnavailable(RmmError):
    """The device is not enrolled, is revoked, or is not currently reachable."""


@dataclass(frozen=True)
class Device:
    device_id: str
    hostname: str
    online: bool
    os_version: str
    uptime_seconds: int | None


@dataclass(frozen=True)
class DiagnosticResult:
    """What one diagnostic produced. `data` is the parsed JSON payload when the
    script returned one; `raw_stdout` is always kept so a parse failure remains
    inspectable rather than being swallowed."""
    diagnostic: str
    arguments: dict
    device_id: str
    job_id: str
    state: str
    exit_code: int | None
    data: object | None
    raw_stdout: str
    stderr: str
    duration_ms: int | None
    round_trip_ms: int
    truncated: bool

    @property
    def succeeded(self) -> bool:
        return self.state == "Completed" and self.exit_code == 0

    def summary(self) -> str:
        if self.succeeded:
            return f"{self.diagnostic}: ok in {self.duration_ms}ms"
        return f"{self.diagnostic}: {self.state}" + (
            f" (exit {self.exit_code})" if self.exit_code else "")


class RmmClient:
    def __init__(self, base_url: str, api_key: str, *, request_timeout: float = 90.0) -> None:
        if not base_url.startswith("https://") and "localhost" not in base_url:
            raise ValueError("refusing to send an operator key over an unencrypted connection")
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._request_timeout = request_timeout

    # ---------- transport ----------

    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        request = urllib.request.Request(
            self._base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-API-Key": self._key,
                     **({"Content-Type": "application/json"} if body is not None else {})},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._request_timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = _detail(error)
            if error.code in (404, 409, 403):
                raise DeviceUnavailable(detail) from None
            raise RmmError(f"{method} {path} failed ({error.code}): {detail}") from None
        except urllib.error.URLError as error:
            raise RmmError(f"control plane unreachable: {error.reason}") from None

    # ---------- devices ----------

    def list_devices(self) -> list[Device]:
        rows = self._request("GET", "/api/devices")
        return [Device(device_id=r["deviceId"], hostname=r["hostname"], online=r["online"],
                       os_version=r["osVersion"], uptime_seconds=r.get("uptimeSeconds"))
                for r in rows]

    def resolve_device(self, needle: str) -> Device:
        """Accepts a device id or a hostname fragment. Refuses to guess when a
        fragment matches more than one machine: silently choosing which computer
        to run commands on is not an acceptable failure mode."""
        devices = self.list_devices()
        for device in devices:
            if device.device_id == needle:
                return device
        matches = [d for d in devices if needle.lower() in d.hostname.lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise DeviceUnavailable(f"no enrolled device matches '{needle}'")
        raise DeviceUnavailable(
            f"'{needle}' matches several devices: {', '.join(d.hostname for d in matches)}")

    # ---------- diagnostics ----------

    def run_diagnostic(self, device_id: str, name: str, arguments: dict | None = None,
                       *, deadline_seconds: float | None = None,
                       idempotency_key: str | None = None) -> DiagnosticResult:
        """Dispatches one reviewed diagnostic and waits for a terminal state.

        The idempotency key is derived once per logical attempt and reused on
        retry, so a lost response cannot cause the same check to run twice.
        """
        diagnostic = diagnostics.get(name)
        script = diagnostic.build(arguments)
        deadline = deadline_seconds or diagnostic.timeout_seconds + 15
        idempotency_key = idempotency_key or f"diag-{uuid.uuid4().hex}"

        started = time.perf_counter()
        dispatch = self._request("POST", f"/api/devices/{device_id}/jobs", {
            "script": script,
            "timeoutSeconds": diagnostic.timeout_seconds,
            "idempotencyKey": idempotency_key,
        })
        job_id = dispatch["jobId"]

        job = self._await_terminal(job_id, deadline)
        round_trip_ms = int((time.perf_counter() - started) * 1000)

        stdout = job.get("stdout") or ""
        return DiagnosticResult(
            diagnostic=name,
            arguments=dict(arguments or {}),
            device_id=device_id,
            job_id=job_id,
            state=job["state"],
            exit_code=job.get("exitCode"),
            data=_parse_json(stdout),
            raw_stdout=stdout,
            stderr=job.get("stderr") or "",
            duration_ms=job.get("durationMs"),
            round_trip_ms=round_trip_ms,
            truncated=bool(job.get("stdoutTruncated") or job.get("stderrTruncated")),
        )

    def _await_terminal(self, job_id: str, deadline_seconds: float) -> dict:
        """Waits for a terminal state or gives up. The control plane's own
        supervisor also forces terminal states, so this deadline guards against
        the control plane itself being unreachable, not against a hung job."""
        expires_at = time.monotonic() + deadline_seconds
        while True:
            remaining = expires_at - time.monotonic()
            if remaining <= 0:
                raise RmmError(
                    f"job {job_id} did not reach a terminal state within {deadline_seconds:.0f}s")
            wait_ms = int(min(remaining, 15.0) * 1000)
            job = self._request("GET", f"/api/jobs/{job_id}?waitMs={wait_ms}")
            if job["state"] in TERMINAL_STATES:
                return job


def _parse_json(stdout: str) -> object | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _detail(error: urllib.error.HTTPError) -> str:
    try:
        return json.load(error).get("detail", error.reason)
    except Exception:
        return str(error.reason)
