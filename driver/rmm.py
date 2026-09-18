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
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

import diagnostics
from diagnostics import ArgumentError

TERMINAL_STATES = {"Completed", "TimedOut", "Unreachable", "Failed"}
# Floor between polls when the control plane's long-poll returns immediately,
# so a server that does not hold the connection cannot make this client spin.
MIN_POLL_INTERVAL_SECONDS = 0.25


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
    # The control plane's own explanation, e.g. "No result within 30s." or
    # "Device is not reachable." Different causes need different responses, so
    # this must survive rather than be flattened into the state alone.
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.state == "Completed" and self.exit_code == 0

    def summary(self) -> str:
        if self.succeeded:
            return f"{self.diagnostic}: ok in {self.duration_ms}ms"
        parts = [f"{self.diagnostic}: {self.state}"]
        if self.exit_code:
            parts.append(f"exit {self.exit_code}")
        if self.error:
            parts.append(self.error)
        return " — ".join(parts)


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """urllib follows redirects and carries headers with them, so a redirect
    could deliver the operator key to another host, or downgrade to http. An
    API has no legitimate reason to redirect, so all of them are refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RmmError(
            f"control plane redirected to {newurl!r}; refusing to follow and "
            "resend the operator key")


def _validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme == "https":
        return base_url.rstrip("/")
    # Plaintext is tolerated only against the loopback interface, where there
    # is no network for the key to cross. Matching on the parsed hostname
    # matters: a substring test would accept http://localhost.example.com.
    if parsed.scheme == "http" and (parsed.hostname or "") in LOOPBACK_HOSTS:
        return base_url.rstrip("/")
    raise ValueError(
        f"refusing to send an operator key to {base_url!r}: use https, "
        "or http only on localhost")


class RmmClient:
    def __init__(self, base_url: str, api_key: str, *, request_timeout: float = 90.0) -> None:
        self._base = _validate_base_url(base_url)
        self._key = api_key
        self._request_timeout = request_timeout
        self._opener = urllib.request.build_opener(_RefuseRedirects)

    # ---------- transport ----------

    def _request(self, method: str, path: str, body: dict | None = None,
                 timeout: float | None = None) -> dict | list:
        request = urllib.request.Request(
            self._base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-API-Key": self._key,
                     **({"Content-Type": "application/json"} if body is not None else {})},
            method=method,
        )
        effective_timeout = self._request_timeout if timeout is None else max(0.001, timeout)
        try:
            with self._opener.open(request, timeout=effective_timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = _detail(error)
            if error.code in (404, 409, 403):
                raise DeviceUnavailable(detail) from None
            raise RmmError(f"{method} {path} failed ({error.code}): {detail}") from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, RmmError):
                raise error.reason from None
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

        # One deadline covers dispatch and retrieval, and bounds each HTTP
        # request. A per-request timeout alone lets a slow dispatch consume far
        # more than the caller allowed before waiting even begins.
        expires_at = time.monotonic() + deadline
        started = time.perf_counter()

        dispatch = self._request("POST", f"/api/devices/{device_id}/jobs", {
            "script": script,
            "timeoutSeconds": diagnostic.timeout_seconds,
            "idempotencyKey": idempotency_key,
        }, timeout=self._remaining(expires_at, deadline))
        job_id = dispatch["jobId"]

        job = self._await_terminal(job_id, expires_at, deadline)
        round_trip_ms = int((time.perf_counter() - started) * 1000)

        stdout = job.get("stdout") or ""
        truncated = bool(job.get("stdoutTruncated") or job.get("stderrTruncated"))
        return DiagnosticResult(
            diagnostic=name,
            arguments=dict(arguments or {}),
            device_id=device_id,
            job_id=job_id,
            state=job["state"],
            exit_code=job.get("exitCode"),
            # Truncated output is never parsed: a cut-off document can still be
            # syntactically valid and would then become confident, wrong data.
            data=None if truncated else _parse_json(stdout),
            raw_stdout=stdout,
            stderr=job.get("stderr") or "",
            duration_ms=job.get("durationMs"),
            round_trip_ms=round_trip_ms,
            truncated=truncated,
            error=job.get("error"),
        )

    @staticmethod
    def _remaining(expires_at: float, deadline: float) -> float:
        remaining = expires_at - time.monotonic()
        if remaining <= 0:
            raise RmmError(f"deadline of {deadline:.2f}s elapsed before the request completed")
        return remaining

    def run_raw(self, device_id: str, script: str, *, timeout_seconds: int = 60,
                idempotency_key: str | None = None,
                deadline_seconds: float | None = None) -> dict:
        """Dispatches an already-built script and returns the raw job.

        Used for repairs, whose scripts come from the repair catalogue and have
        already been validated there. Nothing should pass model-authored text to
        this: the catalogue is what bounds what can run, and bypassing it would
        make that bound meaningless.
        """
        deadline = deadline_seconds or timeout_seconds + 30
        expires_at = time.monotonic() + deadline
        dispatch = self._request("POST", f"/api/devices/{device_id}/jobs", {
            "script": script,
            "timeoutSeconds": timeout_seconds,
            "idempotencyKey": idempotency_key or f"repair-{uuid.uuid4().hex}",
        }, timeout=self._remaining(expires_at, deadline))
        job = self._await_terminal(dispatch["jobId"], expires_at, deadline)
        job.setdefault("jobId", dispatch["jobId"])
        return job

    def _await_terminal(self, job_id: str, expires_at: float, deadline_seconds: float) -> dict:
        """Waits for a terminal state or gives up. The control plane's own
        supervisor also forces terminal states, so this deadline guards against
        the control plane itself being unreachable, not against a hung job.

        The long-poll normally blocks server-side. If it returns immediately --
        an older build, a proxy that does not hold the connection -- this would
        otherwise spin, so a returning-too-fast response is paced locally.
        """
        while True:
            remaining = expires_at - time.monotonic()
            if remaining <= 0:
                raise RmmError(
                    f"job {job_id} did not reach a terminal state within {deadline_seconds:.2f}s")

            wait_ms = int(min(remaining, 15.0) * 1000)
            asked_at = time.monotonic()
            # Allow a little beyond the long-poll for the response itself, but
            # never beyond the caller's deadline.
            job = self._request("GET", f"/api/jobs/{job_id}?waitMs={wait_ms}",
                                timeout=min(remaining, wait_ms / 1000 + 10.0))
            if job["state"] in TERMINAL_STATES:
                return job

            elapsed = time.monotonic() - asked_at
            if elapsed < MIN_POLL_INTERVAL_SECONDS:
                time.sleep(min(MIN_POLL_INTERVAL_SECONDS - elapsed,
                               max(0.0, expires_at - time.monotonic())))


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
