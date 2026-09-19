from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import logging
import math
import os
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

import auth
import eventlog
import inventory
import protocol
import reboots
from jobs import JobStore
from protocol import JobState, hello_ack, job_dispatch
from registry import HEARTBEAT_INTERVAL_SECONDS, DeviceConnection, DeviceRegistry
from store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("controlplane")

SUPERVISOR_TICK_SECONDS = 1.0
TIMEOUT_GRACE_SECONDS = 5.0
# Finished jobs are served from SQLite; memory holds only what is in flight.
FINISHED_JOB_RETENTION_SECONDS = 60.0
STATIC_DIR = Path(__file__).parent / "static"
DIST_DIR = Path(os.environ.get("SQUASH_DIST", Path(__file__).parent / "dist"))
DB_PATH = os.environ.get("SQUASH_DB", str(Path(__file__).parent / "squash.db"))
# Reject results from agents too old to sign them. Off only while a fleet is
# mid-upgrade; every such result is audited as unverified.
REQUIRE_ATTESTATION = os.environ.get("SQUASH_REQUIRE_ATTESTATION", "1") != "0"

store = Store(DB_PATH)
registry = DeviceRegistry()
jobs = JobStore(store)
OPERATOR_KEYS = auth.load_operator_keys()

import investigations  # noqa: E402  (after `store` exists, which it depends on)
investigations.configure(store)


def require_operator(x_api_key: str | None = Header(default=None)) -> str:
    operator = auth.match_operator(x_api_key, OPERATOR_KEYS)
    if operator is None:
        raise HTTPException(status_code=401, detail="Valid X-API-Key required.")
    return operator


class DispatchRequest(BaseModel):
    script: str = Field(min_length=1)
    timeout_seconds: int = Field(default=30, ge=1, le=600, alias="timeoutSeconds")
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=protocol.MAX_OUTPUT_BYTES,
                                  alias="maxOutputBytes")
    idempotency_key: str | None = Field(default=None, alias="idempotencyKey")

    model_config = {"populate_by_name": True}

    @field_validator("script")
    @classmethod
    def _fits_a_command_line(cls, script: str) -> str:
        if protocol.script_length(script) > protocol.MAX_SCRIPT_CHARS:
            raise ValueError(f"script is longer than {protocol.MAX_SCRIPT_CHARS} characters, "
                             "which Windows cannot pass to PowerShell")
        return script


class RestartRequest(BaseModel):
    """The delay has a floor because the machine has to stay up long enough to
    report the result of its own restart; see protocol.restart_script."""
    delay_seconds: int = Field(default=15, alias="delaySeconds",
                               ge=protocol.MIN_RESTART_DELAY_SECONDS,
                               le=protocol.MAX_RESTART_DELAY_SECONDS)
    reason: str = Field(default=protocol.DEFAULT_RESTART_REASON, max_length=200)
    idempotency_key: str | None = Field(default=None, alias="idempotencyKey")

    model_config = {"populate_by_name": True}


class UpgradeRequest(BaseModel):
    idempotency_key: str | None = Field(default=None, alias="idempotencyKey")

    model_config = {"populate_by_name": True}


class EnrollRequest(BaseModel):
    token: str
    device_id: str = Field(alias="deviceId")
    public_key: str = Field(alias="publicKey")
    hostname: str
    os_version: str = Field(alias="osVersion")
    agent_version: str = Field(alias="agentVersion")

    model_config = {"populate_by_name": True}


async def supervise() -> None:
    while True:
        await asyncio.sleep(SUPERVISOR_TICK_SECONDS)
        now = time.time()
        jobs.evict_finished(FINISHED_JOB_RETENTION_SECONDS)
        for job in jobs.active():
            connection = registry.get(job.device_id)
            if connection is None or not connection.is_reachable:
                jobs.fail(job, JobState.UNREACHABLE, "Device is not reachable.")
                store.audit("system", "job.unreachable", device_id=job.device_id, job_id=job.job_id)
                continue

            started = job.dispatched_at or job.created_at
            if now - started > job.timeout_seconds + TIMEOUT_GRACE_SECONDS:
                jobs.fail(job, JobState.TIMED_OUT, f"No result within {job.timeout_seconds}s.")
                store.audit("system", "job.timeout", device_id=job.device_id, job_id=job.job_id)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    store.orphan_active_jobs()
    if not OPERATOR_KEYS:
        log.warning("No operator keys configured; the REST API will reject every request.")
    task = asyncio.create_task(supervise())
    refresher = asyncio.create_task(refresh_inventories())
    restart_watcher = asyncio.create_task(watch_restarts())
    recovered = investigations.recover()
    if recovered:
        log.warning("resumed %d interrupted investigation task(s)", len(recovered))
    try:
        yield
    finally:
        for background in (task, refresher, restart_watcher):
            background.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await background


app = FastAPI(title="Squash RMM Control Plane", lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _dist_file(name: str, media_type: str) -> FileResponse:
    """Install artifacts are unauthenticated on purpose: they contain no
    secrets, and an endpoint has no credential until it enrols. Integrity
    comes from the published SHA-256, which is why this must run over TLS
    in any real deployment."""
    path = DIST_DIR / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"{name} has not been published.")
    return FileResponse(path, media_type=media_type, filename=name)


@app.get("/download/agent.exe")
async def download_agent() -> FileResponse:
    return _dist_file("SquashRmm.Agent.exe", "application/octet-stream")


@app.get("/download/agent.sha256")
async def download_agent_hash() -> FileResponse:
    return _dist_file("SquashRmm.Agent.exe.sha256", "text/plain")


@app.get("/install.ps1")
async def install_script() -> FileResponse:
    return _dist_file("install.ps1", "text/plain")


@app.get("/uninstall.ps1")
async def uninstall_script() -> FileResponse:
    return _dist_file("uninstall.ps1", "text/plain")


class TokenRequest(BaseModel):
    allow_rebind: bool = Field(default=False, alias="allowRebind")
    device_id: str | None = Field(default=None, alias="deviceId")

    model_config = {"populate_by_name": True}


@app.post("/api/enrollment-tokens", status_code=201)
async def mint_enrollment_token(request: TokenRequest | None = None,
                                operator: str = Depends(require_operator)) -> dict:
    """A default token enrols a new device. `allowRebind` additionally permits
    replacing an enrolled device's key, and should be pinned to a `deviceId`
    so that a leak cannot be redirected at another machine."""
    request = request or TokenRequest()
    if request.allow_rebind and not request.device_id:
        raise HTTPException(
            status_code=400,
            detail="A recovery token must name the deviceId it may rebind.")

    token = auth.new_enrollment_token()
    expires_at = store.create_enrollment_token(
        auth.hash_token(token), auth.ENROLLMENT_TOKEN_TTL_SECONDS, operator,
        allow_rebind=request.allow_rebind, bound_device_id=request.device_id,
    )
    store.audit(operator, "enrollment_token.create",
                device_id=request.device_id,
                detail={"allowRebind": request.allow_rebind})
    return {"token": token, "expiresAt": expires_at,
            "ttlSeconds": auth.ENROLLMENT_TOKEN_TTL_SECONDS,
            "allowRebind": request.allow_rebind, "boundDeviceId": request.device_id}


@app.post("/api/enroll", status_code=201)
async def enroll(request: EnrollRequest) -> dict:
    """Authenticated by the single-use enrolment token only. Grants no standing
    access: it registers a key and is immediately burned.

    A plain token can only claim a device id that is not yet enrolled. Replacing
    an enrolled device's key is credential recovery, which needs a token the
    operator explicitly issued for it -- a matching device id proves nothing,
    since the id is derived from hardware an attacker may simply assert.
    """
    ok, reason, grants = store.redeem_enrollment_token(
        auth.hash_token(request.token), request.device_id)
    if not ok:
        store.audit("unknown", "enroll.rejected", device_id=request.device_id,
                    detail={"reason": reason})
        raise HTTPException(status_code=403, detail=f"Enrollment refused: {reason}")

    existing = store.get_device(request.device_id)

    hostname = protocol.clean_endpoint_text(request.hostname)
    os_version = protocol.clean_endpoint_text(request.os_version)
    agent_version = protocol.clean_endpoint_text(request.agent_version, max_length=32)

    if existing is None:
        store.insert_device(request.device_id, request.public_key, hostname,
                            os_version, agent_version)
        store.audit("device", "enroll.success", device_id=request.device_id,
                    detail={"hostname": hostname})
        log.info("device %s (%s) enrolled", request.device_id, hostname)
        return {"deviceId": request.device_id,
                "heartbeatIntervalSeconds": HEARTBEAT_INTERVAL_SECONDS}

    if existing["revoked"]:
        store.audit("unknown", "enroll.rejected", device_id=request.device_id,
                    detail={"reason": "device is revoked", "hostname": hostname})
        log.warning("rejected enrolment for revoked device %s", request.device_id)
        raise HTTPException(
            status_code=403,
            detail="Device is revoked. An operator must restore it before it can re-enrol.")

    if not grants.get("allow_rebind"):
        store.audit("unknown", "enroll.rejected", device_id=request.device_id,
                    detail={"reason": "device already enrolled; recovery token required",
                            "hostname": hostname})
        log.warning("rejected key replacement for enrolled device %s", request.device_id)
        raise HTTPException(
            status_code=409,
            detail="Device is already enrolled. Replacing its key requires a "
                   "recovery token issued for that device.")

    if not store.rebind_device(request.device_id, request.public_key, hostname,
                               os_version, agent_version):
        raise HTTPException(status_code=409, detail="Device could not be rebound.")

    store.audit("device", "enroll.rebind", device_id=request.device_id,
                detail={"hostname": hostname,
                        "previousHostname": existing["hostname"],
                        "authorizedBy": "recovery token"})
    log.warning("device %s key replaced via recovery token", request.device_id)
    return {"deviceId": request.device_id, "rebound": True,
            "heartbeatIntervalSeconds": HEARTBEAT_INTERVAL_SECONDS}


def uptime_view(row: dict, online: bool) -> dict:
    """Uptime only advances while we can see the device. An offline machine may
    be powered off, so its last observation is reported as last known rather
    than extrapolated forward."""
    observed = row.get("last_uptime_observed_at")
    reported = row.get("last_uptime_seconds")
    if reported is None or observed is None:
        return {"uptimeSeconds": None, "uptimeIsLastKnown": False, "uptimeObservedAt": None}
    if online:
        return {"uptimeSeconds": round(reported + max(0.0, time.time() - observed)),
                "uptimeIsLastKnown": False, "uptimeObservedAt": observed}
    return {"uptimeSeconds": round(reported),
            "uptimeIsLastKnown": True, "uptimeObservedAt": observed}


@app.get("/api/devices")
async def list_devices(operator: str = Depends(require_operator)) -> list[dict]:
    out = []
    for row in store.list_devices():
        connection = registry.get(row["device_id"])
        out.append({
            "deviceId": row["device_id"],
            "hostname": row["hostname"],
            "osVersion": row["os_version"],
            "agentVersion": row["agent_version"],
            "online": bool(connection and connection.is_reachable),
            "secondsSinceLastSeen": connection.seconds_since_last_seen if connection else None,
            "enrolledAt": row["enrolled_at"],
            "lastSeenAt": row["last_seen_at"],
            "revoked": bool(row["revoked"]),
            "lastBootAt": row["last_boot_at"],
            **uptime_view(row, bool(connection and connection.is_reachable)),
        })
    return out


@app.get("/api/devices/{device_id}/events")
async def device_events(device_id: str, limit: int = Query(default=50, ge=1, le=500),
                        operator: str = Depends(require_operator)) -> list[dict]:
    if store.get_device(device_id) is None:
        raise HTTPException(status_code=404, detail="Unknown device.")
    return store.device_events(device_id, limit)


@app.post("/api/devices/{device_id}/revoke")
async def revoke_device(device_id: str, operator: str = Depends(require_operator)) -> dict:
    if not store.revoke_device(device_id):
        raise HTTPException(status_code=404, detail="Unknown device.")
    connection = registry.get(device_id)
    if connection is not None:
        connection.revoked = True
    # Revocation must take effect now, not at the next reconnect: drop any work
    # already queued for the device and close the socket it is holding.
    cancelled = 0
    for job in list(jobs.active()):
        if job.device_id == device_id:
            jobs.fail(job, JobState.UNREACHABLE, "Device was revoked before the job completed.")
            store.audit(operator, "job.cancelled_by_revoke",
                        device_id=device_id, job_id=job.job_id)
            cancelled += 1

    if connection is not None:
        connection.drain_pending()
        await connection.close()

    store.audit(operator, "device.revoke", device_id=device_id,
                detail={"cancelledJobs": cancelled, "hadLiveConnection": connection is not None})
    return {"deviceId": device_id, "revoked": True, "cancelledJobs": cancelled}


@app.post("/api/devices/{device_id}/unrevoke")
async def unrevoke_device(device_id: str, operator: str = Depends(require_operator)) -> dict:
    """Restoring a revoked device is an explicit operator act, never a
    side effect of the device re-enrolling."""
    if not store.unrevoke_device(device_id):
        raise HTTPException(status_code=404, detail="Unknown device.")
    connection = registry.get(device_id)
    if connection is not None:
        connection.revoked = False
    store.audit(operator, "device.unrevoke", device_id=device_id)
    return {"deviceId": device_id, "revoked": False}


@app.get("/api/jobs")
async def list_jobs(
    limit: int = Query(default=50, ge=1, le=1000),
    page: int | None = Query(default=None, ge=1),
    page_size: int = Query(default=30, ge=1, le=100, alias="pageSize"),
    state: JobState | None = None,
    device_id: str | None = Query(default=None, alias="deviceId"),
    search: str = Query(default="", max_length=500),
    operator: str = Depends(require_operator),
) -> dict | list[dict]:
    # Keep the existing array response for callers using only ?limit=.
    if page is None and state is None and device_id is None and not search:
        return jobs.recent(limit)
    return jobs.page(page or 1, page_size, state=state.value if state else None,
                     device_id=device_id, search=search)


@app.get("/api/audit")
async def list_audit(limit: int = 100, operator: str = Depends(require_operator)) -> list[dict]:
    return store.recent_audit(limit)


async def send_to_device(device_id: str, script: str, *, timeout_seconds: int,
                         max_output_bytes: int, operator: str,
                         idempotency_key: str | None, action: str,
                         detail: dict) -> dict:
    """The one path from an operator request to a script on an endpoint.

    Every route that runs something goes through here, so the checks that
    matter -- deduplication, enrolment, revocation, reachability -- cannot be
    skipped by adding a new route that forgets one of them.
    """
    if idempotency_key:
        earlier = store.job_for_idempotency_key(idempotency_key)
        if earlier:
            # A key proves a retry only if the request is the same one. Anything
            # else is a collision, and answering it with the earlier job would
            # hand the caller a result from a different script or device.
            # (maxOutputBytes is not stored, so it is not compared.)
            same = (earlier["device_id"], earlier["script"], earlier["timeout_seconds"],
                    earlier["created_by"]) == (device_id, script, timeout_seconds, operator)
            if not same:
                store.audit(operator, "job.idempotency_conflict", device_id=device_id,
                            job_id=earlier["job_id"], detail={"action": action})
                raise HTTPException(
                    status_code=409,
                    detail="This idempotencyKey was already used for a different request.")
            return {"jobId": earlier["job_id"], "state": "Duplicate", "deduplicated": True}

    def refuse(status_code: int, reason: str) -> HTTPException:
        # The caller learns at once; the attempt still leaves a record.
        store.audit(operator, "job.refused", device_id=device_id,
                    detail={"action": action, "reason": reason})
        return HTTPException(status_code=status_code, detail=f"Device '{device_id}' {reason}.")

    device = store.get_device(device_id)
    if device is None:
        raise refuse(404, "is not enrolled")
    if device["revoked"]:
        raise refuse(403, "is revoked")

    connection = registry.get(device_id)
    if connection is None or not connection.is_reachable:
        raise refuse(409, "is not reachable")

    job = jobs.create(device_id, script, timeout_seconds, max_output_bytes,
                      operator, idempotency_key)
    jobs.mark_dispatched(job)
    store.audit(operator, action, device_id=device_id, job_id=job.job_id, detail=detail)

    await connection.outbound.put(
        job_dispatch(job.job_id, job.script, job.timeout_seconds, job.max_output_bytes)
    )
    return {"jobId": job.job_id, "state": job.state.value}


@app.post("/api/devices/{device_id}/jobs", status_code=202)
async def dispatch(device_id: str, request: DispatchRequest,
                   operator: str = Depends(require_operator)) -> dict:
    return await send_to_device(
        device_id, request.script,
        timeout_seconds=request.timeout_seconds,
        max_output_bytes=request.max_output_bytes,
        operator=operator, idempotency_key=request.idempotency_key,
        action="job.dispatch",
        detail={"scriptBytes": len(request.script),
                "timeoutSeconds": request.timeout_seconds})


@app.post("/api/devices/{device_id}/restart", status_code=202)
async def restart_device(device_id: str, request: RestartRequest | None = None,
                         operator: str = Depends(require_operator)) -> dict:
    """Restarting has its own route rather than being a script an operator is
    expected to know, because it is the one destructive thing in this API and
    it should be legible in the audit log as itself.

    Each restart is tracked as a record of its own (see reboots.py): before it
    is sent, the machine is asked whether it was already waiting on a pending
    reboot; the record then follows it offline and back, and says whether it
    came back with a new boot. GET /api/restarts/{restartId} reads it.
    """
    request = request or RestartRequest()
    try:
        script = protocol.restart_script(request.delay_seconds, request.reason)
    except protocol.RestartError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None

    send = dict(timeout_seconds=30, max_output_bytes=4096, operator=operator,
                idempotency_key=request.idempotency_key, action="device.restart",
                # shutdown.exe schedules the restart and returns at once; it does
                # not block for the delay, so this is an ordinary short job.
                detail={"delaySeconds": request.delay_seconds, "reason": request.reason})

    if request.idempotency_key and store.job_for_idempotency_key(request.idempotency_key):
        # A retry: answered by the earlier restart, or 409 if the key was reused
        # for something else. Nothing is checked or sent again.
        result = await send_to_device(device_id, script, **send)
        record = store.restart_for_job(result["jobId"])
        if record is None:
            return {**result, "delaySeconds": request.delay_seconds}
        return {**result, **_restart_response(record)}

    # Asking first also settles 404/403/409 before anything is recorded.
    pending, pending_error, _ = await check_pending_reboot(device_id, operator)

    restart_id = "rst-" + uuid.uuid4().hex[:20]
    store.insert_restart({
        "restart_id": restart_id, "device_id": device_id, "requested_by": operator,
        "requested_at": time.time(), "delay_seconds": request.delay_seconds,
        "reason": request.reason, "status": "scheduling",
        "pending_before": None if pending is None else int(pending["pending"]),
        "pending_before_reasons": json.dumps(pending["reasons"]) if pending else None,
        "pending_check_error": pending_error,
    })
    try:
        result = await send_to_device(device_id, script,
                                      **{**send, "detail": {**send["detail"], "restartId": restart_id}})
    except HTTPException as error:
        store.update_restart(restart_id, {"status": "failed",
                                          "error": f"the restart could not be sent: {error.detail}"})
        raise
    store.update_restart(restart_id, {"job_id": result["jobId"]})
    store.record_device_event(device_id, "restart_requested",
                              {"operator": operator, "delaySeconds": request.delay_seconds,
                               "restartId": restart_id})
    _spawn(_follow_restart_command(restart_id, jobs.get(result["jobId"])))
    return {**result, **_restart_response(store.get_restart(restart_id))}


def _restart_response(record: dict) -> dict:
    view = restart_view(record)
    return {"restartId": view["restartId"],
            "restartAt": record["requested_at"] + (record["delay_seconds"] or 0),
            "delaySeconds": record["delay_seconds"],
            "pendingRebootBefore": view["pendingRebootBefore"],
            "pendingCheckError": view["pendingCheckError"]}


# ---------- restart tracking ----------

def restart_view(record: dict) -> dict:
    def pending(flag, reasons):
        if flag is None:
            return None
        return {"pending": bool(flag), "reasons": json.loads(reasons) if reasons else []}
    return {
        "restartId": record["restart_id"],
        "deviceId": record["device_id"],
        "status": record["status"],
        "requestedBy": record["requested_by"],
        "requestedAt": record["requested_at"],
        "delaySeconds": record["delay_seconds"],
        "reason": record["reason"],
        "jobId": record["job_id"],
        "pendingRebootBefore": pending(record["pending_before"], record["pending_before_reasons"]),
        "pendingCheckError": record["pending_check_error"],
        "scheduledAt": record["scheduled_at"],
        "wentOfflineAt": record["went_offline_at"],
        "cameBackAt": record["came_back_at"],
        "bootConfirmed": None if record["boot_confirmed"] is None else bool(record["boot_confirmed"]),
        "pendingRebootAfter": pending(record["pending_after"], record["pending_after_reasons"]),
        "error": record["error"],
    }


async def _dispatch_and_wait(device_id: str, script: str, *, timeout_seconds: int,
                             max_output_bytes: int, operator: str, action: str,
                             detail: dict) -> tuple[dict, str]:
    dispatched = await send_to_device(device_id, script, timeout_seconds=timeout_seconds,
                                      max_output_bytes=max_output_bytes, operator=operator,
                                      idempotency_key=None, action=action, detail=detail)
    job = jobs.get(dispatched["jobId"])
    if job is not None and not job.state.is_terminal:
        # The supervisor guarantees a terminal state; this only bounds the wait.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(job.completion), timeout=timeout_seconds + 15)
    return jobs.view(dispatched["jobId"]) or {}, dispatched["jobId"]


async def check_pending_reboot(device_id: str, operator: str) -> tuple[dict | None, str | None, str]:
    """Asks the machine whether Windows is waiting to restart. Raises the
    usual dispatch errors; a check that ran but failed is returned as an
    error, never as "nothing pending"."""
    view, job_id = await _dispatch_and_wait(
        device_id, reboots.PENDING_SCRIPT, timeout_seconds=reboots.CHECK_TIMEOUT_SECONDS,
        max_output_bytes=16384, operator=operator, action="reboot.pending_check", detail={})
    result, error = reboots.parse_pending(view)
    return result, error, job_id


async def _follow_restart_command(restart_id: str, job) -> None:
    if job is not None and not job.state.is_terminal:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(job.completion), timeout=job.timeout_seconds + 30)
    record = store.get_restart(restart_id)
    view = jobs.view(job.job_id) if job is not None else None
    if record is not None:
        store.update_restart(restart_id,
                             reboots.restart_command_finished(record, view or {}, time.time()))


def advance_restarts_on_disconnect(device_id: str) -> None:
    for record in store.open_restarts(device_id):
        store.update_restart(record["restart_id"], reboots.went_offline(record, time.time()))


def advance_restarts_on_return(device_id: str, rebooted: bool | None) -> None:
    for record in store.open_restarts(device_id):
        changes = reboots.came_back(record, rebooted, time.time())
        store.update_restart(record["restart_id"], changes)
        if changes.get("status") == "completed":
            _spawn(_check_pending_after(record["restart_id"], device_id))


async def _check_pending_after(restart_id: str, device_id: str) -> None:
    """Did the restart clear what Windows was waiting for?"""
    try:
        pending, error, _ = await check_pending_reboot(device_id, "system")
    except HTTPException as refused:
        log.info("pending-reboot check after restart %s not run: %s", restart_id, refused.detail)
        return
    if pending is not None:
        store.update_restart(restart_id, {"pending_after": int(pending["pending"]),
                                          "pending_after_reasons": json.dumps(pending["reasons"])})
    else:
        log.info("pending-reboot check after restart %s failed: %s", restart_id, error)


RESTART_WATCH_SECONDS = 30.0


async def watch_restarts() -> None:
    """Closes restarts that will not finish on their own: never went offline,
    or never came back."""
    while True:
        await asyncio.sleep(RESTART_WATCH_SECONDS)
        now = time.time()
        for record in store.open_restarts():
            store.update_restart(record["restart_id"], reboots.overdue(record, now))


@app.get("/api/restarts/{restart_id}")
async def get_restart(restart_id: str, operator: str = Depends(require_operator)) -> dict:
    record = store.get_restart(restart_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown restart.")
    return restart_view(record)


@app.get("/api/devices/{device_id}/restarts")
async def list_restarts(device_id: str, limit: int = Query(default=20, ge=1, le=100),
                        operator: str = Depends(require_operator)) -> list[dict]:
    if store.get_device(device_id) is None:
        raise HTTPException(status_code=404, detail="Unknown device.")
    return [restart_view(r) for r in store.restarts_for_device(device_id, limit)]


@app.get("/api/devices/{device_id}/pending-reboot")
async def pending_reboot(device_id: str, operator: str = Depends(require_operator)) -> dict:
    """Asks the machine now whether Windows is waiting to restart, and why."""
    pending, error, job_id = await check_pending_reboot(device_id, operator)
    if error:
        state = (jobs.view(job_id) or {}).get("state")
        no_answer = state in (None, "Queued", "Dispatched", "Running", "TimedOut", "Unreachable")
        raise HTTPException(status_code=504 if no_answer else 502,
                            detail=f"The device could not answer the check: {error}")
    device = store.get_device(device_id) or {}
    return {"deviceId": device_id, "hostname": device.get("hostname"),
            "pending": pending["pending"], "reasons": pending["reasons"],
            "checkedAt": time.time(), "jobId": job_id}


@app.post("/api/devices/{device_id}/upgrade", status_code=202)
async def upgrade_device(device_id: str, request: UpgradeRequest | None = None,
                         operator: str = Depends(require_operator)) -> dict:
    """Reinstalls the agent in place with whatever build this server serves.

    Like restart, it has its own route so the script lives in one place and
    reads as itself in the audit log. The caller supplies nothing that reaches
    the script: it reinstalls from the server the endpoint is enrolled with,
    into the directory the service is registered in.

    The response means the upgrade is scheduled, not finished. The agent drops
    off about UPGRADE_DELAY_SECONDS later and reconnects on the new build;
    callers watch GET /api/devices for it to come back online. It needs the
    agent to be connected -- a machine whose agent is gone needs a recovery
    token and someone on the machine.
    """
    request = request or UpgradeRequest()
    result = await send_to_device(
        device_id, protocol.UPGRADE_SCRIPT,
        # Only schedules a task and returns; the installer runs afterwards.
        timeout_seconds=60, max_output_bytes=4096,
        operator=operator, idempotency_key=request.idempotency_key,
        action="device.upgrade",
        detail={"startsInSeconds": protocol.UPGRADE_DELAY_SECONDS})

    if not result.get("deduplicated"):
        store.record_device_event(device_id, "upgrade_requested", {"operator": operator})
    return {**result, "startsInSeconds": protocol.UPGRADE_DELAY_SECONDS}


# ---------- inventory ----------
# See inventory.py. Collection is an ordinary job sent by the control plane
# itself, so it is signed, bounded and audited like any other; what callers get
# from the API is the stored result, without running anything.

INVENTORY_TICK_SECONDS = 60.0
_inventory_in_flight: set[str] = set()
_background: set[asyncio.Task] = set()


def _spawn(coroutine) -> None:
    """Runs work in the background, keeping a reference so it is not
    collected before it finishes."""
    task = asyncio.create_task(coroutine)
    _background.add(task)
    task.add_done_callback(_background.discard)


async def start_inventory(device_id: str) -> dict:
    """Sends the collection now and finishes it in the background. Raises the
    same HTTP errors as any dispatch: unknown, revoked, unreachable."""
    _inventory_in_flight.add(device_id)
    try:
        dispatched = await send_to_device(
            device_id, inventory.SCRIPT,
            timeout_seconds=inventory.TIMEOUT_SECONDS,
            max_output_bytes=inventory.MAX_OUTPUT_BYTES,
            operator="system", idempotency_key=None,
            action="inventory.collect", detail={})
    except BaseException:
        _inventory_in_flight.discard(device_id)
        raise
    _spawn(_finish_inventory(device_id, jobs.get(dispatched["jobId"])))
    return dispatched


async def _finish_inventory(device_id: str, job) -> None:
    try:
        if job is not None and not job.state.is_terminal:
            # The supervisor guarantees a terminal state; this only bounds the wait.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(job.completion),
                                       timeout=job.timeout_seconds + 30)
        view = jobs.view(job.job_id) if job is not None else None
        data, error = inventory.parse(view or {})
        store.record_inventory(device_id, attempted_at=time.time(), data=data,
                               job_id=job.job_id if job is not None else None, error=error)
        if error:
            log.warning("inventory for %s not collected: %s", device_id, error)
    finally:
        _inventory_in_flight.discard(device_id)


async def refresh_inventory_if_due(device_id: str, *, force: bool = False) -> None:
    if device_id in _inventory_in_flight:
        return
    if not force and not inventory.due(store.get_inventory(device_id), time.time()):
        return
    try:
        await start_inventory(device_id)
    except HTTPException as error:
        log.info("inventory for %s not started: %s", device_id, error.detail)


async def refresh_inventories() -> None:
    """Keeps every reachable device's inventory within MAX_AGE_SECONDS."""
    while True:
        await asyncio.sleep(INVENTORY_TICK_SECONDS)
        for device in store.list_devices():
            connection = registry.get(device["device_id"])
            if not device["revoked"] and connection is not None and connection.is_reachable:
                await refresh_inventory_if_due(device["device_id"])


def inventory_view(device: dict, record: dict | None, *, include_software: bool = True) -> dict:
    connection = registry.get(device["device_id"])
    data = json.loads(record["data"]) if record and record.get("data") else None
    if data is not None:
        data["softwareCount"] = len(data.get("software") or [])
        if not include_software:
            data.pop("software", None)
    return {
        "deviceId": device["device_id"],
        "hostname": device["hostname"],
        "online": bool(connection and connection.is_reachable),
        "revoked": bool(device["revoked"]),
        # Live: derived from the uptime the agent reports on every connection,
        # so it is current even between inventory collections.
        "lastBootAt": device["last_boot_at"],
        "collectedAt": (record or {}).get("collected_at"),
        "stale": inventory.stale(record, time.time()),
        "collecting": device["device_id"] in _inventory_in_flight,
        "lastAttemptAt": (record or {}).get("attempted_at"),
        "lastError": (record or {}).get("error"),
        "inventory": data,
    }


@app.get("/api/inventory")
async def list_inventory(include_software: bool = Query(default=True, alias="includeSoftware"),
                         operator: str = Depends(require_operator)) -> list[dict]:
    """Every enrolled device with its current inventory. Devices not yet
    collected are listed with "inventory": null."""
    records = store.all_inventory()
    return [inventory_view(d, records.get(d["device_id"]), include_software=include_software)
            for d in store.list_devices()]


@app.get("/api/devices/{device_id}/inventory")
async def device_inventory(device_id: str,
                           include_software: bool = Query(default=True, alias="includeSoftware"),
                           operator: str = Depends(require_operator)) -> dict:
    device = store.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Unknown device.")
    return inventory_view(device, store.get_inventory(device_id),
                          include_software=include_software)


@app.post("/api/devices/{device_id}/inventory/refresh", status_code=202)
async def refresh_inventory(device_id: str, operator: str = Depends(require_operator)) -> dict:
    """Collects now rather than at the next interval. The result replaces the
    stored inventory when the job finishes; read it back with GET."""
    store.audit(operator, "inventory.refresh_requested", device_id=device_id)
    if device_id in _inventory_in_flight:
        return {"deviceId": device_id, "collecting": True, "jobId": None}
    dispatched = await start_inventory(device_id)
    return {"deviceId": device_id, "collecting": True, "jobId": dispatched["jobId"]}


# ---------- event logs ----------
# See eventlog.py. Queried live rather than stored: event logs change by the
# second. The query is a fixed, read-only job built from validated filters, run
# under the caller's name so the audit log shows who looked.

@app.get("/api/devices/{device_id}/event-logs")
async def query_event_log(
    device_id: str,
    log: str = Query(default="System"),
    levels: str | None = Query(default=None, max_length=100),
    since: datetime.datetime | None = Query(default=None),
    until: datetime.datetime | None = Query(default=None),
    max_events: int = Query(default=eventlog.DEFAULT_EVENTS, alias="maxEvents"),
    provider: str | None = Query(default=None),
    event_id: int | None = Query(default=None, alias="eventId"),
    operator: str = Depends(require_operator),
) -> dict:
    """Structured event log entries from one device, newest first."""
    try:
        query = eventlog.make_query(log=log, levels=levels, since=since, until=until,
                                    max_events=max_events, provider=provider,
                                    event_id=event_id)
    except eventlog.QueryError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None

    dispatched = await send_to_device(
        device_id, eventlog.build_script(query),
        timeout_seconds=eventlog.TIMEOUT_SECONDS, max_output_bytes=eventlog.MAX_OUTPUT_BYTES,
        operator=operator, idempotency_key=None,
        action="eventlog.query", detail=query.view())

    job = jobs.get(dispatched["jobId"])
    if job is not None and not job.state.is_terminal:
        # The supervisor guarantees a terminal state; this only bounds the wait.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(job.completion),
                                   timeout=eventlog.TIMEOUT_SECONDS + 15)

    result = jobs.view(dispatched["jobId"]) or {}
    entries, error = eventlog.parse(result)
    if error:
        # 504: the device never answered. 502: it answered, but with a failure.
        no_answer = result.get("state") in (None, "Queued", "Dispatched", "Running",
                                            "TimedOut", "Unreachable")
        raise HTTPException(status_code=504 if no_answer else 502,
                            detail=f"The device could not answer the query: {error}")

    device = store.get_device(device_id) or {}
    return {
        "deviceId": device_id,
        "hostname": device.get("hostname"),
        "query": query.view(),
        "count": len(entries),
        "entries": entries,
        "jobId": dispatched["jobId"],
    }


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, waitMs: int = 0,
                  operator: str = Depends(require_operator)) -> dict:
    job = jobs.get(job_id)
    if job is None:
        view = jobs.view(job_id)
        if view is None:
            raise HTTPException(status_code=404, detail="Unknown job.")
        return view

    if waitMs > 0 and not job.state.is_terminal:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(job.completion), timeout=waitMs / 1000)

    return job.view()


@app.websocket("/agent/connect")
async def agent_connect(websocket: WebSocket) -> None:
    await websocket.accept()

    challenge = auth.new_challenge()
    await websocket.send_json({"type": "challenge", "nonce": challenge})

    try:
        hello = await websocket.receive_json()
    except (WebSocketDisconnect, ValueError):
        return

    device_id = hello.get("deviceId", "")
    if hello.get("type") != "hello" or not device_id:
        await websocket.close(code=1002, reason="expected hello")
        return

    device = store.get_device(device_id)
    if device is None:
        store.audit("unknown", "connect.rejected", device_id=device_id,
                    detail={"reason": "not enrolled"})
        await websocket.close(code=4401, reason="not enrolled")
        return

    if device["revoked"]:
        store.audit("unknown", "connect.rejected", device_id=device_id,
                    detail={"reason": "revoked"})
        await websocket.close(code=4403, reason="revoked")
        return

    if not auth.verify_device_signature(device["public_key"], challenge,
                                        hello.get("signature", "")):
        store.audit("unknown", "connect.rejected", device_id=device_id,
                    detail={"reason": "bad signature"})
        log.warning("device %s failed signature check", device_id)
        await websocket.close(code=4401, reason="signature verification failed")
        return

    connection = registry.register(
        DeviceConnection(
            device_id=device_id,
            hostname=protocol.clean_endpoint_text(
                hello.get("hostname"), fallback=device["hostname"]),
            os_version=protocol.clean_endpoint_text(
                hello.get("osVersion"), fallback=device["os_version"]),
            agent_version=protocol.clean_endpoint_text(
                hello.get("agentVersion"), max_length=32, fallback=device["agent_version"]),
        )
    )
    store.touch_device(device_id)
    store.audit("device", "connect.success", device_id=device_id)
    # Only now, after the signature check, may a device's own report update
    # its record -- and only its own record.
    changed = store.update_device_details(device_id, connection.hostname,
                                          connection.os_version, connection.agent_version)
    if changed:
        store.record_device_event(device_id, "details_changed", changed)
        store.audit("device", "device.details_changed", device_id=device_id, detail=changed)
    rebooted = record_connection(device, hello)
    advance_restarts_on_return(device_id, rebooted)
    # A reboot changes what the inventory says (boot time, often updates), so
    # it is collected again straight away rather than at the next interval.
    _spawn(refresh_inventory_if_due(device_id, force=bool(rebooted)))
    log.info("device %s (%s) authenticated", device_id, connection.hostname)

    await websocket.send_json(hello_ack(device_id, HEARTBEAT_INTERVAL_SECONDS))

    sender = asyncio.create_task(_send_loop(websocket, connection))
    receiver = asyncio.create_task(_receive_loop(websocket, connection))
    revoked = asyncio.create_task(connection.closed.wait())
    try:
        _, pending = await asyncio.wait({sender, receiver, revoked},
                                        return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if revoked.done():
            log.warning("closing socket for revoked device %s", device_id)
            with contextlib.suppress(Exception):
                await websocket.close(code=4403, reason="revoked")
    finally:
        # A reconnect can open a replacement socket before this one finishes
        # closing. Only the connection still registered for the device may
        # record it offline, or the older socket's cleanup marks a live
        # device as gone.
        superseded = registry.get(device_id) is not connection
        registry.remove(device_id, connection)
        if superseded:
            log.info("device %s: stale connection closed, replacement is live", device_id)
        else:
            store.set_disconnected(device_id)
            store.record_device_event(device_id, "offline", {"reason": "connection closed"})
            advance_restarts_on_disconnect(device_id)
            store.audit("device", "disconnect", device_id=device_id)
            log.info("device %s disconnected", device_id)


# Boot time is derived from an uptime counter, so successive reports of the same
# boot differ by a little. Only a gap larger than this is treated as a new boot.
# Reboots are detected from uptime, which comes from a monotonic counter and is
# therefore unaffected by the endpoint's clock. Boot time is derived from that
# clock, so it shifts whenever the clock is corrected and cannot be compared
# reliably; it is kept for display only.
#
# Absent a reboot, uptime should grow by at least the elapsed time. A shortfall
# larger than this means the counter restarted.
UPTIME_SHORTFALL_TOLERANCE_SECONDS = 120.0
# Uptime cannot fall within one boot, so any real decrease is a restart
# regardless of how much time passed. Only measurement jitter is tolerated.
UPTIME_DECREASE_EPSILON_SECONDS = 5.0
# Across a control plane restart the monotonic reference is lost and elapsed
# time falls back to wall clock, which can be adjusted. Require a much larger
# shortfall there: missing a restart is safer than inventing one.
UNRELIABLE_ELAPSED_TOLERANCE_SECONDS = 900.0

# Identifies this process, so a stored monotonic reading is only compared
# against readings from the same process.
OBSERVER_EPOCH = uuid.uuid4().hex
MAX_PLAUSIBLE_UPTIME_SECONDS = 20 * 365 * 24 * 3600
BOOT_TIME_FLOOR = 1_577_836_800.0   # 2020-01-01Z
BOOT_TIME_FUTURE_SLACK_SECONDS = 300.0


def _finite_number(value: object) -> float | None:
    """Rejects booleans, non-numerics, NaN, infinities, and integers too large
    to convert -- each of which otherwise reaches arithmetic and either passes
    every comparison or raises."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def parse_reported_uptime(value: object) -> float | None:
    seconds = _finite_number(value)
    if seconds is None or seconds < 0 or seconds > MAX_PLAUSIBLE_UPTIME_SECONDS:
        return None
    return seconds


def parse_reported_boot_time(value: object) -> float | None:
    """Display only. Endpoint clock-derived, so treated as advisory."""
    milliseconds = _finite_number(value)
    if milliseconds is None:
        return None
    seconds = milliseconds / 1000
    if seconds < BOOT_TIME_FLOOR or seconds > time.time() + BOOT_TIME_FUTURE_SLACK_SECONDS:
        return None
    return seconds


def detect_reboot(previous_uptime: float | None, reported_uptime: float | None,
                  elapsed_seconds: float | None, elapsed_is_reliable: bool = True) -> bool | None:
    """True if the endpoint restarted since we last saw it, False if it did not,
    None if we cannot tell.

    Two independent signals, because neither alone is sufficient:

      - Uptime decreasing. Within one boot the counter only rises, so a fall is
        proof of a restart no matter how little time has passed. This is what
        catches a machine that reboots twice in quick succession, where the new
        uptime is small but the shortfall against elapsed time is not.
      - Uptime rising more slowly than time passed. This catches a restart
        after a long absence, where the new uptime may still exceed the old.

    `elapsed_seconds` must come from a monotonic source; a wall clock can be
    adjusted, and an adjustment would otherwise look exactly like a restart.
    """
    if reported_uptime is None or previous_uptime is None:
        return None

    if reported_uptime < previous_uptime - UPTIME_DECREASE_EPSILON_SECONDS:
        return True

    if elapsed_seconds is None:
        return False

    tolerance = (UPTIME_SHORTFALL_TOLERANCE_SECONDS if elapsed_is_reliable
                 else UNRELIABLE_ELAPSED_TOLERANCE_SECONDS)
    expected = previous_uptime + max(0.0, elapsed_seconds)
    return reported_uptime < expected - tolerance


def elapsed_since_observation(device: dict, monotonic_now: float) -> tuple[float | None, bool]:
    """Time since this device's uptime was last recorded, and whether that
    figure can be trusted. Monotonic readings only survive within one process,
    so after a control plane restart we fall back to the wall clock and say so."""
    if device.get("last_uptime_observer_epoch") == OBSERVER_EPOCH \
            and device.get("last_uptime_observed_monotonic") is not None:
        return max(0.0, monotonic_now - device["last_uptime_observed_monotonic"]), True

    observed_at = device.get("last_uptime_observed_at")
    if observed_at is None:
        return None, False
    return max(0.0, time.time() - observed_at), False


def record_connection(device: dict, hello: dict) -> bool | None:
    """Records what reconnecting tells us, and no more. A device returning with
    the same boot time means only that no new boot was observed -- it could have
    been a network interruption, an agent restart or a control plane restart.
    A later boot time means the endpoint reports having started again."""
    device_id = device["device_id"]
    now = time.time()
    monotonic_now = time.monotonic()

    uptime = parse_reported_uptime(hello.get("uptimeSeconds"))
    boot_at = parse_reported_boot_time(hello.get("bootTimeUnixMs"))

    # Only meaningful when this control plane saw the device go away. If it was
    # restarted while the device was gone, it has no disconnect to measure from,
    # and reporting a number anyway would be an invention.
    unreachable_for = None
    if device.get("last_disconnect_at"):
        unreachable_for = round(max(0.0, now - device["last_disconnect_at"]), 1)

    elapsed, elapsed_is_reliable = elapsed_since_observation(device, monotonic_now)
    rebooted = detect_reboot(device.get("last_uptime_seconds"), uptime,
                             elapsed, elapsed_is_reliable)

    store.record_uptime(device_id, uptime, boot_at, now, monotonic_now, OBSERVER_EPOCH)
    store.clear_disconnected(device_id)

    detail = {"secondsUnreachable": unreachable_for, "uptimeSeconds": uptime}

    if rebooted is None:
        detail["rebootDetermined"] = False
        detail["reason"] = "no comparable previous observation" if uptime is not None \
            else "endpoint did not report uptime"
        store.record_device_event(device_id, "online", detail)
        return None

    if rebooted:
        store.record_device_event(device_id, "rebooted", detail)
        store.audit("system", "device.rebooted", device_id=device_id,
                    detail={"secondsUnreachable": unreachable_for})
        log.info("device %s returned after a restart (unreachable %ss)",
                 device_id, unreachable_for)
    else:
        detail["newBootObserved"] = False
        store.record_device_event(device_id, "online", detail)
    return rebooted


def verify_result(job, payload: dict, device_id: str) -> tuple[bool, str]:
    """A result is accepted only if it describes the script we dispatched and
    carries a signature from the enrolled device's key. Without this, what a
    device reports having run is merely an assertion.

    `payload` is the output of protocol.parse_result, so every field is
    present and of the right type.

    A fleet cannot be upgraded atomically, so an agent predating attestation is
    tolerated while REQUIRE_ATTESTATION is off -- recorded as unverified rather
    than silently trusted, so the gap stays visible in the audit trail.
    """
    expected_sha = protocol.sha256_hex(job.script)
    claimed_sha = payload.get("scriptSha256")
    signature = payload.get("signature")

    if claimed_sha is None and signature is None:
        if REQUIRE_ATTESTATION:
            return False, "agent does not attest results; upgrade it"
        store.audit("system", "job.result_unverified", device_id=device_id,
                    job_id=job.job_id, detail={"reason": "agent predates attestation"})
        return True, "unverified (legacy agent)"

    if claimed_sha != expected_sha:
        return False, f"script hash mismatch (expected {expected_sha[:12]}, got {str(claimed_sha)[:12]})"

    if not signature:
        return False, "result is not signed"

    device = store.get_device(device_id)
    if device is None:
        return False, "device is no longer enrolled"

    attestation = protocol.result_attestation(
        job.job_id, expected_sha, payload["exitCode"],
        payload["durationMs"], payload["stdout"], payload["stderr"])

    if not auth.verify_device_payload(device["public_key"], attestation, signature):
        return False, "signature does not match the enrolled device key"

    return True, "ok"


async def _send_loop(websocket: WebSocket, connection: DeviceConnection) -> None:
    while True:
        message = await connection.outbound.get()
        await websocket.send_json(message)


async def _receive_loop(websocket: WebSocket, connection: DeviceConnection) -> None:
    while True:
        message = await websocket.receive_json()
        connection.touch()
        if not isinstance(message, dict):
            continue
        kind = message.get("type")

        if kind == "heartbeat":
            store.touch_device(connection.device_id)
            continue

        if kind == "job_accepted":
            job = _owned_job(message.get("jobId"), connection)
            if job is not None and job.state is JobState.DISPATCHED:
                jobs.mark_running(job)
            continue

        if kind == "job_result":
            handle_result(message.get("result"), connection)


def handle_result(payload: object, connection: DeviceConnection) -> None:
    """Checks, in order: that the job is this device's, that the result has
    the protocol's shape, that the device signed it, and that it fits the
    limit the job was dispatched with. Only then is it stored."""
    job = _owned_job(payload.get("jobId") if isinstance(payload, dict) else None, connection)
    if job is None:
        log.warning("device %s returned a result for a job it does not own",
                    connection.device_id)
        return

    try:
        result = protocol.parse_result(payload)
    except protocol.MalformedResult as error:
        _reject_result(job, connection, f"malformed result: {error}")
        return

    verified, reason = verify_result(job, result, connection.device_id)
    if not verified:
        _reject_result(job, connection, reason)
        return

    result = protocol.limit_output(result, job.max_output_bytes)
    state = result["state"]
    jobs.complete(job, result, state)
    store.audit("device", "job.result", device_id=connection.device_id,
                job_id=job.job_id,
                detail={"state": state.value, "exitCode": result["exitCode"],
                        "durationMs": result["durationMs"], "attested": True})


def _owned_job(job_id: object, connection: DeviceConnection):
    """The in-flight job with this id, if it belongs to this connection's
    device. Anything else -- a missing id, a non-string, another device's
    job -- is None rather than an exception that would drop the socket."""
    if not isinstance(job_id, str):
        return None
    job = jobs.get(job_id)
    return job if job is not None and job.device_id == connection.device_id else None


def _reject_result(job, connection: DeviceConnection, reason: str) -> None:
    jobs.fail(job, JobState.FAILED, f"Result rejected: {reason}")
    store.audit("system", "job.result_rejected", device_id=connection.device_id,
                job_id=job.job_id, detail={"reason": reason})
    log.error("job %s result rejected: %s", job.job_id, reason)


# ==================================================================
# Investigations -- see docs/design.md and docs/api.md.
#
# The AI driver (diagnosis loop, repair catalogue, approval binding, budget)
# lives in ../driver and is imported by investigations.py, which owns the
# background work. These routes only validate, read and write durable state,
# and schedule that work; none of them execute anything themselves.
# ==================================================================

def iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.datetime.fromtimestamp(
        timestamp, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CreateInvestigationRequest(BaseModel):
    device_id: str = Field(alias="deviceId", min_length=1)
    problem: str = Field(min_length=10, max_length=4000)
    request_id: str = Field(alias="requestId", min_length=1, max_length=128)

    model_config = {"populate_by_name": True}


class InvestigationDecisionRequest(BaseModel):
    proposal_id: str = Field(alias="proposalId")
    proposal_hash: str = Field(alias="proposalHash")
    device_id: str = Field(alias="deviceId")
    decision: Literal["approve", "reject"]

    model_config = {"populate_by_name": True}


def investigation_list_view(row: dict) -> dict:
    return {
        "investigationId": row["investigation_id"],
        "deviceId": row["device_id"],
        "hostname": row["hostname"] or row["device_id"],
        "problem": row["problem"],
        "status": row["status"],
        "createdAt": iso(row["created_at"]),
    }


def proposal_view(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {
        "proposalId": row["proposal_id"],
        "proposalHash": row["proposal_hash"],
        "decision": row["decision"],
        "reasoning": row["reasoning"],
        "expectedEffect": row["expected_effect"],
        "risk": row["risk"],
        "verifiedBy": row["verified_by"],
        "script": row["script"],
        "scriptSha256": row["script_sha256"],
        "refusalReason": row["refusal_reason"],
        "expiresAt": iso(row["expires_at"]),
    }


def investigation_detail_view(row: dict) -> dict:
    import json as _json
    proposal_row = store.get_current_proposal(row["investigation_id"])
    events = [{"at": iso(e["at"]), "message": e["message"]}
              for e in store.get_investigation_events(row["investigation_id"])]
    evidence = [{"diagnostic": e["diagnostic"], "checkSucceeded": bool(e["check_succeeded"]),
                "output": _json.loads(e["output"]) if e["output"] else None, "note": e["note"]}
               for e in store.get_investigation_evidence(row["investigation_id"])]
    return {
        "investigationId": row["investigation_id"],
        "deviceId": row["device_id"],
        "hostname": row["hostname"] or row["device_id"],
        "problem": row["problem"],
        "status": row["status"],
        "createdAt": iso(row["created_at"]),
        "events": events,
        "finding": row["finding"],
        "confidence": row["confidence"],
        "evidence": evidence,
        "proposal": proposal_view(proposal_row) if row["status"] != "queued" else None,
        "outcome": _json.loads(row["outcome"]) if row["outcome"] else None,
        "error": row["error"],
    }


@app.get("/api/investigations")
async def list_investigations(
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=30, ge=1, le=100),
    search: str = Query(default="", max_length=500),
    status: str | None = None,
    operator: str = Depends(require_operator),
) -> dict:
    result = store.list_investigations(page, pageSize, search=search, status=status)
    return {"items": [investigation_list_view(r) for r in result["items"]],
            "page": result["page"], "totalPages": result["totalPages"], "total": result["total"]}


@app.post("/api/investigations", status_code=202)
async def create_investigation(request: CreateInvestigationRequest,
                               operator: str = Depends(require_operator)) -> dict:
    device = store.get_device(request.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{request.device_id}' is not enrolled.")
    if device["revoked"]:
        raise HTTPException(status_code=403, detail="Device is revoked.")

    problem = request.problem.strip()
    if not (10 <= len(problem) <= 4000):
        raise HTTPException(status_code=400,
                            detail="Problem description must be 10-4000 characters.")

    investigation_id = "inv-" + uuid.uuid4().hex[:20]
    row, created = store.create_investigation(
        investigation_id, request.device_id, problem, operator, request.request_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Could not create the investigation.")

    if not created:
        if row["device_id"] != request.device_id or row["problem"] != problem:
            raise HTTPException(
                status_code=409,
                detail="This request ID was already used for a different investigation.")
        return {"investigationId": row["investigation_id"]}

    store.append_investigation_event(row["investigation_id"], f"Request received for {device['hostname']}.")
    store.audit(operator, "investigation.create", device_id=request.device_id,
                detail={"investigationId": row["investigation_id"]})

    if investigations.DRIVER_AVAILABLE:
        investigations.schedule_start(row["investigation_id"])
    else:
        store.set_investigation_error(row["investigation_id"], "AI driver is not deployed on this control plane.")
        store.set_investigation_status(row["investigation_id"], "failed")

    return {"investigationId": row["investigation_id"]}


@app.get("/api/investigations/{investigation_id}")
async def get_investigation(investigation_id: str,
                            operator: str = Depends(require_operator)) -> dict:
    row = store.get_investigation(investigation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown investigation.")
    return investigation_detail_view(row)


@app.post("/api/investigations/{investigation_id}/decision")
async def decide_investigation(investigation_id: str, request: InvestigationDecisionRequest,
                               operator: str = Depends(require_operator)) -> dict:
    inv = store.get_investigation(investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Unknown investigation.")

    proposal = store.get_current_proposal(investigation_id)
    if proposal is None or proposal["decision"] != "proposed":
        raise HTTPException(status_code=409,
                            detail="This investigation has no actionable proposal.")

    binding_matches = (proposal["proposal_id"] == request.proposal_id
                       and proposal["proposal_hash"] == request.proposal_hash
                       and inv["device_id"] == request.device_id
                       and investigations.proposal_hash_matches(
                           investigation_id, inv["device_id"], proposal))
    if not binding_matches:
        raise HTTPException(
            status_code=409,
            detail="The proposal has changed since you last saw it. Refresh and try again.")

    if proposal["decided_at"] is not None:
        # Already decided, by this request or a concurrent one. Identical
        # decisions are idempotent; a different one is a genuine conflict.
        if proposal["decision_outcome"] == request.decision:
            # Also heals the tiny crash window between recording approval and
            # scheduling the durable work. The scheduler deduplicates a task
            # already running in this process.
            if request.decision == "approve" and inv["status"] == "awaiting_approval":
                store.set_investigation_status(investigation_id, "applying")
                investigations.schedule_apply(investigation_id)
            elif request.decision == "reject" and inv["status"] == "awaiting_approval":
                store.set_investigation_status(investigation_id, "rejected")
            return investigation_detail_view(store.get_investigation(investigation_id))
        raise HTTPException(status_code=409, detail="A different decision was already recorded.")

    if inv["status"] != "awaiting_approval":
        raise HTTPException(status_code=409, detail="This proposal is no longer awaiting a decision.")

    if request.decision == "approve" and (
            proposal["expires_at"] is None or time.time() >= proposal["expires_at"]):
        raise HTTPException(status_code=409, detail="This proposal has expired.")

    # Compare-and-set: only the first decision for this proposal is recorded.
    decided, recorded = store.record_proposal_decision(
        proposal["proposal_id"], operator, request.decision)
    if decided is None or decided["decision_outcome"] != request.decision:
        raise HTTPException(status_code=409,
                            detail="A different decision was already recorded.")
    if not recorded:
        # A concurrent identical request won the compare-and-set. It owns the
        # status transition and scheduling; this request is only a read retry.
        return investigation_detail_view(store.get_investigation(investigation_id))

    store.audit(operator, f"investigation.{request.decision}", device_id=inv["device_id"],
                detail={"investigationId": investigation_id, "proposalId": proposal["proposal_id"]})

    if request.decision == "reject":
        store.set_investigation_status(investigation_id, "rejected")
        store.append_investigation_event(investigation_id, "Operator rejected the proposed fix.")
    else:
        store.set_investigation_status(investigation_id, "applying")
        store.append_investigation_event(investigation_id, "Operator approved the proposed fix.")
        if investigations.DRIVER_AVAILABLE:
            investigations.schedule_apply(investigation_id)
        else:
            store.set_investigation_error(investigation_id, "AI driver is not deployed on this control plane.")
            store.set_investigation_status(investigation_id, "failed")

    return investigation_detail_view(store.get_investigation(investigation_id))
