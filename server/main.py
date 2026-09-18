from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import auth
import protocol
from jobs import JobStore
from protocol import JobState, hello_ack, job_dispatch, parse_job_state
from registry import HEARTBEAT_INTERVAL_SECONDS, DeviceConnection, DeviceRegistry
from store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("controlplane")

SUPERVISOR_TICK_SECONDS = 1.0
TIMEOUT_GRACE_SECONDS = 5.0
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


def require_operator(x_api_key: str | None = Header(default=None)) -> str:
    operator = auth.match_operator(x_api_key, OPERATOR_KEYS)
    if operator is None:
        raise HTTPException(status_code=401, detail="Valid X-API-Key required.")
    return operator


class DispatchRequest(BaseModel):
    script: str = Field(min_length=1)
    timeout_seconds: int = Field(default=30, ge=1, le=600, alias="timeoutSeconds")
    max_output_bytes: int = Field(default=1_048_576, ge=1024, alias="maxOutputBytes")
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
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


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
            "uptimeSeconds": round(time.time() - row["last_boot_at"])
                             if row["last_boot_at"] else None,
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


@app.post("/api/devices/{device_id}/jobs", status_code=202)
async def dispatch(device_id: str, request: DispatchRequest,
                   operator: str = Depends(require_operator)) -> dict:
    if request.idempotency_key:
        existing = store.job_id_for_idempotency_key(request.idempotency_key)
        if existing:
            return {"jobId": existing, "state": "Duplicate", "deduplicated": True}

    device = store.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' is not enrolled.")
    if device["revoked"]:
        raise HTTPException(status_code=403, detail=f"Device '{device_id}' is revoked.")

    connection = registry.get(device_id)
    if connection is None or not connection.is_reachable:
        raise HTTPException(status_code=409, detail=f"Device '{device_id}' is not reachable.")

    job = jobs.create(device_id, request.script, request.timeout_seconds,
                      request.max_output_bytes, operator, request.idempotency_key)
    jobs.mark_dispatched(job)
    store.audit(operator, "job.dispatch", device_id=device_id, job_id=job.job_id,
                detail={"scriptBytes": len(request.script),
                        "timeoutSeconds": request.timeout_seconds})

    await connection.outbound.put(
        job_dispatch(job.job_id, job.script, job.timeout_seconds, job.max_output_bytes)
    )
    return {"jobId": job.job_id, "state": job.state.value}


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
    record_connection(device, hello)
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
        registry.remove(device_id, connection)
        store.set_disconnected(device_id)
        store.record_device_event(device_id, "offline", {"reason": "connection closed"})
        store.audit("device", "disconnect", device_id=device_id)
        log.info("device %s disconnected", device_id)


# Boot time is derived from an uptime counter, so successive reports of the same
# boot differ by a little. Only a gap larger than this is treated as a new boot.
BOOT_TIME_TOLERANCE_SECONDS = 120.0
# A machine claiming to have booted in the future, or before this software
# existed, is reporting a broken clock or lying. Either way the value is not
# usable, and a far-future value would otherwise poison every later comparison.
BOOT_TIME_FLOOR = 1_577_836_800.0   # 2020-01-01Z
BOOT_TIME_FUTURE_SLACK_SECONDS = 300.0


def parse_reported_boot_time(value: object) -> float | None:
    """Endpoint-reported boot time, rejected unless it is plausible."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    seconds = value / 1000
    if seconds < BOOT_TIME_FLOOR:
        return None
    if seconds > time.time() + BOOT_TIME_FUTURE_SLACK_SECONDS:
        return None
    return seconds


def record_connection(device: dict, hello: dict) -> None:
    """Records what reconnecting tells us, and no more. A device returning with
    the same boot time means only that no new boot was observed -- it could have
    been a network interruption, an agent restart or a control plane restart.
    A later boot time means the endpoint reports having started again."""
    device_id = device["device_id"]
    boot_at = parse_reported_boot_time(hello.get("bootTimeUnixMs"))

    previous_boot = device.get("last_boot_at")
    unreachable_for = None
    if device.get("last_disconnect_at"):
        unreachable_for = round(time.time() - device["last_disconnect_at"], 1)

    if boot_at is None:
        store.record_device_event(device_id, "online",
                                  {"bootTimeReported": False,
                                   "secondsUnreachable": unreachable_for})
        return

    store.set_boot_time(device_id, boot_at)

    drift = boot_at - previous_boot if previous_boot is not None else None

    # A boot time moving backwards is not a reboot; it means the endpoint's
    # clock changed. Record it rather than silently treating it as normal.
    if drift is not None and drift < -BOOT_TIME_TOLERANCE_SECONDS:
        store.record_device_event(device_id, "boot_time_regressed", {
            "previousBootAt": previous_boot, "bootAt": boot_at,
            "secondsUnreachable": unreachable_for,
        })
        log.warning("device %s reported an earlier boot time than before", device_id)
        return

    if drift is not None and drift > BOOT_TIME_TOLERANCE_SECONDS:
        store.record_device_event(device_id, "rebooted", {
            "previousBootAt": previous_boot,
            "bootAt": boot_at,
            # What the control plane can actually measure: how long the device
            # was out of contact. Windows may have been down for less.
            "secondsUnreachable": unreachable_for,
        })
        store.audit("system", "device.rebooted", device_id=device_id,
                    detail={"secondsUnreachable": unreachable_for})
        log.info("device %s returned after a new boot (unreachable %ss)",
                 device_id, unreachable_for)
    else:
        store.record_device_event(device_id, "online", {
            "newBootObserved": False,
            "secondsUnreachable": unreachable_for,
        })


def verify_result(job, payload: dict, device_id: str) -> tuple[bool, str]:
    """A result is accepted only if it describes the script we dispatched and
    carries a signature from the enrolled device's key. Without this, what a
    device reports having run is merely an assertion.

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
        job.job_id, expected_sha, payload.get("exitCode"),
        payload.get("durationMs") or 0, payload.get("stdout", ""), payload.get("stderr", ""))

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
        kind = message.get("type")

        if kind == "heartbeat":
            store.touch_device(connection.device_id)
            continue

        if kind == "job_accepted":
            job = jobs.get(message.get("jobId", ""))
            if job is not None and job.device_id == connection.device_id \
                    and job.state is JobState.DISPATCHED:
                jobs.mark_running(job)
            continue

        if kind == "job_result":
            payload = message.get("result") or {}
            job = jobs.get(payload.get("jobId", ""))
            if job is None or job.device_id != connection.device_id:
                log.warning("device %s returned a result for a job it does not own",
                            connection.device_id)
                continue

            verified, reason = verify_result(job, payload, connection.device_id)
            if not verified:
                jobs.fail(job, JobState.FAILED, f"Result rejected: {reason}")
                store.audit("system", "job.result_rejected", device_id=connection.device_id,
                            job_id=job.job_id, detail={"reason": reason})
                log.error("job %s result rejected: %s", job.job_id, reason)
                continue

            state = parse_job_state(payload.get("state", JobState.COMPLETED.value))
            jobs.complete(job, payload, state)
            store.audit("device", "job.result", device_id=connection.device_id,
                        job_id=job.job_id,
                        detail={"state": state.value, "exitCode": payload.get("exitCode"),
                                "durationMs": payload.get("durationMs"),
                                "attested": True})
