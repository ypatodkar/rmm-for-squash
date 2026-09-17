from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import auth
from jobs import JobStore
from protocol import JobState, hello_ack, job_dispatch, parse_job_state
from registry import HEARTBEAT_INTERVAL_SECONDS, DeviceConnection, DeviceRegistry
from store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("controlplane")

SUPERVISOR_TICK_SECONDS = 1.0
TIMEOUT_GRACE_SECONDS = 5.0
STATIC_DIR = Path(__file__).parent / "static"
DB_PATH = os.environ.get("SQUASH_DB", str(Path(__file__).parent / "squash.db"))

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


@app.post("/api/enrollment-tokens", status_code=201)
async def mint_enrollment_token(operator: str = Depends(require_operator)) -> dict:
    token = auth.new_enrollment_token()
    expires_at = store.create_enrollment_token(
        auth.hash_token(token), auth.ENROLLMENT_TOKEN_TTL_SECONDS, operator
    )
    store.audit(operator, "enrollment_token.create")
    return {"token": token, "expiresAt": expires_at,
            "ttlSeconds": auth.ENROLLMENT_TOKEN_TTL_SECONDS}


@app.post("/api/enroll", status_code=201)
async def enroll(request: EnrollRequest) -> dict:
    """Authenticated by the single-use enrolment token only. Grants no
    standing access: it registers a key and is immediately burned."""
    ok, reason = store.redeem_enrollment_token(auth.hash_token(request.token), request.device_id)
    if not ok:
        store.audit("unknown", "enroll.rejected", device_id=request.device_id,
                    detail={"reason": reason})
        raise HTTPException(status_code=403, detail=f"Enrollment refused: {reason}")

    store.upsert_device(request.device_id, request.public_key, request.hostname,
                        request.os_version, request.agent_version)
    store.audit("device", "enroll.success", device_id=request.device_id,
                detail={"hostname": request.hostname})
    log.info("device %s (%s) enrolled", request.device_id, request.hostname)
    return {"deviceId": request.device_id, "heartbeatIntervalSeconds": HEARTBEAT_INTERVAL_SECONDS}


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
        })
    return out


@app.post("/api/devices/{device_id}/revoke")
async def revoke_device(device_id: str, operator: str = Depends(require_operator)) -> dict:
    if not store.revoke_device(device_id):
        raise HTTPException(status_code=404, detail="Unknown device.")
    connection = registry.get(device_id)
    if connection is not None:
        connection.revoked = True
    store.audit(operator, "device.revoke", device_id=device_id)
    return {"deviceId": device_id, "revoked": True}


@app.get("/api/jobs")
async def list_jobs(limit: int = 50, operator: str = Depends(require_operator)) -> list[dict]:
    return jobs.recent(limit)


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
            hostname=hello.get("hostname", device["hostname"]),
            os_version=hello.get("osVersion", device["os_version"]),
            agent_version=hello.get("agentVersion", device["agent_version"]),
        )
    )
    store.touch_device(device_id)
    store.audit("device", "connect.success", device_id=device_id)
    log.info("device %s (%s) authenticated", device_id, connection.hostname)

    await websocket.send_json(hello_ack(device_id, HEARTBEAT_INTERVAL_SECONDS))

    sender = asyncio.create_task(_send_loop(websocket, connection))
    receiver = asyncio.create_task(_receive_loop(websocket, connection))
    try:
        _, pending = await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    finally:
        registry.remove(device_id, connection)
        store.audit("device", "disconnect", device_id=device_id)
        log.info("device %s disconnected", device_id)


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
            state = parse_job_state(payload.get("state", JobState.COMPLETED.value))
            jobs.complete(job, payload, state)
            store.audit("device", "job.result", device_id=connection.device_id,
                        job_id=job.job_id,
                        detail={"state": state.value, "exitCode": payload.get("exitCode"),
                                "durationMs": payload.get("durationMs")})
