# Control plane API

Every capability in this system is an HTTP API. The dashboard, the `squashctl`
CLI and the AI driver are three independent clients of the routes below — none
of them has a private path into the server, and anything they can do, a program
you write can do.

Base URL of the reference deployment:

```
https://35-173-64-136.sslip.io
```

All request and response bodies are JSON with camelCase field names. Times are
UNIX epoch seconds (float) except on the investigations routes, which use
`YYYY-MM-DDTHH:MM:SSZ` strings.

---

## 1. Authentication

There are two kinds of caller, and they authenticate differently.

**Operators** (a human console, a script, the AI driver) send a shared key in a
header on every request:

```
X-API-Key: <key>
```

Keys are configured server-side as `SQUASH_OPERATOR_KEYS="name:key,name:key"`,
so each key carries an operator name that is written into the audit log. A
missing or unknown key returns `401` with `{"detail": "Valid X-API-Key required."}`.
There is no login, no session and no cookie: the dashboard holds its key in
`localStorage` and sends the same header as everything else.

**Endpoints** (the Windows agent) never use an API key. They authenticate once
with a single-use enrolment token to register a public key, and afterwards by
signing a server-issued challenge on each WebSocket connection. See
[§6](#6-agent-transport-websocket).

Unauthenticated on purpose: `GET /health`, `GET /`, and the four installer
artefacts. They contain no secrets and an endpoint has no credential until it
enrols; integrity of the binary comes from the published SHA-256, which is why
the deployment must be HTTPS.

### Status codes

| Code | Meaning in this API |
|------|---------------------|
| `200` | Done. |
| `201` | Created — a token was minted, or a device enrolled. |
| `202` | Accepted — the work is real but not finished. Dispatch and investigations return this; poll for the result. |
| `400` | The request is malformed or self-contradictory (e.g. a rebind token with no `deviceId`). |
| `401` | No valid `X-API-Key`. |
| `403` | Authenticated, but refused — the device is revoked, or enrolment was rejected. |
| `404` | No such device, job or investigation. |
| `409` | The request was valid but the world is not in the state it assumes — device unreachable, proposal changed, decision already made. |
| `422` | Body failed schema validation (FastAPI's default shape). |

`409` is the one worth reading carefully: it never means "try harder", it means
"re-read the current state and decide again".

---

## 2. Service and artefacts

### `GET /health`
No auth. `{"status": "ok"}`. Nothing else; a load balancer can use it.

### `GET /`
No auth. The operator dashboard (a single static HTML page).

### `GET /download/agent.exe`
### `GET /download/agent.sha256`
### `GET /install.ps1`
### `GET /uninstall.ps1`
No auth. The published agent binary, its hash, and the install/uninstall
scripts. `404` if the control plane has no build published.

---

## 3. Enrolment

### `POST /api/enrollment-tokens` → `201`
Mints a single-use enrolment token. Operator auth.

```jsonc
// body is optional; this is the default
{ "allowRebind": false, "deviceId": null }
```

| Field | Type | Meaning |
|-------|------|---------|
| `allowRebind` | bool | Permits replacing an **already enrolled** device's public key. Credential recovery only. |
| `deviceId` | string | Pins the token to one device. Required when `allowRebind` is true. |

```json
{
  "token": "…",
  "expiresAt": 1758230400.0,
  "ttlSeconds": 3600,
  "allowRebind": false,
  "boundDeviceId": null
}
```

The token is returned **once** and stored only as a SHA-256 hash, so a database
leak yields nothing usable. TTL is one hour.

`400` — `allowRebind` without a `deviceId`. A recovery token that names no
device is a token that can be redirected at any machine.

```bash
curl -sX POST https://HOST/api/enrollment-tokens -H "X-API-Key: $KEY"
```

### `POST /api/enroll` → `201`
Called by the agent, not by an operator. **No API key** — the token is the
credential, and it is burned on use.

```json
{
  "token": "…",
  "deviceId": "sha256 of MachineGuid, 32 hex chars",
  "publicKey": "base64 SPKI, P-256",
  "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022",
  "agentVersion": "0.4.0"
}
```

```json
{ "deviceId": "…", "heartbeatIntervalSeconds": 10 }
```
A rebind additionally returns `"rebound": true`.

Enrolment grants no standing access: it registers a key, nothing more.

| Situation | Response |
|-----------|----------|
| Token unknown, expired, already used, or bound to another device | `403 Enrollment refused: …` |
| Device is revoked | `403` — an operator must restore it first |
| Device already enrolled, plain token | `409` — replacing a key needs a recovery token issued for that device |

That last row is the important one. A matching device id proves nothing: the id
is derived from hardware an attacker can simply assert. Replacing an enrolled
key is therefore an operator decision, not something a device can do for itself.

`hostname`, `osVersion` and `agentVersion` are endpoint-supplied and therefore
untrusted: they are stripped of control characters and length-bounded before
being stored.

---

## 4. Devices

### `GET /api/devices`
Operator auth. Every enrolled device, including revoked ones.

```json
[{
  "deviceId": "a1b2…",
  "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022",
  "agentVersion": "0.4.0",
  "online": true,
  "secondsSinceLastSeen": 3.2,
  "enrolledAt": 1758140000.0,
  "lastSeenAt": 1758230391.4,
  "revoked": false,
  "lastBootAt": 1758100000.0,
  "uptimeSeconds": 130391,
  "uptimeIsLastKnown": false,
  "uptimeObservedAt": 1758230391.4
}]
```

`online` is heartbeat-derived, not socket-derived: it means a frame arrived
within the last 30 seconds. An open TCP connection does not prove a machine is
alive, so it is not what the field reports.

`uptimeIsLastKnown` is `true` when the device is offline. Uptime is not
extrapolated forward for a machine we cannot see, because it may be powered
off; the last observation is reported as-is and labelled.

### `GET /api/devices/{deviceId}/events?limit=50`
Operator auth. `limit` 1–500. Lifecycle events for one device — reboots,
connects, disconnects.

```json
[{ "event": "reboot", "at": 1758100000.0, "detail": "{\"previousUptimeSeconds\":54321}" }]
```
`404` if the device is not enrolled.

### `POST /api/devices/{deviceId}/revoke`
Operator auth. Takes effect immediately, not at the next reconnect: any queued
or in-flight job for the device is failed as `Unreachable`, pending work is
drained, and the socket is closed.

```json
{ "deviceId": "…", "revoked": true, "cancelledJobs": 1 }
```

### `POST /api/devices/{deviceId}/unrevoke`
Operator auth. Restores a revoked device. Deliberately a separate, explicit act
— never a side effect of the device re-enrolling.

```json
{ "deviceId": "…", "revoked": false }
```

---

## 5. Jobs

### `POST /api/devices/{deviceId}/jobs` → `202`
Operator auth. Dispatches a PowerShell script to an endpoint.

```json
{
  "script": "Get-Service Spooler | Select-Object Name,Status | ConvertTo-Json",
  "timeoutSeconds": 30,
  "maxOutputBytes": 1048576,
  "idempotencyKey": "optional-caller-supplied-string"
}
```

| Field | Default | Range |
|-------|---------|-------|
| `script` | required | at least 1 character |
| `timeoutSeconds` | 30 | 1–600 |
| `maxOutputBytes` | 1048576 | ≥ 1024 |
| `idempotencyKey` | none | any string |

```json
{ "jobId": "…", "state": "Dispatched" }
```

`202` means the job has been handed to the device's socket, not that it has
run. Poll `GET /api/jobs/{jobId}` for the result.

**Idempotency.** If `idempotencyKey` has been seen before, the original job id
is returned and nothing new is dispatched:

```json
{ "jobId": "<the original>", "state": "Duplicate", "deduplicated": true }
```

This check happens before any other validation, so a retry of a request whose
response you never saw is always safe.

| Situation | Response |
|-----------|----------|
| Device not enrolled | `404` |
| Device revoked | `403` |
| Device not reachable (no heartbeat in 30s) | `409` |

A `409` here is honest rather than optimistic: the job is refused instead of
queued for a machine that may never come back. Jobs that were in flight when
the control plane restarted are moved to a terminal state at startup, because
they can never report back.

```bash
curl -sX POST https://HOST/api/devices/$DEVICE/jobs \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"script":"Get-Date -Format o","timeoutSeconds":15}'
```

### `GET /api/jobs/{jobId}?waitMs=0`
Operator auth. One job, in flight or from history.

`waitMs > 0` long-polls: the request blocks until the job reaches a terminal
state or that many milliseconds elapse, then returns whatever is current. It
never errors on timeout — you get the job in its present state, so a client can
simply call again. This is what makes a synchronous-feeling `squashctl run`
possible without polling in a tight loop.

```json
{
  "jobId": "…",
  "deviceId": "…",
  "script": "…",
  "state": "Completed",
  "exitCode": 0,
  "stdout": "…",
  "stderr": "",
  "durationMs": 412,
  "roundTripMs": 416,
  "stdoutTruncated": false,
  "stderrTruncated": false,
  "error": null,
  "createdAt": 1758230388.1
}
```

| State | Terminal | Meaning |
|-------|----------|---------|
| `Queued` | no | Created, not yet on the wire. |
| `Dispatched` | no | Sent to the device. |
| `Running` | no | The device acknowledged and started it. |
| `Completed` | yes | The script ran. **Check `exitCode` separately** — completing is not succeeding. |
| `TimedOut` | yes | Exceeded `timeoutSeconds`; the process tree was killed. |
| `Unreachable` | yes | The device went away, or was revoked, before reporting. |
| `Failed` | yes | The agent reported failure, or the result failed attestation. |

`durationMs` is measured on the endpoint. `roundTripMs` is measured by the
server from dispatch to result — it excludes how far away the operator is and
includes everything the system itself contributes.

`stdoutTruncated` / `stderrTruncated` mean output hit `maxOutputBytes` and was
cut. **Do not parse truncated output.** `"12345"` truncated to `"123"` parses
cleanly and is wrong; the AI driver treats a truncation flag as a failed
observation rather than a small one.

Results are attested. The agent signs

```
squash-rmm-result-v1|jobId|scriptSha256|exitCode|durationMs|sha256(stdout)|sha256(stderr)
```

with its enrolled key, and the server verifies it before storing anything. A
result that does not verify becomes `Failed` with `error` explaining why —
output that reached us over an authenticated socket but was not signed by the
device that ran it is not evidence. (`SQUASH_REQUIRE_ATTESTATION=0` exists for
bootstrapping an older fleet; it defaults to on.)

### `GET /api/jobs`
Operator auth. Two response shapes, chosen by the query string.

With only `?limit=` (1–1000, default 50) it returns a **bare array** of job
views, newest first.

With any of `page`, `state`, `deviceId` or `search` it returns a **page
object**:

```
GET /api/jobs?page=1&pageSize=30&state=Completed&deviceId=…&search=Spooler
```
```json
{ "items": [ … ], "total": 412, "page": 1, "pageSize": 30, "totalPages": 14 }
```

`pageSize` is 1–100 (default 30). `state` must be one of the states above.
`search` matches script text, up to 500 characters.

### `GET /api/audit?limit=100`
Operator auth. The append-only audit trail, newest first.

```json
[{ "at": 1758230388.0, "actor": "ai-driver", "action": "job.dispatch",
   "device_id": "…", "job_id": "…", "detail": "{\"scriptBytes\":64}" }]
```

Every state-changing operation writes here: token minting, enrolment success
and rejection, connects, dispatches, results, rejected results, revocations,
investigation creation and every approval decision. `actor` is the operator
name behind the API key, or `device` / `system` for things the server and
endpoints do on their own. Note the snake_case keys — this route returns rows
as stored.

---

## 6. Agent transport (WebSocket)

### `WS /agent/connect`

Device-initiated, which is what makes this work behind NAT with no inbound
firewall rule. One socket carries dispatch and results in both directions.

Handshake:

1. Server → `{"type":"challenge","nonce":"…"}`
2. Device → `{"type":"hello","deviceId":"…","signature":"<nonce signed with the enrolled key>","hostname":"…","osVersion":"…","agentVersion":"…","bootTimeUnixMs":…,"uptimeSeconds":…}`
3. Server → `{"type":"hello_ack","deviceId":"…","heartbeatIntervalSeconds":10}`

Close codes: `1002` (no hello), `4401` (not enrolled, or signature failed),
`4403` (revoked).

Steady state:

| Direction | Frame |
|-----------|-------|
| Device → | `{"type":"heartbeat"}` every 10s |
| Server → | `{"type":"job_dispatch","job":{"jobId","script","timeoutSeconds","maxOutputBytes","scriptSha256"}}` |
| Device → | `{"type":"job_accepted","jobId":"…"}` |
| Device → | `{"type":"job_result","result":{…,"attestation":"<signature>"}}` |

`scriptSha256` travels with the dispatch so the agent signs a hash of the
script it actually received, binding the result to the exact instructions.

A result for a job the device does not own is logged and dropped.

---

## 7. Investigations

The AI surface. An investigation takes a problem in a user's own words, gathers
evidence from read-only diagnostics, and — if it finds something with a known
remedy — proposes one repair from a fixed catalogue and stops, waiting for a
human. See [remediation-design.md](remediation-design.md) for why diagnosis and
remediation are separated, and [investigations-ui-contract.md](investigations-ui-contract.md)
for the UI's view of the same routes.

Nothing in these routes executes anything. They validate, read and write
durable state, and schedule background work.

### Lifecycle

```
queued → investigating → planning → awaiting_approval → applying → verifying → resolved
                              ↓              ↓                                    ↓
                          completed       rejected                           unresolved
                                                                     (any stage) failed
```

| Status | Meaning |
|--------|---------|
| `queued` | Accepted, not yet picked up. |
| `investigating` | Running diagnostics. |
| `planning` | Choosing whether any catalogue repair fits. |
| `awaiting_approval` | A proposal exists and a human must decide. **Nothing happens until you do.** |
| `applying` | Approved; the repair is being dispatched. |
| `verifying` | The repair ran; checking whether the problem is actually gone. |
| `resolved` | Verification passed. |
| `unresolved` | The repair ran but the condition it targets is still true. |
| `completed` | Diagnosis finished with no repair proposed. This is a normal, common outcome. |
| `rejected` | A human declined the proposal. |
| `failed` | The investigation could not be completed. |

The `status` query parameter also accepts three group names: `active`
(`queued`, `investigating`, `planning`, `applying`, `verifying`),
`awaiting_approval`, and `finished`.

### `POST /api/investigations` → `202`
Operator auth.

```json
{
  "deviceId": "…",
  "problem": "Nothing prints from this computer. Jobs vanish from the queue.",
  "requestId": "a unique string from the caller"
}
```

`problem` is 10–4000 characters — a user's description, not a diagnosis.
`requestId` (1–128 chars) makes creation idempotent.

```json
{ "investigationId": "inv-…" }
```

| Situation | Response |
|-----------|----------|
| Same `requestId`, same device and problem | `202` with the original id; nothing new starts |
| Same `requestId`, **different** device or problem | `409` |
| Device not enrolled | `404` |
| Device revoked | `403` |
| `problem` outside 10–4000 characters | `400` |

`202` means the work was scheduled. It survives a control-plane restart:
investigations left mid-flight are recovered and re-queued at startup.

### `GET /api/investigations?page=1&pageSize=30&search=&status=`
Operator auth. `pageSize` 1–100, `search` up to 500 characters.

```json
{
  "items": [{
    "investigationId": "inv-…", "deviceId": "…", "hostname": "EC2AMAZ-ABC123",
    "problem": "…", "status": "awaiting_approval", "createdAt": "2026-09-18T14:02:11Z"
  }],
  "page": 1, "totalPages": 3, "total": 74
}
```

### `GET /api/investigations/{investigationId}`
Operator auth. The whole investigation, including the evidence behind it.

```json
{
  "investigationId": "inv-…",
  "deviceId": "…",
  "hostname": "EC2AMAZ-ABC123",
  "problem": "Nothing prints from this computer.",
  "status": "awaiting_approval",
  "createdAt": "2026-09-18T14:02:11Z",
  "events": [{ "at": "2026-09-18T14:02:12Z", "message": "service_status check completed in 214ms." }],
  "finding": "The Print Spooler service is stopped.",
  "confidence": "high",
  "evidence": [{
    "diagnostic": "service_status",
    "checkSucceeded": true,
    "output": { "name": "Spooler", "status": "Stopped", "startType": "Automatic" },
    "note": null
  }],
  "proposal": {
    "proposalId": "…",
    "proposalHash": "…",
    "decision": "proposed",
    "reasoning": "service_status shows Spooler Stopped with StartType Automatic.",
    "expectedEffect": "The spooler is running and queued jobs print.",
    "risk": "The service is briefly unavailable, and anything depending on it may error while it restarts.",
    "verifiedBy": "the service reports Running",
    "script": "Start-Service -Name 'Spooler' …",
    "scriptSha256": "…",
    "refusalReason": null,
    "expiresAt": "2026-09-18T14:17:12Z"
  },
  "outcome": null,
  "error": null
}
```

`proposal` is `null` while `status` is `queued`. `decision` is `proposed`,
`no_action` (nothing in the catalogue fits — normal) or `refused` (the planner
chose something that failed validation; `refusalReason` says what).

`evidence` is the raw diagnostic output, not a summary of it. This matters: an
earlier version passed summaries to the planner, which then reasoned from
`"service_status: ok"` instead of from the data, and got it wrong. If you build
a UI on this, show the evidence — a finding is a claim, and the evidence is
what makes it checkable.

`checkSucceeded: false` means the diagnostic itself did not complete. That is
not the same as the condition being absent, and must never be rendered as
"nothing found".

Once applied, `outcome` carries:

```json
{ "applied": true, "resolved": true, "detail": "the service reports Running",
  "jobId": "…", "exitCode": 0, "conditionBefore": true, "conditionAfter": true }
```

`resolved: null` means the repair ran but its effect could not be verified.
Exiting zero means the command ran; whether the problem is gone is a separate
question, answered only by re-running the verification check.

### `POST /api/investigations/{investigationId}/decision`
Operator auth. The approval gate. This is the only route that can cause a
repair to execute.

```json
{
  "proposalId": "…",
  "proposalHash": "…",
  "deviceId": "…",
  "decision": "approve"
}
```

`decision` is `approve` or `reject`. All four fields are required and all four
are checked: the proposal id, its hash, the device, **and** a recomputation of
the hash from the stored proposal. You approve a specific action on a specific
machine, and if any part of it changed since you looked, the approval does not
apply to it.

Returns the full investigation detail (same shape as `GET`).

| Situation | Response |
|-----------|----------|
| No actionable proposal | `409` |
| Any binding field mismatches, or the recomputed hash differs | `409` "The proposal has changed since you last saw it." |
| Proposal expired (15 minutes) | `409` |
| Same decision already recorded | `200`, idempotent |
| A *different* decision already recorded | `409` |

Approval is recorded with a compare-and-set, so two concurrent approvals
produce one execution. Re-sending the same decision is safe and also heals the
window between recording an approval and scheduling the work.

What the approval authorises is deliberately narrow. At execution the script is
**rebuilt from the repair catalogue** using the approved repair name and
arguments, and the approved hash is checked against that rebuild — the stored
script text is never trusted. Comparing one stored field against another proves
only that nobody changed both. The precondition is then re-evaluated on the
live machine, because the world may have moved on while a human was deciding,
and a repair whose condition no longer holds is refused rather than applied.

---

## 8. Building a client

A minimal integration is three calls:

```bash
HOST=https://35-173-64-136.sslip.io
KEY=…

# 1. find a device
DEVICE=$(curl -s $HOST/api/devices -H "X-API-Key: $KEY" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["deviceId"])')

# 2. dispatch
JOB=$(curl -sX POST $HOST/api/devices/$DEVICE/jobs \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"script":"Get-Service Spooler | ConvertTo-Json","timeoutSeconds":20}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["jobId"])')

# 3. wait for it
curl -s "$HOST/api/jobs/$JOB?waitMs=20000" -H "X-API-Key: $KEY"
```

Four habits worth keeping:

- **Send an `idempotencyKey` on every dispatch.** Retrying a request whose
  response you lost is otherwise a second execution.
- **Check `exitCode`, not just `state`.** `Completed` means the script ran.
- **Refuse to parse truncated output.** Treat `stdoutTruncated` as a failed
  observation.
- **Treat `409` as "re-read, then decide again".** It is never a retry signal.

FastAPI serves OpenAPI at `/openapi.json` and interactive docs at `/docs`, both
generated from the same route definitions this file describes.
