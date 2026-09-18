# Control plane API

Every capability in this system is an HTTP API. The dashboard, the `squashctl`
CLI and the AI driver are three independent clients of the routes below — none
has a private path into the server.

```bash
export HOST=https://35-173-64-136.sslip.io
export KEY=<your operator key>
```

Bodies are JSON, camelCase. Times are UNIX epoch seconds, except investigations,
which use `2026-09-18T14:02:11Z` strings.

**Contents** — [Auth](#auth) · [Status codes](#status-codes) · [Health & downloads](#health--downloads) ·
[Enrolment](#enrolment) · [Devices](#devices) · [Restart](#restart) · [Jobs](#jobs) ·
[Audit](#audit) · [Agent WebSocket](#agent-websocket) · [Investigations](#investigations) ·
[Four rules](#four-rules-for-any-client)

---

## Auth

Operators send a header on every request:

```
X-API-Key: <key>
```

Keys are configured server-side as `SQUASH_OPERATOR_KEYS="name:key,name:key"`, so
each key carries an operator name that lands in the audit log. Missing or wrong →
`401`.

Agents never use an API key. They enrol once with a single-use token, then sign a
server challenge on each connection.

Open routes (no key): `/health`, `/`, `/download/*`, `/install.ps1`, `/uninstall.ps1`.

## Status codes

| Code | Meaning here |
|------|--------------|
| `200` | Done. |
| `201` | Token minted, or device enrolled. |
| `202` | Accepted — real work, not yet finished. Poll for it. |
| `400` | Malformed or self-contradictory request. |
| `401` | No valid `X-API-Key`. |
| `403` | Refused — device revoked, or enrolment rejected. |
| `404` | No such device, job or investigation. |
| `409` | Valid request, wrong world state. **Re-read and decide again — never retry blindly.** |
| `422` | Body failed schema validation. |

---

## Health & downloads

```bash
curl -s $HOST/health                       # {"status":"ok"}
curl -sO $HOST/download/agent.exe          # the agent binary
curl -s  $HOST/download/agent.sha256       # verify the binary against this
curl -s  $HOST/install.ps1
curl -s  $HOST/uninstall.ps1
```

No auth: they hold no secrets, and an endpoint has no credential until it enrols.
Integrity comes from the published SHA-256, which is why this must run over TLS.
`404` if no build is published.

---

## Enrolment

### `POST /api/enrollment-tokens` → `201`

Mint a single-use token. The token is returned **once** and stored only as a hash.

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `allowRebind` | bool | `false` | Permits replacing an **already enrolled** device's key. Recovery only. |
| `deviceId` | string | `null` | Pins the token to one device. **Required** when `allowRebind` is true. |

```bash
# A new machine
curl -sX POST $HOST/api/enrollment-tokens -H "X-API-Key: $KEY"

# Recovery for a machine that is already enrolled
curl -sX POST $HOST/api/enrollment-tokens \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"allowRebind": true, "deviceId": "a1b2c3…"}'
```

```json
{ "token": "…", "expiresAt": 1758230400.0, "ttlSeconds": 3600,
  "allowRebind": false, "boundDeviceId": null }
```

`400` — `allowRebind` with no `deviceId`. A recovery token naming no device can be
redirected at any machine.

Install on the endpoint with the token:

```powershell
iwr https://HOST/install.ps1 -OutFile i.ps1
.\i.ps1 -Server https://HOST -Token <token>
```

### `POST /api/enroll` → `201`

Called by the agent, **not** by an operator. No API key — the token is the
credential and is burned on use.

| Field | Type |
|-------|------|
| `token` | string, from the route above |
| `deviceId` | string, SHA-256 of MachineGuid, 32 hex chars |
| `publicKey` | string, base64 SPKI, P-256 |
| `hostname` | string |
| `osVersion` | string |
| `agentVersion` | string |

```bash
curl -sX POST $HOST/api/enroll -H 'Content-Type: application/json' -d '{
  "token": "…",
  "deviceId": "a1b2c3…",
  "publicKey": "MFkwEwYHKoZIzj0CAQ…",
  "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022",
  "agentVersion": "0.4.0"
}'
```

```json
{ "deviceId": "a1b2c3…", "heartbeatIntervalSeconds": 10 }
```

| Situation | Response |
|-----------|----------|
| Token unknown, expired, used, or bound elsewhere | `403` |
| Device is revoked | `403` — an operator must restore it first |
| Device already enrolled, plain token | `409` — needs a recovery token for that device |

That last row matters: a matching device id proves nothing, since the id is
derived from hardware an attacker can simply assert. `hostname`, `osVersion` and
`agentVersion` are endpoint-supplied and therefore stripped and length-bounded
before storage.

---

## Devices

### `GET /api/devices`

```bash
curl -s $HOST/api/devices -H "X-API-Key: $KEY"
```

```json
[{
  "deviceId": "a1b2c3…", "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022", "agentVersion": "0.4.0",
  "online": true, "secondsSinceLastSeen": 3.2,
  "enrolledAt": 1758140000.0, "lastSeenAt": 1758230391.4, "revoked": false,
  "lastBootAt": 1758100000.0, "uptimeSeconds": 130391,
  "uptimeIsLastKnown": false, "uptimeObservedAt": 1758230391.4
}]
```

`online` is heartbeat-derived, not socket-derived: a frame arrived within 30
seconds. An open TCP connection does not prove a machine is alive.

`uptimeIsLastKnown: true` means the device is offline and the figure is the last
observation, not extrapolated — a machine we cannot see may be powered off.

### `GET /api/devices/{deviceId}/events?limit=50`

Lifecycle events for one device: reboots, connects, disconnects, restart requests.
`limit` 1–500. `404` if not enrolled.

```bash
curl -s "$HOST/api/devices/$DEVICE/events?limit=20" -H "X-API-Key: $KEY"
```

```json
[{ "event": "reboot", "at": 1758100000.0, "detail": "{\"previousUptimeSeconds\":54321}" }]
```

### `POST /api/devices/{deviceId}/revoke`

No body. Takes effect immediately, not at the next reconnect: queued and in-flight
jobs are failed as `Unreachable`, pending work is drained, the socket is closed.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/revoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": true, "cancelledJobs": 1 }
```

### `POST /api/devices/{deviceId}/unrevoke`

No body. Restoring is deliberately a separate operator act — never a side effect
of the device re-enrolling.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/unrevoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": false }
```

---

## Restart

### `POST /api/devices/{deviceId}/restart` → `202`

Restarting has its own route rather than being a script the caller is expected to
know. It is the one destructive action in this API, so it should read as itself in
the audit log (`device.restart`), and a caller should not be able to get the
command wrong or smuggle anything in beside it.

All fields optional:

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `delaySeconds` | int | `15` | 5–3600 |
| `reason` | string | `"Restart requested from Squash RMM"` | 1–200 chars, `A-Z a-z 0-9` and `. , : ! ? ' - _ ( ) /` |
| `idempotencyKey` | string | none | any string |

```bash
# Default: 15 seconds from now
curl -sX POST $HOST/api/devices/$DEVICE/restart -H "X-API-Key: $KEY"

# With a message for whoever is at the machine, and a safe retry
curl -sX POST $HOST/api/devices/$DEVICE/restart \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
        "delaySeconds": 120,
        "reason": "Monthly patch window (ticket 4821)",
        "idempotencyKey": "restart-4821"
      }'
```

```json
{ "jobId": "…", "state": "Dispatched", "restartAt": 1758230520.0, "delaySeconds": 120 }
```

It becomes an ordinary job — same dispatch path, same attested result, same
history — so poll `GET /api/jobs/{jobId}` as usual. The endpoint reports back
before it goes down; `stdout` will read `restart scheduled in 120s`.

**Why there is a minimum delay.** The agent has to report the result over the same
machine that is about to shut down. A restart that begins immediately produces a
job stuck at `Unreachable` for an action that actually succeeded, so the floor is
5 seconds.

**Why `reason` is so restricted.** It is substituted into a command line.
Anything that could close the quote or start a new statement is refused rather
than escaped — a whitelist is a thing you cannot get subtly wrong.

| Situation | Response |
|-----------|----------|
| `reason` contains anything outside the class, or is empty/over 200 chars | `400` |
| `delaySeconds` outside 5–3600 | `422` |
| Device not enrolled / revoked / unreachable | `404` / `403` / `409` |
| `idempotencyKey` already used | `202`, original job id, `"deduplicated": true` |

The dashboard also requires the operator to type the hostname before it calls
this. That is a console concern, not an API one: the API assumes the caller
already decided.

---

## Jobs

### `POST /api/devices/{deviceId}/jobs` → `202`

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `script` | string | required | ≥ 1 char |
| `timeoutSeconds` | int | `30` | 1–600 |
| `maxOutputBytes` | int | `1048576` | ≥ 1024 |
| `idempotencyKey` | string | none | any string |

```bash
curl -sX POST $HOST/api/devices/$DEVICE/jobs \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
        "script": "Get-Service Spooler | Select-Object Name,Status | ConvertTo-Json",
        "timeoutSeconds": 20,
        "maxOutputBytes": 1048576,
        "idempotencyKey": "spooler-check-2026-09-18"
      }'
```

```json
{ "jobId": "…", "state": "Dispatched" }
```

`202` means handed to the device's socket, not that it ran.

**Idempotency.** A key seen before returns the original job and dispatches nothing:

```json
{ "jobId": "<the original>", "state": "Duplicate", "deduplicated": true }
```

This check runs before every other check, so retrying a request whose response you
lost is always safe.

| Situation | Response |
|-----------|----------|
| Device not enrolled | `404` |
| Device revoked | `403` |
| No heartbeat in 30s | `409` |

`409` here is honest rather than optimistic — the job is refused, not queued for a
machine that may never return. Jobs in flight when the control plane restarts are
moved to a terminal state at startup, since they can never report back.

### `GET /api/jobs/{jobId}?waitMs=0`

`waitMs > 0` long-polls: blocks until the job is terminal or that many
milliseconds pass, then returns whatever is current. It never errors on timeout,
so a client can just call again.

```bash
curl -s "$HOST/api/jobs/$JOB?waitMs=20000" -H "X-API-Key: $KEY"
```

```json
{
  "jobId": "…", "deviceId": "…", "script": "…",
  "state": "Completed", "exitCode": 0,
  "stdout": "{\"Name\":\"Spooler\",\"Status\":\"Stopped\"}", "stderr": "",
  "durationMs": 412, "roundTripMs": 416,
  "stdoutTruncated": false, "stderrTruncated": false,
  "error": null, "createdAt": 1758230388.1
}
```

| State | Terminal | Meaning |
|-------|----------|---------|
| `Queued` | no | Created, not on the wire yet. |
| `Dispatched` | no | Sent to the device. |
| `Running` | no | Device acknowledged and started it. |
| `Completed` | yes | The script ran. **Check `exitCode` separately** — completing is not succeeding. |
| `TimedOut` | yes | Exceeded `timeoutSeconds`; the process tree was killed. |
| `Unreachable` | yes | Device went away, or was revoked, before reporting. |
| `Failed` | yes | Agent reported failure, or the result failed attestation. |

`durationMs` is measured on the endpoint. `roundTripMs` is measured by the server
from dispatch to result — it excludes how far away the operator is and includes
everything the system contributes.

`stdoutTruncated` / `stderrTruncated` mean output hit `maxOutputBytes`.
**Never parse truncated output**: `"12345"` cut to `"123"` parses cleanly and is
wrong.

Results are attested. The agent signs

```
squash-rmm-result-v1|jobId|scriptSha256|exitCode|durationMs|sha256(stdout)|sha256(stderr)
```

with its enrolled key; the server verifies before storing. A result that fails
becomes `Failed` with `error` saying why — output that arrived over an
authenticated socket but was not signed by the device that ran it is not evidence.

### `GET /api/jobs`

Two shapes, chosen by the query string.

```bash
# Bare array, newest first. limit 1-1000, default 50.
curl -s "$HOST/api/jobs?limit=20" -H "X-API-Key: $KEY"

# Page object, if any of page / state / deviceId / search is present.
curl -s "$HOST/api/jobs?page=1&pageSize=30&state=Completed&search=Spooler" \
  -H "X-API-Key: $KEY"
```

```json
{ "items": [ … ], "total": 412, "page": 1, "pageSize": 30, "totalPages": 14 }
```

`pageSize` 1–100 (default 30). `state` is one of the states above. `search`
matches script text, ≤ 500 chars.

---

## Audit

### `GET /api/audit?limit=100`

Append-only, newest first. Note: snake_case keys — these are rows as stored.

```bash
curl -s "$HOST/api/audit?limit=50" -H "X-API-Key: $KEY"
```

```json
[{ "at": 1758230388.0, "actor": "ai-driver", "action": "job.dispatch",
   "device_id": "a1b2c3…", "job_id": "…", "detail": "{\"scriptBytes\":64}" }]
```

Every state-changing operation writes here: token minting, enrolment success and
rejection, connects, dispatches, results, rejected results, restarts, revocations,
investigation creation, and every approval decision. `actor` is the operator name
behind the key, or `device` / `system`.

---

## Agent WebSocket

### `WS /agent/connect`

Device-initiated, which is what makes this work behind NAT with no inbound
firewall rule. One socket carries dispatch and results both ways.

```
1. server → {"type":"challenge","nonce":"…"}
2. device → {"type":"hello","deviceId":"…","signature":"<nonce signed>",
             "hostname":"…","osVersion":"…","agentVersion":"…",
             "bootTimeUnixMs":…,"uptimeSeconds":…}
3. server → {"type":"hello_ack","deviceId":"…","heartbeatIntervalSeconds":10}
```

Close codes: `1002` no hello · `4401` not enrolled or bad signature · `4403` revoked.

| Direction | Frame |
|-----------|-------|
| device → | `{"type":"heartbeat"}` every 10s |
| server → | `{"type":"job_dispatch","job":{"jobId","script","timeoutSeconds","maxOutputBytes","scriptSha256"}}` |
| device → | `{"type":"job_accepted","jobId":"…"}` |
| device → | `{"type":"job_result","result":{…,"attestation":"<signature>"}}` |

`scriptSha256` travels with the dispatch so the agent signs a hash of the script
it actually received. A result for a job the device does not own is dropped.

---

## Investigations

The AI surface. Takes a problem in a user's own words, gathers evidence from
read-only diagnostics, and — if it finds something with a known remedy — proposes
**one** repair from a fixed catalogue and stops, waiting for a human. See
[remediation-design.md](remediation-design.md).

None of these routes execute anything. They validate, read and write durable
state, and schedule background work.

```
queued → investigating → planning → awaiting_approval → applying → verifying → resolved
                             ↓              ↓                                     ↓
                         completed       rejected                             unresolved
                                                                    (any stage) failed
```

| Status | Meaning |
|--------|---------|
| `queued` | Accepted, not picked up yet. |
| `investigating` | Running diagnostics. |
| `planning` | Deciding whether any catalogue repair fits. |
| `awaiting_approval` | A proposal exists. **Nothing happens until a human decides.** |
| `applying` | Approved; dispatching the repair. |
| `verifying` | Repair ran; checking whether the problem is actually gone. |
| `resolved` | Verification passed. |
| `unresolved` | Repair ran, condition still true. |
| `completed` | Diagnosis finished, no repair proposed. Normal and common. |
| `rejected` | A human declined. |
| `failed` | Could not be completed. |

The `status` filter also accepts `active`, `awaiting_approval` and `finished`.

### `POST /api/investigations` → `202`

| Field | Type | Notes |
|-------|------|-------|
| `deviceId` | string | must be enrolled and not revoked |
| `problem` | string | 10–4000 chars, the **user's** description, not a diagnosis |
| `requestId` | string | 1–128 chars, makes creation idempotent |

```bash
curl -sX POST $HOST/api/investigations \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
        "deviceId": "a1b2c3…",
        "problem": "Nothing prints from this computer. Jobs vanish from the queue.",
        "requestId": "ticket-4821"
      }'
```

```json
{ "investigationId": "inv-…" }
```

| Situation | Response |
|-----------|----------|
| Same `requestId`, same device and problem | `202`, original id, nothing new starts |
| Same `requestId`, **different** device or problem | `409` |
| Device not enrolled / revoked | `404` / `403` |
| `problem` outside 10–4000 chars | `400` |

Scheduled work survives a restart: investigations left mid-flight are recovered
and re-queued at startup.

### `GET /api/investigations?page=1&pageSize=30&search=&status=`

```bash
curl -s "$HOST/api/investigations?status=awaiting_approval" -H "X-API-Key: $KEY"
```

```json
{
  "items": [{ "investigationId": "inv-…", "deviceId": "a1b2c3…",
              "hostname": "EC2AMAZ-ABC123", "problem": "…",
              "status": "awaiting_approval", "createdAt": "2026-09-18T14:02:11Z" }],
  "page": 1, "totalPages": 3, "total": 74
}
```

### `GET /api/investigations/{investigationId}`

```bash
curl -s $HOST/api/investigations/inv-abc123 -H "X-API-Key: $KEY"
```

```json
{
  "investigationId": "inv-…", "deviceId": "a1b2c3…", "hostname": "EC2AMAZ-ABC123",
  "problem": "Nothing prints from this computer.",
  "status": "awaiting_approval", "createdAt": "2026-09-18T14:02:11Z",
  "events": [{ "at": "2026-09-18T14:02:12Z",
               "message": "service_status check completed in 214ms." }],
  "finding": "The Print Spooler service is stopped.",
  "confidence": "high",
  "evidence": [{
    "diagnostic": "service_status", "checkSucceeded": true,
    "output": { "name": "Spooler", "status": "Stopped", "startType": "Automatic" },
    "note": null
  }],
  "proposal": {
    "proposalId": "…", "proposalHash": "…", "decision": "proposed",
    "reasoning": "service_status shows Spooler Stopped with StartType Automatic.",
    "expectedEffect": "The spooler is running and queued jobs print.",
    "risk": "The service is briefly unavailable while it restarts.",
    "verifiedBy": "the service reports Running",
    "script": "Start-Service -Name 'Spooler' …", "scriptSha256": "…",
    "refusalReason": null, "expiresAt": "2026-09-18T14:17:12Z"
  },
  "outcome": null, "error": null
}
```

`proposal` is `null` while `status` is `queued`. `decision` is `proposed`,
`no_action` (nothing in the catalogue fits — normal), or `refused` (the planner
chose something that failed validation; `refusalReason` says what).

`evidence` is raw diagnostic output, not a summary. An earlier version passed
summaries to the planner, which reasoned from `"service_status: ok"` instead of
from the data and got it wrong. If you build a UI, show the evidence — a finding
is a claim, the evidence is what makes it checkable.

`checkSucceeded: false` means the diagnostic did not complete. That is **not** the
same as the condition being absent, and must never render as "nothing found".

Once applied, `outcome`:

```json
{ "applied": true, "resolved": true, "detail": "the service reports Running",
  "jobId": "…", "exitCode": 0, "conditionBefore": true, "conditionAfter": true }
```

`resolved: null` means it ran but the effect could not be verified. Exiting zero
means the command ran; whether the problem is gone is a separate question,
answered only by re-running the verification check.

### `POST /api/investigations/{investigationId}/decision`

The approval gate — the only route that can cause a repair to execute. All four
fields are required.

| Field | Type | Notes |
|-------|------|-------|
| `proposalId` | string | from `GET`, must be the current proposal |
| `proposalHash` | string | from `GET`; also recomputed server-side |
| `deviceId` | string | must match the investigation's device |
| `decision` | string | `"approve"` or `"reject"` |

```bash
curl -sX POST $HOST/api/investigations/inv-abc123/decision \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
        "proposalId": "…",
        "proposalHash": "…",
        "deviceId": "a1b2c3…",
        "decision": "approve"
      }'
```

Returns the full investigation detail, same shape as `GET`.

| Situation | Response |
|-----------|----------|
| No actionable proposal | `409` |
| Any binding field mismatches, or the recomputed hash differs | `409` "The proposal has changed since you last saw it." |
| Proposal expired (15 minutes) | `409` |
| Same decision already recorded | `200`, idempotent |
| A *different* decision already recorded | `409` |

You approve a specific action on a specific machine; if any part changed since you
looked, the approval does not apply to it. Recording uses compare-and-set, so two
concurrent approvals produce one execution.

What the approval authorises is deliberately narrow. At execution the script is
**rebuilt from the repair catalogue** from the approved name and arguments, and
the approved hash is checked against that rebuild — the stored script text is
never trusted, because comparing one stored field against another proves only that
nobody changed both. The precondition is then re-evaluated on the live machine,
since the world may have moved on while a human was deciding.

---

## Four rules for any client

- **Send an `idempotencyKey` on every dispatch and restart.** Retrying a request
  whose response you lost is otherwise a second execution.
- **Check `exitCode`, not just `state`.** `Completed` only means the script ran.
- **Refuse to parse truncated output.** Treat `stdoutTruncated` as a failed
  observation, not a small one.
- **Treat `409` as "re-read, then decide again".** It is never a retry signal.

FastAPI serves OpenAPI at `/openapi.json` and interactive docs at `/docs`, both
generated from the same route definitions described here.
