# Control Plane API

This API controls a fleet of Windows devices, runs scripts on them, and uses AI to
diagnose and propose fixes. Everything is standard HTTP with JSON.

## The Basics

- **Base URL:** `https://35-173-64-136.sslip.io`
- **Format:** JSON, camelCase. Times are Unix seconds, except investigations, which
  use strings like `2026-09-18T14:02:11Z`.
- **Authentication:** If you are a human or a script, put your API key in a header:
  `X-API-Key: <your-key>`. Devices don't use API keys — they enrol with a one-time
  token, then sign a server challenge on every connection.

The examples below assume:

```bash
export HOST=https://35-173-64-136.sslip.io
export KEY=<your-key>
export DEVICE=<a deviceId from GET /api/devices>
```

**Status codes to know:**

- `200` / `201` / `202` — success. `202` means *accepted*: the work is real but not
  finished yet, so check back.
- `400` / `422` — your request was malformed or failed validation.
- `401` — no valid API key. `403` — the device is revoked. `404` — no such thing.
- `409` — **conflict.** The world isn't in the state your request assumed: the
  device went offline, a proposal changed, a decision was already made.
  **Don't just retry.** Fetch the latest state and decide again.

**Everything in this system is one of three clients of these routes** — the
dashboard, the `squashctl` CLI, and the AI driver. None of them has a private path
into the server, so anything they do, you can do.

---

## 1. Getting the Agent

No authentication. Anyone can hit these — they hold no secrets, and a device has no
credential until it enrols. Integrity comes from the published hash, which is why
this must run over HTTPS.

```bash
curl -s  $HOST/health              # {"status":"ok"}
curl -sO $HOST/download/agent.exe  # the agent binary
curl -s  $HOST/download/agent.sha256
curl -s  $HOST/install.ps1
curl -s  $HOST/uninstall.ps1
```

`GET /` loads the dashboard. `404` on the downloads means no build is published.

---

## 2. Adding Devices (Enrolment)

You generate a one-time ticket; the computer redeems it.

### Step 1 — Generate a token

`POST /api/enrollment-tokens` → `201`

Everything is optional. The defaults produce a token for a **brand-new** machine.

| Field | Type | Default | What it does |
|-------|------|---------|--------------|
| `allowRebind` | bool | `false` | Lets the token replace the key of a device that is **already enrolled**. This is credential recovery — a reinstall, a wiped disk. |
| `deviceId` | string | `null` | Pins the token to one machine. **Required** if `allowRebind` is true. |

```bash
# A machine the control plane has never seen
curl -sX POST $HOST/api/enrollment-tokens -H "X-API-Key: $KEY"

# Recovery for a machine that is already enrolled
curl -sX POST $HOST/api/enrollment-tokens \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"allowRebind": true, "deviceId": "a1b2c3…"}'
```

```json
{
  "token": "enr_…",
  "expiresAt": 1758230400.0,
  "ttlSeconds": 3600,
  "allowRebind": false,
  "boundDeviceId": null
}
```

Valid for one hour, single use. The token is shown **once** and stored only as a
hash, so a database leak yields nothing usable.

A recovery token with no `deviceId` returns `400` — a token that names no machine
can be pointed at any machine.

Then, on the endpoint, in an Administrator PowerShell:

```powershell
iwr https://HOST/install.ps1 -OutFile i.ps1
.\i.ps1 -Server https://HOST -Token enr_…
```

### Step 2 — The device enrols

`POST /api/enroll` → `201`

**The agent does this automatically.** You will not call it by hand; it's here so
you know what the agent is doing. No API key — the token *is* the credential, and
it is burned on use.

| Field | What it is |
|-------|------------|
| `token` | from step 1 |
| `deviceId` | SHA-256 of the machine's MachineGuid, 32 hex chars |
| `publicKey` | base64 SPKI, P-256. The private half never leaves the machine. |
| `hostname`, `osVersion`, `agentVersion` | descriptive; treated as untrusted and sanitised before storage |

```bash
curl -sX POST $HOST/api/enroll -H 'Content-Type: application/json' -d '{
  "token": "enr_…",
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

| If | You get |
|----|---------|
| The token is unknown, expired, used, or bound to another device | `403` |
| The device is revoked | `403` — an operator must restore it first |
| The device is already enrolled and this is a plain token | `409` — replacing a key needs a recovery token issued for *that* device |

That last rule is the point of the whole design. A matching `deviceId` proves
nothing, because the id comes from hardware an attacker can simply claim to have.
So replacing an enrolled key is an operator's decision, never a device's.

---

## 3. Managing Devices

### List all devices

`GET /api/devices`

```bash
curl -s $HOST/api/devices -H "X-API-Key: $KEY"
```

```json
[{
  "deviceId": "a1b2c3…",
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

`online` means the device sent a heartbeat in the last 30 seconds — not that a
socket is open. An open TCP connection doesn't prove a machine is alive.

`uptimeIsLastKnown: true` means the device is offline and this is the last figure
we saw, not a running total. A machine we can't see may be powered off, so we don't
keep counting for it.

### View device history

`GET /api/devices/{deviceId}/events?limit=50`

Reboots, connections, disconnects, restart requests. `limit` is 1–500.

```bash
curl -s "$HOST/api/devices/$DEVICE/events?limit=20" -H "X-API-Key: $KEY"
```

```json
[
  { "event": "reboot", "at": 1758100000.0, "detail": "{\"previousUptimeSeconds\":54321}" },
  { "event": "restart_requested", "at": 1758099980.0, "detail": "{\"operator\":\"ops\",\"delaySeconds\":15}" }
]
```

### Kick a device

`POST /api/devices/{deviceId}/revoke` — no body.

Instantly kills the connection and cancels pending work. It takes effect now, not
at the next reconnect: in-flight jobs are failed as `Unreachable` and the socket is
closed.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/revoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": true, "cancelledJobs": 1 }
```

### Restore a device

`POST /api/devices/{deviceId}/unrevoke` — no body.

Deliberately a separate, explicit act. A revoked device cannot un-revoke itself by
re-enrolling.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/unrevoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": false }
```

---

## 4. Restarting a Device

`POST /api/devices/{deviceId}/restart` → `202`

Restarting has its own endpoint rather than being a script you're expected to know.
It's the one destructive action here, so it should read as itself in the audit log
(`device.restart`), and you shouldn't be able to get the command wrong or attach
anything to it. You supply a delay and a message — nothing else.

All fields optional:

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `delaySeconds` | int | `15` | 5–3600 |
| `reason` | string | `"Restart requested from Squash RMM"` | 1–200 chars. Letters, digits, spaces, and `. , : ! ? ' - _ ( ) /` |
| `idempotencyKey` | string | none | any string |

```bash
# Default: 15 seconds from now
curl -sX POST $HOST/api/devices/$DEVICE/restart -H "X-API-Key: $KEY"

# With a message for whoever is sitting at the machine, and a safe retry
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

It becomes an ordinary job, so poll `GET /api/jobs/{jobId}` exactly as you would
for a script. The machine reports back before it goes down; `stdout` reads
`restart scheduled in 120s`.

**Why there's a minimum delay.** The agent has to report the result over the same
machine that's about to shut down. With no delay, the job dies as `Unreachable` and
you're shown a failure for something that actually worked. Five seconds is the
floor.

**Why `reason` is so restricted.** It goes into a command line. Anything that could
close the quote or start a new statement is refused rather than escaped — escaping
is a thing you can get subtly wrong; a whitelist isn't.

| If | You get |
|----|---------|
| `reason` has a character outside the list, or is empty or over 200 chars | `400` |
| `delaySeconds` is outside 5–3600 | `422` |
| Device isn't enrolled / is revoked / is offline | `404` / `403` / `409` |
| `idempotencyKey` was already used | `202` with the original `jobId` and `"deduplicated": true` |

The dashboard makes you type the hostname before it calls this. That's a console
safeguard, not an API one — the API assumes you already decided.

---

## 5. Running Scripts (Jobs)

### Send a script

`POST /api/devices/{deviceId}/jobs` → `202`

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `script` | string | **required** | at least 1 char |
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

**Pro-tip:** always include an `idempotencyKey` — a unique ID you make up. If your
connection drops and you send the request twice, the system recognises the key and
runs the script once:

```json
{ "jobId": "<the original>", "state": "Duplicate", "deduplicated": true }
```

That check happens before every other check, so retrying a request whose response
you never saw is always safe.

| If | You get |
|----|---------|
| Device isn't enrolled | `404` |
| Device is revoked | `403` |
| No heartbeat in 30 seconds | `409` |

The `409` is deliberate: the job is refused rather than queued for a machine that
might never come back. Likewise, jobs that were in flight when the server restarted
are moved to a terminal state at startup, because they can never report back.

### Check the results

`GET /api/jobs/{jobId}?waitMs=0`

Set `waitMs=10000` to make the request pause for up to 10 seconds waiting for the
script to finish, instead of spamming the server. It never errors on timeout — you
get whatever is current, so you can just call again.

```bash
curl -s "$HOST/api/jobs/$JOB?waitMs=20000" -H "X-API-Key: $KEY"
```

```json
{
  "jobId": "…",
  "deviceId": "a1b2c3…",
  "script": "Get-Service Spooler | …",
  "state": "Completed",
  "exitCode": 0,
  "stdout": "{\"Name\":\"Spooler\",\"Status\":\"Stopped\"}",
  "stderr": "",
  "durationMs": 412,
  "roundTripMs": 416,
  "stdoutTruncated": false,
  "stderrTruncated": false,
  "error": null,
  "createdAt": 1758230388.1
}
```

**Crucial rule:** `Completed` only means the script finished running. You must check
`exitCode` to see whether it actually succeeded.

| State | Finished? | Meaning |
|-------|-----------|---------|
| `Queued` | no | Created, not sent yet. |
| `Dispatched` | no | Sent to the device. |
| `Running` | no | The device acknowledged it and started. |
| `Completed` | yes | The script ran. **Check `exitCode`.** |
| `TimedOut` | yes | Ran past `timeoutSeconds`; the process tree was killed. |
| `Unreachable` | yes | The device went away, or was revoked, before reporting. |
| `Failed` | yes | The agent reported failure, or the result failed its signature check. |

**Output limits:** if `stdoutTruncated` is true, the script produced more than
`maxOutputBytes` and was cut off. Do not trust or parse truncated output —
`"12345"` cut to `"123"` parses perfectly and is wrong.

**Results are signed.** The agent signs

```
squash-rmm-result-v1|jobId|scriptSha256|exitCode|durationMs|sha256(stdout)|sha256(stderr)
```

with the key it enrolled, and the server checks it before storing anything. A
result that doesn't verify becomes `Failed`. Output that arrived over an
authenticated socket but wasn't signed by the device that ran it isn't evidence.

`durationMs` is measured on the endpoint. `roundTripMs` is measured by the server
from dispatch to result — it excludes how far away you are and includes everything
the system itself contributes.

### Browse job history

`GET /api/jobs` returns two different shapes depending on the query string.

```bash
# Just a list, newest first. limit is 1-1000, default 50.
curl -s "$HOST/api/jobs?limit=20" -H "X-API-Key: $KEY"

# A page object, if you pass any of page / state / deviceId / search
curl -s "$HOST/api/jobs?page=1&pageSize=30&state=Completed&search=Spooler" \
  -H "X-API-Key: $KEY"
```

```json
{ "items": [ … ], "total": 412, "page": 1, "pageSize": 30, "totalPages": 14 }
```

`pageSize` is 1–100 (default 30), `state` is one of the states above, `search`
matches script text up to 500 characters.

### The audit log

`GET /api/audit?limit=100` — append-only, newest first. Note these come back
snake_case; they're rows as stored.

```bash
curl -s "$HOST/api/audit?limit=50" -H "X-API-Key: $KEY"
```

```json
[{
  "at": 1758230388.0,
  "actor": "ai-driver",
  "action": "job.dispatch",
  "device_id": "a1b2c3…",
  "job_id": "…",
  "detail": "{\"scriptBytes\":64,\"timeoutSeconds\":20}"
}]
```

Everything that changes state is here: tokens minted, enrolments accepted and
refused, connections, dispatches, results, rejected results, restarts, revocations,
investigations opened, and every approval decision. `actor` is the operator name
behind the API key, or `device` / `system`.

---

## 6. AI Diagnostics (Investigations)

Tell the system about a problem in plain English. It investigates, gathers
evidence, and proposes a fix. **It will never execute a fix without your explicit
approval.** None of these endpoints run anything themselves.

### Step 1 — Report a problem

`POST /api/investigations` → `202`

| Field | Type | Notes |
|-------|------|-------|
| `deviceId` | string | must be enrolled and not revoked |
| `problem` | string | 10–4000 chars. The **user's** description, not your diagnosis. |
| `requestId` | string | 1–128 chars, your own unique ID. Makes this idempotent. |

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
{ "investigationId": "inv-abc123…" }
```

| If | You get |
|----|---------|
| Same `requestId`, same device and problem | `202` with the original id — nothing new starts |
| Same `requestId`, **different** device or problem | `409` |
| Device isn't enrolled / is revoked | `404` / `403` |
| `problem` is outside 10–4000 chars | `400` |

Write the symptom, not the cause. "The printer spooler keeps crashing" is already a
diagnosis, and a wrong one will send the investigation down the wrong path.
"Nothing prints and jobs vanish from the queue" is what the user actually knows.

Scheduled work survives a server restart: anything left mid-flight is recovered and
re-queued at startup.

### Step 2 — Check the progress

`GET /api/investigations/{investigationId}`

```bash
curl -s $HOST/api/investigations/inv-abc123 -H "X-API-Key: $KEY"
```

Status moves `queued` ➔ `investigating` ➔ `planning` ➔ `awaiting_approval`, then
`applying` ➔ `verifying` ➔ `resolved`.

| Status | Meaning |
|--------|---------|
| `queued` | Accepted, not picked up yet. |
| `investigating` | Running read-only diagnostics. |
| `planning` | Deciding whether any known repair fits. |
| `awaiting_approval` | A proposal is waiting. **Nothing happens until you decide.** |
| `applying` | You approved; the repair is being sent. |
| `verifying` | The repair ran; checking whether the problem is actually gone. |
| `resolved` | Verified fixed. |
| `unresolved` | The repair ran, but the problem is still there. |
| `completed` | Diagnosis finished and proposed nothing. Normal and common. |
| `rejected` | You declined. |
| `failed` | It couldn't be completed. |

Once it hits `awaiting_approval`, you get exactly what checks it ran, the evidence,
and the exact script it wants to run:

```json
{
  "investigationId": "inv-abc123…",
  "deviceId": "a1b2c3…",
  "hostname": "EC2AMAZ-ABC123",
  "problem": "Nothing prints from this computer.",
  "status": "awaiting_approval",
  "createdAt": "2026-09-18T14:02:11Z",
  "events": [
    { "at": "2026-09-18T14:02:12Z", "message": "Checking service_status (service_name=Spooler)." },
    { "at": "2026-09-18T14:02:13Z", "message": "service_status check completed in 214ms." }
  ],
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
    "risk": "The service is briefly unavailable while it restarts.",
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

`proposal` is `null` while the status is `queued`. Its `decision` is one of:

- `proposed` — there's something to approve.
- `no_action` — nothing in the repair catalogue fits. **This is a normal outcome**,
  not a failure; most findings have no safe automated remedy.
- `refused` — the planner picked something that failed validation. `refusalReason`
  says what.

Two things worth reading carefully if you're building a UI on this:

**`evidence` is the raw diagnostic output, not a summary.** Show it. A finding is a
claim; the evidence is what lets someone check it. (An earlier version passed
summaries to the planner, which then reasoned from `"service_status: ok"` instead
of from the data, and got it wrong.)

**`checkSucceeded: false` means the check itself didn't complete.** That is not the
same as the condition being absent, and must never be rendered as "nothing found".

After a repair is applied, `outcome` appears:

```json
{
  "applied": true, "resolved": true,
  "detail": "the service reports Running",
  "jobId": "…", "exitCode": 0,
  "conditionBefore": true, "conditionAfter": true
}
```

`resolved: null` means it ran but the effect couldn't be verified. Exiting zero
means the command ran; whether the problem is gone is a separate question, answered
only by re-running the verification check.

### Step 3 — Approve or reject

`POST /api/investigations/{investigationId}/decision`

All four fields are required.

| Field | Type | Where it comes from |
|-------|------|---------------------|
| `proposalId` | string | `proposal.proposalId` from step 2 |
| `proposalHash` | string | `proposal.proposalHash` from step 2 |
| `deviceId` | string | the investigation's device |
| `decision` | string | `"approve"` or `"reject"` |

```bash
curl -sX POST $HOST/api/investigations/inv-abc123/decision \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
        "proposalId": "p-7f3a…",
        "proposalHash": "9c1d…",
        "deviceId": "a1b2c3…",
        "decision": "approve"
      }'
```

Returns the full investigation, same shape as step 2.

To prevent accidents you must include the `proposalHash`. If the situation on the
computer changed while you were reading the proposal, your approval is rejected and
you're made to review the new reality first.

| If | You get |
|----|---------|
| There's no actionable proposal | `409` |
| Any field mismatches, or the server's recomputed hash differs | `409` — "The proposal has changed since you last saw it." |
| The proposal expired (15 minutes) | `409` |
| You send the same decision twice | `200` — idempotent |
| A **different** decision was already recorded | `409` |

Two more guarantees behind that gate, which matter if you're reviewing this system
rather than just calling it:

- **The script that runs is rebuilt from the repair catalogue** using the approved
  repair name and arguments, and the approved hash is checked against that rebuild.
  The `script` text stored on the proposal is never trusted — comparing one stored
  field against another only proves nobody changed both.
- **The precondition is re-checked on the live machine** immediately before the
  repair runs. The world may have moved on while you were deciding, and a repair
  whose condition no longer holds is refused rather than applied.

---

## 7. How Agents Connect

You don't call this — the agent does. It's here so the model is clear.

`WS /agent/connect`. The device opens the connection, which is what makes this work
behind NAT with no inbound firewall rule. One socket carries jobs out and results
back.

```
1. server → {"type":"challenge","nonce":"…"}
2. device → {"type":"hello","deviceId":"…","signature":"<nonce signed>",
             "hostname":"…","osVersion":"…","agentVersion":"…",
             "bootTimeUnixMs":…,"uptimeSeconds":…}
3. server → {"type":"hello_ack","deviceId":"…","heartbeatIntervalSeconds":10}
```

Close codes: `1002` no hello · `4401` not enrolled or bad signature · `4403` revoked.

Then, continuously:

| Direction | Frame |
|-----------|-------|
| device → | `{"type":"heartbeat"}` every 10 seconds |
| server → | `{"type":"job_dispatch","job":{"jobId","script","timeoutSeconds","maxOutputBytes","scriptSha256"}}` |
| device → | `{"type":"job_accepted","jobId":"…"}` |
| device → | `{"type":"job_result","result":{…,"attestation":"<signature>"}}` |

`scriptSha256` is sent with the job so the agent signs a hash of the script it
actually received, binding the result to the exact instructions. A result for a job
the device doesn't own is dropped.

---

## Four Rules for Any Client

1. **Send an `idempotencyKey` on every dispatch and restart.** Retrying a request
   whose response you lost is otherwise a second execution.
2. **Check `exitCode`, not just `state`.** `Completed` only means the script ran.
3. **Never parse truncated output.** Treat `stdoutTruncated` as a failed
   observation, not a smaller one.
4. **Treat `409` as "re-read, then decide again".** It is never a retry signal.

FastAPI also serves OpenAPI at `/openapi.json` and interactive docs at `/docs`,
generated from the same routes described here.
