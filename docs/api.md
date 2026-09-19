# Control Plane API Guide

This API controls Windows devices, runs scripts, and uses AI for diagnostics. Everything uses standard HTTP and JSON.

## The Basics

- **Base URL:** `https://35-173-64-136.sslip.io`
- **Format:** JSON (camelCase). Times are Unix seconds (except for investigations, which use dates like `2026-09-18T14:02:11Z`).
- **Authentication:** Humans and scripts use `X-API-Key: <your-key>`. A device uses a one-time token only to enroll; afterward it authenticates each connection by signing a server challenge with its private key.

**Setup variables for the examples below:**
```bash
export HOST=https://35-173-64-136.sslip.io
export KEY=<your-key>
export DEVICE=<a deviceId from GET /api/devices>
```

**Status Codes:**
- `200` / `201`: Success. 
- `202`: Accepted (Working on it, check back later).
- `400` / `422`: Bad request.
- `401` / `403` / `404`: Unauthorized, Forbidden (revoked), or Not Found.
- `409`: Conflict (The system state changed. **Do not just retry.** Fetch the latest data and decide again).

---

## 1. Getting the Agent

These endpoints are public and require no authentication.

```bash
curl -s  $HOST/health              # {"status":"ok"}
curl -sO $HOST/download/agent.exe  # the agent binary
curl -s  $HOST/download/agent.sha256
curl -s  $HOST/install.ps1
curl -s  $HOST/uninstall.ps1
```

---

## 2. Adding Devices (Enrolment)

### Step 1 — Generate a token
Creates a single-use token valid for one hour. Set `allowRebind: true` and provide a `deviceId` only if you are recovering an already-enrolled machine.

```bash
# For a brand-new machine
curl -sX POST $HOST/api/enrollment-tokens -H "X-API-Key: $KEY"

# For recovering an already-enrolled machine
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

Run this on the endpoint in an Administrator PowerShell to install:
```powershell
$Server = "https://35-173-64-136.sslip.io"
iwr "$Server/install.ps1" -OutFile i.ps1
.\i.ps1 -Server $Server -Token enr_…
```

### Step 2 — The device enrols
**The agent software does this automatically.** It redeems the token to register its security keys.

```bash
curl -sX POST $HOST/api/enroll -H 'Content-Type: application/json' -d '{
  "token": "enr_…",
  "deviceId": "a1b2c3…",
  "publicKey": "MFkwEwYHKoZIzj0CAQ…",
  "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022",
  "agentVersion": "0.2.0"
}'
```

```json
{ "deviceId": "a1b2c3…", "heartbeatIntervalSeconds": 10 }
```

---

## 3. Managing Devices

### List all devices
Shows online status (`online` means it pinged the server in the last 30 seconds), OS, and uptime.

```bash
curl -s $HOST/api/devices -H "X-API-Key: $KEY"
```

```json
[{
  "deviceId": "a1b2c3…",
  "hostname": "EC2AMAZ-ABC123",
  "osVersion": "Microsoft Windows Server 2022",
  "agentVersion": "0.2.0",
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

### View device history
Shows reboots, connections, and disconnects.

```bash
curl -s "$HOST/api/devices/$DEVICE/events?limit=20" -H "X-API-Key: $KEY"
```

```json
[
  { "event": "rebooted", "at": 1758100000.0, "detail": "{\"previousUptimeSeconds\":54321}" },
  { "event": "restart_requested", "at": 1758099980.0, "detail": "{\"operator\":\"ops\",\"delaySeconds\":15}" }
]
```

### Kick a device
Instantly kills the connection and cancels pending work.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/revoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": true, "cancelledJobs": 1 }
```

### Restore a device
Must be done explicitly to allow a kicked device back in.

```bash
curl -sX POST $HOST/api/devices/$DEVICE/unrevoke -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "a1b2c3…", "revoked": false }
```

### Upgrade (reinstall) the agent
Reinstalls the agent in place with whatever build the server is currently serving. The device keeps its ID, key and history, and no token is needed. The agent must be online; if it's gone or its key is lost, use a recovery token (`allowRebind`, section 2) and run the installer on the machine.

The script is the server's, not yours: it reinstalls from the server the device is enrolled with, into the folder its service is registered in. The only optional field is `idempotencyKey`.

```bash
# Upgrade one device
curl -sX POST $HOST/api/devices/$DEVICE/upgrade -H "X-API-Key: $KEY"

# With a safe retry key
curl -sX POST $HOST/api/devices/$DEVICE/upgrade \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"idempotencyKey": "upgrade-2026-09-18"}'
```

```json
{ "jobId": "…", "state": "Dispatched", "startsInSeconds": 20 }
```

`202` means the upgrade is **scheduled**, not finished. The job completes within seconds with `stdout` reading `upgrade scheduled from https://…`. About 20 seconds later the agent goes offline, reinstalls, and reconnects. To know it's back, look for an `online` event newer than the job's `createdAt` in `GET /api/devices/{deviceId}/events`. Don't use `online` in `GET /api/devices`: it stays true until the upgrade actually starts.

Publish the new `SquashRmm.Agent.exe` and its `.sha256` to the server **before** calling this, or it reinstalls the old build. If the agent doesn't come back, the installer's log is at `C:\Windows\Temp\squash-install.log` on the endpoint.

Same checks as any job: `404` if not enrolled, `403` if revoked, `409` if offline. Shows up in the audit log as `device.upgrade`, and in device history as `upgrade_requested`.

From the CLI, which also waits for the agent to come back:

```bash
squashctl upgrade WIN-DEMO-1
```

### Device inventory
What each machine is: OS version and build, hardware, installed software and last boot time. The server collects it itself, so reading it never runs anything on the machine:
- when a device connects and hasn't been collected in the last 6 hours
- straight away after a reboot
- every 6 hours while it's online
- whenever you ask for a refresh.

**Every device:**

```bash
curl -s $HOST/api/inventory -H "X-API-Key: $KEY"

# Leave out the software lists (each still includes softwareCount)
curl -s "$HOST/api/inventory?includeSoftware=false" -H "X-API-Key: $KEY"
```

**One device:**

```bash
curl -s $HOST/api/devices/$DEVICE/inventory -H "X-API-Key: $KEY"
```

```json
{
  "deviceId": "c61f63b9…",
  "hostname": "EC2AMAZ-LP5BJ78",
  "online": true,
  "revoked": false,
  "lastBootAt": 1758167003.5,
  "collectedAt": 1758242130.2,
  "stale": false,
  "collecting": false,
  "lastAttemptAt": 1758242130.2,
  "lastError": null,
  "inventory": {
    "os": {
      "name": "Microsoft Windows Server 2022 Datacenter",
      "version": "10.0.20348", "build": "20348.5622", "displayVersion": "21H2",
      "architecture": "64-bit",
      "installedAt": "2026-09-17T08:00:22Z", "lastBootAt": "2026-09-18T03:43:23Z"
    },
    "hardware": {
      "manufacturer": "Amazon EC2", "model": "t3.medium",
      "serialNumber": "ec24eff6-…", "biosVersion": "1.0", "memoryMB": 4036,
      "processors": [{ "name": "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
                       "cores": 1, "logicalProcessors": 2, "maxClockMHz": 2500 }],
      "disks": [{ "drive": "C:", "sizeGB": 50, "freeGB": 29.7 }],
      "networkAdapters": [{ "name": "Amazon Elastic Network Adapter",
                            "mac": "0A:FF:C8:B4:EF:43", "ipv4": ["172.31.27.210"] }]
    },
    "software": [
      { "name": "Amazon SSM Agent", "version": "3.3.5226.0",
        "publisher": "Amazon Web Services", "installedOn": null }
    ],
    "softwareCount": 6
  }
}
```

| Field | Meaning |
|---|---|
| `lastBootAt` (top level) | **Live.** Worked out from the uptime the agent reports every time it connects, so it's current even between collections |
| `collectedAt` | When the stored inventory was collected |
| `stale` | `true` if it's older than 6 hours, or has never been collected |
| `collecting` | A collection is running right now |
| `lastError` | Why the most recent attempt failed. **The last good inventory is kept**: one failed attempt never erases it |
| `inventory` | `null` until the first collection succeeds |

A device that hasn't been collected yet is still listed, with `"inventory": null`.

**Collect now:**

```bash
curl -sX POST $HOST/api/devices/$DEVICE/inventory/refresh -H "X-API-Key: $KEY"
```

```json
{ "deviceId": "c61f63b9…", "collecting": true, "jobId": "…" }
```

`202`: collection has started. It usually takes about 3 seconds; read the result back with `GET`, where `collectedAt` changes. If one is already running you get `"jobId": null` and nothing new is sent. Same checks as any job: `404` if the device isn't enrolled, `403` if revoked, `409` if offline.

**How it's collected.** A fixed, read-only script, sent by the server as an ordinary job under the name `system`. It's signed and time-limited like every other job, and it appears in the job history and audit log (`inventory.collect`). Nothing you send can change the script. Installed software is read from the registry, not from `Win32_Product`, which is slow and makes Windows re-check every installed MSI program. A result that was cut off, or isn't valid JSON, is recorded as a failed collection, never stored as a partial inventory.

---

## 4. Restarting a Device

Schedule a secure restart. The `reason` accepts a restricted set of ordinary printable characters; command separators and other unsafe characters are rejected. Minimum delay is 5 seconds.

```bash
# Default: 15 seconds from now
curl -sX POST $HOST/api/devices/$DEVICE/restart -H "X-API-Key: $KEY"

# With a message and a safe retry key
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

From the CLI, where `restart` and `reboot` are the same command:

```bash
squashctl restart WIN-DEMO-1                    # prompts for the hostname, 15s
squashctl reboot  WIN-DEMO-1 --in 120 --reason 'Monthly patch window'
squashctl restart WIN-DEMO-1 --yes              # no prompt, for scripts
```

Without `--yes` it asks you to type the device name, and refuses outright if there is no terminal to ask at, so a restart cannot happen by accident in a pipeline.

---

## 5. Running Scripts (Jobs)

### Send a script
Send a PowerShell script to a device. **Always use an `idempotencyKey`** so if your internet drops, retrying won't run the script twice.

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

| Field | Default | Limit |
|---|---|---|
| `script` | required | Up to 12,000 characters. Windows passes the script to PowerShell on a command line capped at 32,767 characters, so a longer script could never start; it gets `422` instead. |
| `timeoutSeconds` | `30` | 1–600 |
| `maxOutputBytes` | `1048576` | 1,024 – 4,194,304 (4 MiB), per stream, counted in UTF-8 bytes |
| `idempotencyKey` | none | Optional |

Sending the same request again with the same `idempotencyKey` returns the original job with `"state": "Duplicate"` and runs nothing. Reusing a key for a **different** request (another script, device, timeout or operator) returns `409` rather than someone else's job.

### Check the results
Use `waitMs` to wait for the script to finish without spamming the server. 
**Note:** `Completed` just means it ran. Always check the `exitCode`. Do not trust output if `stdoutTruncated` is true.

The server checks every result before storing it: `exitCode` and `durationMs` must be whole numbers and `state` must be a finished state, or the job becomes `Failed` with `"error": "Result rejected: malformed result: …"`. Output longer than `maxOutputBytes` is cut there and flagged, even if an agent sent more.

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

### Browse job history

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

### The audit log
Shows all state changes (row names are snake_case).

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

---

## 6. AI Diagnostics (Investigations)

Report a problem in plain English. The AI will investigate and propose a fix, but **will never execute it without your approval**.

### Browse investigations
The list endpoint is paginated. `status` accepts an exact status or one of the groups `active`, `awaiting_approval` and `finished`.

```bash
curl -s "$HOST/api/investigations?page=1&pageSize=30&status=active" \
  -H "X-API-Key: $KEY"
```

```json
{ "items": [ … ], "page": 1, "totalPages": 1, "total": 2 }
```

### Step 1 — Report a problem
Describe the symptoms the user is seeing, not your guessed cause.

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

### Step 2 — Check the progress
Status flows like this: `queued` ➔ `investigating` ➔ `planning` ➔ `awaiting_approval`.

```bash
curl -s $HOST/api/investigations/inv-abc123 -H "X-API-Key: $KEY"
```

Once it reaches `awaiting_approval`, you will see the evidence and the proposed script:

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

### Step 3 — Approve or reject
You must include the `proposalHash` to prove you are approving the most current plan. If the device's situation changed while you were reading, it will reject your approval and require you to review the new data.

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

Reject with the same body and `"decision": "reject"`.

### Step 4 — Poll for the final result
The decision endpoint returns immediately. Continue fetching the investigation while an approved repair is `applying` or `verifying`:

```bash
curl -s $HOST/api/investigations/inv-abc123 -H "X-API-Key: $KEY"
```

`resolved` means the repair ran and its verification check passed. `unresolved` means the repair or verification did not establish success. `failed` reports an execution error, `rejected` records an operator rejection, and `completed` means the planner found no appropriate automated repair. The final response includes an `outcome` object with the repair and verification job IDs, whether the repair was applied, the verification result, and a human-readable detail.

---

## 7. How Agents Connect (WebSocket)

The agent initiates the connection (allowing it to work behind NATs). 
`WS /agent/connect`

**Handshake:**
```json
1. server → {"type":"challenge","nonce":"…"}
2. device → {"type":"hello","deviceId":"…","signature":"<nonce signed>","hostname":"…","osVersion":"…","agentVersion":"…","bootTimeUnixMs":…,"uptimeSeconds":…}
3. server → {"type":"hello_ack","deviceId":"…","heartbeatIntervalSeconds":10}
```

**Steady State:**
```json
// device →
{"type":"heartbeat"} // (every 10 seconds)

// server → 
{"type":"job_dispatch","job":{"jobId":"…","script":"…","timeoutSeconds":30,"maxOutputBytes":1048576,"scriptSha256":"…"}}

// device → 
{"type":"job_accepted","jobId":"…"}

// device → 
{"type":"job_result","result":{"jobId":"…","state":"Completed","exitCode":0,"stdout":"…","stderr":"…","durationMs":150,"stdoutTruncated":false,"stderrTruncated":false,"scriptSha256":"…","signature":"…"}}
```

Before running anything, the agent hashes the script it received and compares it with `scriptSha256`; on a mismatch it refuses and reports `Failed` without starting a process. All of a session's messages go out through one sender, so a heartbeat and a finishing job never write to the socket at the same time.

---

## Four Rules for Any Client

1. **Send an `idempotencyKey` on dispatches and restarts** to prevent accidental double-executions.
2. **Check `exitCode`, not just `state`.** `Completed` only means the script finished running, not that it worked.
3. **Never parse truncated output.** Treat `stdoutTruncated` as a failed observation.
4. **Treat `409` as "re-read, then decide again".** Never automatically retry on a 409 conflict.
