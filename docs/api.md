# Control Plane API - Simplified Guide

This API controls Windows devices, runs scripts, and uses AI for diagnostics. Everything uses standard HTTP and JSON.

## The Basics

- **Base URL:** `https://35-173-64-136.sslip.io`
- **Format:** JSON (camelCase). Times are Unix seconds (except for investigations, which use dates like `2026-09-18T14:02:11Z`).
- **Authentication:** Humans and scripts use a header: `X-API-Key: <your-key>`. Devices use one-time tokens.

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
iwr https://HOST/install.ps1 -OutFile i.ps1
.\i.ps1 -Server https://HOST -Token enr_…
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
  "agentVersion": "0.4.0"
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

### View device history
Shows reboots, connections, and disconnects.

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

---

## 4. Restarting a Device

Schedule a secure restart. The `reason` must be simple text (no special characters). Minimum delay is 5 seconds.

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

### Check the results
Use `waitMs` to wait for the script to finish without spamming the server. 
**Note:** `Completed` just means it ran. Always check the `exitCode`. Do not trust output if `stdoutTruncated` is true.

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
{"type":"job_result","result":{"jobId":"…","exitCode":0,"stdout":"…","stderr":"…","durationMs":150,"attestation":"<signature>"}}
```

---

## Four Rules for Any Client

1. **Send an `idempotencyKey` on dispatches and restarts** to prevent accidental double-executions.
2. **Check `exitCode`, not just `state`.** `Completed` only means the script finished running, not that it worked.
3. **Never parse truncated output.** Treat `stdoutTruncated` as a failed observation.
4. **Treat `409` as "re-read, then decide again".** Never automatically retry on a 409 conflict.