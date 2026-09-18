# Simplified Control Plane API Guide

This API lets you manage Windows devices, run PowerShell scripts on them, and use AI to troubleshoot and fix issues. It uses standard HTTP requests and JSON.

## The Basics
* **Base URL:** `https://35-173-64-136.sslip.io`
* **Format:** Send and receive JSON (camelCase).
* **Authentication:** Humans and scripts put their API key in the header: `X-API-Key: <your-key>`. Devices use one-time tokens instead.

**Key Status Codes:**
* `200` / `201`: Success!
* `202`: Accepted. The system is working on it, check back soon.
* `409`: Conflict. Something changed (e.g., the device went offline). **Do not just retry.** Fetch the latest data and decide what to do.

---

## 1. Getting the Agent 
*(No authentication required)*
* `GET /health`: Check if the server is alive.
* `GET /download/agent.exe` (or `.sha256`, `install.ps1`, `uninstall.ps1`): Download the installation files.

---

## 2. Adding Devices (Enrolment)
1. **Get a Token:** `POST /api/enrollment-tokens`
   * Generates a 1-hour, single-use ticket for a new machine.
2. **Device Enrolls:** `POST /api/enroll`
   * *The agent does this for you.* It trades the token for secure keys. 

---

## 3. Managing Devices
* **List Devices:** `GET /api/devices`
  * See who is online (pinged in the last 30s) and their uptime.
* **View History:** `GET /api/devices/{deviceId}/events`
  * See connection drops, reboots, and restart requests.
* **Kick Device:** `POST /api/devices/{deviceId}/revoke`
  * Instantly kills the connection and stops pending work.
* **Restore Device:** `POST /api/devices/{deviceId}/unrevoke`

---

## 4. Restarting a Device
* **Request a Restart:** `POST /api/devices/{deviceId}/restart`
  * Needs a `delaySeconds` (minimum 5s) and a `reason` (strict text limits, no weird characters).
  * *Pro-tip:* Always use an `idempotencyKey` so a network blip doesn't trigger two restarts.

---

## 5. Running Scripts (Jobs)
* **Send Script:** `POST /api/devices/{deviceId}/jobs`
  * Provide the `script` and a `timeoutSeconds`. Use an `idempotencyKey`!
* **Check Result:** `GET /api/jobs/{jobId}?waitMs=0`
  * Use `waitMs=10000` to pause and wait for up to 10 seconds for it to finish.
  * **Rule 1:** Just because the state is `Completed` doesn't mean the script worked. Check the `exitCode`!
  * **Rule 2:** If `stdoutTruncated` is true, the text got cut off. Don't trust it.
* **View History:** `GET /api/jobs` (Lists past jobs)
* **View Audit Log:** `GET /api/audit` (Lists every major action taken on the server)

---

## 6. AI Diagnostics (Investigations)
Tell the AI what's broken in plain English. **It will never fix anything without your approval.**

1. **Report Problem:** `POST /api/investigations`
   * Describe the user's symptom (e.g., "Nothing prints from this computer").
2. **Check Progress:** `GET /api/investigations/{investigationId}`
   * Wait until the status hits `awaiting_approval`. 
   * Review the `evidence` (raw data the AI found) and the `proposal` (the exact script it wants to run).
3. **Approve / Reject:** `POST /api/investigations/{investigationId}/decision`
   * Send `approve` or `reject`. 
   * You *must* include the `proposalHash`. If the computer's state changed while you were reading, the server rejects your approval to keep things safe.

---

## 💡 The 4 Golden Rules for Building Clients
1. **Always use an `idempotencyKey`** when dispatching jobs or restarts. 
2. **Check the `exitCode`**, not just the job state.
3. **Never parse truncated output.** Treat it as a failure.
4. **Treat a `409` error as a red flag.** Re-read the current state before trying again.