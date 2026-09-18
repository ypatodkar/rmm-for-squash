# Simplified Control Plane API Documentation

This API controls a fleet of devices, runs scripts on them, and uses AI to diagnose and fix problems. Everything is handled via standard HTTP requests with JSON. 

Here is the simplified breakdown of how to use it.

## The Basics

*   **Base URL:** `https://35-173-64-136.sslip.io`
*   **Format:** Send and receive JSON (camelCase). Times are in Unix seconds.
*   **Authentication:** If you are a human or a script, put your API key in the header: `X-API-Key: <your-key>`. Devices (agents) don't use API keys; they use one-time tokens.

**Key Status Codes to Know:**
*   `200` / `201`: Success.
*   `202`: Accepted. The system got your request and is working on it in the background. Check back later.
*   `409`: Conflict. The state of the system changed (e.g., the device went offline or a proposal expired). **Do not just retry.** Fetch the latest data and decide what to do next.

---

## 1. Getting the Agent 
These endpoints require no authentication. Anyone can hit them.
*   `GET /health`: Checks if the server is up.
*   `GET /`: Loads the dashboard interface.
*   `GET /download/agent.exe` (or `.sha256` / `install.ps1`): Downloads the agent software to install on a device.

---

## 2. Adding Devices (Enrolment)
To connect a new computer to the system, you generate a one-time ticket, and the computer redeems it.

1.  **Generate a token:** `POST /api/enrollment-tokens`
    *   Creates a single-use token valid for one hour. 
2.  **Device enrolls:** `POST /api/enroll`
    *   *Note: The agent software does this automatically.* It hands in the token and registers its security keys. 

---

## 3. Managing Devices
Once devices are enrolled, you can monitor and control their access.

*   **List all devices:** `GET /api/devices`
    *   Shows who is online, their OS, and uptime. "Online" means it pinged the server in the last 30 seconds.
*   **View device history:** `GET /api/devices/{deviceId}/events`
    *   Shows reboots, connections, and disconnects.
*   **Kick a device:** `POST /api/devices/{deviceId}/revoke`
    *   Instantly kills the connection and cancels any pending work.
*   **Restore a device:** `POST /api/devices/{deviceId}/unrevoke`
*   **Restart a device:** `POST /api/devices/{deviceId}/restart`
    *   You give it a delay and a message, not a script, so you can't get the command wrong or attach anything to it. Every field is optional. The defaults restart the machine in 15 seconds.
    *   `delaySeconds` (default `15`, range 5-3600) and `reason` (default `"Restart requested from Squash RMM"`, 1-200 characters) and `idempotencyKey`.
    *   *Why there's a minimum delay:* the agent has to report the result over the same machine that is about to shut down. With no delay, the job dies as `Unreachable` and you get shown a failure for something that actually worked.
    *   *Why `reason` is fussy:* it goes onto a command line, so anything that could close the quote or start a new statement is refused rather than escaped.
    *   It becomes an ordinary job, so check the result with `GET /api/jobs/{jobId}` exactly as you would for a script. The machine reports back before it goes down.

    ```bash
    # Restart in 15 seconds
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
    { "jobId": "...", "state": "Dispatched", "restartAt": 1758230520.0, "delaySeconds": 120 }
    ```

    From the CLI, where `restart` and `reboot` are the same command:

    ```bash
    squashctl restart WIN-DEMO-1                    # prompts for the hostname, 15s
    squashctl reboot  WIN-DEMO-1 --in 120 --reason 'Monthly patch window'
    squashctl restart WIN-DEMO-1 --yes              # no prompt, for scripts
    ```

---

## 4. Running Scripts (Jobs)
You can send PowerShell scripts to any online device.

*   **Send a script:** `POST /api/devices/{deviceId}/jobs`
    *   You provide the `script` and a `timeoutSeconds`. 
    *   *Pro-tip:* Always include an `idempotencyKey` (a unique ID you make up). If your internet drops and you accidentally send the request twice, the system will recognize the key and only run the script once.
*   **Check the results:** `GET /api/jobs/{jobId}?waitMs=0`
    *   You can set `waitMs=10000` to make the request pause for up to 10 seconds waiting for the script to finish. This saves you from having to spam the server with requests.
    *   **Crucial Rule:** If the job state is `Completed`, that just means the script finished running. You must check the `exitCode` to see if the script actually succeeded (0 usually means success). 
    *   **Output Limits:** If `stdoutTruncated` is true, the script generated too much text and got cut off. Do not trust or parse truncated output.

---

## 5. AI Diagnostics (Investigations)
You can tell the system about a problem in plain English. It will investigate, gather evidence, and propose a fix. **It will never execute a fix without your explicit approval.**

1.  **Report a problem:** `POST /api/investigations`
    *   Tell it what's wrong (e.g., `"The printer spooler keeps crashing"`). It returns an `investigationId`.
2.  **Check the progress:** `GET /api/investigations/{investigationId}`
    *   The status will move from `queued` ➔ `investigating` ➔ `planning` ➔ `awaiting_approval`. 
    *   Once it hits `awaiting_approval`, it will show you exactly what diagnostic checks it ran, the evidence it found, and the exact PowerShell script it wants to run to fix it.
3.  **Approve or Reject:** `POST /api/investigations/{investigationId}/decision`
    *   Send `approve` or `reject`. 
    *   To prevent accidents, you must include the `proposalHash` in your approval. If the situation on the computer changed while you were reading the proposal, the system will reject your approval and make you review the new reality first.