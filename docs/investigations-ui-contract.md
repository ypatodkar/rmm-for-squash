# Investigations UI handoff

The frontend lives in `server/static/index.html`, under `#investigations`.
`#devices` retains device enrollment, manual PowerShell and job history.
No server or driver implementation is included in this frontend change.

Until the routes below exist, the page keeps submission disabled, allows a
request draft, and offers a clearly labelled, non-executable example preview.
There are no simulated live requests or direct PowerShell dispatches from this
page. The API uses the dashboard's existing `X-API-Key` authentication.

## Routes to implement

- `GET /api/investigations?page=1&pageSize=30&search=...&status=...`
  returns `{ "items": [...], "page": 1, "totalPages": 1, "total": 0 }`.
  Search matches problem/device name. Status filters: omitted (all), `active`
  (queued/investigating/planning/applying/verifying), `awaiting_approval`, and
  `finished` (completed/resolved/unresolved/failed/rejected/cancelled).
  Order newest first; each item contains the detail object's identity, problem,
  device, status and creation time fields. Empty results have one page.
- `POST /api/investigations` accepts
  `{ "deviceId": "...", "problem": "...", "requestId": "client UUID" }`.
  Return `202` with `{ "investigationId": "..." }` immediately after durable
  creation. Atomically deduplicate by operator and requestId; reject payload
  changes for an existing key. The browser reuses this key after an ambiguous
  network failure. Validate device access/revocation, text length (10–4000),
  and reject invalid requests before enqueueing work.
- `GET /api/investigations/{id}` returns the detail object below. The page polls
  snapshots every three seconds while visible. Failed updates preserve the last
  displayed results and disable approval until refreshed successfully.
- `POST /api/investigations/{id}/decision` accepts
  `{ "proposalId": "...", "proposalHash": "...", "deviceId": "...",
  "decision": "approve" }` (or `reject`). Return the updated detail object.
  Authenticate the operator server-side; never accept `approvedBy` from the UI.
  Reject changed, expired, unauthorized or already superseded proposals with
  `409`/`403`. Deduplicate identical decisions; conflicting decisions are `409`.
  Commit approval and enqueue execution durably. Do not execute in the HTTP
  handler or trust a browser checkbox as authorization.

Use JSON `{ "detail": "safe error message" }` for errors. The UI uses existing
`GET /api/devices` for device choices; no additional fleet route is needed.

## Detail response

```json
{
  "investigationId": "inv-123",
  "deviceId": "device-123",
  "hostname": "OFFICE-PC",
  "problem": "Nothing prints from this computer.",
  "status": "awaiting_approval",
  "createdAt": "2026-09-18T10:00:00Z",
  "events": [
    { "at": "2026-09-18T10:00:01Z", "message": "Checking the Print Spooler service." }
  ],
  "finding": "The Print Spooler service is stopped.",
  "confidence": "high",
  "evidence": [
    { "diagnostic": "service_status", "checkSucceeded": true,
      "output": { "name": "Spooler", "status": "Stopped" }, "note": null }
  ],
  "proposal": {
    "proposalId": "proposal-123",
    "proposalHash": "server-computed immutable action digest",
    "decision": "proposed",
    "reasoning": "The service check confirms Spooler is stopped.",
    "expectedEffect": "Windows can process print jobs again.",
    "risk": "Starts a service that may have been stopped deliberately.",
    "verifiedBy": "Check Spooler is running, then ask the user to try printing.",
    "script": "Start-Service -Name 'Spooler' -ErrorAction Stop",
    "scriptSha256": "SHA-256 of the exact script",
    "expiresAt": "2026-09-18T10:15:00Z"
  },
  "outcome": null,
  "error": null
}
```

`proposalHash` must bind the investigation, device, proposal version/ID, repair
name, validated arguments, exact script/hash, expiry, and reviewed impact and
verification details. The server must revalidate that binding and recompute the
script hash at execution. The frontend only sends back the server-issued binding;
it does not decide its validity. Return immutable proposal fields while awaiting
a decision; a changed proposal must get a fresh ID/hash and fresh approval.

Optional `proposal.decision` values `no_action` and `refused` display an
explanation without approval controls. Omit `proposal` until planning finishes.
`outcome` has `{ "applied": true, "resolved": true, "detail": "...", "jobId": "..." }`;
`resolved` is true, false, or null (unknown). Status values supported by the UI:
`queued`, `investigating`, `planning`, `awaiting_approval`, `applying`, `verifying`,
`completed` (diagnosis only), `resolved`, `unresolved`, `failed`, `rejected`,
`cancelled`. `resolved` means the specific repair condition was verified; avoid
claiming that the original user symptom was necessarily fixed.

## Ownership and recovery

All investigation state, events, evidence, proposals, decisions and execution
job IDs belong in durable backend storage. The frontend stores no investigation
data or approvals in browser storage. Reloading the page retrieves history from
the backend. A submission key survives retries within the current page, not a
browser restart; after a reload, consult request history before resubmitting.

The preview is explicit fixture data and never sends commands or decisions.
Only actual backend status/events animate the live progress indicator. Endpoint
and model output is rendered as text (no HTML/Markdown execution).
