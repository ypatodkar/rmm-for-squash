# System architecture and design notes

The system has a C# Windows service, a Python/FastAPI control plane, and a Python
AI driver. SQLite stores device identity, job history, inventory, investigations,
proposals, and decisions. The dashboard, curl, Postman, and AI driver use the
same REST API. The endpoint executes commands; it does not run an LLM.

## Connection and identity

The Windows service runs as LocalSystem, starts automatically, and opens an
outbound WebSocket. This works behind NAT without an inbound endpoint port.
Public deployments use HTTPS/WSS with normal certificate validation. Heartbeats
arrive every 10 seconds; reachability requires an open, non-revoked connection
and a received message within 30 seconds.

Enrollment uses a random, single-use token that expires after one hour. The
agent generates a P-256 key pair and registers its **public** key. Its private
key stays on Windows, protected by machine-scope DPAPI and file permissions
restricted to SYSTEM and Administrators. Every connection requires signing a
fresh server challenge. The MachineGuid-derived device ID survives reinstall,
but is not proof of identity. Replacing a lost key requires a recovery token
bound to that device.

A stolen unused token can still enroll the first machine that redeems it. This
remaining gap and the proposed pending-enrollment check are described in the
[threat model](threat-model.md).

## Job lifecycle and speed

A request validates authentication, enrollment, revocation and reachability,
stores the job, and returns a job ID without waiting for execution. The server
pushes it over the existing socket. Individual jobs, rather than persistent
PowerShell sessions, keep results and audit records isolated while the open
connection avoids polling delays. PowerShell startup and the command itself
still contribute latency; roughly two seconds per dependent step is a target,
not a guarantee for every diagnostic.

Jobs progress through `Dispatched`, `Running`, and a terminal state:
`Completed`, `TimedOut`, `Failed`, or `Unreachable`. `Completed` must be checked
alongside `exitCode`. Output is bounded per stream and truncation is flagged.
`durationMs` measures endpoint execution; `roundTripMs` measures server dispatch
to result, excluding client latency and model reasoning.

Offline dispatches fail immediately with HTTP 409. An idempotency key makes a
retry return the original job; conflicting reuse is rejected. The agent checks
the script hash before execution, and signs the job ID, script hash, exit code,
duration, and output hashes. The server verifies the result before accepting it.
Revocation closes the socket, discards undispatched work, and marks outstanding
jobs unreachable; it cannot undo work already executed.

## AI investigation and durable state

A problem submission creates a SQLite investigation in `queued` state and
schedules an in-process asyncio task. An atomic database update claims it as
`investigating`; blocking model and API calls run in a worker thread. SQLite is
the durable state store, not a separate polling queue or message broker.

The diagnosis agent chooses from eleven reviewed read-only diagnostics, using
each result to decide what to check next. Progress is recorded as events and
collected evidence is saved after diagnosis. The same worker passes the finding
and evidence directly to a separate planner model call. The planner selects one
of four reviewed repairs, or explains why no action applies; it does not consume
a second queue. The operator jobs API still accepts arbitrary PowerShell.

Code limits diagnostic attempts, repeated checks, errors, output and elapsed
time. The five-minute budget is checked between calls; an in-flight call can
extend it. Endpoint and user text is treated as untrusted data. Catalogue limits,
validated arguments and approval enforce the action boundary.

A proposed repair waits for a human decision. Approval binds the device,
proposal, rebuilt script and 15-minute expiry. The executor validates that
binding, rechecks the current condition, dispatches the repair through the job
API, and runs a verification diagnostic. These checks use ordinary code; the
model does not authorize or declare its own repair successful.

At server startup, interrupted read-only investigations can restart, pending
human decisions remain pending, and approved work resumes with its original
repair idempotency key. Unfinished raw jobs are marked failed instead of being
blindly rerun. Device connections and active-job coordination are process-local:
this version must run as one control-plane instance with one uvicorn worker.

## Inventory and operations

Inventory is collected on connection when stale, after a detected reboot, and
periodically while online. GET requests return the stored snapshot. Event-log
queries run live with validated filters; their output remains in job history.
Restart records track offline/return transitions, uptime-based boot confirmation,
and pending-reboot indicators before and after restart. Remote upgrades preserve
the device key; uninstall removes local files and credentials while retaining
server history.

## Next steps

- Bind first enrollment to an independently verified device-key fingerprint.
- Coordinate sockets and work across instances, with a shared broker and Postgres.
- Add scoped operator roles and device groups.
- Sign releases and dispatched jobs with keys protected separately from the server.
- Send audit records to external storage with tamper-evident chaining.
- Expand the diagnostic and repair catalogues through review and testing.

Supporting diagrams: [enrollment](images/enrollment.png),
[investigation](images/investigation.png), and [API/approval flow](images/api_flow.png).
These illustrate the main paths; the API reference documents error and no-action outcomes.
