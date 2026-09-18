# Threat model

An RMM is authorized remote code execution as SYSTEM. The main security goal is
therefore narrow: only authenticated operators may dispatch work, only the
intended enrolled device may receive it, and the result must correspond to the
script that was dispatched. Endpoint and model text is always untrusted.

## Assets and trust boundaries

The critical assets are fleet-wide operator API keys, each device's private
key, the ability to run PowerShell as `LocalSystem`, job results, and the audit
history. Job output may also contain endpoint data that is later sent to the
model provider.

| Boundary | Authentication and data crossing it |
|---|---|
| Operator → control plane | `X-API-Key` over HTTPS; requests may contain arbitrary PowerShell |
| New device → control plane | One-time enrollment token, then a registered public key |
| Enrolled device → control plane | Fresh signed WebSocket challenge and signed job results |
| Control plane → device | TLS plus a script and its SHA-256 |
| Endpoint/user text → model | Labelled, randomly delimited untrusted text |
| Model → action | Typed diagnostic/repair catalogues, budgets and human approval |

The control-plane host is trusted. A compromised endpoint is trusted only to
speak for that one device. The model is not trusted to authorize actions.

## Defenses in place

**Operator and transport security.** Operator keys are compared in constant
time and every mutation records the operator name. Caddy terminates public TLS;
the agent performs normal certificate validation. The CLI refuses to send an
operator key over plaintext unless explicitly enabled. The AI client permits
plaintext only for a parsed loopback hostname and refuses redirects, preventing
credential forwarding to a different host. Known secret formats and configured
secret values are removed from investigation errors and stored model-facing
text.

**Device identity and enrollment.** Each device generates a P-256 key. Its
private key is protected with Windows DPAPI in machine scope and stored in a
directory restricted to SYSTEM and Administrators. Every connection begins
with a fresh server challenge that the device must sign. The MachineGuid-based
device ID is only an identifier and is never accepted as proof.

Enrollment tokens are random, stored as hashes, expire after one hour and can
be redeemed only once. The installer removes the token after enrollment. An
ordinary token cannot replace an enrolled device's key; recovery requires a
token pinned to that device. Revoked devices cannot reconnect or re-enroll
until an operator restores them, and rejected attempts are audited.

**Execution and result integrity.** A job carries the SHA-256 of its exact
script. The agent checks that hash before starting PowerShell. It signs the job
ID, script hash, exit code, duration, and hashes of stdout and stderr. The
server verifies the signature, device/job relationship and original script
hash before accepting the result. It also type- and range-checks result fields
and enforces each stream's UTF-8 byte limit even if a faulty agent sends more.
The installer similarly checks the downloaded agent binary against the
published SHA-256.

**Untrusted data.** Hostname, OS and agent-version fields are length-bounded
and stripped of control characters. The dashboard inserts device, job and
model text as text or escaped HTML. Restart reasons and catalogue arguments
are accepted only through typed or character-whitelisted fields. These checks
keep endpoint text out of HTML and command syntax.

Before text reaches a model, the driver labels it untrusted and wraps it in a
random delimiter that the text cannot close. This reduces prompt-injection
risk; capability limits provide the security boundary. Diagnosis exposes only
six reviewed read-only checks, remediation exposes only four reviewed repairs,
the device is fixed for the investigation, and budgets cap time, attempts,
failures and output. The raw operator job API remains unrestricted by design.

A repair requires a human decision bound to the device, proposal, expiry and
hash of a script rebuilt from the catalogue. The executor rebuilds it again,
checks the binding, and rechecks the device condition immediately before
dispatch. Verification is another device diagnostic; the model does not
declare its own repair successful. Critical processes and the RMM agent cannot
be stopped through the repair catalogue.

**Reliability and revocation.** Offline devices are rejected immediately.
Timeouts at both ends and an offline supervisor move every accepted job to a
terminal state. When supplied, an idempotency key makes a repeated identical
dispatch return the original job and rejects reuse for a different request.
One serialized WebSocket sender prevents heartbeat and result frames from
interleaving. Revocation closes the socket and fails outstanding work.

## Deferred risks

| Gap | Why deferred and the next step |
|---|---|
| A compromised control plane can command the fleet | This is the central trusted host. Add agent-pinned job signing and quorum approval for high-risk work. |
| Operator keys are static and fleet-wide | The demo has one operator. Add SSO, short-lived scoped roles and device groups; replace dashboard `localStorage` with an HttpOnly session. |
| The audit log shares the SQLite database | An attacker controlling the server can alter it. Hash-chain records and stream them to external storage. |
| The binary hash comes from the same server | It detects corruption, not a malicious server. Authenticode-sign releases and verify the signer. |
| No rate limiting on enrollment or failed-key attempts | Tokens and keys have 256 bits of entropy. Add per-IP limits and alerts before production. |
| A captured unused enrollment token can enroll the first machine that redeems it | Single use and expiry make this short-lived and cause the intended install to fail loudly, but do not prevent it. Add pending enrollment: compare the device-key fingerprint through the trusted deployment channel before enabling jobs. |
| A lost enrollment response strands the agent | The device was registered but the token was consumed. Let a registered key confirm enrollment by signing a new challenge. |
| Cloned VMs share `MachineGuid` | A clone still lacks the enrolled private key. Detect duplicate IDs and optionally use a TPM-backed key. |
| Endpoint output is stored verbatim and may be sent to OpenAI | Exact output is useful for audit, while diagnostics avoid user files. Add view-time field redaction and use a provider under an appropriate data agreement. |
| Result signatures omit state and truncation flags | Those fields are validated and output is capped server-side. Version the signed payload and include both fields. |
| A model may still follow instructions in untrusted text | Fences only reduce the risk. Catalogue-only capabilities, a fixed device, human approval and visible raw evidence limit the effect. |

An attacker who already has SYSTEM on an endpoint can use that device's key,
but cannot derive another device's key or an operator key from it. Physical
attacks and package-registry supply-chain compromise are outside this project.
