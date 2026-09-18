# Diagnosis and remediation

How the AI worker gets from a reported problem to a repair, and what stops it
doing anything it shouldn't along the way.

## The shape

```
Diagnosis agent     read-only diagnostics, iterative      → finding + evidence
        │  handoff record, one investigation id
        ▼
Repair planner      repair catalogue, single call         → proposal
        │
        ▼
Application code    approval, precondition recheck, dispatch
        │
        ▼
Control plane       executes, attests, audits
        │
        ▼
Verification        runs the repair's own predicate       → resolved / not resolved
```

Everything between the two model calls is ordinary code. Neither model can
authorise an action, dispatch one, or decide whether it worked.

## Why diagnosis and remediation are separated

Not for debuggability. A single agent writing each phase to one investigation
record would be just as traceable, and the record is what makes failures
legible either way.

The reason is **capability separation**. The diagnosis agent is the component
that reads endpoint output, which on a compromised or faulty machine is
attacker-influenced text. It is never given repair tools, so no amount of
injected instruction can cause it to propose or perform one — the capability is
absent, not merely discouraged. This is the read-only/mutating split applied at
the agent level, and it is enforced by what is in each component's tool list
rather than by what its prompt asks of it.

## Why the planner is not an agent

Once repairs come from a reviewed catalogue, proposing one is a single decision:
given this finding and these N repairs, which one, with what parameters, or
none. There is nothing to iterate on. Modelling it as an investigate-act-observe
loop would add failure modes and buy nothing, so it is one structured call with
a constrained output.

The planner receives the **evidence**, not only the prose finding. Given just
"the Spooler service is stopped" it cannot notice that the evidence actually
showed it running and the diagnosis misread it. Passing the evidence keeps a bad
diagnosis from compounding into a bad repair.

## Repairs carry their own verification

A repair is not a script. It is a script plus the conditions that make it
applicable and the check that decides whether it worked:

```
restart_service(name)
  precondition   service_status(name).status != "Running"
  script         Start-Service -Name <name>
  verification   service_status(name).status == "Running"
  risk           the service is briefly unavailable
```

Two consequences.

**Success is not the exit code.** A command exiting zero means it ran. Whether
the problem is gone is a separate question, answered by re-running the
verification predicate and comparing. The failure mode of "repair succeeded,
symptoms remain" is then mechanical rather than a matter of the model's opinion.

**Preconditions are rechecked immediately before execution**, not only when the
proposal is made. State changes while a human is deciding: a process exits, a
service is started by someone else, a disk is cleared. A proposal that was
appropriate ten minutes ago may no longer be, and executing it anyway is how
automation causes incidents.

## Approval

An approval authorises one action, on one device, in one investigation. It is
bound to the SHA-256 of the exact script — the same hash the control plane
already computes for result attestation — so a proposal that changes in any way
after approval no longer matches, and dispatch is refused.

Approval is recorded with who granted it and when, and expires: an approval that
has been sitting unused is evidence about a machine's state that has since gone
stale.

Neither model can approve anything, and no endpoint output can constitute an
approval however it is phrased.

## The handoff record

One investigation id spans evidence, diagnosis, proposal, approval, dispatch,
execution result and verification. Each phase is written as it completes.

This is what makes a failure attributable to a component: whether the diagnosis
did not match the evidence, the proposal did not match the diagnosis, the
approval did not match the proposal, or the repair ran and did not help. Without
it, "the AI broke something" is unfalsifiable.

Job ids from the control plane are recorded at each dispatch, so the record
joins to the control plane's own audit trail, and idempotency keys are stable
across retries so a lost response cannot become a second repair.

## What is decided in code, not by a model

| Decision | Decided by |
|---|---|
| Which machine anything runs on | The investigation, fixed at creation |
| Whether a diagnostic may run | Catalogue membership and argument validation |
| Whether a repair may be proposed | Catalogue membership |
| Whether a repair may execute | Human approval, bound to the script hash |
| Whether conditions still hold | Precondition predicate, rechecked before dispatch |
| Whether the problem is resolved | Verification predicate, compared before and after |
| When to stop investigating | Budget: checks, time, output, repeats |

A model chooses which diagnostic to run next, what the evidence means, and which
repair to propose. Everything else is arithmetic.

## Failure modes this is built to handle

- **Device goes offline mid-investigation** — the check returns unreachable, is
  reported as such, and no conclusion is drawn from data that was not collected.
- **Injected instructions in endpoint output** — cannot widen capability;
  diagnosis has no repair tools and repairs come from a catalogue.
- **Model proposes something not in the catalogue** — refused before dispatch and
  returned as an observation.
- **Approval arrives for a stale proposal** — hash mismatch, refused.
- **State changed while awaiting approval** — precondition recheck fails, refused.
- **Repair runs but does not help** — verification predicate says so; the
  investigation ends as not resolved rather than closed.
- **Worker restarts mid-flight** — the record holds the job id; the result is
  retrieved rather than the repair re-dispatched.
- **Model unavailable or looping** — budgets end the investigation with what
  evidence exists.

## Deliberately not built

Arbitrary repair scripts. A model writing PowerShell that a human approves puts
the entire weight of safety on that human reading it correctly, every time,
under time pressure. A catalogue bounds the worst case to "the wrong reviewed
repair ran on the right machine". Widening it is a decision to make with
evidence from operation, not at the outset.
