"""Runs an investigation end to end, writing progress to durable storage.

This is the bridge between the control plane's HTTP routes and the driver
package (`investigator.py`, `remediation.py`), which was built and tested as a
standalone component talking to the control plane over its own public API.
That boundary is kept here too: the worker acts as just another operator,
authenticated with its own key, dispatching through the same
`/api/devices/{id}/jobs` route any other caller would use. Nothing here reaches
into job storage directly.

Route handlers only validate, record, and schedule; the actual investigate /
plan / apply work happens in a background asyncio task so an HTTP request never
blocks on a model call or a multi-step diagnosis.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from pathlib import Path

log = logging.getLogger("investigations")

# The driver package lives in a sibling directory and was built to run
# standalone (its own CLI, its own tests). Importing it here rather than
# duplicating it keeps one implementation of the safety-critical parts --
# the catalogue, the budget, approval binding -- for both the CLI and the
# dashboard.
_DRIVER_DIR = Path(os.environ.get("SQUASH_DRIVER_DIR",
                                  Path(__file__).resolve().parent.parent / "driver"))
if str(_DRIVER_DIR) not in sys.path:
    sys.path.insert(0, str(_DRIVER_DIR))

try:
    import model as model_module
    import remediation
    from investigator import Investigator
    from remediation import Applier, Approval, Decision, Planner, Proposal
    from rmm import RmmClient
    DRIVER_AVAILABLE = True
    _import_error = ""
except ImportError as error:  # pragma: no cover - exercised only when misdeployed
    DRIVER_AVAILABLE = False
    _import_error = str(error)
    log.error("AI driver not available (SQUASH_DRIVER_DIR=%s): %s", _DRIVER_DIR, error)

APPROVAL_TTL_SECONDS = (remediation.APPROVAL_TTL_SECONDS
                        if DRIVER_AVAILABLE else 900.0)

store = None  # set by main.py at startup, avoiding a circular import
_tasks: dict[tuple[str, str], asyncio.Task] = {}


def configure(the_store) -> None:
    global store
    store = the_store


class DriverUnavailable(RuntimeError):
    pass


def _schedule(kind: str, investigation_id: str) -> bool:
    """Schedules one in-process runner per investigation and phase.

    Durable state is still the source of truth. This registry only prevents two
    identical HTTP requests in this process from racing the same work.
    """
    key = (kind, investigation_id)
    existing = _tasks.get(key)
    if existing is not None and not existing.done():
        return False
    coroutine = start(investigation_id) if kind == "start" else apply(investigation_id)
    task = asyncio.create_task(coroutine)
    _tasks[key] = task

    def finished(done: asyncio.Task) -> None:
        if _tasks.get(key) is done:
            _tasks.pop(key, None)

    task.add_done_callback(finished)
    return True


def schedule_start(investigation_id: str) -> bool:
    return _schedule("start", investigation_id)


def schedule_apply(investigation_id: str) -> bool:
    return _schedule("apply", investigation_id)


def recover() -> list[tuple[str, str]]:
    """Called once at application startup to resume durable work."""
    work = store.recover_investigations()
    for investigation_id, kind in work:
        _schedule(kind, investigation_id)
    return work


def _client() -> "RmmClient":
    if not DRIVER_AVAILABLE:
        raise DriverUnavailable(f"AI driver is not deployed on this control plane: {_import_error}")
    base = os.environ.get("SQUASH_SELF_URL", "http://127.0.0.1:5200")
    key = os.environ.get("SQUASH_DRIVER_KEY")
    if not key:
        raise DriverUnavailable("SQUASH_DRIVER_KEY is not configured")
    return RmmClient(base, key)


def _env_file() -> Path:
    """`.env` sits at the repository root, while the server runs from `server/`.
    Resolving it relative to this file rather than the working directory keeps
    local runs working regardless of where uvicorn was started."""
    configured = os.environ.get("SQUASH_ENV_FILE")
    return Path(configured) if configured else Path(__file__).resolve().parent.parent / ".env"


def _model():
    if not DRIVER_AVAILABLE:
        raise DriverUnavailable(f"AI driver is not deployed on this control plane: {_import_error}")
    model_module.load_dotenv(str(_env_file()))
    try:
        return model_module.from_environment()
    except model_module.ModelError as error:
        # A missing or rejected model credential is a configuration problem, not
        # a crash. Reported as such so the operator sees the cause instead of
        # "failed unexpectedly".
        raise DriverUnavailable(f"model is not configured: {error}") from None


# ---------------------------------------------------------------- scheduling

async def start(investigation_id: str) -> None:
    """Runs diagnosis and planning. Scheduled right after an investigation is
    durably created; never awaited by the request that created it."""
    try:
        await asyncio.to_thread(_run_diagnosis_and_planning, investigation_id)
    except Exception as error:  # a crash here must still leave a terminal state
        log.exception("investigation %s failed", investigation_id)
        store.set_investigation_error(
            investigation_id, "Investigation failed unexpectedly. Check the control-plane logs.")
        store.set_investigation_status(investigation_id, "failed")


async def apply(investigation_id: str) -> None:
    """Runs the approved repair. Scheduled after a decision is durably
    recorded as 'approve'; the HTTP handler has already returned by then."""
    try:
        await asyncio.to_thread(_run_apply, investigation_id)
    except Exception as error:
        log.exception("applying decision for %s failed", investigation_id)
        store.set_investigation_error(
            investigation_id, "Applying the repair failed unexpectedly. Check the control-plane logs.")
        store.set_investigation_status(investigation_id, "failed")


# ---------------------------------------------------------------- diagnosis

def _run_diagnosis_and_planning(investigation_id: str) -> None:
    inv = store.get_investigation(investigation_id)
    if inv is None or not store.claim_queued_investigation(investigation_id):
        return
    device = store.get_device(inv["device_id"])
    if device is None:
        store.set_investigation_error(investigation_id, "device is no longer enrolled")
        store.set_investigation_status(investigation_id, "failed")
        return

    client = _client()

    def on_progress(event: str, detail: dict) -> None:
        message = _describe(event, detail)
        if message:
            store.append_investigation_event(investigation_id, message)

    try:
        llm = _model()
    except DriverUnavailable as error:
        store.set_investigation_error(investigation_id, str(error))
        store.set_investigation_status(investigation_id, "failed")
        return

    investigation = Investigator(client, llm, on_progress=on_progress).investigate(
        device["device_id"], device["hostname"], inv["problem"])

    for step in investigation.steps:
        store.insert_investigation_evidence(
            investigation_id, step.diagnostic, step.arguments, step.ok, step.data,
            None if step.ok else step.detail)

    if not investigation.concluded:
        store.set_investigation_error(
            investigation_id,
            investigation.stopped_because or "the investigation did not reach a conclusion")
        store.set_investigation_status(investigation_id, "failed")
        return

    finding, confidence = _parse_finding(investigation.finding)
    store.set_investigation_finding(investigation_id, finding, confidence)

    store.set_investigation_status(investigation_id, "planning")
    store.append_investigation_event(investigation_id, "Reviewing the evidence for a possible fix.")

    try:
        planner_model = _model()
    except DriverUnavailable:
        planner_model = llm

    proposal = Planner(planner_model).propose(
        investigation_id, device["device_id"], device["hostname"],
        investigation.finding, investigation.evidence())

    _store_proposal(investigation_id, device["device_id"], proposal)

    if proposal.decision is Decision.PROPOSED:
        store.set_investigation_status(investigation_id, "awaiting_approval")
        args = ", ".join(f"{k}={v}" for k, v in proposal.arguments.items())
        store.append_investigation_event(
            investigation_id,
            f"Proposed fix: {proposal.repair}({args}). Waiting for operator approval.")
    else:
        store.set_investigation_status(investigation_id, "completed")
        reason = proposal.reasoning or proposal.refusal_reason or "No automated fix applies here."
        store.append_investigation_event(investigation_id, f"No repair proposed: {reason}")


def _store_proposal(investigation_id: str, device_id: str, proposal: "Proposal") -> None:
    expires_at = time.time() + APPROVAL_TTL_SECONDS if proposal.actionable else None
    proposal_hash = _compute_proposal_hash(investigation_id, device_id, proposal, expires_at)
    store.create_proposal(
        proposal.proposal_id, investigation_id,
        decision=proposal.decision.value, repair=proposal.repair,
        arguments=proposal.arguments, script=proposal.script,
        script_sha256=proposal.script_sha256, reasoning=proposal.reasoning,
        expected_effect=proposal.expected_effect, risk=proposal.risk,
        verified_by=proposal.verification_describes, refusal_reason=proposal.refusal_reason,
        proposal_hash=proposal_hash, expires_at=expires_at)


def _compute_proposal_hash(investigation_id: str, device_id: str, proposal: "Proposal",
                           expires_at: float | None) -> str:
    """A binding the UI carries back unexamined on a decision, covering every
    field a human saw when deciding: investigation, device, proposal identity,
    the repair and its arguments, the exact script and its own hash, expiry,
    and the reviewed impact and verification text. Any of those changing
    invalidates the binding.

    This is a separate, coarser check than remediation.authorize()'s hash,
    which rebuilds the script from the catalogue at execution time and is what
    actually determines what may run. This one only decides whether the
    decision the operator is submitting still matches what they were shown.
    """
    payload = {
        "investigationId": investigation_id, "deviceId": device_id,
        "proposalId": proposal.proposal_id, "decision": proposal.decision.value,
        "repair": proposal.repair,
        "arguments": proposal.arguments, "script": proposal.script,
        "scriptSha256": proposal.script_sha256, "expiresAt": expires_at,
        "risk": proposal.risk, "verifiedBy": proposal.verification_describes,
        "expectedEffect": proposal.expected_effect, "reasoning": proposal.reasoning,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def proposal_hash_matches(investigation_id: str, device_id: str, row: dict) -> bool:
    """Recomputes the browser-visible binding from durable fields.

    Comparing the browser value only with a stored digest would allow a server
    bug to alter both the displayed proposal and the eventual action without
    invalidating approval. The executor independently rebuilds the script from
    the reviewed repair catalogue as the final boundary.
    """
    try:
        proposal = _proposal_from_row(investigation_id, device_id, "", row)
        expected = _compute_proposal_hash(
            investigation_id, device_id, proposal, row["expires_at"])
        return expected == row["proposal_hash"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


_FINDING_RE = re.compile(r"FINDING:\s*(.*?)(?=\n[A-Z][A-Z ]*:|\Z)", re.S)
_CONFIDENCE_RE = re.compile(r"CONFIDENCE:\s*(\w+)", re.I)


def _parse_finding(text: str) -> tuple[str, str | None]:
    finding_match = _FINDING_RE.search(text)
    confidence_match = _CONFIDENCE_RE.search(text)
    finding = finding_match.group(1).strip() if finding_match else text.strip()
    confidence = confidence_match.group(1).lower() if confidence_match else None
    return finding, confidence


# ---------------------------------------------------------------- applying

def _run_apply(investigation_id: str) -> None:
    inv = store.get_investigation(investigation_id)
    if inv is None or inv["status"] not in ("applying", "verifying"):
        return
    proposal_row = store.get_current_proposal(investigation_id)
    device = store.get_device(inv["device_id"])
    if (device is None or proposal_row is None
            or proposal_row["decision_outcome"] != "approve"
            or proposal_row["decided_at"] is None):
        store.set_investigation_error(investigation_id, "missing device or proposal at apply time")
        store.set_investigation_status(investigation_id, "failed")
        return

    client = _client()
    proposal = _proposal_from_row(investigation_id, device["device_id"], device["hostname"],
                                  proposal_row)
    approval = Approval(
        proposal_id=proposal.proposal_id, script_sha256=proposal.script_sha256,
        approved_by=proposal_row["decided_by"], device_id=proposal.device_id,
        repair=proposal.repair, arguments=proposal.arguments,
        approved_at=proposal_row["decided_at"])

    def on_progress(event: str, detail: dict) -> None:
        if event == "verifying":
            store.set_investigation_status(investigation_id, "verifying")
        message = _describe(event, detail)
        if message:
            store.append_investigation_event(investigation_id, message)

    outcome = Applier(client, on_progress=on_progress).apply(proposal, approval)

    store.set_investigation_outcome(investigation_id, {
        "applied": outcome.applied, "resolved": outcome.resolved,
        "detail": outcome.detail, "jobId": outcome.job_id,
    })
    store.append_investigation_event(investigation_id, outcome.detail)

    if not outcome.applied:
        store.set_investigation_error(investigation_id, outcome.detail)
        store.set_investigation_status(investigation_id, "failed")
    elif outcome.resolved is True:
        store.set_investigation_status(investigation_id, "resolved")
    else:
        # False (ran but did not help) and None (could not confirm) both need
        # a human to look again; neither is the same as resolved.
        store.set_investigation_status(investigation_id, "unresolved")


def _proposal_from_row(investigation_id: str, device_id: str, hostname: str, row: dict) -> "Proposal":
    return Proposal(
        investigation_id=investigation_id, device_id=device_id, hostname=hostname,
        decision=Decision(row["decision"]), repair=row["repair"],
        arguments=json.loads(row["arguments"] or "{}"), script=row["script"],
        script_sha256=row["script_sha256"], reasoning=row["reasoning"] or "",
        expected_effect=row["expected_effect"] or "", risk=row["risk"] or "",
        verification_describes=row["verified_by"] or "",
        refusal_reason=row["refusal_reason"] or "", proposal_id=row["proposal_id"],
        created_at=row["created_at"])


# ---------------------------------------------------------------- progress text

def _describe(event: str, detail: dict) -> str | None:
    """Turns an internal progress event into the operator-facing sentence
    shown in the timeline. Concise and factual -- what ran, what it found out,
    what's next -- never the model's reasoning."""
    if event == "started":
        return f"Started diagnosis for {detail.get('device', 'the device')}."
    if event == "collecting":
        args = detail.get("arguments") or {}
        suffix = f" ({', '.join(f'{k}={v}' for k, v in args.items())})" if args else ""
        return f"Checking {detail.get('diagnostic')}{suffix}."
    if event == "collected":
        ok = detail.get("ok")
        ms = detail.get("durationMs")
        return (f"{detail.get('diagnostic')} check completed in {ms}ms." if ok
                else f"{detail.get('diagnostic')} check did not complete.")
    if event == "refused":
        return f"Refused a request that was outside what is allowed: {detail.get('reason')}"
    if event == "analyzing":
        return None  # internal only; the next "collecting"/"finished" event says more
    if event == "finished":
        return None  # the caller emits a specific finding/no-repair message instead
    if event == "applying":
        repair = detail.get("repair")
        return f"Applying the approved fix: {repair}." if repair else "Applying the approved fix."
    if event == "verifying":
        return f"Verifying: {detail.get('check')}."
    return None
