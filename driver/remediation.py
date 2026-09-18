"""Proposing, approving and applying a repair.

The planner is a single model call, not a loop: once repairs come from a
catalogue, choosing one is one decision with no intermediate state to iterate
over. Everything after it -- approval, the precondition recheck, dispatch, and
deciding whether the problem is gone -- is ordinary code, because none of those
should depend on a model's judgement.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

import repairs
from diagnostics import ArgumentError
from model import Model
from rmm import DeviceUnavailable, RmmClient, RmmError

APPROVAL_TTL_SECONDS = 900.0

PLANNER_PROMPT = """\
You choose a repair for a diagnosed fault on a Windows endpoint.

You are given the investigation's finding and the evidence it was drawn from.
Read the evidence, not only the finding: if they disagree, trust the evidence
and propose nothing.

You may only choose from the repairs listed. You cannot write scripts, and you
cannot act -- a human reviews and approves whatever you propose.

Propose a repair only when the evidence shows the condition it addresses.
Proposing nothing is correct and common: most findings do not have a safe
automated remedy, and a repair that does not match the evidence is worse than
none.

Reply with JSON only:
{"repair": "<name or null>", "arguments": {...}, "reasoning": "<why this, from the evidence>",
 "expected_effect": "<what should change>"}
"""


class Decision(str, Enum):
    PROPOSED = "proposed"
    NO_ACTION = "no_action"
    REFUSED = "refused"


@dataclass
class Proposal:
    """A specific action, on a specific device, bound to a specific script."""
    investigation_id: str
    device_id: str
    hostname: str
    decision: Decision
    repair: str | None = None
    arguments: dict = field(default_factory=dict)
    script: str | None = None
    script_sha256: str | None = None
    reasoning: str = ""
    expected_effect: str = ""
    risk: str = ""
    verification_describes: str = ""
    refusal_reason: str = ""
    proposal_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)

    @property
    def actionable(self) -> bool:
        return self.decision is Decision.PROPOSED and bool(self.script_sha256)

    def view(self) -> dict:
        return {
            "proposalId": self.proposal_id,
            "investigationId": self.investigation_id,
            "device": self.hostname,
            "decision": self.decision.value,
            "repair": self.repair,
            "arguments": self.arguments,
            "script": self.script,
            "scriptSha256": self.script_sha256,
            "reasoning": self.reasoning,
            "expectedEffect": self.expected_effect,
            "risk": self.risk,
            "verifiedBy": self.verification_describes,
            "refusalReason": self.refusal_reason,
        }


@dataclass
class Approval:
    proposal_id: str
    script_sha256: str
    approved_by: str
    approved_at: float = field(default_factory=time.time)

    def matches(self, proposal: Proposal) -> tuple[bool, str]:
        """An approval authorises one action. Anything that differs from what
        was shown to the human is not that action."""
        if self.proposal_id != proposal.proposal_id:
            return False, "approval is for a different proposal"
        if self.script_sha256 != proposal.script_sha256:
            return False, "the proposed script changed after it was approved"
        if time.time() - self.approved_at > APPROVAL_TTL_SECONDS:
            return False, "approval has expired; the machine's state may have moved on"
        return True, "ok"


@dataclass
class Outcome:
    applied: bool
    resolved: bool | None
    detail: str
    job_id: str | None = None
    exit_code: int | None = None
    before: bool | None = None
    after: bool | None = None

    def view(self) -> dict:
        return {"applied": self.applied, "resolved": self.resolved, "detail": self.detail,
                "jobId": self.job_id, "exitCode": self.exit_code,
                "conditionBefore": self.before, "conditionAfter": self.after}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def repair_definitions() -> list[dict]:
    return [{"name": name, "summary": r.summary,
             "parameters": sorted(r.parameters),
             "appliesWhen": r.precondition.describes,
             "verifiedBy": r.verification.describes,
             "risk": r.risk}
            for name, r in sorted(repairs.CATALOG.items())]


class Planner:
    """Maps a finding plus its evidence onto at most one catalogue repair."""

    def __init__(self, model: Model) -> None:
        self._model = model

    def propose(self, investigation_id: str, device_id: str, hostname: str,
                finding: str, evidence: list[dict]) -> Proposal:
        payload = {
            "finding": finding,
            "evidence": evidence,
            "availableRepairs": repair_definitions(),
        }
        messages = [
            {"role": "system", "content": PLANNER_PROMPT},
            {"role": "user", "content": json.dumps(payload, indent=2)[:20_000]},
        ]

        base = {"investigation_id": investigation_id, "device_id": device_id,
                "hostname": hostname}
        try:
            reply = self._model.respond(messages, [])
        except Exception as error:
            return Proposal(**base, decision=Decision.REFUSED,
                            refusal_reason=f"planner unavailable: {error}")

        choice = _parse_choice(reply.text)
        if choice is None:
            return Proposal(**base, decision=Decision.REFUSED,
                            refusal_reason="planner did not return usable JSON")

        name = choice.get("repair")
        reasoning = str(choice.get("reasoning", ""))[:2000]
        expected = str(choice.get("expected_effect", ""))[:1000]

        if not name:
            return Proposal(**base, decision=Decision.NO_ACTION, reasoning=reasoning)

        try:
            repair = repairs.get(str(name))
            arguments = repair.validate(choice.get("arguments") or {})
            script = repair.build(arguments)
        except ArgumentError as error:
            return Proposal(**base, decision=Decision.REFUSED, reasoning=reasoning,
                            refusal_reason=str(error))

        return Proposal(**base, decision=Decision.PROPOSED, repair=repair.name,
                        arguments=arguments, script=script,
                        script_sha256=sha256_hex(script), reasoning=reasoning,
                        expected_effect=expected, risk=repair.risk,
                        verification_describes=repair.verification.describes)


class Applier:
    """Applies an approved proposal. No model is involved past this point."""

    def __init__(self, client: RmmClient, on_progress=None) -> None:
        self._client = client
        self._on_progress = on_progress or (lambda event, detail: None)

    def apply(self, proposal: Proposal, approval: Approval | None) -> Outcome:
        if not proposal.actionable:
            return Outcome(False, None, f"nothing to apply: {proposal.decision.value}")

        if approval is None:
            return Outcome(False, None, "refused: no approval")

        ok, reason = approval.matches(proposal)
        if not ok:
            self._progress("refused", {"reason": reason})
            return Outcome(False, None, f"refused: {reason}")

        repair = repairs.get(proposal.repair)

        # The machine may have moved on while a human was deciding.
        before = self._evaluate(proposal, repair.precondition)
        if before is None:
            return Outcome(False, None, "refused: could not confirm current state")
        if not before:
            self._progress("refused", {"reason": "condition no longer holds"})
            return Outcome(False, None,
                           f"refused: {repair.precondition.describes} is no longer true",
                           before=False)

        self._progress("applying", {"repair": proposal.repair,
                                    "arguments": proposal.arguments})
        try:
            job = self._client.run_raw(
                proposal.device_id, proposal.script,
                timeout_seconds=repair.timeout_seconds,
                idempotency_key=f"repair-{proposal.proposal_id}")
        except (RmmError, DeviceUnavailable) as error:
            return Outcome(False, None, f"dispatch failed: {error}", before=True)

        if job["state"] != "Completed" or job.get("exitCode") != 0:
            return Outcome(True, False,
                           f"the repair did not complete cleanly: {job['state']}"
                           + (f", exit {job.get('exitCode')}" if job.get("exitCode") else ""),
                           job_id=job.get("jobId"), exit_code=job.get("exitCode"),
                           before=True)

        # Exiting zero means the command ran. Whether the problem is gone is a
        # separate question, and only the verification predicate answers it.
        self._progress("verifying", {"check": repair.verification.describes})
        after = self._evaluate(proposal, repair.verification)
        if after is None:
            return Outcome(True, None, "the repair ran, but its effect could not be verified",
                           job_id=job.get("jobId"), exit_code=0, before=True)

        detail = (f"{repair.verification.describes}" if after
                  else f"the repair ran but {repair.verification.describes} is still not true")
        return Outcome(True, after, detail, job_id=job.get("jobId"), exit_code=0,
                       before=True, after=after)

    def _evaluate(self, proposal: Proposal, check) -> bool | None:
        """Runs a check and applies its predicate. None means the check itself
        could not be completed, which is not the same as the condition being
        false and must not be treated as one."""
        try:
            result = self._client.run_diagnostic(
                proposal.device_id, check.diagnostic, check.arguments(proposal.arguments))
        except (RmmError, DeviceUnavailable, ArgumentError):
            return None
        if not result.succeeded or result.data is None:
            return None
        return check.evaluate(result.data)

    def _progress(self, event: str, detail: dict) -> None:
        try:
            self._on_progress(event, detail)
        except Exception:
            pass


def _parse_choice(text: str) -> dict | None:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text.strip("`")
        text = text.removeprefix("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
