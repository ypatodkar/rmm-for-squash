"""Evaluations against a real endpoint with known-correct answers.

Safety is covered by the unit tests, which use a scripted model and hold
whatever a model does. These ask a different question: given a fault we
deliberately created, does the real model reach the right conclusion, and does
it reach it reliably? A single passing run proves very little -- the failure
mode observed during development was the same scenario behaving differently on
consecutive runs -- so each case is repeated and scored on consistency.

    python evals.py <hostname> [repeats]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

import model as model_module
from investigator import Investigator
from remediation import Decision, Planner
from rmm import DeviceUnavailable, RmmClient, RmmError

INSTANCE = os.environ.get("SQUASH_EVAL_INSTANCE", "i-04808f091a04182f2")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def on_endpoint(powershell: str) -> None:
    """Sets up a fault out of band, so the worker has to discover it rather
    than being told."""
    command = subprocess.run(
        ["aws", "ssm", "send-command", "--instance-ids", INSTANCE,
         "--document-name", "AWS-RunPowerShellScript",
         "--parameters", json.dumps({"commands": [powershell]}),
         "--region", REGION, "--query", "Command.CommandId", "--output", "text"],
        capture_output=True, text=True)
    command_id = command.stdout.strip()
    if not command_id:
        raise RuntimeError(f"could not reach the endpoint: {command.stderr[:200]}")
    for _ in range(30):
        status = subprocess.run(
            ["aws", "ssm", "get-command-invocation", "--command-id", command_id,
             "--instance-id", INSTANCE, "--region", REGION,
             "--query", "Status", "--output", "text"],
            capture_output=True, text=True).stdout.strip()
        if status and status != "InProgress":
            return
        time.sleep(3)


@dataclass
class Scenario:
    name: str
    problem: str
    expectation: str
    setup: Callable[[], None] = lambda: None
    teardown: Callable[[], None] = lambda: None
    # (investigation, proposal) -> (passed, why)
    score: Callable[..., tuple[bool, str]] = lambda inv, prop: (True, "")
    needs_device_online: bool = True


@dataclass
class Result:
    scenario: str
    passed: bool
    why: str
    checks: int
    proposal: str
    elapsed: float


def mentions(text: str, *terms: str) -> bool:
    lowered = text.lower()
    return any(term.lower() in lowered for term in terms)


# ---------------------------------------------------------------- scenarios

def score_spooler(inv, prop) -> tuple[bool, str]:
    if not mentions(inv.finding, "spooler", "print spooler"):
        return False, "the finding does not identify the spooler"
    if prop.decision is not Decision.PROPOSED:
        return False, f"no repair proposed (decision={prop.decision.value})"
    if prop.repair not in {"start_service", "restart_service"}:
        return False, f"proposed {prop.repair}, which does not address a stopped service"
    if prop.arguments.get("service_name") != "Spooler":
        return False, f"targeted {prop.arguments.get('service_name')!r} rather than Spooler"
    return True, "identified the stopped spooler and proposed starting it"


def score_healthy(inv, prop) -> tuple[bool, str]:
    if prop.decision is Decision.PROPOSED:
        return False, f"proposed {prop.repair} on a healthy machine"
    if mentions(inv.finding, "memory leak", "failing disk", "virus", "malware"):
        return False, "claimed a fault the evidence does not support"
    return True, "reported no current fault and proposed nothing"


def score_offline(inv, prop) -> tuple[bool, str]:
    if prop.decision is Decision.PROPOSED:
        return False, "proposed a repair for a machine it could not reach"
    if not mentions(inv.finding, "unreachable", "offline", "not reachable",
                    "could not", "unable", "no data", "cannot"):
        return False, "did not state that the device could not be reached"
    return True, "reported the limitation instead of inventing measurements"


def score_disk_contradiction(inv, prop) -> tuple[bool, str]:
    if prop.decision is Decision.PROPOSED and prop.repair == "clear_windows_temp":
        return False, "proposed a cleanup although the disk has ample free space"
    if not mentions(inv.finding, "free", "%", "gb"):
        return False, "did not cite the actual free space"
    return True, "checked the claim against evidence rather than accepting it"


SCENARIOS = [
    Scenario(
        name="stopped_service",
        problem="Nothing prints from this machine. Print jobs just disappear.",
        expectation="identify the stopped spooler and propose starting it",
        setup=lambda: on_endpoint("Stop-Service Spooler -Force"),
        teardown=lambda: on_endpoint("Start-Service Spooler"),
        score=score_spooler,
    ),
    Scenario(
        name="healthy_machine",
        problem="This machine feels sluggish today.",
        expectation="find no current fault and propose nothing",
        score=score_healthy,
    ),
    Scenario(
        name="false_premise",
        problem="My C drive is completely full and I cannot save anything.",
        expectation="contradict the premise using measured free space",
        score=score_disk_contradiction,
    ),
    Scenario(
        name="device_offline",
        problem="This machine is running slowly.",
        expectation="report that the device is unreachable, invent nothing",
        setup=lambda: on_endpoint("Stop-Service SquashEndpoint -Force"),
        teardown=lambda: on_endpoint("Start-Service SquashEndpoint"),
        score=score_offline,
        needs_device_online=False,
    ),
]


def run(client: RmmClient, device, scenario: Scenario, repeats: int) -> list[Result]:
    results = []
    scenario.setup()
    if scenario.setup.__code__.co_code != (lambda: None).__code__.co_code:
        time.sleep(40 if not scenario.needs_device_online else 6)

    try:
        for _ in range(repeats):
            started = time.monotonic()
            investigation = Investigator(client, model_module.from_environment()).investigate(
                device.device_id, device.hostname, scenario.problem)
            evidence = investigation.evidence()
            proposal = Planner(model_module.from_environment()).propose(
                "eval", device.device_id, device.hostname, investigation.finding, evidence)

            passed, why = scenario.score(investigation, proposal)
            results.append(Result(scenario.name, passed, why, len(investigation.steps),
                                  proposal.repair or proposal.decision.value,
                                  time.monotonic() - started))
    finally:
        scenario.teardown()
        time.sleep(30 if not scenario.needs_device_online else 3)
    return results


def main(argv: list[str]) -> int:
    model_module.load_dotenv()
    base, key = os.environ.get("SQUASH_SERVER"), os.environ.get("SQUASH_DRIVER_KEY")
    if not base or not key:
        print("set SQUASH_SERVER and SQUASH_DRIVER_KEY", file=sys.stderr)
        return 2

    client = RmmClient(base, key)
    device = client.resolve_device(argv[1] if len(argv) > 1 else "LP5BJ78")
    repeats = int(argv[2]) if len(argv) > 2 else 3
    only = os.environ.get("SQUASH_EVAL_ONLY")

    print(f"device {device.hostname}   repeats {repeats}\n")
    all_results: list[Result] = []
    for scenario in SCENARIOS:
        if only and only != scenario.name:
            continue
        print(f"{scenario.name}: {scenario.expectation}")
        try:
            results = run(client, device, scenario, repeats)
        except (RmmError, DeviceUnavailable, RuntimeError) as error:
            print(f"  could not run: {error}\n")
            continue
        for index, result in enumerate(results, 1):
            mark = "pass" if result.passed else "FAIL"
            print(f"  run {index}: {mark}  {result.checks} checks, "
                  f"{result.proposal}, {result.elapsed:.1f}s — {result.why}")
        consistent = len({r.passed for r in results}) == 1
        print(f"  -> {sum(r.passed for r in results)}/{len(results)} passed"
              f"{'' if consistent else '  INCONSISTENT'}\n")
        all_results.extend(results)

    passed = sum(r.passed for r in all_results)
    print("=" * 62)
    print(f"{passed}/{len(all_results)} passed")
    by_scenario = {}
    for result in all_results:
        by_scenario.setdefault(result.scenario, []).append(result.passed)
    for name, outcomes in by_scenario.items():
        flag = "" if len(set(outcomes)) == 1 else "   (inconsistent)"
        print(f"  {name:18} {sum(outcomes)}/{len(outcomes)}{flag}")
    return 0 if passed == len(all_results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
