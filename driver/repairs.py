"""Repairs the worker is permitted to propose.

A repair is not a script. It is a script together with the condition that makes
it applicable and the check that decides whether it worked, because those are
three different questions and a command exiting zero only answers the first.

Every repair here changes the endpoint, so none may run without human approval.
The catalogue exists so that the worst case of a confused or manipulated model
is the wrong reviewed repair on the right machine, rather than arbitrary code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from diagnostics import ArgumentError, windows_name


@dataclass(frozen=True)
class Check:
    """A diagnostic to run, and a predicate over its parsed output.

    Used for both preconditions and verification, so 'is this repair
    applicable' and 'did it work' are answered the same way and neither
    depends on a model's opinion.

    The predicate receives the repair's own arguments as well as the output,
    because some conditions are only meaningful relative to them -- whether a
    particular process is still running, rather than whether any process is.
    """
    diagnostic: str
    arguments: Callable[[dict], dict]
    predicate: Callable[[object, dict], bool]
    describes: str

    def evaluate(self, data: object, arguments: dict | None = None) -> bool:
        try:
            return bool(self.predicate(data, arguments or {}))
        except (TypeError, KeyError, AttributeError, IndexError):
            # Absent or unexpected output is not evidence that a condition
            # holds. Treating it as satisfied would let a failed check
            # authorise a repair, or declare a problem fixed.
            return False


@dataclass(frozen=True)
class Repair:
    name: str
    summary: str
    script: str
    parameters: dict[str, Callable[[object], object]]
    precondition: Check
    verification: Check
    risk: str
    timeout_seconds: int = 60

    def validate(self, arguments: dict | None = None) -> dict:
        if arguments is None:
            arguments = {}
        # Arguments arrive from model-generated JSON, so the container's type is
        # itself untrusted: a bare number here would otherwise raise rather than
        # producing a refusal the workflow can report.
        if not isinstance(arguments, dict):
            raise ArgumentError(f"{self.name}: arguments must be an object, "
                                f"got {type(arguments).__name__}")
        unexpected = set(arguments) - set(self.parameters)
        if unexpected:
            raise ArgumentError(f"unknown argument(s): {', '.join(sorted(unexpected))}")
        missing = set(self.parameters) - set(arguments)
        if missing:
            raise ArgumentError(f"missing argument(s): {', '.join(sorted(missing))}")

        validated = {}
        for name, validate in self.parameters.items():
            try:
                validated[name] = validate(arguments[name])
            except ArgumentError as error:
                raise ArgumentError(f"{self.name}.{name}: {error}") from None
        return validated

    def build(self, arguments: dict | None = None) -> str:
        return self.script.format(**self.validate(arguments))


# Processes that keep Windows running, or that keep this agent able to receive
# the next instruction. Stopping any of them is never a repair, so the name is
# refused before a proposal can be built rather than being left to a model's
# judgement or an operator's attention at approval time.
PROTECTED_PROCESSES = frozenset(name.lower() for name in [
    "system", "idle", "registry", "memory compression",
    "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsm",
    "svchost", "dwm", "explorer", "fontdrvhost", "sihost", "taskhostw",
    "msmpeng",                      # Defender: stopping it disables protection
    "squashrmm.agent",              # this agent: stopping it strands the device
    "amazonssmagent", "ssm-agent-worker",
])

MIN_REPAIRABLE_MEMORY_MB = 300


def killable_process_name(maximum_length: int = 64) -> Callable[[object], str]:
    """A process name that may be stopped. Narrow character class as elsewhere,
    plus a refusal for anything the machine needs to keep running."""
    base = windows_name(maximum_length)

    def validate(value: object) -> str:
        name = base(value)
        if name.lower().removesuffix(".exe") in PROTECTED_PROCESSES \
                or name.lower() in PROTECTED_PROCESSES:
            raise ArgumentError(
                f"'{name}' is required by Windows or by this agent and is never stopped")
        return name
    return validate


def process_id() -> Callable[[object], int]:
    def validate(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ArgumentError("expected a numeric process id")
        if not 8 <= value <= 0xFFFFFFFF:
            raise ArgumentError(f"{value} is not a process that may be stopped")
        return value
    return validate


def _process_present(data: object, pid: int, name: str, min_memory_mb: int = 0) -> bool:
    rows = data if isinstance(data, list) else [data]
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("pid") == pid and str(row.get("name", "")).lower() == name.lower():
            memory = row.get("memoryMB")
            if min_memory_mb and not (isinstance(memory, (int, float))
                                      and memory >= min_memory_mb):
                return False
            return True
    return False


def _service_is(status: str) -> Callable[[object, dict], bool]:
    def predicate(data: object, arguments: dict) -> bool:
        return isinstance(data, dict) and data.get("status") == status
    return predicate


def _free_space_below(threshold_percent: float) -> Callable[[object, dict], bool]:
    def predicate(data: object, arguments: dict) -> bool:
        drives = data if isinstance(data, list) else [data]
        return any(isinstance(d, dict) and d.get("drive") == "C"
                   and isinstance(d.get("percentFree"), (int, float))
                   and d["percentFree"] < threshold_percent
                   for d in drives)
    return predicate


def _free_space_at_least(threshold_percent: float) -> Callable[[object, dict], bool]:
    def predicate(data: object, arguments: dict) -> bool:
        drives = data if isinstance(data, list) else [data]
        return any(isinstance(d, dict) and d.get("drive") == "C"
                   and isinstance(d.get("percentFree"), (int, float))
                   and d["percentFree"] >= threshold_percent
                   for d in drives)
    return predicate


CATALOG: dict[str, Repair] = {
    r.name: r for r in [
        Repair(
            name="restart_service",
            summary="Stop and start a Windows service that is not running.",
            parameters={"service_name": windows_name()},
            script=(
                "Restart-Service -Name '{service_name}' -Force -ErrorAction Stop; "
                "\"restarted {service_name}\""
            ),
            precondition=Check(
                diagnostic="service_status",
                arguments=lambda a: {"service_name": a["service_name"]},
                predicate=lambda data, arguments: isinstance(data, dict)
                                       and data.get("status") in {"Stopped", "StopPending",
                                                                  "Paused", "StartPending"},
                describes="the service is not running",
            ),
            verification=Check(
                diagnostic="service_status",
                arguments=lambda a: {"service_name": a["service_name"]},
                predicate=_service_is("Running"),
                describes="the service is running",
            ),
            risk="The service is briefly unavailable, and anything depending on it may "
                 "fail during the restart.",
        ),
        Repair(
            name="start_service",
            summary="Start a stopped Windows service.",
            parameters={"service_name": windows_name()},
            script=(
                "Start-Service -Name '{service_name}' -ErrorAction Stop; "
                "\"started {service_name}\""
            ),
            precondition=Check(
                diagnostic="service_status",
                arguments=lambda a: {"service_name": a["service_name"]},
                predicate=_service_is("Stopped"),
                describes="the service is stopped",
            ),
            verification=Check(
                diagnostic="service_status",
                arguments=lambda a: {"service_name": a["service_name"]},
                predicate=_service_is("Running"),
                describes="the service is running",
            ),
            risk="Low. A service that was stopped deliberately would be started again.",
        ),
        Repair(
            name="stop_process",
            summary="Stop a single process that is consuming an unreasonable amount of memory.",
            parameters={"process_name": killable_process_name(), "pid": process_id()},
            # The endpoint re-checks that the pid still belongs to the named
            # process immediately before stopping it. A pid is reused as soon as
            # it is freed, so a check made anywhere else -- here, at proposal
            # time, even at precondition time -- can be stale by the time the
            # command lands, and would stop whatever inherited the number.
            script=(
                "$p = Get-Process -Id {pid} -ErrorAction Stop; "
                "if ($p.ProcessName -ne '{process_name}') {{ "
                "throw \"pid {pid} is now '$($p.ProcessName)', not '{process_name}'; refusing\" }}; "
                "$mb = [int]($p.WorkingSet64/1MB); "
                "Stop-Process -Id {pid} -Force -ErrorAction Stop; "
                "\"stopped {process_name} (pid {pid}, was $mb MB)\""
            ),
            precondition=Check(
                diagnostic="top_processes_by_memory",
                arguments=lambda a: {"top_n": 25},
                predicate=lambda data, arguments: _process_present(
                    data, arguments.get("pid"), arguments.get("process_name", ""),
                    MIN_REPAIRABLE_MEMORY_MB),
                describes="the process is running and is among the largest memory consumers",
            ),
            verification=Check(
                diagnostic="top_processes_by_memory",
                arguments=lambda a: {"top_n": 25},
                predicate=lambda data, arguments: not _process_present(
                    data, arguments.get("pid"), arguments.get("process_name", "")),
                describes="the process is no longer consuming that memory",
            ),
            risk="Stops the process immediately. Anything it had not saved is lost, and a "
                 "process that is merely busy would also be stopped.",
        ),
        Repair(
            name="clear_windows_temp",
            summary="Delete files from the Windows temp directory to reclaim disk space.",
            parameters={},
            script=(
                "$before = (Get-PSDrive C).Free; "
                "Get-ChildItem -Path $env:TEMP,C:\\Windows\\Temp -File -Recurse "
                "-ErrorAction SilentlyContinue | Where-Object "
                "{{ $_.LastWriteTime -lt (Get-Date).AddDays(-1) }} | "
                "Remove-Item -Force -ErrorAction SilentlyContinue; "
                "$after = (Get-PSDrive C).Free; "
                "\"reclaimed $([math]::Round(($after-$before)/1MB)) MB\""
            ),
            precondition=Check(
                diagnostic="disk_usage",
                arguments=lambda a: {},
                predicate=_free_space_below(15.0),
                describes="drive C has less than 15% free",
            ),
            verification=Check(
                diagnostic="disk_usage",
                arguments=lambda a: {},
                predicate=_free_space_at_least(15.0),
                describes="drive C has at least 15% free",
            ),
            risk="Deletes temporary files older than one day. An application actively "
                 "using an old temp file could be affected.",
            timeout_seconds=180,
        ),
    ]
}


def get(name: str) -> Repair:
    if name not in CATALOG:
        raise ArgumentError(
            f"'{name}' is not a permitted repair. Available: {', '.join(sorted(CATALOG))}")
    return CATALOG[name]
