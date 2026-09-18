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
    """
    diagnostic: str
    arguments: Callable[[dict], dict]
    predicate: Callable[[object], bool]
    describes: str

    def evaluate(self, data: object) -> bool:
        try:
            return bool(self.predicate(data))
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
        arguments = arguments or {}
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


def _service_is(status: str) -> Callable[[object], bool]:
    def predicate(data: object) -> bool:
        return isinstance(data, dict) and data.get("status") == status
    return predicate


def _free_space_below(threshold_percent: float) -> Callable[[object], bool]:
    def predicate(data: object) -> bool:
        drives = data if isinstance(data, list) else [data]
        return any(isinstance(d, dict) and d.get("drive") == "C"
                   and isinstance(d.get("percentFree"), (int, float))
                   and d["percentFree"] < threshold_percent
                   for d in drives)
    return predicate


def _free_space_at_least(threshold_percent: float) -> Callable[[object], bool]:
    def predicate(data: object) -> bool:
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
                predicate=lambda data: isinstance(data, dict)
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
