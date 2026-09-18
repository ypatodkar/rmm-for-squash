"""The diagnostics this worker is permitted to run.

Every entry is a fixed, reviewed script. Callers choose a diagnostic by name and
supply arguments that are validated against a declared type before any
substitution happens, so nothing a caller provides can become script text. The
control plane still accepts arbitrary PowerShell, as the brief requires; this
worker simply declines to use that freedom.

All of these are read-only. Anything that changes an endpoint belongs in a
separate catalogue that requires human approval.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


class ArgumentError(ValueError):
    """An argument failed validation and the diagnostic must not be built."""


def bounded_int(minimum: int, maximum: int) -> Callable[[object], int]:
    def validate(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ArgumentError(f"expected a whole number between {minimum} and {maximum}")
        if not minimum <= value <= maximum:
            raise ArgumentError(f"must be between {minimum} and {maximum}, got {value}")
        return value
    return validate


def windows_name(maximum_length: int = 64) -> Callable[[object], str]:
    """Windows service and process names. The character class is deliberately
    narrow: these values are substituted into a script, so anything that could
    terminate a string or start a new statement is refused rather than escaped."""
    pattern = re.compile(r"^[A-Za-z0-9_.\-]{1,%d}$" % maximum_length)

    def validate(value: object) -> str:
        if not isinstance(value, str):
            raise ArgumentError("expected a name")
        if not pattern.match(value):
            raise ArgumentError(
                "may contain only letters, digits, underscore, dot and hyphen "
                f"(up to {maximum_length} characters)")
        return value
    return validate


@dataclass(frozen=True)
class Diagnostic:
    name: str
    summary: str
    script: str
    timeout_seconds: int = 30
    parameters: dict[str, Callable[[object], object]] = field(default_factory=dict)

    def build(self, arguments: dict | None = None) -> str:
        """Validates arguments and substitutes them. Literal braces in a script
        must be doubled, since every script goes through the same substitution
        whether or not it declares parameters."""
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
        return self.script.format(**validated)


# Diagnostics emit JSON rather than formatted tables: the consumer is a program,
# and -Depth keeps PowerShell from silently truncating nested objects.
_JSON = "| ConvertTo-Json -Depth 4 -Compress"

CATALOG: dict[str, Diagnostic] = {
    d.name: d for d in [
        Diagnostic(
            name="system_overview",
            summary="OS, uptime, processor load and memory in one call.",
            script=(
                "$os = Get-CimInstance Win32_OperatingSystem; "
                "[pscustomobject]@{{"
                " hostname = $env:COMPUTERNAME;"
                " osCaption = $os.Caption;"
                " uptimeSeconds = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds;"
                " totalMemoryMB = [int]($os.TotalVisibleMemorySize/1KB);"
                " freeMemoryMB = [int]($os.FreePhysicalMemory/1KB);"
                " memoryUsedPercent = [math]::Round(100*(1-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)),1);"
                " processorLoadPercent = (Get-CimInstance Win32_Processor "
                "| Measure-Object -Property LoadPercentage -Average).Average;"
                " processCount = (Get-Process).Count"
                f"}}}} {_JSON}"
            ),
        ),
        Diagnostic(
            name="top_processes_by_memory",
            summary="Processes using the most working-set memory.",
            parameters={"top_n": bounded_int(1, 25)},
            script=(
                "Get-Process | Sort-Object WorkingSet64 -Descending "
                "| Select-Object -First {top_n} "
                "@{{N='name';E={{$_.Name}}}},@{{N='pid';E={{$_.Id}}}},"
                "@{{N='memoryMB';E={{[int]($_.WorkingSet64/1MB)}}}},"
                "@{{N='startTime';E={{if ($_.StartTime) {{$_.StartTime.ToUniversalTime().ToString('o')}} else {{$null}}}}}} "
                f"{_JSON}"
            ),
        ),
        Diagnostic(
            name="top_processes_by_cpu",
            summary="Processes that have consumed the most processor time.",
            parameters={"top_n": bounded_int(1, 25)},
            script=(
                "Get-Process | Sort-Object CPU -Descending "
                "| Select-Object -First {top_n} "
                "@{{N='name';E={{$_.Name}}}},@{{N='pid';E={{$_.Id}}}},"
                "@{{N='cpuSeconds';E={{[math]::Round($_.CPU,1)}}}},"
                "@{{N='memoryMB';E={{[int]($_.WorkingSet64/1MB)}}}} "
                f"{_JSON}"
            ),
        ),
        Diagnostic(
            name="disk_usage",
            summary="Free and used space for each fixed drive.",
            script=(
                "Get-PSDrive -PSProvider FileSystem | Where-Object {{ $_.Used -ne $null }} "
                "| Select-Object @{{N='drive';E={{$_.Name}}}},"
                "@{{N='usedGB';E={{[math]::Round($_.Used/1GB,2)}}}},"
                "@{{N='freeGB';E={{[math]::Round($_.Free/1GB,2)}}}},"
                "@{{N='percentFree';E={{if (($_.Used+$_.Free) -gt 0) "
                "{{[math]::Round(100*$_.Free/($_.Used+$_.Free),1)}} else {{$null}}}}}} "
                f"{_JSON}"
            ),
        ),
        Diagnostic(
            name="service_status",
            summary="Status and start type of one named service.",
            parameters={"service_name": windows_name()},
            script=(
                "Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue "
                "| Select-Object @{{N='name';E={{$_.Name}}}},"
                "@{{N='displayName';E={{$_.DisplayName}}}},"
                "@{{N='status';E={{$_.Status.ToString()}}}},"
                "@{{N='startType';E={{$_.StartType.ToString()}}}} "
                f"{_JSON}"
            ),
        ),
        Diagnostic(
            name="recent_system_errors",
            summary="Recent error-level entries from the System event log.",
            parameters={"hours": bounded_int(1, 168), "max_events": bounded_int(1, 50)},
            timeout_seconds=60,
            script=(
                "Get-WinEvent -FilterHashtable @{{LogName='System';Level=2;"
                "StartTime=(Get-Date).AddHours(-{hours})}} "
                "-MaxEvents {max_events} -ErrorAction SilentlyContinue "
                "| Select-Object @{{N='timeCreated';E={{$_.TimeCreated.ToUniversalTime().ToString('o')}}}},"
                "@{{N='provider';E={{$_.ProviderName}}}},@{{N='eventId';E={{$_.Id}}}},"
                "@{{N='message';E={{if ($_.Message) {{$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))}} else {{'' }}}}}} "
                f"{_JSON}"
            ),
        ),
    ]
}


def get(name: str) -> Diagnostic:
    if name not in CATALOG:
        raise ArgumentError(
            f"'{name}' is not a permitted diagnostic. Available: {', '.join(sorted(CATALOG))}")
    return CATALOG[name]
