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


_HOST = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


def host_name() -> Callable[[object], str]:
    """A DNS name or an IPv4 address. Like windows_name, it is substituted
    into a script, so only the characters a hostname can contain are allowed:
    no quotes, spaces or separators, and nothing that could start a statement."""
    def validate(value: object) -> str:
        if not isinstance(value, str) or not _HOST.match(value):
            raise ArgumentError("must be a hostname or IPv4 address "
                                "(letters, digits, hyphens and dots)")
        return value
    return validate


def _ps(script: str) -> str:
    """Lets a script be written as ordinary PowerShell. Every script goes
    through str.format, so literal braces must be doubled; doing that by hand
    has gone wrong before. Here braces are literal and <<name>> marks a
    parameter."""
    escaped = script.replace("{", "{{").replace("}", "}}")
    return re.sub(r"<<(\w+)>>", r"{\1}", escaped)


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
        if arguments is None:
            arguments = {}
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
            # Get-WinEvent exits non-zero when nothing matches the filter, which
            # makes "no errors were logged" indistinguishable from "the check
            # failed". An empty result is a finding in its own right, so it is
            # returned as an empty list with a successful exit.
            script=(
                "$found = @(Get-WinEvent -FilterHashtable @{{LogName='System';Level=2;"
                "StartTime=(Get-Date).AddHours(-{hours})}} "
                "-MaxEvents {max_events} -ErrorAction SilentlyContinue); "
                "$rows = @($found | Select-Object "
                "@{{N='timeCreated';E={{$_.TimeCreated.ToUniversalTime().ToString('o')}}}},"
                "@{{N='provider';E={{$_.ProviderName}}}},@{{N='eventId';E={{$_.Id}}}},"
                "@{{N='message';E={{if ($_.Message) {{$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))}} else {{'' }}}}}}); "
                "if ($rows.Count -eq 0) {{ '[]' }} else {{ $rows "
                # f-string: '}}}}' survives as '}}' so that .format() later
                # renders the single brace PowerShell needs.
                f"{_JSON} }}}}; "
                "exit 0"
            ),
        ),

        # ---- network: from the machine outward, one layer at a time ----
        # Each reports a failure to connect as data, with exit 0. "The host did
        # not answer" is the finding; only a check that could not run at all is
        # a failed check. Timeouts are short so a dead end costs seconds.
        Diagnostic(
            name="network_adapters",
            summary="Network adapters: whether each is up, its IPv4 address, default "
                    "gateway and DNS servers. The first step for any connectivity problem.",
            # .NET rather than Get-NetIPConfiguration, which takes three
            # seconds to load its module.
            script=_ps(r"""
$rows = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
  Where-Object { $_.NetworkInterfaceType -ne 'Loopback' } | ForEach-Object {
    $ip = $_.GetIPProperties()
    [pscustomobject]@{
      name = $_.Name
      status = $_.OperationalStatus.ToString()
      ipv4 = @($ip.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
               ForEach-Object { $_.Address.ToString() })
      gateways = @($ip.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
                   ForEach-Object { $_.Address.ToString() })
      dnsServers = @($ip.DnsAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                     ForEach-Object { $_.ToString() })
    }
  })
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""),
        ),
        Diagnostic(
            name="ping_host",
            summary="Sends two pings to a host or IP (1s timeout each) and reports "
                    "replies and round-trip times. Many hosts ignore ping, so no reply "
                    "alone does not prove a host is unreachable; confirm with test_tcp_port.",
            parameters={"host": host_name()},
            script=_ps(r"""
$ping = New-Object Net.NetworkInformation.Ping
$replies = @(1..2 | ForEach-Object {
  try {
    $r = $ping.Send('<<host>>', 1000)
    [pscustomobject]@{ status = $r.Status.ToString(); ms = $r.RoundtripTime; from = "$($r.Address)" }
  } catch {
    [pscustomobject]@{ status = 'Error: ' + $_.Exception.GetBaseException().Message; ms = $null; from = $null }
  }
})
[pscustomobject]@{
  host = '<<host>>'
  sent = 2
  received = @($replies | Where-Object { $_.status -eq 'Success' }).Count
  replies = $replies
} | ConvertTo-Json -Depth 4 -Compress
"""),
        ),
        Diagnostic(
            name="resolve_name",
            summary="Resolves a hostname two ways: asking the DNS server directly, and "
                    "through the system resolver, which also reads the hosts file. "
                    "Different answers mean a local override. Includes matching "
                    "hosts-file lines.",
            parameters={"name": host_name()},
            script=_ps(r"""
$name = '<<name>>'
$dnsAnswer = @(); $dnsError = $null
try {
  $dnsAnswer = @(Resolve-DnsName $name -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                 Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
} catch { $dnsError = $_.Exception.Message }
$systemAnswer = @(); $systemError = $null
try {
  $systemAnswer = @([Net.Dns]::GetHostAddresses($name) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() })
} catch { $systemError = $_.Exception.GetBaseException().Message }
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$pattern = '(^|\s)' + [regex]::Escape($name) + '(\s|$)'
$hostsLines = @(Get-Content $hostsFile -ErrorAction SilentlyContinue |
  Where-Object { $_ -notmatch '^\s*#' -and $_ -match $pattern } | ForEach-Object { $_.Trim() })
[pscustomobject]@{
  name = $name
  dnsServerAnswer = $dnsAnswer
  dnsServerError = $dnsError
  systemAnswer = $systemAnswer
  systemError = $systemError
  hostsFileEntries = $hostsLines
} | ConvertTo-Json -Depth 4 -Compress
"""),
        ),
        Diagnostic(
            name="test_tcp_port",
            summary="Tries to open a TCP connection to a host and port (2s timeout), e.g. "
                    "445 for a file share, 443 for HTTPS, 3389 for RDP. Reports connected, "
                    "refused or timed out.",
            parameters={"host": host_name(), "port": bounded_int(1, 65535)},
            script=_ps(r"""
$client = New-Object Net.Sockets.TcpClient
$timer = [Diagnostics.Stopwatch]::StartNew()
try {
  if ($client.ConnectAsync('<<host>>', <<port>>).Wait(2000)) { $result = 'connected' }
  else { $result = 'timed out after 2000ms' }
} catch {
  $result = 'failed: ' + $_.Exception.GetBaseException().Message
} finally { $client.Close() }
[pscustomobject]@{
  host = '<<host>>'
  port = <<port>>
  connected = ($result -eq 'connected')
  result = $result
  ms = [int]$timer.ElapsedMilliseconds
} | ConvertTo-Json -Compress
"""),
        ),
        Diagnostic(
            name="outbound_firewall_blocks",
            summary="Enabled Windows Firewall rules that block outbound traffic, with the "
                    "addresses and ports each one blocks. Use when a host is reachable "
                    "from elsewhere but not from this machine.",
            timeout_seconds=45,
            script=_ps(r"""
$rules = @(Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
  Select-Object -First 25 | ForEach-Object {
    $address = $_ | Get-NetFirewallAddressFilter
    $port = $_ | Get-NetFirewallPortFilter
    [pscustomobject]@{
      name = $_.DisplayName
      profile = $_.Profile.ToString()
      remoteAddress = @($address.RemoteAddress)
      protocol = "$($port.Protocol)"
      remotePort = @($port.RemotePort)
    }
  })
ConvertTo-Json -InputObject $rules -Depth 4 -Compress
"""),
        ),
    ]
}


def get(name: str) -> Diagnostic:
    if name not in CATALOG:
        raise ArgumentError(
            f"'{name}' is not a permitted diagnostic. Available: {', '.join(sorted(CATALOG))}")
    return CATALOG[name]
