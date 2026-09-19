"""Device inventory: what a machine is, kept current without anyone running
a script to find out.

The control plane collects it itself -- when a device connects, when one has
rebooted, every few hours, and on request -- by sending the fixed script below
as an ordinary job. It is signed, bounded and audited like every other job, and
the agent needs nothing new. Callers read the stored result.

This module holds the parts that do not touch the network: the script, how its
answer is judged, and when a device is due for another collection.
"""

from __future__ import annotations

import json

# Collected no more often than this while nothing changes.
MAX_AGE_SECONDS = 6 * 3600
# After a failed attempt, wait this long before trying again.
RETRY_AFTER_FAILURE_SECONDS = 15 * 60
TIMEOUT_SECONDS = 90
MAX_OUTPUT_BYTES = 1_048_576

# Read-only, and fixed: nothing from a caller reaches it. Installed software
# comes from the registry's uninstall keys, deliberately not Win32_Product,
# which is slow and makes Windows re-verify -- sometimes repair -- every MSI
# package on the machine.
SCRIPT = r"""$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$uninstall = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$software = @(Get-ItemProperty $uninstall -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } |
  Sort-Object DisplayName, DisplayVersion -Unique |
  ForEach-Object { [pscustomobject]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; installedOn = $_.InstallDate } })
[pscustomobject]@{
  os = [pscustomobject]@{
    name = $os.Caption
    version = $os.Version
    build = "$($os.BuildNumber).$($cv.UBR)"
    displayVersion = $cv.DisplayVersion
    architecture = $os.OSArchitecture
    installedAt = $os.InstallDate.ToUniversalTime().ToString('o')
    lastBootAt = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  }
  hardware = [pscustomobject]@{
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    serialNumber = $bios.SerialNumber
    biosVersion = $bios.SMBIOSBIOSVersion
    memoryMB = [int]($cs.TotalPhysicalMemory / 1MB)
    processors = @(Get-CimInstance Win32_Processor | ForEach-Object {
      [pscustomobject]@{ name = $_.Name.Trim(); cores = $_.NumberOfCores; logicalProcessors = $_.NumberOfLogicalProcessors; maxClockMHz = $_.MaxClockSpeed } })
    disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
      [pscustomobject]@{ drive = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1) } })
    networkAdapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
      [pscustomobject]@{ name = $_.Description; mac = $_.MACAddress; ipv4 = @($_.IPAddress | Where-Object { $_ -match '^\d+\.' }) } })
  }
  software = $software
} | ConvertTo-Json -Depth 5 -Compress"""

REQUIRED_SECTIONS = {"os": dict, "hardware": dict, "software": list}


def parse(job: dict) -> tuple[dict | None, str | None]:
    """Turns a finished collection job into (inventory, None) or
    (None, reason). An incomplete answer is never stored as if it were whole:
    a truncated or unparseable result is a failed collection, not a small
    inventory."""
    if job.get("state") != "Completed" or job.get("exitCode") != 0:
        detail = job.get("error") or (job.get("stderr") or "").strip()[:200]
        return None, (f"collection ended {job.get('state')}, exit {job.get('exitCode')}"
                      + (f": {detail}" if detail else ""))
    if job.get("stdoutTruncated"):
        return None, "the inventory was too large and was cut off; nothing stored"
    try:
        data = json.loads(job.get("stdout") or "")
    except ValueError:
        return None, "the inventory was not valid JSON"
    if not isinstance(data, dict):
        return None, "the inventory had an unexpected shape"
    for section, kind in REQUIRED_SECTIONS.items():
        if not isinstance(data.get(section), kind):
            return None, f"the inventory is missing its {section} section"
    return data, None


def due(record: dict | None, now: float) -> bool:
    """Whether a device should be collected again. A failure is retried, but
    not in a tight loop against a machine that keeps failing."""
    if record is None:
        return True
    if record.get("error") and record.get("attempted_at") \
            and now - record["attempted_at"] < RETRY_AFTER_FAILURE_SECONDS:
        return False
    collected = record.get("collected_at")
    return collected is None or now - collected >= MAX_AGE_SECONDS


def stale(record: dict | None, now: float) -> bool:
    """Older than the refresh interval, or never collected."""
    collected = (record or {}).get("collected_at")
    return collected is None or now - collected >= MAX_AGE_SECONDS
