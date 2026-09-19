"""Tracked restarts, and whether Windows was already waiting for one.

A restart is followed as a record of its own rather than inferred from device
events: requested, confirmed scheduled by the machine, seen going offline, and
back with a new boot -- or, if not, why not. Before it is sent, the machine is
asked whether it was already waiting on a pending reboot; after it returns, it
is asked again, so the record shows whether the restart cleared it.

The pieces here do not touch the network: the pending-reboot check, how its
answer is judged, and every status transition, as plain functions.
"""

from __future__ import annotations

import json

OPEN = ("scheduling", "scheduled", "offline")
# After the restart was confirmed scheduled, the machine should drop within
# its delay; this is how much longer we wait before calling it failed.
NEVER_WENT_OFFLINE_AFTER_SECONDS = 10 * 60
DID_NOT_RETURN_AFTER_SECONDS = 30 * 60
CHECK_TIMEOUT_SECONDS = 30

# Read-only. These are the places Windows records that it needs a restart.
PENDING_SCRIPT = r"""$reasons = [System.Collections.Generic.List[object]]::new()
function Add-Reason($code, $description) { $reasons.Add([pscustomobject]@{ code = $code; description = $description }) }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
  Add-Reason 'component_servicing' 'Windows component servicing is waiting for a restart to finish installing or removing a feature or update' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
  Add-Reason 'windows_update' 'Windows Update has installed updates that need a restart' }
$renames = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations |
  Where-Object { $_ -and $_.StartsWith('\??\') })
if ($renames.Count -gt 0) {
  Add-Reason 'pending_file_operations' "$($renames.Count) file operation(s) are scheduled to run at the next restart" }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction SilentlyContinue).UpdateExeVolatile) {
  Add-Reason 'update_installer' 'An update installer is waiting for a restart to finish' }
$active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
$next = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
if ($active -ne $next) { Add-Reason 'computer_rename' "The computer is being renamed to $next, which takes effect at the next restart" }
[pscustomobject]@{ pending = ($reasons.Count -gt 0); reasons = @($reasons) } | ConvertTo-Json -Depth 3 -Compress"""


def parse_pending(job: dict) -> tuple[dict | None, str | None]:
    """({"pending": bool, "reasons": [...]}, None) or (None, reason). A check
    that did not complete is not the same as "nothing pending"."""
    if job.get("state") != "Completed" or job.get("exitCode") != 0:
        detail = job.get("error") or (job.get("stderr") or "").strip()[:200]
        return None, (f"the check ended {job.get('state')}, exit {job.get('exitCode')}"
                      + (f": {detail}" if detail else ""))
    if job.get("stdoutTruncated"):
        return None, "the check's answer was cut off"
    try:
        data = json.loads(job.get("stdout") or "")
    except ValueError:
        return None, "the check's answer was not valid JSON"
    if not isinstance(data, dict) or not isinstance(data.get("pending"), bool) \
            or not isinstance(data.get("reasons"), list):
        return None, "the check's answer had an unexpected shape"
    return {"pending": data["pending"], "reasons": data["reasons"]}, None


# ---------- transitions: each returns the fields to change, or {} ----------

def restart_command_finished(record: dict, job: dict, now: float) -> dict:
    if job.get("state") == "Completed" and job.get("exitCode") == 0:
        changes = {"scheduled_at": now}
        if record["status"] == "scheduling":
            changes["status"] = "scheduled"
        return changes
    if record["status"] not in OPEN:
        return {}
    detail = job.get("error") or (job.get("stderr") or "").strip()[:200]
    return {"status": "failed",
            "error": f"the restart command did not run ({job.get('state')})"
                     + (f": {detail}" if detail else "")}


def went_offline(record: dict, now: float) -> dict:
    if record["status"] in ("scheduling", "scheduled") and now >= record["requested_at"]:
        return {"status": "offline", "went_offline_at": now}
    return {}


def came_back(record: dict, rebooted: bool | None, now: float) -> dict:
    """What reconnecting means for a restart in progress. `rebooted` is the
    control plane's own judgement, from the machine's uptime."""
    if record["status"] not in OPEN:
        return {}
    if rebooted:
        return {"status": "completed", "came_back_at": now, "boot_confirmed": 1}
    if record["status"] != "offline":
        # Reconnected before going down -- a network blip or a control plane
        # restart. The restart has not happened yet; keep waiting.
        return {}
    if rebooted is False:
        return {"status": "not_restarted", "came_back_at": now, "boot_confirmed": 0,
                "error": "it went offline but came back without having restarted; "
                         "the restart may have been cancelled on the machine"}
    return {"status": "completed", "came_back_at": now, "boot_confirmed": None,
            "error": "back online, but a new boot could not be confirmed"}


def overdue(record: dict, now: float) -> dict:
    status = record["status"]
    if status == "scheduled" and record.get("scheduled_at") and \
            now - record["scheduled_at"] > (record.get("delay_seconds") or 0) + NEVER_WENT_OFFLINE_AFTER_SECONDS:
        return {"status": "failed",
                "error": "the machine never went offline; the restart may have been "
                         "cancelled on the machine"}
    if status == "offline" and record.get("went_offline_at") and \
            now - record["went_offline_at"] > DID_NOT_RETURN_AFTER_SECONDS:
        return {"status": "failed",
                "error": f"the machine did not come back within "
                         f"{DID_NOT_RETURN_AFTER_SECONDS // 60} minutes"}
    return {}
