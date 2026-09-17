<#
.SYNOPSIS
    Removes the Squash RMM endpoint agent and all local state.

.NOTES
    The server-side device record and its audit history are retained
    deliberately; removing an agent must not erase the evidence of what it
    was asked to do. Use the control plane's revoke endpoint to stop a
    device from reconnecting.
#>
[CmdletBinding()]
param(
    [string] $InstallDir = "$env:ProgramFiles\SquashRmm",
    [string] $ServiceName = 'SquashEndpoint'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($message) { Write-Host "==> $message" -ForegroundColor Cyan }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to remove a Windows Service.'
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Step "Stopping $ServiceName"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and (Get-Service $ServiceName).Status -ne 'Stopped') {
        Start-Sleep -Milliseconds 500
    }

    Write-Step "Deleting service registration"
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
} else {
    Write-Step "Service '$ServiceName' is not installed"
}

if (Test-Path $InstallDir) {
    Write-Step "Removing $InstallDir (including the device key)"
    Remove-Item -Recurse -Force $InstallDir
}

$remaining = @()
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { $remaining += "service $ServiceName" }
if (Test-Path $InstallDir) { $remaining += $InstallDir }

if ($remaining.Count -gt 0) {
    throw "Uninstall incomplete; these remain: $($remaining -join ', ')"
}

Write-Host ''
Write-Host 'Uninstalled cleanly. No service, no files, no keys.' -ForegroundColor Green
Write-Host 'The device record remains on the control plane for audit purposes.'
