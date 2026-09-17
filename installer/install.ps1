<#
.SYNOPSIS
    Installs the Squash RMM endpoint agent as an unattended Windows Service.

.EXAMPLE
    .\install.ps1 -Server http://control-plane:5200 -Token enr_xxx
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Server,
    # Only needed when this machine has no identity yet. An upgrade over an
    # existing install keeps its key and needs no token.
    [string] $Token,
    [string] $InstallDir = "$env:ProgramFiles\SquashRmm",
    [string] $ServiceName = 'SquashEndpoint'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($message) { Write-Host "==> $message" -ForegroundColor Cyan }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to register a Windows Service.'
}

$base = $Server.TrimEnd('/')
$wsBase = $base -replace '^https://', 'wss://' -replace '^http://', 'ws://'

$statePath = Join-Path $InstallDir 'state'
$hasIdentity = (Test-Path (Join-Path $statePath 'device.key')) -and
               (Test-Path (Join-Path $statePath 'enrolled'))

if ($hasIdentity) {
    Write-Step 'Existing device identity found; upgrading in place and keeping its key'
} elseif (-not $Token) {
    throw 'This machine has no device identity, so an enrollment token is required. ' +
          'Get one with: squashctl install   (or squashctl reinstall <host> if it was enrolled before)'
}

Write-Step "Stopping any previous installation"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Step "Preparing $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'state') | Out-Null

Write-Step "Downloading agent from $base"
$exePath = Join-Path $InstallDir 'SquashRmm.Agent.exe'
$progressPreferencePrevious = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri "$base/download/agent.exe" -OutFile $exePath -UseBasicParsing
    $expected = (Invoke-WebRequest -Uri "$base/download/agent.sha256" -UseBasicParsing).Content.Trim()
} finally {
    $ProgressPreference = $progressPreferencePrevious
}

$actual = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected.ToLower()) {
    Remove-Item $exePath -Force
    throw "Agent integrity check failed. Expected $expected, got $actual."
}
Write-Step "Integrity verified (sha256 $($actual.Substring(0,16))...)"

Write-Step 'Writing configuration'
$settings = @{
    Logging = @{ LogLevel = @{ Default = 'Information' } }
    Server  = @{ Url = $wsBase }
} | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $InstallDir 'appsettings.json') -Value $settings -Encoding UTF8

# The enrolment token lives in its own file so the agent can delete it the
# moment it has been redeemed; it must not linger as a standing secret.
if ($Token) {
    Set-Content -Path (Join-Path $statePath 'enroll.token') -Value $Token -Encoding ASCII -NoNewline
}

Write-Step 'Restricting access to SYSTEM and Administrators'
& icacls.exe $InstallDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

Write-Step "Registering service '$ServiceName'"
& sc.exe create $ServiceName binPath= "`"$exePath`"" start= auto DisplayName= 'Squash RMM Endpoint' | Out-Null
& sc.exe description $ServiceName 'Executes operator-dispatched scripts for Squash RMM.' | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Step 'Starting service'
Start-Service -Name $ServiceName

function Write-Success($headline) {
    Write-Host ''
    Write-Host $headline -ForegroundColor Green
    Write-Host "  Service : $ServiceName ($((Get-Service $ServiceName).Status), starts automatically)"
    Write-Host "  Location: $InstallDir"
    Write-Host "  Server  : $wsBase"
}

if ($hasIdentity) {
    Write-Success 'Upgraded. Existing device identity preserved.'
    exit 0
}

$deadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $deadline) {
    if (-not (Test-Path (Join-Path $statePath 'enroll.token'))) {
        Write-Success 'Installed and enrolled.'
        exit 0
    }
    Start-Sleep -Seconds 2
}

Write-Warning 'Service started but enrolment has not completed within 45s.'
Write-Warning 'The token may be expired, already used, or issued for a different device.'
Write-Warning 'Check: Get-EventLog -LogName Application -Source SquashEndpoint -Newest 5'
exit 1
