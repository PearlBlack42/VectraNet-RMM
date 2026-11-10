#Requires -RunAsAdministrator
<#
.SYNOPSIS
    VectraNet RMM Silent Agent Installer & Windows Service Provisioner
    File: agents/windows/install.ps1
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\agents\windows\install.ps1 `
      -ServerUrl "https://rmm.internal.corp:8443" `
      -AgentToken "vn_live_98a7bc6512f4"
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "https://rmm.internal.corp:8443",

    [Parameter(Mandatory = $false)]
    [string]$AgentToken = "vn_default_bootstrap_token",

    [Parameter(Mandatory = $false)]
    [string]$BinaryUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedSha256 = "",

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = "C:\Program Files\VectraNet"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($BinaryUrl -eq "") {
    $BinaryUrl = "$($ServerUrl.TrimEnd('/'))/downloads/windows/vectranet-agent.exe"
}

$ServiceName = "VectraNetAgent"
$ServiceDisplayName = "VectraNet RMM Discovery & Telemetry Agent"
$BinaryPath = Join-Path $InstallDir "vectranet-agent.exe"

Write-Host "[1/5] Preparing installation directory: $InstallDir"
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existingSvc) {
    Write-Host "[2/5] Stopping existing service $ServiceName..."
    if ($existingSvc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "[3/5] Downloading agent binary from $BinaryUrl..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
Invoke-WebRequest -Uri $BinaryUrl -OutFile $BinaryPath -UseBasicParsing

if ($ExpectedSha256 -ne "") {
    $actualHash = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash
    if ($actualHash.ToLower() -ne $ExpectedSha256.ToLower()) {
        Remove-Item -Path $BinaryPath -Force
        Throw "SHA-256 verification failed! Expected: $ExpectedSha256, Actual: $actualHash"
    }
    Write-Host "      SHA-256 checksum verified: $actualHash"
}

[System.Environment]::SetEnvironmentVariable("VECTRANET_SERVER_URL", $ServerUrl, [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable("VECTRANET_AGENT_TOKEN", $AgentToken, [System.EnvironmentVariableTarget]::Machine)

Write-Host "[4/5] Registering Windows Service '$ServiceName'..."
$binArgs = "`"$BinaryPath`" -server `"$ServerUrl`" -token `"$AgentToken`" -interval 60"
sc.exe create $ServiceName binPath= $binArgs start= auto DisplayName= $ServiceDisplayName | Out-Null
sc.exe description $ServiceName "Ultra-lightweight IT Asset Discovery and Telemetry Collector (<15MB RAM)" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

Write-Host "[5/5] Starting service '$ServiceName'..."
Start-Service -Name $ServiceName
$svcState = (Get-Service -Name $ServiceName).Status
Write-Host "[SUCCESS] $ServiceName is now $svcState."
