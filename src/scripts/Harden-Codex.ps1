<#
.SYNOPSIS
  Maximum practical hardening (PowerShell-only) to:
    1) Restrict network egress for the current machine/user workflow by BLOCKING common “escape” executables
    2) ALLOW outbound Internet only for Codex (and, if required, its runtime)
    3) Limit filesystem scope operationally to the CURRENT DIRECTORY by launching Codex in an isolated working dir

.DESCRIPTION
  Windows does not provide a true “filesystem jail” purely from PowerShell without OS policy (WDAC/AppLocker),
  containers, or a VM/Sandbox. This script does the strongest enforcement that *is* feasible in a script:
    - Windows Defender Firewall program rules (enforced by OS)
    - Aggressive blocking of common network-capable tools
    - Launch Codex with locked-down environment variables and in the current directory

  REQUIREMENTS
    - Run as Administrator (to manage firewall rules).
    - Best results if Codex is a single executable. If Codex is a .cmd wrapper that calls node.exe,
      you may need to allow node.exe as well (the script attempts this conservatively).

USAGE
  # Apply hardening and start Codex in the current directory
  .\Harden-Codex.ps1 -Apply -StartCodex

  # Apply hardening only (no start)
  .\Harden-Codex.ps1 -Apply

  # Remove firewall rules created by this script
  .\Harden-Codex.ps1 -Revert

NOTES
  - This script does NOT change global firewall defaults; it creates targeted rules in a dedicated group.
  - “Filesystem-only to current directory” cannot be strictly enforced for the same user without WDAC/AppLocker/Sandbox.
    If you want true filesystem isolation, ask and I will provide a Windows Sandbox or WDAC/AppLocker approach.
#>

[CmdletBinding(DefaultParameterSetName="Apply")]
param(
  [Parameter(ParameterSetName="Apply", Mandatory=$true)]
  [switch]$Apply,

  [Parameter(ParameterSetName="Revert", Mandatory=$true)]
  [switch]$Revert,

  [Parameter(ParameterSetName="Apply")]
  [switch]$StartCodex,

  # Optional: allow Codex to reach only specific remote ports (leave empty to allow all outbound)
  [Parameter(ParameterSetName="Apply")]
  [int[]]$AllowRemotePorts = @(),

  # Optional: allow Codex to reach only specific remote addresses / CIDRs (leave empty to allow all)
  [Parameter(ParameterSetName="Apply")]
  [string[]]$AllowRemoteAddresses = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RuleGroup = "CodexHardening"
$RulePrefix = "CodexHardening - "

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator privileges are required. Re-run PowerShell as Administrator."
  }
}

function Remove-RuleGroup {
  $existing = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $RuleGroup }
  if ($existing) {
    $existing | Remove-NetFirewallRule | Out-Null
  }
}

function Add-BlockOutboundRule {
  param(
    [Parameter(Mandatory=$true)][string]$ProgramPath,
    [Parameter(Mandatory=$true)][string]$NameSuffix
  )
  if (-not (Test-Path -LiteralPath $ProgramPath)) { return }

  New-NetFirewallRule `
    -DisplayName ($RulePrefix + "BLOCK Outbound - " + $NameSuffix) `
    -Group $RuleGroup `
    -Enabled True `
    -Direction Outbound `
    -Action Block `
    -Program $ProgramPath `
    -Profile Any `
    -Protocol Any | Out-Null
}

function Add-AllowOutboundRuleForCodex {
  param(
    [Parameter(Mandatory=$true)][string]$ProgramPath,
    [Parameter(Mandatory=$true)][string]$NameSuffix
  )
  if (-not (Test-Path -LiteralPath $ProgramPath)) { return }

  $params = @{
    DisplayName = ($RulePrefix + "ALLOW Outbound - " + $NameSuffix)
    Group       = $RuleGroup
    Enabled     = $true
    Direction   = "Outbound"
    Action      = "Allow"
    Program     = $ProgramPath
    Profile     = "Any"
    Protocol    = "Any"
  }

  if ($AllowRemotePorts.Count -gt 0) {
    $params["RemotePort"] = ($AllowRemotePorts -join ",")
  }

  if ($AllowRemoteAddresses.Count -gt 0) {
    $params["RemoteAddress"] = ($AllowRemoteAddresses -join ",")
  }

  New-NetFirewallRule @params | Out-Null
}

function Resolve-ProgramPath {
  param([Parameter(Mandatory=$true)][string]$Command)
  $cmd = Get-Command $Command -ErrorAction SilentlyContinue
  if (-not $cmd) { return $null }
  return $cmd.Source
}

function Get-SystemBinaryPath {
  param([Parameter(Mandatory=$true)][string]$ExeName)
  $p = Join-Path $env:WINDIR "System32\$ExeName"
  if (Test-Path $p) { return $p }
  $p = Join-Path $env:WINDIR "SysWOW64\$ExeName"
  if (Test-Path $p) { return $p }
  return $null
}

function Get-PathExeCandidates {
  param([Parameter(Mandatory=$true)][string]$ExeName)
  $results = @()

  # Prefer system32
  $sys = Get-SystemBinaryPath $ExeName
  if ($sys) { $results += $sys }

  # Search PATH
  try {
    $where = (& where.exe $ExeName 2>$null) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($w in $where) {
      if (Test-Path $w) { $results += $w }
    }
  } catch { }

  $results | Select-Object -Unique
}

function Apply-Hardening {
  Assert-Admin

  # Clean slate for our rule group
  Remove-RuleGroup

  # Resolve Codex entrypoint
  $codexPath = Resolve-ProgramPath "codex"
  if (-not $codexPath) {
    throw "Could not find 'codex' on PATH. Install/ensure it is available, then re-run."
  }

  # If Codex is a .cmd wrapper, it may invoke node.exe; attempt to locate node.exe
  $codexIsCmd = [IO.Path]::GetExtension($codexPath).ToLowerInvariant() -eq ".cmd"
  $nodeCandidates = @()
  if ($codexIsCmd) {
    $nodeCandidates = Get-PathExeCandidates "node.exe"
  }

  # 1) BLOCK outbound for common “living-off-the-land” and scripting tools to reduce bypass options
  #    (You can add/remove items depending on your environment.)
  $blockList = @(
    (Get-SystemBinaryPath "WindowsPowerShell\v1.0\powershell.exe"),
    (Get-SystemBinaryPath "pwsh.exe"),
    (Get-SystemBinaryPath "cmd.exe"),
    (Get-SystemBinaryPath "wscript.exe"),
    (Get-SystemBinaryPath "cscript.exe"),
    (Get-SystemBinaryPath "mshta.exe"),
    (Get-SystemBinaryPath "rundll32.exe"),
    (Get-SystemBinaryPath "regsvr32.exe"),
    (Get-SystemBinaryPath "bitsadmin.exe"),
    (Get-SystemBinaryPath "certutil.exe")
  ) | Where-Object { $_ }

  # Add common network clients if found
  $blockList += Get-PathExeCandidates "curl.exe"
  $blockList += Get-PathExeCandidates "wget.exe"
  $blockList += Get-PathExeCandidates "git.exe"
  $blockList += Get-PathExeCandidates "python.exe"
  $blockList += Get-PathExeCandidates "python3.exe"
  $blockList += Get-PathExeCandidates "pip.exe"
  $blockList += Get-PathExeCandidates "pip3.exe"
  $blockList += Get-PathExeCandidates "node.exe"  # NOTE: we will re-ALLOW node only if Codex needs it (see below)

  $blockList = $blockList | Where-Object { $_ } | Select-Object -Unique

  foreach ($p in $blockList) {
    $name = Split-Path $p -Leaf
    Add-BlockOutboundRule -ProgramPath $p -NameSuffix $name
  }

  # 2) ALLOW Codex outbound (optionally constrained to remote ports/addresses)
  Add-AllowOutboundRuleForCodex -ProgramPath $codexPath -NameSuffix ("codex (" + (Split-Path $codexPath -Leaf) + ")")

  # 3) If Codex is a .cmd wrapper, it probably uses node.exe; allow node.exe *but only if we can’t avoid it*
  #    This is a tradeoff: allowing node.exe enables other Node tooling to reach the Internet if the user can run it.
  if ($codexIsCmd -and $nodeCandidates.Count -gt 0) {
    foreach ($n in $nodeCandidates) {
      Add-AllowOutboundRuleForCodex -ProgramPath $n -NameSuffix ("node for codex (" + (Split-Path $n -Leaf) + ")")
    }
  }

  # 4) Session-level hardening (best-effort; not a security boundary)
  #    These reduce accidental egress and credential leakage from tooling that honors env vars.
  $env:NO_PROXY="*"
  $env:HTTP_PROXY="http://127.0.0.1:9"
  $env:HTTPS_PROXY="http://127.0.0.1:9"
  $env:ALL_PROXY="http://127.0.0.1:9"

  # Reduce PowerShell script exposure in this session
  try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy AllSigned -Force | Out-Null } catch { }

  Write-Host "Hardening applied. Firewall rules created in group: $RuleGroup"
  Write-Host "Codex allowed outbound; common tools blocked outbound."
  Write-Host "Codex path: $codexPath"
  if ($codexIsCmd -and $nodeCandidates.Count -gt 0) {
    Write-Host ("Node allowed (Codex wrapper detected): " + ($nodeCandidates -join ", "))
  }
  if ($AllowRemotePorts.Count -gt 0) {
    Write-Host ("Codex outbound restricted to remote ports: " + ($AllowRemotePorts -join ", "))
  }
  if ($AllowRemoteAddresses.Count -gt 0) {
    Write-Host ("Codex outbound restricted to remote addresses: " + ($AllowRemoteAddresses -join ", "))
  }
}

function Start-CodexInCurrentDir {
  # Operational constraint: run in the current directory and avoid inheriting extra proxy config.
  # This is not a filesystem sandbox; it is “best practice hygiene”.
  $cwd = (Get-Location).Path

  # Optional: minimize PATH to reduce tool discovery (can break Codex if it relies on git, etc.)
  # Uncomment if you want to be extremely strict and are prepared to add exceptions.
  # $env:PATH = "$env:WINDIR\System32;$env:WINDIR"

  Write-Host "Starting Codex in: $cwd"
  & codex
}

function Revert-Hardening {
  Assert-Admin
  Remove-RuleGroup
  Write-Host "Hardening reverted. Firewall rules removed from group: $RuleGroup"
}

if ($Revert) {
  Revert-Hardening
  return
}

if ($Apply) {
  Apply-Hardening
  if ($StartCodex) {
    Start-CodexInCurrentDir
  }
}
