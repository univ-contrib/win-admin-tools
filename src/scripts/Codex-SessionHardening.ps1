<#
.SYNOPSIS
  Session-only hardening for the CURRENT PowerShell session:
    - Creates TEMPORARY Windows Defender Firewall rules (removed automatically when you exit this script/session)
    - Blocks outbound network for common escape tools
    - Allows outbound network ONLY for Codex (and optionally its runtime, e.g., node.exe if codex is a .cmd wrapper)
    - Applies process-scope environment hardening (proxies, PATH tightening options)

.DESCRIPTION
  IMPORTANT LIMITATIONS
  - True filesystem “jailing” to only the current directory is not possible purely from a single PowerShell session
    without OS policy (WDAC/AppLocker), Sandbox/VM, or running under a restricted user + ACLs.
  - Network enforcement IS real because it uses Windows Firewall, but Windows Firewall rules are machine-level.
    This script makes them effectively session-scoped by:
      1) tagging them in a unique rule group, and
      2) registering cleanup handlers to remove them on exit (normal exit, Ctrl+C, terminating errors).
    If the machine crashes or PowerShell is killed externally, cleanup might not run; you can revert manually:
      Get-NetFirewallRule | ? Group -like "CodexHardening(Session)*" | Remove-NetFirewallRule

REQUIREMENTS
  - Run as Administrator (to add/remove firewall rules).

USAGE
  # Apply for this session and start codex
  .\Codex-SessionHardening.ps1 -StartCodex

  # Apply for this session only (no start)
  .\Codex-SessionHardening.ps1

  # Optional: restrict Codex to specific remote ports / addresses
  .\Codex-SessionHardening.ps1 -AllowRemotePorts 443 -AllowRemoteAddresses "0.0.0.0/0"
#>

[CmdletBinding()]
param(
  [switch]$StartCodex,
  [int[]]$AllowRemotePorts = @(),
  [string[]]$AllowRemoteAddresses = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator privileges are required. Re-run PowerShell as Administrator."
  }
}

# Unique per invocation so concurrent sessions do not collide
$SessionId  = [Guid]::NewGuid().ToString("N")
$RuleGroup  = "CodexHardening(Session)-$SessionId"
$RulePrefix = "Codex(Session) - "

function Cleanup-FirewallRules {
  try {
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $RuleGroup } |
      Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
  } catch {
    # Swallow cleanup errors to avoid masking original failures.
  }
}

# Ensure cleanup happens on:
# - normal script exit
# - Ctrl+C (ConsoleCancelEvent)
# - terminating errors in this script (trap)
$cleanupRegistered = $false
try {
  $null = Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action { Cleanup-FirewallRules } | Out-Null
  $null = Register-EngineEvent -SourceIdentifier "ConsoleCancelEvent" -Action { Cleanup-FirewallRules } | Out-Null
  $cleanupRegistered = $true
} catch {
  # If event registration fails, we still do best-effort cleanup in finally.
}

trap {
  Cleanup-FirewallRules
  throw
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
  param([Parameter(Mandatory=$true)][string]$Relative)
  $p = Join-Path $env:WINDIR "System32\$Relative"
  if (Test-Path $p) { return $p }
  $p = Join-Path $env:WINDIR "SysWOW64\$Relative"
  if (Test-Path $p) { return $p }
  return $null
}

function Get-PathExeCandidates {
  param([Parameter(Mandatory=$true)][string]$ExeName)
  $results = @()
  try {
    $where = (& where.exe $ExeName 2>$null) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($w in $where) {
      if (Test-Path $w) { $results += $w }
    }
  } catch { }
  $results | Select-Object -Unique
}

function Apply-SessionHardening {
  Assert-Admin

  # Clean any leftovers for this session group (should be none)
  Cleanup-FirewallRules

  # Resolve Codex
  $codexPath = Resolve-ProgramPath "codex"
  if (-not $codexPath) {
    throw "Could not find 'codex' on PATH."
  }

  $codexIsCmd = ([IO.Path]::GetExtension($codexPath).ToLowerInvariant() -eq ".cmd")
  $nodeCandidates = @()
  if ($codexIsCmd) {
    $nodeCandidates = Get-PathExeCandidates "node.exe"
  }

  # Block outbound for common escape / LOLBins / network tools
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

  $blockList += Get-PathExeCandidates "curl.exe"
  $blockList += Get-PathExeCandidates "wget.exe"
  $blockList += Get-PathExeCandidates "git.exe"
  $blockList += Get-PathExeCandidates "python.exe"
  $blockList += Get-PathExeCandidates "python3.exe"
  $blockList += Get-PathExeCandidates "pip.exe"
  $blockList += Get-PathExeCandidates "pip3.exe"

  # NOTE: We only block node.exe if Codex is not using it; otherwise we allow it explicitly below.
  if (-not $codexIsCmd) {
    $blockList += Get-PathExeCandidates "node.exe"
  }

  $blockList = $blockList | Where-Object { $_ } | Select-Object -Unique
  foreach ($p in $blockList) {
    Add-BlockOutboundRule -ProgramPath $p -NameSuffix (Split-Path $p -Leaf)
  }

  # Allow Codex outbound (optionally constrained)
  Add-AllowOutboundRuleForCodex -ProgramPath $codexPath -NameSuffix ("codex (" + (Split-Path $codexPath -Leaf) + ")")

  # If Codex is a wrapper, allow node.exe for this session; tradeoff acknowledged
  if ($codexIsCmd -and $nodeCandidates.Count -gt 0) {
    foreach ($n in $nodeCandidates) {
      Add-AllowOutboundRuleForCodex -ProgramPath $n -NameSuffix ("node for codex (" + (Split-Path $n -Leaf) + ")")
    }
  }

  # Process-scope environment hardening (applies only to this PowerShell process and its children)
  $env:NO_PROXY   = "*"
  $env:HTTP_PROXY = "http://127.0.0.1:9"
  $env:HTTPS_PROXY= "http://127.0.0.1:9"
  $env:ALL_PROXY  = "http://127.0.0.1:9"

  # Optional: reduce accidental tool discovery (can break workflows; keep conservative)
  # $env:PATH = "$env:WINDIR\System32;$env:WINDIR"

  # Reduce script execution surface in this session (best-effort; may be restricted by policy)
  try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy AllSigned -Force | Out-Null } catch { }

  Write-Host "Session hardening ACTIVE."
  Write-Host "Firewall rule group: $RuleGroup"
  Write-Host "Codex allowed outbound; common tools blocked outbound."
  Write-Host "Codex path: $codexPath"
  if ($AllowRemotePorts.Count -gt 0)     { Write-Host ("Remote ports allowed for Codex: " + ($AllowRemotePorts -join ", ")) }
  if ($AllowRemoteAddresses.Count -gt 0) { Write-Host ("Remote addresses allowed for Codex: " + ($AllowRemoteAddresses -join ", ")) }
  if ($codexIsCmd -and $nodeCandidates.Count -gt 0) {
    Write-Host ("Node allowed (Codex wrapper detected): " + ($nodeCandidates -join ", "))
  }

  Write-Host ""
  Write-Host "To end the session policy, close this PowerShell window or press Ctrl+C in the script run."
}

function Start-CodexInCurrentDir {
  $cwd = (Get-Location).Path
  Write-Host "Starting Codex in: $cwd"
  & codex
}

try {
  Apply-SessionHardening

  if ($StartCodex) {
    Start-CodexInCurrentDir
  } else {
    Write-Host "Hardening applied. Run 'codex' from this session when ready."
  }
}
finally {
  # If user chose not to keep an interactive session, cleanup on script completion.
  # If StartCodex was used and codex exits, cleanup will run here.
  # If you want the policy to persist until the user closes the PowerShell window, run:
  #   powershell -NoExit -File .\Codex-SessionHardening.ps1
  Cleanup-FirewallRules
}
