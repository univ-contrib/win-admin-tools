<#
.SYNOPSIS
    Hardens Windows 10 by disabling telemetry, Cortana, Copilot, and unwanted Windows Update behaviors.

.DESCRIPTION
    This script performs a series of inspections and optional changes to reduce telemetry and 
    automatic update behaviors in Windows 10 Pro. All items are inspected, and only those 
    that are not in the desired state are presented to the user for confirmation before applying changes.
    Logging is performed for all actions, including before/after states and items already correct.

.PARAMETER Force
    Automatically approve all changes without prompting.

.PARAMETER Preview
    Inspects and logs all items, but does not apply any changes. Uses a separate preview log.

.PARAMETER Help
    Displays this help message and exits.

.EXAMPLE
    .\Win-Telemetry-Hardening.ps1 -Force
    Applies all changes automatically without user prompts.

.EXAMPLE
    .\Win-Telemetry-Hardening.ps1 -Preview
    Performs inspection only; logs results in a separate preview log file.

.NOTES
    - Must be run as Administrator.
    - Logs all transactions in C:\Windows\TelemetryTransaction.log (or Preview log)
    - Works on Windows 10 Pro/Enterprise/LTSC (Home not fully supported)
    - PowerShell 5+ recommended.

.VERSION
    1.6 - Added final summary table of all changes applied, colored output, and preview log support
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Preview,
    [switch]$Help
)

# ** Parameter validation and help
if ($Help) {
    Write-Host "Win-Telemetry-Hardening.ps1 - Hardens Windows 10 telemetry, Cortana, Copilot, and update behaviors." -ForegroundColor Cyan
    Write-Host "`nUsage:"
    Write-Host "    .\Win-Telemetry-Hardening.ps1 [-Force] [-Preview] [-Help]" -ForegroundColor Cyan
    Write-Host "`nParameters:"
    Write-Host "    -Force     Automatically approve all changes without prompting." -ForegroundColor Cyan
    Write-Host "    -Preview   Inspect and log all changes only, no modifications applied." -ForegroundColor Cyan
    Write-Host "    -Help      Show this help message." -ForegroundColor Cyan
    exit
}

$AllowedParams = @("Force","Preview","Help")
$UnknownParams = $PSBoundParameters.Keys | Where-Object { $_ -notin $AllowedParams }
if ($UnknownParams.Count -gt 0) {
    Write-Host "ERROR: Unknown parameter(s): $($UnknownParams -join ', ')" -ForegroundColor Red
    Write-Host "Usage: .\Win-Telemetry-Hardening.ps1 [-Force] [-Preview] [-Help]" -ForegroundColor Cyan
    exit
}

# ** Script version info
$ScriptVersion = "1.6"
$ScriptRevisionHistory = @(
    "1.6 - Added final summary table, colored output, and preview log",
    "1.5 - Added colored console output",
    "1.4 - Added parameter validation and -Help support",
    "1.3 - Added -Force and -Preview parameters",
    "1.2 - Parameter validation and pre-flight checks",
    "1.1 - Initial version with user validation and changes"
)

# ** Pre-flight checks

# PowerShell version check (require 5.1+)
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "ERROR: PowerShell 5.1+ required. Current: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}

# Administrator check
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "ERROR: Must run as Administrator." -ForegroundColor Red
    exit 1
}

# ** Set log file
$TransactionLogFile = "C:\Windows\TelemetryTransaction.log"
$PreviewLogFile = "C:\Windows\TelemetryTransaction_Preview.log"
if ($Preview) { $LogFile = $PreviewLogFile } else { $LogFile = $TransactionLogFile }

$modeText = if ($Preview) { "PREVIEW MODE (no changes applied)" } else { "EXECUTION MODE" }

# ** Logging function
Function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Before","After","Already","Audit")] [string]$State
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$Timestamp - [$State] $Message"
    Add-Content -Path $LogFile -Value $Entry

    switch ($State) {
        "Before" { Write-Host "[Before] $Message" -ForegroundColor Yellow }
        "After" { Write-Host "[After] $Message" -ForegroundColor Green }
        "Already" { Write-Host "[Already] $Message" -ForegroundColor DarkYellow }
        "Audit" { Write-Host "[Audit] $Message" -ForegroundColor Cyan }
    }
}

Write-Log "=== Win-Telemetry-Hardening Script Version $ScriptVersion Started - $modeText ===" -State "Audit"

# ** Helper Functions
Function Get-RegistryValue {
    param([string]$Path,[string]$Name)
    if (Test-Path $Path) {
        return (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue) 
    } else { 
        return $null 
    }
}

# ** Track executed changes
$ExecutedChanges = @()
# ** Define all items to inspect
$AllChanges = @()

# ** Registry keys to update
$registryChanges = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0; Desc="Telemetry Level"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"; Value=0; Desc="Cortana Disable"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name="TurnOffWindowsCopilot"; Value=1; Desc="Copilot Disable (LM)"},
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"; Name="TurnOffWindowsCopilot"; Value=1; Desc="Copilot Disable (CU)"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; Value=1; Desc="Disable Windows Update Auto"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DisableOSUpgrade"; Value=1; Desc="Disable OS Upgrade"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ElevateNonAdmins"; Value=0; Desc="Prevent Windows Update elevation"}
)
foreach ($reg in $registryChanges) {
    $current = Get-RegistryValue -Path $reg.Path -Name $reg.Name
    if ($current -ne $reg.Value) {
        $AllChanges += @{Type="Registry"; Path=$reg.Path; Name=$reg.Name; DesiredValue=$reg.Value; Desc=$reg.Desc; CurrentValue=$current; NeedsChange=$true}
    } else {
        Write-Log "$($reg.Desc): Already at desired value $($reg.Value)" -State "Already"
        $AllChanges += @{Type="Registry"; Path=$reg.Path; Name=$reg.Name; DesiredValue=$reg.Value; Desc=$reg.Desc; CurrentValue=$current; NeedsChange=$false}
    }
}

# ** Services to update
$serviceChanges = @(
    @{Name="DiagTrack"; Status="Stopped"; StartType="Disabled"; Desc="Telemetry Service"},
    @{Name="dmwappushservice"; Status="Stopped"; StartType="Disabled"; Desc="WAP Push Service"},
    @{Name="wuauserv"; Status="Stopped"; StartType="Disabled"; Desc="Windows Update Service"},
    @{Name="UsoSvc"; Status="Stopped"; StartType="Disabled"; Desc="Update Orchestrator Service"}
)
foreach ($s in $serviceChanges) {
    $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
    $currentStatus = if ($svc) { $svc.Status } else { "Not found" }
    $currentStart = if ($svc) { $svc.StartType } else { "N/A" }
    if ($currentStatus -ne $s.Status -or $currentStart -ne $s.StartType) {
        $AllChanges += @{Type="Service"; Name=$s.Name; DesiredStatus=$s.Status; DesiredStartType=$s.StartType; Desc=$s.Desc; CurrentStatus=$currentStatus; CurrentStartType=$currentStart; NeedsChange=$true}
    } else {
        Write-Log "$($s.Desc): Already at desired state Status=$currentStatus, StartType=$currentStart" -State "Already"
        $AllChanges += @{Type="Service"; Name=$s.Name; DesiredStatus=$s.Status; DesiredStartType=$s.StartType; Desc=$s.Desc; CurrentStatus=$currentStatus; CurrentStartType=$currentStart; NeedsChange=$false}
    }
}

# ** Tasks to disable
$taskChanges = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\UpdateOrchestrator\Scheduled Start",
    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot"
)
foreach ($t in $taskChanges) {
    $exists = schtasks /Query /TN $t /V 2>$null
    if ($exists) {
        $AllChanges += @{Type="Task"; TaskName=$t; CurrentState="Enabled"; NeedsChange=$true}
    } else {
        Write-Log "Task ${t}: Already disabled or not present" -State "Already"
        $AllChanges += @{Type="Task"; TaskName=$t; CurrentState="Disabled or Not Found"; NeedsChange=$false}
    }
}

# ** Prompt user only for items that need change (Force skips prompts)
$ApprovedChanges = @()
foreach ($item in $AllChanges | Where-Object { $_.NeedsChange }) {
    if ($Force) {
        $ApprovedChanges += $item
        continue 
    }

    switch ($item.Type) {
        "Registry" {
            $prompt = "Registry '$($item.Desc)': Current='$($item.CurrentValue)', Desired='$($item.DesiredValue)'. Apply change? (Y/N)" 
        }
        "Service" { 
            $prompt = "Service '$($item.Desc)': Current Status=$($item.CurrentStatus), StartType=$($item.CurrentStartType), Desired Status=$($item.DesiredStatus), StartType=$($item.DesiredStartType). Apply change? (Y/N)" 
        }
        "Task" { 
            $prompt = "Task '$($item.TaskName)': Current=$($item.CurrentState), Desired=Disabled. Apply change? (Y/N)" 
        }
    }

    $resp = Read-Host $prompt
    if ($resp -match "^[Yy]$") { $ApprovedChanges += $item }
}

# ** Preview mode: show summary and exit
if ($Preview) {
    Write-Host "`nPreview mode active. No changes will be applied." -ForegroundColor Cyan
    Write-Host "The following changes would have been applied:" -ForegroundColor Cyan
    foreach ($c in $ApprovedChanges) {
        switch ($c.Type) {
            "Registry" { Write-Host "Registry: $($c.Desc) -> $($c.DesiredValue)" -ForegroundColor Yellow }
            "Service" { Write-Host "Service: $($c.Desc) -> Status=$($c.DesiredStatus), StartType=$($c.DesiredStartType)" -ForegroundColor Yellow }
            "Task" { Write-Host "Task: $($c.TaskName) -> Disabled" -ForegroundColor Yellow }
        }
    }
    Write-Log "Preview mode: no changes applied. Items inspected: $($ApprovedChanges.Count)" -State "Audit"
    exit
}

# ** Show summary and final confirmation (if not Force)
if (-not $Force) {
    if ($ApprovedChanges.Count -eq 0) { 
        Write-Host "No changes selected. Exiting." -ForegroundColor Cyan; 
        Write-Log "No changes selected by user" -State "Already" 
        exit
    }

    Write-Host "`nYou have approved the following changes:"
    foreach ($c in $ApprovedChanges) {
        switch ($c.Type) {
            "Registry" { Write-Host "Registry: $($c.Desc) -> $($c.DesiredValue)" }
            "Service" { Write-Host "Service: $($c.Desc) -> Status=$($c.DesiredStatus), StartType=$($c.DesiredStartType)" }
            "Task" { Write-Host "Task: $($c.TaskName) -> Disabled" }
        }
    }

    $final = Read-Host "Apply all approved changes? (Y/N)"
    if ($final -notmatch "^[Yy]$") { Write-Host "Changes cancelled by user." -ForegroundColor Red; exit }
}

# ** Execute approved changes
foreach ($change in $ApprovedChanges) {
    switch ($change.Type) {
        "Registry" {
            $before = $change.CurrentValue; $after = $change.DesiredValue
            Write-Log "$($change.Desc): Current=$before, Desired=$after" -State "Before"
            if (!(Test-Path $change.Path)) { New-Item -Path $change.Path -Force | Out-Null }
            Set-ItemProperty -Path $change.Path -Name $change.Name -Value $after
            Write-Log "$($change.Desc): Changed to $after" -State "After"
            $ExecutedChanges += [PSCustomObject]@{Type="Registry"; Desc=$change.Desc; Before=$before; After=$after}
        }
        "Service" {
            $beforeStatus = $change.CurrentStatus; $beforeStart = $change.CurrentStartType
            if ($change.DesiredStatus -eq "Stopped") { Stop-Service -Name $change.Name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $change.Name -StartupType $change.DesiredStartType -ErrorAction SilentlyContinue
            $svcUpdated = Get-Service -Name $change.Name -ErrorAction SilentlyContinue
            $statusUpdated = if ($svcUpdated) { $svcUpdated.Status } else { "Not found" }
            $startUpdated = if ($svcUpdated) { $svcUpdated.StartType } else { "N/A" }
            Write-Log "$($change.Desc): Status=$statusUpdated, StartType=$startUpdated" -State "After"
            $ExecutedChanges += [PSCustomObject]@{Type="Service"; Desc=$change.Desc; Before="Status=$beforeStatus, StartType=$beforeStart"; After="Status=$statusUpdated, StartType=$startUpdated"}
        }
        "Task" {
            $before = $change.CurrentState
            schtasks /Change /TN $change.TaskName /Disable 2>$null
            $after = "Disabled"
            Write-Log "Task ${($change.TaskName)} disabled" -State "After"
            $ExecutedChanges += [PSCustomObject]@{Type="Task"; Desc=$change.TaskName; Before=$before; After=$after}
        }
    }
}

# ** Final summary table
Write-Host "`n=== Changes Summary ===" -ForegroundColor Cyan
$ExecutedChanges | Format-Table @{Label="Type";Expression={$_.Type};Width=10},
                                @{Label="Description";Expression={$_.Desc};Width=50},
                                @{Label="Before";Expression={$_.Before};Width=30},
                                @{Label="After";Expression={$_.After};Width=30} -AutoSize

foreach ($c in $ExecutedChanges) {
    Write-Log "$($c.Type) | $($c.Desc) | Before: $($c.Before) | After: $($c.After)" -State "Audit"
}

Write-Log "=== Win-Telemetry-Hardening Script Version $ScriptVersion Completed ===" -State "After"
Write-Host "All approved changes executed. Transaction log at $LogFile" -ForegroundColor Green
