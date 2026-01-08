<#
.SYNOPSIS
    Remaps all SMB shares from an old hostname to a new hostname for the current user, with logging and prechecks.

.DESCRIPTION
    This script scans all current SMB client mappings (both drive-letter and UNC-only) 
    that reference the old hostname, removes them, and recreates them using the new hostname. 
    It preserves persistence and existing drive letters. All actions are logged.

.PARAMETER OldName
    The current/old hostname of the SMB server. Example: OLDNAME

.PARAMETER NewName
    The new hostname of the SMB server. Example: NEWNAME

.EXAMPLE
    .\Remap-SmbShares.ps1 -OldName OLDNAME -NewName NEWNAME

.NOTES
    - Requires PowerShell 5+ (Get-SmbMapping cmdlet available)
    - Affects the current user only
    - Persistent mappings are preserved
    - If credentials are cached for OLDNAME, remove them with:
        cmdkey /delete:OLDNAME
    - Logs are written to the current directory: Remap-SmbShares.log
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OldName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$NewName
)

# -----------------------------
# Execution Precheck: PowerShell 5+
# -----------------------------
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: This script requires PowerShell 5.0 or higher. Detected version: $($PSVersionTable.PSVersion)"
    exit 1
}

# -----------------------------
# Logging Setup
# -----------------------------
$LogFile = Join-Path -Path $PSScriptRoot -ChildPath "Remap-SmbShares.log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    # Write to console
    Write-Host $logEntry
    # Append to log file
    Add-Content -Path $LogFile -Value $logEntry
}

Write-Log "Starting remap from '$OldName' to '$NewName'"

# -----------------------------
# Enumerate existing SMB mappings
# -----------------------------
try {
    $mappings = Get-SmbMapping | Where-Object {
        $_.RemotePath -match "(?i)\\\\$OldName\\"
    }
} catch {
    Write-Log "ERROR: Failed to enumerate SMB mappings. $_" "ERROR"
    exit 1
}

if (-not $mappings) {
    Write-Log "No mappings found for $OldName"
    exit 0
}

# -----------------------------
# Remap each mapping
# -----------------------------
foreach ($map in $mappings) {

    $oldPath = $map.RemotePath
    $newPath = $oldPath -replace "(?i)\\\\$OldName\\", "\\$NewName\"

    Write-Log "Remapping: $oldPath -> $newPath"

    try {
        # Remove existing mapping
        if ($map.LocalPath) {
            Remove-SmbMapping -LocalPath $map.LocalPath -Force -UpdateProfile
            Write-Log "Removed mapping for drive $($map.LocalPath)"
        } else {
            Remove-SmbMapping -RemotePath $oldPath -Force
            Write-Log "Removed UNC mapping $oldPath"
        }
    } catch {
        Write-Log "ERROR: Failed to remove mapping $oldPath. $_" "ERROR"
        continue
    }

    try {
        # Recreate mapping
        if ($map.LocalPath) {
            New-SmbMapping -LocalPath $map.LocalPath -RemotePath $newPath -Persistent $map.Persistent -ErrorAction Stop
            Write-Log "Created mapping $($map.LocalPath) -> $newPath"
        } else {
            New-SmbMapping -RemotePath $newPath -Persistent $map.Persistent -ErrorAction Stop
            Write-Log "Created UNC mapping $newPath"
        }
    } catch {
        Write-Log "ERROR: Failed to create mapping $newPath. $_" "ERROR"
        continue
    }
}

Write-Log "Remapping complete."