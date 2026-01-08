<#
.SYNOPSIS
    Queries a hostname via DNS repeatedly using primary and backup servers, logging the results with timestamps.

.DESCRIPTION
    Resolves the specified hostname using the primary DNS server. If no result is returned, it retries using the backup DNS server.
    Each query is logged with timestamp, which DNS server responded, and the resulting IP(s). Runs in a loop until manually stopped.

.PARAMETER Hostname
    The hostname to query. Example: stream01.mooo.com

.PARAMETER PrimaryDnsServer
    The primary DNS server to query. Example: 8.8.8.8

.PARAMETER BackupDnsServer
    The backup DNS server to query if primary fails. Example: 1.1.1.1

.PARAMETER IntervalSeconds
    Number of seconds to wait between queries. Default is 5.

.PARAMETER LogFile
    Path to a file where results are logged. Default is Remap-SmbShares.log in the script folder.

.EXAMPLE
    .\DnsQueryLoop.ps1 -Hostname stream01.mooo.com -PrimaryDnsServer 8.8.8.8 -BackupDnsServer 1.1.1.1 -IntervalSeconds 1 -LogFile .\dns.log

.NOTES
    Requires PowerShell 5+. The script uses the external 'dig' utility.

.VERSION
    1.7 - Fixed DNS timeout detection to correctly trigger backup DNS
#>

# ** Parameters with positional support
param(
    [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()][string]$Hostname,
    [Parameter(Mandatory=$true, Position=1)][ValidateNotNullOrEmpty()][string]$PrimaryDnsServer,
    [Parameter(Mandatory=$true, Position=2)][ValidateNotNullOrEmpty()][string]$BackupDnsServer,
    [Parameter(Mandatory=$false, Position=3)][ValidateNotNullOrEmpty()][int]$IntervalSeconds = 5,
    [Parameter(Mandatory=$false, Position=4)][ValidateNotNullOrEmpty()][string]$LogFile = "$PSScriptRoot\DnsQueryLoop.log"
)

# ** Script version info
$ScriptVersion = "1.6"  # Current version
$ScriptRevisionHistory = @(
    "1.1 - Initial version with primary/backup DNS fallback, timestamped logging",
    "1.2 - Added console parameter printout",
    "1.3 - Added column headers in console output",
    "1.4 - Added log file creation with header (optional)",
    "1.5 - Parameter validation and default values cleaned up",
    "1.6 - Added positional parameters support"
    "1.7 - Fixed DNS timeout detection to correctly trigger backup DNS"
)

# ** Print input parameters and version
Write-Host "DNS Query Loop - Script Version: $ScriptVersion using params"
Write-Host "  Hostname          : $Hostname"
Write-Host "  Primary DNS       : $PrimaryDnsServer"
Write-Host "  Backup DNS        : $BackupDnsServer"
Write-Host "  Query Interval(s) : $IntervalSeconds"
Write-Host "  Log File          : $LogFile"
Write-Host ("{0,-23} {1,-15} {2,-20} {3}" -f "Timestamp", "DNS", "Hostname", "Result")
Write-Host ("{0,-23} {1,-15} {2,-20} {3}" -f "---------", "---", "--------", "------")

# ** Main loop
while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

    # Query primary DNS
    $dnsResult = dig "@$PrimaryDnsServer" +short $Hostname 2>&1

    if (-not $dnsResult -or $dnsResult -match "timed out|no servers could be reached") {
        $dnsResult = dig "@$BackupDnsServer" +short $Hostname 2>&1
        $dnsUsed = $BackupDnsServer
    } else {
        $dnsUsed = $PrimaryDnsServer
    }

    # Prepare output line
    $outputLine = ("{0,-23} {1,-15} {2,-20} {3}" -f $timestamp, $dnsUsed, $Hostname, $dnsResult)

    # Write to console and log file
    Write-Output $outputLine
    $outputLine | Out-File -FilePath $LogFile -Append -Encoding UTF8

    Start-Sleep -Seconds $IntervalSeconds
}
