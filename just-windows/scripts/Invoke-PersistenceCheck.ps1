<#
.SYNOPSIS
    Comprehensive Windows Persistence Detection using Sysinternals Autoruns

.DESCRIPTION
    Detects persistence mechanisms and backdoors on Windows systems using autorunsc64.exe.
    Compares current autorun entries with baseline backup to identify new/modified entries.
    Flags unsigned binaries, VirusTotal hits, and suspicious locations.

    Covers 20+ persistence categories including:
    - Run/RunOnce keys
    - Services and drivers
    - Scheduled tasks
    - Winlogon
    - AppInit_DLLs
    - Image File Execution Options (IFEO)
    - Print monitors
    - WMI event consumers
    - COM hijacking
    - LSA providers
    - Boot execute
    - And more...

.PARAMETER BaselineFile
    Path to baseline autorunsc CSV file. If not specified, uses latest backup.

.PARAMETER OutputFile
    Path to save current autorunsc scan results (CSV format)

.PARAMETER CompareWithBackup
    Compare current state with backup baseline

.PARAMETER VirusTotalCheck
    Enable VirusTotal hash lookups (requires internet connection)

.PARAMETER ShowAll
    Show all entries, not just new/changed ones

.PARAMETER ExportOnly
    Only export current state, don't compare with baseline

.EXAMPLE
    .\Invoke-PersistenceCheck.ps1
    Run persistence check and compare with backup baseline

.EXAMPLE
    .\Invoke-PersistenceCheck.ps1 -VirusTotalCheck
    Run with VirusTotal hash checking

.EXAMPLE
    .\Invoke-PersistenceCheck.ps1 -ExportOnly
    Export current state without comparison

.NOTES
    Requires Sysinternals autorunsc64.exe
    PowerShell 3.0+ compatible
    Administrator privileges recommended for complete scan
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$BaselineFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile,

    [Parameter(Mandatory=$false)]
    [switch]$CompareWithBackup = $true,

    [Parameter(Mandatory=$false)]
    [switch]$VirusTotalCheck,

    [Parameter(Mandatory=$false)]
    [switch]$ShowAll,

    [Parameter(Mandatory=$false)]
    [switch]$ExportOnly
)

# Configuration
$BaseDir = if ($env:KK_BASE_DIR) { $env:KK_BASE_DIR } else { "C:\KeyboardKowboys" }
$BackupRoot = if ($env:KK_BACKUP_DIR) { $env:KK_BACKUP_DIR } else { "$BaseDir\backups" }
$LogDir = if ($env:KK_LOG_DIR) { $env:KK_LOG_DIR } else { "$BaseDir\logs" }
$ToolsDir = if ($env:KK_TOOLS_DIR) { $env:KK_TOOLS_DIR } else { "$BaseDir\tools\sysinternals" }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = if ($OutputFile) { $OutputFile } else { "$LogDir\persistence_check_$timestamp.csv" }

# Ensure directories exist
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

# Function to write colored output
function Write-ColorOutput {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to find autorunsc64.exe
function Find-Autorunsc {
    # Check common locations
    $locations = @(
        "$ToolsDir\autorunsc64.exe",
        "$ToolsDir\autorunsc.exe",
        "C:\Tools\SysinternalsSuite\autorunsc64.exe",
        "C:\SysinternalsSuite\autorunsc64.exe",
        "$env:ProgramFiles\SysinternalsSuite\autorunsc64.exe"
    )

    foreach ($location in $locations) {
        if (Test-Path $location) {
            Write-ColorOutput "Found autorunsc at: $location" "Green"
            return $location
        }
    }

    # Try to find in PATH
    $autorunsc = Get-Command autorunsc64.exe -ErrorAction SilentlyContinue
    if ($autorunsc) {
        Write-ColorOutput "Found autorunsc64.exe in PATH: $($autorunsc.Source)" "Green"
        return $autorunsc.Source
    }

    $autorunsc = Get-Command autorunsc.exe -ErrorAction SilentlyContinue
    if ($autorunsc) {
        Write-ColorOutput "Found autorunsc.exe in PATH: $($autorunsc.Source)" "Green"
        return $autorunsc.Source
    }

    Write-ColorOutput "ERROR: autorunsc64.exe not found" "Red"
    Write-ColorOutput "Please install Sysinternals Suite to $ToolsDir" "Yellow"
    Write-ColorOutput "Download from: https://live.sysinternals.com/autorunsc64.exe" "Yellow"
    return $null
}

# Function to run autorunsc scan
function Invoke-AutorunscScan {
    param (
        [string]$AutorunscPath,
        [string]$OutputPath,
        [switch]$EnableVirusTotal
    )

    Write-ColorOutput "`n=== Running Autorunsc Scan ===" "Cyan"
    Write-ColorOutput "This may take several minutes..." "Yellow"

    # Build command line arguments
    $args = @(
        "-accepteula",  # Accept EULA
        "-a", "*",      # All categories
        "-c",           # CSV output
        "-h",           # Show file hashes
        "-s",           # Verify digital signatures
        "-nobanner"     # No banner (CSV compatibility)
    )

    # Add VirusTotal check if enabled
    if ($EnableVirusTotal) {
        $args += "-v"   # VirusTotal hash lookup
        $args += "-vt"  # Accept VirusTotal ToS
        Write-ColorOutput "VirusTotal checking enabled (may be slow)" "Yellow"
    }

    # Add user profile scanning
    $args += "*"  # All user profiles

    try {
        Write-ColorOutput "Running: $AutorunscPath $($args -join ' ')" "Gray"

        # Run autorunsc and capture output
        $output = & $AutorunscPath $args 2>&1

        # Save to file
        $output | Out-File -FilePath $OutputPath -Encoding UTF8

        Write-ColorOutput "Scan complete: $OutputPath" "Green"

        # Parse CSV to get entry count
        $entries = Import-Csv -Path $OutputPath -ErrorAction SilentlyContinue
        if ($entries) {
            Write-ColorOutput "Found $($entries.Count) autorun entries" "Cyan"
        }

        return $true
    }
    catch {
        Write-ColorOutput "ERROR running autorunsc: $_" "Red"
        return $false
    }
}

# Function to find baseline file
function Find-BaselineFile {
    Write-ColorOutput "`nLooking for baseline file..." "Cyan"

    # Check if baseline file was specified
    if ($BaselineFile -and (Test-Path $BaselineFile)) {
        Write-ColorOutput "Using specified baseline: $BaselineFile" "Green"
        return $BaselineFile
    }

    # Search for latest autorunsc backup
    $searchPaths = @(
        "$BackupRoot\all\latest\system_info\autorunsc.csv",
        "$BackupRoot\all\*\system_info\autorunsc.csv"
    )

    foreach ($pattern in $searchPaths) {
        $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1

        if ($found) {
            Write-ColorOutput "Found baseline: $($found.FullName)" "Green"
            return $found.FullName
        }
    }

    Write-ColorOutput "WARNING: No baseline file found" "Yellow"
    Write-ColorOutput "Run 'just backup' first to create a baseline" "Yellow"
    return $null
}

# Function to compare current scan with baseline
function Compare-WithBaseline {
    param (
        [string]$CurrentFile,
        [string]$BaselineFile
    )

    Write-ColorOutput "`n=== Comparing with Baseline ===" "Cyan"

    try {
        # Import CSV files
        $current = Import-Csv -Path $CurrentFile -ErrorAction Stop
        $baseline = Import-Csv -Path $BaselineFile -ErrorAction Stop

        Write-ColorOutput "Current entries: $($current.Count)" "Gray"
        Write-ColorOutput "Baseline entries: $($baseline.Count)" "Gray"

        # Create hashtables for faster lookup (using Entry Location as key)
        $baselineHash = @{}
        foreach ($entry in $baseline) {
            $key = "$($entry.'Entry Location')::$($entry.'Entry')"
            $baselineHash[$key] = $entry
        }

        # Find new and modified entries
        $newEntries = @()
        $modifiedEntries = @()

        foreach ($entry in $current) {
            $key = "$($entry.'Entry Location')::$($entry.'Entry')"

            if (-not $baselineHash.ContainsKey($key)) {
                # New entry
                $newEntries += $entry
            }
            else {
                # Check if modified (compare MD5/SHA1/SHA256)
                $baseEntry = $baselineHash[$key]
                if ($entry.MD5 -ne $baseEntry.MD5 -or
                    $entry.'Image Path' -ne $baseEntry.'Image Path') {
                    $modifiedEntries += $entry
                }
            }
        }

        # Find removed entries
        $currentHash = @{}
        foreach ($entry in $current) {
            $key = "$($entry.'Entry Location')::$($entry.'Entry')"
            $currentHash[$key] = $entry
        }

        $removedEntries = @()
        foreach ($entry in $baseline) {
            $key = "$($entry.'Entry Location')::$($entry.'Entry')"
            if (-not $currentHash.ContainsKey($key)) {
                $removedEntries += $entry
            }
        }

        # Display results
        Write-ColorOutput "`n=== PERSISTENCE CHECK RESULTS ===" "Cyan"
        Write-ColorOutput "New entries: $($newEntries.Count)" "Yellow"
        Write-ColorOutput "Modified entries: $($modifiedEntries.Count)" "Yellow"
        Write-ColorOutput "Removed entries: $($removedEntries.Count)" "Yellow"

        # Flag suspicious entries
        $suspicious = @()

        # Check new entries for unsigned binaries and suspicious locations
        foreach ($entry in $newEntries) {
            $isSuspicious = $false
            $reasons = @()

            # Check if unsigned
            if ($entry.Publisher -eq '' -or $entry.Publisher -eq '(Verified)' -or $entry.Publisher -like '*not verified*') {
                $isSuspicious = $true
                $reasons += "UNSIGNED"
            }

            # Check for suspicious paths
            $suspiciousPaths = @('\Temp\', '\AppData\Local\Temp\', '\Users\Public\', '\ProgramData\', 'C:\Windows\Temp\')
            foreach ($path in $suspiciousPaths) {
                if ($entry.'Image Path' -like "*$path*") {
                    $isSuspicious = $true
                    $reasons += "SUSPICIOUS_PATH:$path"
                    break
                }
            }

            # Check VirusTotal results if available
            if ($entry.'VT detection' -and $entry.'VT detection' -ne '0/0' -and $entry.'VT detection' -ne '') {
                $isSuspicious = $true
                $reasons += "VT_DETECTION:$($entry.'VT detection')"
            }

            if ($isSuspicious) {
                $suspicious += [PSCustomObject]@{
                    Entry = $entry
                    Reasons = $reasons -join ", "
                }
            }
        }

        # Display new entries
        if ($newEntries.Count -gt 0) {
            Write-ColorOutput "`n!!! NEW AUTORUN ENTRIES DETECTED !!!" "Red"
            Write-ColorOutput "The following entries were not in the baseline:" "Yellow"

            foreach ($entry in $newEntries) {
                $color = "Yellow"
                $prefix = "[NEW]"

                # Check if this entry is suspicious
                $suspEntry = $suspicious | Where-Object { $_.Entry -eq $entry }
                if ($suspEntry) {
                    $color = "Red"
                    $prefix = "[NEW-SUSPICIOUS]"
                }

                Write-ColorOutput "`n$prefix" $color
                Write-ColorOutput "  Location: $($entry.'Entry Location')" $color
                Write-ColorOutput "  Entry: $($entry.'Entry')" $color
                Write-ColorOutput "  Path: $($entry.'Image Path')" $color
                Write-ColorOutput "  Publisher: $($entry.Publisher)" $color

                if ($suspEntry) {
                    Write-ColorOutput "  REASONS: $($suspEntry.Reasons)" "Red"
                }
            }
        }

        # Display modified entries
        if ($modifiedEntries.Count -gt 0) {
            Write-ColorOutput "`n!!! MODIFIED AUTORUN ENTRIES DETECTED !!!" "Red"

            foreach ($entry in $modifiedEntries) {
                Write-ColorOutput "`n[MODIFIED]" "Yellow"
                Write-ColorOutput "  Location: $($entry.'Entry Location')" "Yellow"
                Write-ColorOutput "  Entry: $($entry.'Entry')" "Yellow"
                Write-ColorOutput "  Path: $($entry.'Image Path')" "Yellow"
            }
        }

        # Display removed entries
        if ($removedEntries.Count -gt 0 -and $ShowAll) {
            Write-ColorOutput "`n[REMOVED ENTRIES]" "Gray"
            Write-ColorOutput "Removed entries: $($removedEntries.Count)" "Gray"
        }

        # Display suspicious summary
        if ($suspicious.Count -gt 0) {
            Write-ColorOutput "`n!!! CRITICAL: $($suspicious.Count) SUSPICIOUS ENTRIES DETECTED !!!" "Red"
            Write-ColorOutput "Review the entries above marked as [NEW-SUSPICIOUS]" "Red"
        }
        else {
            Write-ColorOutput "`nNo obviously suspicious entries detected" "Green"
        }

        # Summary
        Write-ColorOutput "`n=== SUMMARY ===" "Cyan"
        if ($newEntries.Count -eq 0 -and $modifiedEntries.Count -eq 0 -and $removedEntries.Count -eq 0) {
            Write-ColorOutput "System matches baseline - no persistence changes detected" "Green"
        }
        else {
            Write-ColorOutput "Changes detected - review entries above" "Yellow"
            if ($suspicious.Count -gt 0) {
                Write-ColorOutput "CRITICAL: Suspicious entries require immediate investigation" "Red"
            }
        }

        # Save detailed comparison report
        $reportFile = "$LogDir\persistence_report_$timestamp.txt"
        $report = @"
=== PERSISTENCE CHECK REPORT ===
Generated: $(Get-Date)
Baseline: $BaselineFile
Current: $CurrentFile

SUMMARY:
- New entries: $($newEntries.Count)
- Modified entries: $($modifiedEntries.Count)
- Removed entries: $($removedEntries.Count)
- Suspicious entries: $($suspicious.Count)

NEW ENTRIES:
$($newEntries | ForEach-Object { "  [$($_.\ 'Entry Location')] $($_.Entry) -> $($_.'Image Path')" } | Out-String)

MODIFIED ENTRIES:
$($modifiedEntries | ForEach-Object { "  [$($_.'Entry Location')] $($_.Entry) -> $($_.'Image Path')" } | Out-String)

SUSPICIOUS ENTRIES:
$($suspicious | ForEach-Object { "  [$($_. Entry.'Entry Location')] $($_.Entry.Entry) -> $($_.Entry.'Image Path') [REASONS: $($_.Reasons)]" } | Out-String)
"@

        $report | Out-File -FilePath $reportFile -Encoding UTF8
        Write-ColorOutput "`nDetailed report saved to: $reportFile" "Cyan"

    }
    catch {
        Write-ColorOutput "ERROR comparing files: $_" "Red"
    }
}

# Main execution
Write-ColorOutput "=== Keyboard Kowboys Persistence Detection ===" "Cyan"
Write-ColorOutput "Using Sysinternals Autorunsc" "Cyan"

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-ColorOutput "WARNING: Not running as Administrator" "Yellow"
    Write-ColorOutput "Some persistence mechanisms may not be detected" "Yellow"
}

# Find autorunsc
$autorunscPath = Find-Autorunsc
if (-not $autorunscPath) {
    exit 1
}

# Run autorunsc scan
$scanSuccess = Invoke-AutorunscScan -AutorunscPath $autorunscPath -OutputPath $OutputFile -EnableVirusTotal:$VirusTotalCheck
if (-not $scanSuccess) {
    exit 1
}

# If export-only mode, we're done
if ($ExportOnly) {
    Write-ColorOutput "`nExport complete: $OutputFile" "Green"
    Write-ColorOutput "This can be used as a baseline for future comparisons" "Cyan"
    exit 0
}

# Compare with baseline if requested
if ($CompareWithBackup) {
    $baselinePath = Find-BaselineFile

    if ($baselinePath) {
        Compare-WithBaseline -CurrentFile $OutputFile -BaselineFile $baselinePath
    }
    else {
        Write-ColorOutput "`nNo baseline found - showing current state only" "Yellow"
        Write-ColorOutput "Current autorunsc output saved to: $OutputFile" "Cyan"
        Write-ColorOutput "Run 'just backup' to create a baseline for future comparisons" "Yellow"
    }
}
else {
    Write-ColorOutput "`nCurrent autorunsc output saved to: $OutputFile" "Cyan"
}

Write-ColorOutput "`nPersistence check complete" "Green"
