<#
.SYNOPSIS
    System State Diff Tool - Compare current Windows system state with backup baseline

.DESCRIPTION
    PowerShell 3.0+ compatible script for comparing current system state with backup snapshots.
    Provides deep comparison of ports, processes, services, registry keys, scheduled tasks, and more.
    Designed for CCDC competitions to quickly identify changes and potential compromises.

.PARAMETER Target
    The diff target: all, ports, connections, processes, services, users, registry, tasks, configs, files

.PARAMETER SystemType
    The backup system type to compare against (default: "all")

.PARAMETER BackupDate
    Specific backup date to compare against (default: latest)

.PARAMETER LogFile
    Path to log file

.PARAMETER Verbose
    Enable verbose output

.PARAMETER NoColor
    Disable colored output

.PARAMETER Files
    Specific files to compare (only used with -Target files)

.EXAMPLE
    .\Invoke-Diff.ps1 all
    Compare all categories against latest backup

.EXAMPLE
    .\Invoke-Diff.ps1 ports -SystemType network
    Compare network ports against network backup

.EXAMPLE
    .\Invoke-Diff.ps1 registry
    Compare critical registry keys against backup

.NOTES
    PowerShell 3.0+ compatible
    Requires Administrator privileges for full functionality
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("all", "ports", "connections", "processes", "services", "users", "registry", "tasks", "configs", "files", "shares", "firewall")]
    [string]$Target,

    [Parameter(Mandatory=$false)]
    [string]$SystemType = "all",

    [Parameter(Mandatory=$false)]
    [string]$BackupDate,

    [Parameter(Mandatory=$false)]
    [string]$LogFile,

    [Parameter(Mandatory=$false)]
    [switch]$Verbose,

    [Parameter(Mandatory=$false)]
    [switch]$NoColor,

    [Parameter(Mandatory=$false)]
    [string[]]$Files
)

# Default configuration
$BaseDir = if ($env:KK_BASE_DIR) { $env:KK_BASE_DIR } else { "C:\KeyboardKowboys" }
$BackupRoot = if ($env:KK_BACKUP_DIR) { $env:KK_BACKUP_DIR } else { "$BaseDir\backups" }
$LogDir = if ($env:KK_LOG_DIR) { $env:KK_LOG_DIR } else { "$BaseDir\logs" }
$LogFile = if ($LogFile) { $LogFile } else { "$LogDir\diff.log" }
$TempDir = "$env:TEMP\system_diff_$(Get-Random)"
$UseColor = -not $NoColor

# Function to write log messages
function Write-Log {
    param (
        [string]$Level,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Create log directory if it doesn't exist
    $logDirPath = Split-Path -Parent $LogFile
    if (-not (Test-Path $logDirPath)) {
        New-Item -Path $logDirPath -ItemType Directory -Force | Out-Null
    }

    # Write to log file
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue

    # Write to console if verbose or error
    if ($Verbose -or $Level -eq "ERROR") {
        if ($UseColor) {
            switch ($Level) {
                "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
                "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
                "INFO"    { Write-Host $logMessage -ForegroundColor Cyan }
                default   { Write-Host $logMessage }
            }
        } else {
            Write-Host $logMessage
        }
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to output diff results
function Write-DiffOutput {
    param (
        [string]$Title,
        [string]$Content
    )

    $separator = "=" * 60
    $header = "=== $Title ==="

    Write-Host ""
    Write-Host $separator -ForegroundColor Gray
    Write-Host $header -ForegroundColor Yellow
    Write-Host $separator -ForegroundColor Gray
    Write-Host $Content
}

# Function to compare two arrays and show differences
function Compare-Arrays {
    param (
        [object[]]$Reference,
        [object[]]$Difference,
        [string]$PropertyName = "Value"
    )

    $results = @{
        Added = @()
        Removed = @()
        Changed = @()
    }

    # Find added items (in Difference but not in Reference)
    foreach ($item in $Difference) {
        $found = $false
        foreach ($refItem in $Reference) {
            if ($item -eq $refItem) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $results.Added += $item
        }
    }

    # Find removed items (in Reference but not in Difference)
    foreach ($item in $Reference) {
        $found = $false
        foreach ($diffItem in $Difference) {
            if ($item -eq $diffItem) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $results.Removed += $item
        }
    }

    return $results
}

# Function to find backup file
function Find-BackupFile {
    param (
        [string]$SystemType,
        [string]$FileName
    )

    Write-Log "INFO" "Looking for backup file: $FileName"
    Write-Log "INFO" "System type: $SystemType"
    Write-Log "INFO" "Backup root: $BackupRoot"

    # Try different paths
    $pathsToCheck = @(
        "$BackupRoot\$SystemType\latest\system_info\$FileName",
        "$BackupRoot\all\latest\system_info\$FileName"
    )

    # If a specific date is provided, add those paths too
    if ($BackupDate) {
        $pathsToCheck = @(
            "$BackupRoot\$SystemType\$BackupDate\system_info\$FileName",
            "$BackupRoot\all\$BackupDate\system_info\$FileName"
        ) + $pathsToCheck
    }

    foreach ($path in $pathsToCheck) {
        Write-Log "INFO" "Checking path: $path"
        if (Test-Path $path) {
            Write-Log "INFO" "Found backup file at: $path"
            return $path
        }
    }

    # Last resort: search for the file
    Write-Log "INFO" "Backup file not found in standard locations, searching..."
    $found = Get-ChildItem -Path $BackupRoot -Filter $FileName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Write-Log "INFO" "Found backup file at: $($found.FullName)"
        return $found.FullName
    }

    Write-Log "ERROR" "Backup file $FileName not found in any location"
    return $null
}

# Function to create current snapshot
function New-CurrentSnapshot {
    param (
        [string]$Target
    )

    $snapshotDir = "$TempDir\current"
    if (-not (Test-Path $snapshotDir)) {
        New-Item -Path $snapshotDir -ItemType Directory -Force | Out-Null
    }

    switch ($Target) {
        { $_ -in @("ports", "all") } {
            Write-Log "INFO" "Capturing listening ports"
            $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            $ports | Select-Object LocalAddress, LocalPort, OwningProcess, State |
                Sort-Object LocalPort |
                Out-File -FilePath "$snapshotDir\listening_ports.txt"
        }

        { $_ -in @("connections", "all") } {
            Write-Log "INFO" "Capturing network connections"
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
            $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                Sort-Object State, RemoteAddress |
                Out-File -FilePath "$snapshotDir\network_connections.txt"
        }

        { $_ -in @("processes", "all") } {
            Write-Log "INFO" "Capturing running processes"
            $processes = Get-Process | Select-Object Name, Id, Path, Company | Sort-Object Name
            $processes | Out-File -FilePath "$snapshotDir\processes.txt"
        }

        { $_ -in @("services", "all") } {
            Write-Log "INFO" "Capturing services"
            $services = Get-Service | Select-Object Name, DisplayName, Status, StartType | Sort-Object Name
            $services | Out-File -FilePath "$snapshotDir\active_services.txt"

            # Also get service details
            Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode, State, StartName |
                Sort-Object Name |
                Out-File -FilePath "$snapshotDir\service_details.txt"
        }

        { $_ -in @("users", "all") } {
            Write-Log "INFO" "Capturing user information"
            Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet |
                Out-File -FilePath "$snapshotDir\local_users.txt"

            # Get logged in users
            query user 2>$null | Out-File -FilePath "$snapshotDir\logged_users.txt"
        }

        { $_ -in @("registry", "all") } {
            Write-Log "INFO" "Capturing critical registry keys"
            Export-RegistrySnapshot -OutputPath "$snapshotDir\registry_snapshot.txt"
        }

        { $_ -in @("tasks", "all") } {
            Write-Log "INFO" "Capturing scheduled tasks"
            Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
                Select-Object TaskName, TaskPath, State |
                Sort-Object TaskPath, TaskName |
                Out-File -FilePath "$snapshotDir\scheduled_tasks.txt"
        }

        { $_ -in @("shares", "all") } {
            Write-Log "INFO" "Capturing network shares"
            Get-SmbShare | Select-Object Name, Path, Description |
                Sort-Object Name |
                Out-File -FilePath "$snapshotDir\network_shares.txt" -ErrorAction SilentlyContinue
        }

        { $_ -in @("firewall", "all") } {
            Write-Log "INFO" "Capturing firewall rules"
            Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } |
                Select-Object Name, DisplayName, Direction, Action, Enabled |
                Sort-Object Direction, Name |
                Out-File -FilePath "$snapshotDir\firewall_rules.txt"
        }
    }
}

# Function to export registry snapshot
function Export-RegistrySnapshot {
    param (
        [string]$OutputPath
    )

    # CCDC-relevant registry keys
    $registryKeys = @(
        # Run keys (persistence)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name = "HKLM Run" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Name = "HKLM RunOnce" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name = "HKCU Run" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Name = "HKCU RunOnce" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Name = "HKLM Run (WOW6432)" },

        # Services
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services"; Name = "Services" },

        # Winlogon (persistence)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "Winlogon" },

        # Image File Execution Options (debugger persistence)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Name = "IFEO" },

        # AppInit_DLLs (persistence)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "AppInit_DLLs" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "AppInit_DLLs (WOW6432)" },

        # LSA (authentication)
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LSA" },

        # Network settings
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TCP/IP Parameters" },

        # Windows Defender
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"; Name = "Defender Exclusions - Paths" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"; Name = "Defender Exclusions - Extensions" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"; Name = "Defender Exclusions - Processes" },

        # Firewall
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"; Name = "Firewall Policy" },

        # Safe Mode
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot"; Name = "Safe Boot" },

        # Print Monitors (persistence)
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"; Name = "Print Monitors" },

        # Time Providers (persistence)
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"; Name = "Time Providers" },

        # WMI (persistence)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Wbem\ESS"; Name = "WMI Event Subscriptions" },

        # Terminal Services / RDP
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "Terminal Server" },

        # UAC Settings
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "UAC/System Policies" },

        # Startup folders (check all users)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Name = "Common Shell Folders" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"; Name = "User Shell Folders" }
    )

    $output = @()

    foreach ($key in $registryKeys) {
        $output += ""
        $output += "=" * 80
        $output += "Registry Key: $($key.Name)"
        $output += "Path: $($key.Path)"
        $output += "=" * 80

        if (Test-Path $key.Path) {
            try {
                $values = Get-ItemProperty -Path $key.Path -ErrorAction Stop

                # Get all properties except PS* properties
                $properties = $values.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }

                if ($properties) {
                    foreach ($prop in $properties) {
                        $output += "  $($prop.Name) = $($prop.Value)"
                    }
                } else {
                    $output += "  (No values)"
                }

                # For certain keys, also enumerate subkeys
                if ($key.Path -like "*\Services" -or $key.Path -like "*\Run*") {
                    $subKeys = Get-ChildItem -Path $key.Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
                    if ($subKeys) {
                        $output += ""
                        $output += "  Subkeys:"
                        foreach ($subKey in $subKeys) {
                            $output += "    - $subKey"
                        }
                    }
                }
            } catch {
                $output += "  ERROR: Unable to read registry key - $($_.Exception.Message)"
            }
        } else {
            $output += "  (Key does not exist)"
        }
    }

    $output | Out-File -FilePath $OutputPath
}

# Diff functions
function Compare-Ports {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\listening_ports.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "listening_ports.txt"

    if (-not $backupFile) {
        Write-DiffOutput "LISTENING PORTS" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupPorts = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentPorts = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupPorts -Difference $currentPorts

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "LISTENING PORTS" "No changes detected"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW LISTENING PORTS:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED LISTENING PORTS:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "LISTENING PORTS" $output
    }
}

function Compare-Connections {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\network_connections.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "network_connections.txt"

    if (-not $backupFile) {
        Write-DiffOutput "NETWORK CONNECTIONS" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupConns = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentConns = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupConns -Difference $currentConns

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "NETWORK CONNECTIONS" "No changes detected"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW CONNECTIONS:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nCLOSED CONNECTIONS:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "NETWORK CONNECTIONS" $output
    }
}

function Compare-Processes {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\processes.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "processes.txt"

    if (-not $backupFile) {
        Write-DiffOutput "RUNNING PROCESSES" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupProcs = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentProcs = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupProcs -Difference $currentProcs

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "RUNNING PROCESSES" "No changes detected"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW PROCESSES:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED PROCESSES:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "RUNNING PROCESSES" $output
    }
}

function Compare-Services {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\active_services.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "active_services.txt"

    if (-not $backupFile) {
        Write-DiffOutput "SERVICES" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupSvcs = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentSvcs = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupSvcs -Difference $currentSvcs

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "SERVICES" "No changes in services"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW SERVICES:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED/STOPPED SERVICES:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "SERVICES" $output
    }
}

function Compare-Users {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\local_users.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "local_users.txt"

    if (-not $backupFile) {
        Write-DiffOutput "LOCAL USERS" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupUsers = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentUsers = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupUsers -Difference $currentUsers

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "LOCAL USERS" "No changes in local users"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW USERS:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED USERS:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "LOCAL USERS" $output
    }
}

function Compare-Registry {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\registry_snapshot.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "registry_snapshot.txt"

    if (-not $backupFile) {
        Write-DiffOutput "REGISTRY KEYS" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupReg = Get-Content $backupFile
    $currentReg = Get-Content $currentFile

    # Simple diff
    $diff = Compare-Object -ReferenceObject $backupReg -DifferenceObject $currentReg

    if (-not $diff) {
        Write-DiffOutput "REGISTRY KEYS" "No changes in monitored registry keys"
    } else {
        $output = ""

        $added = $diff | Where-Object { $_.SideIndicator -eq "=>" } | Select-Object -ExpandProperty InputObject
        $removed = $diff | Where-Object { $_.SideIndicator -eq "<=" } | Select-Object -ExpandProperty InputObject

        if ($added) {
            $output += "`nADDED/CHANGED REGISTRY VALUES:`n"
            $output += $added -join "`n"
        }

        if ($removed) {
            $output += "`n`nREMOVED REGISTRY VALUES:`n"
            $output += $removed -join "`n"
        }

        Write-DiffOutput "REGISTRY KEYS" $output

        # Highlight critical changes
        $criticalKeywords = @("Run", "Winlogon", "IFEO", "AppInit", "Service", "Defender", "Exclusion")
        $criticalChanges = @()

        foreach ($change in $diff) {
            foreach ($keyword in $criticalKeywords) {
                if ($change.InputObject -like "*$keyword*") {
                    $criticalChanges += $change.InputObject
                    break
                }
            }
        }

        if ($criticalChanges.Count -gt 0) {
            Write-Host "`n!!! CRITICAL REGISTRY CHANGES DETECTED !!!" -ForegroundColor Red
            Write-Host "The following changes may indicate persistence or malicious activity:" -ForegroundColor Yellow
            $criticalChanges | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
    }
}

function Compare-Tasks {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\scheduled_tasks.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "scheduled_tasks.txt"

    if (-not $backupFile) {
        Write-DiffOutput "SCHEDULED TASKS" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupTasks = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentTasks = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupTasks -Difference $currentTasks

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "SCHEDULED TASKS" "No changes in scheduled tasks"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW SCHEDULED TASKS:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED SCHEDULED TASKS:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "SCHEDULED TASKS" $output
    }
}

function Compare-Shares {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\network_shares.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "network_shares.txt"

    if (-not $backupFile) {
        Write-DiffOutput "NETWORK SHARES" "WARNING: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupShares = Get-Content $backupFile -ErrorAction SilentlyContinue | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentShares = Get-Content $currentFile -ErrorAction SilentlyContinue | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    if (-not $backupShares) { $backupShares = @() }
    if (-not $currentShares) { $currentShares = @() }

    # Compare
    $diff = Compare-Arrays -Reference $backupShares -Difference $currentShares

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "NETWORK SHARES" "No changes in network shares"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW NETWORK SHARES:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED NETWORK SHARES:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "NETWORK SHARES" $output
    }
}

function Compare-Firewall {
    param (
        [string]$SystemType
    )

    $currentFile = "$TempDir\current\firewall_rules.txt"
    $backupFile = Find-BackupFile -SystemType $SystemType -FileName "firewall_rules.txt"

    if (-not $backupFile) {
        Write-DiffOutput "FIREWALL RULES" "ERROR: Backup file not found. Run 'just backup $SystemType' first."
        return
    }

    # Parse files
    $backupRules = Get-Content $backupFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
    $currentRules = Get-Content $currentFile | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    # Compare
    $diff = Compare-Arrays -Reference $backupRules -Difference $currentRules

    if ($diff.Added.Count -eq 0 -and $diff.Removed.Count -eq 0) {
        Write-DiffOutput "FIREWALL RULES" "No changes in firewall rules"
    } else {
        $output = ""

        if ($diff.Added.Count -gt 0) {
            $output += "`nNEW FIREWALL RULES:`n"
            $output += $diff.Added -join "`n"
        }

        if ($diff.Removed.Count -gt 0) {
            $output += "`n`nREMOVED FIREWALL RULES:`n"
            $output += $diff.Removed -join "`n"
        }

        Write-DiffOutput "FIREWALL RULES" $output
    }
}

# Main execution
Write-Log "INFO" "Starting System State Diff Tool"
Write-Log "INFO" "Target: $Target, System type: $SystemType"

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-Host "WARNING: Some diff operations require administrator privileges" -ForegroundColor Yellow
}

# Create temp directory
if (-not (Test-Path $TempDir)) {
    New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
}

# Ensure cleanup on exit
trap {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Create current snapshot
Write-Log "INFO" "Creating current snapshot for: $Target"
New-CurrentSnapshot -Target $Target

# Perform diff based on target
switch ($Target) {
    "ports"       { Compare-Ports -SystemType $SystemType }
    "connections" { Compare-Connections -SystemType $SystemType }
    "processes"   { Compare-Processes -SystemType $SystemType }
    "services"    { Compare-Services -SystemType $SystemType }
    "users"       { Compare-Users -SystemType $SystemType }
    "registry"    { Compare-Registry -SystemType $SystemType }
    "tasks"       { Compare-Tasks -SystemType $SystemType }
    "shares"      { Compare-Shares -SystemType $SystemType }
    "firewall"    { Compare-Firewall -SystemType $SystemType }
    "all" {
        Compare-Ports -SystemType $SystemType
        Compare-Connections -SystemType $SystemType
        Compare-Processes -SystemType $SystemType
        Compare-Services -SystemType $SystemType
        Compare-Users -SystemType $SystemType
        Compare-Registry -SystemType $SystemType
        Compare-Tasks -SystemType $SystemType
        Compare-Shares -SystemType $SystemType
        Compare-Firewall -SystemType $SystemType
    }
}

# Cleanup
if (Test-Path $TempDir) {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Log "INFO" "Diff completed successfully"
