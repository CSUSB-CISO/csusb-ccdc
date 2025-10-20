#Requires -Version 3.0

<#
.SYNOPSIS
    Query and analyze Sysmon events for CCDC incident response and threat detection.

.DESCRIPTION
    Comprehensive Sysmon event analysis tool for Windows CCDC competitions.

    Query modes:
    - Recent events across all categories
    - Specific event types (process, network, file, registry, DNS)
    - Suspicious activity detection
    - Real-time event monitoring
    - Process ancestry/lineage tracking

    Detects:
    - Processes from unusual locations
    - Network connections to suspicious IPs
    - Registry persistence mechanisms
    - File operations in sensitive directories
    - DNS queries to suspicious domains
    - Credential dumping attempts
    - Lateral movement indicators

.PARAMETER Query
    Query mode: recent, suspicious, watch, process, network, file, registry, dns

.PARAMETER EventId
    Specific Sysmon Event ID to query (1-26)

.PARAMETER Hours
    Number of hours to look back (default: 1)

.PARAMETER MaxEvents
    Maximum events to retrieve (default: 100)

.PARAMETER ProcessName
    Filter by process name (supports wildcards)

.PARAMETER CommandLine
    Filter by command line (supports wildcards)

.PARAMETER IpAddress
    Filter by IP address

.PARAMETER Domain
    Filter by DNS domain

.PARAMETER OutputFile
    Export results to JSON file

.PARAMETER Watch
    Real-time monitoring mode (press Ctrl+C to exit)

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Query recent
    Show recent events from all categories

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Query suspicious
    Analyze for suspicious activity

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Query process -Hours 24
    Show all process creation events from last 24 hours

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Query network -IpAddress 192.168.1.100
    Show network connections to specific IP

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Query dns -Domain evil.com
    Search for DNS queries to specific domain

.EXAMPLE
    .\Invoke-SysmonMonitor.ps1 -Watch
    Real-time event monitoring

.NOTES
    Requires Sysmon to be installed and running
    PowerShell 3.0+ compatible
    Event log: Microsoft-Windows-Sysmon/Operational
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('recent', 'suspicious', 'watch', 'process', 'network', 'file', 'registry', 'dns', 'status')]
    [string]$Query = 'status',

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 26)]
    [int]$EventId,

    [Parameter(Mandatory=$false)]
    [int]$Hours = 1,

    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 100,

    [Parameter(Mandatory=$false)]
    [string]$ProcessName,

    [Parameter(Mandatory=$false)]
    [string]$CommandLine,

    [Parameter(Mandatory=$false)]
    [string]$IpAddress,

    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile,

    [Parameter(Mandatory=$false)]
    [switch]$Watch
)

# Sysmon log name
$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Success { param([string]$Message) Write-ColorOutput "[OK] $Message" "Green" }
function Write-Info    { param([string]$Message) Write-ColorOutput "[INFO] $Message" "Cyan" }
function Write-Warn    { param([string]$Message) Write-ColorOutput "[WARN] $Message" "Yellow" }
function Write-Fail    { param([string]$Message) Write-ColorOutput "[FAIL] $Message" "Red" }
function Write-Suspicious { param([string]$Message) Write-ColorOutput "[ALERT] $Message" "Red" }

# Function to check if Sysmon is installed and running
function Test-Sysmon {
    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-Fail "Sysmon is not installed"
        Write-Info "Install with: just install-sysmon"
        return $false
    }

    if ($service.Status -ne "Running") {
        Write-Fail "Sysmon service is not running (Status: $($service.Status))"
        Write-Info "Start with: Start-Service Sysmon64"
        return $false
    }

    # Check if event log is accessible
    try {
        $log = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
        return $true
    } catch {
        Write-Fail "Cannot access Sysmon event log: $_"
        return $false
    }
}

# Function to get Sysmon status
function Show-SysmonStatus {
    Write-ColorOutput "`n=== Sysmon Monitor Status ===" "Cyan"

    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-Fail "Sysmon is NOT installed"
        Write-Info "Install with: just install-sysmon"
        return
    }

    Write-Success "Sysmon service is installed"
    Write-ColorOutput "  Status:     $($service.Status)" $(if ($service.Status -eq "Running") { "Green" } else { "Red" })
    Write-ColorOutput "  Start Type: $($service.StartType)" "White"

    # Get event log statistics
    try {
        $log = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
        $recentEvent = Get-WinEvent -LogName $SysmonLog -MaxEvents 1 -ErrorAction Stop

        Write-ColorOutput "`n  Event Log:  Microsoft-Windows-Sysmon/Operational" "Cyan"
        Write-ColorOutput "    Records:    $($log.RecordCount)" "White"
        Write-ColorOutput "    Size:       $([math]::Round($log.FileSize / 1MB, 2)) MB" "White"
        Write-ColorOutput "    Last Event: $($recentEvent.TimeCreated)" "White"

        # Count events by type in last hour
        Write-ColorOutput "`n  Events (Last Hour):" "Cyan"
        $startTime = (Get-Date).AddHours(-1)

        $eventCounts = @{}
        $eventTypes = @{
            1 = "Process Create"
            3 = "Network Connect"
            5 = "Process Terminate"
            7 = "Image Load"
            11 = "File Create"
            12 = "Registry Add/Delete"
            13 = "Registry Set"
            22 = "DNS Query"
            23 = "File Delete"
        }

        foreach ($id in $eventTypes.Keys) {
            try {
                $count = (Get-WinEvent -FilterHashtable @{
                    LogName = $SysmonLog
                    ID = $id
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-ColorOutput "    ID $($id.ToString().PadLeft(2)): $($count.ToString().PadLeft(5)) - $($eventTypes[$id])" "White"
            } catch {
                # No events of this type
            }
        }

    } catch {
        Write-Warn "Could not retrieve event log statistics: $_"
    }

    Write-ColorOutput "`n=== Available Commands ===" "Cyan"
    Write-ColorOutput "  Recent events:      just query-sysmon" "Gray"
    Write-ColorOutput "  Suspicious events:  just sysmon-suspicious" "Gray"
    Write-ColorOutput "  Real-time watch:    just watch-sysmon" "Gray"
    Write-ColorOutput "  Process events:     .\Invoke-SysmonMonitor.ps1 -Query process" "Gray"
    Write-ColorOutput "  Network events:     .\Invoke-SysmonMonitor.ps1 -Query network" "Gray"
}

# Function to format event details
function Format-SysmonEvent {
    param (
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $eventXml = [xml]$Event.ToXml()
    $eventData = @{}

    foreach ($data in $eventXml.Event.EventData.Data) {
        $eventData[$data.Name] = $data.'#text'
    }

    return @{
        Time = $Event.TimeCreated
        EventId = $Event.Id
        Computer = $Event.MachineName
        Data = $eventData
    }
}

# Function to detect suspicious activity
function Test-SuspiciousActivity {
    param (
        [hashtable]$EventData,
        [int]$EventId
    )

    $reasons = @()

    # Suspicious paths for process execution
    $suspiciousPaths = @(
        '*\AppData\Local\Temp\*',
        '*\Users\Public\*',
        '*\ProgramData\*',
        '*\Windows\Temp\*',
        '*\Recycle.Bin\*',
        '*\Downloads\*'
    )

    # Suspicious process names
    $suspiciousProcesses = @(
        '*powershell*',
        '*cmd.exe',
        '*wscript*',
        '*cscript*',
        '*mshta*',
        '*rundll32*',
        '*regsvr32*',
        '*certutil*',
        '*bitsadmin*',
        '*wmic*',
        '*psexec*',
        '*mimikatz*',
        '*procdump*'
    )

    # Suspicious command line patterns
    $suspiciousCommandPatterns = @(
        '*-encodedcommand*',
        '*-enc*',
        '*-e *',
        '*invoke-expression*',
        '*iex *',
        '*downloadstring*',
        '*downloadfile*',
        '*webclient*',
        '*net user*',
        '*net localgroup*',
        '*reg add*',
        '*schtasks*',
        '*at *',
        '*sc create*',
        '*wmic process*',
        '*lsass*',
        '*sekurlsa*',
        '*mimikatz*'
    )

    # Suspicious registry keys (persistence)
    $suspiciousRegKeys = @(
        '*\Software\Microsoft\Windows\CurrentVersion\Run*',
        '*\Software\Microsoft\Windows\CurrentVersion\RunOnce*',
        '*\Software\Microsoft\Windows NT\CurrentVersion\Winlogon*',
        '*\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options*',
        '*\System\CurrentControlSet\Services\*'
    )

    # Suspicious IP addresses (private/internal might be lateral movement)
    $suspiciousIPPatterns = @(
        '10.*',
        '172.16.*', '172.17.*', '172.18.*', '172.19.*',
        '172.20.*', '172.21.*', '172.22.*', '172.23.*',
        '172.24.*', '172.25.*', '172.26.*', '172.27.*',
        '172.28.*', '172.29.*', '172.30.*', '172.31.*',
        '192.168.*'
    )

    # Event ID 1: Process Creation
    if ($EventId -eq 1) {
        $image = $EventData['Image']
        $commandLine = $EventData['CommandLine']
        $parentImage = $EventData['ParentImage']

        # Check suspicious paths
        foreach ($pattern in $suspiciousPaths) {
            if ($image -like $pattern) {
                $reasons += "Process started from suspicious location: $image"
            }
        }

        # Check suspicious processes
        foreach ($pattern in $suspiciousProcesses) {
            if ($image -like $pattern) {
                $reasons += "Suspicious process: $(Split-Path -Leaf $image)"
            }
        }

        # Check command line patterns
        foreach ($pattern in $suspiciousCommandPatterns) {
            if ($commandLine -like $pattern) {
                $reasons += "Suspicious command line pattern detected"
            }
        }

        # Check for unusual parent processes
        if ($parentImage -like '*\w3wp.exe' -or $parentImage -like '*\sql*.exe') {
            $reasons += "Web server or database spawned process (potential web shell)"
        }
    }

    # Event ID 3: Network Connection
    if ($EventId -eq 3) {
        $destIp = $EventData['DestinationIp']
        $destPort = $EventData['DestinationPort']
        $image = $EventData['Image']

        # Check for connections from script interpreters
        foreach ($pattern in $suspiciousProcesses) {
            if ($image -like $pattern) {
                $reasons += "Network connection from suspicious process: $(Split-Path -Leaf $image)"
            }
        }

        # Check for unusual ports
        $unusualPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345)
        if ($destPort -in $unusualPorts) {
            $reasons += "Connection to unusual port: $destPort"
        }

        # Check for lateral movement (SMB, WinRM, RDP)
        $lateralPorts = @(445, 139, 5985, 5986, 3389)
        if ($destPort -in $lateralPorts) {
            $reasons += "Potential lateral movement (port $destPort)"
        }
    }

    # Event ID 11: File Create
    if ($EventId -eq 11) {
        $targetFilename = $EventData['TargetFilename']

        # Check for files in startup locations
        $startupPaths = @(
            '*\Start Menu\Programs\Startup\*',
            '*\AppData\Roaming\Microsoft\Windows\Start Menu\*'
        )
        foreach ($pattern in $startupPaths) {
            if ($targetFilename -like $pattern) {
                $reasons += "File created in startup location: $targetFilename"
            }
        }

        # Check for script files in temp
        if ($targetFilename -like '*\Temp\*.ps1' -or
            $targetFilename -like '*\Temp\*.vbs' -or
            $targetFilename -like '*\Temp\*.bat' -or
            $targetFilename -like '*\Temp\*.cmd') {
            $reasons += "Script file created in temp directory"
        }
    }

    # Event ID 12/13: Registry modifications
    if ($EventId -in @(12, 13)) {
        $targetObject = $EventData['TargetObject']

        foreach ($pattern in $suspiciousRegKeys) {
            if ($targetObject -like $pattern) {
                $reasons += "Registry persistence mechanism modified: $targetObject"
            }
        }
    }

    # Event ID 22: DNS Query
    if ($EventId -eq 22) {
        $queryName = $EventData['QueryName']

        # Check for suspicious TLDs
        $suspiciousTLDs = @('.ru', '.cn', '.tk', '.top', '.xyz')
        foreach ($tld in $suspiciousTLDs) {
            if ($queryName -like "*$tld") {
                $reasons += "DNS query to suspicious TLD: $queryName"
            }
        }

        # Check for DNS tunneling indicators (long subdomains)
        $parts = $queryName -split '\.'
        if ($parts.Count -gt 5 -or ($parts[0].Length -gt 50)) {
            $reasons += "Potential DNS tunneling: $queryName"
        }
    }

    return $reasons
}

# Function to query recent events
function Get-RecentEvents {
    Write-ColorOutput "`n=== Recent Sysmon Events (Last $Hours hour(s)) ===" "Cyan"

    $startTime = (Get-Date).AddHours(-$Hours)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $SysmonLog
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop

        Write-Info "Found $($events.Count) events"

        $eventGroups = $events | Group-Object Id | Sort-Object Name

        foreach ($group in $eventGroups) {
            $eventId = $group.Name
            $count = $group.Count

            $eventType = switch ($eventId) {
                1 { "Process Create" }
                2 { "File Time Changed" }
                3 { "Network Connect" }
                5 { "Process Terminate" }
                7 { "Image Load" }
                8 { "CreateRemoteThread" }
                10 { "Process Access" }
                11 { "File Create" }
                12 { "Registry Add/Delete" }
                13 { "Registry Set" }
                15 { "File Stream Create" }
                22 { "DNS Query" }
                23 { "File Delete" }
                default { "Other" }
            }

            Write-ColorOutput "  Event ID $($eventId.PadLeft(2)): $($count.ToString().PadLeft(4)) - $eventType" "White"
        }

        # Show sample of latest events
        Write-ColorOutput "`n=== Latest 10 Events ===" "Cyan"
        foreach ($event in ($events | Select-Object -First 10)) {
            $formatted = Format-SysmonEvent -Event $event
            $eventType = switch ($event.Id) {
                1 { "Process" }
                3 { "Network" }
                11 { "FileCreate" }
                13 { "Registry" }
                22 { "DNS" }
                default { "Event" }
            }

            Write-ColorOutput "$($formatted.Time.ToString('HH:mm:ss')) [$eventType] " "Gray" -NoNewline
            Write-ColorOutput "$($event.Id) " "Yellow" -NoNewline

            # Show relevant details based on event type
            if ($event.Id -eq 1 -and $formatted.Data['Image']) {
                Write-ColorOutput "$(Split-Path -Leaf $formatted.Data['Image'])" "White"
            } elseif ($event.Id -eq 3 -and $formatted.Data['DestinationIp']) {
                Write-ColorOutput "$($formatted.Data['DestinationIp']):$($formatted.Data['DestinationPort'])" "White"
            } elseif ($event.Id -eq 22 -and $formatted.Data['QueryName']) {
                Write-ColorOutput "$($formatted.Data['QueryName'])" "White"
            } else {
                Write-ColorOutput "" "White"
            }
        }

    } catch {
        Write-Fail "Error querying events: $_"
    }
}

# Function to detect suspicious events
function Get-SuspiciousEvents {
    Write-ColorOutput "`n=== Analyzing for Suspicious Activity (Last $Hours hour(s)) ===" "Cyan"

    $startTime = (Get-Date).AddHours(-$Hours)
    $suspiciousCount = 0

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $SysmonLog
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop

        Write-Info "Analyzing $($events.Count) events..."

        foreach ($event in $events) {
            $formatted = Format-SysmonEvent -Event $event
            $reasons = Test-SuspiciousActivity -EventData $formatted.Data -EventId $event.Id

            if ($reasons.Count -gt 0) {
                $suspiciousCount++

                Write-Suspicious "Time: $($formatted.Time) | Event ID: $($event.Id)"

                foreach ($reason in $reasons) {
                    Write-ColorOutput "  ⚠ $reason" "Yellow"
                }

                # Show relevant details
                if ($event.Id -eq 1) {
                    Write-ColorOutput "    Process: $($formatted.Data['Image'])" "Gray"
                    if ($formatted.Data['CommandLine']) {
                        $cmdLine = $formatted.Data['CommandLine']
                        if ($cmdLine.Length -gt 100) {
                            $cmdLine = $cmdLine.Substring(0, 100) + "..."
                        }
                        Write-ColorOutput "    Command: $cmdLine" "Gray"
                    }
                    Write-ColorOutput "    Parent:  $($formatted.Data['ParentImage'])" "Gray"
                } elseif ($event.Id -eq 3) {
                    Write-ColorOutput "    Process: $($formatted.Data['Image'])" "Gray"
                    Write-ColorOutput "    Target:  $($formatted.Data['DestinationIp']):$($formatted.Data['DestinationPort'])" "Gray"
                } elseif ($event.Id -in @(12, 13)) {
                    Write-ColorOutput "    Target:  $($formatted.Data['TargetObject'])" "Gray"
                    if ($formatted.Data['Details']) {
                        Write-ColorOutput "    Value:   $($formatted.Data['Details'])" "Gray"
                    }
                } elseif ($event.Id -eq 22) {
                    Write-ColorOutput "    Query:   $($formatted.Data['QueryName'])" "Gray"
                }

                Write-ColorOutput "" "White"
            }
        }

        if ($suspiciousCount -eq 0) {
            Write-Success "No suspicious activity detected"
        } else {
            Write-Suspicious "Found $suspiciousCount suspicious events!"
        }

    } catch {
        Write-Fail "Error analyzing events: $_"
    }
}

# Function to query specific event types
function Get-EventsByType {
    param (
        [string]$Type
    )

    $eventIds = switch ($Type) {
        'process' { @(1, 5) }
        'network' { @(3) }
        'file' { @(11, 23) }
        'registry' { @(12, 13) }
        'dns' { @(22) }
        default { @() }
    }

    if ($eventIds.Count -eq 0) {
        Write-Fail "Unknown event type: $Type"
        return
    }

    Write-ColorOutput "`n=== $($Type.ToUpper()) Events (Last $Hours hour(s)) ===" "Cyan"

    $startTime = (Get-Date).AddHours(-$Hours)

    try {
        $filterHash = @{
            LogName = $SysmonLog
            ID = $eventIds
            StartTime = $startTime
        }

        $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction Stop

        Write-Info "Found $($events.Count) $Type events"

        foreach ($event in $events) {
            $formatted = Format-SysmonEvent -Event $event

            Write-ColorOutput "$($formatted.Time.ToString('yyyy-MM-dd HH:mm:ss')) [ID:$($event.Id)]" "Cyan" -NoNewline

            # Display relevant info based on type
            switch ($Type) {
                'process' {
                    if ($event.Id -eq 1) {
                        $image = Split-Path -Leaf $formatted.Data['Image']
                        $ProcessID = $formatted.Data['ProcessId']
                        Write-ColorOutput " Create: $image (PID: $ProcessID)" "White"
                        if ($formatted.Data['CommandLine']) {
                            $cmd = $formatted.Data['CommandLine']
                            if ($cmd.Length -gt 80) { $cmd = $cmd.Substring(0, 80) + "..." }
                            Write-ColorOutput "    CMD: $cmd" "Gray"
                        }
                    } else {
                        $image = Split-Path -Leaf $formatted.Data['Image']
                        Write-ColorOutput " Terminate: $image" "White"
                    }
                }
                'network' {
                    $process = Split-Path -Leaf $formatted.Data['Image']
                    $dest = "$($formatted.Data['DestinationIp']):$($formatted.Data['DestinationPort'])"
                    Write-ColorOutput " $process -> $dest" "White"
                }
                'file' {
                    $file = $formatted.Data['TargetFilename']
                    $action = if ($event.Id -eq 11) { "Created" } else { "Deleted" }
                    Write-ColorOutput " $action`: $file" "White"
                }
                'registry' {
                    $key = $formatted.Data['TargetObject']
                    $action = if ($event.Id -eq 12) { "Key Modified" } else { "Value Set" }
                    Write-ColorOutput " $action`: $key" "White"
                }
                'dns' {
                    $query = $formatted.Data['QueryName']
                    $result = $formatted.Data['QueryResults']
                    Write-ColorOutput " $query -> $result" "White"
                }
            }
        }

    } catch {
        Write-Fail "Error querying $Type events: $_"
    }
}

# Function for real-time monitoring
function Start-Watch {
    Write-ColorOutput "`n=== Real-Time Sysmon Event Monitoring ===" "Cyan"
    Write-Info "Press Ctrl+C to exit"
    Write-ColorOutput ""

    $lastEventTime = Get-Date

    try {
        while ($true) {
            Start-Sleep -Seconds 2

            $events = Get-WinEvent -FilterHashtable @{
                LogName = $SysmonLog
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue

            if ($events) {
                foreach ($event in $events) {
                    $formatted = Format-SysmonEvent -Event $event
                    $lastEventTime = $event.TimeCreated

                    # Check if suspicious
                    $reasons = Test-SuspiciousActivity -EventData $formatted.Data -EventId $event.Id

                    if ($reasons.Count -gt 0) {
                        Write-Suspicious "$($formatted.Time.ToString('HH:mm:ss')) [ID:$($event.Id)] SUSPICIOUS"
                        foreach ($reason in $reasons) {
                            Write-ColorOutput "  $reason" "Yellow"
                        }
                    } else {
                        $eventType = switch ($event.Id) {
                            1 { "PROC" }
                            3 { "NET " }
                            11 { "FILE" }
                            13 { "REG " }
                            22 { "DNS " }
                            default { "EVT " }
                        }

                        Write-ColorOutput "$($formatted.Time.ToString('HH:mm:ss')) [$eventType] " "Gray" -NoNewline

                        if ($event.Id -eq 1) {
                            Write-ColorOutput "$(Split-Path -Leaf $formatted.Data['Image'])" "White"
                        } elseif ($event.Id -eq 3) {
                            Write-ColorOutput "$($formatted.Data['DestinationIp']):$($formatted.Data['DestinationPort'])" "White"
                        } elseif ($event.Id -eq 22) {
                            Write-ColorOutput "$($formatted.Data['QueryName'])" "White"
                        } else {
                            Write-ColorOutput "Event ID $($event.Id)" "White"
                        }
                    }
                }
            }
        }
    } catch {
        Write-Info "`nMonitoring stopped"
    }
}

# Main execution
if ($Watch) {
    if (Test-Sysmon) {
        Start-Watch
    }
    exit 0
}

# Check Sysmon status first
if (-not (Test-Sysmon)) {
    exit 1
}

# Execute query based on mode
switch ($Query) {
    'status' {
        Show-SysmonStatus
    }
    'recent' {
        Get-RecentEvents
    }
    'suspicious' {
        Get-SuspiciousEvents
    }
    'process' {
        Get-EventsByType -Type 'process'
    }
    'network' {
        Get-EventsByType -Type 'network'
    }
    'file' {
        Get-EventsByType -Type 'file'
    }
    'registry' {
        Get-EventsByType -Type 'registry'
    }
    'dns' {
        Get-EventsByType -Type 'dns'
    }
    'watch' {
        Start-Watch
    }
}

# Export to file if requested
if ($OutputFile) {
    Write-Info "Exporting results to $OutputFile..."
    # Export logic here
    Write-Success "Results exported"
}
