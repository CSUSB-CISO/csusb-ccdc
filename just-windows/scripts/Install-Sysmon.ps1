#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and configure Sysmon for Windows system monitoring in CCDC environments.

.DESCRIPTION
    Downloads and installs Sysmon64 with SwiftOnSecurity configuration or custom CCDC config.
    Sysmon provides real-time logging of:
    - Process creation/termination
    - Network connections
    - File creation/modification
    - Registry changes
    - Driver/DLL loads
    - DNS queries
    - And more...

.PARAMETER ConfigUrl
    URL to custom Sysmon configuration XML file.
    Default: SwiftOnSecurity's production config

.PARAMETER ConfigFile
    Path to local Sysmon configuration XML file.

.PARAMETER Uninstall
    Uninstall Sysmon service.

.PARAMETER Update
    Update existing Sysmon configuration without reinstalling.

.PARAMETER Verify
    Verify Sysmon installation and display status.

.EXAMPLE
    .\Install-Sysmon.ps1
    Install Sysmon with SwiftOnSecurity default config

.EXAMPLE
    .\Install-Sysmon.ps1 -ConfigFile .\custom-sysmon.xml
    Install with custom local config file

.EXAMPLE
    .\Install-Sysmon.ps1 -Update
    Update configuration on existing installation

.EXAMPLE
    .\Install-Sysmon.ps1 -Verify
    Check Sysmon installation status

.NOTES
    Requires Administrator privileges
    PowerShell 3.0+ compatible
    Sysmon64.exe must be in PATH or in Sysinternals tools directory
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",

    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,

    [Parameter(Mandatory=$false)]
    [switch]$Update,

    [Parameter(Mandatory=$false)]
    [switch]$Verify
)

# Enable TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Warning "Could not enable TLS 1.2. Downloads may fail."
}

# Configuration
$BaseDir = if ($env:KK_BASE_DIR) { $env:KK_BASE_DIR } else { "C:\KeyboardKowboys" }
$ToolsDir = if ($env:KK_TOOLS_DIR) { $env:KK_TOOLS_DIR } else { "$BaseDir\tools\sysinternals" }
$ConfigDir = "$BaseDir\configs\sysmon"
$LogDir = if ($env:KK_LOG_DIR) { $env:KK_LOG_DIR } else { "$BaseDir\logs" }

# Sysmon paths
$SysmonPath = $null
$PossiblePaths = @(
    "$ToolsDir\sysmon64.exe",
    "C:\SecurityTools\Sysinternals\sysmon64.exe",
    "C:\KeyboardKowboys\tools\sysinternals\sysmon64.exe"
)

foreach ($path in $PossiblePaths) {
    if (Test-Path $path) {
        $SysmonPath = $path
        break
    }
}

# If not found in known locations, check PATH
if (-not $SysmonPath) {
    $cmd = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        $SysmonPath = $cmd.Source
    }
}

# Color output functions
function Write-ColorOutput {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success {
    param ([string]$Message)
    Write-ColorOutput "✓ $Message" "Green"
}

function Write-Info {
    param ([string]$Message)
    Write-ColorOutput "ℹ $Message" "Cyan"
}

function Write-Warn {
    param ([string]$Message)
    Write-ColorOutput "⚠ $Message" "Yellow"
}

function Write-Fail {
    param ([string]$Message)
    Write-ColorOutput "✗ $Message" "Red"
}

# Function to check Sysmon installation
function Test-SysmonInstalled {
    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    return ($null -ne $service)
}

# Function to get Sysmon status
function Get-SysmonStatus {
    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if (-not $service) {
        return @{
            Installed = $false
            Running = $false
            Status = "Not Installed"
            Version = "N/A"
            ConfigFile = "N/A"
        }
    }

    # Get version from executable
    $version = "Unknown"
    if ($SysmonPath -and (Test-Path $SysmonPath)) {
        try {
            $fileInfo = Get-Item $SysmonPath
            $version = $fileInfo.VersionInfo.FileVersion
        } catch {
            $version = "Unable to determine"
        }
    }

    # Try to get config file location from registry
    $configPath = "N/A"
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
        if (Test-Path $regPath) {
            $configPath = (Get-ItemProperty -Path $regPath -Name "ConfigFile" -ErrorAction SilentlyContinue).ConfigFile
            if (-not $configPath) {
                $configPath = "Using built-in rules"
            }
        }
    } catch {
        $configPath = "Unable to determine"
    }

    return @{
        Installed = $true
        Running = ($service.Status -eq "Running")
        Status = $service.Status
        StartType = $service.StartType
        Version = $version
        ConfigFile = $configPath
        BinaryPath = $SysmonPath
    }
}

# Function to verify Sysmon
function Show-SysmonStatus {
    Write-ColorOutput "`n=== Sysmon Installation Status ===" "Cyan"

    $status = Get-SysmonStatus

    if (-not $status.Installed) {
        Write-Fail "Sysmon is NOT installed"
        Write-Info "Run: .\Install-Sysmon.ps1"
        Write-Info "Or:  just install-sysmon"
        return
    }

    Write-Success "Sysmon is installed"
    Write-ColorOutput "  Status:      $($status.Status)" $(if ($status.Running) { "Green" } else { "Red" })
    Write-ColorOutput "  Start Type:  $($status.StartType)" "White"
    Write-ColorOutput "  Version:     $($status.Version)" "White"
    Write-ColorOutput "  Binary:      $($status.BinaryPath)" "Gray"
    Write-ColorOutput "  Config:      $($status.ConfigFile)" "Gray"

    # Check event log
    Write-ColorOutput "`n=== Event Log Status ===" "Cyan"
    try {
        $logName = "Microsoft-Windows-Sysmon/Operational"
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $recentEvents = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop

        Write-Success "Event log is accessible"
        Write-ColorOutput "  Log Name:    $logName" "White"
        Write-ColorOutput "  Log Size:    $([math]::Round($log.FileSize / 1MB, 2)) MB" "White"
        Write-ColorOutput "  Record Count: $($log.RecordCount)" "White"
        Write-ColorOutput "  Last Event:  $($recentEvents.TimeCreated)" "White"
    } catch {
        Write-Warn "Event log may not be accessible: $_"
    }

    # Show what Sysmon monitors
    Write-ColorOutput "`n=== Monitored Events ===" "Cyan"
    Write-ColorOutput "  Event ID 1:  Process creation" "White"
    Write-ColorOutput "  Event ID 2:  File creation time changed" "White"
    Write-ColorOutput "  Event ID 3:  Network connection" "White"
    Write-ColorOutput "  Event ID 5:  Process terminated" "White"
    Write-ColorOutput "  Event ID 7:  Image/DLL loaded" "White"
    Write-ColorOutput "  Event ID 8:  CreateRemoteThread" "White"
    Write-ColorOutput "  Event ID 10: Process access" "White"
    Write-ColorOutput "  Event ID 11: File created" "White"
    Write-ColorOutput "  Event ID 12: Registry object added/deleted" "White"
    Write-ColorOutput "  Event ID 13: Registry value set" "White"
    Write-ColorOutput "  Event ID 15: File stream created" "White"
    Write-ColorOutput "  Event ID 22: DNS query" "White"
    Write-ColorOutput "  Event ID 23: File delete" "White"

    Write-ColorOutput "`n=== Quick Commands ===" "Cyan"
    Write-ColorOutput "  Query events:       just query-sysmon" "Gray"
    Write-ColorOutput "  Watch real-time:    just watch-sysmon" "Gray"
    Write-ColorOutput "  Check suspicious:   just sysmon-suspicious" "Gray"
    Write-ColorOutput "  Update config:      .\Install-Sysmon.ps1 -Update" "Gray"
}

# Function to uninstall Sysmon
function Uninstall-Sysmon {
    Write-ColorOutput "`n=== Uninstalling Sysmon ===" "Cyan"

    if (-not (Test-SysmonInstalled)) {
        Write-Warn "Sysmon is not installed"
        return
    }

    if (-not $SysmonPath -or -not (Test-Path $SysmonPath)) {
        Write-Fail "Cannot find sysmon64.exe"
        Write-Info "Manual uninstall: sysmon64.exe -u"
        return
    }

    try {
        Write-Info "Uninstalling Sysmon service..."
        & $SysmonPath -u -accepteula

        Start-Sleep -Seconds 2

        if (Test-SysmonInstalled) {
            Write-Fail "Sysmon uninstall failed"
        } else {
            Write-Success "Sysmon uninstalled successfully"
        }
    } catch {
        Write-Fail "Error uninstalling Sysmon: $_"
    }
}

# Function to download Sysmon config
function Get-SysmonConfig {
    param (
        [string]$Url,
        [string]$LocalPath
    )

    # Ensure config directory exists
    $configParent = Split-Path -Parent $LocalPath
    if (-not (Test-Path $configParent)) {
        New-Item -Path $configParent -ItemType Directory -Force | Out-Null
    }

    Write-Info "Downloading Sysmon configuration..."
    Write-ColorOutput "  Source: $Url" "Gray"
    Write-ColorOutput "  Destination: $LocalPath" "Gray"

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $LocalPath)
        $webClient.Dispose()

        if (Test-Path $LocalPath) {
            Write-Success "Configuration downloaded successfully"
            return $true
        } else {
            Write-Fail "Download failed - file not created"
            return $false
        }
    } catch {
        Write-Fail "Error downloading configuration: $_"
        return $false
    }
}

# Function to install or update Sysmon
function Install-SysmonService {
    param (
        [string]$ConfigPath,
        [bool]$IsUpdate = $false
    )

    if (-not $SysmonPath -or -not (Test-Path $SysmonPath)) {
        Write-Fail "Cannot find sysmon64.exe"
        Write-Info "Please install Sysinternals tools first:"
        Write-Info "  just install-tools"
        Write-Info "Or download from: https://live.sysinternals.com/sysmon64.exe"
        return $false
    }

    Write-ColorOutput "  Binary: $SysmonPath" "Gray"

    if ($IsUpdate) {
        Write-Info "Updating Sysmon configuration..."
        $command = "-c"
    } else {
        Write-Info "Installing Sysmon service..."
        $command = "-i"
    }

    try {
        if ($ConfigPath -and (Test-Path $ConfigPath)) {
            Write-ColorOutput "  Using config: $ConfigPath" "Gray"
            & $SysmonPath $command $ConfigPath -accepteula
        } else {
            Write-Warn "No config file - using default Sysmon rules"
            & $SysmonPath $command -accepteula
        }

        Start-Sleep -Seconds 3

        # Verify installation
        $status = Get-SysmonStatus

        if ($status.Installed -and $status.Running) {
            Write-Success "Sysmon $(if ($IsUpdate) { 'updated' } else { 'installed' }) successfully!"
            return $true
        } else {
            Write-Fail "Sysmon installation verification failed"
            if ($status.Installed -and -not $status.Running) {
                Write-Warn "Service is installed but not running"
                Write-Info "Try starting it: Start-Service Sysmon64"
            }
            return $false
        }
    } catch {
        Write-Fail "Error during Sysmon installation: $_"
        return $false
    }
}

# Main execution
Write-ColorOutput "=== Sysmon Installation Tool ===" "Cyan"
Write-ColorOutput "Version: 1.0 - CCDC Edition" "Gray"

# Handle verify flag
if ($Verify) {
    Show-SysmonStatus
    exit 0
}

# Handle uninstall flag
if ($Uninstall) {
    Uninstall-Sysmon
    exit 0
}

# Handle update flag
if ($Update) {
    Write-ColorOutput "`n=== Updating Sysmon Configuration ===" "Cyan"

    if (-not (Test-SysmonInstalled)) {
        Write-Fail "Sysmon is not installed"
        Write-Info "Run: .\Install-Sysmon.ps1 (without -Update)"
        exit 1
    }

    # Determine config path
    $finalConfigPath = $null

    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        $finalConfigPath = $ConfigFile
        Write-Info "Using local config file"
    } else {
        $downloadPath = "$ConfigDir\sysmonconfig.xml"
        if (Get-SysmonConfig -Url $ConfigUrl -LocalPath $downloadPath) {
            $finalConfigPath = $downloadPath
        }
    }

    if ($finalConfigPath) {
        if (Install-SysmonService -ConfigPath $finalConfigPath -IsUpdate $true) {
            Write-Success "Configuration update complete!"
            Show-SysmonStatus
            exit 0
        } else {
            Write-Fail "Configuration update failed"
            exit 1
        }
    } else {
        Write-Fail "No configuration file available"
        exit 1
    }
}

# Standard installation flow
Write-ColorOutput "`n=== Installing Sysmon ===" "Cyan"

# Check if already installed
if (Test-SysmonInstalled) {
    Write-Warn "Sysmon is already installed"
    Write-Info "To update configuration, run: .\Install-Sysmon.ps1 -Update"
    Write-Info "To reinstall, first uninstall: .\Install-Sysmon.ps1 -Uninstall"
    Write-ColorOutput ""
    Show-SysmonStatus
    exit 0
}

# Determine config path
$finalConfigPath = $null

if ($ConfigFile) {
    # Use provided local config
    if (Test-Path $ConfigFile) {
        $finalConfigPath = $ConfigFile
        Write-Success "Using local config file: $ConfigFile"
    } else {
        Write-Fail "Config file not found: $ConfigFile"
        exit 1
    }
} else {
    # Download config from URL
    $downloadPath = "$ConfigDir\sysmonconfig.xml"
    Write-Info "No local config specified - downloading SwiftOnSecurity config..."

    if (Get-SysmonConfig -Url $ConfigUrl -LocalPath $downloadPath) {
        $finalConfigPath = $downloadPath
    } else {
        Write-Warn "Config download failed - will install with default rules"
        $finalConfigPath = $null
    }
}

# Install Sysmon
if (Install-SysmonService -ConfigPath $finalConfigPath -IsUpdate $false) {
    Write-ColorOutput "`n=== Installation Complete ===" "Green"

    # Create a log entry
    $installLog = "$LogDir\sysmon-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    @"
Sysmon Installation Log
Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Config: $finalConfigPath
Binary: $SysmonPath
"@ | Out-File -FilePath $installLog -Encoding UTF8

    Write-Success "Installation log: $installLog"

    Write-ColorOutput "`n=== Next Steps ===" "Cyan"
    Write-ColorOutput "  1. Verify installation:  .\Install-Sysmon.ps1 -Verify" "Yellow"
    Write-ColorOutput "  2. Query events:         just query-sysmon" "Yellow"
    Write-ColorOutput "  3. Watch real-time:      just watch-sysmon" "Yellow"
    Write-ColorOutput "  4. Create baseline:      just backup" "Yellow"

    Write-ColorOutput "`n=== Current Status ===" "Cyan"
    Show-SysmonStatus

    exit 0
} else {
    Write-Fail "Installation failed"
    exit 1
}
