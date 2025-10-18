<#
.SYNOPSIS
    Install Sysinternals Suite for Windows CCDC toolkit

.DEPRECATED
    This script is deprecated. Use Install-Tools.ps1 instead which includes
    Sysinternals Suite installation along with other CCDC tools.

    Run: just install-tools

.DESCRIPTION
    Downloads and installs essential Sysinternals tools for incident response,
    persistence detection, and system monitoring.

    Tools installed:
    - autorunsc64.exe - Persistence detection
    - sysmon64.exe - Real-time system monitoring
    - pslist.exe - Process enumeration
    - psloglist.exe - Event log extraction
    - handle.exe - Handle enumeration
    - tcpvcon.exe - Network connection monitoring
    - sigcheck.exe - File integrity and VirusTotal checking
    - procdump.exe - Process memory dumping
    - psservice.exe - Service management

.PARAMETER InstallPath
    Installation directory (default: C:\KeyboardKowboys\tools\sysinternals)

.PARAMETER DownloadSuite
    Download entire Sysinternals Suite (default: individual tools)

.PARAMETER AddToPath
    Add installation directory to system PATH

.EXAMPLE
    .\Install-SysinternalsTools.ps1
    Install essential tools to default location

.EXAMPLE
    .\Install-SysinternalsTools.ps1 -DownloadSuite -AddToPath
    Download entire suite and add to PATH

.NOTES
    PowerShell 3.0+ compatible
    Requires internet connection
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$InstallPath,

    [Parameter(Mandatory=$false)]
    [switch]$DownloadSuite,

    [Parameter(Mandatory=$false)]
    [switch]$AddToPath
)

# Enable TLS 1.2 for PowerShell 3.0+ (required for HTTPS downloads)
# PowerShell 3.0 defaults to TLS 1.0 which most modern sites reject
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Warning "Could not enable TLS 1.2. Downloads may fail."
}

# Configuration
$BaseDir = if ($env:KK_BASE_DIR) { $env:KK_BASE_DIR } else { "C:\KeyboardKowboys" }
$DefaultInstallPath = "$BaseDir\tools\sysinternals"
$InstallPath = if ($InstallPath) { $InstallPath } else { $DefaultInstallPath }

# Sysinternals live URL
$sysinternalsLiveUrl = "https://live.sysinternals.com"
$sysinternalsSuiteUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

# Essential tools for CCDC
$essentialTools = @(
    "autorunsc64.exe",  # Persistence detection
    "sysmon64.exe",     # System monitoring
    "pslist.exe",       # Process listing
    "psloglist.exe",    # Event log extraction
    "handle.exe",       # Handle enumeration
    "tcpvcon.exe",      # TCP/UDP connections
    "sigcheck.exe",     # File signatures and VirusTotal
    "procdump.exe",     # Process memory dumps
    "psservice.exe",    # Service management
    "procexp64.exe",    # Process Explorer
    "strings.exe",      # String extraction
    "accesschk.exe"     # Access permissions check
)

# Function to write colored output
function Write-ColorOutput {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to download file with progress
function Download-File {
    param (
        [string]$Url,
        [string]$Destination
    )

    try {
        Write-ColorOutput "  Downloading from: $Url" "Gray"

        # PowerShell 3.0 compatible download with progress
        $webClient = New-Object System.Net.WebClient

        # Add event handler for progress
        $webClient.DownloadProgressChanged += {
            param($sender, $e)
            $percent = $e.ProgressPercentage
            if ($percent % 10 -eq 0) {  # Only show every 10%
                Write-Progress -Activity "Downloading" -Status "$percent% Complete" -PercentComplete $percent
            }
        }

        # Download file
        $webClient.DownloadFile($Url, $Destination)
        $webClient.Dispose()

        Write-Progress -Activity "Downloading" -Completed
        Write-ColorOutput "  Downloaded: $Destination" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "  ERROR downloading $Url : $_" "Red"
        return $false
    }
}

# Function to test if tool already exists
function Test-ToolExists {
    param (
        [string]$ToolName
    )

    $path = Join-Path $InstallPath $ToolName
    return (Test-Path $path)
}

# Main installation function
function Install-SysinternalsTools {
    Write-ColorOutput "=== Sysinternals Tools Installation ===" "Cyan"
    Write-ColorOutput "Installation path: $InstallPath" "Cyan"

    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        Write-ColorOutput "`nCreating installation directory..." "Yellow"
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-ColorOutput "Created: $InstallPath" "Green"
    }
    else {
        Write-ColorOutput "`nInstallation directory exists" "Green"
    }

    if ($DownloadSuite) {
        # Download entire Sysinternals Suite
        Write-ColorOutput "`nDownloading Sysinternals Suite..." "Cyan"

        $suiteZip = Join-Path $env:TEMP "SysinternalsSuite.zip"
        $downloaded = Download-File -Url $sysinternalsSuiteUrl -Destination $suiteZip

        if ($downloaded) {
            Write-ColorOutput "`nExtracting Sysinternals Suite..." "Cyan"

            try {
                # PowerShell 3.0 compatible extraction
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($suiteZip, $InstallPath)

                Write-ColorOutput "Extracted all tools to: $InstallPath" "Green"

                # Clean up
                Remove-Item -Path $suiteZip -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-ColorOutput "ERROR extracting suite: $_" "Red"
                Write-ColorOutput "Falling back to individual tool downloads..." "Yellow"
                $DownloadSuite = $false
            }
        }
        else {
            Write-ColorOutput "Failed to download suite, falling back to individual tools" "Yellow"
            $DownloadSuite = $false
        }
    }

    if (-not $DownloadSuite) {
        # Download individual essential tools
        Write-ColorOutput "`nDownloading essential CCDC tools..." "Cyan"

        $successCount = 0
        $failCount = 0

        foreach ($tool in $essentialTools) {
            Write-ColorOutput "`nTool: $tool" "Yellow"

            # Check if already exists
            if (Test-ToolExists -ToolName $tool) {
                Write-ColorOutput "  Already exists - skipping" "Gray"
                $successCount++
                continue
            }

            # Download from Sysinternals Live
            $url = "$sysinternalsLiveUrl/$tool"
            $destination = Join-Path $InstallPath $tool

            $downloaded = Download-File -Url $url -Destination $destination

            if ($downloaded) {
                $successCount++
            }
            else {
                $failCount++
            }
        }

        Write-ColorOutput "`n=== Download Summary ===" "Cyan"
        Write-ColorOutput "Successful: $successCount" "Green"
        Write-ColorOutput "Failed: $failCount" "Red"
    }

    # Verify essential tools
    Write-ColorOutput "`n=== Verifying Essential Tools ===" "Cyan"

    $critical = @("autorunsc64.exe", "sysmon64.exe", "pslist.exe")
    $allCriticalPresent = $true

    foreach ($tool in $critical) {
        $exists = Test-ToolExists -ToolName $tool
        $status = if ($exists) { "OK" } else { "MISSING" }
        $color = if ($exists) { "Green" } else { "Red" }

        Write-ColorOutput "  $tool : $status" $color

        if (-not $exists) {
            $allCriticalPresent = $false
        }
    }

    if (-not $allCriticalPresent) {
        Write-ColorOutput "`nWARNING: Some critical tools are missing" "Yellow"
        Write-ColorOutput "Try downloading manually from: https://live.sysinternals.com" "Yellow"
    }

    # Add to PATH if requested
    if ($AddToPath) {
        Write-ColorOutput "`n=== Adding to System PATH ===" "Cyan"

        try {
            # Get current PATH
            $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)

            # Check if already in PATH
            if ($currentPath -like "*$InstallPath*") {
                Write-ColorOutput "Already in system PATH" "Green"
            }
            else {
                # Add to PATH
                $newPath = "$currentPath;$InstallPath"
                [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)

                Write-ColorOutput "Added to system PATH" "Green"
                Write-ColorOutput "Restart PowerShell to use tools from any location" "Yellow"
            }
        }
        catch {
            Write-ColorOutput "ERROR adding to PATH: $_" "Red"
            Write-ColorOutput "You may need to run this script as Administrator" "Yellow"
        }
    }

    # Display usage information
    Write-ColorOutput "`n=== Installation Complete ===" "Green"
    Write-ColorOutput "`nInstalled tools location: $InstallPath" "Cyan"
    Write-ColorOutput "`nKey tools for CCDC:" "Cyan"
    Write-ColorOutput "  autorunsc64.exe - Detect persistence mechanisms" "White"
    Write-ColorOutput "  sysmon64.exe    - Real-time system monitoring" "White"
    Write-ColorOutput "  pslist.exe      - Process enumeration" "White"
    Write-ColorOutput "  tcpvcon.exe     - Network connections" "White"
    Write-ColorOutput "  sigcheck.exe    - File integrity checking" "White"

    Write-ColorOutput "`nUsage examples:" "Cyan"
    Write-ColorOutput "  .\scripts\Invoke-PersistenceCheck.ps1          # Detect persistence" "Gray"
    Write-ColorOutput "  .\scripts\Install-Sysmon.ps1                   # Install Sysmon" "Gray"
    Write-ColorOutput "  $InstallPath\autorunsc64.exe -accepteula -a *  # Manual scan" "Gray"

    Write-ColorOutput "`nNext steps:" "Cyan"
    Write-ColorOutput "  1. Run: just backup                            # Create baseline" "Yellow"
    Write-ColorOutput "  2. Run: just install-sysmon                    # Install monitoring" "Yellow"
    Write-ColorOutput "  3. Run: just check-persistence                 # Check for backdoors" "Yellow"
}

# Run installation
Install-SysinternalsTools
