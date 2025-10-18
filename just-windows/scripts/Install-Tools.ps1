<#
.SYNOPSIS
    Installs Windows security and system tools to a specified directory and adds it to PATH.
.DESCRIPTION
    This script installs the following tools from the CSUSB-CCDC repository:
    - Autoruns.exe
    - Chainsaw
    - Hardening Kitty
    - Process Explorer (procexp.exe)
    - TCPView
    The script will download or copy these tools, extract ZIP files, and add the installation
    directory to the system PATH.
.PARAMETER InstallDir
    The directory where the tools will be installed. Defaults to "C:\SecurityTools".
.PARAMETER SourceDir
    Optional. The source directory containing the tool files. If not specified, the script assumes
    the files need to be downloaded.
.EXAMPLE
    .\Install-Tools.ps1
    Installs tools to the default directory (C:\SecurityTools)
.EXAMPLE
    .\Install-Tools.ps1 -InstallDir "D:\Tools" -SourceDir ".\tools"
    Installs tools from the .\tools directory to D:\Tools
#>

param (
    [string]$InstallDir = "C:\SecurityTools",
    [string]$SourceDir = $null
)

# Enable TLS 1.2 for PowerShell 3.0+ (required for HTTPS downloads from GitHub)
# PowerShell 3.0 defaults to TLS 1.0 which most modern sites reject
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "TLS 1.2 enabled for secure downloads" -ForegroundColor Green
} catch {
    Write-Warning "Could not enable TLS 1.2: $_"
    Write-Warning "Downloads may fail. Consider updating to PowerShell 5.1+"
}

# Ensure we're running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You need to run this script as an Administrator!"
    exit 1
}

# Create installation directory if it doesn't exist
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    Write-Host "Created installation directory: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "Using existing installation directory: $InstallDir" -ForegroundColor Yellow
}

# Set the GitHub repository URL for downloading files if no source directory is provided
$repoUrl = "https://github.com/CSUSB-CISO/csusb-ccdc/raw/main/bin/windows"

# Function to download a file if it doesn't exist in the source directory
function Get-ToolFile {
    param (
        [string]$FileName,
        [string]$DestinationPath
    )
    
    if ($SourceDir -and (Test-Path -Path "$SourceDir\$FileName")) {
        Write-Host "Copying $FileName from source directory..." -ForegroundColor Cyan
        Copy-Item -Path "$SourceDir\$FileName" -Destination $DestinationPath
    } else {
        Write-Host "Downloading $FileName..." -ForegroundColor Cyan
        $downloadUrl = "$repoUrl/$FileName"
        
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $DestinationPath
        } catch {
            Write-Error "Failed to download $FileName. Error: $_"
            return $false
        }
    }
    return $true
}

# Tool installation functions
function Install-Autoruns {
    $toolName = "Autoruns.exe"
    $destinationPath = Join-Path -Path $InstallDir -ChildPath $toolName
    
    if (Get-ToolFile -FileName $toolName -DestinationPath $destinationPath) {
        Write-Host "Autoruns installed successfully." -ForegroundColor Green
    }
}

function Install-Chainsaw {
    $zipName = "chainsaw_x86_64-pc-windows-msvc.zip"
    $zipPath = Join-Path -Path $InstallDir -ChildPath $zipName
    $chainsawDir = Join-Path -Path $InstallDir -ChildPath "Chainsaw"
    
    if (Get-ToolFile -FileName $zipName -DestinationPath $zipPath) {
        if (-not (Test-Path -Path $chainsawDir)) {
            New-Item -ItemType Directory -Path $chainsawDir | Out-Null
        }
        
        Write-Host "Extracting Chainsaw..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $chainsawDir -Force
        Remove-Item -Path $zipPath -Force  # Clean up the zip file
        
        # Add the actual executable path to PATH rather than just the top directory
        $chainsawExePath = Join-Path -Path $chainsawDir -ChildPath "chainsaw"
        if (Test-Path -Path $chainsawExePath) {
            Add-DirectoryToPath -Directory $chainsawExePath
        }
        
        Write-Host "Chainsaw installed successfully." -ForegroundColor Green
    }
}

function Install-HardeningKitty {
    $zipName = "hardening_kitty.zip"
    $zipPath = Join-Path -Path $InstallDir -ChildPath $zipName
    $kittyDir = Join-Path -Path $InstallDir -ChildPath "HardeningKitty"
    
    if (Get-ToolFile -FileName $zipName -DestinationPath $zipPath) {
        if (-not (Test-Path -Path $kittyDir)) {
            New-Item -ItemType Directory -Path $kittyDir | Out-Null
        }
        
        Write-Host "Extracting Hardening Kitty..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $kittyDir -Force
        Remove-Item -Path $zipPath -Force  # Clean up the zip file
        
        # Find the module directory
        $sourcePath = Get-ChildItem -Path $kittyDir -Recurse -Filter "HardeningKitty.psm1" | Select-Object -First 1
        if ($sourcePath) {
            $sourceDir = Split-Path -Path $sourcePath.FullName -Parent
            
            # Create a module directory in PowerShell modules path
            $psModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine").Split(';')[0]
            $moduleDestDir = Join-Path -Path $psModulePath -ChildPath "HardeningKitty"
            
            if (-not (Test-Path -Path $moduleDestDir)) {
                New-Item -ItemType Directory -Path $moduleDestDir -Force | Out-Null
            }
            
            # Copy all module files to the modules directory
            Copy-Item -Path "$sourceDir\*" -Destination $moduleDestDir -Recurse -Force
            
            Write-Host "Installed HardeningKitty as a system-wide PowerShell module." -ForegroundColor Green
            Write-Host "You can now use 'Invoke-HardeningKitty' directly from any PowerShell session." -ForegroundColor Green
        } else {
            Write-Host "Could not find HardeningKitty.psm1 in the extracted files." -ForegroundColor Red
        }
        
        Write-Host "Hardening Kitty installed successfully." -ForegroundColor Green
    }
}

function Install-Lynix {
    $zipName = "lynix.zip"
    $zipPath = Join-Path -Path $InstallDir -ChildPath $zipName
    $lynixDir = Join-Path -Path $InstallDir -ChildPath "Lynix"
    
    if (Get-ToolFile -FileName $zipName -DestinationPath $zipPath) {
        if (-not (Test-Path -Path $lynixDir)) {
            New-Item -ItemType Directory -Path $lynixDir | Out-Null
        }
        
        Write-Host "Extracting Lynix..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $lynixDir -Force
        Remove-Item -Path $zipPath -Force  # Clean up the zip file
        
        Write-Host "Lynix installed successfully." -ForegroundColor Green
    }
}

function Install-ProcessExplorer {
    $toolName = "procexp.exe"
    $destinationPath = Join-Path -Path $InstallDir -ChildPath $toolName
    
    if (Get-ToolFile -FileName $toolName -DestinationPath $destinationPath) {
        Write-Host "Process Explorer installed successfully." -ForegroundColor Green
    }
}

function Install-TCPView {
    $exeName = "tcpview.exe"
    $chmName = "tcpview.chm"
    $exePath = Join-Path -Path $InstallDir -ChildPath $exeName
    $chmPath = Join-Path -Path $InstallDir -ChildPath $chmName
    
    $exeSuccess = Get-ToolFile -FileName $exeName -DestinationPath $exePath
    $chmSuccess = Get-ToolFile -FileName $chmName -DestinationPath $chmPath
    
    if ($exeSuccess -and $chmSuccess) {
        Write-Host "TCPView installed successfully." -ForegroundColor Green
    }
}

function Add-DirectoryToPath {
    param (
        [string]$Directory
    )

    # Get the current PATH from the environment variables
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    
    # Check if the directory is already in the PATH
    if ($currentPath -split ";" -contains $Directory) {
        Write-Host "Directory already exists in PATH: $Directory" -ForegroundColor Yellow
        return
    }
    
    # Add the directory to PATH
    $newPath = $currentPath + ";" + $Directory
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
    
    Write-Host "Added directory to system PATH: $Directory" -ForegroundColor Green
}

function Update-SessionEnvironment {
    $HWND_BROADCAST = [IntPtr]0xffff
    $WM_SETTINGCHANGE = 0x001A
    $result = [UIntPtr]::Zero
    
    if (-not ("Win32.NativeMethods" -as [Type])) {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
    }
    
    [Win32.NativeMethods]::SendMessageTimeout(
        $HWND_BROADCAST, $WM_SETTINGCHANGE,
        [UIntPtr]::Zero, "Environment",
        2, 5000, [ref]$result
    ) | Out-Null
    
    # Also update the current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    Write-Host "Environment variables refreshed system-wide" -ForegroundColor Green
}

# Sysinternals Suite installation
function Install-SysinternalsSuite {
    param (
        [switch]$FullSuite
    )

    $sysinternalsDir = Join-Path -Path $InstallDir -ChildPath "Sysinternals"

    if (-not (Test-Path -Path $sysinternalsDir)) {
        New-Item -ItemType Directory -Path $sysinternalsDir | Out-Null
    }

    $sysinternalsLiveUrl = "https://live.sysinternals.com"

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
        "accesschk.exe",    # Access permissions check
        "PsExec.exe",       # Remote execution
        "psinfo.exe",       # System information
        "psfile.exe"        # File/share info
    )

    Write-Host "Installing Sysinternals tools..." -ForegroundColor Cyan

    if ($FullSuite) {
        # Download entire suite
        Write-Host "Downloading full Sysinternals Suite..." -ForegroundColor Cyan
        $suiteZip = Join-Path -Path $env:TEMP -ChildPath "SysinternalsSuite.zip"
        $suiteUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

        try {
            Invoke-WebRequest -Uri $suiteUrl -OutFile $suiteZip -ErrorAction Stop
            Expand-Archive -Path $suiteZip -DestinationPath $sysinternalsDir -Force
            Remove-Item -Path $suiteZip -Force
            Write-Host "Sysinternals Suite extracted successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to download suite, falling back to individual tools"
            $FullSuite = $false
        }
    }

    if (-not $FullSuite) {
        # Download individual essential tools
        $successCount = 0
        $failCount = 0

        foreach ($tool in $essentialTools) {
            $toolPath = Join-Path -Path $sysinternalsDir -ChildPath $tool

            if (Test-Path $toolPath) {
                Write-Host "  $tool - already exists" -ForegroundColor Gray
                $successCount++
                continue
            }

            $url = "$sysinternalsLiveUrl/$tool"

            try {
                Invoke-WebRequest -Uri $url -OutFile $toolPath -ErrorAction Stop
                Write-Host "  $tool - downloaded" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Warning "  $tool - failed to download"
                $failCount++
            }
        }

        Write-Host "`nSysinternals installation summary:" -ForegroundColor Cyan
        Write-Host "  Success: $successCount" -ForegroundColor Green
        Write-Host "  Failed: $failCount" -ForegroundColor Red
    }

    # Add Sysinternals directory to PATH
    Add-DirectoryToPath -Directory $sysinternalsDir

    Write-Host "Sysinternals tools installed to: $sysinternalsDir" -ForegroundColor Green
}

# Sysmon installation with default configuration
function Install-Sysmon {
    param (
        [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    )

    Write-Host "`nInstalling Sysmon for real-time system monitoring..." -ForegroundColor Cyan

    $sysinternalsDir = Join-Path -Path $InstallDir -ChildPath "Sysinternals"
    $sysmonPath = Join-Path -Path $sysinternalsDir -ChildPath "sysmon64.exe"
    $configPath = Join-Path -Path $sysinternalsDir -ChildPath "sysmonconfig.xml"

    # Check if Sysmon is already installed
    $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Write-Host "Sysmon is already installed. Updating configuration..." -ForegroundColor Yellow

        # Download latest config
        try {
            Write-Host "Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath -ErrorAction Stop

            # Update Sysmon config
            & $sysmonPath -c $configPath -accepteula
            Write-Host "Sysmon configuration updated successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to update Sysmon configuration: $_"
        }
        return
    }

    # Ensure Sysmon binary exists
    if (-not (Test-Path $sysmonPath)) {
        Write-Warning "Sysmon64.exe not found. Please run Install-SysinternalsSuite first."
        return
    }

    # Download Sysmon configuration
    try {
        Write-Host "Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Cyan
        Write-Host "Source: $ConfigUrl" -ForegroundColor Gray
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath -ErrorAction Stop
        Write-Host "Configuration downloaded successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download Sysmon configuration: $_"
        Write-Host "Attempting to install Sysmon with default configuration..." -ForegroundColor Yellow
        $configPath = $null
    }

    # Install Sysmon
    Write-Host "Installing Sysmon64 service..." -ForegroundColor Cyan

    try {
        if ($configPath -and (Test-Path $configPath)) {
            & $sysmonPath -accepteula -i $configPath
        } else {
            & $sysmonPath -accepteula -i
        }

        # Verify installation
        Start-Sleep -Seconds 2
        $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            Write-Host "`nSysmon installed and running successfully!" -ForegroundColor Green
            Write-Host "Event Log: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
            Write-Host "Configuration: $configPath" -ForegroundColor Cyan

            # Show what Sysmon monitors
            Write-Host "`nSysmon is now monitoring:" -ForegroundColor Yellow
            Write-Host "  - Process creation (Event ID 1)" -ForegroundColor White
            Write-Host "  - Network connections (Event ID 3)" -ForegroundColor White
            Write-Host "  - Process termination (Event ID 5)" -ForegroundColor White
            Write-Host "  - Driver loads (Event ID 6)" -ForegroundColor White
            Write-Host "  - Image loads (Event ID 7)" -ForegroundColor White
            Write-Host "  - File creation (Event ID 11)" -ForegroundColor White
            Write-Host "  - Registry modifications (Event ID 12, 13, 14)" -ForegroundColor White
            Write-Host "  - Named pipe events (Event ID 17, 18)" -ForegroundColor White
            Write-Host "  - WMI events (Event ID 19, 20, 21)" -ForegroundColor White
            Write-Host "  - DNS queries (Event ID 22)" -ForegroundColor White

            # Provide usage examples
            Write-Host "`nQuery Sysmon events:" -ForegroundColor Cyan
            Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100" -ForegroundColor Gray
            Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 50" -ForegroundColor Gray
        } else {
            Write-Error "Sysmon installation failed or service is not running"
        }
    } catch {
        Write-Error "Error installing Sysmon: $_"
    }
}

# Main installation process
Write-Host "Starting installation of security tools..." -ForegroundColor Magenta

# Install each tool
Install-Autoruns
Install-Chainsaw
Install-HardeningKitty
# Install-Lynix (excluded as requested)
Install-ProcessExplorer
Install-TCPView

# Install Sysinternals Suite (essential tools)
Install-SysinternalsSuite

# Install Sysmon for real-time monitoring
Install-Sysmon

# Add the installation directory to PATH
Add-DirectoryToPath -Directory $InstallDir

# Broadcast the environment changes to all Windows processes
Update-SessionEnvironment

Write-Host "`n=== Installation Complete ===" -ForegroundColor Magenta
Write-Host "All tools have been installed to $InstallDir and added to PATH." -ForegroundColor Green
Write-Host "The PATH has been updated in the current session and broadcast to other applications." -ForegroundColor Green

# Summary of installed components
Write-Host "`n=== Installed Components ===" -ForegroundColor Cyan
Write-Host "  - Autoruns (GUI)" -ForegroundColor White
Write-Host "  - Chainsaw (log analysis)" -ForegroundColor White
Write-Host "  - HardeningKitty (PowerShell module)" -ForegroundColor White
Write-Host "  - Process Explorer" -ForegroundColor White
Write-Host "  - TCPView" -ForegroundColor White
Write-Host "  - Sysinternals Suite (15+ tools)" -ForegroundColor White
Write-Host "  - Sysmon64 (real-time monitoring)" -ForegroundColor White

Write-Host "`n=== Quick Start Commands ===" -ForegroundColor Cyan
Write-Host "  just check-persistence         # Detect backdoors/persistence" -ForegroundColor Gray
Write-Host "  just backup                    # Create baseline" -ForegroundColor Gray
Write-Host "  just diff                      # Check all changes" -ForegroundColor Gray
Write-Host "  autorunsc64 -accepteula -a *   # Manual persistence scan" -ForegroundColor Gray

