param(
    [string]$BaseDir = "C:\KeyboardKowboys"
)

# PowerShell version compatibility check
$PSVersion = $PSVersionTable.PSVersion.Major
Write-Host "PowerShell Version: $PSVersion" -ForegroundColor Cyan

if ($PSVersion -lt 3) {
    Write-Host "ERROR: This script requires PowerShell 3.0 or higher" -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}

# Enable TLS 1.2 for PowerShell 3.0+ (required for HTTPS downloads from GitHub)
# PowerShell 3.0 defaults to TLS 1.0 which most modern sites reject
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "TLS 1.2 enabled for secure downloads" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not enable TLS 1.2: $_" -ForegroundColor Yellow
    Write-Host "Downloads may fail. Consider updating to PowerShell 5.1+" -ForegroundColor Yellow
}

# Import Win32 API for broadcasting environment changes
if (-not ("Win32.NativeMethods" -as [Type])) {
    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
}

# Function to broadcast environment changes system-wide
function Update-SessionEnvironment {
    $HWND_BROADCAST = [IntPtr]0xffff
    $WM_SETTINGCHANGE = 0x001A
    $result = [UIntPtr]::Zero
    
    [Win32.NativeMethods]::SendMessageTimeout(
        $HWND_BROADCAST, $WM_SETTINGCHANGE,
        [UIntPtr]::Zero, "Environment",
        2, 5000, [ref]$result
    ) | Out-Null
    
    # Also update the current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    Write-Host "Environment variables refreshed system-wide" -ForegroundColor Green
}

# Function to add a directory to PATH with graceful degradation
function Add-DirectoryToPath {
    param (
        [string]$Directory,
        [string]$PathType = "User" # Can be "User" or "Machine"
    )

    # Get the current PATH from the environment variables
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", $PathType)

    # Check if the directory is already in the PATH
    if ($currentPath -split ";" -contains $Directory) {
        Write-Host "Directory already exists in PATH: $Directory" -ForegroundColor Yellow
        return $true
    }

    try {
        # Add the directory to PATH
        $newPath = $currentPath + ";" + $Directory
        [Environment]::SetEnvironmentVariable("PATH", $newPath, $PathType)
        Write-Host "Added directory to $PathType PATH: $Directory" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "WARNING: Could not add to $PathType PATH (requires admin rights)" -ForegroundColor Yellow

        # If Machine PATH failed, try User PATH as fallback
        if ($PathType -eq "Machine") {
            Write-Host "Falling back to User PATH..." -ForegroundColor Yellow
            return (Add-DirectoryToPath -Directory $Directory -PathType "User")
        }

        Write-Host "You can manually add to PATH: $Directory" -ForegroundColor Yellow
        return $false
    }
}

# Function to download files with PowerShell 3.0 compatibility
function Download-File {
    param (
        [string]$Url,
        [string]$OutFile
    )

    try {
        if ($PSVersion -ge 3) {
            # Use Invoke-WebRequest for PS 3.0+
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            return $true
        }
        else {
            # Fallback to WebClient for older versions
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($Url, $OutFile)
            $webClient.Dispose()
            return $true
        }
    }
    catch {
        Write-Host "ERROR downloading $Url : $_" -ForegroundColor Red
        return $false
    }
}

# Function to detect system architecture
function Get-SystemArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    $is64Bit = [Environment]::Is64BitOperatingSystem

    if ($is64Bit) {
        return "x86_64-pc-windows-msvc"
    }
    else {
        return "i686-pc-windows-msvc"
    }
}

# Display script info
Write-Host "Setting up Keyboard Kowboys environment at: $BaseDir" -ForegroundColor Green

# Create necessary subdirectories based on the Justfile
$Directories = @(
    $BaseDir,
    "$BaseDir\scripts",
    "$BaseDir\ops",
    "$BaseDir\backups",
    "$BaseDir\tools",
    "$BaseDir\configs",
    "$BaseDir\logs",
    "$BaseDir\bin"  # Added bin directory for executables
)

# Create the directories
foreach ($Dir in $Directories) {
    if (-not (Test-Path -Path $Dir)) {
        Write-Host "Creating directory: $Dir" -ForegroundColor Yellow
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
    } else {
        Write-Host "Directory already exists: $Dir" -ForegroundColor Cyan
    }
}

# Set permissions (Administrators get full control)
$Acl = Get-Acl -Path $BaseDir
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$Acl.SetAccessRule($Ar)
Set-Acl -Path $BaseDir -AclObject $Acl

# Create temporary directory for downloading files
$TmpDir = Join-Path -Path $env:TEMP -ChildPath "KKowboys_$(Get-Random)"
New-Item -Path $TmpDir -ItemType Directory -Force | Out-Null

try {
    # Download the zip file
    $ZipUrl = "https://github.com/CSUSB-CISO/csusb-ccdc/releases/download/CCDC-2024-2025/just-win.zip"
    $ZipFile = Join-Path -Path $TmpDir -ChildPath "just-win.zip"

    Write-Host "Downloading Keyboard Kowboys files..." -ForegroundColor Green

    # Use our Download-File function for compatibility
    $downloadSuccess = Download-File -Url $ZipUrl -OutFile $ZipFile

    # Check if download was successful
    if (-not $downloadSuccess -or -not (Test-Path -Path $ZipFile)) {
        throw "Failed to download the zip file. Please check your internet connection."
    }
    
    # Extract files to a temporary directory to examine the structure
    $ExtractTempDir = Join-Path -Path $TmpDir -ChildPath "extract_temp"
    Write-Host "Examining zip contents..." -ForegroundColor Green
    
    # Extract the ZIP file
    Expand-Archive -Path $ZipFile -DestinationPath $ExtractTempDir -Force
    
    # Check what was extracted
    $Items = Get-ChildItem -Path $ExtractTempDir
    foreach ($Item in $Items) {
        Write-Host "Found in zip: $($Item.Name)" -ForegroundColor Gray
    }
    
    # Check if "just-windows" directory exists in the zip contents
    $JustWindowsDir = Join-Path -Path $ExtractTempDir -ChildPath "just-windows"
    if (Test-Path -Path $JustWindowsDir) {
        Write-Host "Found 'just-windows' directory in the zip contents" -ForegroundColor Green

        # Check for Justfile in the just-windows directory
        $JustfilePaths = @(
            (Join-Path -Path $JustWindowsDir -ChildPath "Justfile"),
            (Join-Path -Path $JustWindowsDir -ChildPath "justfile")
        )

        $JustfileFound = $false
        foreach ($JustfilePath in $JustfilePaths) {
            if (Test-Path -Path $JustfilePath) {
                $targetJustfile = Join-Path -Path $BaseDir -ChildPath "Justfile"

                # Only copy if Justfile doesn't exist (preserve existing)
                if (-not (Test-Path -Path $targetJustfile)) {
                    Write-Host "Copying Justfile..." -ForegroundColor Green
                    Copy-Item -Path $JustfilePath -Destination $targetJustfile -Force
                }
                else {
                    Write-Host "Justfile already exists (preserving existing)" -ForegroundColor Yellow
                }
                $JustfileFound = $true
                break
            }
        }

        # Copy scripts if they exist (preserve existing files)
        $ScriptsDir = Join-Path -Path $JustWindowsDir -ChildPath "scripts"
        if (Test-Path -Path $ScriptsDir) {
            Write-Host "Copying scripts (preserving existing files)..." -ForegroundColor Green
            $sourceScripts = Get-ChildItem -Path $ScriptsDir -File
            foreach ($script in $sourceScripts) {
                $targetScript = Join-Path -Path "$BaseDir\scripts" -ChildPath $script.Name

                if (-not (Test-Path -Path $targetScript)) {
                    Write-Host "  Adding new script: $($script.Name)" -ForegroundColor Cyan
                    Copy-Item -Path $script.FullName -Destination $targetScript -Force
                }
                else {
                    Write-Host "  Script already exists (skipping): $($script.Name)" -ForegroundColor Gray
                }
            }
        }

        # If Justfile not found, copy all contents (preserving existing)
        if (-not $JustfileFound) {
            Write-Host "Could not find Justfile inside just-windows directory, copying all content" -ForegroundColor Yellow
            $items = Get-ChildItem -Path $JustWindowsDir
            foreach ($item in $items) {
                $targetPath = Join-Path -Path $BaseDir -ChildPath $item.Name

                if (-not (Test-Path -Path $targetPath)) {
                    Copy-Item -Path $item.FullName -Destination $targetPath -Recurse -Force
                }
                else {
                    Write-Host "  Item already exists (skipping): $($item.Name)" -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host "No 'just-windows' directory found, copying all extracted files (preserving existing)..." -ForegroundColor Yellow
        $items = Get-ChildItem -Path $ExtractTempDir
        foreach ($item in $items) {
            $targetPath = Join-Path -Path $BaseDir -ChildPath $item.Name

            if (-not (Test-Path -Path $targetPath)) {
                Copy-Item -Path $item.FullName -Destination $targetPath -Recurse -Force
            }
            else {
                Write-Host "  Item already exists (skipping): $($item.Name)" -ForegroundColor Gray
            }
        }
    }
    
    # Define the bin directory
    $BinDir = "$BaseDir\bin"
    
    # Install 'just' if not already installed
    if (-not (Get-Command -Name "just" -ErrorAction SilentlyContinue)) {
        Write-Host "Installing 'just' command..." -ForegroundColor Green

        $JustVersion = "1.40.0"
        $JustArch = Get-SystemArchitecture

        Write-Host "Detected architecture: $JustArch" -ForegroundColor Cyan

        $JustUrl = "https://github.com/casey/just/releases/download/$JustVersion/just-$JustVersion-$JustArch.zip"
        $JustZipFile = Join-Path -Path $TmpDir -ChildPath "just.zip"
        $JustExtractDir = Join-Path -Path $TmpDir -ChildPath "just_extract"

        Write-Host "Downloading just $JustVersion for $JustArch..." -ForegroundColor Yellow

        # Use our Download-File function for compatibility
        $downloadSuccess = Download-File -Url $JustUrl -OutFile $JustZipFile

        if (-not $downloadSuccess) {
            Write-Host "ERROR: Failed to download just" -ForegroundColor Red
            throw "just download failed"
        }
        
        # Create directory for extraction
        New-Item -Path $JustExtractDir -ItemType Directory -Force | Out-Null
        
        # Extract Just
        Expand-Archive -Path $JustZipFile -DestinationPath $JustExtractDir -Force
        
        # Install just to our bin directory
        $JustExe = Join-Path -Path $JustExtractDir -ChildPath "just.exe"
        $TargetExe = Join-Path -Path $BinDir -ChildPath "just.exe"
        
        Write-Host "Installing just to: $TargetExe" -ForegroundColor Green
        Copy-Item -Path $JustExe -Destination $TargetExe -Force
        
        Write-Host "just installed successfully to $TargetExe" -ForegroundColor Green
    } else {
        Write-Host "just is already installed." -ForegroundColor Green
        
        # Copy just.exe to our bin directory if found in PATH
        $existingJust = Get-Command -Name "just" -ErrorAction SilentlyContinue
        if ($null -ne $existingJust) {
            $TargetExe = Join-Path -Path $BinDir -ChildPath "just.exe"
            Write-Host "Copying existing just from $($existingJust.Source) to bin directory..." -ForegroundColor Green
            Copy-Item -Path $existingJust.Source -Destination $TargetExe -Force
        }
    }
    
    # If Justfile was not found in the zip, create a simple one based on the provided Justfile
    $JustfilePath = Join-Path -Path $BaseDir -ChildPath "Justfile"
    if (-not (Test-Path -Path $JustfilePath)) {
        Write-Host "No Justfile found, creating a simple one..." -ForegroundColor Yellow
        
        $JustfileContent = @"
set shell := ["powershell.exe", "-c"]

base_dir := "$($BaseDir.Replace('\', '/'))"
scripts_dir := base_dir + "/scripts"
ops_dir := base_dir + "/ops"
backup_dir := base_dir + "/backups"
tools_dir := base_dir + "/tools"
config_dir := base_dir + "/configs"
log_dir := base_dir + "/logs"
bin_dir := base_dir + "/bin"

# Display available commands with descriptions
default:
    @just --list

# Initialize directory structure (run once or after reset)
init:
    powershell -Command "Write-Host 'Setting up keyboard kowboys operation environment...' -ForegroundColor Green; \
    \$Dirs = @('{{base_dir}}', '{{scripts_dir}}', '{{ops_dir}}', '{{backup_dir}}', '{{tools_dir}}', '{{config_dir}}', '{{log_dir}}', '{{bin_dir}}'); \
    foreach (\$Dir in \$Dirs) { \
        if (-not (Test-Path \$Dir)) { \
            New-Item -Path \$Dir -ItemType Directory -Force | Out-Null; \
            Write-Host ('Created directory: ' + \$Dir) -ForegroundColor Yellow; \
        } else { \
            Write-Host ('Directory already exists: ' + \$Dir) -ForegroundColor Cyan; \
        } \
    } \
    # Set appropriate permissions \
    \$Acl = Get-Acl -Path '{{base_dir}}'; \
    \$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'); \
    \$Acl.SetAccessRule(\$Ar); \
    Set-Acl -Path '{{base_dir}}' -AclObject \$Acl; \
    Write-Host 'Directory structure created at {{base_dir}}' -ForegroundColor Green;"
"@
        
        # Write the Justfile
        $JustfileContent | Out-File -FilePath $JustfilePath -Encoding utf8 -Force
    }
    
    # Look for any executable files in tools directory and copy to bin directory
    $ToolsDir = Join-Path -Path $BaseDir -ChildPath "tools"
    if (Test-Path -Path $ToolsDir) {
        Write-Host "Checking for tool executables to copy to bin directory..." -ForegroundColor Green
        $Executables = Get-ChildItem -Path $ToolsDir -Include "*.exe", "*.ps1" -Recurse -ErrorAction SilentlyContinue
        foreach ($Exe in $Executables) {
            $TargetPath = Join-Path -Path $BinDir -ChildPath $Exe.Name
            Write-Host "Copying $($Exe.Name) to bin directory..." -ForegroundColor Cyan
            Copy-Item -Path $Exe.FullName -Destination $TargetPath -Force
        }
    }
    
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-Host "Running with Administrator privileges" -ForegroundColor Green

        # Add bin directory to Machine PATH
        Write-Host "Adding bin directory to Machine PATH..." -ForegroundColor Green
        Add-DirectoryToPath -Directory $BinDir -PathType "Machine"

        # Add scripts directory to Machine PATH
        $ScriptsDirPath = Join-Path -Path $BaseDir -ChildPath "scripts"
        if (Test-Path -Path $ScriptsDirPath) {
            Write-Host "Adding scripts directory to Machine PATH..." -ForegroundColor Green
            Add-DirectoryToPath -Directory $ScriptsDirPath -PathType "Machine"
        }
    }
    else {
        Write-Host "Not running as Administrator - using User PATH" -ForegroundColor Yellow

        # Add bin directory to User PATH
        Write-Host "Adding bin directory to User PATH..." -ForegroundColor Green
        Add-DirectoryToPath -Directory $BinDir -PathType "User"

        # Add scripts directory to User PATH
        $ScriptsDirPath = Join-Path -Path $BaseDir -ChildPath "scripts"
        if (Test-Path -Path $ScriptsDirPath) {
            Write-Host "Adding scripts directory to User PATH..." -ForegroundColor Green
            Add-DirectoryToPath -Directory $ScriptsDirPath -PathType "User"
        }

        Write-Host ""
        Write-Host "TIP: Run as Administrator to add to Machine PATH (available to all users)" -ForegroundColor Cyan
    }
    
    # Broadcast the environment changes
    Write-Host "Broadcasting environment changes..." -ForegroundColor Green
    Update-SessionEnvironment
    
    # Done
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Keyboard Kowboys environment has been set up successfully!" -ForegroundColor Green
    Write-Host "Base directory: $BaseDir" -ForegroundColor Green
    Write-Host "Bin directory: $BinDir" -ForegroundColor Green
    Write-Host "" -ForegroundColor Green
    
    # Test if just is available in current session
    if (Get-Command -Name "just" -ErrorAction SilentlyContinue) {
        Write-Host "just command is available in the current session" -ForegroundColor Green
        Write-Host "To use just, simply run:" -ForegroundColor Yellow
        Write-Host "  just --list" -ForegroundColor Yellow
    } else {
        Write-Host "just should be available at: $BinDir\just.exe" -ForegroundColor Green
        Write-Host "You can run it directly as: $BinDir\just.exe --list" -ForegroundColor Yellow
    }
    
    # Show current PATH for verification
    Write-Host "" -ForegroundColor Green
    Write-Host "Current PATH includes:" -ForegroundColor Cyan
    $EnvPath = $env:PATH -split ";"
    foreach ($PathEntry in $EnvPath) {
        if ($PathEntry -eq $BinDir -or $PathEntry -eq $ScriptsDirPath) {
            Write-Host "  $PathEntry" -ForegroundColor Green
        }
    }
    
    Write-Host "==========================================================" -ForegroundColor Cyan
} finally {
    # Clean up
    if (Test-Path -Path $TmpDir) {
        Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
