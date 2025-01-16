function Initialize-SecurityDirectory {
    $script:logPath = "C:\Program Files\SecurityConfig"
    New-Item -ItemType Directory -Path $logPath -Force
}

function Write-SecurityLog {
    [CmdletBinding()]
    param(
        [string]$Component,
        [string]$Message,
        [ValidateSet('Info', 'Error', 'Warning')]
        [string]$Level = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $script:logPath "$Component.log"
    "$timestamp [$Level] - $Message" | Out-File $logFile -Append
    
    switch($Level) {
        'Error' { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        default { Write-Output $Message }
    }
}

# Install-OpenSSH
<#
.SYNOPSIS
    Installs and configures OpenSSH for Windows.

.DESCRIPTION
    Downloads, installs, and configures the latest version of OpenSSH for Windows.
    Includes firewall rule creation, service configuration, and security settings.

.NOTES
    Requires administrative privileges.
    Creates comprehensive logs of all operations.
    Sets up secure default configurations.

.EXAMPLE
    Install-OpenSSH
#>
function Install-OpenSSH {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting OpenSSH installation..." -Verbose
    
    try {
        # Configure TLS 1.2
        Write-Verbose "Configuring TLS 1.2..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-SecurityLog -Component "OpenSSH" -Message "Successfully configured TLS 1.2"

        # Define installation paths
        $installPath = "C:\Program Files\OpenSSH\"
        $tempPath = Join-Path $env:TEMP "OpenSSH-Win64"
        $zipPath = Join-Path (Get-Location).Path "OpenSSH-Win64.zip"

        # Download latest OpenSSH release
        Write-Verbose "Downloading latest OpenSSH release..."
        $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
        $request = [System.Net.WebRequest]::Create($url)
        $request.AllowAutoRedirect = $false
        
        try {
            $response = $request.GetResponse()
            $source = $([String]$response.GetResponseHeader("Location")).Replace('tag', 'download') + '/OpenSSH-Win64.zip'
            $webClient = [System.Net.WebClient]::new()
            $webClient.DownloadFile($source, $zipPath)
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully downloaded OpenSSH package"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to download OpenSSH: $_" -Level Error
            throw
        }

        # Extract and install OpenSSH
        Write-Verbose "Extracting and installing OpenSSH..."
        try {
            Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
            
            # Ensure installation directory is clean
            if (Test-Path $installPath) {
                Remove-Item -Path $installPath -Recurse -Force
            }
            
            Move-Item $tempPath -Destination $installPath -Force
            Get-ChildItem -Path $installPath | Unblock-File
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully extracted and installed OpenSSH"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to extract/install OpenSSH: $_" -Level Error
            throw
        }

        # Install and configure SSHD service
        Write-Verbose "Configuring SSHD service..."
        try {
            & "$installPath\install-sshd.ps1"
            Set-Service sshd -StartupType Automatic
            Start-Service sshd
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully configured SSHD service"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to configure SSHD service: $_" -Level Error
            throw
        }

        # Configure firewall
        Write-Verbose "Configuring firewall rules..."
        try {
            if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
                Write-SecurityLog -Component "OpenSSH" -Message "Successfully created firewall rule"
            }
            else {
                Write-SecurityLog -Component "OpenSSH" -Message "Firewall rule already exists" -Level Info
            }
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to configure firewall: $_" -Level Error
            throw
        }

        # Configure default shell
        Write-Verbose "Configuring default shell..."
        try {
            $shellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $shellPath -PropertyType String -Force
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully configured default shell"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to configure default shell: $_" -Level Warning
        }

        # Configure permissions
        Write-Verbose "Configuring security permissions..."
        try {
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly
            $objType = [System.Security.AccessControl.AccessControlType]::Allow 
            
            $acl = Get-Acl $installPath
            $permission = "NT Authority\Authenticated Users", "ReadAndExecute", $InheritanceFlag, $PropagationFlag, $objType
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
            $acl.SetAccessRule($accessRule)
            Set-Acl $installPath $acl
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully configured security permissions"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to configure permissions: $_" -Level Error
            throw
        }

        # Cleanup
        Write-Verbose "Cleaning up temporary files..."
        try {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            Write-SecurityLog -Component "OpenSSH" -Message "Successfully cleaned up temporary files"
        }
        catch {
            Write-SecurityLog -Component "OpenSSH" -Message "Failed to clean up temporary files: $_" -Level Warning
        }

        Write-SecurityLog -Component "OpenSSH" -Message "OpenSSH installation and configuration completed successfully"
    }
    catch {
        Write-SecurityLog -Component "OpenSSH" -Message "OpenSSH installation failed: $_" -Level Error
        throw
    }
}

# Main execution
Initialize-SecurityDirectory
Install-OpenSSH
