# PowerShell Upgrade Script
# Requires: Administrative privileges

[CmdletBinding()]
param()

# Define download URLs
$urls = @{
    'WinServ2012R2' = 'https://go.microsoft.com/fwlink/?linkid=839516'
    'WinServ2012'   = 'https://go.microsoft.com/fwlink/?linkid=839513'
    'WinServ2008R2' = 'https://go.microsoft.com/fwlink/?linkid=839523'
    'Win8'          = 'https://go.microsoft.com/fwlink/?linkid=839521'
    'Win7'          = 'https://go.microsoft.com/fwlink/?linkid=839522'
    'Prerequisites' = @{
        'Win7'         = 'https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe'
        'WinServ2008R2'= 'https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe'
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Info'    { Write-Host $logMessage -ForegroundColor Green }
    }
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Download-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        Write-Log "Downloading from $Url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $Path)
        Write-Log "Download completed successfully"
        return $true
    }
    catch {
        Write-Log "Failed to download file: $_" -Level Error
        return $false
    }
}

function Install-Update {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        Write-Log "Installing update from $Path"
        $process = Start-Process -FilePath "wusa.exe" -ArgumentList "/update $Path /quiet /promptrestart" -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Update installed successfully"
            return $true
        }
        else {
            Write-Log "Update installation failed with exit code: $($process.ExitCode)" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Failed to install update: $_" -Level Error
        return $false
    }
}

function Install-Prerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OSVersion
    )
    
    if ($urls.Prerequisites.ContainsKey($OSVersion)) {
        $prereqUrl = $urls.Prerequisites[$OSVersion]
        $prereqPath = Join-Path $env:TEMP "prereq.exe"
        
        if (Download-File -Url $prereqUrl -Path $prereqPath) {
            Write-Log "Installing prerequisites for $OSVersion"
            Start-Process -FilePath $prereqPath -ArgumentList "/quiet /norestart" -Wait
            Remove-Item $prereqPath -Force
        }
    }
}

function Update-PowerShell {
    [CmdletBinding()]
    param()
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log "This script requires administrative privileges" -Level Error
        return
    }
    
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osCaption = $os.Caption
    
    Write-Log "Detected OS: $osCaption"
    
    switch -Wildcard ($osCaption) {
        '*Windows 10*' { 
            Write-Log "PowerShell 5.1 is included in Windows 10" 
        }
        
        '*Windows Server 2016*' { 
            Write-Log "PowerShell 5.1 is included in Windows Server 2016" 
        }
        
        '*Windows Server 2012*' {
            $updatePath = Join-Path $env:TEMP "Win2012-PSUpdate.msu"
            if (Download-File -Url $urls.WinServ2012R2 -Path $updatePath) {
                Install-Update -Path $updatePath
                Remove-Item $updatePath -Force
            }
        }
        
        '*Windows 7*' {
            Install-Prerequisites -OSVersion 'Win7'
            $updatePath = Join-Path $env:TEMP "Win7-PSUpdate.msu"
            if (Download-File -Url $urls.Win7 -Path $updatePath) {
                Install-Update -Path $updatePath
                Remove-Item $updatePath -Force
            }
        }
        
        '*Windows Server 2008 R2*' {
            Install-Prerequisites -OSVersion 'WinServ2008R2'
            $updatePath = Join-Path $env:TEMP "Win2008R2-PSUpdate.msu"
            if (Download-File -Url $urls.WinServ2008R2 -Path $updatePath) {
                Install-Update -Path $updatePath
                Remove-Item $updatePath -Force
            }
        }
        
        default {
            Write-Log "Unsupported operating system: $osCaption" -Level Warning
        }
    }
}

# Main execution
try {
    Update-PowerShell
    Write-Log "PowerShell upgrade process completed"
}
catch {
    Write-Log "An unexpected error occurred: $_" -Level Error
}
