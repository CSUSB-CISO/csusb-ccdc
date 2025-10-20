#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures PowerShell profile to always use TLS 1.2 for HTTPS connections

.DESCRIPTION
    This script creates or updates the PowerShell profile for all users to ensure
    TLS 1.2 is always enabled. This prevents SSL/TLS errors when downloading from
    modern HTTPS sites, especially in PowerShell 3.0 which defaults to TLS 1.0.

.EXAMPLE
    .\Initialize-PowerShellProfile.ps1

.NOTES
    PowerShell 3.0+ compatible
    Requires Administrator privileges
#>

[CmdletBinding()]
param()

# Profile paths for different PowerShell hosts
$profilePaths = @(
    $PROFILE.AllUsersAllHosts,           # All users, all hosts
    $PROFILE.AllUsersCurrentHost,        # All users, current host
    $PROFILE.CurrentUserAllHosts,        # Current user, all hosts
    $PROFILE.CurrentUserCurrentHost      # Current user, current host
)

# The TLS 1.2 configuration snippet to add
$tlsConfig = @'

# Enable TLS 1.2 for all HTTPS connections (required for PowerShell 3.0)
# This prevents SSL/TLS errors when downloading from modern HTTPS sites
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    # Silently ignore if TLS 1.2 is not available
}
'@

function Write-ColorOutput {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

Write-ColorOutput "`n===== PowerShell Profile TLS 1.2 Configuration =====" "Cyan"

# Set TLS 1.2 for this session
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-ColorOutput "TLS 1.2 enabled for current session" "Green"
} catch {
    Write-ColorOutput "WARNING: Could not enable TLS 1.2 for current session" "Yellow"
}

# Configure all user profile
$allUsersProfile = $PROFILE.AllUsersAllHosts
$profileDir = Split-Path -Parent $allUsersProfile

# Create profile directory if it doesn't exist
if (-not (Test-Path $profileDir)) {
    Write-ColorOutput "Creating profile directory: $profileDir" "Yellow"
    New-Item -Path $profileDir -ItemType Directory -Force | Out-Null
}

# Check if profile exists and if it already has TLS 1.2 configuration
$needsUpdate = $true
if (Test-Path $allUsersProfile) {
    $currentContent = Get-Content -Path $allUsersProfile -Raw
    if ($currentContent -like "*SecurityProtocol*Tls12*") {
        Write-ColorOutput "TLS 1.2 configuration already exists in profile" "Green"
        $needsUpdate = $false
    }
}

if ($needsUpdate) {
    Write-ColorOutput "Adding TLS 1.2 configuration to profile: $allUsersProfile" "Yellow"

    # Append TLS configuration to profile
    Add-Content -Path $allUsersProfile -Value $tlsConfig

    Write-ColorOutput "Profile updated successfully!" "Green"
} else {
    Write-ColorOutput "No profile update needed" "Cyan"
}

# Also set system-wide registry keys for maximum compatibility
Write-ColorOutput "`nConfiguring system-wide TLS settings in registry..." "Cyan"

$registrySettings = @(
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        Name = "SchUseStrongCrypto"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        Name = "SchUseStrongCrypto"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        Name = "DisabledByDefault"
        Value = 0
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        Name = "Enabled"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        Name = "DisabledByDefault"
        Value = 0
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        Name = "Enabled"
        Value = 1
        Type = "DWord"
    }
)

foreach ($setting in $registrySettings) {
    $path = $setting.Path
    $name = $setting.Name
    $value = $setting.Value
    $type = $setting.Type

    # Create registry path if it doesn't exist
    if (-not (Test-Path $path)) {
        Write-ColorOutput "Creating registry path: $path" "Yellow"
        New-Item -Path $path -Force | Out-Null
    }

    # Set registry value
    try {
        $currentValue = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        if ($currentValue.$name -ne $value) {
            Set-ItemProperty -Path $path -Name $name -Value $value -Type $type -Force
            Write-ColorOutput "Set $path\$name = $value" "Green"
        } else {
            Write-ColorOutput "Already set: $path\$name = $value" "Gray"
        }
    } catch {
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
        Write-ColorOutput "Created $path\$name = $value" "Green"
    }
}

Write-ColorOutput "`n===== Configuration Complete =====" "Green"
Write-ColorOutput "TLS 1.2 is now enabled system-wide!" "Green"
Write-ColorOutput "`nChanges applied:" "Cyan"
Write-ColorOutput "  - PowerShell profile configured for all users" "White"
Write-ColorOutput "  - .NET Framework strong crypto enabled" "White"
Write-ColorOutput "  - TLS 1.2 enabled at OS level via registry" "White"
Write-ColorOutput "`nNo restart required - changes take effect immediately" "Yellow"
