# Keyboard Kowboys - Windows Operations Toolkit

> **A comprehensive Windows cybersecurity operations platform for CCDC environments**

[![PowerShell](https://img.shields.io/badge/PowerShell-3.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

## 🎯 Overview

The Keyboard Kowboys Windows toolkit provides automated system hardening, monitoring, backup, and incident response capabilities specifically designed for Windows environments in CCDC competitions.

### Key Features

- **🔒 Automated Hardening**: EzScript comprehensive security baseline
- **📊 Security Auditing**: HardeningKitty integration for compliance checks
- **💾 Backup & Recovery**: Robocopy-based incremental backups
- **🔍 Network Analysis**: Real-time connection and port monitoring
- **📝 Log Analysis**: Automated Windows Event Log analysis
- **🔑 Password Management**: AD password rotation for Domain Controllers
- **🛡️ Wazuh Integration**: Security monitoring agent deployment
- **⚙️ PowerShell 3.0+**: Maximum compatibility across Windows versions

## 🚀 Quick Start

### Prerequisites

- Windows Server 2008 R2+ or Windows 7+
- PowerShell 3.0 or higher
- Administrator privileges
- Internet connectivity (for initial setup)

**Check PowerShell version**:
```powershell
$PSVersionTable.PSVersion
```

### Installation

1. **Download or clone this repository**:
   ```powershell
   cd C:\
   git clone <repository-url> just-windows
   cd just-windows
   ```

2. **Install Just command runner** (if not already installed):
   ```powershell
   # Download and install from https://just.systems/
   # Or use chocolatey:
   choco install just
   ```

3. **Initialize the environment**:
   ```powershell
   just init
   ```

4. **Verify installation**:
   ```powershell
   just ps-version
   just status
   ```

### First Steps

```powershell
# Create baseline backup
just backup all

# Apply security hardening
just harden

# Run security audit
just audit

# Check system status
just status
```

## 📚 Documentation

**📖 [Complete Documentation](docs/)** - Obsidian-formatted documentation vault

### Quick Links

- **[Quick Start Guide](docs/01-Quick-Start-Guide.md)** - Get up and running in 5 minutes
- **[PowerShell Compatibility](docs/12-PowerShell-Compatibility.md)** - PS 3.0+ compatibility reference
- **[Compatibility Checker](docs/98-Compatibility-Checker.md)** - Script compatibility analysis tool
- **[TODO & Roadmap](TODO.md)** - Feature roadmap and known issues

### Key Documentation

| Document | Description |
|----------|-------------|
| [00-Index.md](docs/00-Index.md) | Main documentation hub |
| [01-Quick-Start-Guide.md](docs/01-Quick-Start-Guide.md) | Getting started guide |
| [12-PowerShell-Compatibility.md](docs/12-PowerShell-Compatibility.md) | PS 3.0 compatibility guide |
| [98-Compatibility-Checker.md](docs/98-Compatibility-Checker.md) | Script analysis tool |

## 🔧 Core Components

### Justfile Commands

```powershell
# Initialization
just init                          # Create directory structure

# System Information
just status                        # View system status dashboard
just ps-version                    # Check PowerShell version

# Backup Operations
just backup                        # Backup all configurations
just backup network                # Backup network configs
just backup firewall               # Backup firewall rules

# Security Hardening
just harden                        # Apply comprehensive hardening
just audit                         # Run HardeningKitty audit

# Network Analysis
just network-eval                  # Basic network analysis
just network-eval detailed         # Full network analysis

# Log Analysis
just analyze-logs                  # Analyze last hour
just analyze-logs 24               # Analyze last 24 hours

# Password Management (Domain Controllers)
just rotate-passwords              # Rotate AD passwords

# Tools
just install-tools                 # Install security tools
just add-agent <ip>                # Deploy Wazuh agent

# Compatibility Checking
just check-compatibility           # Check PS 3.0 compatibility
just check-compatibility-report    # Generate compatibility report
```

### PowerShell Scripts

| Script | Description | PS Version |
|--------|-------------|------------|
| `Invoke-EzScript.ps1` | Comprehensive system hardening | 3.0+ |
| `Invoke-Backup.ps1` | System backup with robocopy | 3.0+ |
| `Invoke-NetworkSecurityAnalysis.ps1` | Network analysis | 3.0+ |
| `Invoke-LogAnalyzer.ps1` | Event log analysis | 3.0+ |
| `Rotate-Passwords.ps1` | AD password rotation | 3.0+ |
| `Install-Tools.ps1` | Security tool installation | 3.0+ |
| `Invoke-CompatibilityCheck.ps1` | Script compatibility checker | 5.1+ |
| `Setup-Just.ps1` | Initial setup | 3.0+ |
| `wazuh-agent.ps1` | Wazuh deployment | 3.0+ |

## 🏗️ Architecture

```
C:\KeyboardKowboys\               # Base installation directory
├── scripts\                      # Core PowerShell scripts
│   ├── Invoke-EzScript.ps1      # System hardening
│   ├── Invoke-Backup.ps1        # Backup management
│   ├── Invoke-NetworkSecurityAnalysis.ps1
│   ├── Invoke-LogAnalyzer.ps1
│   ├── Rotate-Passwords.ps1
│   ├── Install-Tools.ps1
│   ├── Invoke-CompatibilityCheck.ps1
│   └── Setup-Just.ps1
├── backups\                      # System backups
├── logs\                         # Operation logs
├── configs\                      # Configuration files
├── tools\                        # Installed security tools
└── ops\                          # Operational scripts
```

## ⚡ PowerShell 3.0 Compatibility

This toolkit is designed for **PowerShell 3.0+** for maximum compatibility with legacy Windows systems.

**Minimum Requirements**:
- PowerShell 3.0 (Windows 7 SP1 / Server 2008 R2 SP1)
- .NET Framework 4.0+

**Recommended**:
- PowerShell 5.1+ (Windows 10 / Server 2016+)

### Compatibility Checker

Built-in tool to verify PS 3.0 compatibility:

```powershell
# Check all scripts
just check-compatibility

# Generate detailed report
just check-compatibility-report

# View report
Get-Content C:\KeyboardKowboys\logs\compatibility-report.json
```

See **[PowerShell Compatibility Guide](docs/12-PowerShell-Compatibility.md)** for details.

## 📊 Features

### Security Hardening (EzScript)

- ✅ Audit policy configuration
- ✅ SMB protocol security
- ✅ Group policy hardening
- ✅ Kerberos and Zerologon mitigations
- ✅ Windows Defender optimization
- ✅ Firewall rule configuration
- ✅ Registry security hardening
- ✅ Local account security

### Backup & Recovery

- ✅ Incremental backups with robocopy
- ✅ Multiple system types (network, firewall, services, database, web)
- ✅ Network connection snapshots
- ✅ Point-in-time recovery

### Monitoring & Analysis

- ✅ Network connection monitoring
- ✅ Event log analysis
- ✅ Security audit logging
- ✅ HardeningKitty integration

### Password Management

- ✅ Active Directory password rotation (Domain Controllers)
- ✅ Secure password generation
- ✅ CSV export for documentation

## 🔍 Compatibility Status

| Category | Status | Notes |
|----------|--------|-------|
| PowerShell 3.0 Compat | 🟡 Needs Review | Use `just check-compatibility` |
| PowerShell 5.1 | ✅ Tested | Recommended version |
| PowerShell 7.x | ✅ Compatible | Cross-platform version |
| Windows 7 / 2008 R2 | 🟡 Requires PS upgrade | Upgrade to PS 3.0+ first |
| Windows 10 / 2016+ | ✅ Fully Compatible | Native support |

## 🧪 Testing

### Run Compatibility Check

```powershell
# Check all scripts for PS 3.0 compatibility
just check-compatibility

# Show only errors
just check-compatibility severity=Error

# Generate JSON report
just check-compatibility-report
```

### Known Compatibility Issues

Current scripts with PS 4.0+ dependencies:
- `Invoke-Backup.ps1:1` - Uses `#Requires -RunAsAdministrator`
- `Invoke-LogAnalyzer.ps1:1` - Uses `#Requires -RunAsAdministrator`

See **[TODO.md](TODO.md)** for complete list and roadmap.

## 📋 Common Workflows

### Pre-Competition Setup

```powershell
# 1. Initialize environment
just init

# 2. Create baseline backup
just backup all

# 3. Apply hardening
just harden

# 4. Deploy Wazuh (if available)
just add-agent 192.168.1.100

# 5. Verify setup
just status
just audit
```

### Daily Security Check

```powershell
# Check system status
just status

# Analyze recent logs
just analyze-logs 24

# Run network analysis
just network-eval detailed

# Security audit
just audit
```

### Incident Response

```powershell
# Analyze logs
just analyze-logs 24 > incident-logs.txt

# Network analysis
just network-eval detailed > incident-network.txt

# Create backup snapshot
just backup all

# Review findings
Get-ChildItem C:\KeyboardKowboys\logs\
```

### Domain Controller Password Rotation

```powershell
# Verify you're on a DC
Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

# Rotate passwords
just rotate-passwords

# Verify output
Get-Content C:\KeyboardKowboys\passwords.csv
```

## 🔒 Security Considerations

**Important**: This toolkit requires Administrator privileges for most operations.

### Best Practices

1. **Test hardening in non-production first**
2. **Always create backups before major changes**
3. **Review HardeningKitty audit before applying fixes**
4. **Use secure password storage**
5. **Regular security audits**
6. **Monitor logs continuously**

### Execution Policy

Set appropriate execution policy:

```powershell
# For current user (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Check current policy
Get-ExecutionPolicy -List
```

## 🤝 Contributing

Contributions welcome! Priority areas:

1. **PowerShell 3.0 compatibility fixes** (Critical)
2. **Documentation completion** (High)
3. **Testing suite creation** (High)
4. **Monitoring and diff features** (High)

See **[TODO.md](TODO.md)** for detailed roadmap.

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: Check TODO.md for known issues
- **Compatibility**: See [PowerShell Compatibility Guide](docs/12-PowerShell-Compatibility.md)

## 📄 License

This project is licensed under the MIT License.

## 🏆 Credits

**Keyboard Kowboys** - CSUSB CCDC Team 2024-25 Season

### Tools & Technologies

- [Just](https://just.systems/) - Command runner
- [HardeningKitty](https://github.com/scipag/HardeningKitty) - Security baseline auditing
- [Wazuh](https://wazuh.com/) - Security monitoring
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - Code quality

---

## 🚦 Project Status

**Version**: 2024-25 Season
**Platform**: Windows (PowerShell 3.0+)
**Status**: Active Development

**Completion**: ~40% (Core features functional, documentation and testing in progress)

See **[TODO.md](TODO.md)** for detailed roadmap and current priorities.

---

**Keyboard Kowboys** - Defending the digital frontier! 🛡️
