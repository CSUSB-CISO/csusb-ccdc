# Keyboard Kowboys Windows - TODO & Feature Roadmap

> **Last Updated**: 2025-10-17
> **Target PowerShell Version**: 3.0+ (Maximum Compatibility)

---

## Quick Status Overview

| Category | Status | Priority | Notes |
|----------|--------|----------|-------|
| Core Functionality | 🟢 Complete | - | All major features working |
| Documentation | 🟡 In Progress | High | Obsidian docs started |
| PowerShell 3.0 Compat | 🟢 Phase 1 Complete | Critical | 0 errors, 123 warnings (Phase 2 pending) |
| Testing | 🔴 Needs Work | High | No test suite exists |
| Remote Deployment | 🔴 Missing | Medium | No Ansible playbooks |
| Monitoring | 🔴 Missing | High | No real-time monitoring |

**Legend**: 🟢 Complete | 🟡 In Progress | 🔴 Needs Work | ⚪ Not Started

---

## 🚨 Critical Priorities

### 1. PowerShell 3.0 Compatibility Audit ⚠️
**Priority**: CRITICAL
**Status**: 🟢 Phase 1 Complete | 🟡 Remaining Issues

**Latest Compatibility Check**: 2025-10-17 16:01:12
- **Status**: ✅ All 7 scripts are PowerShell 3.0+ compatible (0 errors)
- **Warnings**: 123 (down from 134 - 8.2% reduction)
- **Scripts Analyzed**: 7 of 7

**Phase 1: Quick Wins - COMPLETED ✅**
- [x] Fixed 3 unused variables
- [x] Fixed 4 empty catch blocks
- [x] Replaced 4 deprecated WMI cmdlets with CIM cmdlets
- **Result**: 11 issues fixed, 123 warnings remaining

**Remaining Issues by Category** (123 total warnings):

1. **PSAvoidUsingWriteHost** (86 warnings) - LOW PRIORITY
   - Write-Host is intentional for CCDC colored console output
   - Status: ACCEPTED (not blocking)

2. **PSUseShouldProcessForStateChangingFunctions** (16 warnings) - MEDIUM PRIORITY
   - Functions that modify system state should support -WhatIf/-Confirm
   - Affects: Functions in Invoke-Backup.ps1, Invoke-EzScript.ps1, Rotate-Passwords.ps1
   - Estimated effort: 2-3 hours

3. **Function Naming Conventions** (10 warnings) - LOW PRIORITY
   - PSUseApprovedVerbs (5 warnings)
   - PSUseSingularNouns (5 warnings)
   - Estimated effort: 1 hour

4. **PSUseProcessBlockForPipelineCommand** (1 warning) - LOW PRIORITY
   - Install-Tools.ps1: Add process block for pipeline support
   - Estimated effort: 15 minutes

5. **PSReviewUnusedParameter** (1 warning) - FALSE POSITIVE
   - Install-Tools.ps1:$SourceDir is actually used (line 55)
   - Status: No fix needed

**Action Items**:
- [x] Create compatibility checking script (`Invoke-CompatibilityCheck.ps1`)
- [x] Add Justfile commands (`check-compatibility`, `check-compatibility-report`)
- [x] Document compatibility checker (`docs/98-Compatibility-Checker.md`)
- [x] Run compatibility check on all scripts
- [x] Fix Phase 1 Quick Wins (unused variables, empty catches, WMI→CIM)
- [ ] Phase 2: Add ShouldProcess support (16 functions) - 2-3 hours
- [ ] Phase 3: Fix naming conventions (10 functions) - 1 hour
- [ ] Add process block for pipeline command (1 instance) - 15 minutes
- [ ] Test on Windows Server 2008 R2 with PS 3.0
- [ ] Test on Windows 7 with PS 3.0
- [ ] Create compatibility test matrix
- [ ] Add version detection to all scripts
- [ ] Document minimum requirements per script

**Implementation Example**:
```powershell
# Replace this (PS 4.0+):
#Requires -RunAsAdministrator

# With this (PS 3.0+):
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges."
    exit 1
}
```

**Compatibility Checker**:
```powershell
# Check all scripts
just check-compatibility

# Generate report
just check-compatibility-report
```

**Files Fixed in Phase 1** ✅:
- [x] `scripts/Invoke-Backup.ps1` - WMI→CIM (line 235), removed unused variable (line 553)
- [x] `scripts/Invoke-EzScript.ps1` - Removed unused variable (line 396)
- [x] `scripts/Invoke-NetworkSecurityAnalysis.ps1` - WMI→CIM (lines 476, 498, 726), removed unused variable (line 833)
- [x] `scripts/Invoke-LogAnalyzer.ps1` - Fixed 4 empty catch blocks (lines 504, 520, 533, 548)

**Next Phase Files**:
- [ ] Add ShouldProcess to state-changing functions (16 functions across multiple scripts)
- [ ] Fix function naming conventions (10 functions)
- [ ] Add process block to Install-Tools.ps1

**Run Compatibility Check Anytime**: `just check-compatibility-report`

---

### 2. Complete Documentation Suite 📚
**Priority**: HIGH
**Status**: 🟡 In Progress (30% complete)

**Completed**:
- [x] `00-Index.md` - Main documentation index
- [x] `01-Quick-Start-Guide.md` - Getting started guide
- [x] `12-PowerShell-Compatibility.md` - Compatibility reference
- [x] `98-Compatibility-Checker.md` - Compatibility checker guide
- [x] `.obsidian/workspace.json` - Obsidian configuration
- [x] `README.md` - Documentation overview

**Needed Documentation**:
- [ ] `02-Installation-Guide.md` - Detailed installation steps
- [ ] `03-Architecture-Overview.md` - System architecture
- [ ] `10-Justfile-Commands.md` - Complete command reference
- [ ] `11-Scripts-Reference.md` - PowerShell script documentation
- [ ] `20-Backup-and-Recovery.md` - Backup strategies and recovery
- [ ] `21-Monitoring-and-Analysis.md` - Log monitoring and analysis
- [ ] `22-Incident-Response.md` - Incident handling procedures
- [ ] `23-Network-Operations.md` - Network analysis guide
- [ ] `30-Troubleshooting-Guide.md` - Common issues and solutions
- [ ] `31-Files-to-Check.md` - Critical files and locations
- [ ] `32-Debug-Procedures.md` - Debugging guide
- [ ] `40-Security-Hardening.md` - EzScript deep dive
- [ ] `41-Password-Rotation.md` - Password rotation guide
- [ ] `42-Audit-Configuration.md` - Audit policy reference
- [ ] `43-Security-Best-Practices.md` - Security guidelines
- [ ] `50-Directory-Structure.md` - File system layout
- [ ] `51-Configuration-Files.md` - Config file reference
- [ ] `52-Environment-Variables.md` - Environment setup
- [ ] `53-Dependencies.md` - Dependencies and requirements
- [ ] `99-Testing-Guide.md` - Testing procedures
- [ ] `EMERGENCY-RESTORE.md` - Emergency recovery procedures
- [ ] `README.md` - Main project README

**Action Items**:
- [ ] Create all missing documentation files
- [ ] Add cross-references between docs
- [ ] Include code examples in all guides
- [ ] Add troubleshooting sections
- [ ] Create quick reference cards
- [ ] Add diagrams and flowcharts where helpful

---

### 3. Testing Suite 🧪
**Priority**: HIGH
**Status**: 🔴 Not Started

**Required Tests**:
- [ ] PowerShell 3.0 compatibility tests
- [ ] PowerShell 5.1 compatibility tests
- [ ] PowerShell 7.x compatibility tests
- [ ] Windows Server 2008 R2 tests
- [ ] Windows Server 2012/2012 R2 tests
- [ ] Windows Server 2016/2019/2022 tests
- [ ] Windows 7 tests
- [ ] Windows 10 tests
- [ ] Domain Controller specific tests
- [ ] Non-DC tests
- [ ] Backup/restore tests
- [ ] Hardening validation tests
- [ ] Network analysis tests
- [ ] Log analysis tests

**Implementation**:
- [ ] Create `tests/` directory
- [ ] Write Pester test framework
- [ ] Create `test-compatibility.ps1` script
- [ ] Create `test-backup.ps1` script
- [ ] Create `test-hardening.ps1` script
- [ ] Create `test-network.ps1` script
- [ ] Create CI/CD pipeline (GitHub Actions)
- [ ] Document testing procedures in `99-Testing-Guide.md`

**Test Script Template**:
```powershell
# tests/Test-Compatibility.ps1
Describe "PowerShell Compatibility Tests" {
    Context "PowerShell Version Detection" {
        It "Should detect PowerShell version correctly" {
            $PSVersionTable.PSVersion | Should -Not -BeNullOrEmpty
        }
    }

    Context "Script Syntax Validation" {
        It "Should not have syntax errors in Invoke-Backup.ps1" {
            { . .\scripts\Invoke-Backup.ps1 } | Should -Not -Throw
        }
    }
}
```

---

## 🎯 High Priority Features

### 4. Real-Time Monitoring System 📊
**Priority**: HIGH
**Status**: 🔴 Not Started

**Goal**: Implement Linux-style real-time file monitoring for Windows

**Features Needed**:
- [ ] Monitor critical system files for changes
- [ ] Watch registry keys for modifications
- [ ] Monitor user accounts and group memberships
- [ ] Track service configuration changes
- [ ] Monitor scheduled tasks
- [ ] Watch firewall rule changes
- [ ] Monitor startup programs
- [ ] Track network connections in real-time

**Implementation Approach**:
```powershell
# Use FileSystemWatcher for file monitoring
# Use WMI event subscriptions for system events
# Create Invoke-Monitor.ps1 script
```

**Action Items**:
- [ ] Create `Invoke-Monitor.ps1` script
- [ ] Implement FileSystemWatcher for files
- [ ] Implement WMI event subscriptions for system changes
- [ ] Add monitoring start/stop/status commands to Justfile
- [ ] Create monitoring configuration file
- [ ] Add alerting mechanism (email, log, etc.)
- [ ] Document in `21-Monitoring-and-Analysis.md`

**Justfile Commands**:
```just
# Start real-time monitoring
start-monitor:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Monitor.ps1 -Action Start

# Stop monitoring
stop-monitor:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Monitor.ps1 -Action Stop

# Check monitoring status
monitor-status:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Monitor.ps1 -Action Status
```

---

### 5. System State Comparison (Diff) 🔍
**Priority**: HIGH
**Status**: 🔴 Not Started

**Goal**: Implement Linux-style `just diff` functionality for Windows

**Features Needed**:
- [ ] Compare current state with backup baseline
- [ ] Detect new listening ports
- [ ] Detect new processes
- [ ] Detect new services
- [ ] Detect new scheduled tasks
- [ ] Detect new user accounts
- [ ] Detect registry changes
- [ ] Detect firewall rule changes
- [ ] Detect new startup programs

**Implementation**:
- [ ] Create `Invoke-Diff.ps1` script
- [ ] Capture system state during backup
- [ ] Compare current state with baseline
- [ ] Generate diff reports
- [ ] Highlight critical changes

**Action Items**:
- [ ] Create `Invoke-Diff.ps1` script
- [ ] Implement state capture in `Invoke-Backup.ps1`
- [ ] Add diff commands to Justfile
- [ ] Create diff report templates
- [ ] Document in `20-Backup-and-Recovery.md`

**Justfile Commands**:
```just
# Compare all system state
diff:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Diff.ps1 -Type All

# Compare only ports
diff-ports:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Diff.ps1 -Type Ports

# Compare only processes
diff-processes:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Diff.ps1 -Type Processes

# Compare only services
diff-services:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-Diff.ps1 -Type Services
```

---

### 6. Incident Snapshot Feature 📸
**Priority**: HIGH
**Status**: 🔴 Not Started

**Goal**: Quick forensic snapshot capability during incidents

**Features Needed**:
- [ ] Create timestamped incident snapshot
- [ ] Capture all critical system state
- [ ] Capture network connections
- [ ] Capture running processes
- [ ] Capture recent event logs
- [ ] Capture user sessions
- [ ] Capture scheduled tasks
- [ ] Create incident report

**Implementation**:
- [ ] Create `Invoke-IncidentSnapshot.ps1` script
- [ ] Add incident-snapshot command to Justfile
- [ ] Create incident report template
- [ ] Document in `22-Incident-Response.md`

**Justfile Command**:
```just
# Create incident snapshot
incident-snapshot name:
    #!{{shebang}}
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $snapshotName = '{{name}}_' + $timestamp
    & {{scripts_dir}}/Invoke-IncidentSnapshot.ps1 -Name $snapshotName
```

---

### 7. Service Verification 🔐
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Goal**: Verify integrity of critical services

**Features Needed**:
- [ ] Check service binary integrity
- [ ] Verify service configuration
- [ ] Check service permissions
- [ ] Monitor service failures
- [ ] Alert on unexpected service changes

**Implementation**:
- [ ] Create `Invoke-ServiceVerification.ps1` script
- [ ] Add verify-services command to Justfile
- [ ] Create service baseline during backup
- [ ] Document in `21-Monitoring-and-Analysis.md`

**Justfile Command**:
```just
# Verify service integrity
verify-services:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-ServiceVerification.ps1
```

---

## 🔧 Medium Priority Enhancements

### 8. Remote Deployment via Ansible 🚀
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Goal**: Deploy and manage Windows toolkit via Ansible from Linux

**Action Items**:
- [ ] Create `playbooks/` directory
- [ ] Create `just_install_windows.yml` playbook
- [ ] Create `just_remote_windows.yml` playbook
- [ ] Configure WinRM for remote management
- [ ] Create `hosts.ini` configuration
- [ ] Test remote deployment
- [ ] Document in `03-Architecture-Overview.md`

**Ansible Playbook Structure**:
```yaml
# playbooks/just_install_windows.yml
---
- name: Deploy Keyboard Kowboys to Windows systems
  hosts: windows
  tasks:
    - name: Create base directory
      win_file:
        path: C:\KeyboardKowboys
        state: directory

    - name: Copy PowerShell scripts
      win_copy:
        src: ../scripts/
        dest: C:\KeyboardKowboys\scripts\
```

---

### 9. Persistence Detection 🕵️
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Goal**: Detect persistence mechanisms and backdoors (Windows equivalent of `check_persistence.sh`)

**Detection Categories**:
- [ ] Registry run keys
- [ ] Scheduled tasks
- [ ] Services
- [ ] WMI event subscriptions
- [ ] DLL hijacking
- [ ] Startup folder items
- [ ] GPO modifications
- [ ] Account modifications

**Implementation**:
- [ ] Create `Invoke-PersistenceCheck.ps1` script
- [ ] Add check-persistence command to Justfile
- [ ] Create baseline comparison
- [ ] Document in `22-Incident-Response.md`

**Justfile Command**:
```just
# Check for persistence mechanisms
check-persistence:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-PersistenceCheck.ps1 -Verbose
```

---

### 10. Firewall Reset/Restore 🛡️
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Goal**: Reset firewall to known-good state

**Features Needed**:
- [ ] Backup current firewall rules
- [ ] Restore firewall from backup
- [ ] Reset to default secure state
- [ ] Document rule changes

**Implementation**:
- [ ] Create `Invoke-FirewallReset.ps1` script
- [ ] Add reset-firewall command to Justfile
- [ ] Create secure baseline rules
- [ ] Document in `40-Security-Hardening.md`

**Justfile Command**:
```just
# Reset firewall to secure baseline
reset-firewall:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-FirewallReset.ps1 -RestoreBaseline
```

---

### 11. Enhanced HardeningKitty Integration 🐱
**Priority**: MEDIUM
**Status**: 🟡 Partial (audit command exists)

**Current State**:
- [x] Basic audit functionality in Justfile
- [ ] Advanced filtering
- [ ] Automated remediation
- [ ] Custom finding lists
- [ ] Scheduled audits

**Action Items**:
- [ ] Add more HardeningKitty commands to Justfile
- [ ] Create custom finding lists for CCDC
- [ ] Add automated remediation workflows
- [ ] Create audit report templates
- [ ] Document in `42-Audit-Configuration.md`

**Enhanced Justfile Commands**:
```just
# Run audit with custom CCDC finding list
audit-ccdc:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-HardeningKittyAudit.ps1 -FindingList ccdc_baseline.csv

# Generate compliance report
audit-report:
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-HardeningKittyReport.ps1
```

---

### 12. PII Scanner 🔍
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Goal**: Scan for PII (Personally Identifiable Information) in files

**Features Needed**:
- [ ] Scan for SSN patterns
- [ ] Scan for credit card numbers
- [ ] Scan for email addresses
- [ ] Scan for phone numbers
- [ ] Configurable scan patterns
- [ ] Exclusion lists

**Implementation**:
- [ ] Create `Invoke-PIIScanner.ps1` script
- [ ] Add find-pii command to Justfile
- [ ] Create pattern configuration file
- [ ] Document in `22-Incident-Response.md`

**Justfile Command**:
```just
# Scan for PII
find-pii path="C:\\":
    #!{{shebang}}
    & {{scripts_dir}}/Invoke-PIIScanner.ps1 -Path '{{path}}' -Verbose
```

---

## 📝 Documentation Improvements

### 13. Complete All Documentation Files
**Priority**: HIGH
**Status**: 🟡 In Progress (see item #2)

### 14. Add Code Examples to All Docs
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Action Items**:
- [ ] Add PowerShell examples to all guides
- [ ] Add expected output examples
- [ ] Add troubleshooting examples
- [ ] Add screenshot placeholders where helpful

### 15. Create Quick Reference Cards
**Priority**: MEDIUM
**Status**: 🟡 Partial (in Quick Start)

**Action Items**:
- [ ] Create printable quick reference PDF
- [ ] Create command cheat sheet
- [ ] Create troubleshooting flowchart
- [ ] Create incident response checklist

---

## 🔬 Testing & Quality Assurance

### 16. PowerShell Script Analyzer Integration
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Action Items**:
- [ ] Install PSScriptAnalyzer
- [ ] Create analysis script
- [ ] Fix all warnings
- [ ] Add to CI/CD pipeline

**Implementation**:
```powershell
# Test with PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer -Force
Invoke-ScriptAnalyzer -Path .\scripts\ -Recurse -Settings PSGallery
```

### 17. Pester Test Framework
**Priority**: MEDIUM
**Status**: 🔴 Not Started

**Action Items**:
- [ ] Install Pester
- [ ] Create test structure
- [ ] Write unit tests for all scripts
- [ ] Write integration tests
- [ ] Add to CI/CD pipeline

---

## 🚀 Future Enhancements

### 18. GUI Dashboard (Optional)
**Priority**: LOW
**Status**: ⚪ Future Consideration

**Ideas**:
- PowerShell WPF dashboard
- Web-based dashboard (PowerShell Universal)
- Real-time monitoring display

### 19. Automated Threat Response
**Priority**: LOW
**Status**: ⚪ Future Consideration

**Ideas**:
- Automatic IP blocking
- Automatic service isolation
- Automatic account lockout

### 20. SIEM Integration
**Priority**: LOW
**Status**: ⚪ Future Consideration

**Ideas**:
- Splunk integration
- Elastic Stack integration
- Windows Event Forwarding

---

## 🐛 Known Issues

### Issue 1: Wazuh Agent Script Name Mismatch
**Severity**: MEDIUM
**Status**: 🔴 Open

**Problem**: Justfile line 378 references `wazuh_agent_install.ps1` but actual file is `wazuh-agent.ps1`

**Location**: `Justfile:378`

**Fix**:
```just
# Change from:
& "{{scripts_dir}}\wazuh_agent_install.ps1" "{{server_ip}}"

# To:
& "{{scripts_dir}}\wazuh-agent.ps1" "{{server_ip}}"
```

**Action**:
- [ ] Update Justfile line 378
- [ ] Test Wazuh agent installation
- [ ] Document in `23-Network-Operations.md`

### Issue 2: HardeningKitty Not Pre-Installed
**Severity**: LOW
**Status**: 🔴 Open

**Problem**: Audit command assumes HardeningKitty is installed

**Fix**: Add check and installation prompt

**Action**:
- [ ] Add HardeningKitty check to audit command
- [ ] Improve error message
- [ ] Update `Install-Tools.ps1` to include HardeningKitty

---

## 📊 Progress Tracking

### Overall Completion Status

| Area | Progress | Items Complete | Items Total |
|------|----------|----------------|-------------|
| Core Scripts | 80% | 8 | 10 |
| Documentation | 15% | 3 | 20 |
| Testing | 0% | 0 | 17 |
| Features | 50% | 5 | 10 |
| Compatibility | 50% | 11 | 22 |
| **Overall** | **41%** | **27** | **79** |

### Milestone Targets

**Milestone 1: Core Stability (Target: 2 weeks)**
- [x] Complete PS 3.0 compatibility audit ✅
- [x] Fix Phase 1 critical compatibility issues (11 issues) ✅
- [ ] Fix Phase 2 compatibility issues (ShouldProcess support)
- [ ] Create basic test suite
- [ ] Complete critical documentation

**Milestone 2: Feature Parity with Linux Version (Target: 4 weeks)**
- [ ] Implement monitoring system
- [ ] Implement diff functionality
- [ ] Implement incident snapshots
- [ ] Implement service verification
- [ ] Complete all documentation

**Milestone 3: Production Ready (Target: 6 weeks)**
- [ ] Complete all testing
- [ ] CI/CD pipeline
- [ ] Ansible playbooks
- [ ] Performance optimization
- [ ] Security audit

---

## 🤝 Contributing

**If you want to contribute, prioritize**:
1. PowerShell 3.0 compatibility fixes (Critical)
2. Documentation completion (High)
3. Testing suite creation (High)
4. Monitoring and diff features (High)

**Style Guidelines**:
- Use PowerShell 3.0+ compatible syntax
- Include comment-based help for all functions
- Use proper error handling
- Follow verb-noun naming convention
- Include Pester tests for new features

---

## 📞 Contact & Support

For questions about this TODO list or to propose new features, please:
- Review existing documentation first
- Check PowerShell compatibility requirements
- Create detailed feature proposals
- Test on multiple PowerShell versions

---

*This TODO list is a living document and will be updated as features are completed and new requirements emerge.*

**Last Updated**: 2025-10-17 16:15:00
**Next Review**: 2025-10-24
**Last Compatibility Check**: 2025-10-17 16:01:12 (123 warnings, 0 errors)
