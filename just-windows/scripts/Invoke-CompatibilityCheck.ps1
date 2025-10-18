<#
.SYNOPSIS
    Analyzes PowerShell scripts for compatibility and best practices.

.DESCRIPTION
    Uses PSScriptAnalyzer to check PowerShell scripts for compatibility issues,
    best practice violations, and potential bugs. Outputs raw PSScriptAnalyzer
    results for maximum compatibility.

.PARAMETER Severity
    Minimum severity level to report (Error, Warning, Information). Defaults to Warning.

.PARAMETER ExportReport
    Export results to a JSON file for further analysis.

.PARAMETER ReportPath
    Path where the JSON report should be saved. Defaults to .\compatibility-report.json

.EXAMPLE
    .\Invoke-CompatibilityCheck.ps1
    Analyzes all PowerShell scripts in the scripts directory.

.EXAMPLE
    .\Invoke-CompatibilityCheck.ps1 -Severity Error
    Analyzes all scripts, showing only errors.

.EXAMPLE
    .\Invoke-CompatibilityCheck.ps1 -ExportReport
    Analyzes all scripts and exports results to JSON.
#>

[CmdletBinding()]
param(
    [ValidateSet('Error', 'Warning', 'Information')]
    [string]$Severity = 'Warning',

    [switch]$ExportReport,

    [string]$ReportPath = ".\compatibility-report.json"
)

# Ensure PSScriptAnalyzer is installed
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Output "PSScriptAnalyzer module not found. Installing..."
    try {
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
        Write-Output "PSScriptAnalyzer installed successfully."
    }
    catch {
        Write-Error "Failed to install PSScriptAnalyzer: $_"
        exit 1
    }
}

Import-Module PSScriptAnalyzer

# Determine script location and set path to scripts directory
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Path = $ScriptRoot

Write-Output ""
Write-Output "=== PowerShell Script Compatibility Analysis ==="
Write-Output "Analyzing scripts in: $Path"
Write-Output "Minimum Severity: $Severity"
Write-Output "Target: PowerShell 3.0+ compatibility"
Write-Output "=" * 50
Write-Output ""

# Get all PowerShell scripts in the scripts directory (excluding this script)
$scripts = Get-ChildItem -Path $Path -Filter "*.ps1" -File |
    Where-Object { $_.Name -ne 'Invoke-CompatibilityCheck.ps1' }

if (-not $scripts) {
    Write-Warning "No PowerShell scripts found in $Path"
    exit 0
}

Write-Output "Found $($scripts.Count) script(s) to analyze:"
foreach ($s in $scripts) {
    Write-Output "  - $($s.Name)"
}
Write-Output ""

# Analyze each script and collect results
$allResults = @()
$errorCount = 0
$warningCount = 0

foreach ($script in $scripts) {
    Write-Output "Analyzing: $($script.Name)"
    Write-Output ""

    # Run PSScriptAnalyzer
    $results = Invoke-ScriptAnalyzer -Path $script.FullName -Severity $Severity

    if ($results) {
        # Output results directly
        $results | Format-List RuleName, Severity, Line, Message, SuggestedCorrections

        # Count by severity
        $errors = ($results | Where-Object { $_.Severity -eq 'Error' }).Count
        $warnings = ($results | Where-Object { $_.Severity -eq 'Warning' }).Count

        $errorCount += $errors
        $warningCount += $warnings

        # Add script name to each result for export
        foreach ($result in $results) {
            $result | Add-Member -NotePropertyName 'ScriptName' -NotePropertyValue $script.Name -Force
            $allResults += $result
        }
    }
    else {
        Write-Output "  No issues found!"
    }

    Write-Output ""
    Write-Output ("-" * 50)
    Write-Output ""
}

# Display summary
Write-Output ""
Write-Output "=== Analysis Summary ==="
Write-Output "Total Scripts Analyzed: $($scripts.Count)"
Write-Output "Total Errors Found: $errorCount"
Write-Output "Total Warnings Found: $warningCount"
Write-Output "Total Issues Found: $($allResults.Count)"

# Display most common issues
if ($allResults) {
    Write-Output ""
    Write-Output "=== Most Common Issues ==="
    $topIssues = $allResults | Group-Object -Property RuleName |
        Sort-Object Count -Descending |
        Select-Object -First 10

    foreach ($issue in $topIssues) {
        Write-Output "  $($issue.Name): $($issue.Count) occurrence(s)"
    }
}

# Display critical PS 3.0 compatibility issues
$ps3Issues = $allResults | Where-Object {
    $_.RuleName -match 'CompatibleSyntax|CompatibleCmdlets|CompatibleTypes|CompatibleCommands' -or
    $_.Message -match 'PowerShell 3|PowerShell 4|PowerShell 5|PowerShell 7'
}

if ($ps3Issues) {
    Write-Output ""
    Write-Output "=== PowerShell 3.0 Compatibility Issues ==="
    foreach ($issue in $ps3Issues) {
        Write-Output "  [$($issue.ScriptName)] $($issue.RuleName): $($issue.Message)"
    }
}

# Export report if requested
if ($ExportReport) {
    Write-Output ""
    Write-Output "Exporting report to: $ReportPath"

    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AnalysisPath = $Path
        Severity = $Severity
        ScriptsAnalyzed = $scripts | ForEach-Object { $_.Name }
        TotalScripts = $scripts.Count
        TotalErrors = $errorCount
        TotalWarnings = $warningCount
        TotalIssues = $allResults.Count
        Results = $allResults | ForEach-Object {
            @{
                ScriptName = $_.ScriptName
                RuleName = $_.RuleName
                Severity = $_.Severity
                Line = $_.Line
                Column = $_.Column
                Message = $_.Message
                ScriptPath = $_.ScriptPath
            }
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Output "Report exported successfully."
}

Write-Output ""

# Exit with error code if errors were found
if ($errorCount -gt 0) {
    Write-Output "Analysis completed with ERRORS!"
    exit 1
}
elseif ($warningCount -gt 0) {
    Write-Output "Analysis completed with warnings."
    exit 0
}
else {
    Write-Output "All scripts passed analysis!"
    exit 0
}
