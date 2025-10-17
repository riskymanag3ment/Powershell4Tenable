################################################################################
# QuickStart-Testing.ps1
# Quick start examples for testing the Tenable PowerShell module
################################################################################

# Example 1: Basic Read-Only Test (Safest)
# Tests only GET operations, no data is created or modified

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Example 1: Read-Only Testing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Set your API credentials
$env:TENABLE_API_KEY = "accessKey=your_access_key;secretKey=your_secret_key"

# Run read-only tests
..\Test-TenableModule.ps1 -TestMode "ReadOnly"

# Check the results
$logFile = Get-ChildItem ..\TenableModuleTest_*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "`nLog file created: $($logFile.Name)" -ForegroundColor Green
Write-Host "Review the log for detailed results`n" -ForegroundColor Yellow

################################################################################

# Example 2: Safe Write Test with Cleanup
# Creates test resources but cleans them up automatically

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Example 2: Safe Write Testing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Run safe write tests (creates resources but cleans up)
..\Test-TenableModule.ps1 -TestMode "SafeWrite"

# View the CSV report
$csvFile = Get-ChildItem ..\TenableModuleTest_*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($csvFile) {
    Write-Host "`nCSV report created: $($csvFile.Name)" -ForegroundColor Green

    # Import and display summary
    $results = Import-Csv $csvFile.FullName
    $summary = $results | Group-Object Status | Select-Object Name, Count

    Write-Host "`nTest Summary:" -ForegroundColor Yellow
    $summary | Format-Table -AutoSize

    # Show failed tests if any
    $failed = $results | Where-Object { $_.Status -eq "Failed" }
    if ($failed) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        $failed | Format-Table Function, Category, Error -AutoSize
    }
}

################################################################################

# Example 3: Testing Specific Categories
# Test only specific function categories

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Example 3: Custom Test Scenario" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Import the module
Import-Module ..\TenablePowershell.psm1 -Force

# Set credentials
$global:TenableAPIKey = $env:TENABLE_API_KEY

Write-Host "Testing Scanner Functions..." -ForegroundColor Yellow
try {
    $scanners = Get-TenableScannerList
    Write-Host "  ✓ Get-TenableScannerList: $($scanners.Count) scanners found" -ForegroundColor Green

    if ($scanners.Count -gt 0) {
        $scanner = $scanners[0]
        $details = Get-TenableScannerDetails -ScannerID $scanner.id
        Write-Host "  ✓ Get-TenableScannerDetails: Retrieved details for $($scanner.name)" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ✗ Error: $_" -ForegroundColor Red
}

Write-Host "`nTesting Asset Functions..." -ForegroundColor Yellow
try {
    $assets = Get-TenableAssetList
    Write-Host "  ✓ Get-TenableAssetList: $($assets.Count) assets found" -ForegroundColor Green

    if ($assets.Count -gt 0) {
        $asset = $assets[0]
        $assetInfo = Get-TenableAssetInfo -UUID $asset.id
        Write-Host "  ✓ Get-TenableAssetInfo: Retrieved info for asset $($asset.id)" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ✗ Error: $_" -ForegroundColor Red
}

################################################################################

# Example 4: Performance Testing
# Measure response times for key operations

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Example 4: Performance Testing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$performanceTests = @(
    @{ Name = "Get-TenableScannerList"; Function = { Get-TenableScannerList } },
    @{ Name = "Get-TenableAssetList"; Function = { Get-TenableAssetList } },
    @{ Name = "Get-TenableScans"; Function = { Get-TenableScans } },
    @{ Name = "Get-TenablePluginFamilies"; Function = { Get-TenablePluginFamilies } },
    @{ Name = "Get-TenablePolicies"; Function = { Get-TenablePolicies } }
)

Write-Host "`nMeasuring response times..." -ForegroundColor Yellow
$performanceResults = @()

foreach ($test in $performanceTests) {
    try {
        $duration = Measure-Command { & $test.Function | Out-Null }
        $performanceResults += [PSCustomObject]@{
            Function = $test.Name
            Duration = "$([math]::Round($duration.TotalSeconds, 2))s"
            Status = "Success"
        }
        Write-Host "  $($test.Name): $([math]::Round($duration.TotalSeconds, 2))s" -ForegroundColor Green
    }
    catch {
        $performanceResults += [PSCustomObject]@{
            Function = $test.Name
            Duration = "N/A"
            Status = "Failed"
        }
        Write-Host "  $($test.Name): Failed - $_" -ForegroundColor Red
    }
}

# Show summary
Write-Host "`nPerformance Summary:" -ForegroundColor Cyan
$performanceResults | Format-Table -AutoSize

################################################################################

# Example 5: Continuous Monitoring
# Run tests periodically and track results over time

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Example 5: Scheduled Testing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host @"
To set up scheduled testing, create a Windows Task Scheduler task:

PowerShell Command:
-NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Test-TenableModule.ps1" -TestMode "ReadOnly"

Schedule:
- Daily at 2:00 AM
- Or hourly for continuous monitoring

Store credentials securely:
1. Use Windows Credential Manager
2. Or Azure Key Vault
3. Or environment variables set at system level

Example Task Scheduler XML:
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2025-01-01T02:00:00</StartBoundary>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-File "C:\Scripts\Test-TenableModule.ps1" -TestMode "ReadOnly"</Arguments>
    </Exec>
  </Actions>
</Task>
"@ -ForegroundColor Yellow

################################################################################

# Example 6: Integration Testing
# Test complete workflows

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Example 6: Workflow Testing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nTesting Scan Creation Workflow..." -ForegroundColor Yellow

try {
    # Step 1: Get scan templates
    Write-Host "  Step 1: Getting scan templates..." -ForegroundColor Cyan
    $templates = Get-TenableScanTemplates
    $basicTemplate = $templates | Where-Object { $_.title -like "*Basic*" } | Select-Object -First 1

    if ($basicTemplate) {
        Write-Host "    ✓ Found template: $($basicTemplate.title)" -ForegroundColor Green

        # Step 2: Get folders
        Write-Host "  Step 2: Getting folders..." -ForegroundColor Cyan
        $folders = Get-TenableFolders
        Write-Host "    ✓ Found $($folders.Count) folders" -ForegroundColor Green

        # Step 3: Get scanners
        Write-Host "  Step 3: Getting scanners..." -ForegroundColor Cyan
        $scanners = Get-TenableScannerList
        Write-Host "    ✓ Found $($scanners.Count) scanners" -ForegroundColor Green

        Write-Host "`n  ✓ Scan creation workflow validated (dry-run)" -ForegroundColor Green
        Write-Host "    To actually create a scan, use:" -ForegroundColor Yellow
        Write-Host "    New-TenableScan -Name 'Test' -Targets '192.168.1.1' -TemplateUUID '$($basicTemplate.uuid)'" -ForegroundColor White
    }
}
catch {
    Write-Host "  ✗ Workflow failed: $_" -ForegroundColor Red
}

################################################################################

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Quick Start Examples Completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host @"

Next Steps:
1. Review the generated log and CSV files
2. Run full test suite: ..\Test-TenableModule.ps1 -TestMode "SafeWrite"
3. Check TESTING.md for comprehensive documentation
4. Integrate tests into your CI/CD pipeline

For more information:
- README.md - Module documentation
- TESTING.md - Testing guide
- Test-TenableModule.ps1 - Full test script

"@ -ForegroundColor Cyan
