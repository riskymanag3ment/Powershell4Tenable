# Tenable PowerShell Module Testing Guide

## Overview

The `Test-TenableModule.ps1` script provides comprehensive testing for all 84 functions in the TenablePowerShell module. It includes safety controls, automatic cleanup, and detailed reporting.

## Prerequisites

1. **Valid Tenable.io API Credentials**
   - Access Key and Secret Key with appropriate permissions
   - Set as environment variable: `$env:TENABLE_API_KEY = "accessKey=xxx;secretKey=xxx"`

2. **PowerShell 5.1 or later**

3. **TenablePowershell.psm1 module** in the same directory

4. **Network access** to cloud.tenable.com

## Test Modes

### ReadOnly Mode (Safest)
Tests only GET operations - no data is created, modified, or deleted.

```powershell
.\Test-TenableModule.ps1 -TestMode "ReadOnly"
```

**Tests:**
- All list/get functions (Get-TenableScans, Get-TenableAssets, etc.)
- All filter functions
- Scanner/plugin/policy queries
- Audit log retrieval

**Skips:**
- Create operations (New-*)
- Update operations (Update-*)
- Delete operations (Remove-*)

### SafeWrite Mode (Recommended for Testing)
Tests create and update operations with automatic cleanup. Does not perform delete operations.

```powershell
.\Test-TenableModule.ps1 -TestMode "SafeWrite"
```

**Tests:**
- All ReadOnly tests
- Create operations (groups, folders, tags, networks, exclusions)
- Update operations
- Automatic cleanup of created resources

**Skips:**
- Direct delete operations (but performs cleanup at end)

### Full Mode (Use with Caution)
Tests all operations including destructive actions.

```powershell
.\Test-TenableModule.ps1 -TestMode "Full"
```

**WARNING:** This mode tests delete operations. Use only in non-production environments.

### DryRun Mode
Validates test structure without making actual API calls.

```powershell
.\Test-TenableModule.ps1 -TestMode "DryRun"
```

## Usage Examples

### Basic Usage
```powershell
# Set API credentials
$env:TENABLE_API_KEY = "accessKey=your_key;secretKey=your_secret"

# Run read-only tests
.\Test-TenableModule.ps1 -TestMode "ReadOnly"
```

### With Custom Log File
```powershell
.\Test-TenableModule.ps1 -TestMode "SafeWrite" -LogFile "MyTest_$(Get-Date -Format 'yyyyMMdd').log"
```

### With Verbose Output
```powershell
.\Test-TenableModule.ps1 -TestMode "ReadOnly" -Verbose
```

### Passing API Key Directly
```powershell
.\Test-TenableModule.ps1 -TestMode "ReadOnly" -TenableAPIKey "accessKey=xxx;secretKey=xxx"
```

## Test Categories

The script organizes tests into the following categories:

### Tenable Platform & Settings API
1. **Access Control - API Settings** (2 functions)
   - Get-TenableAllowedIPs
   - Update-TenableAPIAccess

2. **Access Control - Groups** (7 functions)
   - New-TenableGroup, Get-TenableGroups, Update-TenableGroup
   - Remove-TenableGroup, Get-TenableGroupMembers
   - Add-TenableGroupMember, Remove-TenableGroupMember

3. **Access Control - Permissions** (3 functions)
   - New-TenablePermission, Get-TenablePermissions
   - Remove-TenablePermission

4. **Access Control - Users** (6 functions)
   - Get-TenableUser, New-TenableUser, Update-TenableUser
   - Remove-TenableUser, Get-TenableUserAuth, Update-TenableUserAuth

5. **Agents** (1 function)
   - Get-TenableAgentList

6. **Cloud Connectors** (1 function)
   - Get-TenableCloudCon

7. **Credentials** (3 functions)
   - Get-TenableCredType, Get-TenableCredList, Get-TenableCredDetails

8. **Exclusions** (4 functions)
   - Get-TenableExclusionList, New-TenableExclusion
   - Update-TenableExclusion, Remove-TenableExclusion

9. **Networks** (5 functions)
   - Get-TenableNets, New-TenableNet, Update-TenableNet
   - Remove-TenableNet, Get-TenableNetAssetCount

10. **Scanners** (2 functions)
    - Get-TenableScannerList, Get-TenableScannerDetails

11. **Tags** (9 functions)
    - Get-TenableTags, New-TenableTag, Update-TenableTag
    - Remove-TenableTag, Add-TenableAssetTag, Remove-TenableAssetTag
    - Get-TenableAssetTags, Get-TenableTagCategories, Get-TenableTagValues

### Vulnerability Management API
12. **Assets** (6 functions)
    - Get-TenableAssetList, Get-TenableAssetInfo, Search-TenableAssets
    - Move-TenableAsset, Remove-TenableAsset, Export-TenableAssets

13. **Editor / Templates** (1 function)
    - Get-TenableScanTemplates

14. **Filters** (7 functions)
    - Get-TenableAgentFilter, Get-TenableAssetFilter
    - Get-TenableCredentialFilter, Get-TenableReportFilter
    - Get-TenableScanFilter, Get-TenableScanHistoryFilter
    - Get-TenableVulnFilter

15. **Folders** (4 functions)
    - Get-TenableFolders, New-TenableFolder
    - Update-TenableFolder, Remove-TenableFolder

16. **Plugins** (3 functions)
    - Get-TenablePluginFamilies, Get-TenablePluginFamilyDetails
    - Get-TenablePluginDetails

17. **Policies** (4 functions)
    - Get-TenablePolicies, Get-TenablePolicyDetails
    - Copy-TenablePolicy, Remove-TenablePolicy

18. **Scans** (9 functions)
    - Get-TenableScans, New-TenableScan, Get-TenableScanInfo
    - Update-TenableScan, Remove-TenableScan
    - Start-TenableScan, Pause-TenableScan
    - Resume-TenableScan, Stop-TenableScan

19. **Vulnerabilities / Exports** (5 functions)
    - Get-TenableVulnerabilityList, Get-TenableVulnDetail
    - Export-TenableVulnerabilities, Get-VulnerabilityExportStatus
    - Get-VulnerabilityExportChunk

20. **Audit Log** (1 function)
    - Get-TenableAuditLog

21. **PCI ASV** (1 function)
    - Get-TenablePCIList

## Output Files

### Log File
- **Default:** `TenableModuleTest_YYYYMMDD_HHMMSS.log`
- **Format:** Timestamped entries with log levels (INFO, SUCCESS, WARN, ERROR, SKIP)
- **Contains:** Detailed execution log with function results and errors

### CSV Report
- **Default:** `TenableModuleTest_YYYYMMDD_HHMMSS.csv`
- **Format:** CSV with columns: Function, Category, Status, Duration, Result/Error
- **Use:** Import into Excel or other tools for analysis

## Test Results Interpretation

### Success Metrics
- **Pass Rate ≥ 90%**: Excellent - Module is functioning correctly
- **Pass Rate 70-90%**: Good - Minor issues may exist
- **Pass Rate < 70%**: Poor - Significant issues need attention

### Common Test Failures

1. **Authentication Errors**
   - **Symptom:** All tests fail with 401 Unauthorized
   - **Solution:** Verify API credentials are correct and valid

2. **Permission Errors**
   - **Symptom:** Some write operations fail with 403 Forbidden
   - **Solution:** Ensure API keys have sufficient permissions

3. **Rate Limiting**
   - **Symptom:** Tests fail sporadically with 429 Too Many Requests
   - **Solution:** Add delays between tests or reduce concurrent operations

4. **Network Issues**
   - **Symptom:** Intermittent connection failures
   - **Solution:** Check network connectivity to cloud.tenable.com

## Automatic Cleanup

The script automatically cleans up resources created during testing in reverse dependency order:

1. Scans
2. Folders
3. Exclusions
4. Networks
5. Tags
6. Users
7. Groups

Cleanup occurs even if tests fail, ensuring no orphaned resources remain.

## Best Practices

### Before Running Tests
1. ✅ Verify API credentials have appropriate permissions
2. ✅ Use a non-production Tenable instance if possible
3. ✅ Review test mode selection (start with ReadOnly)
4. ✅ Ensure adequate API rate limit headroom

### During Testing
1. ✅ Monitor log output for errors
2. ✅ Watch for rate limiting warnings
3. ✅ Note any skipped tests that may need manual verification

### After Testing
1. ✅ Review the CSV report for detailed results
2. ✅ Investigate any failed tests
3. ✅ Verify cleanup completed successfully
4. ✅ Document any issues discovered

## Troubleshooting

### "No API key provided" Error
```powershell
# Set environment variable
$env:TENABLE_API_KEY = "accessKey=xxx;secretKey=xxx"

# Or pass directly
.\Test-TenableModule.ps1 -TenableAPIKey "accessKey=xxx;secretKey=xxx"
```

### "Failed to import module" Error
```powershell
# Ensure module is in same directory
Get-ChildItem TenablePowershell.psm1

# Or specify full path
cd C:\Path\To\Module
.\Test-TenableModule.ps1
```

### High Failure Rate
```powershell
# Run with verbose logging
.\Test-TenableModule.ps1 -TestMode "ReadOnly" -Verbose

# Check specific log file
Get-Content .\TenableModuleTest_*.log | Select-String "ERROR"
```

### Cleanup Failures
Cleanup failures are non-fatal but logged as warnings. Manual cleanup may be required:

```powershell
# List test resources (named with Test_ prefix and timestamp)
Get-TenableGroups | Where-Object { $_.name -like "Test_*" }
Get-TenableFolders | Where-Object { $_.name -like "Test_*" }
Get-TenableTags | Where-Object { $_.category_name -like "Test_*" }

# Remove manually if needed
Remove-TenableGroup -GroupID <id>
```

## Extending the Test Script

### Adding a New Test

```powershell
Function Test-NewCategory {
    Write-TestLog -Message "========================================" -Level "INFO"
    Write-TestLog -Message "Testing: New Category" -Level "INFO"
    Write-TestLog -Message "========================================" -Level "INFO"

    Test-Function -FunctionName "Get-NewFunction" -OperationType "Read" -Category "NewCategory" -TestCode {
        $result = Get-NewFunction
        if ($null -eq $result) { throw "No data returned" }
        return $result
    } -Description "Test new function"
}

# Add to main execution
Test-NewCategory
```

### Customizing Test Behavior

Edit the `Test-Function` helper to add custom validation:

```powershell
# Add custom assertions
if ($result.Count -eq 0) {
    throw "Expected results but got none"
}

# Add timing checks
if ($duration.TotalSeconds -gt 30) {
    Write-TestLog -Message "  WARNING: Slow response time" -Level "WARN"
}
```

## Integration with CI/CD

### Jenkins Example
```groovy
pipeline {
    stage('Test Tenable Module') {
        steps {
            powershell '''
                $env:TENABLE_API_KEY = $env:TENABLE_CREDS
                .\\Test-TenableModule.ps1 -TestMode "ReadOnly"
            '''
        }
    }
}
```

### GitHub Actions Example
```yaml
- name: Test Tenable Module
  shell: pwsh
  env:
    TENABLE_API_KEY: ${{ secrets.TENABLE_API_KEY }}
  run: |
    ./Test-TenableModule.ps1 -TestMode "ReadOnly"
```

## Support

For issues with the test script:
- Check the log file for detailed error messages
- Review the CSV report for patterns in failures
- Verify API credentials and permissions
- Ensure network connectivity to Tenable.io

For issues with the module itself:
- Refer to README.md
- Check the Tenable API documentation: https://developer.tenable.com/reference/navigate
- Create an issue in the repository

## Security Considerations

1. **API Key Protection**
   - Never commit API keys to version control
   - Use environment variables or secure vaults
   - Rotate keys regularly

2. **Test Data**
   - Test resources use clearly identifiable naming (Test_*)
   - All test data should be non-sensitive
   - Cleanup removes all test artifacts

3. **Production Safety**
   - Always start with ReadOnly mode
   - Use SafeWrite mode for validation
   - Reserve Full mode for non-production environments

---

**Last Updated:** 2025-10-14
**Test Script Version:** 2.0
**Compatible with:** TenablePowerShell Module v2.0
