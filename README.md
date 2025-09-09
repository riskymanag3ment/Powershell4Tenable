# TenablePowerShell Module

A comprehensive PowerShell module for interacting with the Tenable.io cloud vulnerability management platform. This module provides functions to manage scans, assets, users, groups, tags, and more through the Tenable.io API.

## Prerequisites

- PowerShell 5.1 or later
- Valid Tenable.io API keys
- Network access to cloud.tenable.com

## Installation

1. Download the `TenablePowershell.psm1` file
2. Place it in your PowerShell modules directory or import it directly:
   ```powershell
   Import-Module .\TenablePowershell.psm1
   ```

## Configuration

Before using any functions, you must set your Tenable API key as a global variable:

```powershell
$global:TenableAPIKey = "accessKey=your_access_key;secretKey=your_secret_key"
```

## Function Categories

### Authentication & Connection
- `Connect-ToTenable` - Basic connection test (returns user permissions)

### API Access Control
- `Get-TenableAllowedIPs` - Retrieve allowed IP addresses for API access
- `Update-TenableAPIAccess` - Update allowed IP addresses for API access

### Scanner Management
- `Get-TenableScannerList` - List all available scanners
- `Get-TenableAgentList` - List agents for a specific scanner

### Group Management
- `New-TenableGroup` - Create a new access group
- `Get-TenableGroups` - List all access groups
- `Update-TenableGroup` - Update an existing group
- `Remove-TenableGroup` - Delete a group
- `Get-TenableGroupMembers` - Get members of a specific group
- `Add-TenableGroupMember` - Add user to a group
- `Remove-TenableGroupMember` - Remove user from a group

### Permission Management
- `New-TenablePermission` - Create new access permissions
- `Get-TenablePermissions` - Retrieve permissions with optional filtering

### User Management
- `Get-TenableUser` - Get user details (all users or specific UUID)
- `New-TenableUser` - Create a new user account
- `Update-TenableUser` - Update existing user account
- `Remove-TenableUser` - Delete a user account
- `Get-TenableUserAuth` - Get user authorization settings
- `Update-TenableUserAuth` - Update user authorization settings

### Scan Management
- `Get-TenableScans` - List all scans
- `New-TenableScans` - Create new scan (function incomplete)
- `Update-TenableScan` - Update existing scan configuration
- `Remove-TenableScan` - Delete a scan
- `Get-TenableScanInfo` - Get detailed information about a specific scan

### Scan Control
- `Start-TenableScan` - Launch a scan
- `Pause-TenableScan` - Pause a running scan
- `Resume-TenableScan` - Resume a paused scan
- `Stop-TenableScan` - Stop a scan (with optional force parameter)

### Asset Management
- `Get-TenableAssetList` - List all assets
- `Get-TenableAssetInfo` - Get detailed asset information
- `Search-TenableAssets` - Search assets with specific criteria
- `Move-TenableAsset` - Move assets between networks
- `Remove-TenableAsset` - Delete assets (soft or hard delete)

### Network Management
- `Get-TenableNets` - List all networks
- `New-TenableNet` - Create a new network
- `Update-TenableNet` - Update existing network
- `Remove-TenableNet` - Delete a network
- `Get-TenableNetAssetCount` - Get asset count for network

### Tag Management
- `Get-TenableTags` - List tags with optional filtering
- `New-TenableTag` - Create a new tag
- `Update-TenableTag` - Update existing tag
- `Remove-TenableTag` - Delete a tag
- `Add-TenableAssetTag` - Assign tags to assets
- `Remove-TenableAssetTag` - Remove tags from assets
- `Get-TenableAssetTags` - Get tags assigned to assets
- `Get-TenableTagCategories` - List all tag categories
- `Get-TenableTagValues` - Get values for a specific tag category

### Vulnerability Management
- `Get-TenableVulnerabilityList` - List vulnerabilities from workbench
- `Get-TenableVulnDetail` - Get detailed vulnerability information
- `Get-TenableVulnFamilies` - List vulnerability families
- `Export-TenableVulnerabilities` - Export vulnerability data
- `Get-VulnerabilityExportStatus` - Check export status
- `Get-VulnerabilityExportChunk` - Download export chunk data

### Credential Management
- `Get-TenableCredType` - List credential types
- `Get-TenableCredList` - List all credentials
- `Get-TenableCredDetails` - Get detailed credential information
- `New-TenableCred` - Create new credential (function incomplete)

### Filter Functions
- `Get-TenableAgentFilter` - Get agent filter options
- `Get-TenableAssetFilter` - Get asset filter options
- `Get-TenableCredentialFilter` - Get credential filter options
- `Get-TenableReportFilter` - Get report filter options
- `Get-TenableScanFilter` - Get scan filter options
- `Get-TenableScanHistoryFilter` - Get scan history filter options
- `Get-TenableVulnFilter` - Get vulnerability filter options

### Exclusion Management
- `Get-TenableExclusionList` - List scan exclusions
- `Update-TenableExclusion` - Update exclusion settings
- `Remove-TenableExclusion` - Delete exclusions

### Cloud Connector
- `Get-TenableCloudCon` - List cloud connectors

### Reporting
- `Create-TenableReport` - Create reports (function incomplete)

### Compliance
- `Get-TenablePCIList` - List PCI attestations

### Audit & Logging
- `Get-TenableAuditLog` - Retrieve audit log events (function needs work)

## Usage Examples

### Basic Connection Test
```powershell
$permissions = Connect-ToTenable
```

### List All Scans
```powershell
$scans = Get-TenableScans
$scans | Format-Table name, status, creation_date
```

### Create a New User
```powershell
$newUser = New-TenableUser -EmailAddress "user@company.com" -Password "SecurePass123!" -Name "John Doe" -Permissions 16
```

### Search for Assets
```powershell
$assets = Search-TenableAssets -SearchString "hostname:web-server" -Limit 100
```

### Create and Assign Tags
```powershell
$tag = New-TenableTag -CategoryName "Environment" -Value "Production" -Description "Production environment assets"
Add-TenableAssetTag -AssetUUIDs @("asset-uuid-1", "asset-uuid-2") -TagUUIDs @($tag.uuid)
```

### Start a Scan
```powershell
Start-TenableScan -ScanID "scan-uuid-here"
```

## Error Handling

Most functions return the JSON response from the Tenable API. Check the response for error messages or HTTP status codes. Some functions may throw PowerShell exceptions for invalid parameters.

## Known Issues

- `New-TenableScans` function is incomplete
- `New-TenableCred` function is incomplete  
- `Create-TenableReport` function doesn't work properly
- `Get-TenableAuditLog` function needs additional work
- `Update-TenableAPIAccess` has a bug where `$body` is referenced before initialization

## API Rate Limits

Be mindful of Tenable.io API rate limits when using these functions in loops or automated scripts. Consider adding delays between API calls for bulk operations.

## Security Notes

- Store API keys securely and never commit them to version control
- Use least-privilege principles when creating users and permissions
- Regularly rotate API keys according to your security policies

## Contributing

This module appears to be a work in progress. When contributing:
- Follow PowerShell naming conventions
- Add proper parameter validation
- Include error handling
- Add help documentation for functions
- Test thoroughly before submitting changes

## License

Please check with the original author for licensing information.

## Support

For Tenable.io API documentation, visit: https://developer.tenable.com/reference/navigate

For issues with this PowerShell module, contact the original author or create issues in the repository.
