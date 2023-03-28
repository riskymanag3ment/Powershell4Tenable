# Powershell4Tenable

Tenable for Powershell is a Powershell module that adds a variety of controls and reporting to the Tenable.io cloud, allowing users to import data into Tenable for scans, export data from Tenable and correlate information across systems.

You must set the following variables

Very few of these powershell functions have great failsafe processes, so please beware. This is not an elegent solution. 

PS C:\> Import-Module .\TenablePowershell.psm1

You need to variables set up. the $apikey. This is an example of what they should look like. 

$apikey = "accessKey=XXXX;secretKey=a246bf07a405d6c8bds5af5616516512110190f7a9a22a1c0257"

There's still work to be done and most of these functions don't have proper error handling. Used at your own risk.

Functions Include

Add-TenableGroupMember -GroupID 1234 -UserID 1234

Connect-ToTenable *Currently not in use

Export-TenableVulnerabilities -AssetNum 500

Get-TenableAgentList

Get-TenableAssetInfo -UUID 67555555-13d0-5555-1111-0b08315a2f64

Get-TenableAssetList

Get-TenableAuditLog

Get-TenableCredentialList

Get-TenableExclusionList

Get-TenableGroupMembers -GroupID

Get-TenableGroups

Get-TenablePluginList

Get-TenableScanInfo -ScanID 111

Get-TenableScannerList

Get-TenableScans

Get-TenableUser -UUID *for individual user or no UUID for all users

Get-TenableVulnerabilityList

Get-VulnerabilityExportStatus 

New-TenableGroup -Name "Group Name"

New-TenableUser -emailAddress "user@domain.com" -Password "Clear Text Password" -Name "First Last" -Permissions *See tenable permissions

Remove-TenableGroup -GroupID 111

Remove-TenableGroupMember -GroupID 111 -UserID 111

Remove-TenableScan -ScanID 111

Remove-TenableUser -UserID 111

Start-TenableScan -ScanID 111

Stop-TenableScan -ScanID 111

Update-TenableGroup -GroupID 111 -Name "New Group Name"

Update-TenableScan -ScanID 1111 -TextTargets "TestComputer1,TestComputer2" -ScannerID 67555555-13d0-5555-1111-0b08315a2f64  *more work to be done here

Update-TenableUser -UUID -EmailAddress -Name -Permissions -Enabled

Update-TenableUserAuth -Password -SAML -API -MFARequired













Update-TenableUser -UUID -Permissions -Name -Enabled -EmailAddress

Get-TenableUserAuth -UUID

Update-TenableUserAuth -API -Password -SAML -MFARequired

New-TenableGroup -Name "Group Name"


