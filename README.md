# Powershell4Tenable

Tenable for Powershell is a Powershell module that adds a variety of controls and reporting to the Tenable.io cloud, allowing users to import data into Tenable for scans, export data from Tenable and correlate information across systems.

You must set the following variables

Very few of these powershell functions have great failsafe processes, so please beware. This is not an elegent solution. 

PS C:\> Import-Module .\TenablePowershell.psm1

You need to variables set up. the $apikey and the $defaultScannerID. This is an example of what they should look like. 

$apikey = "accessKey=XXXX;secretKey=a246bf07a405d6c8bds5af5616516512110190f7a9a22a1c0257"

$defaultScannerID = "12345678-9abc-defg-1234-56789abcdefg"

You could just add the UUID for the scanner for the commands that use the ScannerID. In my use case, I reference pretty much a single scannerID group and found that it's easier to define that once. 

There's still work to be done and most of these functions don't have proper error handling. Used at your own risk.

Functions Include
Get-TenableScans
Remove-TenableScan -ScanID 111
Start-TenableScan -ScanID 111
Stop-TenableScan -ScanID 111
Get-TenableScanInfo -ScanID 111
Get-TenableAssetList
Get-TenableAssetInfo -UUID 67555555-13d0-5555-1111-0b08315a2f64
Get-TenableScannerList
Update-TenableScan -ScanID 1111 -TextTargets "TestComputer1,TestComputer2"  *This currently only updates TextTargets. It may be broken out later
Export-TenableVulnerabilities -AssetNum 500
Get-VulnerabilityExportStatus 
Get-TenableAgentList
Get-TenableCredentialList
Get-TenableExclusionList
Get-TenableVulnerabilityList
Get-TenablePluginList
Get-TenableAuditLog
