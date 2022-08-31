# Powershell4Tenable
# 08/25/2022

Function ConnectTo-Tenable {
param(
    [Parameter(Mandatory = $true)] [String[]]$AccessKey,
    [Parameter(Mandatory = $true)] [String[]]$SecretKey
    )
    $apikey = "accessKey=$AccessKey;secretKey=$SecretKey"
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/access-control/permissions/users/me' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.permissions | select name
}
Function Get-TenableScans {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scans
}
Function Remove-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID -Method DELETE -Headers $headers
}
Function Start-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/launch -Method POST -Headers $headers
}
Function Stop-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/stop -Method POST -Headers $headers
}
Function Get-TenableScanInfo {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/ -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.info
}
Function Get-TenableAssetList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/assets' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.assets
}   
Function Search-TenableAssets {
    param(
    [Parameter(Mandatory = $true)] [String[]]$SearchString,
    [Parameter(Mandatory = $false)] [String[]]$Limit
    )
    if ($Limit -eq $null) { $Limit = "200" }
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $body = @{
    properties = $SearchString
    limit = $Limit
        }
    $body = $body | ConvertTo-Json
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/assets/search' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.assets
}    
Function Get-TenableScannerList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scanners' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scanners
}
Function Update-TenableScan {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ScanID,
    [Parameter(Mandatory = $true)] [String[]]$TextTargets
    )
    $body = @{
        text_targets = "$TextTargets"
        scanner_id = $defaultScannerID
        }
    $body = $body | ConvertTo-Json
    
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID" -Method PUT -Headers $headers -Body "{""settings"":$body}"
    $response = $response.Content | ConvertFrom-Json
    Return $response
}
Function Export-TenableVulnerabilities{
param(    
    [Parameter(Mandatory = $false)] [String[]]$AssetNum
    )
    if($AssetNum -eq $null) { $AssetNum = "5000"}
    $body = @{
        num_assets = $AssetNum
        }
    $body = $body | ConvertTo-Json

    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.export_uuid
}
Function Get-VulnerabilityExportStatus {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $apikey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export/status' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.exports
}
Function Get-TenableAgentList {
param(    
    [Parameter(Mandatory = $false)] [String[]]$ScannerID
    )
    if ($ScannerID -eq $null ){ $ScannerID = $defaultScannerID }
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scanners/$ScannerID/agents -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.agents
}
Function Get-TenableCredentialList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.credentials
}
Function Get-TenableExclusionList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/exclusions' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.exclusions
}
Function Get-TenableVulnFilterList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/vulnerabilities' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.filters
}
Function Get-TenableVulnerabilityList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/workbenches/vulnerabilities' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.vulnerabilities
}
Function Get-TenablePluginList{ #needs work
param(
    [Parameter(Mandatory = $false)] [String[]]$Size
    )
if ($Size -eq $null ){ $Size = "10000" }
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/plugin?last_updated=2021-01-01&size=$Size" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.filters
}
Function Get-TenableAuditLog { #needs work
param(
    [Parameter(Mandatory = $false)] [String[]]$Size
    )
if ($Size -eq $null ){ $Size = "100" }
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/audit-log/v1/events?$" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.events
}
Function Get-TenableAssetInfo{
param(
    [Parameter(Mandatory = $True)] [String[]]$UUID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $apikey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$uuid" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}