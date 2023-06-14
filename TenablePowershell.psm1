# Powershell4Tenable
# 2023.03.24 Added User List, Create, Update and Delete

Function Connect-ToTenable { #This function is BS and shouldn't exist. 
param(
    [Parameter(Mandatory = $true)] [String[]]$AccessKey,
    [Parameter(Mandatory = $true)] [String[]]$SecretKey
    )
    $TenableAPIKey = "accessKey=$AccessKey;secretKey=$SecretKey"
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/access-control/permissions/users/me' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.permissions | select name
}
Function Get-TenableScans {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
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
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID -Method DELETE -Headers $headers
}
Function Start-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/launch -Method POST -Headers $headers
}
Function Stop-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/stop -Method POST -Headers $headers
}
Function Get-TenableScanInfo {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/ -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.info
}
Function Get-TenableAssetList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
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
    $headers.Add("X-ApiKeys", $TenableAPIKey)
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
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scanners' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scanners
}
Function Update-TenableScan {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ScanID,
    [Parameter(Mandatory = $true)] [String[]]$TextTargets,
    [Parameter(Mandatory = $false)] [String[]]$ScannerID,
    [Parameter(Mandatory = $false)] [String[]]$EmailAddress
    )
    
    if ($ScannerID -eq $null){
        $ScannerName = Get-TenableScanInfo -ScanID $ScanID | select scanner_name
        $ScannerName = $ScannerName.scanner_name
        $ScannerID = Get-TenableScannerList | Where-Object {$_.name -like "$ScannerName"} | select uuid
        $ScannerID = $ScannerID.uuid
    }
    
    $body = @{
        text_targets = "$TextTargets"
        scanner_id = $ScannerID
        }
    $body = $body | ConvertTo-Json
    
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID" -Method PUT -Headers $headers -Body "{""settings"":$body}"
    $response = $response.Content | ConvertFrom-Json
    Clear-Variable $ScannerID
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
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.export_uuid
}
Function Get-VulnerabilityExportStatus {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export/status' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.exports
}
Function Get-TenableAgentList {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ScannerID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri https://cloud.tenable.com/scanners/$ScannerID/agents -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.agents
}
Function Get-TenableCredentialList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.credentials
}
Function Get-TenableExclusionList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/exclusions' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.exclusions
}
Function Get-TenableVulnFilterList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/vulnerabilities' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.filters
}
Function Get-TenableVulnerabilityList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
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
$headers.Add("X-ApiKeys", $TenableAPIKey)
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
$headers.Add("X-ApiKeys", $TenableAPIKey)
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
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$uuid" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}
Function Get-TenableUser{
param(    
    [Parameter(Mandatory = $false)] [String[]]$UUID
    )
if ($UUID -ne $null) {
    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}
else {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.users
}
}
Function Remove-TenableUser{
param(    
    [Parameter(Mandatory = $true)] [String[]]$UUID
    )
    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}
Function New-TenableUser{
param(    
    [Parameter(Mandatory = $true)] [String[]]$EmailAddress,
    [Parameter(Mandatory = $true)] [String[]]$Password,
    [Parameter(Mandatory = $true)] [String[]]$Name,
    [Parameter(Mandatory = $true)] [Int[]]$Permissions
    )
$body=@{}
$body.Add("username","$EmailAddress")
$body.Add("password","$Password")
$body.Add("name","$Name")
$body.Add("permissions",$Permissions)
$body = $body | ConvertTo-Json


$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users" -Method POST -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response
}
Function Update-TenableUser{
param(    
    [Parameter(Mandatory = $true)] [String[]]$UUID,
    [Parameter(Mandatory = $false)] [int]$Permissions,
    [Parameter(Mandatory = $false)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$Enabled,
    [Parameter(Mandatory = $false)] [String[]]$EmailAddress
    )
$body = @{}
if ($Permissions -ne $null) { $body.Add("permissions",$Permissions)}
if ($Name -ne $null) { $body.Add("name","$Name")}
if ($EmailAddress -ne $null) { $body.Add("email","$EmailAddress")}
if ($Enabled -ne $null) { $body.Add("enabled","$Enabled")}
$body = $body | ConvertTo-Json
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response
}
Function Get-TenableUserAuth{
param(    
    [Parameter(Mandatory = $true)] [String[]]$UUID
    )
$headers=@{}
$headers.Add("accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID/authorizations" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}
Function Update-TenableUserAuth{
param(    
    [Parameter(Mandatory = $true)] [String[]]$UUID,
    [Parameter(Mandatory = $false)] [String[]]$API,
    [Parameter(Mandatory = $false)] [String[]]$Password,
    [Parameter(Mandatory = $false)] [String[]]$SAML,
    [Parameter(Mandatory = $false)] [String[]]$MFARequired
    )

$userauth = Get-TenableUserAuth -UUID $UUID
$body = @{}
if ($API -ne $null) { $body.Add("api_permitted","$API")} else { $API = $userauth.api_permitted; $body.Add("api_permitted","$API")}
if ($Password -ne $null) { $body.Add("password_permitted","$Password")} else { $Password = $userauth.password_permitted; $body.Add("password_permitted","$Password")}
if ($SAML-ne $null) {$body.Add("saml_permitted","$SAML") } else { $SAML = $userauth.saml_permitted; $body.Add("saml_permitted","$SAML")}
if($MFARequired -ne $null) {$body.Add("mfa_enrollment_required","$MFARequired") }
$body = $body | ConvertTo-Json

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID/authorizations" -Method PUT -Headers $headers -Body $body
$response = $response.Content | ConvertFrom-Json
$userauth = Get-TenableUserAuth -UUID $UUID
return $userauth
}

Function New-TenableGroup{
param(    
    [Parameter(Mandatory = $true)] [String[]]$Name
    )

$body = @{}
$body.Add("name","$Name")
$body = $body | ConvertTo-Json

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups" -Method POST -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response
}

Function Get-TenableGroups{
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
$response = $response.groups
return $response
}

Function Update-TenableGroup{
param(    
    [Parameter(Mandatory = $true)] [String[]]$GroupID,
    [Parameter(Mandatory = $true)] [String[]]$Name
    )

$body = @{}
$body.Add("name",$Name)
$body = $body | ConvertTo-Json

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)

$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response
}

Function Remove-TenableGroup{
param(    
    [Parameter(Mandatory = $true)] [String[]]$GroupID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID" -Method DELETE -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}

Function Get-TenableGroupMembers{
param(    
    [Parameter(Mandatory = $true)] [String[]]$GroupID
    )

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
$response = $response.users
return $response
}

Function Add-TenableGroupMember{
param(    
    [Parameter(Mandatory = $true)] [String[]]$GroupID,
    [Parameter(Mandatory = $true)] [String[]]$UserID
    
    )

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users/$UserID" -Method POST -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response

}

Function Remove-TenableGroupMember{
param(    
    [Parameter(Mandatory = $true)] [String[]]$GroupID,
    [Parameter(Mandatory = $true)] [String[]]$UserID
    
    )

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users/$UserID" -Method DELETE -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response

}