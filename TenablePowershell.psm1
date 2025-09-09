# Powershell4Tenable
# 2023.03.24 Added User List, Create, Update and Delete

Function Connect-ToTenable { #This function is BS and shouldn't exist. 
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/access-control/permissions/users/me' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.permissions
}

#API Access Control Functions
Function Get-TenableAllowedIPs {
    param(
        [Parameter(Mandatory = $false)] 
        [ValidateSet("IPv4", "IPv6", "Both")]
        [String]$IPVersion = "Both"
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/access-control/v1/api-security-settings' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    
    switch ($IPVersion) {
        "IPv4" { 
            return [PSCustomObject]@{
                allowed_ipv4_addresses = $response.allowed_ipv4_addresses
            }
        }
        "IPv6" { 
            return [PSCustomObject]@{
                allowed_ipv6_addresses = $response.allowed_ipv6_addresses
            }
        }
        "Both" { 
            return [PSCustomObject]@{
                allowed_ipv4_addresses = $response.allowed_ipv4_addresses
                allowed_ipv6_addresses = $response.allowed_ipv6_addresses
            }
        }
    }
}

Function Update-TenableAPIAccess {
param(    
    [Parameter(Mandatory = $false)] [String[]]$IPv4,
    [Parameter(Mandatory = $false)] [String[]]$IPv6
    )    
    if ($IPv4 -eq $null -and $IPv6 -eq $null) {throw "IP Address Not Found"}
    if ($IPv4 -ne $null) { $body.Add("allowed_ipv4_addresses","$IPv4")}
    if ($IPv6 -ne $null) { $body.Add("allowed_ipv6_addresses","$IPv6")}
    
    $body = $body | ConvertTo-Json
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/access-control/v1/api-security-settings' -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#Scanner Functions
Function Get-TenableScannerList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scanners' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scanners
}

#Access Control Groups
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

#Access Control Permissions
Function New-TenablePermission {
    param(
        [Parameter(Mandatory = $true)] 
        [String]$Name,
        
        [Parameter(Mandatory = $true)] 
        [ValidateSet("CanScan", "CanView", "CanEdit", "CanUse")]
        [String[]]$Actions,
        
        [Parameter(Mandatory = $true)] 
        [String[]]$SubjectUUIDs,
        
        [Parameter(Mandatory = $true)] 
        [ValidateSet("User", "Group")]
        [String]$SubjectType,
        
        [Parameter(Mandatory = $true)] 
        [String[]]$ObjectUUIDs,
        
        [Parameter(Mandatory = $true)] 
        [ValidateSet("Tag", "Network", "Asset", "Scan")]
        [String]$ObjectType
    )
    
    # Build subjects array
    $subjects = @()
    foreach ($uuid in $SubjectUUIDs) {
        $subjects += @{
            type = $SubjectType
            uuid = $uuid
        }
    }
    
    # Build objects array
    $objects = @()
    foreach ($uuid in $ObjectUUIDs) {
        $objects += @{
            type = $ObjectType
            uuid = $uuid
        }
    }
    
    # Build request body
    $body = @{
        name = $Name
        subjects = $subjects
        actions = $Actions
        objects = $objects
    }
    $body = $body | ConvertTo-Json -Depth 3
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/access-control/permissions' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    
    Return $response
}

Function Get-TenablePermissions {
    param(
        [Parameter(Mandatory = $false)] 
        [String]$PermissionUUID,
        
        [Parameter(Mandatory = $false)] 
        [ValidateSet("CanScan", "CanView", "CanEdit", "CanUse")]
        [String[]]$FilterByActions,
        
        [Parameter(Mandatory = $false)] 
        [ValidateSet("User", "Group")]
        [String]$FilterBySubjectType,
        
        [Parameter(Mandatory = $false)] 
        [ValidateSet("Tag", "Network", "Asset", "Scan")]
        [String]$FilterByObjectType
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    if ($PermissionUUID) {
        # Get specific permission by UUID
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/api/v3/access-control/permissions/$PermissionUUID" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response
    } else {
        # Get all permissions
        $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/access-control/permissions' -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        
        $permissions = $response.permissions
        
        # Apply filters if specified
        if ($FilterByActions) {
            $permissions = $permissions | Where-Object { 
                $permissionActions = $_.actions
                $FilterByActions | ForEach-Object { $permissionActions -contains $_ }
            }
        }
        
        if ($FilterBySubjectType) {
            $permissions = $permissions | Where-Object { 
                $_.subjects | Where-Object { $_.type -eq $FilterBySubjectType }
            }
        }
        
        if ($FilterByObjectType) {
            $permissions = $permissions | Where-Object { 
                $_.objects | Where-Object { $_.type -eq $FilterByObjectType }
            }
        }
        
        Return $permissions
    }
}

#Access Control Users

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



#Scan Functions
Function New-TenableScans {
    param(    
    [Parameter(Mandatory = $true)] [String[]]$ScanTemplateUUID,
    [Parameter(Mandatory = $true)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$Description,
    [Parameter(Mandatory = $true)] [String[]]$TextTargets,
    [Parameter(Mandatory = $false)] [String[]]$ScannerID,
    [Parameter(Mandatory = $false)] [String[]]$EmailAddress
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scans
}
Function Get-TenableScans {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scans
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
Function Remove-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID -Method DELETE -Headers $headers
}

#Scan Control Functions
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
Function Pause-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/pause" -Method POST -Headers $headers
}
Function Resume-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID
    )
$headers=@{}
$headers.Add("Content-Type", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/resume" -Method POST -Headers $headers
}
Function Stop-TenableScan {
param(
    [Parameter(Mandatory = $true)] [String[]]$ScanID, 
    [switch]$Force
    )
    if ($Force) {
        $ScheduleUUID = (Get-TenableScanInfo -ScanID $ScanID).schedule_uuid
        $headers=@{}
        $headers.Add("Accept", "application/json")
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScheduleUUID/force-stop -Method POST -Headers $headers
    } else {
        $headers=@{}
        $headers.Add("Accept", "application/json")
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/stop -Method POST -Headers $headers
    }
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

#Filter Functions
Function Get-TenableAgentFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/agents' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}  
Function Get-TenableAssetFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/assets' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}  
Function Get-TenableCredentialFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/credentials' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}  
Function Get-TenableReportFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/reports/export' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}
Function Get-TenableScanFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/reports' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}  
Function Get-TenableScanHistoryFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/reports/history' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}  
Function Get-TenableVulnFilter {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/vulnerabilities' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}  

#Asset Functions
Function Get-TenableAssetList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/assets' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.assets
}  
Function Get-TenableAssetInfo{
    param(
    [Parameter(Mandatory = $True)] [String[]]$UUID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$UUID" -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}     
Function Move-TenableAsset{
param(
    [Parameter(Mandatory = $True)] [String[]]$Source,
    [Parameter(Mandatory = $True)] [String[]]$Destination,
    [Parameter(Mandatory = $True)] [String[]]$Targets
    )
    

    $body = @{}
    $body.add("source","$Source")
    $body.add("destination","$Destination")
    $body.add("targets","$Targets")
    $body = $body | ConvertTo-Json

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v2/assets/bulk-jobs/move-to-network' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response.response
}     
Function Remove-TenableAsset{
param(
    [Parameter(Mandatory = $false)] [bool[]]$HardDelete,
    [Parameter(Mandatory = $True)] [String[]]$Destination,
    [Parameter(Mandatory = $True)] [String[]]$Targets
    )
    

    $body = @{}
    $body.add("source","$Source")
    $body.add("destination","$Destination")
    $body.add("targets","$Targets")
    if ($HardDelete -ne $null) { $body.Add("hard_delete",$HardDelete)}
    $body = $body | ConvertTo-Json

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v2/assets/bulk-jobs/move-to-network' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
$response = $response.Content | ConvertFrom-Json
return $response.response
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


#Cloud Connector Functions
Function Get-TenableCloudCon {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/settings/connectors' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.connectors
}

#Credential Functions
Function New-TenableCred {
param(
    [Parameter(Mandatory = $true)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$Description,
    [Parameter(Mandatory = $true)] [String[]]$Type
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri https://cloud.tenable.com/scans/$ScanID/ -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.info
}
Function Get-TenableCredType {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials/types' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.credentials
}
Function Get-TenableCredList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.credentials
}
Function Get-TenableCredDetails {
param(
    [Parameter(Mandatory = $true)] [String[]]$UUID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/credentials/$UUID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}


Function Export-TenableVulnerabilities{
param(    
    [Parameter(Mandatory = $false)] [String[]]$AssetNum
    )
    if($AssetNum -eq $null) { $AssetNum = "5000"}
    
    $body = @{}
    $body.add("num_assets","$AssetNum")
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
Function Get-VulnerabilityExportChunk {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ExportUUID,
    [Parameter(Mandatory = $true)] [String[]]$ChunkID
    )

    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/vulns/export/$ExportUUID/chunks/$ChunkID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
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

#Exclusion Lists
Function Get-TenableExclusionList {
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/exclusions' -Method GET -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response.exclusions
}
Function Update-TenableExclusion {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ExclusionID,
    [Parameter(Mandatory = $false)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$Members,
    [Parameter(Mandatory = $false)] [bool[]]$Schedule,
    [Parameter(Mandatory = $false)] [datetime[]]$StartTime,
    [Parameter(Mandatory = $false)] [datetime[]]$EndTime,
    [Parameter(Mandatory = $false)] [ValidateSet("ONETIME","DAILY","WEEKLY","MONTHLY","YEARLY")][string[]]$Frequency
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/exclusions/$ExclusionID" -Method PUT -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
} 
Function Remove-TenableExclusion {
param(    
    [Parameter(Mandatory = $true)] [String[]]$ExclusionID
    )
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("X-ApiKeys", $TenableAPIKey)
$response = Invoke-WebRequest -Uri "https://cloud.tenable.com/exclusions/$ExclusionID" -Method DELETE -Headers $headers
$response = $response.Content | ConvertFrom-Json
return $response
}

#Vulnerability Functions
Function Get-TenableVulnDetail{
param(    
    [Parameter(Mandatory = $True)] [Int[]]$PluginID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/plugin/$PluginID" -Method GET -Headers $headers -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.attributes
}
Function Get-TenableVulnFamilies{
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/families?all=true" -Method GET -Headers $headers -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.families
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

#User Functions
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




Function Create-TenableReport {
    param(
        [ValidateSet('Summary', 'Asset', 'Plugin')]
        [Parameter(Mandatory=$true)]
        [string]$TemplateName
    )
    $body = @{}
    if ($TemplateName -eq "Summary"){
        $body.Add("template_name","host_vulns_summary")
    }
    if ($TemplateName -eq "Asset"){
        $body.Add("template_name","host_vulns_by_assets")
    }
    if ($TemplateName -eq "Plugin"){
        $body.Add("template_name","host_vulns_by_plugins")
    }
    $body = $body | ConvertTo-Json

     $body += '"filters": [{"property": "severity", "operator": "eq", "value": ["CRITICAL","HIGH" ]}]'
$headers=@{}
$headers.Add("accept", "application/json")
$headers.Add("content-type", "application/json")
$headers.Add("X-ApiKeys", "$TenableAPIKey")
#$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/reports/export' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
$response = "This function doesn't work"
return $response
}

#Network Functions
Function Get-TenableNets {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/networks' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.networks
} 
Function Update-TenableNet {
param(    
    [Parameter(Mandatory = $true)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$NetworkID,
    [Parameter(Mandatory = $false)] [String[]]$Description,
    [Parameter(Mandatory = $false)] [String[]]$TTL
    )
    If ($NetworkID -eq $null) {
        $NetworkID = (Get-TenableNets | Where-Object -FilterScript {$_.name -eq $Name}).uuid
    }
    $body = @{}
    $body.Add("name","$Name")
    if ($Description -ne $null){
        $body.Add("description","$Description")
    }
    if ($TTL -ge 14 -and $TTL -le 365){
        $body.Add("assets_ttl_days","$TTL")
    }
    if ($TemplateName -eq "Plugin"){
        $body.Add("template_name","host_vulns_by_plugins")
    }
    $body = $body | ConvertTo-Json
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID" -Method PUT -Headers $headers -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}
Function New-TenableNet {
    param(    
    [Parameter(Mandatory = $true)] [String[]]$Name,
    [Parameter(Mandatory = $false)] [String[]]$Description,
    [Parameter(Mandatory = $false)] [Int[]]$TTL
    )
    $body = @{}
    $body.Add("name","$Name")
    
    if ($Description -ne $null){
        $body.Add("description","$Description")
    }
    if ($TTL -ge 14 -and $TTL -le 365){
        $body.Add("assets_ttl_days","$TTL")
    }
    $body = $body | ConvertTo-Json    
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/networks' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
} 
Function Remove-TenableNet {
param(    
    [Parameter(Mandatory = $true)] [String[]]$NetworkID
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}
Function Get-TenableNetAssetCount {
    param(    
    [Parameter(Mandatory = $true)] [String[]]$NetworkID,
    [Parameter(Mandatory = $true)] [int[]]$Days
    )
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID/counts/assets-not-seen-in/$Days" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
} 

# PCI Attestations
Function Get-TenablePCIList {
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/pci-asv/attestations/list' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
} 

# Tag Management Functions

Function Get-TenableTags {
    param(
        [Parameter(Mandatory = $false)] 
        [String]$TagUUID,
        
        [Parameter(Mandatory = $false)] 
        [String]$CategoryName,
        
        [Parameter(Mandatory = $false)] 
        [String]$ValueName,
        
        [Parameter(Mandatory = $false)] 
        [Int]$Limit = 5000
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    if ($TagUUID) {
        # Get specific tag by UUID
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/$TagUUID" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response
    } else {
        # Get all tags with optional filters
        $uri = "https://cloud.tenable.com/tags?limit=$Limit"
        if ($CategoryName) { $uri += "&f=category_name:match:$CategoryName" }
        if ($ValueName) { $uri += "&f=value:match:$ValueName" }
        
        $response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response.tags
    }
}

Function New-TenableTag {
    param(
        [Parameter(Mandatory = $true)] 
        [String]$CategoryName,
        
        [Parameter(Mandatory = $true)] 
        [String]$Value,
        
        [Parameter(Mandatory = $false)] 
        [String]$Description,
        
        [Parameter(Mandatory = $false)] 
        [String]$CategoryDescription
    )
    
    $body = @{
        category_name = $CategoryName
        value = $Value
    }
    
    if ($Description) { $body.Add("description", $Description) }
    if ($CategoryDescription) { $body.Add("category_description", $CategoryDescription) }
    
    $body = $body | ConvertTo-Json
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/tags' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Update-TenableTag {
    param(
        [Parameter(Mandatory = $true)] 
        [String]$TagUUID,
        
        [Parameter(Mandatory = $false)] 
        [String]$CategoryName,
        
        [Parameter(Mandatory = $false)] 
        [String]$Value,
        
        [Parameter(Mandatory = $false)] 
        [String]$Description,
        
        [Parameter(Mandatory = $false)] 
        [String]$CategoryDescription
    )
    
    $body = @{}
    
    if ($CategoryName) { $body.Add("category_name", $CategoryName) }
    if ($Value) { $body.Add("value", $Value) }
    if ($Description) { $body.Add("description", $Description) }
    if ($CategoryDescription) { $body.Add("category_description", $CategoryDescription) }
    
    $body = $body | ConvertTo-Json
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/$TagUUID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenableTag {
    param(
        [Parameter(Mandatory = $true)] 
        [String]$TagUUID
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/$TagUUID" -Method DELETE -Headers $headers
    Return "Tag $TagUUID deleted successfully"
}

Function Add-TenableAssetTag {
    param(
        [Parameter(Mandatory = $true)] 
        [String[]]$AssetUUIDs,
        
        [Parameter(Mandatory = $true)] 
        [String[]]$TagUUIDs,
        
        [Parameter(Mandatory = $false)] 
        [ValidateSet("add", "replace")]
        [String]$Action = "add"
    )
    
    $body = @{
        action = $Action
        assets = $AssetUUIDs
        tags = $TagUUIDs
    }
    $body = $body | ConvertTo-Json
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/tags/assets/assignments' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenableAssetTag {
    param(
        [Parameter(Mandatory = $true)] 
        [String[]]$AssetUUIDs,
        
        [Parameter(Mandatory = $true)] 
        [String[]]$TagUUIDs
    )
    
    $body = @{
        action = "remove"
        assets = $AssetUUIDs
        tags = $TagUUIDs
    }
    $body = $body | ConvertTo-Json
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/tags/assets/assignments' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Get-TenableAssetTags {
    param(
        [Parameter(Mandatory = $false)] 
        [String]$AssetUUID
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    if ($AssetUUID -ne $Null){
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/values" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json 
        Return $response.values
    }else { 
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$AssetUUID/tags" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response.tags
    }

}


Function Get-TenableTagCategories {
    param(
        [Parameter(Mandatory = $false)] 
        [Int]$Limit = 1000
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/categories?limit=$Limit" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.categories
}

Function Get-TenableTagValues {
    param(
        [Parameter(Mandatory = $true)] 
        [String]$CategoryUUID,
        
        [Parameter(Mandatory = $false)] 
        [Int]$Limit = 1000
    )
    
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)
    
    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/categories/$CategoryUUID/values?limit=$Limit" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.values
}