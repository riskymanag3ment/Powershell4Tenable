################################################################################
# Powershell4Tenable
# PowerShell Module for Tenable.io API
#
# This module provides comprehensive access to the Tenable.io API
# organized to match the official API structure at:
# https://developer.tenable.com/reference/navigate
#
# Version: 2.0
# Last Updated: 2025-10-14
#
# Prerequisites:
# - Set global variable: $global:TenableAPIKey = "accessKey=xxx;secretKey=xxx"
#
# Change History:
# - 2025.10.14: Major reorganization to match API structure, added missing
#               functions, fixed bugs, enhanced existing functions
# - 2023.03.24: Added User List, Create, Update and Delete
################################################################################

################################################################################
#                    TENABLE PLATFORM & SETTINGS API
################################################################################

#==============================================================================
# ACCESS CONTROL - API SECURITY SETTINGS
# Endpoint: /access-control/v1/api-security-settings
#==============================================================================

Function Get-TenableAllowedIPs {
    <#
    .SYNOPSIS
    Retrieve allowed IP addresses for API access.

    .DESCRIPTION
    Returns the IPv4 and/or IPv6 addresses that are allowed to access the Tenable.io API.

    .PARAMETER IPVersion
    Specify which IP version to return: IPv4, IPv6, or Both (default).

    .EXAMPLE
    Get-TenableAllowedIPs
    Get-TenableAllowedIPs -IPVersion IPv4
    #>
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
    <#
    .SYNOPSIS
    Update allowed IP addresses for API access.

    .DESCRIPTION
    Updates the list of IPv4 and/or IPv6 addresses that are allowed to access the Tenable.io API.

    .PARAMETER IPv4
    Array of IPv4 addresses or CIDR blocks to allow.

    .PARAMETER IPv6
    Array of IPv6 addresses or CIDR blocks to allow.

    .EXAMPLE
    Update-TenableAPIAccess -IPv4 @("192.168.1.0/24", "10.0.0.1")
    #>
    param(
        [Parameter(Mandatory = $false)] [String[]]$IPv4,
        [Parameter(Mandatory = $false)] [String[]]$IPv6
    )

    if ($IPv4 -eq $null -and $IPv6 -eq $null) {
        throw "At least one IP address (IPv4 or IPv6) must be provided"
    }

    $body = @{}
    if ($IPv4 -ne $null) { $body.Add("allowed_ipv4_addresses", $IPv4) }
    if ($IPv6 -ne $null) { $body.Add("allowed_ipv6_addresses", $IPv6) }

    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/access-control/v1/api-security-settings' -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# ACCESS CONTROL - GROUPS
# Endpoint: /groups
#==============================================================================

Function New-TenableGroup {
    <#
    .SYNOPSIS
    Create a new user group.

    .DESCRIPTION
    Creates a new access control group in Tenable.io.

    .PARAMETER Name
    The name of the group to create.

    .EXAMPLE
    New-TenableGroup -Name "Security Admins"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name
    )

    $body = @{}
    $body.Add("name", "$Name")
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups" -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Get-TenableGroups {
    <#
    .SYNOPSIS
    List all user groups.

    .DESCRIPTION
    Returns a list of all user groups in the Tenable.io instance.

    .EXAMPLE
    Get-TenableGroups
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.groups
}

Function Update-TenableGroup {
    <#
    .SYNOPSIS
    Update a user group.

    .DESCRIPTION
    Updates the name of an existing user group.

    .PARAMETER GroupID
    The UUID of the group to update.

    .PARAMETER Name
    The new name for the group.

    .EXAMPLE
    Update-TenableGroup -GroupID "12345-abcde" -Name "New Group Name"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$GroupID,
        [Parameter(Mandatory = $true)] [String]$Name
    )

    $body = @{}
    $body.Add("name", $Name)
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Remove-TenableGroup {
    <#
    .SYNOPSIS
    Delete a user group.

    .DESCRIPTION
    Deletes a user group from Tenable.io.

    .PARAMETER GroupID
    The UUID of the group to delete.

    .EXAMPLE
    Remove-TenableGroup -GroupID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$GroupID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Get-TenableGroupMembers {
    <#
    .SYNOPSIS
    List members of a group.

    .DESCRIPTION
    Returns all users that are members of the specified group.

    .PARAMETER GroupID
    The UUID of the group.

    .EXAMPLE
    Get-TenableGroupMembers -GroupID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$GroupID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.users
}

Function Add-TenableGroupMember {
    <#
    .SYNOPSIS
    Add a user to a group.

    .DESCRIPTION
    Adds a user to the specified group.

    .PARAMETER GroupID
    The UUID of the group.

    .PARAMETER UserID
    The UUID of the user to add.

    .EXAMPLE
    Add-TenableGroupMember -GroupID "12345-abcde" -UserID "67890-fghij"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$GroupID,
        [Parameter(Mandatory = $true)] [String]$UserID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users/$UserID" -Method POST -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Remove-TenableGroupMember {
    <#
    .SYNOPSIS
    Remove a user from a group.

    .DESCRIPTION
    Removes a user from the specified group.

    .PARAMETER GroupID
    The UUID of the group.

    .PARAMETER UserID
    The UUID of the user to remove.

    .EXAMPLE
    Remove-TenableGroupMember -GroupID "12345-abcde" -UserID "67890-fghij"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$GroupID,
        [Parameter(Mandatory = $true)] [String]$UserID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/groups/$GroupID/users/$UserID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

#==============================================================================
# ACCESS CONTROL - PERMISSIONS
# Endpoint: /api/v3/access-control/permissions
#==============================================================================

Function New-TenablePermission {
    <#
    .SYNOPSIS
    Create a new permission.

    .DESCRIPTION
    Creates a new access control permission in Tenable.io.

    .PARAMETER Name
    The name of the permission.

    .PARAMETER Actions
    The actions allowed by this permission: CanScan, CanView, CanEdit, CanUse.

    .PARAMETER SubjectUUIDs
    Array of UUIDs for the subjects (users or groups).

    .PARAMETER SubjectType
    The type of subjects: User or Group.

    .PARAMETER ObjectUUIDs
    Array of UUIDs for the objects.

    .PARAMETER ObjectType
    The type of objects: Tag, Network, Asset, or Scan.

    .EXAMPLE
    New-TenablePermission -Name "Scan Permission" -Actions @("CanScan") -SubjectUUIDs @("user-uuid") -SubjectType "User" -ObjectUUIDs @("scan-uuid") -ObjectType "Scan"
    #>
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
        name     = $Name
        subjects = $subjects
        actions  = $Actions
        objects  = $objects
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
    <#
    .SYNOPSIS
    List or get specific permission.

    .DESCRIPTION
    Returns all permissions or a specific permission by UUID, with optional filtering.

    .PARAMETER PermissionUUID
    The UUID of a specific permission to retrieve.

    .PARAMETER FilterByActions
    Filter by allowed actions.

    .PARAMETER FilterBySubjectType
    Filter by subject type (User or Group).

    .PARAMETER FilterByObjectType
    Filter by object type (Tag, Network, Asset, Scan).

    .EXAMPLE
    Get-TenablePermissions
    Get-TenablePermissions -PermissionUUID "12345-abcde"
    Get-TenablePermissions -FilterByObjectType "Scan"
    #>
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
    }
    else {
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

Function Remove-TenablePermission {
    <#
    .SYNOPSIS
    Delete a permission.

    .DESCRIPTION
    Deletes an access control permission.

    .PARAMETER PermissionUUID
    The UUID of the permission to delete.

    .EXAMPLE
    Remove-TenablePermission -PermissionUUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [String]$PermissionUUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/api/v3/access-control/permissions/$PermissionUUID" -Method DELETE -Headers $headers
    Return "Permission $PermissionUUID deleted successfully"
}

#==============================================================================
# ACCESS CONTROL - USERS
# Endpoint: /users
#==============================================================================

Function Get-TenableUser {
    <#
    .SYNOPSIS
    List users or get specific user details.

    .DESCRIPTION
    Returns all users or details for a specific user by UUID.

    .PARAMETER UUID
    The UUID of a specific user to retrieve.

    .EXAMPLE
    Get-TenableUser
    Get-TenableUser -UUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $false)] [String]$UUID
    )

    if ($UUID -ne $null) {
        $headers = @{}
        $headers.Add("Accept", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        return $response
    }
    else {
        $headers = @{}
        $headers.Add("Accept", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        return $response.users
    }
}

Function New-TenableUser {
    <#
    .SYNOPSIS
    Create a new user account.

    .DESCRIPTION
    Creates a new user in Tenable.io.

    .PARAMETER EmailAddress
    The email address (username) for the new user.

    .PARAMETER Password
    The password for the new user.

    .PARAMETER Name
    The display name for the new user.

    .PARAMETER Permissions
    The permission level (16=Basic, 32=Scan Operator, 64=Administrator).

    .EXAMPLE
    New-TenableUser -EmailAddress "user@company.com" -Password "SecurePass123!" -Name "John Doe" -Permissions 16
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$EmailAddress,
        [Parameter(Mandatory = $true)] [String]$Password,
        [Parameter(Mandatory = $true)] [String]$Name,
        [Parameter(Mandatory = $true)] [Int]$Permissions
    )

    $body = @{}
    $body.Add("username", "$EmailAddress")
    $body.Add("password", "$Password")
    $body.Add("name", "$Name")
    $body.Add("permissions", $Permissions)
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users" -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Update-TenableUser {
    <#
    .SYNOPSIS
    Update an existing user account.

    .DESCRIPTION
    Updates properties of an existing user.

    .PARAMETER UUID
    The UUID of the user to update.

    .PARAMETER Permissions
    The new permission level.

    .PARAMETER Name
    The new display name.

    .PARAMETER Enabled
    Enable or disable the user account (true/false).

    .PARAMETER EmailAddress
    The new email address.

    .EXAMPLE
    Update-TenableUser -UUID "12345-abcde" -Name "Jane Doe" -Enabled "true"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$UUID,
        [Parameter(Mandatory = $false)] [int]$Permissions,
        [Parameter(Mandatory = $false)] [String]$Name,
        [Parameter(Mandatory = $false)] [String]$Enabled,
        [Parameter(Mandatory = $false)] [String]$EmailAddress
    )

    $body = @{}
    if ($Permissions -ne $null) { $body.Add("permissions", $Permissions) }
    if ($Name -ne $null) { $body.Add("name", "$Name") }
    if ($EmailAddress -ne $null) { $body.Add("email", "$EmailAddress") }
    if ($Enabled -ne $null) { $body.Add("enabled", "$Enabled") }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Remove-TenableUser {
    <#
    .SYNOPSIS
    Delete a user account.

    .DESCRIPTION
    Deletes a user from Tenable.io.

    .PARAMETER UUID
    The UUID of the user to delete.

    .EXAMPLE
    Remove-TenableUser -UUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$UUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Get-TenableUserAuth {
    <#
    .SYNOPSIS
    Get user authorization settings.

    .DESCRIPTION
    Returns the authorization settings for a specific user.

    .PARAMETER UUID
    The UUID of the user.

    .EXAMPLE
    Get-TenableUserAuth -UUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$UUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID/authorizations" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Update-TenableUserAuth {
    <#
    .SYNOPSIS
    Update user authorization settings.

    .DESCRIPTION
    Updates the authorization settings for a user (API access, password auth, SAML, MFA).

    .PARAMETER UUID
    The UUID of the user.

    .PARAMETER API
    Allow API access (true/false).

    .PARAMETER Password
    Allow password authentication (true/false).

    .PARAMETER SAML
    Allow SAML authentication (true/false).

    .PARAMETER MFARequired
    Require MFA enrollment (true/false).

    .EXAMPLE
    Update-TenableUserAuth -UUID "12345-abcde" -API "true" -MFARequired "true"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$UUID,
        [Parameter(Mandatory = $false)] [String]$API,
        [Parameter(Mandatory = $false)] [String]$Password,
        [Parameter(Mandatory = $false)] [String]$SAML,
        [Parameter(Mandatory = $false)] [String]$MFARequired
    )

    $userauth = Get-TenableUserAuth -UUID $UUID
    $body = @{}
    if ($API -ne $null) { $body.Add("api_permitted", "$API") }
    else { $API = $userauth.api_permitted; $body.Add("api_permitted", "$API") }
    if ($Password -ne $null) { $body.Add("password_permitted", "$Password") }
    else { $Password = $userauth.password_permitted; $body.Add("password_permitted", "$Password") }
    if ($SAML -ne $null) { $body.Add("saml_permitted", "$SAML") }
    else { $SAML = $userauth.saml_permitted; $body.Add("saml_permitted", "$SAML") }
    if ($MFARequired -ne $null) { $body.Add("mfa_enrollment_required", "$MFARequired") }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/users/$UUID/authorizations" -Method PUT -Headers $headers -Body $body
    $response = $response.Content | ConvertFrom-Json
    $userauth = Get-TenableUserAuth -UUID $UUID
    return $userauth
}

#==============================================================================
# AGENTS
# Endpoint: /scanners/{scanner_id}/agents
#==============================================================================

Function Get-TenableAgentList {
    <#
    .SYNOPSIS
    List agents for a scanner.

    .DESCRIPTION
    Returns a list of agents for the specified scanner.

    .PARAMETER ScannerID
    The UUID of the scanner.

    .EXAMPLE
    Get-TenableAgentList -ScannerID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScannerID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scanners/$ScannerID/agents" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.agents
}

#==============================================================================
# CLOUD CONNECTORS
# Endpoint: /settings/connectors
#==============================================================================

Function Get-TenableCloudCon {
    <#
    .SYNOPSIS
    List cloud connectors.

    .DESCRIPTION
    Returns a list of all cloud connectors.

    .EXAMPLE
    Get-TenableCloudCon
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/settings/connectors' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.connectors
}

#==============================================================================
# CREDENTIALS
# Endpoint: /credentials
#==============================================================================

Function Get-TenableCredType {
    <#
    .SYNOPSIS
    List credential types.

    .DESCRIPTION
    Returns available credential types in Tenable.io.

    .EXAMPLE
    Get-TenableCredType
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials/types' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.credentials
}

Function Get-TenableCredList {
    <#
    .SYNOPSIS
    List all credentials.

    .DESCRIPTION
    Returns a list of all managed credentials.

    .EXAMPLE
    Get-TenableCredList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/credentials' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.credentials
}

Function Get-TenableCredDetails {
    <#
    .SYNOPSIS
    Get credential details.

    .DESCRIPTION
    Returns details for a specific credential.

    .PARAMETER UUID
    The UUID of the credential.

    .EXAMPLE
    Get-TenableCredDetails -UUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$UUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/credentials/$UUID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# EXCLUSIONS
# Endpoint: /exclusions
#==============================================================================

Function Get-TenableExclusionList {
    <#
    .SYNOPSIS
    List scan exclusions.

    .DESCRIPTION
    Returns all scan exclusions.

    .EXAMPLE
    Get-TenableExclusionList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/exclusions' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.exclusions
}

Function New-TenableExclusion {
    <#
    .SYNOPSIS
    Create a new scan exclusion.

    .DESCRIPTION
    Creates a new scan exclusion with specified members and optional schedule.

    .PARAMETER Name
    The name of the exclusion.

    .PARAMETER Members
    Array of targets (IPs, hostnames, or CIDR blocks) to exclude.

    .PARAMETER Description
    Optional description of the exclusion.

    .PARAMETER Schedule
    Whether this is a scheduled exclusion (true/false).

    .PARAMETER StartTime
    Start time for scheduled exclusion (datetime).

    .PARAMETER EndTime
    End time for scheduled exclusion (datetime).

    .PARAMETER Frequency
    Frequency for scheduled exclusion: ONETIME, DAILY, WEEKLY, MONTHLY, YEARLY.

    .PARAMETER Timezone
    Timezone for the schedule (e.g., "America/New_York").

    .EXAMPLE
    New-TenableExclusion -Name "Maintenance Window" -Members @("192.168.1.1", "192.168.1.2")
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name,
        [Parameter(Mandatory = $true)] [String[]]$Members,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $false)] [bool]$Schedule,
        [Parameter(Mandatory = $false)] [datetime]$StartTime,
        [Parameter(Mandatory = $false)] [datetime]$EndTime,
        [Parameter(Mandatory = $false)]
        [ValidateSet("ONETIME", "DAILY", "WEEKLY", "MONTHLY", "YEARLY")]
        [String]$Frequency,
        [Parameter(Mandatory = $false)] [String]$Timezone = "UTC"
    )

    $body = @{
        name    = $Name
        members = $Members -join ","
    }

    if ($Description) { $body.Add("description", $Description) }

    if ($Schedule) {
        $scheduleObj = @{
            enabled = $true
        }
        if ($StartTime) { $scheduleObj.Add("starttime", $StartTime.ToString("yyyy-MM-dd HH:mm:ss")) }
        if ($EndTime) { $scheduleObj.Add("endtime", $EndTime.ToString("yyyy-MM-dd HH:mm:ss")) }
        if ($Frequency) {
            $rrules = @{
                freq = $Frequency
            }
            $scheduleObj.Add("rrules", $rrules)
        }
        if ($Timezone) { $scheduleObj.Add("timezone", $Timezone) }

        $body.Add("schedule", $scheduleObj)
    }

    $body = $body | ConvertTo-Json -Depth 3

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/exclusions' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Update-TenableExclusion {
    <#
    .SYNOPSIS
    Update an exclusion.

    .DESCRIPTION
    Updates an existing scan exclusion.

    .PARAMETER ExclusionID
    The ID of the exclusion to update.

    .PARAMETER Name
    The new name for the exclusion.

    .PARAMETER Members
    New array of targets to exclude.

    .PARAMETER Schedule
    Whether this is a scheduled exclusion.

    .PARAMETER StartTime
    Start time for scheduled exclusion.

    .PARAMETER EndTime
    End time for scheduled exclusion.

    .PARAMETER Frequency
    Frequency: ONETIME, DAILY, WEEKLY, MONTHLY, YEARLY.

    .EXAMPLE
    Update-TenableExclusion -ExclusionID 123 -Name "Updated Exclusion" -Members @("192.168.1.10")
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ExclusionID,
        [Parameter(Mandatory = $false)] [String]$Name,
        [Parameter(Mandatory = $false)] [String[]]$Members,
        [Parameter(Mandatory = $false)] [bool]$Schedule,
        [Parameter(Mandatory = $false)] [datetime]$StartTime,
        [Parameter(Mandatory = $false)] [datetime]$EndTime,
        [Parameter(Mandatory = $false)]
        [ValidateSet("ONETIME", "DAILY", "WEEKLY", "MONTHLY", "YEARLY")]
        [String]$Frequency
    )

    $body = @{}
    if ($Name) { $body.Add("name", $Name) }
    if ($Members) { $body.Add("members", ($Members -join ",")) }

    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/exclusions/$ExclusionID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Remove-TenableExclusion {
    <#
    .SYNOPSIS
    Delete an exclusion.

    .DESCRIPTION
    Deletes a scan exclusion.

    .PARAMETER ExclusionID
    The ID of the exclusion to delete.

    .EXAMPLE
    Remove-TenableExclusion -ExclusionID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ExclusionID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/exclusions/$ExclusionID" -Method DELETE -Headers $headers
    Return "Exclusion $ExclusionID deleted successfully"
}

#==============================================================================
# NETWORKS
# Endpoint: /networks
#==============================================================================

Function Get-TenableNets {
    <#
    .SYNOPSIS
    List all networks.

    .DESCRIPTION
    Returns a list of all networks configured in Tenable.io.

    .EXAMPLE
    Get-TenableNets
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/networks' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.networks
}

Function New-TenableNet {
    <#
    .SYNOPSIS
    Create a new network.

    .DESCRIPTION
    Creates a new network in Tenable.io.

    .PARAMETER Name
    The name of the network.

    .PARAMETER Description
    Optional description of the network.

    .PARAMETER TTL
    Asset TTL in days (14-365).

    .EXAMPLE
    New-TenableNet -Name "Corporate Network" -Description "Main office network" -TTL 90
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $false)] [Int]$TTL
    )

    $body = @{}
    $body.Add("name", "$Name")

    if ($Description -ne $null) {
        $body.Add("description", "$Description")
    }
    if ($TTL -ge 14 -and $TTL -le 365) {
        $body.Add("assets_ttl_days", "$TTL")
    }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/networks' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Update-TenableNet {
    <#
    .SYNOPSIS
    Update a network.

    .DESCRIPTION
    Updates an existing network.

    .PARAMETER Name
    The name of the network to update.

    .PARAMETER NetworkID
    The UUID of the network (if not using Name).

    .PARAMETER Description
    New description.

    .PARAMETER TTL
    New asset TTL in days (14-365).

    .EXAMPLE
    Update-TenableNet -Name "Corporate Network" -TTL 120
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name,
        [Parameter(Mandatory = $false)] [String]$NetworkID,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $false)] [String]$TTL
    )

    If ($NetworkID -eq $null) {
        $NetworkID = (Get-TenableNets | Where-Object -FilterScript { $_.name -eq $Name }).uuid
    }

    $body = @{}
    $body.Add("name", "$Name")
    if ($Description -ne $null) {
        $body.Add("description", "$Description")
    }
    if ($TTL -ge 14 -and $TTL -le 365) {
        $body.Add("assets_ttl_days", "$TTL")
    }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenableNet {
    <#
    .SYNOPSIS
    Delete a network.

    .DESCRIPTION
    Deletes a network from Tenable.io.

    .PARAMETER NetworkID
    The UUID of the network to delete.

    .EXAMPLE
    Remove-TenableNet -NetworkID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$NetworkID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID" -Method DELETE -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Get-TenableNetAssetCount {
    <#
    .SYNOPSIS
    Get network asset count for assets not seen in N days.

    .DESCRIPTION
    Returns the count of assets in a network that have not been seen in the specified number of days.

    .PARAMETER NetworkID
    The UUID of the network.

    .PARAMETER Days
    Number of days to check.

    .EXAMPLE
    Get-TenableNetAssetCount -NetworkID "12345-abcde" -Days 30
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$NetworkID,
        [Parameter(Mandatory = $true)] [int]$Days
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/networks/$NetworkID/counts/assets-not-seen-in/$Days" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# SCANNERS
# Endpoint: /scanners
#==============================================================================

Function Get-TenableScannerList {
    <#
    .SYNOPSIS
    List all scanners.

    .DESCRIPTION
    Returns a list of all scanners in the Tenable.io instance.

    .EXAMPLE
    Get-TenableScannerList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scanners' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scanners
}

Function Get-TenableScannerDetails {
    <#
    .SYNOPSIS
    Get scanner details.

    .DESCRIPTION
    Returns details for a specific scanner.

    .PARAMETER ScannerID
    The UUID of the scanner.

    .EXAMPLE
    Get-TenableScannerDetails -ScannerID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScannerID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scanners/$ScannerID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# TAGS
# Endpoint: /tags
#==============================================================================

Function Get-TenableTags {
    <#
    .SYNOPSIS
    List tags or get specific tag.

    .DESCRIPTION
    Returns all tags or a specific tag by UUID, with optional filtering.

    .PARAMETER TagUUID
    The UUID of a specific tag to retrieve.

    .PARAMETER CategoryName
    Filter by category name.

    .PARAMETER ValueName
    Filter by value name.

    .PARAMETER Limit
    Maximum number of results to return (default: 5000).

    .EXAMPLE
    Get-TenableTags
    Get-TenableTags -TagUUID "12345-abcde"
    Get-TenableTags -CategoryName "Environment"
    #>
    param(
        [Parameter(Mandatory = $false)] [String]$TagUUID,
        [Parameter(Mandatory = $false)] [String]$CategoryName,
        [Parameter(Mandatory = $false)] [String]$ValueName,
        [Parameter(Mandatory = $false)] [Int]$Limit = 5000
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    if ($TagUUID) {
        # Get specific tag by UUID
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/$TagUUID" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response
    }
    else {
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
    <#
    .SYNOPSIS
    Create a new tag.

    .DESCRIPTION
    Creates a new tag with category and value.

    .PARAMETER CategoryName
    The category name for the tag.

    .PARAMETER Value
    The value for the tag.

    .PARAMETER Description
    Optional description of the tag value.

    .PARAMETER CategoryDescription
    Optional description of the tag category.

    .EXAMPLE
    New-TenableTag -CategoryName "Environment" -Value "Production" -Description "Production environment"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$CategoryName,
        [Parameter(Mandatory = $true)] [String]$Value,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $false)] [String]$CategoryDescription
    )

    $body = @{
        category_name = $CategoryName
        value         = $Value
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
    <#
    .SYNOPSIS
    Update a tag.

    .DESCRIPTION
    Updates an existing tag.

    .PARAMETER TagUUID
    The UUID of the tag to update.

    .PARAMETER CategoryName
    New category name.

    .PARAMETER Value
    New value.

    .PARAMETER Description
    New description.

    .PARAMETER CategoryDescription
    New category description.

    .EXAMPLE
    Update-TenableTag -TagUUID "12345-abcde" -Value "Staging"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$TagUUID,
        [Parameter(Mandatory = $false)] [String]$CategoryName,
        [Parameter(Mandatory = $false)] [String]$Value,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $false)] [String]$CategoryDescription
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
    <#
    .SYNOPSIS
    Delete a tag.

    .DESCRIPTION
    Deletes a tag from Tenable.io.

    .PARAMETER TagUUID
    The UUID of the tag to delete.

    .EXAMPLE
    Remove-TenableTag -TagUUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$TagUUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/$TagUUID" -Method DELETE -Headers $headers
    Return "Tag $TagUUID deleted successfully"
}

Function Add-TenableAssetTag {
    <#
    .SYNOPSIS
    Assign tags to assets.

    .DESCRIPTION
    Adds or replaces tags on assets.

    .PARAMETER AssetUUIDs
    Array of asset UUIDs.

    .PARAMETER TagUUIDs
    Array of tag UUIDs to assign.

    .PARAMETER Action
    Action to perform: add or replace (default: add).

    .EXAMPLE
    Add-TenableAssetTag -AssetUUIDs @("asset1","asset2") -TagUUIDs @("tag1") -Action "add"
    #>
    param(
        [Parameter(Mandatory = $true)] [String[]]$AssetUUIDs,
        [Parameter(Mandatory = $true)] [String[]]$TagUUIDs,
        [Parameter(Mandatory = $false)]
        [ValidateSet("add", "replace")]
        [String]$Action = "add"
    )

    $body = @{
        action = $Action
        assets = $AssetUUIDs
        tags   = $TagUUIDs
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
    <#
    .SYNOPSIS
    Remove tags from assets.

    .DESCRIPTION
    Removes tags from specified assets.

    .PARAMETER AssetUUIDs
    Array of asset UUIDs.

    .PARAMETER TagUUIDs
    Array of tag UUIDs to remove.

    .EXAMPLE
    Remove-TenableAssetTag -AssetUUIDs @("asset1") -TagUUIDs @("tag1")
    #>
    param(
        [Parameter(Mandatory = $true)] [String[]]$AssetUUIDs,
        [Parameter(Mandatory = $true)] [String[]]$TagUUIDs
    )

    $body = @{
        action = "remove"
        assets = $AssetUUIDs
        tags   = $TagUUIDs
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
    <#
    .SYNOPSIS
    Get tags assigned to an asset.

    .DESCRIPTION
    Returns tags assigned to a specific asset or all tag values.

    .PARAMETER AssetUUID
    The UUID of the asset.

    .EXAMPLE
    Get-TenableAssetTags -AssetUUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $false)] [String]$AssetUUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    if ($AssetUUID -ne $Null) {
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$AssetUUID/tags" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response.tags
    }
    else {
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/values" -Method GET -Headers $headers
        $response = $response.Content | ConvertFrom-Json
        Return $response.values
    }
}

Function Get-TenableTagCategories {
    <#
    .SYNOPSIS
    List tag categories.

    .DESCRIPTION
    Returns all tag categories.

    .PARAMETER Limit
    Maximum number of results (default: 1000).

    .EXAMPLE
    Get-TenableTagCategories
    #>
    param(
        [Parameter(Mandatory = $false)] [Int]$Limit = 1000
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/categories?limit=$Limit" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.categories
}

Function Get-TenableTagValues {
    <#
    .SYNOPSIS
    List tag values for a category.

    .DESCRIPTION
    Returns all values for a specific tag category.

    .PARAMETER CategoryUUID
    The UUID of the category.

    .PARAMETER Limit
    Maximum number of results (default: 1000).

    .EXAMPLE
    Get-TenableTagValues -CategoryUUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$CategoryUUID,
        [Parameter(Mandatory = $false)] [Int]$Limit = 1000
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/tags/categories/$CategoryUUID/values?limit=$Limit" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.values
}

################################################################################
#                    VULNERABILITY MANAGEMENT API
################################################################################

#==============================================================================
# ASSETS
# Endpoint: /assets, /api/v3/assets
#==============================================================================

Function Get-TenableAssetList {
    <#
    .SYNOPSIS
    List all assets.

    .DESCRIPTION
    Returns a list of all assets in the system.

    .EXAMPLE
    Get-TenableAssetList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/assets' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.assets
}

Function Get-TenableAssetInfo {
    <#
    .SYNOPSIS
    Get asset details.

    .DESCRIPTION
    Returns detailed information for a specific asset.

    .PARAMETER UUID
    The UUID of the asset.

    .EXAMPLE
    Get-TenableAssetInfo -UUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $True)] [String]$UUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/assets/$UUID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Search-TenableAssets {
    <#
    .SYNOPSIS
    Search for assets.

    .DESCRIPTION
    Searches for assets using specified criteria.

    .PARAMETER SearchString
    The search criteria/properties.

    .PARAMETER Limit
    Maximum number of results (default: 200).

    .EXAMPLE
    Search-TenableAssets -SearchString "hostname:web-server" -Limit 100
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$SearchString,
        [Parameter(Mandatory = $false)] [String]$Limit
    )

    if ($Limit -eq $null) { $Limit = "200" }

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $body = @{
        properties = $SearchString
        limit      = $Limit
    }
    $body = $body | ConvertTo-Json

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v3/assets/search' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.assets
}

Function Move-TenableAsset {
    <#
    .SYNOPSIS
    Move assets between networks.

    .DESCRIPTION
    Moves assets from one network to another.

    .PARAMETER Source
    Source network UUID.

    .PARAMETER Destination
    Destination network UUID.

    .PARAMETER Targets
    Array of asset identifiers to move.

    .EXAMPLE
    Move-TenableAsset -Source "net1-uuid" -Destination "net2-uuid" -Targets @("192.168.1.1")
    #>
    param(
        [Parameter(Mandatory = $True)] [String]$Source,
        [Parameter(Mandatory = $True)] [String]$Destination,
        [Parameter(Mandatory = $True)] [String[]]$Targets
    )

    $body = @{}
    $body.add("source", "$Source")
    $body.add("destination", "$Destination")
    $body.add("targets", $Targets)
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v2/assets/bulk-jobs/move-to-network' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Remove-TenableAsset {
    <#
    .SYNOPSIS
    Delete assets.

    .DESCRIPTION
    Deletes (soft or hard) specified assets.

    .PARAMETER HardDelete
    Perform hard delete if true.

    .PARAMETER Source
    Source network UUID.

    .PARAMETER Targets
    Array of asset identifiers to delete.

    .EXAMPLE
    Remove-TenableAsset -Source "net-uuid" -Targets @("192.168.1.1") -HardDelete $true
    #>
    param(
        [Parameter(Mandatory = $false)] [bool]$HardDelete,
        [Parameter(Mandatory = $True)] [String]$Source,
        [Parameter(Mandatory = $True)] [String[]]$Targets
    )

    $body = @{}
    $body.add("source", "$Source")
    $body.add("targets", $Targets)
    if ($HardDelete -ne $null) { $body.Add("hard_delete", $HardDelete) }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/api/v2/assets/bulk-jobs/delete' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    return $response
}

Function Export-TenableAssets {
    <#
    .SYNOPSIS
    Export asset data.

    .DESCRIPTION
    Initiates an asset export job.

    .PARAMETER ChunkSize
    Number of assets per chunk (default: 1000).

    .PARAMETER Filters
    Optional filters for the export.

    .EXAMPLE
    Export-TenableAssets -ChunkSize 500
    #>
    param(
        [Parameter(Mandatory = $false)] [int]$ChunkSize = 1000,
        [Parameter(Mandatory = $false)] [hashtable]$Filters
    )

    $body = @{
        chunk_size = $ChunkSize
    }

    if ($Filters) { $body.Add("filters", $Filters) }

    $body = $body | ConvertTo-Json -Depth 3

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/assets/export' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.export_uuid
}

#==============================================================================
# EDITOR / TEMPLATES
# Endpoint: /editor
#==============================================================================

Function Get-TenableScanTemplates {
    <#
    .SYNOPSIS
    List scan templates.

    .DESCRIPTION
    Returns available scan templates (policies).

    .PARAMETER Type
    Type of templates to retrieve (scan or policy).

    .EXAMPLE
    Get-TenableScanTemplates
    #>
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("scan", "policy")]
        [String]$Type = "scan"
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/editor/$Type/templates" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.templates
}

#==============================================================================
# FILTERS
# Endpoint: /filters
#==============================================================================

Function Get-TenableAgentFilter {
    <#
    .SYNOPSIS
    Get agent filter options.

    .DESCRIPTION
    Returns available filter options for agents.

    .EXAMPLE
    Get-TenableAgentFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/agents' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Get-TenableAssetFilter {
    <#
    .SYNOPSIS
    Get asset filter options.

    .DESCRIPTION
    Returns available filter options for assets in workbenches.

    .EXAMPLE
    Get-TenableAssetFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/assets' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

Function Get-TenableCredentialFilter {
    <#
    .SYNOPSIS
    Get credential filter options.

    .DESCRIPTION
    Returns available filter options for credentials.

    .EXAMPLE
    Get-TenableCredentialFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/credentials' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

Function Get-TenableReportFilter {
    <#
    .SYNOPSIS
    Get report filter options.

    .DESCRIPTION
    Returns available filter options for reports.

    .EXAMPLE
    Get-TenableReportFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/reports/export' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

Function Get-TenableScanFilter {
    <#
    .SYNOPSIS
    Get scan filter options.

    .DESCRIPTION
    Returns available filter options for scan reports.

    .EXAMPLE
    Get-TenableScanFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/reports' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

Function Get-TenableScanHistoryFilter {
    <#
    .SYNOPSIS
    Get scan history filter options.

    .DESCRIPTION
    Returns available filter options for scan history.

    .EXAMPLE
    Get-TenableScanHistoryFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/scans/reports/history' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

Function Get-TenableVulnFilter {
    <#
    .SYNOPSIS
    Get vulnerability filter options.

    .DESCRIPTION
    Returns available filter options for vulnerabilities in workbenches.

    .EXAMPLE
    Get-TenableVulnFilter
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/filters/workbenches/vulnerabilities' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.filters
}

#==============================================================================
# FOLDERS
# Endpoint: /folders
#==============================================================================

Function Get-TenableFolders {
    <#
    .SYNOPSIS
    List all folders.

    .DESCRIPTION
    Returns a list of all folders.

    .EXAMPLE
    Get-TenableFolders
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/folders' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.folders
}

Function New-TenableFolder {
    <#
    .SYNOPSIS
    Create a new folder.

    .DESCRIPTION
    Creates a new folder for organizing scans.

    .PARAMETER Name
    The name of the folder.

    .EXAMPLE
    New-TenableFolder -Name "Production Scans"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name
    )

    $body = @{
        name = $Name
    }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/folders' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Update-TenableFolder {
    <#
    .SYNOPSIS
    Update a folder.

    .DESCRIPTION
    Updates the name of an existing folder.

    .PARAMETER FolderID
    The ID of the folder to update.

    .PARAMETER Name
    The new name for the folder.

    .EXAMPLE
    Update-TenableFolder -FolderID 123 -Name "New Folder Name"
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$FolderID,
        [Parameter(Mandatory = $true)] [String]$Name
    )

    $body = @{
        name = $Name
    }
    $body = $body | ConvertTo-Json

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/folders/$FolderID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenableFolder {
    <#
    .SYNOPSIS
    Delete a folder.

    .DESCRIPTION
    Deletes a folder.

    .PARAMETER FolderID
    The ID of the folder to delete.

    .EXAMPLE
    Remove-TenableFolder -FolderID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$FolderID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/folders/$FolderID" -Method DELETE -Headers $headers
    Return "Folder $FolderID deleted successfully"
}

#==============================================================================
# PLUGINS
# Endpoint: /plugins
#==============================================================================

Function Get-TenablePluginFamilies {
    <#
    .SYNOPSIS
    List plugin families.

    .DESCRIPTION
    Returns a list of all plugin families.

    .EXAMPLE
    Get-TenablePluginFamilies
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/families" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.families
}

Function Get-TenablePluginFamilyDetails {
    <#
    .SYNOPSIS
    Get plugins in a family.

    .DESCRIPTION
    Returns all plugins in a specific family.

    .PARAMETER FamilyID
    The ID of the plugin family.

    .EXAMPLE
    Get-TenablePluginFamilyDetails -FamilyID 10
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$FamilyID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/families/$FamilyID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.plugins
}

Function Get-TenablePluginDetails {
    <#
    .SYNOPSIS
    Get plugin details.

    .DESCRIPTION
    Returns detailed information for a specific plugin.

    .PARAMETER PluginID
    The ID of the plugin.

    .EXAMPLE
    Get-TenablePluginDetails -PluginID 19506
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$PluginID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/plugin/$PluginID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# POLICIES
# Endpoint: /policies
#==============================================================================

Function Get-TenablePolicies {
    <#
    .SYNOPSIS
    List all policies.

    .DESCRIPTION
    Returns a list of all scan policies.

    .EXAMPLE
    Get-TenablePolicies
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/policies' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.policies
}

Function Get-TenablePolicyDetails {
    <#
    .SYNOPSIS
    Get policy details.

    .DESCRIPTION
    Returns details for a specific scan policy.

    .PARAMETER PolicyID
    The ID of the policy.

    .EXAMPLE
    Get-TenablePolicyDetails -PolicyID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$PolicyID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/policies/$PolicyID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Copy-TenablePolicy {
    <#
    .SYNOPSIS
    Copy a policy.

    .DESCRIPTION
    Creates a copy of an existing scan policy.

    .PARAMETER PolicyID
    The ID of the policy to copy.

    .EXAMPLE
    Copy-TenablePolicy -PolicyID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$PolicyID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/policies/$PolicyID/copy" -Method POST -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenablePolicy {
    <#
    .SYNOPSIS
    Delete a policy.

    .DESCRIPTION
    Deletes a scan policy.

    .PARAMETER PolicyID
    The ID of the policy to delete.

    .EXAMPLE
    Remove-TenablePolicy -PolicyID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [int]$PolicyID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/policies/$PolicyID" -Method DELETE -Headers $headers
    Return "Policy $PolicyID deleted successfully"
}

#==============================================================================
# SCANS
# Endpoint: /scans
#==============================================================================

Function Get-TenableScans {
    <#
    .SYNOPSIS
    List all scans.

    .DESCRIPTION
    Returns a list of all scans.

    .PARAMETER FolderID
    Optional: Filter scans by folder ID.

    .EXAMPLE
    Get-TenableScans
    Get-TenableScans -FolderID 123
    #>
    param(
        [Parameter(Mandatory = $false)] [int]$FolderID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $uri = 'https://cloud.tenable.com/scans'
    if ($FolderID) { $uri += "?folder_id=$FolderID" }

    $response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.scans
}

Function New-TenableScan {
    <#
    .SYNOPSIS
    Create a new scan.

    .DESCRIPTION
    Creates a new scan with the specified configuration.

    .PARAMETER Name
    The name of the scan.

    .PARAMETER Description
    Optional description of the scan.

    .PARAMETER Targets
    Target IP addresses, hostnames, or CIDR ranges (comma-separated).

    .PARAMETER TemplateUUID
    The UUID of the scan template to use.

    .PARAMETER PolicyID
    Optional: The ID of a custom policy to use.

    .PARAMETER FolderID
    Optional: The folder ID to place the scan in.

    .PARAMETER ScannerID
    Optional: The scanner UUID to use.

    .EXAMPLE
    New-TenableScan -Name "Web Server Scan" -Targets "192.168.1.0/24" -TemplateUUID "template-uuid"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$Name,
        [Parameter(Mandatory = $false)] [String]$Description,
        [Parameter(Mandatory = $true)] [String]$Targets,
        [Parameter(Mandatory = $true)] [String]$TemplateUUID,
        [Parameter(Mandatory = $false)] [int]$PolicyID,
        [Parameter(Mandatory = $false)] [int]$FolderID,
        [Parameter(Mandatory = $false)] [String]$ScannerID
    )

    $settings = @{
        name        = $Name
        text_targets = $Targets
    }

    if ($Description) { $settings.Add("description", $Description) }
    if ($PolicyID) { $settings.Add("policy_id", $PolicyID) }
    if ($FolderID) { $settings.Add("folder_id", $FolderID) }
    if ($ScannerID) { $settings.Add("scanner_id", $ScannerID) }

    $body = @{
        uuid     = $TemplateUUID
        settings = $settings
    }
    $body = $body | ConvertTo-Json -Depth 3

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Get-TenableScanInfo {
    <#
    .SYNOPSIS
    Get scan details.

    .DESCRIPTION
    Returns detailed information for a specific scan.

    .PARAMETER ScanID
    The ID of the scan.

    .EXAMPLE
    Get-TenableScanInfo -ScanID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.info
}

Function Update-TenableScan {
    <#
    .SYNOPSIS
    Update a scan.

    .DESCRIPTION
    Updates the configuration of an existing scan.

    .PARAMETER ScanID
    The ID of the scan to update.

    .PARAMETER TextTargets
    New target IP addresses, hostnames, or CIDR ranges.

    .PARAMETER ScannerID
    Optional: New scanner UUID.

    .PARAMETER Name
    Optional: New scan name.

    .PARAMETER Description
    Optional: New description.

    .EXAMPLE
    Update-TenableScan -ScanID 123 -TextTargets "192.168.2.0/24"
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID,
        [Parameter(Mandatory = $false)] [String]$TextTargets,
        [Parameter(Mandatory = $false)] [String]$ScannerID,
        [Parameter(Mandatory = $false)] [String]$Name,
        [Parameter(Mandatory = $false)] [String]$Description
    )

    if ($ScannerID -eq $null) {
        $ScannerName = Get-TenableScanInfo -ScanID $ScanID | Select-Object -ExpandProperty scanner_name
        $ScannerID = Get-TenableScannerList | Where-Object { $_.name -like "$ScannerName" } | Select-Object -ExpandProperty uuid
    }

    $settings = @{}
    if ($TextTargets) { $settings.Add("text_targets", "$TextTargets") }
    if ($ScannerID) { $settings.Add("scanner_id", $ScannerID) }
    if ($Name) { $settings.Add("name", $Name) }
    if ($Description) { $settings.Add("description", $Description) }

    $body = @{
        settings = $settings
    }
    $body = $body | ConvertTo-Json -Depth 2

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID" -Method PUT -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Remove-TenableScan {
    <#
    .SYNOPSIS
    Delete a scan.

    .DESCRIPTION
    Deletes a scan from Tenable.io.

    .PARAMETER ScanID
    The ID of the scan to delete.

    .EXAMPLE
    Remove-TenableScan -ScanID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID" -Method DELETE -Headers $headers
    Return "Scan $ScanID deleted successfully"
}

# Scan Control Functions

Function Start-TenableScan {
    <#
    .SYNOPSIS
    Launch a scan.

    .DESCRIPTION
    Starts a scan.

    .PARAMETER ScanID
    The ID of the scan to launch.

    .PARAMETER Targets
    Optional: Override targets for this scan run.

    .EXAMPLE
    Start-TenableScan -ScanID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID,
        [Parameter(Mandatory = $false)] [String[]]$Targets
    )

    $body = @{}
    if ($Targets) {
        $body.Add("alt_targets", ($Targets -join ","))
    }

    $bodyJson = if ($body.Count -gt 0) { $body | ConvertTo-Json } else { "" }

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/launch" -Method POST -Headers $headers -ContentType 'application/json' -Body $bodyJson
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Pause-TenableScan {
    <#
    .SYNOPSIS
    Pause a running scan.

    .DESCRIPTION
    Pauses a scan that is currently running.

    .PARAMETER ScanID
    The ID of the scan to pause.

    .EXAMPLE
    Pause-TenableScan -ScanID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID
    )

    $headers = @{}
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/pause" -Method POST -Headers $headers
    Return "Scan $ScanID paused"
}

Function Resume-TenableScan {
    <#
    .SYNOPSIS
    Resume a paused scan.

    .DESCRIPTION
    Resumes a scan that was paused.

    .PARAMETER ScanID
    The ID of the scan to resume.

    .EXAMPLE
    Resume-TenableScan -ScanID 123
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID
    )

    $headers = @{}
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/resume" -Method POST -Headers $headers
    Return "Scan $ScanID resumed"
}

Function Stop-TenableScan {
    <#
    .SYNOPSIS
    Stop a running scan.

    .DESCRIPTION
    Stops a scan that is currently running.

    .PARAMETER ScanID
    The ID of the scan to stop.

    .PARAMETER Force
    Use force-stop instead of normal stop.

    .EXAMPLE
    Stop-TenableScan -ScanID 123
    Stop-TenableScan -ScanID 123 -Force
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ScanID,
        [switch]$Force
    )

    if ($Force) {
        $ScheduleUUID = (Get-TenableScanInfo -ScanID $ScanID).schedule_uuid
        $headers = @{}
        $headers.Add("Accept", "application/json")
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScheduleUUID/force-stop" -Method POST -Headers $headers
        Return "Scan $ScanID force-stopped"
    }
    else {
        $headers = @{}
        $headers.Add("Accept", "application/json")
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-ApiKeys", $TenableAPIKey)
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/scans/$ScanID/stop" -Method POST -Headers $headers
        Return "Scan $ScanID stopped"
    }
}

#==============================================================================
# VULNERABILITIES / EXPORTS
# Endpoint: /vulns, /workbenches
#==============================================================================

Function Get-TenableVulnerabilityList {
    <#
    .SYNOPSIS
    List vulnerabilities from workbench.

    .DESCRIPTION
    Returns a list of vulnerabilities from the workbench.

    .EXAMPLE
    Get-TenableVulnerabilityList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/workbenches/vulnerabilities' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.vulnerabilities
}

Function Get-TenableVulnDetail {
    <#
    .SYNOPSIS
    Get vulnerability details.

    .DESCRIPTION
    Returns detailed information for a specific vulnerability plugin.

    .PARAMETER PluginID
    The ID of the vulnerability plugin.

    .EXAMPLE
    Get-TenableVulnDetail -PluginID 19506
    #>
    param(
        [Parameter(Mandatory = $True)] [Int]$PluginID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/plugins/plugin/$PluginID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response.attributes
}

Function Export-TenableVulnerabilities {
    <#
    .SYNOPSIS
    Export vulnerabilities.

    .DESCRIPTION
    Initiates a vulnerability export job.

    .PARAMETER NumAssets
    Number of assets per chunk (default: 5000).

    .PARAMETER Severity
    Optional: Array of severity levels to filter (info, low, medium, high, critical).

    .PARAMETER State
    Optional: Array of states to filter (open, reopened, fixed).

    .EXAMPLE
    Export-TenableVulnerabilities -NumAssets 1000
    Export-TenableVulnerabilities -Severity @("high","critical") -State @("open")
    #>
    param(
        [Parameter(Mandatory = $false)] [String]$NumAssets = "5000",
        [Parameter(Mandatory = $false)]
        [ValidateSet("info", "low", "medium", "high", "critical")]
        [String[]]$Severity,
        [Parameter(Mandatory = $false)]
        [ValidateSet("open", "reopened", "fixed")]
        [String[]]$State
    )

    $body = @{}
    $body.add("num_assets", "$NumAssets")

    # Add filters if provided
    if ($Severity -or $State) {
        $filters = @{}
        if ($Severity) { $filters.Add("severity", $Severity) }
        if ($State) { $filters.Add("state", $State) }
        $body.Add("filters", $filters)
    }

    $body = $body | ConvertTo-Json -Depth 3

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export' -Method POST -Headers $headers -ContentType 'application/json' -Body $body
    $response = $response.Content | ConvertFrom-Json
    Return $response.export_uuid
}

Function Get-VulnerabilityExportStatus {
    <#
    .SYNOPSIS
    Get status of all vulnerability exports.

    .DESCRIPTION
    Returns the status of all vulnerability export jobs.

    .PARAMETER ExportUUID
    Optional: Get status of a specific export by UUID.

    .EXAMPLE
    Get-VulnerabilityExportStatus
    Get-VulnerabilityExportStatus -ExportUUID "12345-abcde"
    #>
    param(
        [Parameter(Mandatory = $false)] [String]$ExportUUID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    if ($ExportUUID) {
        $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/vulns/export/$ExportUUID/status" -Method GET -Headers $headers
    }
    else {
        $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/vulns/export/status' -Method GET -Headers $headers
    }

    $response = $response.Content | ConvertFrom-Json
    Return $response
}

Function Get-VulnerabilityExportChunk {
    <#
    .SYNOPSIS
    Download a vulnerability export chunk.

    .DESCRIPTION
    Downloads a specific chunk of a vulnerability export.

    .PARAMETER ExportUUID
    The UUID of the export job.

    .PARAMETER ChunkID
    The chunk ID to download.

    .EXAMPLE
    Get-VulnerabilityExportChunk -ExportUUID "12345-abcde" -ChunkID 1
    #>
    param(
        [Parameter(Mandatory = $true)] [String]$ExportUUID,
        [Parameter(Mandatory = $true)] [String]$ChunkID
    )

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri "https://cloud.tenable.com/vulns/export/$ExportUUID/chunks/$ChunkID" -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

#==============================================================================
# AUDIT LOG
# Endpoint: /audit-log/v1/events
#==============================================================================

Function Get-TenableAuditLog {
    <#
    .SYNOPSIS
    Retrieve audit log events.

    .DESCRIPTION
    Returns audit log events for the organization.

    .PARAMETER Limit
    Maximum number of events to return (default: 100, max: 10000).

    .PARAMETER StartTime
    Optional: Start time for the query (datetime).

    .PARAMETER EndTime
    Optional: End time for the query (datetime).

    .EXAMPLE
    Get-TenableAuditLog -Limit 50
    #>
    param(
        [Parameter(Mandatory = $false)] [int]$Limit = 100,
        [Parameter(Mandatory = $false)] [datetime]$StartTime,
        [Parameter(Mandatory = $false)] [datetime]$EndTime
    )

    $uri = "https://cloud.tenable.com/audit-log/v1/events?limit=$Limit"

    if ($StartTime) {
        $startEpoch = [int](Get-Date $StartTime -UFormat %s)
        $uri += "&f.received.gte=$startEpoch"
    }

    if ($EndTime) {
        $endEpoch = [int](Get-Date $EndTime -UFormat %s)
        $uri += "&f.received.lte=$endEpoch"
    }

    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    return $response.events
}

#==============================================================================
# PCI ASV
# Endpoint: /pci-asv/attestations
#==============================================================================

Function Get-TenablePCIList {
    <#
    .SYNOPSIS
    List PCI ASV attestations.

    .DESCRIPTION
    Returns a list of all PCI ASV attestations.

    .EXAMPLE
    Get-TenablePCIList
    #>
    $headers = @{}
    $headers.Add("Accept", "application/json")
    $headers.Add("X-ApiKeys", $TenableAPIKey)

    $response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/pci-asv/attestations/list' -Method GET -Headers $headers
    $response = $response.Content | ConvertFrom-Json
    Return $response
}

################################################################################
# MODULE EXPORTS
################################################################################

# Export all functions
Export-ModuleMember -Function *

