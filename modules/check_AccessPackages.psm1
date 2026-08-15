<#
.SYNOPSIS
   Enumerates Microsoft Entra Entitlement Management access packages.
#>

# Formats Graph errors into concise Access Package coverage messages.
function Format-AccessPackageGraphError {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        return "Graph API request failed."
    }

    $details = $message.Trim()
    if ($details -match "^API request failed with status\s+(\d+):\s+([^-]+?)\s+-\s+(.+)$") {
        $status = $matches[1]
        $code = $matches[2].Trim()
        $apiMessage = $matches[3].Trim()
        $friendly = "Graph returned $status ($code): $apiMessage"

        if ($code -eq "NoLicense" -or $apiMessage -match "(?i)license requirement|does not meet license") {
            return "$friendly This usually means the tenant does not meet the Entitlement Management / Access Packages license requirement."
        }
        if ($status -eq "403") {
            return "$friendly This can indicate missing Entitlement Management Graph permissions, insufficient administrative privileges."
        }

        return $friendly
    }

    if ($details -match "(?i)NoLicense|license requirement|does not meet license") {
        return "$details This usually means the tenant does not meet the Entitlement Management / Access Packages license requirement."
    }

    return $details
}

# Sends a silent GET request to the Entitlement Management Graph endpoint.
function Invoke-AccessPackageGraphGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][hashtable]$QueryParameters,
        [Parameter(Mandatory = $false)][ValidateSet("v1.0", "beta")][string]$ApiVersion = "v1.0"
    )

    return Send-ApiRequest -Method GET `
        -Uri "https://graph.microsoft.com/$ApiVersion$Uri" `
        -AccessToken $GLOBALMsGraphAccessToken.access_token `
        -QueryParameters $QueryParameters `
        -UserAgent $($GlobalAuditSummary.UserAgent.Name) `
        -Silent `
        -ErrorAction Stop
}

# Retrieves incompatible Access Package and group relationships in Graph batches.
# These relationships are intentionally not expanded on the package collection:
# Graph can return an empty or missing expanded relationship even when the direct
# relationship endpoint contains configured objects.
function Invoke-AccessPackageSeparationBatch {
    param(
        [Parameter(Mandatory = $true)][object[]]$Packages,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [string]$UserAgent
    )

    $requests = New-Object 'System.Collections.Generic.List[object]'
    $requestMap = @{}
    foreach ($package in @($Packages)) {
        $packageId = [string]$package.id
        if ([string]::IsNullOrWhiteSpace($packageId)) { continue }

        $packageRequestId = "ap-$packageId-packages"
        $groupRequestId = "ap-$packageId-groups"
        [void]$requests.Add(@{
            id     = $packageRequestId
            method = 'GET'
            url    = "/identityGovernance/entitlementManagement/accessPackages/$packageId/incompatibleAccessPackages?`$top=100&`$select=id,displayName"
        })
        [void]$requests.Add(@{
            id     = $groupRequestId
            method = 'GET'
            url    = "/identityGovernance/entitlementManagement/accessPackages/$packageId/incompatibleGroups?`$top=100"
        })
        $requestMap[$packageRequestId] = [pscustomobject]@{ PackageId = $packageId; Type = 'Access Package' }
        $requestMap[$groupRequestId] = [pscustomobject]@{ PackageId = $packageId; Type = 'Group' }
    }

    $requestArray = @($requests.ToArray())
    $responses = @()
    if ($requestArray.Count -gt 0) {
        $responses = @(Send-GraphBatchRequest -AccessToken $AccessToken -Requests $requestArray -MaxBatchSize 20 -UserAgent $UserAgent -Silent)
    }

    return [pscustomobject]@{
        Requests = $requestArray
        Responses = @($responses)
        RequestMap = $requestMap
        BatchRequests = if ($requests.Count -gt 0) { [int][math]::Ceiling($requests.Count / 20.0) } else { 0 }
    }
}

# Returns true only when the expanded collection query can reasonably be retried
# through the legacy collection shape. Authentication, licensing, throttling, and
# exhausted transient failures must retain their existing coverage behavior.
function Test-AccessPackageExpandedQueryFallbackEligible {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = [string]$ErrorRecord.Exception.Message
    return (
        $message -match "(?i)status\s+400\b" -or
        $message -match "(?i)InvalidFilter|Request_BadRequest|invalid\s+OData|unsupported.*query"
    )
}

# Reads the first non-empty property value from a Graph object.
function Get-AccessPackageObjectValue {
    param(
        [object]$Object,
        [string[]]$Names
    )

    if ($null -eq $Object) { return $null }
    foreach ($name in $Names) {
        if ($Object.PSObject.Properties[$name]) {
            $value = $Object.$name
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return $value
            }
        }
    }
    return $null
}

# Converts a value to an integer with a stable fallback.
function Get-AccessPackageIntValue {
    param(
        [object]$Value,
        [int]$DefaultValue = 0
    )

    if ($null -eq $Value) { return $DefaultValue }
    $parsed = 0
    if ([int]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return $DefaultValue
}

# Converts HTML-formatted report cells back to plain text for TXT and CSV exports.
function ConvertTo-AccessPackagePlainText {
    param([object]$Value)

    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return "" }
    $text = [regex]::Replace($text, '<[^>]+>', '')
    return [System.Net.WebUtility]::HtmlDecode($text)
}

# Rounds report scores to whole numbers for non-interactive exports.
function ConvertTo-AccessPackageWholeNumber {
    param([object]$Value)

    $number = 0.0
    if ([double]::TryParse([string]$Value, [ref]$number)) {
        return [int][math]::Round($number, 0)
    }
    return $Value
}

# Normalizes Graph truthy flags from booleans and common strings.
function Test-AccessPackageTruthyValue {
    param($Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ([string]$Value).Trim().ToLowerInvariant() -in @("true", "1", "yes", "enabled", "required")
}

# Converts Graph date values without depending on the current PowerShell culture.
function ConvertTo-AccessPackageDateTimeOffset {
    param([Parameter(Mandatory = $false)][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return [datetimeoffset]$Value }
    if ($Value -is [datetime]) { return [datetimeoffset]([datetime]$Value) }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($text, [ref]$parsed)) { return $parsed }
    return $null
}

# Returns the calculated end of an assignment schedule when it can be resolved.
function Get-AccessPackageAssignmentEndDateTime {
    param([Parameter(Mandatory = $true)][object]$Assignment)

    if ($null -eq $Assignment.schedule -or $null -eq $Assignment.schedule.expiration) { return $null }
    $expiration = $Assignment.schedule.expiration
    $expirationType = [string]$expiration.type
    if ($expirationType -ieq "afterDateTime") {
        $endValue = if ($expiration.endDateTime) { $expiration.endDateTime } else { $expiration.expirationDateTime }
        return (ConvertTo-AccessPackageDateTimeOffset -Value $endValue)
    }
    if ($expirationType -ieq "afterDuration") {
        $start = ConvertTo-AccessPackageDateTimeOffset -Value $Assignment.schedule.startDateTime
        if ($null -eq $start -or [string]::IsNullOrWhiteSpace([string]$expiration.duration)) { return $null }
        try {
            return $start.Add([System.Xml.XmlConvert]::ToTimeSpan([string]$expiration.duration))
        } catch {
            return $null
        }
    }
    return $null
}

# Counts only fully delivered assignments whose configured schedule is currently active.
function Test-AccessPackageAssignmentActive {
    param(
        [Parameter(Mandatory = $true)][object]$Assignment,
        [Parameter(Mandatory = $true)][datetimeoffset]$Now
    )

    if ([string]$Assignment.state -ine "delivered" -or [string]$Assignment.status -ine "Delivered") { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Assignment.expiredDateTime)) { return $false }
    if ($null -eq $Assignment.schedule -or $null -eq $Assignment.schedule.expiration) { return $false }

    $startValue = $Assignment.schedule.startDateTime
    $start = ConvertTo-AccessPackageDateTimeOffset -Value $startValue
    if ($null -ne $startValue -and -not [string]::IsNullOrWhiteSpace([string]$startValue)) {
        if ($null -eq $start -or $start.ToUniversalTime() -gt $Now.ToUniversalTime()) { return $false }
    }

    $expirationType = [string]$Assignment.schedule.expiration.type
    if ($expirationType -ieq "noExpiration") { return $true }
    $end = Get-AccessPackageAssignmentEndDateTime -Assignment $Assignment
    return ($null -ne $end -and $end.ToUniversalTime() -gt $Now.ToUniversalTime())
}

# Separately identifies assignments whose state, marker, or schedule shows expiration.
function Test-AccessPackageAssignmentExpired {
    param(
        [Parameter(Mandatory = $true)][object]$Assignment,
        [Parameter(Mandatory = $true)][datetimeoffset]$Now
    )

    if ([string]$Assignment.state -ieq "expired") { return $true }
    if (-not [string]::IsNullOrWhiteSpace([string]$Assignment.expiredDateTime)) { return $true }
    $end = Get-AccessPackageAssignmentEndDateTime -Assignment $Assignment
    return ($null -ne $end -and $end.ToUniversalTime() -le $Now.ToUniversalTime())
}

# Reads a boolean requestor setting from policy requestor metadata.
function Test-AccessPackagePolicyRequestorSetting {
    param(
        [object]$Policy,
        [string]$Name
    )

    if ($null -eq $Policy -or [string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Policy.PSObject.Properties["requestorSettings"] -and $null -ne $Policy.requestorSettings -and $Policy.requestorSettings.PSObject.Properties[$Name]) {
        return (Test-AccessPackageTruthyValue $Policy.requestorSettings.$Name)
    }
    if ($Policy.PSObject.Properties[$Name]) {
        return (Test-AccessPackageTruthyValue $Policy.$Name)
    }
    return $false
}

# Detects whether a policy requires approval for access requests.
function Test-AccessPackagePolicyApprovalRequired {
    param($Policy)

    if ($null -eq $Policy -or -not $Policy.PSObject.Properties["requestApprovalSettings"] -or $null -eq $Policy.requestApprovalSettings) { return $false }
    $settings = $Policy.requestApprovalSettings
    foreach ($name in @("isApprovalRequiredForAdd", "approvalRequiredForAdd", "approvalRequired", "isApprovalRequired")) {
        if ($settings.PSObject.Properties[$name] -and (Test-AccessPackageTruthyValue $settings.$name)) { return $true }
    }
    return $false
}

# Formats a count and unit with simple pluralization.
function ConvertTo-AccessPackagePluralText {
    param(
        [int]$Value,
        [string]$Unit
    )

    if ($Value -eq 1) { return "1 $Unit" }
    return "$Value $($Unit)s"
}

# Converts Graph duration values into readable text.
function ConvertTo-AccessPackageDurationText {
    param([string]$Duration)

    if ([string]::IsNullOrWhiteSpace($Duration)) { return "-" }
    $durationText = $Duration.Trim()

    if ($durationText -match "^\d+$") {
        return (ConvertTo-AccessPackagePluralText -Value ([int]$durationText) -Unit "day")
    }

    $match = [regex]::Match($durationText, "^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) { return $durationText }

    $parts = [System.Collections.Generic.List[string]]::new()
    $units = @(
        @{ Index = 1; Name = "year" },
        @{ Index = 2; Name = "month" },
        @{ Index = 3; Name = "week" },
        @{ Index = 4; Name = "day" },
        @{ Index = 5; Name = "hour" },
        @{ Index = 6; Name = "minute" },
        @{ Index = 7; Name = "second" }
    )

    foreach ($unit in $units) {
        $valueText = $match.Groups[$unit.Index].Value
        if ([string]::IsNullOrWhiteSpace($valueText)) { continue }
        [void]$parts.Add((ConvertTo-AccessPackagePluralText -Value ([int]$valueText) -Unit $unit.Name))
    }

    if ($parts.Count -eq 0) { return $durationText }
    return ($parts -join " ")
}

# Formats Graph date/time values as UTC text.
function ConvertTo-AccessPackageDateTimeText {
    param([string]$DateTimeText)

    if ([string]::IsNullOrWhiteSpace($DateTimeText)) { return "-" }
    try {
        $dateTimeOffset = [datetimeoffset]::Parse($DateTimeText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        return "$($dateTimeOffset.UtcDateTime.ToString('yyyy-MM-dd HH:mm')) UTC"
    } catch {
        return $DateTimeText
    }
}

# Converts Graph expiration type names into readable labels.
function ConvertTo-AccessPackageExpirationTypeText {
    param([string]$Type)

    switch -Regex ($Type) {
        "noExpiration" { return "No expiration" }
        "afterDuration" { return "After duration" }
        "afterDateTime" { return "Fixed date" }
        default { return $Type }
    }
}

# Builds the display text for a policy expiration setting.
function Get-AccessPackagePolicyExpirationText {
    param($Policy)

    if ($null -eq $Policy -or -not $Policy.PSObject.Properties["expiration"] -or $null -eq $Policy.expiration) { return "No expiration" }
    $expiration = $Policy.expiration
    $type = [string](Get-AccessPackageObjectValue -Object $expiration -Names @("type", "expirationType"))
    $duration = [string](Get-AccessPackageObjectValue -Object $expiration -Names @("duration", "durationInDays"))
    $dateTime = [string](Get-AccessPackageObjectValue -Object $expiration -Names @("endDateTime"))
    if ($type -match "noExpiration") { return "No expiration" }
    if ($type -match "afterDuration" -and -not [string]::IsNullOrWhiteSpace($duration)) {
        return (ConvertTo-AccessPackageDurationText -Duration $duration)
    }
    if ($type -match "afterDateTime" -and -not [string]::IsNullOrWhiteSpace($dateTime)) {
        return (ConvertTo-AccessPackageDateTimeText -DateTimeText $dateTime)
    }
    if (-not [string]::IsNullOrWhiteSpace($duration)) { return (ConvertTo-AccessPackageDurationText -Duration $duration) }
    if (-not [string]::IsNullOrWhiteSpace($dateTime)) { return (ConvertTo-AccessPackageDateTimeText -DateTimeText $dateTime) }
    if (-not [string]::IsNullOrWhiteSpace($type)) { return (ConvertTo-AccessPackageExpirationTypeText -Type $type) }
    return "No expiration"
}

# Determines whether a policy has a meaningful expiration.
function Test-AccessPackagePolicyHasExpiration {
    param($Policy)

    $text = (Get-AccessPackagePolicyExpirationText -Policy $Policy).Trim().ToLowerInvariant()
    return -not ([string]::IsNullOrWhiteSpace($text) -or $text -eq "no expiration" -or $text -match "noexpiration")
}

# Finds user attributes in dynamic rules that may be user-controlled.
function Get-AccessPackageDangerousDynamicRuleAttributes {
    param(
        [string]$MembershipRule,
        [switch]$IncludeInviteLinkedAttributes
    )

    $matchedAttributes = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($MembershipRule) -or $MembershipRule -eq "-") {
        return @()
    }

    if ($MembershipRule -match "(?i)\buser\.preferredlanguage\b") { [void]$matchedAttributes.Add("user.preferredLanguage") }
    if ($MembershipRule -match "(?i)\buser\.mobilephone\b") { [void]$matchedAttributes.Add("user.mobilePhone") }
    if ($MembershipRule -match "(?i)\buser\.businessphones\b") { [void]$matchedAttributes.Add("user.businessPhones") }

    if ($IncludeInviteLinkedAttributes) {
        if ($MembershipRule -match "(?i)\buser\.userprincipalname\b") { [void]$matchedAttributes.Add("user.userPrincipalName") }
        if ($MembershipRule -match "(?i)\buser\.mail\b") { [void]$matchedAttributes.Add("user.mail") }
    }

    return @($matchedAttributes | Select-Object -Unique)
}

# Checks fallback resource markers for role or scope hints.
function Test-AccessPackageOriginMarker {
    param(
        [object[]]$Values,
        [string]$Marker
    )

    foreach ($value in @($Values)) {
        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($text -match "(?i)(^|[^A-Za-z])$([regex]::Escape($Marker))([^A-Za-z]|$)") { return $true }
    }
    return $false
}

# Classifies an access package resource role scope by resource type.
function Get-AccessPackageResourceType {
    param(
        [string]$OriginSystem,
        [object]$Role,
        [object]$Scope,
        [hashtable]$AppRoleReferenceCache = @{},
        [switch]$IndexLabel
    )

    $labels = @{
        Group            = "Group"
        Application      = "Application"
        ApiApp           = if ($IndexLabel) { "ApiApp" } else { "ApiAppPerms" }
        ApiDelegated     = if ($IndexLabel) { "ApiDelegated" } else { "ApiDelegatedPerms" }
        SharePoint       = "SharePoint"
        EntraRole        = if ($IndexLabel) { "EntraRole" } else { "Entra Role" }
        AzureRole        = if ($IndexLabel) { "AzureRole" } else { "Azure Role" }
        Other            = "Other"
    }

    if ($OriginSystem -eq "AadGroup") { return $labels.Group }
    if ($OriginSystem -eq "AadApplication") { return $labels.Application }
    if ($OriginSystem -eq "DirectoryRole") { return $labels.EntraRole }
    if ($OriginSystem -match "Azure|Arm|Management") { return $labels.AzureRole }
    if ($OriginSystem -eq "SharePointOnline") { return $labels.SharePoint }
    if ($OriginSystem -eq "OAuthApplication") {
        $permissionIds = [System.Collections.Generic.List[string]]::new()
        foreach ($name in @("originId", "id")) {
            if ($Role -and $Role.PSObject.Properties[$name] -and -not [string]::IsNullOrWhiteSpace([string]$Role.$name)) {
                [void]$permissionIds.Add([string]$Role.$name)
            }
        }

        $resourceIds = [System.Collections.Generic.List[string]]::new()
        foreach ($name in @("originId", "id")) {
            if ($Scope -and $Scope.PSObject.Properties[$name] -and -not [string]::IsNullOrWhiteSpace([string]$Scope.$name)) {
                [void]$resourceIds.Add([string]$Scope.$name)
            }
        }

        foreach ($permissionId in @($permissionIds)) {
            foreach ($resourceId in @($resourceIds)) {
                if ($AppRoleReferenceCache -and
                    $AppRoleReferenceCache.ContainsKey("ByAppId") -and
                    $AppRoleReferenceCache.ByAppId.ContainsKey($resourceId) -and
                    $AppRoleReferenceCache.ByAppId[$resourceId].ContainsKey($permissionId)) {
                    return $labels.ApiApp
                }
                if ($AppRoleReferenceCache -and
                    $AppRoleReferenceCache.ContainsKey("ByResourceId") -and
                    $AppRoleReferenceCache.ByResourceId.ContainsKey($resourceId) -and
                    $AppRoleReferenceCache.ByResourceId[$resourceId].ContainsKey($permissionId)) {
                    return $labels.ApiApp
                }
            }
        }

        $permissionId = [string](Get-AccessPackageObjectValue -Object $Role -Names @("originId", "id"))
        $permissionName = [string](Get-AccessPackageObjectValue -Object $Role -Names @("displayName"))
        if ($IndexLabel) {
            if (-not [string]::IsNullOrWhiteSpace($permissionId) -and $global:GLOBALApiPermissionCategorizationList -and $global:GLOBALApiPermissionCategorizationList.ContainsKey($permissionId)) {
                return $labels.ApiApp
            }
            if (-not [string]::IsNullOrWhiteSpace($permissionName) -and $global:GLOBALDelegatedApiPermissionCategorizationList -and $global:GLOBALDelegatedApiPermissionCategorizationList.ContainsKey($permissionName)) {
                return $labels.ApiDelegated
            }
        }

        $markers = [System.Collections.Generic.List[object]]::new()
        foreach ($object in @($Role, $Scope)) {
            if ($null -eq $object) { continue }
            foreach ($name in @("originId", "displayName", "id")) {
                if ($object.PSObject.Properties[$name]) {
                    [void]$markers.Add($object.$name)
                }
            }
        }
        if (Test-AccessPackageOriginMarker -Values $markers -Marker "Role") { return $labels.ApiApp }
        if (Test-AccessPackageOriginMarker -Values $markers -Marker "Scope") { return $labels.ApiDelegated }
        return $labels.ApiDelegated
    }
    return $labels.Other
}

# Builds lightweight resource type counts for target annotations.
function Get-AccessPackageResourceCounts {
    param(
        [object[]]$ResourceRoleScopes
    )

    $counts = [ordered]@{
        Resources    = 0
        Groups       = 0
        Applications = 0
        ApiApp       = 0
        ApiDelegated = 0
        SharePoint   = 0
        EntraRoles   = 0
        AzureRoles   = 0
    }

    foreach ($resourceRoleScope in @($ResourceRoleScopes)) {
        if ($null -eq $resourceRoleScope) { continue }
        $counts.Resources++
        $role = $resourceRoleScope.role
        $scope = $resourceRoleScope.scope
        $originSystem = [string](Get-AccessPackageObjectValue -Object $scope -Names @("originSystem"))
        if ([string]::IsNullOrWhiteSpace($originSystem)) { $originSystem = [string](Get-AccessPackageObjectValue -Object $role -Names @("originSystem")) }

        switch (Get-AccessPackageResourceType -OriginSystem $originSystem -Role $role -Scope $scope -IndexLabel) {
            "Group" { $counts.Groups++ }
            "Application" { $counts.Applications++ }
            "ApiApp" { $counts.ApiApp++ }
            "ApiDelegated" { $counts.ApiDelegated++ }
            "SharePoint" { $counts.SharePoint++ }
            "EntraRole" { $counts.EntraRoles++ }
            "AzureRole" { $counts.AzureRoles++ }
        }
    }

    return [pscustomobject]$counts
}

# Classifies a specific target or assignment target object.
function Get-AccessPackageTargetClassification {
    param($Target)

    if ($null -eq $Target) {
        return [pscustomobject]@{ Kind = "Unknown"; Id = ""; IdNames = @("objectId", "principalId", "targetId", "id") }
    }

    $odataType = if ($Target.PSObject.Properties["@odata.type"]) { [string]$Target.PSObject.Properties["@odata.type"].Value } else { "" }
    $targetType = [string](Get-AccessPackageObjectValue -Object $Target -Names @("subjectType", "type"))
    $kindText = "$odataType $targetType"
    $idNames = @("objectId", "principalId", "targetId", "id")
    $kind = "Unknown"

    if ($Target.PSObject.Properties["userId"] -or $kindText -match "(?i)singleUser|(^|[^A-Za-z])user([^A-Za-z]|$)") {
        $kind = "User"
        $idNames = @("userId", "objectId", "principalId", "targetId", "id")
    } elseif ($Target.PSObject.Properties["groupId"] -or $kindText -match "(?i)group") {
        $kind = "Group"
        $idNames = @("groupId", "objectId", "principalId", "targetId", "id")
    } elseif ($Target.PSObject.Properties["servicePrincipalId"] -or $kindText -match "(?i)servicePrincipal") {
        $kind = "ServicePrincipal"
        $idNames = @("servicePrincipalId", "objectId", "principalId", "targetId", "id")
    } elseif ($kindText -match "(?i)managedIdentity") {
        $kind = "ManagedIdentity"
        $idNames = @("servicePrincipalId", "objectId", "principalId", "targetId", "id")
    } elseif ($kindText -match "(?i)agentIdentity") {
        $kind = "AgentIdentity"
        $idNames = @("servicePrincipalId", "objectId", "principalId", "targetId", "id")
    } elseif ($kindText -match "(?i)blueprintPrincipal") {
        $kind = "AgentIdentityBlueprintPrincipal"
        $idNames = @("servicePrincipalId", "objectId", "principalId", "targetId", "id")
    } elseif ($kindText -match "(?i)connectedOrganization") {
        $kind = "ConnectedOrganization"
    } elseif ($kindText -match "(?i)externalSponsor") {
        $kind = "ExternalSponsor"
    } elseif ($kindText -match "(?i)internalSponsor") {
        $kind = "InternalSponsor"
    } elseif ($kindText -match "(?i)manager") {
        $kind = "Manager"
    }

    $objectId = [string](Get-AccessPackageObjectValue -Object $Target -Names $idNames)
    return [pscustomobject]@{
        Kind    = $kind
        Id      = $objectId
        IdNames = $idNames
    }
}

# Collects raw Access Package packages, assignments, and resources.
function Get-AccessPackagesRawData {
    ############################## Parameter section ########################
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AuthFlow,
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

    ############################## Script section ########################

    # Raw collection runs early so report tab availability can be decided before report navigation is initialized.
    $supportedFlows = @("BroCi", "BroCiManualCode", "BroCiToken", "ServicePrincipal")
    $Warnings = [System.Collections.Generic.List[string]]::new()

    if ($supportedFlows -notcontains $AuthFlow) {
        $Warnings.Add("Coverage gap: Access Packages were not assessed because Entitlement Management APIs are only queried with BroCi-based flows or ServicePrincipal flow.")
        Write-Log -Level Verbose -Message "[AccessPackages] Skipping Access Package collection for auth flow '$AuthFlow'."
        return [pscustomobject]@{
            IsAvailable                 = $false
            IsSkipped                   = $true
            AssignmentsAvailable        = $false
            ResourceRoleScopesAvailable = $false
            Warnings                    = @($Warnings)
            Packages                    = @()
            Assignments                 = @()
            PolicyEnabledById           = @{}
            ResourceRoleScopesByPackage = @{}
            SeparationOfDutiesAvailable = $false
            SeparationOfDutiesByPackage = @{}
        }
    }

    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) {
        RefreshAuthenticationMsGraph | Out-Null
    }

    $packages = @()
    $assignments = @()
    $assignmentsAvailable = $true
    $policyEnabledById = @{}
    $resourceRoleScopesByPackage = @{}
    $resourceRoleScopesAvailable = $true
    $separationOfDutiesByPackage = @{}
    $separationOfDutiesAvailable = $true
    $collectionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $scopeCollectionMode = "Expanded"
    $scopeFallbackRequests = 0
    $scopeFallbackFailures = 0
    $separationCollectionMode = "Expanded"

    ########################################## SECTION: DATACOLLECTION ##########################################

    try {
        Write-Host "[*] Enumerating Access Packages"
        $packages = @(Invoke-AccessPackageGraphGet -Uri "/identityGovernance/entitlementManagement/accessPackages" -QueryParameters @{
            '$select' = 'id,displayName,isHidden'
            # Do not expand incompatible relationships here. Graph can return
            # empty or missing expanded values even when direct endpoints have data;
            # they are collected reliably through the batch relationship requests below.
            '$expand' = 'catalog,assignmentPolicies,resourceRoleScopes($expand=role,scope)'
            '$top'    = [Math]::Min([Math]::Max($ApiTop, 1), 100)
        })
        Write-Host "[+] Got $(@($packages).Count) Access Packages"
        Write-Log -Level Debug -Message "[AccessPackages] Expanded access package collection returned $(@($packages).Count) package objects."
    } catch {
        if (Test-AccessPackageExpandedQueryFallbackEligible -ErrorRecord $_) {
            $scopeCollectionMode = "Fallback"
            $separationCollectionMode = "Batch"
            Write-Log -Level Debug -Message "[AccessPackages] Expanded collection query was rejected; retrying with the legacy collection shape. $($_.Exception.Message)"
            try {
                $packages = @(Invoke-AccessPackageGraphGet -Uri "/identityGovernance/entitlementManagement/accessPackages" -QueryParameters @{
                    '$select' = 'id,displayName,isHidden'
                    '$expand' = 'catalog,assignmentPolicies'
                    '$top'    = [Math]::Min([Math]::Max($ApiTop, 1), 100)
                })
                Write-Host "[+] Got $(@($packages).Count) Access Packages"
                Write-Log -Level Debug -Message "[AccessPackages] Legacy access package collection returned $(@($packages).Count) package objects."
            } catch {
                $Warnings.Add("Coverage gap: Access Packages could not be enumerated. $(Format-AccessPackageGraphError -ErrorRecord $_)")
                Write-Log -Level Debug -Message "[AccessPackages] Legacy access package collection failed: $($_.Exception.Message)"
                return [pscustomobject]@{
                    IsAvailable                 = $false
                    IsSkipped                   = $false
                    AssignmentsAvailable        = $false
                    ResourceRoleScopesAvailable = $false
                    Warnings                    = @($Warnings)
                    Packages                    = @()
                    Assignments                 = @()
                    PolicyEnabledById           = @{}
                    ResourceRoleScopesByPackage = @{}
                    SeparationOfDutiesAvailable = $false
                    SeparationOfDutiesByPackage = @{}
                }
            }
        } else {
            $Warnings.Add("Coverage gap: Access Packages could not be enumerated. $(Format-AccessPackageGraphError -ErrorRecord $_)")
            Write-Log -Level Debug -Message "[AccessPackages] Expanded access package collection failed: $($_.Exception.Message)"
            return [pscustomobject]@{
                IsAvailable                 = $false
                IsSkipped                   = $false
                AssignmentsAvailable        = $false
                ResourceRoleScopesAvailable = $false
                Warnings                    = @($Warnings)
                Packages                    = @()
                Assignments                 = @()
                PolicyEnabledById           = @{}
                ResourceRoleScopesByPackage = @{}
                SeparationOfDutiesAvailable = $false
                SeparationOfDutiesByPackage = @{}
            }
        }
    }

    if (@($packages).Count -eq 0) {
        Write-Log -Level Verbose -Message "[AccessPackages] No Access Packages found."
        return [pscustomobject]@{
            IsAvailable                 = $true
            IsSkipped                   = $false
            AssignmentsAvailable        = $true
            ResourceRoleScopesAvailable = $true
            Warnings                    = @($Warnings)
            Packages                    = @()
            Assignments                 = @()
            PolicyEnabledById           = @{}
            ResourceRoleScopesByPackage = @{}
            SeparationOfDutiesAvailable = $true
            SeparationOfDutiesByPackage = @{}
        }
    }

    try {
        Write-Host "[*] Enumerating Access Package policy enabled states"
        $policyStates = @(Invoke-AccessPackageGraphGet -ApiVersion "beta" -Uri "/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies" -QueryParameters @{
            '$select' = 'id,requestorSettings'
            '$top'    = $ApiTop
        })
        foreach ($policyState in $policyStates) {
            $policyId = [string](Get-AccessPackageObjectValue -Object $policyState -Names @("id"))
            if ([string]::IsNullOrWhiteSpace($policyId) -or -not $policyState.requestorSettings -or -not $policyState.requestorSettings.PSObject.Properties["acceptRequests"]) { continue }
            $policyEnabledById[$policyId] = Test-AccessPackageTruthyValue $policyState.requestorSettings.acceptRequests
        }
        Write-Host "[+] Got $($policyEnabledById.Count) Access Package policy enabled states"
        Write-Log -Level Debug -Message "[AccessPackages] Policy enabled-state collection returned $($policyEnabledById.Count) mapped policies."
    } catch {
        $Warnings.Add("Coverage gap: Access Package policy enabled states could not be enumerated from Microsoft Graph beta. $(Format-AccessPackageGraphError -ErrorRecord $_)")
        Write-Log -Level Debug -Message "[AccessPackages] Policy enabled-state collection failed: $($_.Exception.Message)"
        $policyEnabledById = @{}
    }

    try {
        Write-Host "[*] Enumerating Access Package assignments"
        $assignments = @(Invoke-AccessPackageGraphGet -Uri "/identityGovernance/entitlementManagement/assignments" -QueryParameters @{
            '$select' = 'id,state,status,expiredDateTime,schedule'
            '$expand' = 'target($select=id,objectId,displayName,principalName,email,subjectType),accessPackage($select=id,displayName),assignmentPolicy'
            '$top'    = $ApiTop
        })
        Write-Host "[+] Got $(@($assignments).Count) Access Package assignments"
        Write-Log -Level Debug -Message "[AccessPackages] Assignment collection returned $(@($assignments).Count) assignment objects."
    } catch {
        $Warnings.Add("Coverage gap: Access Package assignments could not be enumerated. $(Format-AccessPackageGraphError -ErrorRecord $_)")
        Write-Log -Level Debug -Message "[AccessPackages] Assignment collection failed: $($_.Exception.Message)"
        $assignments = @()
        $assignmentsAvailable = $false
    }

    Write-Host "[*] Enumerating Access Package resource role scopes"
    $packageScopeCounter = 0
    $resourceRoleScopeTotal = 0
    foreach ($package in @($packages)) {
        if (-not $package -or [string]::IsNullOrWhiteSpace([string]$package.id)) { continue }
        $packageScopeCounter++
        $expandedScopesProperty = $package.PSObject.Properties["resourceRoleScopes"]
        $expandedNextLinkProperty = $package.PSObject.Properties["resourceRoleScopes@odata.nextLink"]
        $expandedNextLink = if ($expandedNextLinkProperty) { [string]$expandedNextLinkProperty.Value } else { "" }
        $requiresFallback = ($null -eq $expandedScopesProperty -or -not [string]::IsNullOrWhiteSpace($expandedNextLink))

        if (-not $requiresFallback) {
            $resourceRoleScopes = @($expandedScopesProperty.Value)
            $resourceRoleScopesByPackage[[string]$package.id] = $resourceRoleScopes
            $resourceRoleScopeTotal += $resourceRoleScopes.Count
            Write-Log -Level Debug -Message "[AccessPackages] Package '$($package.displayName)' has $($resourceRoleScopes.Count) expanded resource role scope entries."
        } else {
            $scopeFallbackRequests++
            if ($scopeCollectionMode -eq "Expanded") { $scopeCollectionMode = "Mixed" }
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) {
                RefreshAuthenticationMsGraph | Out-Null
            }

            try {
                Write-Log -Level Verbose -Message "[AccessPackages] Collecting paged resource role scopes for package $packageScopeCounter of $(@($packages).Count): $($package.displayName)"
                $resourceRoleScopes = @(Invoke-AccessPackageGraphGet -Uri "/identityGovernance/entitlementManagement/accessPackages/$($package.id)/resourceRoleScopes" -QueryParameters @{
                    '$select' = 'id'
                    '$expand' = 'role,scope'
                    '$top'    = 100
                })
                $resourceRoleScopesByPackage[[string]$package.id] = $resourceRoleScopes
                $resourceRoleScopeTotal += $resourceRoleScopes.Count
                Write-Log -Level Debug -Message "[AccessPackages] Package '$($package.displayName)' has $($resourceRoleScopes.Count) fallback resource role scope entries."
            } catch {
                $scopeFallbackFailures++
                $resourceRoleScopesByPackage[[string]$package.id] = @()
                $resourceRoleScopesAvailable = $false
                $Warnings.Add("Coverage gap: Resource role scopes could not be enumerated for access package '$($package.displayName)'. $(Format-AccessPackageGraphError -ErrorRecord $_)")
                Write-Log -Level Debug -Message "[AccessPackages] Resource role scope collection failed for package '$($package.displayName)': $($_.Exception.Message)"
            }
        }

        foreach ($propertyName in @("resourceRoleScopes", "resourceRoleScopes@odata.context", "resourceRoleScopes@odata.nextLink")) {
            if ($package.PSObject.Properties[$propertyName]) {
                $package.PSObject.Properties.Remove($propertyName)
            }
        }
    }
    Write-Host "[+] Got $resourceRoleScopeTotal Access Package resource role scopes"

    Write-Host "[*] Enumerating Access Package separation-of-duties settings"
    $separationEntryTotal = 0
    $separationCollectionMode = "Batch"
    $separationBatchRequests = 0
    $separationSubrequests = 0
    $separationBatchFailures = 0
    $separationBatchResult = Invoke-AccessPackageSeparationBatch -Packages @($packages) -AccessToken $GLOBALMsGraphAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $separationSubrequests = @($separationBatchResult.Requests).Count
    $separationBatchRequests = [int]$separationBatchResult.BatchRequests

    $entriesByPackage = @{}
    foreach ($package in @($packages)) {
        if ($package -and -not [string]::IsNullOrWhiteSpace([string]$package.id)) {
            $entriesByPackage[[string]$package.id] = [System.Collections.Generic.List[object]]::new()
        }
    }
    $entryKeysByPackage = @{}
    foreach ($packageId in @($entriesByPackage.Keys)) {
        $entryKeysByPackage[$packageId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    foreach ($response in @($separationBatchResult.Responses)) {
        $responseId = [string]$response.id
        if (-not $separationBatchResult.RequestMap.ContainsKey($responseId)) { continue }
        $requestInfo = $separationBatchResult.RequestMap[$responseId]
        $packageId = [string]$requestInfo.PackageId
        if ([string]$response.status -notmatch '^2') {
            $separationBatchFailures++
            $separationOfDutiesAvailable = $false
            $package = @($packages | Where-Object { [string]$_.id -eq $packageId } | Select-Object -First 1)
            $packageName = if ($package) { [string]$package.displayName } else { $packageId }
            $relationshipName = if ($requestInfo.Type -eq 'Group') { 'incompatibleGroups' } else { 'incompatibleAccessPackages' }
            $Warnings.Add("Coverage gap: $relationshipName could not be enumerated for access package '$packageName'. $([string]$response.errorMessage)")
            continue
        }

        $relatedObjects = if ($response.response -and $response.response.value) { @($response.response.value) } else { @() }
        foreach ($relatedObject in $relatedObjects) {
            if ($null -eq $relatedObject) { continue }
            $relatedId = [string](Get-AccessPackageObjectValue -Object $relatedObject -Names @('id'))
            if ([string]::IsNullOrWhiteSpace($relatedId)) { continue }
            $entryKey = "$($requestInfo.Type)|$relatedId"
            if (-not $entryKeysByPackage[$packageId].Add($entryKey)) { continue }
            $relatedDisplayName = [string](Get-AccessPackageObjectValue -Object $relatedObject -Names @('displayName', 'id'))
            if ([string]::IsNullOrWhiteSpace($relatedDisplayName)) { $relatedDisplayName = $relatedId }
            [void]$entriesByPackage[$packageId].Add([pscustomobject]@{
                Id          = $relatedId
                DisplayName = $relatedDisplayName
                Type        = [string]$requestInfo.Type
            })
        }
    }

    foreach ($packageId in @($entriesByPackage.Keys)) {
        $separationOfDutiesByPackage[$packageId] = @($entriesByPackage[$packageId] | Sort-Object Type, DisplayName)
        $separationEntryTotal += @($entriesByPackage[$packageId]).Count
    }
    Write-Host "[+] Got $separationEntryTotal Access Package separation-of-duties entries"
    $collectionStopwatch.Stop()
    Write-Log -Level Debug -Message "[AccessPackages] Collection metrics: ScopeMode=$scopeCollectionMode, SeparationMode=$separationCollectionMode, Packages=$(@($packages).Count), Assignments=$(@($assignments).Count), ResourceRoleScopes=$resourceRoleScopeTotal, SeparationEntries=$separationEntryTotal, ScopeFallbackRequests=$scopeFallbackRequests, ScopeFallbackFailures=$scopeFallbackFailures, SeparationSubrequests=$separationSubrequests, SeparationBatchRequests=$separationBatchRequests, SeparationBatchFailures=$separationBatchFailures, ElapsedMs=$($collectionStopwatch.ElapsedMilliseconds)"
    if ($Warnings.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AccessPackages] Raw collection completed with $($Warnings.Count) warning(s): $($Warnings -join ' / ')"
    }
    return [pscustomobject]@{
        IsAvailable                 = $true
        IsSkipped                   = $false
        AssignmentsAvailable        = $assignmentsAvailable
        ResourceRoleScopesAvailable = $resourceRoleScopesAvailable
        SeparationOfDutiesAvailable = $separationOfDutiesAvailable
        Warnings                    = @($Warnings)
        Packages                    = @($packages)
        Assignments                 = @($assignments)
        PolicyEnabledById           = $policyEnabledById
        ResourceRoleScopesByPackage = $resourceRoleScopesByPackage
        SeparationOfDutiesByPackage = $separationOfDutiesByPackage
    }
}

# Builds a lookup of policies that target specific users or groups.
function New-AccessPackageSpecificTargetIndex {
    ############################## Parameter section ########################
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$RawAccessPackages,
        [Parameter(Mandatory = $true)][ValidateSet("Group", "User")][string]$TargetKind
    )

    ############################## Script section ########################

    Write-Log -Level Verbose -Message "[AccessPackages] Building $TargetKind specific target index."
    $index = @{}
    $dedupe = [System.Collections.Generic.HashSet[string]]::new()

    if ($null -eq $RawAccessPackages -or -not $RawAccessPackages.PSObject.Properties["Packages"]) {
        return $index
    }

    foreach ($package in @($RawAccessPackages.Packages)) {
        if ($null -eq $package) { continue }
        $packageId = [string](Get-AccessPackageObjectValue -Object $package -Names @("id"))
        if ([string]::IsNullOrWhiteSpace($packageId)) { continue }
        $packageName = [string](Get-AccessPackageObjectValue -Object $package -Names @("displayName", "id"))
        if ([string]::IsNullOrWhiteSpace($packageName)) { $packageName = $packageId }
        $resourceRoleScopesByPackage = if ($RawAccessPackages.PSObject.Properties["ResourceRoleScopesByPackage"] -and $null -ne $RawAccessPackages.ResourceRoleScopesByPackage) { $RawAccessPackages.ResourceRoleScopesByPackage } else { @{} }
        $resourceRoleScopes = if ($resourceRoleScopesByPackage.ContainsKey($packageId)) { @($resourceRoleScopesByPackage[$packageId]) } else { @() }
        $resourceCounts = Get-AccessPackageResourceCounts -ResourceRoleScopes $resourceRoleScopes

        foreach ($policy in @($package.assignmentPolicies)) {
            if ($null -eq $policy) { continue }
            $policyId = [string](Get-AccessPackageObjectValue -Object $policy -Names @("id"))
            $policyName = [string](Get-AccessPackageObjectValue -Object $policy -Names @("displayName", "id"))
            if ([string]::IsNullOrWhiteSpace($policyName)) { $policyName = if ($policyId) { $policyId } else { "Unnamed Policy" } }

            foreach ($target in @($policy.specificAllowedTargets)) {
                if ($null -eq $target) { continue }
                $membershipRule = [string](Get-AccessPackageObjectValue -Object $target -Names @("membershipRule"))
                if (-not [string]::IsNullOrWhiteSpace($membershipRule)) { continue }
                $targetClassification = Get-AccessPackageTargetClassification -Target $target
                if ($targetClassification.Kind -ne $TargetKind) { continue }
                $targetId = [string]$targetClassification.Id
                if ([string]::IsNullOrWhiteSpace($targetId)) { continue }

                $dedupeKey = "$targetId|$packageId|$policyId"
                if (-not $dedupe.Add($dedupeKey)) { continue }
                if (-not $index.ContainsKey($targetId)) { $index[$targetId] = [System.Collections.Generic.List[object]]::new() }

                $index[$targetId].Add([pscustomobject]@{
                    TargetId     = $targetId
                    GroupId      = if ($TargetKind -eq "Group") { $targetId } else { $null }
                    UserId       = if ($TargetKind -eq "User") { $targetId } else { $null }
                    PackageId    = $packageId
                    Package      = $packageName
                    PolicyId     = $policyId
                    Policy       = $policyName
                    SelfAdd      = Test-AccessPackagePolicyRequestorSetting -Policy $policy -Name "enableTargetsToSelfAddAccess"
                    Approval     = Test-AccessPackagePolicyApprovalRequired -Policy $policy
                    Resources    = $resourceCounts.Resources
                    Groups       = $resourceCounts.Groups
                    Applications = $resourceCounts.Applications
                    ApiApp       = $resourceCounts.ApiApp
                    ApiDelegated = $resourceCounts.ApiDelegated
                    SharePoint   = $resourceCounts.SharePoint
                    EntraRoles   = $resourceCounts.EntraRoles
                    AzureRoles   = $resourceCounts.AzureRoles
                })
            }
        }
    }

    $targetReferenceCount = 0
    foreach ($bucket in @($index.Values)) {
        $targetReferenceCount += @($bucket).Count
    }
    Write-Log -Level Debug -Message "[AccessPackages] Built $TargetKind specific target index with $($index.Count) target object(s) and $targetReferenceCount policy reference(s)."

    return $index
}

# Builds the group-specific Access Package target index.
function New-AccessPackageGroupSpecificTargetIndex {
    ############################## Parameter section ########################
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$RawAccessPackages
    )

    return (New-AccessPackageSpecificTargetIndex -RawAccessPackages $RawAccessPackages -TargetKind "Group")
}

# Builds the user-specific Access Package target index.
function New-AccessPackageUserSpecificTargetIndex {
    ############################## Parameter section ########################
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$RawAccessPackages
    )

    return (New-AccessPackageSpecificTargetIndex -RawAccessPackages $RawAccessPackages -TargetKind "User")
}

# Produces a stable comparison key while preserving whitespace inside quoted rule values.
function ConvertTo-AccessPackageMembershipRuleKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$MembershipRule
    )

    if ([string]::IsNullOrWhiteSpace($MembershipRule)) { return "" }

    $builder = [System.Text.StringBuilder]::new()
    $insideQuotes = $false
    $escaped = $false
    foreach ($character in $MembershipRule.Trim().ToCharArray()) {
        if ($character -eq '"' -and -not $escaped) {
            $insideQuotes = -not $insideQuotes
            [void]$builder.Append($character)
            $escaped = $false
            continue
        }
        if (-not $insideQuotes -and [char]::IsWhiteSpace($character)) {
            $escaped = $false
            continue
        }
        [void]$builder.Append($character)
        $escaped = ($insideQuotes -and $character -eq '\' -and -not $escaped)
        if ($character -ne '\') { $escaped = $false }
    }
    return $builder.ToString()
}

# Builds a lightweight membership-rule lookup for automatic Access Package policies.
function New-AccessPackageAutoAssignmentPolicyIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$RawAccessPackages
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $index = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([System.StringComparer]::Ordinal)
    if ($null -eq $RawAccessPackages -or -not $RawAccessPackages.PSObject.Properties["Packages"]) {
        return $index
    }

    $scopesAvailable = (-not $RawAccessPackages.PSObject.Properties["ResourceRoleScopesAvailable"] -or [bool]$RawAccessPackages.ResourceRoleScopesAvailable)
    $scopesByPackage = if ($RawAccessPackages.PSObject.Properties["ResourceRoleScopesByPackage"] -and $null -ne $RawAccessPackages.ResourceRoleScopesByPackage) {
        $RawAccessPackages.ResourceRoleScopesByPackage
    } else {
        @{}
    }
    $dedupe = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $policyCount = 0

    foreach ($package in @($RawAccessPackages.Packages)) {
        if ($null -eq $package) { continue }
        $packageId = [string](Get-AccessPackageObjectValue -Object $package -Names @("id"))
        if ([string]::IsNullOrWhiteSpace($packageId)) { continue }
        $packageName = [string](Get-AccessPackageObjectValue -Object $package -Names @("displayName", "id"))
        if ([string]::IsNullOrWhiteSpace($packageName)) { $packageName = $packageId }

        $configuredResources = "-"
        $configuredRoles = "-"
        if ($scopesAvailable) {
            $resourceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $roleKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $roleScopes = if ($scopesByPackage -is [System.Collections.IDictionary] -and $scopesByPackage.Contains($packageId)) { @($scopesByPackage[$packageId]) } else { @() }
            foreach ($roleScope in $roleScopes) {
                if ($null -eq $roleScope) { continue }
                $scope = $roleScope.scope
                $role = $roleScope.role
                $originSystem = [string](Get-AccessPackageObjectValue -Object $scope -Names @("originSystem"))
                if ([string]::IsNullOrWhiteSpace($originSystem)) { $originSystem = [string](Get-AccessPackageObjectValue -Object $role -Names @("originSystem")) }
                $originId = [string](Get-AccessPackageObjectValue -Object $scope -Names @("originId", "id"))
                if ([string]::IsNullOrWhiteSpace($originId)) { $originId = [string](Get-AccessPackageObjectValue -Object $roleScope -Names @("id")) }
                $roleId = [string](Get-AccessPackageObjectValue -Object $role -Names @("originId", "id", "displayName"))
                if ([string]::IsNullOrWhiteSpace($roleId)) { $roleId = [string](Get-AccessPackageObjectValue -Object $roleScope -Names @("id")) }
                $resourceKey = "$originSystem|$originId"
                [void]$resourceKeys.Add($resourceKey)
                [void]$roleKeys.Add("$resourceKey|$roleId")
            }
            $configuredResources = $resourceKeys.Count
            $configuredRoles = $roleKeys.Count
        }

        foreach ($policy in @($package.assignmentPolicies)) {
            if ($null -eq $policy -or -not $policy.PSObject.Properties["automaticRequestSettings"] -or $null -eq $policy.automaticRequestSettings) { continue }
            $policyId = [string](Get-AccessPackageObjectValue -Object $policy -Names @("id"))
            $policyName = [string](Get-AccessPackageObjectValue -Object $policy -Names @("displayName", "id"))
            if ([string]::IsNullOrWhiteSpace($policyName)) { $policyName = if ($policyId) { $policyId } else { "Unnamed Policy" } }

            foreach ($target in @($policy.specificAllowedTargets)) {
                $membershipRule = [string](Get-AccessPackageObjectValue -Object $target -Names @("membershipRule"))
                $ruleKey = ConvertTo-AccessPackageMembershipRuleKey -MembershipRule $membershipRule
                if ([string]::IsNullOrWhiteSpace($ruleKey)) { continue }
                $dedupeKey = "$packageId|$policyId|$ruleKey"
                if (-not $dedupe.Add($dedupeKey)) { continue }
                if (-not $index.ContainsKey($ruleKey)) { $index[$ruleKey] = [System.Collections.Generic.List[object]]::new() }
                [void]$index[$ruleKey].Add([pscustomobject]@{
                    PackageId          = $packageId
                    Package            = $packageName
                    PolicyId           = $policyId
                    Policy             = $policyName
                    MembershipRule     = $membershipRule
                    ConfiguredResources = $configuredResources
                    ConfiguredRoles     = $configuredRoles
                })
                $policyCount++
            }
        }
    }

    $timer.Stop()
    Write-Log -Level Debug -Message ("[AccessPackages] Built automatic-assignment rule index with {0} rule key(s) and {1} policy target(s) in {2:N3} s." -f $index.Count, $policyCount, $timer.Elapsed.TotalSeconds)
    return $index
}

# Processes Access Package data into reports and normalized policy rows.
function Invoke-CheckAccessPackages {
    ############################## Parameter section ########################
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$OutputFolder = ".",
        [Parameter(Mandatory = $true)][Object]$CurrentTenant,
        [Parameter(Mandatory = $true)][string]$StartTimestamp,
        [Parameter(Mandatory = $true)][object]$RawAccessPackages,
        [Parameter(Mandatory = $false)][hashtable]$AllUsersBasicHT = @{},
        [Parameter(Mandatory = $false)][hashtable]$AllGroupsDetails = @{},
        [Parameter(Mandatory = $false)][hashtable]$TenantRoleAssignments = @{},
        [Parameter(Mandatory = $false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory = $false)][hashtable]$EnterpriseApps = @{},
        [Parameter(Mandatory = $false)][hashtable]$ManagedIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentityBlueprintsPrincipals = @{},
        [Parameter(Mandatory = $false)][switch]$Csv = $false,
        [Parameter(Mandatory = $false)][switch]$ExportDataJson = $false
    )

    ############################## Function section ########################

    # Formats approver collections for policy detail output.
    function Format-AccessPackageApproverList {
        param($Approvers)

        $approverTexts = [System.Collections.Generic.List[string]]::new()
        foreach ($approver in @($Approvers)) {
            if ($null -eq $approver) { continue }

            $odataType = if ($approver.PSObject.Properties["@odata.type"]) { [string]$approver.PSObject.Properties["@odata.type"].Value } else { "" }
            switch ($odataType) {
                "#microsoft.graph.requestorManager" {
                    $managerLevel = [string](Get-AccessPackageObjectValue -Object $approver -Names @("managerLevel"))
                    if ([string]::IsNullOrWhiteSpace($managerLevel)) {
                        [void]$approverTexts.Add("Requestor Manager")
                    } else {
                        [void]$approverTexts.Add("Requestor Manager (level $managerLevel)")
                    }
                    continue
                }
                "#microsoft.graph.externalSponsors" {
                    [void]$approverTexts.Add("External Sponsors")
                    continue
                }
                "#microsoft.graph.internalSponsors" {
                    [void]$approverTexts.Add("Internal Sponsors")
                    continue
                }
                default {
                    $targetInfo = Get-AccessPackageTargetInfo -Target $approver
                    if ($targetInfo -and -not [string]::IsNullOrWhiteSpace([string]$targetInfo.Id)) {
                        [void]$approverTexts.Add([string]$targetInfo.Link)
                        continue
                    }

                    $description = [string](Get-AccessPackageObjectValue -Object $approver -Names @("description", "displayName", "id", "userId", "groupId", "servicePrincipalId"))
                    if ([string]::IsNullOrWhiteSpace($description)) {
                        $description = if ([string]::IsNullOrWhiteSpace($odataType)) { "Unknown approver" } else { $odataType }
                    }
                    if (-not [string]::IsNullOrWhiteSpace($odataType)) {
                        $typeLabel = $odataType -replace "^#microsoft\.graph\.", ""
                        [void]$approverTexts.Add("$(ConvertTo-EntraFalconHtmlText $description -DefaultValue '-') ($(ConvertTo-EntraFalconHtmlText $typeLabel -DefaultValue '-'))")
                    } else {
                        [void]$approverTexts.Add((ConvertTo-EntraFalconHtmlText $description -DefaultValue "-"))
                    }
                }
            }
        }

        if ($approverTexts.Count -eq 0) { return "-" }
        return ($approverTexts -join ", ")
    }

    # Converts approval settings into reportable approval rows.
    function Get-AccessPackageApprovalRows {
        param(
            [object]$Policy
        )

        if ($null -eq $Policy -or -not $Policy.PSObject.Properties["requestApprovalSettings"] -or $null -eq $Policy.requestApprovalSettings) {
            return @()
        }

        $settings = $Policy.requestApprovalSettings
        $approvalForAdd = $false
        foreach ($name in @("isApprovalRequiredForAdd", "approvalRequiredForAdd", "approvalRequired", "isApprovalRequired")) {
            if ($settings.PSObject.Properties[$name] -and (Test-AccessPackageTruthyValue $settings.$name)) { $approvalForAdd = $true }
        }
        $approvalForUpdate = $false
        foreach ($name in @("isApprovalRequiredForUpdate", "isApprovalRequiredForUpdateAccess")) {
            if ($settings.PSObject.Properties[$name] -and (Test-AccessPackageTruthyValue $settings.$name)) { $approvalForUpdate = $true }
        }
        $stages = @()
        foreach ($stagePropertyName in @("stages", "approvalStages")) {
            if ($settings.PSObject.Properties[$stagePropertyName] -and $null -ne $settings.$stagePropertyName) {
                $stages = @($settings.$stagePropertyName)
                break
            }
        }

        $stageHasApprovalData = $false
        foreach ($stage in @($stages)) {
            if ($null -eq $stage) { continue }
            foreach ($name in @("primaryApprovers", "fallbackPrimaryApprovers", "escalationApprovers", "fallbackEscalationApprovers")) {
                if ($stage.PSObject.Properties[$name] -and @($stage.$name).Count -gt 0) { $stageHasApprovalData = $true }
            }
            if ($stage.PSObject.Properties["isEscalationEnabled"] -and (Test-AccessPackageTruthyValue $stage.isEscalationEnabled)) { $stageHasApprovalData = $true }
        }

        if (-not $approvalForAdd -and -not $approvalForUpdate -and -not $stageHasApprovalData) {
            return @()
        }

        if ($stages.Count -eq 0) {
            $stages = @($null)
        }

        $stageNumber = 0
        foreach ($stage in @($stages)) {
            $stageNumber++
            $durationBeforeEscalation = if ($stage -and $stage.PSObject.Properties["durationBeforeEscalation"]) {
                ConvertTo-AccessPackageDurationText -Duration ([string]$stage.durationBeforeEscalation)
            } else {
                "-"
            }

            [pscustomobject]@{
                Stage                        = $stageNumber
                ApprovalForAdd               = $approvalForAdd
                ApprovalForUpdate            = $approvalForUpdate
                Escalation                   = if ($stage -and $stage.PSObject.Properties["isEscalationEnabled"]) { Test-AccessPackageTruthyValue $stage.isEscalationEnabled } else { $false }
                EscalationAfter              = $durationBeforeEscalation
                ApproverVisibility           = if ($stage -and $stage.PSObject.Properties["approverInformationVisibility"] -and -not [string]::IsNullOrWhiteSpace([string]$stage.approverInformationVisibility)) { [string]$stage.approverInformationVisibility } else { "-" }
                PrimaryApprovers             = if ($stage) { Format-AccessPackageApproverList -Approvers $stage.primaryApprovers } else { "-" }
                FallbackPrimaryApprovers     = if ($stage) { Format-AccessPackageApproverList -Approvers $stage.fallbackPrimaryApprovers } else { "-" }
                EscalationApprovers          = if ($stage) { Format-AccessPackageApproverList -Approvers $stage.escalationApprovers } else { "-" }
                FallbackEscalationApprovers  = if ($stage) { Format-AccessPackageApproverList -Approvers $stage.fallbackEscalationApprovers } else { "-" }
            }
        }
    }

    # Detects whether a policy has access reviews enabled.
    function Test-AccessPackagePolicyHasReview {
        param($Policy)
        if ($null -eq $Policy) { return $false }
        foreach ($settingsName in @("reviewSettings", "accessReviewSettings")) {
            if ($Policy.PSObject.Properties[$settingsName]) {
                $settings = $Policy.$settingsName
                if ($null -eq $settings) { continue }
                foreach ($name in @("isEnabled", "enabled", "isAccessReviewRequired")) {
                    if ($settings.PSObject.Properties[$name] -and (Test-AccessPackageTruthyValue $settings.$name)) { return $true }
                }
            }
        }
        return $false
    }

    # Extracts automatic assignment rule text from policy targets.
    function Get-AccessPackageAutoAssignmentRuleText {
        param($Policy)

        if ($null -eq $Policy -or -not $Policy.PSObject.Properties["automaticRequestSettings"] -or $null -eq $Policy.automaticRequestSettings) {
            return "-"
        }

        $ruleParts = [System.Collections.Generic.List[string]]::new()
        foreach ($target in @($Policy.specificAllowedTargets)) {
            if ($null -eq $target) { continue }
            $membershipRule = [string](Get-AccessPackageObjectValue -Object $target -Names @("membershipRule"))
            if (-not [string]::IsNullOrWhiteSpace($membershipRule)) {
                [void]$ruleParts.Add($membershipRule)
            }
        }

        if ($ruleParts.Count -eq 0) { return "Enabled" }
        return ($ruleParts -join " || ")
    }

    # Detects broad policy target scopes.
    function Test-AccessPackagePolicyBroadScope {
        param($Policy)
        if ($null -eq $Policy) { return $false }
        $scope = ([string]$Policy.allowedTargetScope).Trim()
        return @(
            "allMemberUsers",
            "allDirectoryUsers",
            "allDirectoryServicePrincipals",
            "allConfiguredConnectedOrganizationUsers",
            "allConfiguredConnectedOrganizationSubjects",
            "allExternalUsers",
            "allDirectoryAgentIdentities"
        ) -contains $scope
    }

    # Converts allowed target scope values into readable labels.
    function Format-AccessPackageAllowedTargetScope {
        param(
            [string]$AllowedTargetScope
        )

        if ([string]::IsNullOrWhiteSpace($AllowedTargetScope)) { return "-" }

        switch ($AllowedTargetScope.Trim()) {
            "notSpecified" { return "Assignment Only" }
            "specificDirectoryUsers" { return "Specific Users" }
            "specificConnectedOrganizationUsers" { return "Specific External Orgs" }
            "specificDirectoryServicePrincipals" { return "Specific Service Principals" }
            "allMemberUsers" { return "All Internal Users" }
            "allDirectoryUsers" { return "All Users" }
            "allDirectoryServicePrincipals" { return "All Service Principals" }
            "allConfiguredConnectedOrganizationUsers" { return "All External Orgs" }
            "allConfiguredConnectedOrganizationSubjects" { return "All External Orgs" }
            "allExternalUsers" { return "All External Users" }
            "allDirectoryAgentIdentities" { return "All Agent Identities" }
            default { return $AllowedTargetScope }
        }
    }

    # Normalizes role tier values into display labels.
    function ConvertTo-AccessPackageTierLabel {
        param($Tier)
        switch ("$Tier") {
            "0" { return "Tier-0" }
            "1" { return "Tier-1" }
            "2" { return "Tier-2" }
            "3" { return "Tier-3" }
            "?" { return "Uncategorized" }
            "Tier-0" { return "Tier-0" }
            "Tier-1" { return "Tier-1" }
            "Tier-2" { return "Tier-2" }
            "Tier-3" { return "Tier-3" }
            "Uncategorized" { return "Uncategorized" }
            default { return "-" }
        }
    }

    # Scores direct Entra role resources by tier.
    function Get-AccessPackageEntraRoleImpact {
        param(
            [string]$TierLabel,
            [bool]$IsPrivileged
        )

        switch ($TierLabel) {
            "Tier-0" { return $GLOBALImpactScore["EntraRoleTier0"] }
            "Tier-1" { return $GLOBALImpactScore["EntraRoleTier1"] }
            "Tier-2" { return $GLOBALImpactScore["EntraRoleTier2"] }
            "Uncategorized" {
                if ($IsPrivileged) { return $GLOBALImpactScore["EntraRoleTier?Privileged"] }
                return $GLOBALImpactScore["EntraRoleTier?"]
            }
            default { return 0 }
        }
    }

    # Scores direct Azure role resources by tier.
    function Get-AccessPackageAzureRoleImpact {
        param([string]$TierLabel)

        switch ($TierLabel) {
            "Tier-0" { return $GLOBALImpactScore["AzureRoleTier0"] }
            "Tier-1" { return $GLOBALImpactScore["AzureRoleTier1"] }
            "Tier-2" { return $GLOBALImpactScore["AzureRoleTier2"] }
            "Tier-3" { return $GLOBALImpactScore["AzureRoleTier3"] }
            "Uncategorized" { return $GLOBALImpactScore["AzureRoleTier?"] }
            default { return 0 }
        }
    }

    # Scores SharePoint access by granted role level.
    function Get-AccessPackageSharePointImpact {
        param([string]$RoleName)

        if ([string]::IsNullOrWhiteSpace($RoleName)) { return 1 }
        if ($RoleName -match "(?i)(^|[^a-z0-9])(owner|owners|full\s*control)([^a-z0-9]|$)") { return 3 }
        if ($RoleName -match "(?i)(^|[^a-z0-9])(member|members|edit|contribute|write)([^a-z0-9]|$)") { return 2 }
        if ($RoleName -match "(?i)(^|[^a-z0-9])(visitor|visitors|read|view)([^a-z0-9]|$)") { return 1 }
        return 1
    }

    # Extracts an Azure role definition ID from a resource ID.
    function Get-AccessPackageAzureRoleDefinitionId {
        param([string]$OriginId)

        if ([string]::IsNullOrWhiteSpace($OriginId)) { return "" }
        $roleDefinitionMatch = [regex]::Match($OriginId, "/roleDefinitions/([^/]+)$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($roleDefinitionMatch.Success) { return $roleDefinitionMatch.Groups[1].Value }
        return ($OriginId.TrimEnd("/") -split "/")[-1]
    }

    # Resolves target display names, links, and object kind.
    function Get-AccessPackageTargetInfo {
        param($Target)
        $displayName = [string](Get-AccessPackageObjectValue -Object $Target -Names @("displayName", "principalName", "email", "description"))
        $targetClassification = Get-AccessPackageTargetClassification -Target $Target
        $objectKind = [string]$targetClassification.Kind
        $objectId = [string]$targetClassification.Id
        $targetReport = $null
        $protected = "-"

        if (-not [string]::IsNullOrWhiteSpace($objectId)) {
            if ($AllUsersBasicHT.ContainsKey($objectId)) {
                $objectKind = "User"
                $targetReport = "Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                $displayName = [string]$AllUsersBasicHT[$objectId].UserPrincipalName
            } elseif ($AllGroupsDetails.ContainsKey($objectId)) {
                $objectKind = "Group"
                $targetReport = "Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                $groupDetails = $AllGroupsDetails[$objectId]
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$groupDetails.DisplayName }
                if ($groupDetails.PSObject.Properties["Protected"] -and $null -ne $groupDetails.Protected) { $protected = $groupDetails.Protected }
            } elseif ($ManagedIdentities.ContainsKey($objectId)) {
                $objectKind = "ManagedIdentity"
                $targetReport = "ManagedIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$ManagedIdentities[$objectId].DisplayName }
            } elseif ($AgentIdentities.ContainsKey($objectId)) {
                $objectKind = "AgentIdentity"
                $targetReport = "AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$AgentIdentities[$objectId].DisplayName }
            } elseif ($AgentIdentityBlueprintsPrincipals.ContainsKey($objectId)) {
                $objectKind = "AgentIdentityBlueprintPrincipal"
                $targetReport = "AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$AgentIdentityBlueprintsPrincipals[$objectId].DisplayName }
            } elseif ($EnterpriseApps.ContainsKey($objectId)) {
                $objectKind = "ServicePrincipal"
                $targetReport = "EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$objectId"
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$EnterpriseApps[$objectId].DisplayName }
            }
        }

        if ($objectKind -eq "User" -and (-not $AllUsersBasicHT.ContainsKey($objectId) -or [string]::IsNullOrWhiteSpace($displayName))) {
            $displayName = if ($objectId) { $objectId } else { "-" }
            $targetReport = $null
        }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = if ($objectId) { $objectId } else { "-" } }
        $displayNameEncoded = ConvertTo-EntraFalconHtmlText $displayName -DefaultValue "-"
        $displayNameLink = if ($targetReport) { "<a href=$targetReport>$displayNameEncoded</a>" } else { $displayNameEncoded }

        return [pscustomobject]@{
            Id          = $objectId
            DisplayName = $displayName
            Link        = $displayNameLink
            Kind        = $objectKind
            Report      = $targetReport
            Protected   = $protected
        }
    }

    # Builds a detail row for a specific allowed target.
    function New-AccessPackageSpecificTargetRow {
        param(
            [object]$Policy,
            [object]$Target
        )

        $policyName = [string](Get-AccessPackageObjectValue -Object $Policy -Names @("displayName", "id"))
        if ([string]::IsNullOrWhiteSpace($policyName)) { $policyName = "-" }

        $targetInfo = Get-AccessPackageTargetInfo -Target $Target
        $membershipRule = [string](Get-AccessPackageObjectValue -Object $Target -Names @("membershipRule"))
        if ([string]::IsNullOrWhiteSpace($membershipRule)) { $membershipRule = "-" }

        [pscustomobject]@{
            Policy         = ConvertTo-EntraFalconHtmlText $policyName -DefaultValue "-"
            Target         = $targetInfo.Link
            TargetType     = $targetInfo.Kind
            Protected      = $targetInfo.Protected
            TargetId       = if ([string]::IsNullOrWhiteSpace($targetInfo.Id)) { "-" } else { $targetInfo.Id }
            MembershipRule = ConvertTo-EntraFalconHtmlText $membershipRule -DefaultValue "-"
            IsAutoAssignmentRuleTarget = ($membershipRule -ne "-")
        }
    }

    # Resolves resource impact, role counts, tiers, and report links.
    function Get-AccessPackageResourceInfo {
        param($ResourceRoleScope)
        $role = $ResourceRoleScope.role
        $scope = $ResourceRoleScope.scope
        $originSystem = [string](Get-AccessPackageObjectValue -Object $scope -Names @("originSystem"))
        if ([string]::IsNullOrWhiteSpace($originSystem)) { $originSystem = [string](Get-AccessPackageObjectValue -Object $role -Names @("originSystem")) }
        $originId = [string](Get-AccessPackageObjectValue -Object $scope -Names @("originId", "id"))
        $resourceName = [string](Get-AccessPackageObjectValue -Object $scope -Names @("displayName", "description"))
        $roleName = [string](Get-AccessPackageObjectValue -Object $role -Names @("displayName", "originId", "id"))
        $roleDescription = [string](Get-AccessPackageObjectValue -Object $role -Names @("description"))
        $resourceReport = $null
        $impact = 0
        $entraTier = "-"
        $azureTier = "-"
        $entraRoles = 0
        $azureRoles = 0
        $apiPermissionCategory = "-"
        $resourceType = Get-AccessPackageResourceType -OriginSystem $originSystem -Role $role -Scope $scope -AppRoleReferenceCache $AppRoleReferenceCache

        if ($originSystem -eq "AadGroup" -and -not [string]::IsNullOrWhiteSpace($originId) -and $AllGroupsDetails.ContainsKey($originId)) {
            $group = $AllGroupsDetails[$originId]
            $resourceName = [string]$group.DisplayName
            $resourceReport = "Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$originId"
            $impact = if ($null -ne $group.Impact) { [double]$group.Impact } else { 0 }
            $entraRoles = Get-AccessPackageIntValue -Value $group.EntraRoles
            $azureRoles = Get-AccessPackageIntValue -Value $group.AzureRoles
            if ($entraRoles -gt 0) {
                $entraTier = if ([string]::IsNullOrWhiteSpace([string]$group.EntraMaxTier)) { "-" } else { [string]$group.EntraMaxTier }
            }
            if ($azureRoles -gt 0) {
                $azureTier = if ([string]::IsNullOrWhiteSpace([string]$group.AzureMaxTier)) { "-" } else { [string]$group.AzureMaxTier }
            } elseif ([string]$group.AzureRoles -eq "?" -or [string]$group.AzureMaxTier -eq "?") {
                $azureTier = "?"
            }
        } elseif ($originSystem -eq "AadApplication" -and -not [string]::IsNullOrWhiteSpace($originId)) {
            $app = $null
            $appImpact = 0
            if ($EnterpriseApps.ContainsKey($originId)) {
                $app = $EnterpriseApps[$originId]
            } else {
                foreach ($candidate in $EnterpriseApps.Values) {
                    if ($candidate.AppId -eq $originId) { $app = $candidate; break }
                }
            }
            if ($app) {
                $resourceName = [string]$app.DisplayName
                $resourceReport = "EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)"
                $appImpact = if ($null -ne $app.Impact) { [double]$app.Impact } else { 0 }
            }
            $impact = Get-AppRoleAssignmentImpact -RoleDisplayName $roleName -RoleDescription $roleDescription -AppImpact $appImpact
        } elseif ($originSystem -eq "DirectoryRole" -and -not [string]::IsNullOrWhiteSpace($originId)) {
            # DirectoryRole resources carry role definition IDs; use the existing Entra tier map and role assignment metadata.
            $roleDefinitionId = $originId
            $roleInfo = if ($entraRoleDefinitionLookup.ContainsKey($roleDefinitionId)) { $entraRoleDefinitionLookup[$roleDefinitionId] } else { $null }
            if ($roleInfo -and -not [string]::IsNullOrWhiteSpace([string]$roleInfo.DisplayName)) {
                $resourceName = [string]$roleInfo.DisplayName
            } else {
                $resourceName = "Directory role $roleDefinitionId"
            }

            $roleTierValue = if ($roleInfo) { $roleInfo.RoleTier } elseif ($GLOBALEntraRoleRating.ContainsKey($roleDefinitionId)) { $GLOBALEntraRoleRating[$roleDefinitionId] } else { "?" }
            $entraTier = ConvertTo-AccessPackageTierLabel -Tier $roleTierValue
            $isPrivileged = if ($roleInfo) { [bool]$roleInfo.IsPrivileged } else { $false }
            $impact = Get-AccessPackageEntraRoleImpact -TierLabel $entraTier -IsPrivileged $isPrivileged
            $entraRoles = 1
        } elseif ($originSystem -match "Azure|Arm|Management") {
            # AzureResources roles expose the role definition in role.originId.
            $roleDefinitionId = Get-AccessPackageAzureRoleDefinitionId -OriginId ([string](Get-AccessPackageObjectValue -Object $role -Names @("originId")))
            $roleTierValue = if (-not [string]::IsNullOrWhiteSpace($roleDefinitionId) -and $GLOBALAzureRoleRating.ContainsKey($roleDefinitionId)) { $GLOBALAzureRoleRating[$roleDefinitionId] } else { "?" }
            $azureTier = ConvertTo-AccessPackageTierLabel -Tier $roleTierValue
            $impact = Get-AccessPackageAzureRoleImpact -TierLabel $azureTier
            $azureRoles = 1
        } elseif ($originSystem -eq "SharePointOnline") {
            $impact = Get-AccessPackageSharePointImpact -RoleName $roleName
        } elseif ($originSystem -eq "OAuthApplication") {
            $permissionId = [string](Get-AccessPackageObjectValue -Object $role -Names @("originId", "id"))
            if ($resourceType -eq "ApiAppPerms") {
                $applicationPermission = Resolve-AppRoleAssignmentRecord -AppRoleReferenceCache $AppRoleReferenceCache -PermissionId $permissionId -ResourceAppId $originId -ApiNameOverride $resourceName
                if ($applicationPermission) {
                    $apiPermissionCategory = [string]$applicationPermission.ApiPermissionCategorization
                    if (-not [string]::IsNullOrWhiteSpace([string]$applicationPermission.ApiPermission) -and [string]$applicationPermission.ApiPermission -ne "-") {
                        $roleName = [string]$applicationPermission.ApiPermission
                    } elseif (-not [string]::IsNullOrWhiteSpace([string]$applicationPermission.ApiPermissionDisplayname) -and [string]$applicationPermission.ApiPermissionDisplayname -ne "-") {
                        $roleName = [string]$applicationPermission.ApiPermissionDisplayname
                    }
                    $impact = (Get-ApiPermissionImpactSummary -ApplicationPermissions @($applicationPermission)).Impact
                }
            } elseif ($resourceType -eq "ApiDelegatedPerms") {
                $permissionName = if (-not [string]::IsNullOrWhiteSpace($roleName)) { $roleName } else { $permissionId }
                $apiPermissionCategory = Get-APIPermissionCategory -InputPermission $permissionName -PermissionType "delegated"
                $delegatedPermission = [pscustomobject]@{
                    ResourceAppId               = $originId
                    Scope                       = $permissionName
                    Permission                  = $permissionName
                    ApiPermissionCategorization = $apiPermissionCategory
                }
                $impact = (Get-ApiPermissionImpactSummary -DelegatedPermissions @($delegatedPermission)).Impact
            }
        }

        if ([string]::IsNullOrWhiteSpace($resourceName)) { $resourceName = if ($originId) { $originId } else { "-" } }
        if ([string]::IsNullOrWhiteSpace($roleName)) { $roleName = "-" }
        $resourceNameEncoded = ConvertTo-EntraFalconHtmlText $resourceName -DefaultValue "-"
        $resourceLink = if ($resourceReport) { "<a href=$resourceReport>$resourceNameEncoded</a>" } else { $resourceNameEncoded }

        return [pscustomobject]@{
            Id           = [string]$ResourceRoleScope.id
            Type         = $resourceType
            OriginSystem = if ([string]::IsNullOrWhiteSpace($originSystem)) { "Unknown" } else { $originSystem }
            OriginId     = $originId
            ResourceName = $resourceName
            ResourceLink = $resourceLink
            RoleName     = $roleName
            ScopeName    = [string](Get-AccessPackageObjectValue -Object $scope -Names @("displayName"))
            Impact       = $impact
            ApiPermissionCategory = $apiPermissionCategory
            EntraRoles   = $entraRoles
            EntraMaxTier = $entraTier
            AzureRoles   = $azureRoles
            AzureMaxTier = $azureTier
        }
    }


    ############################## Script section ########################

    $Title = "AccessPackages"
    $Warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($warning in @($RawAccessPackages.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$warning)) { $Warnings.Add([string]$warning) }
    }

    ########################################## SECTION: Preprocessing ##########################################

    $entraRoleDefinitionLookup = @{}
    foreach ($assignmentBucket in @($TenantRoleAssignments.Values)) {
        foreach ($assignment in @($assignmentBucket)) {
            if ($null -eq $assignment -or [string]::IsNullOrWhiteSpace([string]$assignment.RoleDefinitionId)) { continue }
            $roleDefinitionId = [string]$assignment.RoleDefinitionId
            if (-not $entraRoleDefinitionLookup.ContainsKey($roleDefinitionId)) {
                $entraRoleDefinitionLookup[$roleDefinitionId] = [pscustomobject]@{
                    DisplayName  = [string]$assignment.DisplayName
                    RoleTier     = $assignment.RoleTier
                    IsPrivileged = [bool]$assignment.IsPrivileged
                }
            }
        }
    }

    $AssignmentsByPackageId = @{}
    foreach ($assignment in @($RawAccessPackages.Assignments)) {
        $packageId = [string](Get-AccessPackageObjectValue -Object $assignment.accessPackage -Names @("id"))
        if ([string]::IsNullOrWhiteSpace($packageId) -and $assignment.PSObject.Properties["accessPackageId"]) { $packageId = [string]$assignment.accessPackageId }
        if ([string]::IsNullOrWhiteSpace($packageId)) { continue }
        if (-not $AssignmentsByPackageId.ContainsKey($packageId)) { $AssignmentsByPackageId[$packageId] = [System.Collections.Generic.List[object]]::new() }
        $AssignmentsByPackageId[$packageId].Add($assignment)
    }

    $PolicyEnabledById = if ($RawAccessPackages.PSObject.Properties["PolicyEnabledById"] -and $null -ne $RawAccessPackages.PolicyEnabledById) {
        $RawAccessPackages.PolicyEnabledById
    } else {
        @{}
    }
    $SeparationOfDutiesByPackage = if ($RawAccessPackages.PSObject.Properties["SeparationOfDutiesByPackage"] -and $null -ne $RawAccessPackages.SeparationOfDutiesByPackage) {
        $RawAccessPackages.SeparationOfDutiesByPackage
    } else {
        @{}
    }
    $PackageAnchorById = @{}
    foreach ($anchorPackage in @($RawAccessPackages.Packages)) {
        if ($null -eq $anchorPackage -or [string]::IsNullOrWhiteSpace([string]$anchorPackage.id)) { continue }
        $anchorPackageId = [string]$anchorPackage.id
        $anchorPolicies = @($anchorPackage.assignmentPolicies)
        $anchorPolicyId = if ($anchorPolicies.Count -gt 0) { [string](Get-AccessPackageObjectValue -Object $anchorPolicies[0] -Names @("id")) } else { "" }
        $PackageAnchorById[$anchorPackageId] = if ([string]::IsNullOrWhiteSpace($anchorPolicyId)) {
            "$anchorPackageId`_no-policy"
        } else {
            "$anchorPackageId`_$anchorPolicyId"
        }
    }

    $AccessPackages = @{}
    $TableOutput = [System.Collections.Generic.List[object]]::new()
    $AllObjectDetails = [System.Collections.ArrayList]::new()
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()
    $detailObjectDelimiter = "#" * 206
    $detailSectionDelimiter = "-" * 65
    $assignmentNow = [datetimeoffset]::UtcNow
    $htmlAssignmentLimit = 250
    $assignmentSortProperties = @(
        @{ Expression = {
            if ([bool]$_.IsActive) { 0 }
            elseif ([bool]$_.IsExpired) { 3 }
            elseif ([string]$_.State -ieq "delivered" -or [string]$_.Status -ieq "Delivered") { 1 }
            else { 2 }
        }; Ascending = $true },
        @{ Expression = { [string]$_.Start }; Descending = $true },
        @{ Expression = { [string]$_.Target }; Ascending = $true }
    )
    $actualPolicyCount = 0
    $policylessPackageCount = 0
    ########################################## SECTION: Processing ##########################################

    $packagesToProcess = @($RawAccessPackages.Packages)
    $packageTotalCount = $packagesToProcess.Count
    $packageProgressCounter = 0
    Write-Host "[*] Processing Access Packages"
    if ($packageTotalCount -gt 0) {
        Write-Host "[*] Status: Processing access package 1 of $packageTotalCount..."
    }
    foreach ($package in $packagesToProcess) {
        if (-not $package -or [string]::IsNullOrWhiteSpace([string]$package.id)) { continue }
        $packageProgressCounter++
        Write-Log -Level Verbose -Message "[AccessPackages] Processing access package $packageProgressCounter of $packageTotalCount`: $($package.displayName)"
        $packageId = [string]$package.id
        $packageAssignments = if ($AssignmentsByPackageId.ContainsKey($packageId)) { @($AssignmentsByPackageId[$packageId]) } else { @() }
        $resourceRoleScopesByPackage = if ($RawAccessPackages.PSObject.Properties["ResourceRoleScopesByPackage"] -and $null -ne $RawAccessPackages.ResourceRoleScopesByPackage) { $RawAccessPackages.ResourceRoleScopesByPackage } else { @{} }
        $resourceRoleScopes = if ($resourceRoleScopesByPackage.ContainsKey($packageId)) { @($resourceRoleScopesByPackage[$packageId]) } else { @() }
        $policies = @($package.assignmentPolicies)
        $actualPolicyCount += $policies.Count
        if ($policies.Count -eq 0) { $policylessPackageCount++ }

        $resources = @($resourceRoleScopes | ForEach-Object { Get-AccessPackageResourceInfo -ResourceRoleScope $_ })
        $targetRows = [System.Collections.Generic.List[object]]::new()

        foreach ($assignment in $packageAssignments) {
            $targetInfo = Get-AccessPackageTargetInfo -Target $assignment.target
            $policyId = [string](Get-AccessPackageObjectValue -Object $assignment.assignmentPolicy -Names @("id"))
            $policyName = [string](Get-AccessPackageObjectValue -Object $assignment.assignmentPolicy -Names @("displayName", "id"))
            $scheduleStart = ""
            $scheduleEnd = ""
            if ($assignment.PSObject.Properties["schedule"] -and $assignment.schedule) {
                $scheduleStart = [string](Get-AccessPackageObjectValue -Object $assignment.schedule -Names @("startDateTime"))
                $calculatedScheduleEnd = Get-AccessPackageAssignmentEndDateTime -Assignment $assignment
                if ($null -ne $calculatedScheduleEnd) { $scheduleEnd = $calculatedScheduleEnd.ToString("o") }
            }
            $expiryDateTime = if ([string]::IsNullOrWhiteSpace([string]$assignment.expiredDateTime)) {
                $scheduleEnd
            } else {
                [string]$assignment.expiredDateTime
            }
            $targetRows.Add([pscustomobject]@{
                Target         = $targetInfo.Link
                TargetId       = $targetInfo.Id
                TargetType     = $targetInfo.Kind
                PolicyId       = $policyId
                PolicyName     = if ([string]::IsNullOrWhiteSpace($policyName)) { "-" } else { $policyName }
                Policy         = if ([string]::IsNullOrWhiteSpace($policyName)) { "-" } else { ConvertTo-EntraFalconHtmlText $policyName -DefaultValue "-" }
                State          = if ([string]::IsNullOrWhiteSpace([string]$assignment.state)) { "-" } else { [string]$assignment.state }
                Status         = if ([string]::IsNullOrWhiteSpace([string]$assignment.status)) { "-" } else { [string]$assignment.status }
                Start          = ConvertTo-AccessPackageDateTimeText -DateTimeText $scheduleStart
                Expiry         = ConvertTo-AccessPackageDateTimeText -DateTimeText $expiryDateTime
                IsActive       = Test-AccessPackageAssignmentActive -Assignment $assignment -Now $assignmentNow
                IsExpired      = Test-AccessPackageAssignmentExpired -Assignment $assignment -Now $assignmentNow
            })
        }

        $resourceImpactSum = 0
        $entraTier = "-"
        $azureTier = "-"
        $entraRoleResources = 0
        $azureRoleResources = 0
        foreach ($resource in $resources) {
            $resourceImpactSum += [double]$resource.Impact
            $entraTier = Merge-HigherTierLabel -CurrentTier $entraTier -CandidateTier $resource.EntraMaxTier
            $azureTier = Merge-HigherTierLabel -CurrentTier $azureTier -CandidateTier $resource.AzureMaxTier
            $entraRoleResources += Get-AccessPackageIntValue -Value $resource.EntraRoles
            $azureRoleResources += Get-AccessPackageIntValue -Value $resource.AzureRoles
        }
        $groupResources = @($resources | Where-Object { $_.Type -eq "Group" }).Count
        $applicationResources = @($resources | Where-Object { $_.Type -eq "Application" }).Count
        $apiAppPermissionResources = @($resources | Where-Object { $_.Type -eq "ApiAppPerms" }).Count
        $apiDelegatedPermissionResources = @($resources | Where-Object { $_.Type -eq "ApiDelegatedPerms" }).Count
        $sharePointResources = @($resources | Where-Object { $_.Type -eq "SharePoint" }).Count
        $otherResources = @($resources | Where-Object { $_.Type -eq "Other" }).Count
        $hasHighImpact = ($resourceImpactSum -ge 100)

        $catalogName = if ($package.catalog) { [string]$package.catalog.displayName } else { "-" }
        $catalogId = if ($package.catalog) { [string]$package.catalog.id } else { "" }
        $catalogDetailsLink = if ([string]::IsNullOrWhiteSpace($catalogId)) {
            ConvertTo-EntraFalconHtmlText $catalogName -DefaultValue "-"
        } else {
            "<a href=Catalogs_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$catalogId>$(ConvertTo-EntraFalconHtmlText $catalogName -DefaultValue '-')</a>"
        }
        $catalogEnabled = ($package.catalog -and ([string]$package.catalog.state -eq "published"))
        $displayName = if ([string]::IsNullOrWhiteSpace([string]$package.displayName)) { $packageId } else { [string]$package.displayName }
        $separationOfDutiesEntries = if ($SeparationOfDutiesByPackage -is [System.Collections.IDictionary] -and $SeparationOfDutiesByPackage.Contains($packageId)) {
            @($SeparationOfDutiesByPackage[$packageId])
        } else {
            @()
        }
        $separationOfDutiesRows = @(foreach ($entry in $separationOfDutiesEntries) {
            if ($null -eq $entry) { continue }
            $entryId = [string](Get-AccessPackageObjectValue -Object $entry -Names @("Id", "id"))
            $entryType = [string](Get-AccessPackageObjectValue -Object $entry -Names @("Type"))
            $entryDisplayName = [string](Get-AccessPackageObjectValue -Object $entry -Names @("DisplayName", "displayName", "Id", "id"))
            if ([string]::IsNullOrWhiteSpace($entryDisplayName)) { $entryDisplayName = if ($entryId) { $entryId } else { "-" } }
            $entryDisplayNameEncoded = ConvertTo-EntraFalconHtmlText $entryDisplayName -DefaultValue "-"
            $entryLink = $entryDisplayNameEncoded
            if ($entryType -eq "Access Package" -and -not [string]::IsNullOrWhiteSpace($entryId) -and $PackageAnchorById.Contains($entryId)) {
                $entryLink = "<a href=#$($PackageAnchorById[$entryId])>$entryDisplayNameEncoded</a>"
            } elseif ($entryType -eq "Group" -and -not [string]::IsNullOrWhiteSpace($entryId)) {
                $entryLink = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$entryId>$entryDisplayNameEncoded</a>"
            }
            [pscustomobject]@{
                DisplayName = $entryLink
                Type        = if ([string]::IsNullOrWhiteSpace($entryType)) { "-" } else { $entryType }
            }
        })
        $separationOfDutiesRowsTxt = @($separationOfDutiesEntries | ForEach-Object {
            [pscustomobject]@{
                DisplayName = [string](Get-AccessPackageObjectValue -Object $_ -Names @("DisplayName", "displayName", "Id", "id"))
                Type        = [string](Get-AccessPackageObjectValue -Object $_ -Names @("Type"))
            }
        })

        $policyRows = foreach ($policy in $policies) {
            $policyId = [string](Get-AccessPackageObjectValue -Object $policy -Names @("id"))
            $autoAssignment = ($null -ne $policy.automaticRequestSettings)
            $policyEnabled = if ($PolicyEnabledById -is [System.Collections.IDictionary] -and $PolicyEnabledById.Contains($policyId)) {
                [bool]$PolicyEnabledById[$policyId]
            } else {
                $null
            }
            if ($autoAssignment) {
                $policyEnabled = $true
            }
            $autoAssignmentRule = Get-AccessPackageAutoAssignmentRuleText -Policy $policy
            $rawAllowedTargetScope = [string]$policy.allowedTargetScope
            $dangerousAutoAssignmentAttributes = @(Get-AccessPackageDangerousDynamicRuleAttributes -MembershipRule $autoAssignmentRule)
            $inviteLinkedDangerousAutoAssignmentAttributes = @(Get-AccessPackageDangerousDynamicRuleAttributes -MembershipRule $autoAssignmentRule -IncludeInviteLinkedAttributes | Where-Object {
                $_ -in @("user.userPrincipalName", "user.mail")
            })
            $explicitSpecificTargets = @($policy.specificAllowedTargets | Where-Object {
                $null -ne $_ -and [string]::IsNullOrWhiteSpace([string](Get-AccessPackageObjectValue -Object $_ -Names @("membershipRule")))
            })
            [pscustomobject]@{
                Id                  = $policyId
                IsPolicyPlaceholder = $false
                DisplayName         = ConvertTo-EntraFalconHtmlText (Get-AccessPackageObjectValue -Object $policy -Names @("displayName", "id")) -DefaultValue "-"
                RawDisplayName      = [string](Get-AccessPackageObjectValue -Object $policy -Names @("displayName", "id"))
                PolicyEnabled       = $policyEnabled
                RawAllowedTargetScope = $rawAllowedTargetScope
                AllowedTargetScope  = Format-AccessPackageAllowedTargetScope -AllowedTargetScope $rawAllowedTargetScope
                BroadScope          = Test-AccessPackagePolicyBroadScope -Policy $policy
                SelfAddAccess       = Test-AccessPackagePolicyRequestorSetting -Policy $policy -Name "enableTargetsToSelfAddAccess"
                OnBehalfAddAccess   = Test-AccessPackagePolicyRequestorSetting -Policy $policy -Name "enableOnBehalfRequestorsToAddAccess"
                ApprovalRequired    = Test-AccessPackagePolicyApprovalRequired -Policy $policy
                Expiration          = Get-AccessPackagePolicyExpirationText -Policy $policy
                AccessReview        = Test-AccessPackagePolicyHasReview -Policy $policy
                AutoAssignment      = $autoAssignment
                AutoAssignmentRule  = $autoAssignmentRule
                HasDangerousAutoAssignmentRule = (($dangerousAutoAssignmentAttributes.Count + $inviteLinkedDangerousAutoAssignmentAttributes.Count) -gt 0)
                DangerousAutoAssignmentAttributes = ($dangerousAutoAssignmentAttributes -join ", ")
                InviteLinkedDangerousAutoAssignmentAttributes = ($inviteLinkedDangerousAutoAssignmentAttributes -join ", ")
                SpecificTargets     = $explicitSpecificTargets.Count
            }
        }
        if (@($policyRows).Count -eq 0) {
            $policyRows = @([pscustomobject]@{
                Id                  = ""
                IsPolicyPlaceholder = $true
                DisplayName         = "No policy configured"
                RawDisplayName      = "No policy configured"
                PolicyEnabled       = "-"
                RawAllowedTargetScope = ""
                AllowedTargetScope  = "-"
                BroadScope          = $false
                SelfAddAccess       = $false
                OnBehalfAddAccess   = $false
                ApprovalRequired    = $false
                Expiration          = "-"
                AccessReview        = $false
                AutoAssignment      = $false
                AutoAssignmentRule  = "-"
                HasDangerousAutoAssignmentRule = $false
                DangerousAutoAssignmentAttributes = ""
                InviteLinkedDangerousAutoAssignmentAttributes = ""
                SpecificTargets     = 0
            })
        }
        Write-Log -Level Debug -Message "[AccessPackages] Package '$displayName': Policies=$(@($policies).Count), Resources=$(@($resources).Count), Assignments=$(@($packageAssignments).Count), ResourceImpact=$resourceImpactSum, HighImpact=$hasHighImpact"
        $showResourceApiPermissionCategory = @($resources | Where-Object { $_.Type -in @("ApiAppPerms", "ApiDelegatedPerms") }).Count -gt 0
        $showResourceEntraRoleColumns = @($resources | Where-Object { (Get-AccessPackageIntValue -Value $_.EntraRoles) -gt 0 }).Count -gt 0
        $showResourceAzureRoleColumns = @($resources | Where-Object { (Get-AccessPackageIntValue -Value $_.AzureRoles) -gt 0 }).Count -gt 0
        $resourceRows = @(foreach ($resource in $resources) {
            $resourceRowProperties = [ordered]@{
                Resource = $resource.ResourceLink
                Type     = $resource.Type
                OriginId = $resource.OriginId
                Role     = ConvertTo-EntraFalconHtmlText $resource.RoleName -DefaultValue "-"
                Scope    = ConvertTo-EntraFalconHtmlText $resource.ScopeName -DefaultValue "-"
            }
            if ($showResourceApiPermissionCategory) {
                $resourceRowProperties["ApiPermissionCategory"] = if ($resource.Type -in @("ApiAppPerms", "ApiDelegatedPerms")) { $resource.ApiPermissionCategory } else { "-" }
            }
            if ($showResourceEntraRoleColumns) {
                $resourceEntraRoles = Get-AccessPackageIntValue -Value $resource.EntraRoles
                $resourceRowProperties["EntraRoles"] = if ($resourceEntraRoles -gt 0) { $resourceEntraRoles } else { "-" }
                $resourceRowProperties["EntraMaxTier"] = if ($resourceEntraRoles -gt 0) { $resource.EntraMaxTier } else { "-" }
            }
            if ($showResourceAzureRoleColumns) {
                $resourceAzureRoles = Get-AccessPackageIntValue -Value $resource.AzureRoles
                $resourceRowProperties["AzureRoles"] = if ($resourceAzureRoles -gt 0) { $resourceAzureRoles } else { "-" }
                $resourceRowProperties["AzureMaxTier"] = if ($resourceAzureRoles -gt 0) { $resource.AzureMaxTier } else { "-" }
            }
            $resourceRowProperties["Impact"] = $resource.Impact
            [pscustomobject]$resourceRowProperties
        }) | Sort-Object @{ Expression = { [double]$_.Impact }; Descending = $true }, Resource
        $policyDetailContexts = [System.Collections.Generic.List[object]]::new()
        $policySectionNameCounts = @{}
        for ($policyIndex = 0; $policyIndex -lt @($policyRows).Count; $policyIndex++) {
            $policyRow = @($policyRows)[$policyIndex]
            $policy = if ($policyIndex -lt @($policies).Count) { @($policies)[$policyIndex] } else { $null }
            $isPolicyPlaceholder = [bool]$policyRow.IsPolicyPlaceholder
            $policyId = [string]$policyRow.Id
            $policyName = [string]$policyRow.RawDisplayName
            $policySectionName = $policyName -replace "[\r\n\t]+", " "
            if ([string]::IsNullOrWhiteSpace($policySectionName)) { $policySectionName = "Unnamed Policy" }
            $policySectionName = $policySectionName.Trim()
            $policySectionKey = $policySectionName.ToLowerInvariant()
            if (-not $policySectionNameCounts.ContainsKey($policySectionKey)) {
                $policySectionNameCounts[$policySectionKey] = 0
            }
            $policySectionNameCounts[$policySectionKey]++
            if ($policySectionNameCounts[$policySectionKey] -gt 1) {
                $policySectionName = "$policySectionName ($($policySectionNameCounts[$policySectionKey]))"
            }

            $policyAssignments = @($targetRows | Where-Object {
                (-not [string]::IsNullOrWhiteSpace($policyId) -and [string]$_.PolicyId -eq $policyId) -or
                (-not [string]::IsNullOrWhiteSpace($policyName) -and [string]$_.PolicyName -eq $policyName)
            } | Sort-Object -Property $assignmentSortProperties)
            $policyActiveAssignments = @($policyAssignments | Where-Object { [bool]$_.IsActive })
            $policyExpiredAssignments = @($policyAssignments | Where-Object { [bool]$_.IsExpired })
            $policyUserAssignments = @($policyActiveAssignments | Where-Object { $_.TargetType -eq "User" })
            $policyGuestAssignments = @($policyActiveAssignments | Where-Object {
                $id = [string]$_.TargetId
                $AllUsersBasicHT.ContainsKey($id) -and [string]$AllUsersBasicHT[$id].UserType -eq "Guest"
            })
            $policySpAssignments = @($policyActiveAssignments | Where-Object { "$($_.TargetType)" -match "ServicePrincipal|ManagedIdentity|AgentIdentity|BlueprintPrincipal" })
            $policyHasExpiration = Test-AccessPackagePolicyHasExpiration -Policy $policy

            $policySpecificTargetRows = foreach ($target in @($policy.specificAllowedTargets)) {
                if ($null -eq $target) { continue }
                $membershipRule = [string](Get-AccessPackageObjectValue -Object $target -Names @("membershipRule"))
                if (-not [string]::IsNullOrWhiteSpace($membershipRule)) { continue }
                New-AccessPackageSpecificTargetRow -Policy $policy -Target $target
            }
            $policyAssignmentDetailRows = @($policyAssignments | Select-Object Target,TargetType,Status,Start,Expiry)
            $policyAssignmentHtmlRows = @($policyAssignmentDetailRows | Select-Object -First $htmlAssignmentLimit)
            if ($policyAssignmentDetailRows.Count -gt $htmlAssignmentLimit) {
                $policyAssignmentHtmlRows += [pscustomobject]@{
                    Target     = "Showing first $htmlAssignmentLimit of $($policyAssignmentDetailRows.Count) assignments. See TXT report for the full list."
                    TargetType = "-"
                    Status     = "-"
                    Start      = "-"
                    Expiry     = "-"
                }
            }
            $policyApprovalRows = @(Get-AccessPackageApprovalRows -Policy $policy)

            [void]$policyDetailContexts.Add([pscustomobject]@{
                PolicyRow = $policyRow
                PolicyId = $policyId
                PolicyName = $policyName
                SectionName = $policySectionName
                ApprovalSettings = @($policyApprovalRows)
                SpecificTargets = @($policySpecificTargetRows | Select-Object Target,TargetType,Protected)
                Assignments = @($policyAssignmentDetailRows)
                HtmlAssignments = @($policyAssignmentHtmlRows)
                PolicyAssignments = @($policyAssignments)
                PolicyActiveAssignments = @($policyActiveAssignments)
                PolicyExpiredAssignments = @($policyExpiredAssignments)
                PolicyUserAssignments = @($policyUserAssignments)
                PolicyGuestAssignments = @($policyGuestAssignments)
                PolicySpAssignments = @($policySpAssignments)
                PolicyHasExpiration = $policyHasExpiration
                IsPolicyPlaceholder = $isPolicyPlaceholder
            })
        }

        foreach ($policyContext in @($policyDetailContexts)) {
            $policyRow = $policyContext.PolicyRow
            $policyId = [string]$policyContext.PolicyId
            $policyName = [string]$policyContext.PolicyName
            $policyAssignments = @($policyContext.PolicyAssignments)
            $policyActiveAssignments = @($policyContext.PolicyActiveAssignments)
            $policyExpiredAssignments = @($policyContext.PolicyExpiredAssignments)
            $policyUserAssignments = @($policyContext.PolicyUserAssignments)
            $policyGuestAssignments = @($policyContext.PolicyGuestAssignments)
            $policySpAssignments = @($policyContext.PolicySpAssignments)
            $policyHasExpiration = [bool]$policyContext.PolicyHasExpiration
            $isPolicyPlaceholder = [bool]$policyContext.IsPolicyPlaceholder

            $policyWarnings = [System.Collections.Generic.List[string]]::new()
            if ($isPolicyPlaceholder) {
                $policyWarnings.Add("No assignment policy configured")
            } elseif ($policyRow.BroadScope -and $policyRow.SelfAddAccess -and -not $policyRow.ApprovalRequired) {
                $policyWarnings.Add("Broad self-request without approval")
            }
            $unprotectedGroupSpecificTargets = @($policyContext.SpecificTargets | Where-Object {
                [string]$_.TargetType -eq "Group" -and ([string]$_.Protected).Trim().ToLowerInvariant() -eq "false"
            })
            $hasUnprotectedGroupSpecificTarget = ($unprotectedGroupSpecificTargets.Count -gt 0)
            $unprotectedGroupSpecificTargetText = if ($hasUnprotectedGroupSpecificTarget) { ($unprotectedGroupSpecificTargets | ForEach-Object { [string]$_.Target }) -join "<br>" } else { "" }
            if ($policyRow.AllowedTargetScope -eq "Specific Users" -and $policyRow.SelfAddAccess -and -not $policyRow.ApprovalRequired -and $resourceImpactSum -ge 100 -and $hasUnprotectedGroupSpecificTarget) {
                $policyWarnings.Add("Unprotected group can self-request without approval")
            }
            if ($policyRow.HasDangerousAutoAssignmentRule) { $policyWarnings.Add("Dangerous auto-assignment rule") }

            $policyLikelihood = 1
            if (-not $isPolicyPlaceholder) {
                if ($policyRow.BroadScope) { $policyLikelihood += 5 }
                if ($policyRow.SelfAddAccess) { $policyLikelihood += 5 }
                if (-not $policyRow.ApprovalRequired) { $policyLikelihood += 5 }
                if ($policySpAssignments.Count -gt 0) { $policyLikelihood += 2 }
                if ($hasUnprotectedGroupSpecificTarget) { $policyLikelihood += 3 }
                if ($policyRow.HasDangerousAutoAssignmentRule) { $policyLikelihood += 5 }
            }
            $policyRisk = [math]::Round($resourceImpactSum * $policyLikelihood, 2)
            $policyRowId = if ($isPolicyPlaceholder) {
                "$packageId`_no-policy"
            } elseif (-not [string]::IsNullOrWhiteSpace($policyId)) {
                "$packageId`_$policyId"
            } else {
                "$packageId`_$($TableOutput.Count)"
            }
            $warningsText = if ($policyWarnings.Count -gt 0) { ($policyWarnings -join " / ") } else { "" }
            $policyLinkText = if ([string]::IsNullOrWhiteSpace($policyName)) { "Unnamed Policy" } else { $policyName }
            $policyLink = "<a href=#$policyRowId>$(ConvertTo-EntraFalconHtmlText $policyLinkText -DefaultValue '-')</a>"
            $policyDetailObjectName = if ([string]::IsNullOrWhiteSpace($policyName)) { "$displayName - Policy" } else { "$displayName - $policyName" }
            $policyInformationProperties = [ordered]@{
                Policy             = ConvertTo-EntraFalconHtmlText $policyName -DefaultValue "-"
                PolicyId           = if ($isPolicyPlaceholder) { "-" } else { ConvertTo-EntraFalconHtmlText $policyId -DefaultValue "-" }
                AccessPackage      = ConvertTo-EntraFalconHtmlText $displayName -DefaultValue "-"
                AccessPackageId    = $packageId
                Catalog            = $catalogDetailsLink
                PolicyEnabled      = $policyRow.PolicyEnabled
                CatalogEnabled     = [bool]$catalogEnabled
                Hidden             = [bool]$package.isHidden
                AllowedTargetScope = $policyRow.AllowedTargetScope
                SelfAdd            = if ($isPolicyPlaceholder) { "-" } else { $policyRow.SelfAddAccess }
                OnBehalfAdd        = if ($isPolicyPlaceholder) { "-" } else { $policyRow.OnBehalfAddAccess }
                Approval           = if ($isPolicyPlaceholder) { "-" } else { $policyRow.ApprovalRequired }
                Expiration         = $policyRow.Expiration
                AccessReview       = if ($isPolicyPlaceholder) { "-" } else { $policyRow.AccessReview }
                AutoAssignment     = if ($isPolicyPlaceholder) { "-" } else { $policyRow.AutoAssignment }
            }
            if ($policyRow.AutoAssignment) {
                $policyInformationProperties["Rule"] = $policyRow.AutoAssignmentRule
            }
            $policyInformationProperties["Impact"] = $resourceImpactSum
            $policyInformationProperties["Likelihood"] = $policyLikelihood
            $policyInformationProperties["Risk"] = $policyRisk
            $policyInformationProperties["Warnings"] = $warningsText
            $policyInformation = [pscustomobject]$policyInformationProperties
            $policyInformationTxtProperties = [ordered]@{}
            foreach ($property in $policyInformation.PSObject.Properties) {
                $value = $property.Value
                if ($property.Name -in @("Policy", "AccessPackage", "Catalog", "Rule")) {
                    $value = ConvertTo-AccessPackagePlainText $value
                } elseif ($property.Name -in @("Impact", "Risk")) {
                    $value = ConvertTo-AccessPackageWholeNumber $value
                }
                $policyInformationTxtProperties[$property.Name] = $value
            }
            $policyInformationTxt = [pscustomobject]$policyInformationTxtProperties
            $resourceRowsTxt = @($resourceRows | ForEach-Object {
                $resourceTxtProperties = [ordered]@{}
                foreach ($property in $_.PSObject.Properties) {
                    $value = $property.Value
                    if ($property.Name -in @("Resource", "Role", "Scope")) {
                        $value = ConvertTo-AccessPackagePlainText $value
                    } elseif ($property.Name -eq "Impact") {
                        $value = ConvertTo-AccessPackageWholeNumber $value
                    }
                    $resourceTxtProperties[$property.Name] = $value
                }
                [pscustomobject]$resourceTxtProperties
            })
            $specificTargetsTxt = @($policyContext.SpecificTargets | ForEach-Object {
                [pscustomobject]@{
                    Target     = ConvertTo-AccessPackagePlainText $_.Target
                    TargetType = $_.TargetType
                    Protected  = $_.Protected
                }
            })
            $approvalSettingsTxt = @($policyContext.ApprovalSettings | ForEach-Object {
                [pscustomobject]@{
                    Stage                       = $_.Stage
                    ApprovalForAdd              = $_.ApprovalForAdd
                    ApprovalForUpdate           = $_.ApprovalForUpdate
                    Escalation                  = $_.Escalation
                    EscalationAfter             = $_.EscalationAfter
                    ApproverVisibility          = $_.ApproverVisibility
                    PrimaryApprovers            = ConvertTo-AccessPackagePlainText $_.PrimaryApprovers
                    FallbackPrimaryApprovers    = ConvertTo-AccessPackagePlainText $_.FallbackPrimaryApprovers
                    EscalationApprovers         = ConvertTo-AccessPackagePlainText $_.EscalationApprovers
                    FallbackEscalationApprovers = ConvertTo-AccessPackagePlainText $_.FallbackEscalationApprovers
                }
            })
            $assignmentsTxt = @($policyContext.Assignments | ForEach-Object {
                [pscustomobject]@{
                    Target     = ConvertTo-AccessPackagePlainText $_.Target
                    TargetType = $_.TargetType
                    Status     = $_.Status
                    Start      = $_.Start
                    Expiry     = $_.Expiry
                }
            })

            [void]$DetailTxtBuilder.AppendLine($detailObjectDelimiter)
            [void]$DetailTxtBuilder.AppendLine("Access Package Policy: $policyDetailObjectName")
            [void]$DetailTxtBuilder.AppendLine($detailObjectDelimiter)
            [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
            [void]$DetailTxtBuilder.AppendLine("Policy Information")
            [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
            [void]$DetailTxtBuilder.AppendLine(($policyInformationTxt | Format-List | Out-String))
            if ($separationOfDutiesRowsTxt.Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine("Separation of Duties")
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine(($separationOfDutiesRowsTxt | Select-Object DisplayName,Type | Format-Table | Out-String -Width 512))
            }
            if (@($policyContext.ApprovalSettings).Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine("Approval Settings")
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine(($approvalSettingsTxt | Select-Object Stage,ApprovalForAdd,ApprovalForUpdate,Escalation,EscalationAfter,ApproverVisibility,PrimaryApprovers,FallbackPrimaryApprovers,EscalationApprovers,FallbackEscalationApprovers | Format-Table | Out-String -Width 512))
            }
            if (@($resourceRows).Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine("Granted Resources and Roles (Access Package)")
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine(($resourceRowsTxt | Format-Table | Out-String -Width 512))
            }
            if (@($policyContext.SpecificTargets).Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine("Specific Targets")
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine(($specificTargetsTxt | Select-Object Target,TargetType,Protected | Format-Table | Out-String -Width 512))
            }
            if (@($policyContext.Assignments).Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine("Assignments")
                [void]$DetailTxtBuilder.AppendLine($detailSectionDelimiter)
                [void]$DetailTxtBuilder.AppendLine(($assignmentsTxt | Select-Object Target,TargetType,Status,Start,Expiry | Format-Table | Out-String -Width 512))
            }
            [void]$DetailTxtBuilder.AppendLine()

            $detailObjectProperties = [ordered]@{
                "Object Name"                                  = $policyDetailObjectName
                "Object ID"                                    = $policyRowId
                "Policy Information"                           = $policyInformation
            }
            if ($separationOfDutiesRows.Count -gt 0) {
                $detailObjectProperties["Separation of Duties"] = @($separationOfDutiesRows)
            }
            if (@($policyContext.ApprovalSettings).Count -gt 0) {
                $detailObjectProperties["Approval Settings"] = @($policyContext.ApprovalSettings)
            }
            $detailObjectProperties["Granted Resources and Roles (Access Package)"] = @($resourceRows)
            if (@($policyContext.SpecificTargets).Count -gt 0) {
                $detailObjectProperties["Specific Targets"] = @($policyContext.SpecificTargets)
            }
            if (@($policyContext.Assignments).Count -gt 0) {
                $detailObjectProperties["Assignments"] = @($policyContext.HtmlAssignments)
            }
            [void]$AllObjectDetails.Add([pscustomobject]$detailObjectProperties)

            $tableRow = [pscustomobject]@{
                Id                      = $policyRowId
                PackageId               = $packageId
                Package                 = $displayName
                PolicyId                = $policyId
                Policy                  = $policyName
                PolicyLink              = $policyLink
                IsPolicyPlaceholder     = $isPolicyPlaceholder
                PolicyEnabled           = $policyRow.PolicyEnabled
                Catalog                 = $catalogName
                CatalogEnabled          = [bool]$catalogEnabled
                Hidden                  = [bool]$package.isHidden
                SeparationOfDuties      = ($separationOfDutiesEntries.Count -gt 0)
                Resources               = @($resources).Count
                Groups                  = $groupResources
                Applications            = $applicationResources
                ApiAppPerms             = $apiAppPermissionResources
                ApiDelegatedPerms       = $apiDelegatedPermissionResources
                SharePoint              = $sharePointResources
                AzureRoles              = $azureRoleResources
                EntraRoles              = $entraRoleResources
                OtherResources          = $otherResources
                RawAllowedTargetScope   = $policyRow.RawAllowedTargetScope
                AllowedTargetScope      = $policyRow.AllowedTargetScope
                BroadScope              = if ($isPolicyPlaceholder) { "-" } else { $policyRow.BroadScope }
                SelfAddAccess           = if ($isPolicyPlaceholder) { "-" } else { $policyRow.SelfAddAccess }
                OnBehalfAddAccess       = if ($isPolicyPlaceholder) { "-" } else { $policyRow.OnBehalfAddAccess }
                ApprovalRequired        = if ($isPolicyPlaceholder) { "-" } else { $policyRow.ApprovalRequired }
                Expiration              = if ($isPolicyPlaceholder) { "-" } else { $policyHasExpiration }
                ExpirationDetails       = $policyRow.Expiration
                AccessReview            = if ($isPolicyPlaceholder) { "-" } else { $policyRow.AccessReview }
                AutoAssignment          = if ($isPolicyPlaceholder) { "-" } else { $policyRow.AutoAssignment }
                AutoAssignmentRule      = $policyRow.AutoAssignmentRule
                HasDangerousAutoAssignmentRule = $policyRow.HasDangerousAutoAssignmentRule
                DangerousAutoAssignmentAttributes = $policyRow.DangerousAutoAssignmentAttributes
                InviteLinkedDangerousAutoAssignmentAttributes = $policyRow.InviteLinkedDangerousAutoAssignmentAttributes
                SpecificTargets         = $policyRow.SpecificTargets
                ActiveAssignments       = @($policyActiveAssignments).Count
                ExpiredAssignments      = @($policyExpiredAssignments).Count
                Users                   = @($policyUserAssignments).Count
                Guests                  = @($policyGuestAssignments).Count
                ServicePrincipals       = @($policySpAssignments).Count
                EntraMaxTier            = $entraTier
                AzureMaxTier            = $azureTier
                Impact                  = $resourceImpactSum
                Likelihood              = $policyLikelihood
                Risk                    = $policyRisk
                Warnings                = $warningsText
                PolicyDetails           = $policyRow
                ResourceDetails         = @($resources)
                SeparationOfDutiesDetails = @($separationOfDutiesEntries)
                AssignmentDetails       = @($policyAssignments)
                HasBroadSelfAddNoApproval = ($hasHighImpact -and $policyRow.BroadScope -and $policyRow.SelfAddAccess -and -not $policyRow.ApprovalRequired)
                HasUnprotectedGroupSpecificTarget = $hasUnprotectedGroupSpecificTarget
                UnprotectedGroupSpecificTargets = $unprotectedGroupSpecificTargetText
                HasExpiration           = if ($isPolicyPlaceholder) { $false } else { $policyHasExpiration }
                HasAccessReview         = if ($isPolicyPlaceholder) { $false } else { $policyRow.AccessReview }
                IsHighImpact            = $hasHighImpact
            }
            $TableOutput.Add($tableRow)
            $AccessPackages[$policyRowId] = $tableRow
        }
    }
    Write-Host "[+] Processed $packageProgressCounter Access Packages and generated $($TableOutput.Count) report rows"

    ########################################## SECTION: Summary ##########################################

    if (-not $GlobalAuditSummary.ContainsKey("AccessPackages")) {
        $GlobalAuditSummary.AccessPackages = @{ Count = 0; Policies = 0; ActiveAssignments = 0; ExpiredAssignments = 0; ServicePrincipalAssignments = 0; HighImpact = 0 }
    }
    if (-not $GlobalAuditSummary.AccessPackages.ContainsKey("Policies")) {
        $GlobalAuditSummary.AccessPackages.Policies = 0
    }
    $GlobalAuditSummary.AccessPackages.Count = @($RawAccessPackages.Packages).Count
    $GlobalAuditSummary.AccessPackages.Policies = $actualPolicyCount
    $activeAssignmentCount = (@($TableOutput) | Measure-Object -Property ActiveAssignments -Sum).Sum
    $expiredAssignmentCount = (@($TableOutput) | Measure-Object -Property ExpiredAssignments -Sum).Sum
    if ($GlobalAuditSummary.AccessPackages -is [System.Collections.IDictionary]) {
        $GlobalAuditSummary.AccessPackages["ActiveAssignments"] = $activeAssignmentCount
        $GlobalAuditSummary.AccessPackages["ExpiredAssignments"] = $expiredAssignmentCount
    } else {
        if ($GlobalAuditSummary.AccessPackages.PSObject.Properties["ActiveAssignments"]) {
            $GlobalAuditSummary.AccessPackages.ActiveAssignments = $activeAssignmentCount
        } else {
            $GlobalAuditSummary.AccessPackages | Add-Member -NotePropertyName ActiveAssignments -NotePropertyValue $activeAssignmentCount
        }
        if ($GlobalAuditSummary.AccessPackages.PSObject.Properties["ExpiredAssignments"]) {
            $GlobalAuditSummary.AccessPackages.ExpiredAssignments = $expiredAssignmentCount
        } else {
            $GlobalAuditSummary.AccessPackages | Add-Member -NotePropertyName ExpiredAssignments -NotePropertyValue $expiredAssignmentCount
        }
    }
    # Retain the historical summary key as an active-assignment alias for replay and external consumers.
    $GlobalAuditSummary.AccessPackages.Assignments = $GlobalAuditSummary.AccessPackages.ActiveAssignments
    $GlobalAuditSummary.AccessPackages.ServicePrincipalAssignments = (@($TableOutput) | Measure-Object -Property ServicePrincipals -Sum).Sum
    $GlobalAuditSummary.AccessPackages.HighImpact = @($TableOutput | Where-Object { -not $_.IsPolicyPlaceholder -and $_.IsHighImpact }).Count
    if ($policylessPackageCount -gt 0) {
        Write-Log -Level Debug -Message "[AccessPackages] Added $policylessPackageCount placeholder report row(s) for packages without assignment policies."
    }
    $activeAssignmentSummaryText = ConvertTo-AccessPackagePluralText -Value ([int]$GlobalAuditSummary.AccessPackages.ActiveAssignments) -Unit "active assignment"
    $expiredAssignmentSummaryText = ConvertTo-AccessPackagePluralText -Value ([int]$GlobalAuditSummary.AccessPackages.ExpiredAssignments) -Unit "expired assignment"
    Write-Host "[+] Access Package summary: $($GlobalAuditSummary.AccessPackages.Count) packages, $($GlobalAuditSummary.AccessPackages.Policies) policies, $activeAssignmentSummaryText, $expiredAssignmentSummaryText, $($GlobalAuditSummary.AccessPackages.HighImpact) high-impact policies"
    Write-Log -Level Debug -Message "[AccessPackages] Summary: Packages=$($GlobalAuditSummary.AccessPackages.Count), Policies=$($GlobalAuditSummary.AccessPackages.Policies), ActiveAssignments=$($GlobalAuditSummary.AccessPackages.ActiveAssignments), ExpiredAssignments=$($GlobalAuditSummary.AccessPackages.ExpiredAssignments), ServicePrincipalAssignments=$($GlobalAuditSummary.AccessPackages.ServicePrincipalAssignments), HighImpact=$($GlobalAuditSummary.AccessPackages.HighImpact), Warnings=$($Warnings.Count)"

    ########################################## SECTION: Write Output ##########################################

    Write-Host "[*] Writing Access Package reports"
    $mainTableHtml = @($TableOutput | Select-Object @{Name = "Policy"; Expression = { $_.PolicyLink }},Package,Catalog,PolicyEnabled,CatalogEnabled,Hidden,SeparationOfDuties,Resources,Groups,Applications,@{Name = "ApiApp"; Expression = { $_.ApiAppPerms }},@{Name = "ApiDelegated"; Expression = { $_.ApiDelegatedPerms }},SharePoint,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AllowedTargetScope,BroadScope,@{Name = "SelfAdd"; Expression = { $_.SelfAddAccess }},@{Name = "OnBehalfAdd"; Expression = { $_.OnBehalfAddAccess }},@{Name = "Approval"; Expression = { $_.ApprovalRequired }},Expiration,ExpirationDetails,AccessReview,AutoAssignment,SpecificTargets,ActiveAssignments,ExpiredAssignments,Users,Guests,ServicePrincipals,Impact,Likelihood,Risk,Warnings)
    $mainTableExport = @($TableOutput | Select-Object Policy,Package,Catalog,PolicyEnabled,CatalogEnabled,Hidden,SeparationOfDuties,Resources,Groups,Applications,@{Name = "ApiApp"; Expression = { $_.ApiAppPerms }},@{Name = "ApiDelegated"; Expression = { $_.ApiDelegatedPerms }},SharePoint,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AllowedTargetScope,BroadScope,@{Name = "SelfAdd"; Expression = { $_.SelfAddAccess }},@{Name = "OnBehalfAdd"; Expression = { $_.OnBehalfAddAccess }},@{Name = "Approval"; Expression = { $_.ApprovalRequired }},Expiration,ExpirationDetails,AccessReview,AutoAssignment,SpecificTargets,ActiveAssignments,ExpiredAssignments,Users,Guests,ServicePrincipals,@{Name = "Impact"; Expression = { ConvertTo-AccessPackageWholeNumber $_.Impact }},Likelihood,@{Name = "Risk"; Expression = { ConvertTo-AccessPackageWholeNumber $_.Risk }},Warnings)
    $mainTableJson = if ($mainTableHtml.Count -eq 0) { "[]" } else { $mainTableHtml | ConvertTo-Json -Depth 6 -Compress }
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

    if ($ExportDataJson) {
        Export-EntraFalconDataJson -OutputFolder $OutputFolder -DatasetName "AccessPackages" -Data $TableOutput | Out-Null
    }

    $allObjectDetailsJson = if ($AllObjectDetails.Count -eq 0) { "[]" } else { $AllObjectDetails | ConvertTo-Json -Depth 8 -Compress }
    $objectsDetailsHead = @'
    <h2>Access Package Policy Details</h2>
    <div class="details-toolbar">
        <button id="toggle-expand">Expand All</button>
        <div class="details-search-wrapper">
            <div class="details-search-box">
                <input type="text" id="details-search" placeholder="Search details..." />
                <button class="details-search-help-btn" type="button" title="Search help">?</button>
                <div class="details-search-help-popover hidden">
                    <div class="search-help-title">Search guide</div>
                    <ul class="search-help-list">
                        <li><code>term</code> - substring match anywhere in object</li>
                        <li><code>!term</code> - exclude objects containing term</li>
                        <li><code>=value</code> - exact field value match</li>
                        <li><code>^prefix</code> - field value starts with</li>
                        <li><code>$suffix</code> - field value ends with</li>
                        <li><code>a && b</code> - both must match</li>
                        <li><code>a || b</code> - either must match</li>
                    </ul>
                </div>
            </div>
            <button id="details-search-clear" style="display:none" title="Clear search">&#x2715;</button>
            <div class="detail-scope-toggle">
                <button class="scope-btn active" data-scope="current">Filtered</button>
                <button class="scope-btn" data-scope="global">All objects</button>
            </div>
        </div>
        <div id="details-info" class="details-info">Showing 0-0 of 0 entries</div>
    </div>
    <div id="object-container"></div>
    <script id="object-data" type="application/json">
'@
    $allObjectDetailsHTML = $objectsDetailsHead + "`n" + $allObjectDetailsJson + "`n" + '</script>'

    $ReportDisplayName = "Access Packages Enumeration (BETA)"

    $headerTXT = "************************************************************************************************************************
$ReportDisplayName
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($Warnings -join ' / ')
************************************************************************************************************************
"

    $headerHTML = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>Access Package Policies Overview</h2>
"@

    $txtPath = Join-Path -Path $OutputFolder -ChildPath "$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt"
    $htmlPath = Join-Path -Path $OutputFolder -ChildPath "$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $headerTXT | Out-File -Width 512 -FilePath $txtPath -Append
    $mainTableExport | Format-Table Policy,Package,Catalog,PolicyEnabled,CatalogEnabled,Hidden,SeparationOfDuties,Resources,Groups,Applications,ApiApp,ApiDelegated,SharePoint,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AllowedTargetScope,BroadScope,SelfAdd,OnBehalfAdd,Approval,Expiration,ExpirationDetails,AccessReview,AutoAssignment,SpecificTargets,ActiveAssignments,ExpiredAssignments,Users,Guests,ServicePrincipals,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 $txtPath -Append
    $DetailTxtBuilder.ToString() | Out-File $txtPath -Append

    if ($Csv) {
        $csvPath = Join-Path -Path $OutputFolder -ChildPath "$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv"
        $csvColumns = @("Policy","Package","Catalog","PolicyEnabled","CatalogEnabled","Hidden","SeparationOfDuties","Resources","Groups","Applications","ApiApp","ApiDelegated","SharePoint","EntraRoles","EntraMaxTier","AzureRoles","AzureMaxTier","AllowedTargetScope","BroadScope","SelfAdd","OnBehalfAdd","Approval","Expiration","ExpirationDetails","AccessReview","AutoAssignment","SpecificTargets","ActiveAssignments","ExpiredAssignments","Users","Guests","ServicePrincipals","Impact","Likelihood","Risk","Warnings")
        if ($mainTableExport.Count -eq 0) {
            ($csvColumns -join ",") | Out-File -FilePath $csvPath
        } else {
            $mainTableExport | Select-Object $csvColumns | Export-Csv -Path $csvPath -NoTypeInformation
        }
    }

    Set-GlobalReportManifest -CurrentReportKey 'AccessPackages' -CurrentReportName $ReportDisplayName -Warnings $Warnings
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - Access Packages (BETA)</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript -PreContent $allObjectDetailsHTML
    $Report | Out-File $htmlPath

    return $AccessPackages
}

Export-ModuleMember -Function Get-AccessPackagesRawData,New-AccessPackageGroupSpecificTargetIndex,New-AccessPackageUserSpecificTargetIndex,ConvertTo-AccessPackageMembershipRuleKey,New-AccessPackageAutoAssignmentPolicyIndex,Invoke-CheckAccessPackages
