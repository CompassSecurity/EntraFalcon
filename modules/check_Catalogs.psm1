<#
.SYNOPSIS
   Enumerates Entitlement Management catalogs, catalog resources, and catalog-scoped RBAC assignments.
#>

#region Graph and raw catalog collection

function Format-CatalogGraphError {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) { return "Graph API request failed." }
    if ($message -match "(?i)NoLicense|license requirement|does not meet license|not licensed") {
        return "$($message.Trim()) The tenant might not have an Entitlement Management license."
    }
    if ($message -match "(?i)403|Forbidden|Authorization_RequestDenied") {
        return "$($message.Trim()) The token might lack EntitlementManagement.Read.All or an equivalent catalog role."
    }
    return $message.Trim()
}

function Invoke-CatalogGraphGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][hashtable]$QueryParameters
    )

    return Send-ApiRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0$Uri" `
        -AccessToken $GLOBALMsGraphAccessToken.access_token `
        -QueryParameters $QueryParameters `
        -UserAgent $($GlobalAuditSummary.UserAgent.Name) `
        -Silent `
        -ErrorAction Stop
}

function Test-CatalogExpandedQueryFallbackEligible {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory = $false)][switch]$IncludeServerErrors
    )

    $message = [string]$ErrorRecord.Exception.Message
    if (
        $message -match "(?i)status\s+400\b" -or
        $message -match "(?i)InvalidFilter|Request_BadRequest|invalid\s+OData|unsupported.*query"
    ) {
        return $true
    }
    if ($IncludeServerErrors -and $message -match "(?i)status\s+(500|502|503|504)\b") {
        return $true
    }
    return $false
}

function Get-CatalogRbacRoleDefinitions {
    return [ordered]@{
        'Catalog Owner'                     = 'ae79f266-94d4-4dab-b730-feca7e132178'
        'Catalog Reader'                    = '44272f93-9762-48e8-af59-1b5351b1d6b3'
        'Access Package Manager'            = '7f480852-ebdc-47d4-87de-0d8498384a83'
        'Access Package Assignment Manager' = 'e2182095-804a-4656-ae11-64734e9b7ae5'
    }
}

function Get-CatalogsRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AuthFlow,
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $supportedFlows = @('BroCi', 'BroCiManualCode', 'BroCiToken', 'ServicePrincipal')
    if ($supportedFlows -notcontains $AuthFlow) {
        $warnings.Add("Coverage gap: Catalogs and Identity Governance RBAC were not assessed because Entitlement Management APIs are only queried with BroCi-based flows or ServicePrincipal flow.")
        return [pscustomobject]@{
            IsAvailable = $false; IsSkipped = $true; RbacAvailable = $false; Warnings = @($warnings)
            Catalogs = @(); ResourcesByCatalog = @{}; RoleAssignments = @()
        }
    }

    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) {
        RefreshAuthenticationMsGraph | Out-Null
    }

    $collectionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $resourceCollectionMode = "Expanded"
    $resourceFallbackRequests = 0
    $resourceFallbackFailures = 0

    try {
        Write-Host "[*] Enumerating Entitlement Management catalogs"
        $catalogs = @(Invoke-CatalogGraphGet -Uri '/identityGovernance/entitlementManagement/catalogs' -QueryParameters @{
            '$select' = 'id,displayName,description,catalogType,state,isExternallyVisible,createdDateTime,modifiedDateTime'
            '$expand' = 'resources'
            '$top' = [Math]::Min([Math]::Max($ApiTop, 1), 100)
        })
        Write-Host "[+] Got $($catalogs.Count) Entitlement Management catalogs"
    } catch {
        if (Test-CatalogExpandedQueryFallbackEligible -ErrorRecord $_) {
            $resourceCollectionMode = "Fallback"
            Write-Log -Level Debug -Message "[Catalogs] Expanded collection query was rejected; retrying with the legacy collection shape. $($_.Exception.Message)"
            try {
                $catalogs = @(Invoke-CatalogGraphGet -Uri '/identityGovernance/entitlementManagement/catalogs' -QueryParameters @{
                    '$select' = 'id,displayName,description,catalogType,state,isExternallyVisible,createdDateTime,modifiedDateTime'
                    '$top' = [Math]::Min([Math]::Max($ApiTop, 1), 100)
                })
                Write-Host "[+] Got $($catalogs.Count) Entitlement Management catalogs"
            } catch {
                $warnings.Add("Coverage gap: Entitlement Management catalogs could not be enumerated. $(Format-CatalogGraphError -ErrorRecord $_)")
                Write-Log -Level Debug -Message "[Catalogs] Legacy catalog collection failed: $($_.Exception.Message)"
                return [pscustomobject]@{
                    IsAvailable = $false; IsSkipped = $false; RbacAvailable = $false; Warnings = @($warnings)
                    Catalogs = @(); ResourcesByCatalog = @{}; RoleAssignments = @()
                }
            }
        } else {
            $warnings.Add("Coverage gap: Entitlement Management catalogs could not be enumerated. $(Format-CatalogGraphError -ErrorRecord $_)")
            Write-Log -Level Debug -Message "[Catalogs] Expanded catalog collection failed: $($_.Exception.Message)"
            return [pscustomobject]@{
                IsAvailable = $false; IsSkipped = $false; RbacAvailable = $false; Warnings = @($warnings)
                Catalogs = @(); ResourcesByCatalog = @{}; RoleAssignments = @()
            }
        }
    }

    $resourcesByCatalog = @{}
    $resourceFailures = 0
    $resourceTotal = 0
    foreach ($catalog in $catalogs) {
        if ($null -eq $catalog -or [string]::IsNullOrWhiteSpace([string]$catalog.id)) { continue }
        $expandedResourcesProperty = $catalog.PSObject.Properties['resources']
        $expandedNextLinkProperty = $catalog.PSObject.Properties['resources@odata.nextLink']
        $expandedNextLink = if ($expandedNextLinkProperty) { [string]$expandedNextLinkProperty.Value } else { '' }
        $requiresFallback = ($null -eq $expandedResourcesProperty -or -not [string]::IsNullOrWhiteSpace($expandedNextLink))

        if (-not $requiresFallback) {
            $resources = @($expandedResourcesProperty.Value)
            $resourcesByCatalog[[string]$catalog.id] = $resources
            $resourceTotal += $resources.Count
            Write-Log -Level Debug -Message "[Catalogs] Catalog '$($catalog.displayName)' has $($resources.Count) expanded resource entries."
        } else {
            $resourceFallbackRequests++
            if ($resourceCollectionMode -eq "Expanded") { $resourceCollectionMode = "Mixed" }
            try {
                $resources = @(Invoke-CatalogGraphGet -Uri "/identityGovernance/entitlementManagement/catalogs/$($catalog.id)/resources" -QueryParameters @{
                    '$top' = [Math]::Min([Math]::Max($ApiTop, 1), 100)
                })
                $resourcesByCatalog[[string]$catalog.id] = $resources
                $resourceTotal += $resources.Count
                Write-Log -Level Debug -Message "[Catalogs] Catalog '$($catalog.displayName)' has $($resources.Count) fallback resource entries."
            } catch {
                $resourceFailures++
                $resourceFallbackFailures++
                $resourcesByCatalog[[string]$catalog.id] = @()
                $warnings.Add("Coverage gap: Resources could not be enumerated for catalog '$($catalog.displayName)'. $(Format-CatalogGraphError -ErrorRecord $_)")
                Write-Log -Level Debug -Message "[Catalogs] Resource collection failed for '$($catalog.displayName)': $($_.Exception.Message)"
            }
        }

        foreach ($propertyName in @('resources', 'resources@odata.context', 'resources@odata.nextLink')) {
            if ($catalog.PSObject.Properties[$propertyName]) {
                $catalog.PSObject.Properties.Remove($propertyName)
            }
        }
    }
    Write-Host "[+] Got $resourceTotal catalog resources"

    $roleAssignments = [System.Collections.Generic.List[object]]::new()
    $rbacFailures = 0
    $rbacCollectionMode = "Bulk"
    $roleDefinitions = Get-CatalogRbacRoleDefinitions
    $roleNameByDefinitionId = @{}
    foreach ($roleEntry in $roleDefinitions.GetEnumerator()) {
        $roleNameByDefinitionId[[string]$roleEntry.Value] = [string]$roleEntry.Key
    }

    try {
        $assignments = @(Invoke-CatalogGraphGet -Uri '/roleManagement/entitlementManagement/roleAssignments' -QueryParameters @{
            '$select' = 'id,principalId,roleDefinitionId,directoryScopeId,appScopeId'
            '$expand' = 'principal'
            '$top' = 15
        })
        $assignmentsByRoleDefinitionId = @{}
        foreach ($assignment in $assignments) {
            $roleDefinitionId = [string]$assignment.roleDefinitionId
            if (-not $roleNameByDefinitionId.ContainsKey($roleDefinitionId)) { continue }
            if (-not $assignmentsByRoleDefinitionId.ContainsKey($roleDefinitionId)) {
                $assignmentsByRoleDefinitionId[$roleDefinitionId] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$assignmentsByRoleDefinitionId[$roleDefinitionId].Add($assignment)
        }
        # Preserve the previous role-grouped order so report details and exports
        # remain stable even though assignments now arrive in one collection.
        foreach ($roleEntry in $roleDefinitions.GetEnumerator()) {
            $roleDefinitionId = [string]$roleEntry.Value
            if (-not $assignmentsByRoleDefinitionId.ContainsKey($roleDefinitionId)) { continue }
            foreach ($assignment in @($assignmentsByRoleDefinitionId[$roleDefinitionId])) {
                $catalogId = ''
                if ([string]$assignment.appScopeId -match '^/AccessPackageCatalog/([^/]+)$') {
                    $catalogId = $matches[1]
                }
                if ([string]::IsNullOrWhiteSpace($catalogId)) { continue }
                $assignment | Add-Member -NotePropertyName CatalogId -NotePropertyValue $catalogId -Force
                $assignment | Add-Member -NotePropertyName RoleName -NotePropertyValue ([string]$roleEntry.Key) -Force
                [void]$roleAssignments.Add($assignment)
            }
        }
    } catch {
        if (Test-CatalogExpandedQueryFallbackEligible -ErrorRecord $_ -IncludeServerErrors) {
            $rbacCollectionMode = "RoleFallback"
            Write-Log -Level Debug -Message "[Catalogs] Bulk RBAC collection failed; retrying with role-specific queries. $($_.Exception.Message)"
            foreach ($roleEntry in $roleDefinitions.GetEnumerator()) {
                try {
                    $assignments = @(Invoke-CatalogGraphGet -Uri '/roleManagement/entitlementManagement/roleAssignments' -QueryParameters @{
                        '$select' = 'id,principalId,roleDefinitionId,directoryScopeId,appScopeId'
                        '$filter' = "roleDefinitionId eq '$($roleEntry.Value)'"
                        '$expand' = 'principal'
                        '$top' = 15
                    })
                    foreach ($assignment in $assignments) {
                        $catalogId = ''
                        if ([string]$assignment.appScopeId -match '^/AccessPackageCatalog/([^/]+)$') {
                            $catalogId = $matches[1]
                        }
                        if ([string]::IsNullOrWhiteSpace($catalogId)) { continue }
                        $assignment | Add-Member -NotePropertyName CatalogId -NotePropertyValue $catalogId -Force
                        $assignment | Add-Member -NotePropertyName RoleName -NotePropertyValue ([string]$roleEntry.Key) -Force
                        [void]$roleAssignments.Add($assignment)
                    }
                } catch {
                    $rbacFailures++
                    $warnings.Add("Coverage gap: '$($roleEntry.Key)' assignments could not be enumerated. $(Format-CatalogGraphError -ErrorRecord $_)")
                    Write-Log -Level Debug -Message "[Catalogs] RBAC collection failed for '$($roleEntry.Key)': $($_.Exception.Message)"
                }
            }
        } else {
            $rbacCollectionMode = "Unavailable"
            $rbacFailures = 1
            $warnings.Add("Coverage gap: Identity Governance RBAC assignments could not be enumerated. $(Format-CatalogGraphError -ErrorRecord $_)")
            Write-Log -Level Debug -Message "[Catalogs] Bulk RBAC collection failed without a safe role-specific fallback: $($_.Exception.Message)"
        }
    }
    Write-Host "[+] Got $($roleAssignments.Count) catalog RBAC assignments"
    $collectionStopwatch.Stop()
    Write-Log -Level Debug -Message "[Catalogs] Collection metrics: ResourceMode=$resourceCollectionMode, RbacMode=$rbacCollectionMode, Catalogs=$($catalogs.Count), Resources=$resourceTotal, RoleAssignments=$($roleAssignments.Count), ResourceFallbackRequests=$resourceFallbackRequests, ResourceFallbackFailures=$resourceFallbackFailures, ElapsedMs=$($collectionStopwatch.ElapsedMilliseconds)"

    return [pscustomobject]@{
        IsAvailable        = $true
        IsSkipped          = $false
        RbacAvailable      = ($rbacFailures -eq 0)
        ResourcesAvailable = ($resourceFailures -eq 0)
        Warnings           = @($warnings)
        Catalogs           = @($catalogs)
        ResourcesByCatalog = $resourcesByCatalog
        RoleAssignments    = @($roleAssignments)
    }
}

function New-CatalogRbacPrincipalIndex {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$RawCatalogs)

    $index = @{}
    if ($null -eq $RawCatalogs -or -not $RawCatalogs.PSObject.Properties['RoleAssignments']) { return $index }
    $catalogLookup = @{}
    foreach ($catalog in @($RawCatalogs.Catalogs)) { $catalogLookup[[string]$catalog.id] = $catalog }

    foreach ($assignment in @($RawCatalogs.RoleAssignments)) {
        $principalId = [string]$assignment.principalId
        if ([string]::IsNullOrWhiteSpace($principalId) -and $assignment.principal) { $principalId = [string]$assignment.principal.id }
        if ([string]::IsNullOrWhiteSpace($principalId)) { continue }
        $catalog = if ($catalogLookup.ContainsKey([string]$assignment.CatalogId)) { $catalogLookup[[string]$assignment.CatalogId] } else { $null }
        $detail = [pscustomobject]@{
            AssignmentId  = [string]$assignment.id
            Role           = [string]$assignment.RoleName
            CatalogId      = [string]$assignment.CatalogId
            Catalog        = if ($catalog) { [string]$catalog.displayName } else { [string]$assignment.CatalogId }
            CatalogEnabled = [bool]($catalog -and [string]$catalog.state -eq 'published')
        }
        if (-not $index.ContainsKey($principalId)) { $index[$principalId] = [System.Collections.Generic.List[object]]::new() }
        [void]$index[$principalId].Add($detail)
    }
    return $index
}

#endregion

#region Catalog scoring and normalization helpers

function ConvertTo-CatalogPlainText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlDecode(([regex]::Replace([string]$Value, '<[^>]+>', '')))
}

function ConvertTo-CatalogDateTimeOffset {
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

function Test-CatalogActiveAccessPackageAssignment {
    param(
        [Parameter(Mandatory = $true)][object]$Assignment,
        [Parameter(Mandatory = $true)][datetimeoffset]$Now
    )

    if ([string]$Assignment.state -ine 'delivered' -or [string]$Assignment.status -ine 'Delivered') { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Assignment.expiredDateTime)) { return $false }
    if ($null -eq $Assignment.schedule -or $null -eq $Assignment.schedule.expiration) { return $false }

    $startValue = $Assignment.schedule.startDateTime
    $start = ConvertTo-CatalogDateTimeOffset -Value $startValue
    if ($null -ne $startValue -and -not [string]::IsNullOrWhiteSpace([string]$startValue)) {
        if ($null -eq $start -or $start.ToUniversalTime() -gt $Now.ToUniversalTime()) { return $false }
    }

    $expiration = $Assignment.schedule.expiration
    $expirationType = [string]$expiration.type
    if ($expirationType -ieq 'noExpiration') { return $true }
    if ($expirationType -ieq 'afterDateTime') {
        $endValue = if ($expiration.endDateTime) { $expiration.endDateTime } else { $expiration.expirationDateTime }
        $end = ConvertTo-CatalogDateTimeOffset -Value $endValue
        return ($null -ne $end -and $end.ToUniversalTime() -gt $Now.ToUniversalTime())
    }
    if ($expirationType -ieq 'afterDuration') {
        if ($null -eq $start -or [string]::IsNullOrWhiteSpace([string]$expiration.duration)) { return $false }
        try {
            $duration = [System.Xml.XmlConvert]::ToTimeSpan([string]$expiration.duration)
            return $start.Add($duration).ToUniversalTime() -gt $Now.ToUniversalTime()
        } catch {
            return $false
        }
    }
    return $false
}

function ConvertTo-CatalogTierLabel {
    param([object]$Tier)
    switch ([string]$Tier) {
        '0' { 'Tier-0' }
        '1' { 'Tier-1' }
        '2' { 'Tier-2' }
        '3' { 'Tier-3' }
        'Tier-0' { 'Tier-0' }
        'Tier-1' { 'Tier-1' }
        'Tier-2' { 'Tier-2' }
        'Tier-3' { 'Tier-3' }
        '?' { 'Uncategorized' }
        'Uncategorized' { 'Uncategorized' }
        default { '-' }
    }
}

function Get-CatalogLikelihood {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][object[]]$Assignments = @(),
        [Parameter(Mandatory = $false)][hashtable]$AllUsersBasicHT = @{},
        [Parameter(Mandatory = $false)][hashtable]$AllGroupsDetails = @{},
        [Parameter(Mandatory = $false)][hashtable]$EnterpriseApps = @{},
        [Parameter(Mandatory = $false)][hashtable]$ManagedIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentityBlueprintsPrincipals = @{}
    )

    $roleWeights = @{
        'Catalog Owner'                     = [double]3
        'Access Package Manager'            = [double]3
        'Access Package Assignment Manager' = [double]2
        'Catalog Reader'                    = [double]0
    }
    $principalContributions = @{}

    $addContribution = {
        param([string]$PrincipalId, [double]$Contribution)

        if ([string]::IsNullOrWhiteSpace($PrincipalId) -or $Contribution -le 0) { return }
        $key = $PrincipalId.Trim().ToLowerInvariant()
        if (-not $principalContributions.ContainsKey($key) -or [double]$principalContributions[$key] -lt $Contribution) {
            $principalContributions[$key] = $Contribution
        }
    }

    $getEnabledState = {
        param([object]$Object)

        if ($null -eq $Object) { return $null }
        foreach ($propertyName in @('accountEnabled','Enabled')) {
            $property = $Object.PSObject.Properties[$propertyName]
            if ($null -eq $property -or $null -eq $property.Value) { continue }
            if ($property.Value -is [bool]) { return [bool]$property.Value }
            $parsed = $false
            if ([bool]::TryParse([string]$property.Value, [ref]$parsed)) { return $parsed }
        }
        return $null
    }

    foreach ($assignment in @($Assignments)) {
        if ($null -eq $assignment) { continue }
        $roleName = [string]$assignment.RoleName
        if (-not $roleWeights.ContainsKey($roleName)) { continue }
        $roleWeight = [double]$roleWeights[$roleName]
        if ($roleWeight -le 0) { continue }

        $principal = $assignment.principal
        $principalId = [string]$assignment.principalId
        if ([string]::IsNullOrWhiteSpace($principalId) -and $principal) { $principalId = [string]$principal.id }
        if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

        if ($AllGroupsDetails.ContainsKey($principalId)) {
            $group = $AllGroupsDetails[$principalId]
            $userDetailsProperty = if ($null -ne $group) { $group.PSObject.Properties['Userdetails'] } else { $null }
            if ($null -eq $userDetailsProperty) {
                # Preserve conservative coverage when the assigned group could not be expanded.
                & $addContribution $principalId $roleWeight
                continue
            }

            foreach ($member in @($userDetailsProperty.Value)) {
                if ($null -eq $member) { continue }
                $memberId = [string]$member.Id
                if ([string]::IsNullOrWhiteSpace($memberId)) { continue }
                $memberObject = if ($AllUsersBasicHT.ContainsKey($memberId)) { $AllUsersBasicHT[$memberId] } else { $member }
                $enabled = & $getEnabledState $memberObject
                if ($enabled -ne $true) { continue }
                $userType = if ($null -ne $memberObject -and $memberObject.PSObject.Properties['UserType']) { [string]$memberObject.UserType } else { '' }
                $modifier = if ($userType -eq 'Guest') { [double]1.5 } else { [double]1 }
                & $addContribution $memberId ($roleWeight * $modifier)
            }
            continue
        }

        $principalObject = $null
        foreach ($lookup in @($AllUsersBasicHT, $ManagedIdentities, $AgentIdentities, $AgentIdentityBlueprintsPrincipals, $EnterpriseApps)) {
            if ($null -ne $lookup -and $lookup.ContainsKey($principalId)) {
                $principalObject = $lookup[$principalId]
                break
            }
        }
        if ($null -eq $principalObject) { $principalObject = $principal }

        $enabled = & $getEnabledState $principalObject
        if ($enabled -eq $false) { continue }
        $userType = if ($null -ne $principalObject -and $principalObject.PSObject.Properties['UserType']) { [string]$principalObject.UserType } else { '' }
        $modifier = if ($userType -eq 'Guest') { [double]1.5 } else { [double]1 }
        & $addContribution $principalId ($roleWeight * $modifier)
    }

    $exposure = ($principalContributions.Values | Measure-Object -Sum).Sum
    if ($null -eq $exposure) { $exposure = 0 }
    $roundedExposure = [math]::Round([double]$exposure, 0, [System.MidpointRounding]::AwayFromZero)
    return [int][math]::Max(1, $roundedExposure)
}

function Get-CatalogResourceType {
    param([string]$OriginSystem)
    switch ($OriginSystem) {
        'AadGroup' { 'Group' }
        'AadApplication' { 'Application' }
        'OAuthApplication' { 'API' }
        'SharePointOnline' { 'SharePoint' }
        'DirectoryRole' { 'EntraRole' }
        'AzureResources' { 'AzureResource' }
        'CustomDataProvidedResource' { 'CustomResource' }
        default { if ($OriginSystem -match 'Azure|Arm|Management') { 'AzureResource' } else { 'Other' } }
    }
}

function Get-CatalogExistingRoleInfo {
    param(
        [Parameter(Mandatory = $true)][object]$ResourceRoleScope,
        [Parameter(Mandatory = $false)][hashtable]$AllGroupsDetails = @{},
        [Parameter(Mandatory = $false)][hashtable]$EnterpriseApps = @{},
        [Parameter(Mandatory = $false)][hashtable]$AppRoleReferenceCache = @{}
    )

    $role = $ResourceRoleScope.role
    $scope = $ResourceRoleScope.scope
    $originSystem = if ($scope -and -not [string]::IsNullOrWhiteSpace([string]$scope.originSystem)) { [string]$scope.originSystem } else { [string]$role.originSystem }
    $resourceOriginId = if ($scope) { [string]$scope.originId } else { '' }
    $roleName = if ($role -and -not [string]::IsNullOrWhiteSpace([string]$role.displayName)) { [string]$role.displayName } else { [string]$role.originId }
    $roleDescription = if ($role) { [string]$role.description } else { '' }

    if ($originSystem -eq 'AadGroup') {
        $group = if (-not [string]::IsNullOrWhiteSpace($resourceOriginId) -and $AllGroupsDetails.ContainsKey($resourceOriginId)) { $AllGroupsDetails[$resourceOriginId] } else { $null }
        $impact = if ($group -and $null -ne $group.Impact) { [double]$group.Impact } else { 0 }
        $tierLabels = [System.Collections.Generic.List[string]]::new()
        if ($group -and -not [string]::IsNullOrWhiteSpace([string]$group.EntraMaxTier) -and [string]$group.EntraMaxTier -ne '-') { [void]$tierLabels.Add("Entra: $($group.EntraMaxTier)") }
        if ($group -and -not [string]::IsNullOrWhiteSpace([string]$group.AzureMaxTier) -and [string]$group.AzureMaxTier -ne '-') { [void]$tierLabels.Add("Azure: $($group.AzureMaxTier)") }
        return [pscustomobject]@{
            OriginSystem     = $originSystem
            ResourceOriginId = $resourceOriginId
            Type             = 'Group'
            Role             = $roleName
            TierOrCategory   = if ($tierLabels.Count -gt 0) { $tierLabels -join ' / ' } else { '-' }
            Impact           = $impact
        }
    }

    if ($originSystem -eq 'AadApplication') {
        $app = if (-not [string]::IsNullOrWhiteSpace($resourceOriginId) -and $EnterpriseApps.ContainsKey($resourceOriginId)) { $EnterpriseApps[$resourceOriginId] } else { $null }
        if (-not $app) {
            foreach ($candidate in $EnterpriseApps.Values) {
                if ([string]$candidate.AppId -eq $resourceOriginId) { $app = $candidate; break }
            }
        }
        $appImpact = if ($app -and $null -ne $app.Impact) { [double]$app.Impact } else { 0 }
        return [pscustomobject]@{
            OriginSystem     = $originSystem
            ResourceOriginId = $resourceOriginId
            Type             = 'Application'
            Role             = $roleName
            TierOrCategory   = '-'
            Impact           = [double](Get-AppRoleAssignmentImpact -RoleDisplayName $roleName -RoleDescription $roleDescription -AppImpact $appImpact)
        }
    }

    if ($originSystem -eq 'DirectoryRole') {
        $tierValue = if ($GLOBALEntraRoleRating.ContainsKey($resourceOriginId)) { $GLOBALEntraRoleRating[$resourceOriginId] } else { '?' }
        $tier = ConvertTo-CatalogTierLabel $tierValue
        $impact = switch ($tier) {
            'Tier-0' { $GLOBALImpactScore['EntraRoleTier0'] }
            'Tier-1' { $GLOBALImpactScore['EntraRoleTier1'] }
            'Tier-2' { $GLOBALImpactScore['EntraRoleTier2'] }
            'Uncategorized' { $GLOBALImpactScore['EntraRoleTier?'] }
            default { 0 }
        }
        return [pscustomobject]@{
            OriginSystem    = $originSystem
            ResourceOriginId = $resourceOriginId
            Type            = 'Entra Role'
            Role            = $roleName
            TierOrCategory  = $tier
            Impact          = [double]$impact
        }
    }

    if ($originSystem -eq 'OAuthApplication') {
        $permissionId = if ($role) { [string]$role.originId } else { '' }
        $applicationPermissionRecord = Resolve-AppRoleReference -AppRoleReferenceCache $AppRoleReferenceCache -PermissionId $permissionId -ResourceAppId $resourceOriginId
        $applicationPermission = ($null -ne $applicationPermissionRecord -or (-not [string]::IsNullOrWhiteSpace($permissionId) -and $GLOBALApiPermissionCategorizationList.ContainsKey($permissionId)))
        if ($applicationPermission) {
            $permissionType = 'API Application'
            $category = Get-APIPermissionCategory -InputPermission $permissionId -PermissionType 'application'
        } else {
            $permissionType = 'API Delegated'
            $category = Get-APIPermissionCategory -InputPermission $roleName -PermissionType 'delegated'
        }
        $permissionRecord = [pscustomobject]@{ ApiPermissionCategorization = $category }
        $impact = if ($applicationPermission) {
            (Get-ApiPermissionImpactSummary -ApplicationPermissions @($permissionRecord)).Impact
        } else {
            (Get-ApiPermissionImpactSummary -DelegatedPermissions @($permissionRecord)).Impact
        }
        return [pscustomobject]@{
            OriginSystem    = $originSystem
            ResourceOriginId = $resourceOriginId
            Type            = $permissionType
            Role            = $roleName
            TierOrCategory  = $category
            Impact          = [double]$impact
        }
    }

    if ($originSystem -eq 'SharePointOnline') {
        $impact = if ([string]::IsNullOrWhiteSpace($roleName)) {
            1
        } elseif ($roleName -match '(?i)(^|[^a-z0-9])(owner|owners|full\s*control)([^a-z0-9]|$)') {
            3
        } elseif ($roleName -match '(?i)(^|[^a-z0-9])(member|members|edit|contribute|write)([^a-z0-9]|$)') {
            2
        } else {
            1
        }
        return [pscustomobject]@{
            OriginSystem     = $originSystem
            ResourceOriginId = $resourceOriginId
            Type             = 'SharePoint'
            Role             = $roleName
            TierOrCategory   = '-'
            Impact           = [double]$impact
        }
    }

    if ($originSystem -match 'Azure|Arm|Management') {
        $roleOriginId = if ($role) { [string]$role.originId } else { '' }
        $roleDefinitionMatch = [regex]::Match($roleOriginId, '/roleDefinitions/([^/]+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $roleDefinitionId = if ($roleDefinitionMatch.Success) { $roleDefinitionMatch.Groups[1].Value } elseif ([string]::IsNullOrWhiteSpace($roleOriginId)) { '' } else { ($roleOriginId.TrimEnd('/') -split '/')[-1] }
        $tierValue = if (-not [string]::IsNullOrWhiteSpace($roleDefinitionId) -and $GLOBALAzureRoleRating.ContainsKey($roleDefinitionId)) { $GLOBALAzureRoleRating[$roleDefinitionId] } else { '?' }
        $tier = ConvertTo-CatalogTierLabel $tierValue
        $impact = switch ($tier) {
            'Tier-0' { $GLOBALImpactScore['AzureRoleTier0'] }
            'Tier-1' { $GLOBALImpactScore['AzureRoleTier1'] }
            'Tier-2' { $GLOBALImpactScore['AzureRoleTier2'] }
            'Tier-3' { $GLOBALImpactScore['AzureRoleTier3'] }
            'Uncategorized' { $GLOBALImpactScore['AzureRoleTier?'] }
            default { 0 }
        }
        return [pscustomobject]@{
            OriginSystem     = $originSystem
            ResourceOriginId = $resourceOriginId
            Type             = 'Azure Role'
            Role             = $roleName
            TierOrCategory   = $tier
            Impact           = [double]$impact
        }
    }

    return [pscustomobject]@{
        OriginSystem     = if ([string]::IsNullOrWhiteSpace($originSystem)) { 'Unknown' } else { $originSystem }
        ResourceOriginId = $resourceOriginId
        Type             = Get-CatalogResourceType -OriginSystem $originSystem
        Role             = $roleName
        TierOrCategory   = '-'
        Impact           = 0
    }
}

#endregion

#region Catalog report and assessment pipeline

function Invoke-CheckCatalogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$OutputFolder = '.',
        [Parameter(Mandatory = $true)][object]$CurrentTenant,
        [Parameter(Mandatory = $true)][string]$StartTimestamp,
        [Parameter(Mandatory = $true)][object]$RawCatalogs,
        [Parameter(Mandatory = $false)][object]$RawAccessPackages,
        [Parameter(Mandatory = $false)][hashtable]$AllUsersBasicHT = @{},
        [Parameter(Mandatory = $false)][hashtable]$AllGroupsDetails = @{},
        [Parameter(Mandatory = $false)][hashtable]$EnterpriseApps = @{},
        [Parameter(Mandatory = $false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory = $false)][hashtable]$ManagedIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentIdentityBlueprintsPrincipals = @{},
        [Parameter(Mandatory = $false)][ref]$AssessmentOut = $null,
        [Parameter(Mandatory = $false)][switch]$Csv = $false,
        [Parameter(Mandatory = $false)][switch]$ExportDataJson = $false
    )

    $title = 'Catalogs'
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($warning in @($RawCatalogs.Warnings)) { if (-not [string]::IsNullOrWhiteSpace([string]$warning)) { $warnings.Add([string]$warning) } }
    $packagesByCatalog = @{}
    $resourceRoleScopesByPackage = if ($RawAccessPackages -and $RawAccessPackages.PSObject.Properties['ResourceRoleScopesByPackage'] -and $null -ne $RawAccessPackages.ResourceRoleScopesByPackage) { $RawAccessPackages.ResourceRoleScopesByPackage } else { @{} }
    $policyEnabledById = if ($RawAccessPackages -and $RawAccessPackages.PSObject.Properties['PolicyEnabledById'] -and $null -ne $RawAccessPackages.PolicyEnabledById) { $RawAccessPackages.PolicyEnabledById } else { @{} }
    $assignmentsAvailable = [bool]($RawAccessPackages -and (-not $RawAccessPackages.PSObject.Properties['AssignmentsAvailable'] -or [bool]$RawAccessPackages.AssignmentsAvailable))
    $activeAssignmentsByPackage = @{}
    if ($assignmentsAvailable) {
        $now = [datetimeoffset]::UtcNow
        foreach ($assignment in @($RawAccessPackages.Assignments)) {
            if ($null -eq $assignment -or -not (Test-CatalogActiveAccessPackageAssignment -Assignment $assignment -Now $now)) { continue }
            $packageId = if ($assignment.accessPackage) { [string]$assignment.accessPackage.id } else { '' }
            if ([string]::IsNullOrWhiteSpace($packageId)) { continue }
            if (-not $activeAssignmentsByPackage.ContainsKey($packageId)) { $activeAssignmentsByPackage[$packageId] = 0 }
            $activeAssignmentsByPackage[$packageId]++
        }
    }
    if ($RawAccessPackages -and $RawAccessPackages.PSObject.Properties['Packages']) {
        foreach ($package in @($RawAccessPackages.Packages)) {
            $catalogId = if ($package.catalog) { [string]$package.catalog.id } else { '' }
            if ([string]::IsNullOrWhiteSpace($catalogId)) { continue }
            if (-not $packagesByCatalog.ContainsKey($catalogId)) { $packagesByCatalog[$catalogId] = [System.Collections.Generic.List[object]]::new() }
            [void]$packagesByCatalog[$catalogId].Add($package)
        }
    }

    $assignmentsByCatalog = @{}
    foreach ($assignment in @($RawCatalogs.RoleAssignments)) {
        $catalogId = [string]$assignment.CatalogId
        if (-not $assignmentsByCatalog.ContainsKey($catalogId)) { $assignmentsByCatalog[$catalogId] = [System.Collections.Generic.List[object]]::new() }
        [void]$assignmentsByCatalog[$catalogId].Add($assignment)
    }

    $tableOutput = [System.Collections.Generic.List[object]]::new()
    $allObjectDetails = [System.Collections.ArrayList]::new()
    $detailTxtBuilder = [System.Text.StringBuilder]::new()
    $assessmentCatalogsById = @{}
    $assessmentAssignments = [System.Collections.Generic.List[object]]::new()

    $catalogLookup = @{}
    foreach ($catalog in @($RawCatalogs.Catalogs)) {
        if ($null -ne $catalog -and -not [string]::IsNullOrWhiteSpace([string]$catalog.id)) {
            $catalogLookup[[string]$catalog.id] = $catalog
        }
    }
    foreach ($assignment in @($RawCatalogs.RoleAssignments)) {
        if ($null -eq $assignment) { continue }
        $principal = $assignment.principal
        $principalId = if (-not [string]::IsNullOrWhiteSpace([string]$assignment.principalId)) { [string]$assignment.principalId } elseif ($principal) { [string]$principal.id } else { '' }
        if ([string]::IsNullOrWhiteSpace($principalId)) { continue }
        $catalogId = [string]$assignment.CatalogId
        $catalog = if ($catalogLookup.ContainsKey($catalogId)) { $catalogLookup[$catalogId] } else { $null }
        $principalType = if ($principal -and $principal.PSObject.Properties['@odata.type']) { ([string]$principal.'@odata.type' -replace '^#microsoft\.graph\.','') } else { 'Unknown' }
        $principalName = if ($principal -and -not [string]::IsNullOrWhiteSpace([string]$principal.displayName)) { [string]$principal.displayName } elseif ($principal -and -not [string]::IsNullOrWhiteSpace([string]$principal.userPrincipalName)) { [string]$principal.userPrincipalName } else { $principalId }
        [void]$assessmentAssignments.Add([pscustomobject]@{
            AssignmentId  = [string]$assignment.id
            CatalogId     = $catalogId
            Catalog       = if ($catalog) { [string]$catalog.displayName } else { $catalogId }
            CatalogEnabled = [bool]($catalog -and [string]$catalog.state -eq 'published')
            Role          = [string]$assignment.RoleName
            PrincipalId   = $principalId
            PrincipalType = $principalType
            PrincipalName = $principalName
        })
    }

    foreach ($catalog in @($RawCatalogs.Catalogs)) {
        $catalogId = [string]$catalog.id
        $catalogName = if ([string]::IsNullOrWhiteSpace([string]$catalog.displayName)) { $catalogId } else { [string]$catalog.displayName }
        $resources = if ($RawCatalogs.ResourcesByCatalog.ContainsKey($catalogId)) { @($RawCatalogs.ResourcesByCatalog[$catalogId]) } else { @() }
        $assignments = if ($assignmentsByCatalog.ContainsKey($catalogId)) { @($assignmentsByCatalog[$catalogId]) } else { @() }
        $packages = if ($packagesByCatalog.ContainsKey($catalogId)) { @($packagesByCatalog[$catalogId]) } else { @() }
        $resourceRows = [System.Collections.Generic.List[object]]::new()
        $existingRoleRows = [System.Collections.Generic.List[object]]::new()
        $configuredResourceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $countedExistingGrantKeys = [System.Collections.Generic.HashSet[string]]::new()
        $existingEntraTier = '-'
        $azureTier = '-'
        $entraRoleExposureCount = @($resources | Where-Object { [string]$_.originSystem -eq 'DirectoryRole' }).Count
        $highImpactEntries = 0
        $newAPConfigurable = 0
        $directImpact = 0
        $existingAPImpact = 0
        $newAPContributionsByResourceKey = @{}
        $existingAPContributionsByGrantKey = @{}
        $assignmentManagerExistingAPContributions = @()
        $assignmentManagerImpact = 0
        $unconfiguredResourcesByKey = @{}
        $packageMetricsById = @{}

        $resourceByOriginKey = @{}
        foreach ($resource in $resources) {
            $resourceByOriginKey["$([string]$resource.originSystem)|$([string]$resource.originId)"] = $resource
        }

        foreach ($package in $packages) {
            $packageId = [string]$package.id
            $packagePolicies = @($package.assignmentPolicies)
            $enabledPolicies = 0
            foreach ($policy in $packagePolicies) {
                $policyId = [string]$policy.id
                $policyEnabled = $false
                if ($null -ne $policy.automaticRequestSettings) {
                    $policyEnabled = $true
                } elseif ($policyEnabledById -is [System.Collections.IDictionary] -and $policyEnabledById.Contains($policyId)) {
                    $policyEnabled = [bool]$policyEnabledById[$policyId]
                }
                if ($policyEnabled) { $enabledPolicies++ }
            }
            $firstPolicyId = if ($packagePolicies.Count -gt 0) { [string]$packagePolicies[0].id } else { '' }
            $packageAnchor = if ([string]::IsNullOrWhiteSpace($firstPolicyId)) { "#$packageId`_no-policy" } else { "#$packageId`_$firstPolicyId" }
            $packageLink = "<a href=AccessPackages_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html$packageAnchor>$(ConvertTo-EntraFalconHtmlText $package.displayName -DefaultValue '-')</a>"
            $roleScopes = if ($resourceRoleScopesByPackage -is [System.Collections.IDictionary] -and $resourceRoleScopesByPackage.Contains($packageId)) { @($resourceRoleScopesByPackage[$packageId]) } else { @() }
            $packageResourceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $packageGrantKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $packageImpact = 0
            $packageEntraTier = '-'
            $packageAzureTier = '-'
            foreach ($roleScope in $roleScopes) {
                $existingRole = Get-CatalogExistingRoleInfo -ResourceRoleScope $roleScope -AllGroupsDetails $AllGroupsDetails -EnterpriseApps $EnterpriseApps -AppRoleReferenceCache $AppRoleReferenceCache
                $resourceKey = "$($existingRole.OriginSystem)|$($existingRole.ResourceOriginId)"
                [void]$packageResourceKeys.Add($resourceKey)
                [void]$configuredResourceKeys.Add($resourceKey)
                $catalogResource = if ($resourceByOriginKey.ContainsKey($resourceKey)) { $resourceByOriginKey[$resourceKey] } else { $null }
                $resourceName = if ($catalogResource -and -not [string]::IsNullOrWhiteSpace([string]$catalogResource.displayName)) { [string]$catalogResource.displayName } elseif ($roleScope.scope -and -not [string]::IsNullOrWhiteSpace([string]$roleScope.scope.displayName) -and [string]$roleScope.scope.displayName -ne 'Root') { [string]$roleScope.scope.displayName } else { [string]$existingRole.ResourceOriginId }
                $resourceReport = ''
                if ([string]$existingRole.Type -eq 'Group' -and $AllGroupsDetails.ContainsKey([string]$existingRole.ResourceOriginId)) {
                    $resourceReport = "Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($existingRole.ResourceOriginId)"
                } elseif ([string]$existingRole.Type -eq 'Application') {
                    $blueprintPrincipal = if ($AgentIdentityBlueprintsPrincipals.ContainsKey([string]$existingRole.ResourceOriginId)) { $AgentIdentityBlueprintsPrincipals[[string]$existingRole.ResourceOriginId] } else { $null }
                    if (-not $blueprintPrincipal) {
                        foreach ($candidate in $AgentIdentityBlueprintsPrincipals.Values) {
                            if ([string]$candidate.AppId -eq [string]$existingRole.ResourceOriginId) { $blueprintPrincipal = $candidate; break }
                        }
                    }
                    if ($blueprintPrincipal) {
                        $resourceReport = "AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($blueprintPrincipal.Id)"
                    } else {
                        $app = if ($EnterpriseApps.ContainsKey([string]$existingRole.ResourceOriginId)) { $EnterpriseApps[[string]$existingRole.ResourceOriginId] } else { $null }
                        if (-not $app) {
                            foreach ($candidate in $EnterpriseApps.Values) {
                                if ([string]$candidate.AppId -eq [string]$existingRole.ResourceOriginId) { $app = $candidate; break }
                            }
                        }
                        if ($app) { $resourceReport = "EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)" }
                    }
                }
                $encodedResourceName = ConvertTo-EntraFalconHtmlText $resourceName -DefaultValue '-'
                if ([string]$existingRole.Type -eq 'Entra Role') {
                    $existingEntraTier = Merge-HigherTierLabel -CurrentTier $existingEntraTier -CandidateTier $existingRole.TierOrCategory
                    $packageEntraTier = Merge-HigherTierLabel -CurrentTier $packageEntraTier -CandidateTier $existingRole.TierOrCategory
                }
                if ([string]$existingRole.Type -eq 'Azure Role') {
                    $azureTier = Merge-HigherTierLabel -CurrentTier $azureTier -CandidateTier $existingRole.TierOrCategory
                    $packageAzureTier = Merge-HigherTierLabel -CurrentTier $packageAzureTier -CandidateTier $existingRole.TierOrCategory
                }
                if ([string]$existingRole.Type -eq 'Group' -and $AllGroupsDetails.ContainsKey([string]$existingRole.ResourceOriginId)) {
                    $configuredGroup = $AllGroupsDetails[[string]$existingRole.ResourceOriginId]
                    $configuredGroupEntraRoles = 0
                    $configuredGroupAzureRoles = 0
                    if ([int]::TryParse([string]$configuredGroup.EntraRoles, [ref]$configuredGroupEntraRoles) -and $configuredGroupEntraRoles -gt 0) {
                        $packageEntraTier = Merge-HigherTierLabel -CurrentTier $packageEntraTier -CandidateTier $configuredGroup.EntraMaxTier
                    }
                    if ([int]::TryParse([string]$configuredGroup.AzureRoles, [ref]$configuredGroupAzureRoles) -and $configuredGroupAzureRoles -gt 0) {
                        $packageAzureTier = Merge-HigherTierLabel -CurrentTier $packageAzureTier -CandidateTier $configuredGroup.AzureMaxTier
                    }
                }
                $roleOriginId = if ($roleScope.role -and -not [string]::IsNullOrWhiteSpace([string]$roleScope.role.originId)) { [string]$roleScope.role.originId } elseif ($roleScope.role -and -not [string]::IsNullOrWhiteSpace([string]$roleScope.role.id)) { [string]$roleScope.role.id } else { [string]$existingRole.Role }
                if ([string]::IsNullOrWhiteSpace($roleOriginId)) {
                    $roleOriginId = if (-not [string]::IsNullOrWhiteSpace([string]$roleScope.id)) { [string]$roleScope.id } else { 'unknown-role' }
                }
                $grantKey = "$resourceKey|$roleOriginId".ToLowerInvariant()
                if ($packageGrantKeys.Add($grantKey)) { $packageImpact += [double]$existingRole.Impact }
                if (-not $existingAPContributionsByGrantKey.ContainsKey($grantKey)) {
                    $existingAPContributionsByGrantKey[$grantKey] = [pscustomobject]@{
                        Kind                   = 'ExistingAP'
                        Key                    = "grant|$grantKey"
                        ResourceKey            = $resourceKey.ToLowerInvariant()
                        GrantKey               = $grantKey
                        OriginSystem           = [string]$existingRole.OriginSystem
                        OriginId               = [string]$existingRole.ResourceOriginId
                        RoleOriginId           = $roleOriginId
                        Type                   = [string]$existingRole.Type
                        Impact                 = [double]$existingRole.Impact
                        DirectConfigurableType = ([string]$existingRole.Type -in @('Group','Application','SharePoint','Azure Role','Entra Role'))
                        AccessPackageIds       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        PolicyBackedAccessPackageIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    }
                } elseif ([double]$existingRole.Impact -gt [double]$existingAPContributionsByGrantKey[$grantKey].Impact) {
                    $existingAPContributionsByGrantKey[$grantKey].Impact = [double]$existingRole.Impact
                }
                [void]$existingAPContributionsByGrantKey[$grantKey].AccessPackageIds.Add($packageId)
                if ($packagePolicies.Count -gt 0) {
                    [void]$existingAPContributionsByGrantKey[$grantKey].PolicyBackedAccessPackageIds.Add($packageId)
                }
                $impactCounted = $countedExistingGrantKeys.Add($grantKey)
                if ($impactCounted) {
                    $existingAPImpact += [double]$existingRole.Impact
                    if ([double]$existingRole.Impact -ge 100 -or [string]$existingRole.TierOrCategory -in @('Tier-0','Tier-1')) { $highImpactEntries++ }
                }
                [void]$existingRoleRows.Add([pscustomobject]@{
                    AccessPackage = $packageLink
                    Resource = if ($resourceReport) { "<a href=$resourceReport>$encodedResourceName</a>" } else { $encodedResourceName }
                    Type = [string]$existingRole.Type
                    RoleOrPermission = ConvertTo-EntraFalconHtmlText $existingRole.Role -DefaultValue '-'
                    TierOrCategory = [string]$existingRole.TierOrCategory
                    Impact = [math]::Round([double]$existingRole.Impact, 0)
                    ImpactCounted = $impactCounted
                    EnabledPolicies = $enabledPolicies
                    Policies = $packagePolicies.Count
                    _SortPackageId = $packageId
                    _SortResourceId = [string]$existingRole.ResourceOriginId
                    _SortRoleId = $roleOriginId
                })
            }
            $packageMetricsById[$packageId] = [pscustomobject]@{
                ConfiguredResources = $packageResourceKeys.Count
                ConfiguredRoles     = $packageGrantKeys.Count
                ActiveAssignments   = if ($assignmentsAvailable) { if ($activeAssignmentsByPackage.ContainsKey($packageId)) { $activeAssignmentsByPackage[$packageId] } else { 0 } } else { '-' }
                Impact              = [math]::Round([double]$packageImpact, 0)
                EntraMaxTier        = $packageEntraTier
                AzureMaxTier        = $packageAzureTier
            }
        }

        $assignmentManagerExistingAPContributions = @($existingAPContributionsByGrantKey.Values | ForEach-Object {
            $contribution = $_
            $policyBackedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($packageId in @($contribution.PolicyBackedAccessPackageIds)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$packageId)) { [void]$policyBackedIds.Add([string]$packageId) }
            }
            if ($policyBackedIds.Count -eq 0) { return }
            [pscustomobject]@{
                Kind                   = [string]$contribution.Kind
                Key                    = [string]$contribution.Key
                ResourceKey            = [string]$contribution.ResourceKey
                GrantKey               = [string]$contribution.GrantKey
                OriginSystem           = [string]$contribution.OriginSystem
                OriginId               = [string]$contribution.OriginId
                RoleOriginId           = [string]$contribution.RoleOriginId
                Type                   = [string]$contribution.Type
                Impact                 = [double]$contribution.Impact
                DirectConfigurableType = [bool]$contribution.DirectConfigurableType
                AccessPackageIds       = $policyBackedIds
                PolicyBackedAccessPackageIds = $policyBackedIds
            }
        })
        $assignmentManagerImpact = (@($assignmentManagerExistingAPContributions) | Measure-Object -Property Impact -Sum).Sum
        if ($null -eq $assignmentManagerImpact) { $assignmentManagerImpact = 0 }

        $accessPackageResourceEntries = @($resourceByOriginKey.GetEnumerator() | Where-Object {
            [string]$_.Value.originSystem -ne 'CustomDataProvidedResource'
        })
        $unusedCandidateResourceEntries = @($accessPackageResourceEntries | Where-Object {
            [string]$_.Value.originSystem -ne 'OAuthApplication'
        })
        $configuredResources = @($accessPackageResourceEntries | Where-Object { $configuredResourceKeys.Contains([string]$_.Key) }).Count
        $unconfiguredResources = @($unusedCandidateResourceEntries | Where-Object { -not $configuredResourceKeys.Contains([string]$_.Key) }).Count
        $privilegedCatalogResources = @($resources | Where-Object { [string]$_.originSystem -in @('DirectoryRole','OAuthApplication') })
        $dormantPrivileged = @($privilegedCatalogResources | Where-Object { -not $configuredResourceKeys.Contains("$([string]$_.originSystem)|$([string]$_.originId)") }).Count
        $apiPermissionCatalogResources = @($resources | Where-Object { [string]$_.originSystem -eq 'OAuthApplication' })
        $catalogResourcesNote = if ($apiPermissionCatalogResources.Count -gt 0) {
            'Note: API permissions cannot be added to a new access package solely through Identity Governance catalog-scoped RBAC. Their impact is therefore assessed only when they are configured in an existing access package. Entra ID roles are included in the direct impact because they can be added via the Microsoft Graph API.'
        } else {
            $null
        }

        foreach ($resource in $resources) {
            $originSystem = [string]$resource.originSystem
            $originId = [string]$resource.originId
            $type = Get-CatalogResourceType -OriginSystem $originSystem
            $resourceName = if ([string]::IsNullOrWhiteSpace([string]$resource.displayName)) { $originId } else { [string]$resource.displayName }
            $resourceReport = ''
            $resourceImpact = 0
            $resolvedGroup = $null
            if ($type -eq 'Group' -and $AllGroupsDetails.ContainsKey($originId)) {
                $resolvedGroup = $AllGroupsDetails[$originId]
                $resourceName = [string]$resolvedGroup.DisplayName
                $resourceReport = "Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$originId"
                $resourceImpact = [double]$resolvedGroup.Impact
            } elseif ($type -eq 'Application') {
                $app = if ($EnterpriseApps.ContainsKey($originId)) { $EnterpriseApps[$originId] } else { $null }
                if (-not $app) { foreach ($candidate in $EnterpriseApps.Values) { if ([string]$candidate.AppId -eq $originId) { $app = $candidate; break } } }
                $appImpact = 0
                if ($app) {
                    $resourceName = [string]$app.DisplayName
                    $resourceReport = "EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)"
                    $appImpact = [double]$app.Impact
                }
                foreach ($appRole in @($resource.roles)) {
                    $roleImpact = Get-AppRoleAssignmentImpact `
                        -RoleDisplayName ([string]$appRole.displayName) `
                        -RoleDescription ([string]$appRole.description) `
                        -AppImpact $appImpact
                    if ([double]$roleImpact -gt $resourceImpact) { $resourceImpact = [double]$roleImpact }
                }
            }

            $resourceEntraTier = '-'
            $resourceAzureTier = '-'
            if ($resolvedGroup) {
                $groupEntraRoleCount = 0
                if ([int]::TryParse([string]$resolvedGroup.EntraRoles, [ref]$groupEntraRoleCount) -and $groupEntraRoleCount -gt 0) {
                    $entraRoleExposureCount += $groupEntraRoleCount
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$resolvedGroup.EntraMaxTier)) {
                    $resourceEntraTier = [string]$resolvedGroup.EntraMaxTier
                    $existingEntraTier = Merge-HigherTierLabel -CurrentTier $existingEntraTier -CandidateTier $resourceEntraTier
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$resolvedGroup.AzureMaxTier)) {
                    $resourceAzureTier = [string]$resolvedGroup.AzureMaxTier
                    $azureTier = Merge-HigherTierLabel -CurrentTier $azureTier -CandidateTier $resourceAzureTier
                }
            }
            if ($type -eq 'EntraRole') {
                $tierValue = if ($GLOBALEntraRoleRating.ContainsKey($originId)) { $GLOBALEntraRoleRating[$originId] } else { '?' }
                $resourceEntraTier = ConvertTo-CatalogTierLabel $tierValue
                $existingEntraTier = Merge-HigherTierLabel -CurrentTier $existingEntraTier -CandidateTier $resourceEntraTier
                $resourceImpact = switch ($resourceEntraTier) {
                    'Tier-0' { [double]$GLOBALImpactScore['EntraRoleTier0'] }
                    'Tier-1' { [double]$GLOBALImpactScore['EntraRoleTier1'] }
                    'Tier-2' { [double]$GLOBALImpactScore['EntraRoleTier2'] }
                    'Uncategorized' { [double]$GLOBALImpactScore['EntraRoleTier?'] }
                    default { 0 }
                }
            }
            if ($type -eq 'AzureResource') {
                # An onboarded Azure resource can be configured with a Tier-0 RBAC role such as Owner.
                $resourceAzureTier = 'Tier-0'
                $azureTier = 'Tier-0'
                $resourceImpact = [double]$GLOBALImpactScore['AzureRoleTier0']
            }
            if ($type -eq 'SharePoint') { $resourceImpact = 3 }
            if ($type -in @('Group','Application','SharePoint','AzureResource','EntraRole')) {
                $newAPConfigurable++
                $directImpact += $resourceImpact
                if ($resourceImpact -ge 100 -or $resourceAzureTier -in @('Tier-0','Tier-1')) { $highImpactEntries++ }

                $resourceKey = "$originSystem|$originId".ToLowerInvariant()
                if (-not $newAPContributionsByResourceKey.ContainsKey($resourceKey)) {
                    $newAPContributionsByResourceKey[$resourceKey] = [pscustomobject]@{
                        Kind                   = 'NewAP'
                        Key                    = "resource|$resourceKey"
                        ResourceKey            = $resourceKey
                        GrantKey               = ''
                        OriginSystem           = $originSystem
                        OriginId               = $originId
                        RoleOriginId           = ''
                        Type                   = $type
                        Impact                 = [double]$resourceImpact
                        DirectConfigurableType = $true
                        AccessPackageIds       = @()
                    }
                } elseif ([double]$resourceImpact -gt [double]$newAPContributionsByResourceKey[$resourceKey].Impact) {
                    $newAPContributionsByResourceKey[$resourceKey].Impact = [double]$resourceImpact
                }
            }

            $encodedName = ConvertTo-EntraFalconHtmlText $resourceName -DefaultValue '-'
            $resourceKey = "$originSystem|$originId"
            $configuredInAccessPackage = $configuredResourceKeys.Contains($resourceKey)
            $isAccessPackageResource = ($type -ne 'CustomResource')
            $isUnusedFindingCandidate = ($type -notin @('CustomResource','API'))
            if ($isUnusedFindingCandidate -and -not $configuredInAccessPackage) {
                $normalizedResourceKey = $resourceKey.ToLowerInvariant()
                if (-not $unconfiguredResourcesByKey.ContainsKey($normalizedResourceKey)) {
                    $unconfiguredResourcesByKey[$normalizedResourceKey] = [pscustomobject]@{
                        Resource     = $resourceName
                        Type         = $type
                        OriginSystem = $originSystem
                        OriginId     = $originId
                    }
                }
            }
            [void]$resourceRows.Add([pscustomobject]@{
                Resource = if ($resourceReport) { "<a href=$resourceReport>$encodedName</a>" } else { $encodedName }
                Type = $type
                OriginId = $originId
                ConfiguredInAP = if ($isAccessPackageResource) { $configuredInAccessPackage } else { '-' }
                DirectImpact = if ($type -in @('Group','Application','SharePoint','AzureResource','EntraRole')) { [math]::Round([double]$resourceImpact, 0) } else { '-' }
                EntraMaxTier = $resourceEntraTier
                AzureMaxTier = $resourceAzureTier
            })
        }

        $exposurePath = if ($newAPConfigurable -gt 0 -and $existingRoleRows.Count -gt 0) {
            'New AP + existing AP'
        } elseif ($newAPConfigurable -gt 0) {
            'New AP'
        } elseif ($existingRoleRows.Count -gt 0) {
            'Existing AP'
        } else {
            'None'
        }

        $managerExistingAPImpact = (@($existingRoleRows) | Where-Object {
            $_.ImpactCounted -and [string]$_.Type -notin @('Group','Application','SharePoint','Azure Role','Entra Role')
        } | Measure-Object Impact -Sum).Sum
        if ($null -eq $managerExistingAPImpact) { $managerExistingAPImpact = 0 }
        $catalogManagerImpact = [double]$directImpact + [double]$managerExistingAPImpact
        $catalogImpact = [math]::Max([double]$catalogManagerImpact, [double]$assignmentManagerImpact)

        $catalogWarnings = [System.Collections.Generic.List[string]]::new()
        $hasCatalogManager = @($assignments | Where-Object { [string]$_.RoleName -in @('Catalog Owner','Access Package Manager') }).Count -gt 0
        $hasAssignmentManager = @($assignments | Where-Object { [string]$_.RoleName -eq 'Access Package Assignment Manager' }).Count -gt 0
        $catalogManagerCanGrantHighImpact = $hasCatalogManager -and (
            @($newAPContributionsByResourceKey.Values | Where-Object { [double]$_.Impact -ge 100 }).Count -gt 0 -or
            @($existingAPContributionsByGrantKey.Values | Where-Object { -not [bool]$_.DirectConfigurableType -and [double]$_.Impact -ge 100 }).Count -gt 0
        )
        $assignmentManagerCanGrantHighImpact = $hasAssignmentManager -and (
            @($assignmentManagerExistingAPContributions | Where-Object { [double]$_.Impact -ge 100 }).Count -gt 0
        )
        if ($catalogManagerCanGrantHighImpact -or $assignmentManagerCanGrantHighImpact) {
            [void]$catalogWarnings.Add('Catalog RBAC can grant high-impact access')
        }

        $guestRbacAssigned = $false
        foreach ($assignment in $assignments) {
            $principal = $assignment.principal
            $principalId = if (-not [string]::IsNullOrWhiteSpace([string]$assignment.principalId)) { [string]$assignment.principalId } elseif ($principal) { [string]$principal.id } else { '' }
            if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

            if ($AllUsersBasicHT.ContainsKey($principalId)) {
                if ([string]$AllUsersBasicHT[$principalId].userType -ieq 'Guest') {
                    $guestRbacAssigned = $true
                    break
                }
            } elseif ($principal -and [string]$principal.userType -ieq 'Guest') {
                $guestRbacAssigned = $true
                break
            } elseif ($AllGroupsDetails.ContainsKey($principalId)) {
                foreach ($member in @($AllGroupsDetails[$principalId].Userdetails)) {
                    $memberId = if ($member.PSObject.Properties['Id']) { [string]$member.Id } elseif ($member.PSObject.Properties['id']) { [string]$member.id } else { '' }
                    if (-not [string]::IsNullOrWhiteSpace($memberId) -and $AllUsersBasicHT.ContainsKey($memberId) -and [string]$AllUsersBasicHT[$memberId].userType -ieq 'Guest') {
                        $guestRbacAssigned = $true
                        break
                    }
                }
                if ($guestRbacAssigned) { break }
            }
        }
        if ($guestRbacAssigned) {
            [void]$catalogWarnings.Add('Catalog RBAC is assigned to a guest')
        }
        $catalogWarningText = $catalogWarnings -join ' / '

        if ($RawCatalogs.RbacAvailable) {
            $catalogLikelihood = Get-CatalogLikelihood `
                -Assignments $assignments `
                -AllUsersBasicHT $AllUsersBasicHT `
                -AllGroupsDetails $AllGroupsDetails `
                -EnterpriseApps $EnterpriseApps `
                -ManagedIdentities $ManagedIdentities `
                -AgentIdentities $AgentIdentities `
                -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals
            $catalogRisk = [double]$catalogImpact * [double]$catalogLikelihood
        } else {
            $catalogLikelihood = '-'
            $catalogRisk = '-'
        }

        $rbacRows = foreach ($assignment in $assignments) {
            $principal = $assignment.principal
            $principalId = if ($principal) { [string]$principal.id } else { [string]$assignment.principalId }
            $principalName = if ($principal -and -not [string]::IsNullOrWhiteSpace([string]$principal.displayName)) { [string]$principal.displayName } elseif ($principal -and -not [string]::IsNullOrWhiteSpace([string]$principal.userPrincipalName)) { [string]$principal.userPrincipalName } else { $principalId }
            $principalType = if ($principal -and $principal.PSObject.Properties['@odata.type']) { ([string]$principal.'@odata.type' -replace '^#microsoft\.graph\.','') } else { 'Unknown' }
            $principalReport = ''
            if ($AllUsersBasicHT.ContainsKey($principalId)) { $principalType = 'User'; $principalReport = "Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            elseif ($AllGroupsDetails.ContainsKey($principalId)) { $principalType = 'Group'; $principalReport = "Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            elseif ($ManagedIdentities.ContainsKey($principalId)) { $principalType = 'Managed Identity'; $principalReport = "ManagedIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            elseif ($AgentIdentities.ContainsKey($principalId)) { $principalType = 'Agent Identity'; $principalReport = "AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            elseif ($AgentIdentityBlueprintsPrincipals.ContainsKey($principalId)) { $principalType = 'Blueprint Principal'; $principalReport = "AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            elseif ($EnterpriseApps.ContainsKey($principalId)) { $principalType = 'Enterprise Application'; $principalReport = "EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId" }
            $encodedPrincipal = ConvertTo-EntraFalconHtmlText $principalName -DefaultValue '-'
            $abusePath = switch ([string]$assignment.RoleName) {
                { $_ -in @('Catalog Owner','Access Package Manager') } { $exposurePath; break }
                'Access Package Assignment Manager' { if ($assignmentManagerExistingAPContributions.Count -gt 0) { 'Existing policy-backed AP assignments only' } else { 'No existing assignment policy path' }; break }
                'Catalog Reader' { 'Read only'; break }
                default { 'Unknown' }
            }
            $rbacImpact = switch ([string]$assignment.RoleName) {
                { $_ -in @('Catalog Owner','Access Package Manager') } { $catalogManagerImpact; break }
                'Access Package Assignment Manager' { $assignmentManagerImpact; break }
                'Catalog Reader' { 0; break }
                default { 0 }
            }
            [pscustomobject]@{
                Principal = if ($principalReport) { "<a href=$principalReport>$encodedPrincipal</a>" } else { $encodedPrincipal }
                Type = $principalType
                Role = [string]$assignment.RoleName
                Impact = [math]::Round([double]$rbacImpact, 0)
                AbusePath = $abusePath
            }
        }

        $showPackageEntraMaxTier = @($packageMetricsById.Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.EntraMaxTier) -and [string]$_.EntraMaxTier -ne '-' }).Count -gt 0
        $showPackageAzureMaxTier = @($packageMetricsById.Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.AzureMaxTier) -and [string]$_.AzureMaxTier -ne '-' }).Count -gt 0
        $packageRows = foreach ($package in $packages) {
            $packageId = [string]$package.id
            $packagePolicies = @($package.assignmentPolicies)
            $firstPolicyId = if ($packagePolicies.Count -gt 0) { [string]$packagePolicies[0].id } else { '' }
            $packageAnchor = if ([string]::IsNullOrWhiteSpace($firstPolicyId)) { "#$packageId`_no-policy" } else { "#$packageId`_$firstPolicyId" }
            $metrics = if ($packageMetricsById.ContainsKey($packageId)) { $packageMetricsById[$packageId] } else { $null }
            $packageRow = [pscustomobject][ordered]@{
                AccessPackage = "<a href=AccessPackages_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html$packageAnchor>$(ConvertTo-EntraFalconHtmlText $package.displayName -DefaultValue '-')</a>"
                Hidden = [bool]$package.isHidden
                ConfiguredResources = if ($metrics) { $metrics.ConfiguredResources } else { 0 }
                ConfiguredRoles = if ($metrics) { $metrics.ConfiguredRoles } else { 0 }
                Policies = $packagePolicies.Count
                ActiveAssignments = if ($metrics) { $metrics.ActiveAssignments } elseif ($assignmentsAvailable) { 0 } else { '-' }
            }
            if ($showPackageEntraMaxTier) { $packageRow | Add-Member -NotePropertyName EntraMaxTier -NotePropertyValue $(if ($metrics) { $metrics.EntraMaxTier } else { '-' }) }
            if ($showPackageAzureMaxTier) { $packageRow | Add-Member -NotePropertyName AzureMaxTier -NotePropertyValue $(if ($metrics) { $metrics.AzureMaxTier } else { '-' }) }
            $packageRow | Add-Member -NotePropertyName Impact -NotePropertyValue $(if ($metrics) { $metrics.Impact } else { 0 })
            $packageRow
        }

        $sortedResourceRows = @($resourceRows | Sort-Object `
            @{ Expression = { [string]$_.Type }; Ascending = $true }, `
            @{ Expression = { if ([bool]$_.ConfiguredInAP) { 1 } else { 0 } }; Ascending = $true }, `
            @{ Expression = {
                $impactValue = [double]0
                if ([double]::TryParse([string]$_.DirectImpact, [ref]$impactValue)) { $impactValue } else { [double]::NegativeInfinity }
            }; Descending = $true }, `
            @{ Expression = { ConvertTo-CatalogPlainText $_.Resource }; Ascending = $true }, `
            @{ Expression = { [string]$_.OriginId }; Ascending = $true })

        $sortedExistingRoleRows = @($existingRoleRows | Sort-Object `
            @{ Expression = { ConvertTo-CatalogPlainText $_.AccessPackage }; Ascending = $true }, `
            @{ Expression = { [double]$_.Impact }; Descending = $true }, `
            @{ Expression = { [string]$_.Type }; Ascending = $true }, `
            @{ Expression = { ConvertTo-CatalogPlainText $_.Resource }; Ascending = $true }, `
            @{ Expression = { ConvertTo-CatalogPlainText $_.RoleOrPermission }; Ascending = $true }, `
            @{ Expression = { [string]$_._SortPackageId }; Ascending = $true }, `
            @{ Expression = { [string]$_._SortResourceId }; Ascending = $true }, `
            @{ Expression = { [string]$_._SortRoleId }; Ascending = $true } |
            Select-Object AccessPackage,Resource,Type,RoleOrPermission,TierOrCategory,Impact,ImpactCounted,EnabledPolicies,Policies)

        $catalogInformation = [pscustomobject]@{
            Catalog = ConvertTo-EntraFalconHtmlText $catalogName -DefaultValue '-'
            CatalogId = $catalogId
            Description = ConvertTo-EntraFalconHtmlText $catalog.description -DefaultValue '-'
            Enabled = [bool]([string]$catalog.state -eq 'published')
            Type = [string]$catalog.catalogType
            ExternallyVisible = [bool]$catalog.isExternallyVisible
            AccessPackages = $packages.Count
            CatalogResources = $resources.Count
            NewAPConfigurable = $newAPConfigurable
            ConfiguredResources = $configuredResources
            UnconfiguredResources = $unconfiguredResources
            ConfiguredRoleScopes = $existingRoleRows.Count
            CatalogRBAC = if ($RawCatalogs.RbacAvailable) { $assignments.Count } else { '-' }
            EntraMaxTier = $existingEntraTier
            AzureMaxTier = $azureTier
            Impact = [math]::Round([double]$catalogImpact, 0)
            Likelihood = $catalogLikelihood
            Risk = if ($catalogRisk -is [string]) { $catalogRisk } else { [math]::Round([double]$catalogRisk, 0) }
            Warnings = $catalogWarningText
        }

        [void]$allObjectDetails.Add([pscustomobject]@{
            'Object Name' = $catalogName
            'Object ID' = $catalogId
            'Catalog Information' = $catalogInformation
            'Identity Governance RBAC Assignments' = @($rbacRows)
            'Catalog Resources' = @($sortedResourceRows)
            'Catalog Resources Note' = $catalogResourcesNote
            'Resource Roles in Existing Access Packages' = @($sortedExistingRoleRows)
            'Access Packages' = @($packageRows)
        })

        [void]$detailTxtBuilder.AppendLine("Catalog: $catalogName ($catalogId)")
        [void]$detailTxtBuilder.AppendLine(($catalogInformation | Format-List | Out-String))
        if (@($rbacRows).Count -gt 0) { [void]$detailTxtBuilder.AppendLine((@($rbacRows) | ForEach-Object { [pscustomobject]@{ Principal=ConvertTo-CatalogPlainText $_.Principal; Type=$_.Type; Role=$_.Role; Impact=$_.Impact; AbusePath=$_.AbusePath } } | Format-Table | Out-String -Width 512)) }
        if ($sortedResourceRows.Count -gt 0) { [void]$detailTxtBuilder.AppendLine((@($sortedResourceRows) | ForEach-Object { [pscustomobject]@{ Resource=ConvertTo-CatalogPlainText $_.Resource; Type=$_.Type; OriginId=$_.OriginId; ConfiguredInAP=$_.ConfiguredInAP; DirectImpact=$_.DirectImpact; EntraMaxTier=$_.EntraMaxTier; AzureMaxTier=$_.AzureMaxTier } } | Format-Table | Out-String -Width 512)) }
        if ($catalogResourcesNote) { [void]$detailTxtBuilder.AppendLine($catalogResourcesNote) }
        if ($sortedExistingRoleRows.Count -gt 0) { [void]$detailTxtBuilder.AppendLine((@($sortedExistingRoleRows) | ForEach-Object { [pscustomobject]@{ AccessPackage=ConvertTo-CatalogPlainText $_.AccessPackage; Resource=ConvertTo-CatalogPlainText $_.Resource; Type=$_.Type; RoleOrPermission=$_.RoleOrPermission; TierOrCategory=$_.TierOrCategory; Impact=$_.Impact; ImpactCounted=$_.ImpactCounted; EnabledPolicies=$_.EnabledPolicies; Policies=$_.Policies } } | Format-Table | Out-String -Width 512)) }

        $counts = @{}
        foreach ($roleName in (Get-CatalogRbacRoleDefinitions).Keys) { $counts[$roleName] = @($assignments | Where-Object { [string]$_.RoleName -eq $roleName }).Count }
        [void]$tableOutput.Add([pscustomobject]@{
            Id = $catalogId
            Catalog = $catalogName
            CatalogLink = "<a href=#$catalogId>$(ConvertTo-EntraFalconHtmlText $catalogName -DefaultValue '-')</a>"
            Enabled = [bool]([string]$catalog.state -eq 'published')
            ExternallyVisible = [bool]$catalog.isExternallyVisible
            AccessPackages = $packages.Count
            CatalogResources = $resources.Count
            NewAPConfigurable = $newAPConfigurable
            DirectImpact = [math]::Round([double]$directImpact, 0)
            ConfiguredResources = $configuredResources
            ConfiguredRoleScopes = $existingRoleRows.Count
            ExistingAPImpact = [math]::Round([double]$existingAPImpact, 0)
            UnconfiguredResources = $unconfiguredResources
            DormantPrivileged = $dormantPrivileged
            Groups = @($resources | Where-Object { $_.originSystem -eq 'AadGroup' }).Count
            Applications = @($resources | Where-Object { $_.originSystem -eq 'AadApplication' }).Count
            API = @($resources | Where-Object { $_.originSystem -eq 'OAuthApplication' }).Count
            SharePoint = @($resources | Where-Object { $_.originSystem -eq 'SharePointOnline' }).Count
            EntraRoles = $entraRoleExposureCount
            EntraMaxTier = $existingEntraTier
            AzureResources = @($resources | Where-Object { $_.originSystem -match 'Azure|Arm|Management' }).Count
            AzureMaxTier = $azureTier
            HighImpactEntries = $highImpactEntries
            CatalogRBAC = if ($RawCatalogs.RbacAvailable) { $assignments.Count } else { '-' }
            Owners = $counts['Catalog Owner']
            PackageManagers = $counts['Access Package Manager']
            AssignmentManagers = $counts['Access Package Assignment Manager']
            Readers = $counts['Catalog Reader']
            Impact = [math]::Round([double]$catalogImpact, 0)
            Likelihood = $catalogLikelihood
            Risk = if ($catalogRisk -is [string]) { $catalogRisk } else { [math]::Round([double]$catalogRisk, 0) }
            Warnings = $catalogWarningText
            ResourceDetails = @($sortedResourceRows)
            ExistingAPRoleDetails = @($sortedExistingRoleRows)
            RbacDetails = @($rbacRows)
        })

        $assessmentCatalogsById[$catalogId] = [pscustomobject]@{
            CatalogId               = $catalogId
            Catalog                 = $catalogName
            CatalogEnabled          = [bool]([string]$catalog.state -eq 'published')
            CatalogResources        = $resources.Count
            AccessPackages          = $packages.Count
            UnconfiguredResources   = $unconfiguredResourcesByKey.Count
            UnconfiguredResourceDetails = @($unconfiguredResourcesByKey.Values | Sort-Object Type,Resource,OriginId)
            Warnings                = $catalogWarningText
            RolePotentialImpactByRole = @{
                'Catalog Owner'                    = [math]::Round([double]$catalogManagerImpact)
                'Access Package Manager'           = [math]::Round([double]$catalogManagerImpact)
                'Access Package Assignment Manager' = [math]::Round([double]$assignmentManagerImpact)
                'Catalog Reader'                   = 0
            }
            AssignmentManagerExistingAPImpact = [math]::Round([double]$assignmentManagerImpact)
            NewAPContributions      = @($newAPContributionsByResourceKey.Values)
            ExistingAPContributions = @($existingAPContributionsByGrantKey.Values)
            AssignmentManagerExistingAPContributions = @($assignmentManagerExistingAPContributions)
        }
    }

    $catalogDataAvailable = $true
    if ($RawCatalogs.PSObject.Properties['IsAvailable']) {
        $catalogDataAvailable = [bool]$RawCatalogs.IsAvailable
    }
    $rbacAvailable = $catalogDataAvailable -and [bool]$RawCatalogs.RbacAvailable
    $accessPackageDataAvailable = $false
    if ($null -ne $RawAccessPackages) {
        $rawAccessPackagesAvailable = if ($RawAccessPackages.PSObject.Properties['IsAvailable']) { [bool]$RawAccessPackages.IsAvailable } else { $true }
        $rawAccessPackagesSkipped = if ($RawAccessPackages.PSObject.Properties['IsSkipped']) { [bool]$RawAccessPackages.IsSkipped } else { $false }
        $resourceRoleScopesAvailable = if ($RawAccessPackages.PSObject.Properties['ResourceRoleScopesAvailable']) { [bool]$RawAccessPackages.ResourceRoleScopesAvailable } else { $rawAccessPackagesAvailable }
        $accessPackageDataAvailable = $rawAccessPackagesAvailable -and -not $rawAccessPackagesSkipped -and $resourceRoleScopesAvailable
    }
    $accessPackageAssignmentsAvailable = if ($null -ne $RawAccessPackages -and $RawAccessPackages.PSObject.Properties['AssignmentsAvailable']) {
        $rawAccessPackagesAvailable -and -not $rawAccessPackagesSkipped -and [bool]$RawAccessPackages.AssignmentsAvailable
    } else {
        $accessPackageDataAvailable
    }
    $resourcesAvailable = if ($RawCatalogs.PSObject.Properties['ResourcesAvailable']) { [bool]$RawCatalogs.ResourcesAvailable } else { $catalogDataAvailable }
    $assessmentStatus = if (-not $rbacAvailable) {
        'Unavailable'
    } elseif (-not $accessPackageDataAvailable -or -not $accessPackageAssignmentsAvailable -or -not $resourcesAvailable) {
        'Partial'
    } elseif ($assessmentCatalogsById.Count -eq 0) {
        'NoCatalogs'
    } else {
        'Complete'
    }
    $catalogAssessment = [pscustomobject]@{
        IsAvailable                = $catalogDataAvailable
        RbacAvailable              = $rbacAvailable
        ResourcesAvailable         = $resourcesAvailable
        AccessPackageDataAvailable = $accessPackageDataAvailable
        AccessPackageAssignmentsAvailable = $accessPackageAssignmentsAvailable
        UnconfiguredResourceDetailsAvailable = ($catalogDataAvailable -and $resourcesAvailable -and $accessPackageDataAvailable)
        Status                     = $assessmentStatus
        Warnings                   = @($warnings)
        CatalogsById               = $assessmentCatalogsById
        Assignments                = @($assessmentAssignments)
    }
    if ($null -ne $AssessmentOut) {
        $AssessmentOut.Value = $catalogAssessment
    }

    if (-not $GlobalAuditSummary.ContainsKey('Catalogs')) { $GlobalAuditSummary.Catalogs = @{} }
    $GlobalAuditSummary.Catalogs.Count = $tableOutput.Count
    $GlobalAuditSummary.Catalogs.CatalogResources = (@($tableOutput) | Measure-Object CatalogResources -Sum).Sum
    $GlobalAuditSummary.Catalogs.NewAPConfigurable = (@($tableOutput) | Measure-Object NewAPConfigurable -Sum).Sum
    $GlobalAuditSummary.Catalogs.ConfiguredResources = (@($tableOutput) | Measure-Object ConfiguredResources -Sum).Sum
    $GlobalAuditSummary.Catalogs.ConfiguredRoleScopes = (@($tableOutput) | Measure-Object ConfiguredRoleScopes -Sum).Sum
    $GlobalAuditSummary.Catalogs.UnconfiguredResources = (@($tableOutput) | Measure-Object UnconfiguredResources -Sum).Sum
    $GlobalAuditSummary.Catalogs.DormantPrivileged = (@($tableOutput) | Measure-Object DormantPrivileged -Sum).Sum
    $GlobalAuditSummary.Catalogs.RbacAssignments = @($RawCatalogs.RoleAssignments).Count

    $mainTableHtml = @($tableOutput | Sort-Object Risk -Descending | Select-Object @{Name='Catalog';Expression={$_.CatalogLink}},Enabled,ExternallyVisible,AccessPackages,CatalogResources,NewAPConfigurable,ConfiguredResources,UnconfiguredResources,ConfiguredRoleScopes,Groups,Applications,API,SharePoint,EntraRoles,EntraMaxTier,AzureResources,AzureMaxTier,HighImpactEntries,CatalogRBAC,Owners,PackageManagers,AssignmentManagers,Readers,Impact,Likelihood,Risk,Warnings)
    $mainTableExport = @($tableOutput | Select-Object Catalog,Enabled,ExternallyVisible,AccessPackages,CatalogResources,NewAPConfigurable,ConfiguredResources,UnconfiguredResources,ConfiguredRoleScopes,Groups,Applications,API,SharePoint,EntraRoles,EntraMaxTier,AzureResources,AzureMaxTier,HighImpactEntries,CatalogRBAC,Owners,PackageManagers,AssignmentManagers,Readers,Impact,Likelihood,Risk,Warnings)
    $mainTableJson = if ($mainTableHtml.Count -eq 0) { '[]' } else { $mainTableHtml | ConvertTo-Json -Depth 6 -Compress }
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'
    $detailsJson = if ($allObjectDetails.Count -eq 0) { '[]' } else { $allObjectDetails | ConvertTo-Json -Depth 9 -Compress }
    $detailsHtml = @'
    <h2>Catalog Details</h2>
    <div class="details-toolbar">
        <button id="toggle-expand">Expand All</button>
        <div class="details-search-wrapper"><div class="details-search-box"><input type="text" id="details-search" placeholder="Search details..." /></div><button id="details-search-clear" style="display:none" title="Clear search">&#x2715;</button></div>
        <div id="details-info" class="details-info">Showing 0-0 of 0 entries</div>
    </div>
    <div id="object-container"></div>
    <script id="object-data" type="application/json">
'@ + "`n" + $detailsJson + "`n" + '</script>'

    $headerHtml = @"
<div id="loadingOverlay"><div class="spinner"></div><div class="loading-text">Loading data...</div></div>
<h2>Entitlement Management Catalogs Overview</h2>
"@
    $reportDisplayName = "Entitlement Management Catalogs Enumeration (BETA)"
    $headerTxt = "$reportDisplayName`r`nExecuted in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)`r`nExecuted at: $StartTimestamp`r`nExecution Warnings = $($warnings -join ' / ')`r`n"
    $txtPath = Join-Path $OutputFolder "$($title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt"
    $htmlPath = Join-Path $OutputFolder "$($title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"
    $headerTxt | Out-File -Width 512 -FilePath $txtPath
    $mainTableExport | Format-Table | Out-File -Width 512 -FilePath $txtPath -Append
    $detailTxtBuilder.ToString() | Out-File -Width 512 -FilePath $txtPath -Append
    if ($Csv) { $mainTableExport | Export-Csv -Path (Join-Path $OutputFolder "$($title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv") -NoTypeInformation }
    if ($ExportDataJson) { Export-EntraFalconDataJson -OutputFolder $OutputFolder -DatasetName 'Catalogs' -Data $tableOutput | Out-Null }
    Set-GlobalReportManifest -CurrentReportKey 'Catalogs' -CurrentReportName $reportDisplayName -Warnings $warnings
    $report = ConvertTo-HTML -Body "$headerHtml $mainTableHTML" -Head ("<title>EF - Catalogs (BETA)</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript -PreContent $detailsHtml
    $report | Out-File $htmlPath
    Write-Host "[+] Details of $($tableOutput.Count) catalogs stored in output files: $OutputFolder\$($title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    return $tableOutput
}

#endregion

Export-ModuleMember -Function Get-CatalogsRawData,New-CatalogRbacPrincipalIndex,Invoke-CheckCatalogs
