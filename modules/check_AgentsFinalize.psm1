function Invoke-CheckAgentsFinalize {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][string]$OutputFolder = ".",
        [Parameter(Mandatory = $true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory = $true)][String[]]$StartTimestamp,
        [Parameter(Mandatory = $true)][hashtable]$AllUsersBasicHT,
        [Parameter(Mandatory = $true)][hashtable]$Users,
        [Parameter(Mandatory = $true)][hashtable]$AgentIdentities,
        [Parameter(Mandatory = $true)][hashtable]$AgentIdentityBlueprintsPrincipals,
        [Parameter(Mandatory = $true)][hashtable]$AgentIdentityBlueprints,
        [Parameter(Mandatory = $false)][switch]$Csv = $false
    )

    function Add-UniqueWarningText {
        param(
            [string]$ExistingWarnings,
            [string]$NewWarning
        )

        if ([string]::IsNullOrWhiteSpace($NewWarning)) {
            return $ExistingWarnings
        }

        $parts = @()
        if (-not [string]::IsNullOrWhiteSpace($ExistingWarnings)) {
            $parts = @($ExistingWarnings -split ' / ' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        if ($parts -notcontains $NewWarning) {
            $parts += $NewWarning
        }
        return ($parts -join ' / ')
    }

    function Get-AgentUserLookup {
        param([hashtable]$Users)

        if ($null -eq $Users) {
            return @{}
        }

        $lookup = @{}
        foreach ($entry in $Users.GetEnumerator()) {
            if (-not $entry.Value.Agent) {
                continue
            }

            $impactValue = if ($null -ne $entry.Value.Impact) { [math]::Round([double]$entry.Value.Impact) } else { 0 }
            $lookup[$entry.Key] = [pscustomobject]@{
                Id       = $entry.Key
                UPN      = $entry.Value.UPN
                Enabled  = $entry.Value.Enabled
                Impact   = $impactValue
                Warnings = $entry.Value.Warnings
            }
        }

        return $lookup
    }

    function Get-PrincipalLookupByBlueprintId {
        param([hashtable]$AgentIdentityBlueprintsPrincipals)

        $lookup = @{}
        foreach ($principal in $AgentIdentityBlueprintsPrincipals.Values) {
            foreach ($key in @("$($principal.AppId)".Trim(), "$($principal.Id)".Trim())) {
                if ([string]::IsNullOrWhiteSpace($key)) {
                    continue
                }
                if (-not $lookup.ContainsKey($key)) {
                    $lookup[$key] = $principal
                }
            }
        }

        return $lookup
    }

    function Get-AgentIdentityLookupByBlueprintId {
        param([hashtable]$AgentIdentities)

        $lookup = @{}
        foreach ($agentIdentity in $AgentIdentities.Values) {
            $key = "$($agentIdentity.AgentIdentityBlueprintId)".Trim()
            if ([string]::IsNullOrWhiteSpace($key)) {
                continue
            }
            if (-not $lookup.ContainsKey($key)) {
                $lookup[$key] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$lookup[$key].Add($agentIdentity)
        }

        return $lookup
    }

    function Get-PrincipalLookupByAppId {
        param([hashtable]$AgentIdentityBlueprintsPrincipals)

        $lookup = @{}
        foreach ($principal in $AgentIdentityBlueprintsPrincipals.Values) {
            $key = "$($principal.AppId)".Trim()
            if ([string]::IsNullOrWhiteSpace($key)) {
                continue
            }
            if (-not $lookup.ContainsKey($key)) {
                $lookup[$key] = [System.Collections.Generic.List[object]]::new()
            }
            [void]$lookup[$key].Add($principal)
        }

        return $lookup
    }

    function Get-BlueprintLookupByAppId {
        param([hashtable]$AgentIdentityBlueprints)

        $lookup = @{}
        foreach ($blueprint in $AgentIdentityBlueprints.Values) {
            $key = "$($blueprint.AppId)".Trim()
            if ([string]::IsNullOrWhiteSpace($key)) {
                continue
            }
            if (-not $lookup.ContainsKey($key)) {
                $lookup[$key] = $blueprint
            }
        }

        return $lookup
    }

    function Get-AgentOwnerRawType {
        param($Owner)

        if ($null -eq $Owner) {
            return $null
        }

        if ($Owner.PSObject.Properties['RawType']) {
            return "$($Owner.RawType)".Trim()
        }

        $typeName = "$($Owner.Type)".Trim().ToLowerInvariant()
        switch ($typeName) {
            'agentidentity' { return '#microsoft.graph.agentIdentity' }
            'agentidentityblueprintprincipal' { return '#microsoft.graph.agentIdentityBlueprintPrincipal' }
            'serviceprincipal' { return '#microsoft.graph.servicePrincipal' }
            'managedidentity' { return '#microsoft.graph.servicePrincipal' }
        }

        return '#microsoft.graph.servicePrincipal'
    }

    function Resolve-FinalizedAgentNonUserOwner {
        param(
            $Owner,
            [Object[]]$CurrentTenant,
            [hashtable]$AgentIdentities,
            [hashtable]$AgentIdentityBlueprintsPrincipals
        )

        $ownerId = "$($Owner.Id)".Trim()
        if ([string]::IsNullOrWhiteSpace($ownerId)) {
            return $null
        }

        $rawType = Get-AgentOwnerRawType -Owner $Owner
        switch ($rawType) {
            '#microsoft.graph.agentIdentity' {
                if (-not $AgentIdentities.ContainsKey($ownerId)) {
                    return $null
                }
                $agentIdentity = $AgentIdentities[$ownerId]
                return [pscustomobject]@{
                    Id                   = $agentIdentity.Id
                    DisplayName          = $agentIdentity.DisplayName
                    Enabled              = $agentIdentity.Enabled
                    Foreign              = $agentIdentity.Foreign
                    PublisherName        = if ([string]::IsNullOrWhiteSpace($agentIdentity.PublisherName)) { "-" } else { $agentIdentity.PublisherName }
                    Type                 = 'AgentIdentity'
                    TargetReport         = 'AgentIdentities'
                    OwnersCount          = if ($null -ne $agentIdentity.Owners) { $agentIdentity.Owners } else { "-" }
                    ServicePrincipalType = 'Application'
                }
            }
            '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                if (-not $AgentIdentityBlueprintsPrincipals.ContainsKey($ownerId)) {
                    return $null
                }
                $principal = $AgentIdentityBlueprintsPrincipals[$ownerId]
                return [pscustomobject]@{
                    Id                   = $principal.Id
                    DisplayName          = $principal.DisplayName
                    Enabled              = $principal.Enabled
                    Foreign              = $principal.Foreign
                    PublisherName        = if ([string]::IsNullOrWhiteSpace($principal.PublisherName)) { "-" } else { $principal.PublisherName }
                    Type                 = 'AgentIdentityBlueprintPrincipal'
                    TargetReport         = 'AgentIdentityBlueprintsPrincipals'
                    OwnersCount          = if ($null -ne $principal.Owners) { $principal.Owners } else { "-" }
                    ServicePrincipalType = 'Application'
                }
            }
            default {
                $servicePrincipalType = if ($Owner.PSObject.Properties['ServicePrincipalType']) { $Owner.ServicePrincipalType } elseif ($Owner.PSObject.Properties['servicePrincipalType']) { $Owner.servicePrincipalType } else { 'Application' }
                $appOwnerOrganizationId = if ($Owner.PSObject.Properties['appOwnerOrganizationId']) { "$($Owner.appOwnerOrganizationId)".Trim() } elseif ($Owner.PSObject.Properties['AppOwnerOrganizationId']) { "$($Owner.AppOwnerOrganizationId)".Trim() } else { '' }
                if ($Owner.PSObject.Properties['Foreign']) {
                    $foreign = [bool]$Owner.Foreign
                } else {
                    $foreign = ($servicePrincipalType -ne 'ManagedIdentity' -and -not [string]::IsNullOrWhiteSpace($appOwnerOrganizationId) -and $appOwnerOrganizationId -ne $CurrentTenant.id)
                }
                $publisherName = if ($Owner.PSObject.Properties['PublisherName']) { $Owner.PublisherName } elseif ($Owner.PSObject.Properties['publisherName']) { $Owner.publisherName } else { '-' }
                $enabled = if ($Owner.PSObject.Properties['Enabled']) { $Owner.Enabled } elseif ($Owner.PSObject.Properties['accountEnabled']) { $Owner.accountEnabled } else { $null }
                $displayName = if ($Owner.PSObject.Properties['DisplayName']) { $Owner.DisplayName } elseif ($Owner.PSObject.Properties['displayName']) { $Owner.displayName } else { $ownerId }
                $targetReport = if ($servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentities' } else { 'EnterpriseApps' }
                $type = if ($servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
                $ownersCount = if ($Owner.PSObject.Properties['OwnersCount']) { $Owner.OwnersCount } else { "-" }

                return [pscustomobject]@{
                    Id                   = $ownerId
                    DisplayName          = $displayName
                    Enabled              = $enabled
                    Foreign              = $foreign
                    PublisherName        = if ([string]::IsNullOrWhiteSpace($publisherName)) { "-" } else { $publisherName }
                    Type                 = $type
                    TargetReport         = $targetReport
                    OwnersCount          = if ($null -ne $ownersCount) { $ownersCount } else { "-" }
                    ServicePrincipalType = $servicePrincipalType
                }
            }
        }
    }

    function Get-AgentOwnerLink {
        param(
            $ResolvedOwner,
            [string]$StartTimestamp,
            [string]$EscapedTenantName
        )

        switch ($ResolvedOwner.TargetReport) {
            'AgentIdentities' { return "<a href=AgentIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($ResolvedOwner.Id)>$($ResolvedOwner.DisplayName)</a>" }
            'AgentIdentityBlueprintsPrincipals' { return "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$EscapedTenantName.html#$($ResolvedOwner.Id)>$($ResolvedOwner.DisplayName)</a>" }
            'ManagedIdentities' { return "<a href=ManagedIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($ResolvedOwner.Id)>$($ResolvedOwner.DisplayName)</a>" }
            default { return "<a href=EnterpriseApps_$($StartTimestamp)_$EscapedTenantName.html#$($ResolvedOwner.Id)>$($ResolvedOwner.DisplayName)</a>" }
        }
    }

    function Normalize-AgentOwnerWarnings {
        param([string]$Warnings)

        if ([string]::IsNullOrWhiteSpace($Warnings)) {
            return $Warnings
        }

        $parts = @($Warnings -split ' / ' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $normalized = foreach ($part in $parts) {
            switch ($part) {
                'Foreign SP as owner!' { 'Foreign non-user owner!' }
                'Internal SP as owner' { 'Internal non-user owner' }
                default { $part }
            }
        }

        return ($normalized | Select-Object -Unique) -join ' / '
    }

    function Get-AgentReportWarnings {
        param(
            [Parameter(Mandatory = $true)][string]$ReportKey
        )

        $warningList = @()
        switch ($ReportKey) {
            'AgentIdentities' {
                if (-not ($GLOBALAzurePsChecks)) {
                    if ($GLOBALAzureIamWarningText) {
                        $warningList += $GLOBALAzureIamWarningText
                    } else {
                        $warningList += "Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to agent identities are therefore missing from this report."
                    }
                }
            }
        }

        return @($warningList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    }

    function Get-ApiSeverityWarningText {
        param(
            [hashtable]$Counts,
            [string]$Suffix,
            [switch]$IncludeMedium
        )

        $severities = [System.Collections.ArrayList]::new()
        if (($Counts['Dangerous'] | ForEach-Object { [int]$_ }) -gt 0) { [void]$severities.Add('dangerous') }
        if (($Counts['High'] | ForEach-Object { [int]$_ }) -gt 0) { [void]$severities.Add('high') }
        if ($IncludeMedium -and (($Counts['Medium'] | ForEach-Object { [int]$_ }) -gt 0)) { [void]$severities.Add('medium') }

        $severityParts = @($severities | Select-Object -Unique)
        if ($severityParts.Count -eq 0) {
            return $null
        }

        if ($severityParts.Count -gt 1) {
            $joined = (($severityParts[0..($severityParts.Count - 2)] -join ", ") + " and " + $severityParts[-1])
            return "Known $joined $($Suffix)s!"
        }

        return "Known $($severityParts[0]) $Suffix!"
    }

    function Get-AgentInheritanceWarningText {
        param(
            [hashtable]$Counts,
            [string]$PermissionTypeLabel,
            [switch]$Assumed,
            [switch]$IncludeMedium
        )

        if ([string]::IsNullOrWhiteSpace($PermissionTypeLabel)) {
            return $null
        }

        $severities = [System.Collections.ArrayList]::new()
        if (($Counts['Dangerous'] | ForEach-Object { [int]$_ }) -gt 0) { [void]$severities.Add('dangerous') }
        if (($Counts['High'] | ForEach-Object { [int]$_ }) -gt 0) { [void]$severities.Add('high') }
        if ($IncludeMedium -and (($Counts['Medium'] | ForEach-Object { [int]$_ }) -gt 0)) { [void]$severities.Add('medium') }

        $severityParts = @($severities | Select-Object -Unique)
        if ($severityParts.Count -eq 0) {
            return $null
        }

        if ($severityParts.Count -gt 1) {
            $joined = (($severityParts[0..($severityParts.Count - 2)] -join ", ") + " and " + $severityParts[-1])
        } else {
            $joined = $severityParts[0]
        }

        $permissionText = if ($severityParts.Count -gt 1) { "API permissions ($PermissionTypeLabel)" } else { "API permission ($PermissionTypeLabel)" }
        $inheritanceText = if ($Assumed) { 'may be inherited by child Agent Identities' } else { 'inherited by child Agent Identities' }

        return "Known $joined $permissionText $inheritanceText!"
    }

    function Get-BlueprintInheritablePermissionLookup {
        param($Blueprint)

        $lookup = @{
            Application = @{}
            Delegated   = @{}
        }

        if ($null -eq $Blueprint) {
            return $lookup
        }

        foreach ($permission in @($Blueprint.InheritablePermissionsDetails)) {
            if ($null -eq $permission) { continue }

            $permissionType = [string]$permission.PermissionType
            $resourceAppId = [string]$permission.ResourceAppId
            if ([string]::IsNullOrWhiteSpace($permissionType) -or [string]::IsNullOrWhiteSpace($resourceAppId)) {
                continue
            }

            if (-not $lookup.ContainsKey($permissionType)) {
                $lookup[$permissionType] = @{}
            }

            $valueSet = @{}
            foreach ($value in @($permission.PermissionValues)) {
                $normalizedValue = "$value".Trim().ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($normalizedValue)) {
                    continue
                }
                $valueSet[$normalizedValue] = $true
            }

            $lookup[$permissionType][$resourceAppId] = @{
                Kind   = if ([string]::IsNullOrWhiteSpace([string]$permission.Kind)) { 'none' } else { [string]$permission.Kind }
                Values = $valueSet
            }
        }

        return $lookup
    }

    function Test-BlueprintPermissionInheritance {
        param(
            [hashtable]$BlueprintRuleLookup,
            [string]$PermissionType,
            [string]$ResourceAppId,
            [string]$PermissionValue
        )

        if (-not $BlueprintRuleLookup -or
            [string]::IsNullOrWhiteSpace($PermissionType) -or
            [string]::IsNullOrWhiteSpace($ResourceAppId)) {
            return [pscustomobject]@{
                Allowed  = $false
                RuleKind = 'missing'
            }
        }

        if (-not $BlueprintRuleLookup.ContainsKey($PermissionType) -or
            -not $BlueprintRuleLookup[$PermissionType].ContainsKey($ResourceAppId)) {
            return [pscustomobject]@{
                Allowed  = $false
                RuleKind = 'missing'
            }
        }

        $rule = $BlueprintRuleLookup[$PermissionType][$ResourceAppId]
        $kind = if ([string]::IsNullOrWhiteSpace([string]$rule.Kind)) { 'none' } else { [string]$rule.Kind }
        $normalizedKind = $kind.ToLowerInvariant()
        $normalizedPermissionValue = "$PermissionValue".Trim().ToLowerInvariant()

        switch ($normalizedKind) {
            'allallowed' {
                return [pscustomobject]@{
                    Allowed  = $true
                    RuleKind = 'allAllowed'
                }
            }
            'enumerated' {
                return [pscustomobject]@{
                    Allowed  = (-not [string]::IsNullOrWhiteSpace($normalizedPermissionValue) -and $rule.Values.ContainsKey($normalizedPermissionValue))
                    RuleKind = 'enumerated'
                }
            }
            default {
                return [pscustomobject]@{
                    Allowed  = $false
                    RuleKind = $kind
                }
            }
        }
    }

    function Get-ApiPermissionIdentity {
        param(
            $Permission,
            [string]$PermissionType
        )

        if ($PermissionType -eq 'Application') {
            $resourceKey = if ($Permission.PSObject.Properties['ResourceAppId'] -and -not [string]::IsNullOrWhiteSpace([string]$Permission.ResourceAppId)) { [string]$Permission.ResourceAppId } elseif ($Permission.PSObject.Properties['ApiName']) { [string]$Permission.ApiName } else { '-' }
            $permissionKey = if ($Permission.PSObject.Properties['PermissionId'] -and -not [string]::IsNullOrWhiteSpace([string]$Permission.PermissionId)) { [string]$Permission.PermissionId } else { [string]$Permission.ApiPermission }
        } else {
            $resourceKey = if ($Permission.PSObject.Properties['ResourceAppId'] -and -not [string]::IsNullOrWhiteSpace([string]$Permission.ResourceAppId)) { [string]$Permission.ResourceAppId } elseif ($Permission.PSObject.Properties['APIName']) { [string]$Permission.APIName } elseif ($Permission.PSObject.Properties['ApiName']) { [string]$Permission.ApiName } else { '-' }
            $permissionKey = if ($Permission.PSObject.Properties['Scope']) { [string]$Permission.Scope } else { [string]$Permission.Permission }
        }

        [pscustomobject]@{
            ResourceKey   = if ([string]::IsNullOrWhiteSpace($resourceKey)) { '-' } else { $resourceKey }
            PermissionKey = if ([string]::IsNullOrWhiteSpace($permissionKey)) { '-' } else { $permissionKey }
        }
    }

    function Test-AgentInheritableApplicationPermission {
        param($Permission)

        if ($null -eq $Permission) {
            return $false
        }

        $permissionId = if ($Permission.PSObject.Properties['PermissionId']) { [string]$Permission.PermissionId } else { '' }
        $permissionName = if ($Permission.PSObject.Properties['ApiPermission']) { [string]$Permission.ApiPermission } else { '' }

        $nonInheritablePermissionIds = @(
            '4aa6e624-eee0-40ab-bdd8-f9639038a614', # AgentIdUser.ReadWrite.IdentityParentedBy
            '4c390976-b2b7-42e0-9187-c6be3bead001'  # AgentIdentity.CreateAsManager
        )
        $nonInheritablePermissionNames = @(
            'AgentIdUser.ReadWrite.IdentityParentedBy',
            'AgentIdentity.CreateAsManager'
        )

        if ($nonInheritablePermissionIds -contains $permissionId) {
            return $false
        }
        if ($nonInheritablePermissionNames -contains $permissionName) {
            return $false
        }

        return $true
    }

    function Get-BlueprintPrincipalEffectiveApplicationPermissions {
        param($BlueprintPrincipal)

        $localCategorizationOrder = @{
            'Dangerous'     = 1
            'High'          = 2
            'Medium'        = 3
            'Low'           = 4
            'Uncategorized' = 5
        }
        $effectivePermissionIds = @{
            '4aa6e624-eee0-40ab-bdd8-f9639038a614' = 'Effective on blueprint principal: can create/manage parented agent users'
            '4c390976-b2b7-42e0-9187-c6be3bead001' = 'Effective on blueprint principal: can create agent identities as manager (auto assigned)'
        }
        $effectivePermissionNames = @{
            'AgentIdUser.ReadWrite.IdentityParentedBy' = 'Effective on blueprint principal: can create/manage parented agent users'
            'AgentIdentity.CreateAsManager' = 'Effective on blueprint principal: can create agent identities as manager (auto assigned)'
        }

        $results = [System.Collections.ArrayList]::new()
        $seen = @{}
        foreach ($permission in @($BlueprintPrincipal.AppApiPermission)) {
            if ($null -eq $permission) {
                continue
            }

            $permissionId = if ($permission.PSObject.Properties['PermissionId']) { [string]$permission.PermissionId } else { '' }
            $permissionName = if ($permission.PSObject.Properties['ApiPermission']) { [string]$permission.ApiPermission } else { '' }
            $reason = if ($effectivePermissionIds.ContainsKey($permissionId)) {
                $effectivePermissionIds[$permissionId]
            } elseif ($effectivePermissionNames.ContainsKey($permissionName)) {
                $effectivePermissionNames[$permissionName]
            } else {
                $null
            }

            if ([string]::IsNullOrWhiteSpace($reason)) {
                continue
            }

            $resourceAppId = if ($permission.PSObject.Properties['ResourceAppId']) { [string]$permission.ResourceAppId } else { '' }
            $key = "APP|$resourceAppId|$permissionId|$permissionName"
            if ($seen.ContainsKey($key)) {
                continue
            }

            $seen[$key] = $true
            $category = if (-not [string]::IsNullOrWhiteSpace($permissionId)) {
                Get-APIPermissionCategory -InputPermission $permissionId -PermissionType "application"
            } else {
                $permission.ApiPermissionCategorization
            }
            if ([string]::IsNullOrWhiteSpace([string]$category) -or $category -eq 'ApiPermissionLookupError') {
                $category = if ([string]::IsNullOrWhiteSpace([string]$permission.ApiPermissionCategorization)) { 'Uncategorized' } else { [string]$permission.ApiPermissionCategorization }
            }
            [void]$results.Add([pscustomobject]@{
                ApiName                       = $permission.ApiName
                ResourceAppId                 = $resourceAppId
                ResourceId                    = if ($permission.PSObject.Properties['ResourceId']) { [string]$permission.ResourceId } else { '' }
                PermissionId                  = $permissionId
                ApiPermission                 = $permissionName
                ApiPermissionCategorization   = $category
                ApiPermissionDisplayName      = if ($permission.PSObject.Properties['ApiPermissionDisplayName']) { $permission.ApiPermissionDisplayName } else { $permission.ApiPermissionDisplayname }
                ApiPermissionDescription      = if ($permission.PSObject.Properties['ApiPermissionDescription']) { $permission.ApiPermissionDescription } else { '-' }
                Reason                        = $reason
            })
        }

        return @($results | Sort-Object ApiName, @{ Expression = {
            $sortCategory = if ([string]::IsNullOrWhiteSpace([string]$_.ApiPermissionCategorization)) { 'Uncategorized' } else { [string]$_.ApiPermissionCategorization }
            if ($localCategorizationOrder.ContainsKey($sortCategory)) { $localCategorizationOrder[$sortCategory] } else { 99 }
        }; Ascending = $true }, ApiPermission)
    }

    function Test-BlueprintPrincipalEffectiveApplicationPermission {
        param($Permission)

        if ($null -eq $Permission) {
            return $false
        }

        $permissionId = if ($Permission.PSObject.Properties['PermissionId']) { [string]$Permission.PermissionId } else { '' }
        $permissionName = if ($Permission.PSObject.Properties['ApiPermission']) { [string]$Permission.ApiPermission } else { '' }

        return (
            $permissionId -in @('4aa6e624-eee0-40ab-bdd8-f9639038a614', '4c390976-b2b7-42e0-9187-c6be3bead001') -or
            $permissionName -in @('AgentIdUser.ReadWrite.IdentityParentedBy', 'AgentIdentity.CreateAsManager')
        )
    }

    function New-EffectivePermissionSourceRecord {
        param(
            $Permission,
            [string]$PermissionType,
            [string]$OriginType,
            [string]$OriginObjectDisplayName,
            [string]$OriginObjectId,
            [string]$OriginReport,
            [string]$RuleKind
        )

        $apiName         = if ($PermissionType -eq 'Application') { $Permission.ApiName } elseif ($Permission.PSObject.Properties['APIName']) { $Permission.APIName } else { $Permission.ApiName }
        $permissionValue = if ($PermissionType -eq 'Application') { $Permission.ApiPermission } else { $Permission.Scope }
        $consentType     = if ($PermissionType -eq 'Delegated' -and $Permission.PSObject.Properties['ConsentType']) { [string]$Permission.ConsentType } else { '' }
        $principal       = if ($PermissionType -eq 'Delegated' -and $Permission.PSObject.Properties['Principal'])   { [string]$Permission.Principal }   else { '' }

        [pscustomobject]@{
            PermissionType          = $PermissionType
            ApiName                 = if ([string]::IsNullOrWhiteSpace([string]$apiName))         { '-' } else { [string]$apiName }
            Permission              = if ([string]::IsNullOrWhiteSpace([string]$permissionValue)) { '-' } else { [string]$permissionValue }
            Category                = if ([string]::IsNullOrWhiteSpace([string]$Permission.ApiPermissionCategorization)) { 'Uncategorized' } else { [string]$Permission.ApiPermissionCategorization }
            OriginType              = $OriginType
            OriginObjectDisplayName = if ([string]::IsNullOrWhiteSpace($OriginObjectDisplayName)) { '-' } else { $OriginObjectDisplayName }
            OriginObjectId          = if ([string]::IsNullOrWhiteSpace($OriginObjectId))          { '-' } else { $OriginObjectId }
            OriginReport            = if ([string]::IsNullOrWhiteSpace($OriginReport))            { '-' } else { $OriginReport }
            RuleKind                = if ([string]::IsNullOrWhiteSpace($RuleKind))                { '-' } else { $RuleKind }
            ConsentType             = $consentType
            Principal               = $principal
        }
    }

    function Resolve-AgentEffectiveApiPermissions {
        param(
            $AgentIdentity,
            $ParentPrincipal,
            $ParentBlueprint
        )

        $appMap = @{}
        $delegatedMap = @{}
        $sourceRows = [System.Collections.ArrayList]::new()
        $warnings = [System.Collections.ArrayList]::new()
        $blueprintRuleLookup = Get-BlueprintInheritablePermissionLookup -Blueprint $ParentBlueprint

        $addPermission = {
            param(
                $Permission,
                [string]$PermissionType,
                [string]$OriginType,
                [string]$OriginObjectDisplayName,
                [string]$OriginObjectId,
                [string]$OriginReport,
                [string]$RuleKind
            )

            if ($null -eq $Permission) {
                return
            }

            $identity = Get-ApiPermissionIdentity -Permission $Permission -PermissionType $PermissionType
            $key = if ($PermissionType -eq 'Application') {
                "APP|$($identity.ResourceKey)|$($identity.PermissionKey)"
            } else {
                "DEL|$($identity.ResourceKey)|$($identity.PermissionKey)"
            }

            $sourceRow = New-EffectivePermissionSourceRecord -Permission $Permission -PermissionType $PermissionType -OriginType $OriginType -OriginObjectDisplayName $OriginObjectDisplayName -OriginObjectId $OriginObjectId -OriginReport $OriginReport -RuleKind $RuleKind
            [void]$sourceRows.Add($sourceRow)

            if ($PermissionType -eq 'Application') {
                if (-not $appMap.ContainsKey($key)) {
                    $appMap[$key] = $Permission
                }
            } else {
                if (-not $delegatedMap.ContainsKey($key)) {
                    $delegatedMap[$key] = $Permission
                }
            }
        }

        foreach ($permission in @($AgentIdentity.AppApiPermission)) {
            & $addPermission $permission 'Application' 'Direct' $AgentIdentity.DisplayName $AgentIdentity.Id 'AgentIdentities' 'direct'
        }
        foreach ($permission in @($AgentIdentity.ApiDelegatedDetails)) {
            & $addPermission $permission 'Delegated' 'Direct' $AgentIdentity.DisplayName $AgentIdentity.Id 'AgentIdentities' 'direct'
        }

        if ($null -ne $ParentPrincipal) {
            if ($null -ne $ParentBlueprint) {
                foreach ($permission in @($ParentPrincipal.AppApiPermission)) {
                    if (-not (Test-AgentInheritableApplicationPermission -Permission $permission)) {
                        continue
                    }
                    $resourceAppId = if ($permission.PSObject.Properties['ResourceAppId']) { [string]$permission.ResourceAppId } else { '' }
                    $permissionId = if ($permission.PSObject.Properties['PermissionId']) { [string]$permission.PermissionId } else { '' }
                    $decision = Test-BlueprintPermissionInheritance -BlueprintRuleLookup $blueprintRuleLookup -PermissionType 'Application' -ResourceAppId $resourceAppId -PermissionValue $permissionId
                    if ($decision.Allowed) {
                        & $addPermission $permission 'Application' 'ConfirmedInherited' $ParentPrincipal.DisplayName $ParentPrincipal.Id 'AgentIdentityBlueprintsPrincipals' $decision.RuleKind
                    }
                }

                foreach ($permission in @($ParentPrincipal.ApiDelegatedDetails)) {
                    $resourceAppId = if ($permission.PSObject.Properties['ResourceAppId']) { [string]$permission.ResourceAppId } else { '' }
                    $scope = if ($permission.PSObject.Properties['Scope']) { [string]$permission.Scope } else { '' }
                    $decision = Test-BlueprintPermissionInheritance -BlueprintRuleLookup $blueprintRuleLookup -PermissionType 'Delegated' -ResourceAppId $resourceAppId -PermissionValue $scope
                    if ($decision.Allowed) {
                        & $addPermission $permission 'Delegated' 'ConfirmedInherited' $ParentPrincipal.DisplayName $ParentPrincipal.Id 'AgentIdentityBlueprintsPrincipals' $decision.RuleKind
                    }
                }
            } elseif ([bool]$ParentPrincipal.Foreign) {
                $countBefore = $appMap.Count + $delegatedMap.Count
                foreach ($permission in @($ParentPrincipal.AppApiPermission)) {
                    if (-not (Test-AgentInheritableApplicationPermission -Permission $permission)) {
                        continue
                    }
                    & $addPermission $permission 'Application' 'AssumedInherited' $ParentPrincipal.DisplayName $ParentPrincipal.Id 'AgentIdentityBlueprintsPrincipals' 'assumed-foreign'
                }
                foreach ($permission in @($ParentPrincipal.ApiDelegatedDetails)) {
                    & $addPermission $permission 'Delegated' 'AssumedInherited' $ParentPrincipal.DisplayName $ParentPrincipal.Id 'AgentIdentityBlueprintsPrincipals' 'assumed-foreign'
                }
                if ($appMap.Count + $delegatedMap.Count -gt $countBefore) {
                    [void]$warnings.Add("Inherited API permissions assumed")
                }
            } else {
                [void]$warnings.Add("Data inconsistency: parent blueprint not found; blueprint-principal API permissions were not inherited")
            }
        }

        $effectiveApp = @($appMap.Values | Sort-Object ApiName, ApiPermission)
        $effectiveDelegated = @($delegatedMap.Values | Sort-Object APIName, Scope)
        $effectiveSources = @(
            $sourceRows | Sort-Object `
                PermissionType, `
                ApiName, `
                @{ Expression = {
                        switch ([string]$_.Category) {
                            'Dangerous'     { 1 }
                            'High'          { 2 }
                            'Medium'        { 3 }
                            'Low'           { 4 }
                            'Uncategorized' { 5 }
                            default         { 6 }
                        }
                    }
                }, `
                Category, `
                Permission, `
                OriginType, `
                OriginObjectDisplayName
        )
        $summary = Get-ApiPermissionImpactSummary -ApplicationPermissions $effectiveApp -DelegatedPermissions $effectiveDelegated -DeduplicateApplication -DeduplicateDelegated

        [pscustomobject]@{
            EffectiveAppApiPermission   = @($effectiveApp)
            EffectiveApiDelegatedDetails = @($effectiveDelegated)
            EffectiveApiPermissionSources = @($effectiveSources)
            Summary                     = $summary
            Warnings                    = @($warnings | Select-Object -Unique)
        }
    }

    function Get-ApiPermissionReferenceData {
        param(
            [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Items = @(),
            [Parameter(Mandatory = $false)][string]$PermissionProperty = 'AppApiPermission'
        )

        $categorizationOrder = @{
            'Dangerous'     = 1
            'High'          = 2
            'Medium'        = 3
            'Low'           = 4
            'Uncategorized' = 5
        }

        $rows = foreach ($item in @($Items)) {
            foreach ($permission in @($item.$PermissionProperty)) {
                [pscustomobject]@{
                    ApiName                  = $permission.ApiName
                    Category                 = $permission.ApiPermissionCategorization
                    ApiPermission            = $permission.ApiPermission
                    ApiPermissionDescription = $permission.ApiPermissionDescription
                    CategorySort             = if ($categorizationOrder.ContainsKey($permission.ApiPermissionCategorization)) {
                        $categorizationOrder[$permission.ApiPermissionCategorization]
                    } else {
                        99
                    }
                }
            }
        }

        return @(
            $rows |
            Sort-Object ApiName, CategorySort, ApiPermission, ApiPermissionDescription -Unique |
            Select-Object ApiName, Category, ApiPermission, ApiPermissionDescription
        )
    }

    function Get-BlueprintSecretsAppendixData {
        param(
            [Parameter(Mandatory = $false)][object[]]$Items = @()
        )

        return @(
            foreach ($item in @($Items)) {
                foreach ($credential in @($item.AppCredentialsDetails)) {
                    if ($credential.Type -ne 'Secret') {
                        continue
                    }

                    [pscustomobject]@{
                        AppName       = $item.DisplayName
                        DisplayName   = $credential.DisplayName
                        StartDateTime = $credential.StartDateTime
                        EndDateTime   = $credential.EndDateTime
                        Expired       = $credential.Expired
                    }
                }
            }
        ) | Sort-Object AppName, DisplayName, EndDateTime
    }

    function New-ReportFileSet {
        param(
            [string]$Title,
            [string]$ReportKey,
            [string]$ReportName,
            [string]$HtmlTitle,
            [Object[]]$CurrentTenant,
            [String[]]$StartTimestamp,
            [string]$OutputFolder,
            [object[]]$TableOutput,
            [object]$MainTable,
            [System.Collections.ArrayList]$AllObjectDetailsHTML,
            [string]$DetailOutputTxt,
            [string[]]$TxtColumns,
            [string[]]$WarningList = @(),
            [string]$AppendixTxt = "",
            [string]$AppendixHtml = "",
            [hashtable[]]$AdditionalCsvExports = @(),
            [switch]$Csv = $false
        )

        if ([string]::IsNullOrWhiteSpace($HtmlTitle)) {
            $HtmlTitle = $ReportName
        }

        $MainTableJson = $MainTable | ConvertTo-Json -Depth 5 -Compress
        $MainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $MainTableJson + "`n" + '</script>'
        $AllObjectDetailsJson = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
        $ObjectsDetailsHEAD = @"
    <h2>$Title Details</h2>
    <div class="details-toolbar">
        <button id="toggle-expand">Expand All</button>
        <div class="details-search-wrapper">
            <div class="details-search-box">
                <input type="text" id="details-search" placeholder="Search details..." />
                <button class="details-search-help-btn" type="button" title="Search help">?</button>
                <div class="details-search-help-popover hidden">
                    <div class="search-help-title">Search guide</div>
                    <ul class="search-help-list">
                        <li><code>term</code> — substring match anywhere in object</li>
                        <li><code>!term</code> — exclude objects containing term</li>
                        <li><code>=value</code> — exact field value match</li>
                        <li><code>^prefix</code> — field value starts with</li>
                        <li><code>$suffix</code> — field value ends with</li>
                        <li><code>a && b</code> — both must match</li>
                        <li><code>a || b</code> — either must match</li>
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
"@
        $AllObjectDetailsBlock = $ObjectsDetailsHEAD + "`n" + $AllObjectDetailsJson + "`n" + '</script>'

        Set-GlobalReportManifest -CurrentReportKey $ReportKey -CurrentReportName $ReportName -Warnings $WarningList

        $headerTXT = "************************************************************************************************************************
$ReportName
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningList -join ' / ')
************************************************************************************************************************
"

        $headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

        $txtPath = "$OutputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt"
        $csvPath = "$OutputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv"
        $htmlPath = "$OutputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

        $headerTXT | Out-File -Width 512 -FilePath $txtPath -Append
        $TableOutput | Format-Table -Property $TxtColumns | Out-File -Width 512 $txtPath -Append
        if ($Csv) {
            $TableOutput | Select-Object $TxtColumns | Export-Csv -Path $csvPath -NoTypeInformation
        }
        $DetailOutputTxt | Out-File $txtPath -Append
        if (-not [string]::IsNullOrWhiteSpace($AppendixTxt)) {
            $AppendixTxt | Out-File $txtPath -Append
        }

        if ($Csv) {
            foreach ($csvExport in @($AdditionalCsvExports)) {
                if ($null -eq $csvExport -or -not $csvExport.ContainsKey('Path') -or -not $csvExport.ContainsKey('Data')) {
                    continue
                }
                $exportRows = @($csvExport['Data'])
                if ($exportRows.Count -eq 0) {
                    continue
                }
                $exportRows | Export-Csv -Path $csvExport['Path'] -NoTypeInformation
            }
        }

        $PostContentCombined = if ([string]::IsNullOrWhiteSpace($AppendixHtml)) {
            $GLOBALJavaScript
        } else {
            $GLOBALJavaScript + "`n" + $AppendixHtml
        }

        $Report = ConvertTo-HTML -Body "$headerHtml $MainTableHTML" -Head ("<title>$HtmlTitle</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsBlock
        $Report | Out-File $htmlPath

        $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
        Write-Host "[+] Details of $($TableOutput.Count) $Title objects stored in output files ($OutputFormats): $OutputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    }

    function Add-ObjectDetails {
        param(
            [System.Collections.ArrayList]$Collection,
            [string]$ObjectName,
            [string]$ObjectId,
            [System.Collections.IDictionary]$Sections
        )

        $detail = [ordered]@{
            "Object Name" = $ObjectName
            "Object ID" = $ObjectId
        }
        foreach ($entry in $Sections.GetEnumerator()) {
            $detail[$entry.Key] = $entry.Value
        }
        [void]$Collection.Add([pscustomobject]$detail)
    }

    if ($null -eq $AllUsersBasicHT)                   { $AllUsersBasicHT = @{} }
    if ($null -eq $Users)                             { $Users = @{} }
    if ($null -eq $AgentIdentities)                   { $AgentIdentities = @{} }
    if ($null -eq $AgentIdentityBlueprintsPrincipals) { $AgentIdentityBlueprintsPrincipals = @{} }
    if ($null -eq $AgentIdentityBlueprints)           { $AgentIdentityBlueprints = @{} }

    $EscapedTenantName = $CurrentTenant.FileSafeDisplayNameEncoded
    $AgentUsersLookup = Get-AgentUserLookup -Users $Users
    $PrincipalLookup = Get-PrincipalLookupByBlueprintId -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals
    $BlueprintLookupByAppId = Get-BlueprintLookupByAppId -AgentIdentityBlueprints $AgentIdentityBlueprints
    Write-Log -Level Debug -Message "Agent finalizer input: Users=$($Users.Count), AgentUsers=$($AgentUsersLookup.Count), AgentIdentities=$($AgentIdentities.Count), BlueprintPrincipals=$($AgentIdentityBlueprintsPrincipals.Count), Blueprints=$($AgentIdentityBlueprints.Count)"
    $AgentIdentityLikelihoodAdjustments = @{
        ForeignApp = 30
        InternApp = 5
    }

    $TotalAgentObjects =
        (@($AgentIdentities.Values) | Measure-Object).Count +
        (@($AgentIdentityBlueprintsPrincipals.Values) | Measure-Object).Count +
        (@($AgentIdentityBlueprints.Values) | Measure-Object).Count

    if ($TotalAgentObjects -eq 0) {
        Write-Host "[*] No agent identities, blueprint principals, or blueprints found. Skipping agent report finalization."
        return
    }

    Write-Host "[*] Finalizing agent identities with agent users and foreign parent principal state"
    $missingParentPrincipalCount = 0
    $missingBlueprintCount = 0
    $foreignMissingBlueprintCount = 0
    $localMissingBlueprintCount = 0
    $effectiveApiDebug = [ordered]@{
        Direct             = 0
        ConfirmedInherited = 0
        AssumedInherited   = 0
        ScoredUnique       = 0
    }
    foreach ($agentIdentity in $AgentIdentities.Values) {
        $enrichedAgentUsers = foreach ($agentUser in @($agentIdentity.AgentUsersDetails)) {
            if ($AgentUsersLookup.ContainsKey($agentUser.Id)) {
                $AgentUsersLookup[$agentUser.Id]
            } else {
                [pscustomobject]@{
                    Id       = $agentUser.Id
                    UPN      = $agentUser.UPN
                    Enabled  = $agentUser.Enabled
                    Impact   = 0
                    Warnings = ""
                }
            }
        }

        $parentPrincipal = $null
        $parentKey = "$($agentIdentity.AgentIdentityBlueprintId)".Trim()
        if (-not [string]::IsNullOrWhiteSpace($parentKey) -and $PrincipalLookup.ContainsKey($parentKey)) {
            $parentPrincipal = $PrincipalLookup[$parentKey]
        }
        if (-not [string]::IsNullOrWhiteSpace($parentKey) -and $null -eq $parentPrincipal) {
            $missingParentPrincipalCount++
        }

        $parentBlueprint = $null
        if (-not [string]::IsNullOrWhiteSpace($parentKey) -and $BlueprintLookupByAppId.ContainsKey($parentKey)) {
            $parentBlueprint = $BlueprintLookupByAppId[$parentKey]
        }
        if ($null -ne $parentPrincipal -and $null -eq $parentBlueprint) {
            $missingBlueprintCount++
            if ([bool]$parentPrincipal.Foreign) {
                $foreignMissingBlueprintCount++
            } else {
                $localMissingBlueprintCount++
            }
        }

        $directImpact = if ($null -ne $agentIdentity.Impact) { [double]$agentIdentity.Impact } else { 0 }
        $configuredApiSummary = Get-ApiPermissionImpactSummary -ApplicationPermissions @($agentIdentity.AppApiPermission) -DelegatedPermissions @($agentIdentity.ApiDelegatedDetails)
        $nonApiDirectImpact = [math]::Max(0, ($directImpact - [double]$configuredApiSummary.Impact))
        $inheritedImpact = [double](($enrichedAgentUsers | Measure-Object -Property Impact -Sum).Sum)
        $parentPrincipalId = if ($parentPrincipal) { $parentPrincipal.Id } else { $null }
        $parentPrincipalDisplayName = if ($parentPrincipal) { $parentPrincipal.DisplayName } else { $null }
        $parentPrincipalPublisherName = if ($parentPrincipal) { $parentPrincipal.PublisherName } else { $null }
        $foreignBlueprintPrincipal = if ($parentPrincipal) { [bool]$parentPrincipal.Foreign } else { $false }
        $effectivePermissionData = Resolve-AgentEffectiveApiPermissions -AgentIdentity $agentIdentity -ParentPrincipal $parentPrincipal -ParentBlueprint $parentBlueprint
        foreach ($source in @($effectivePermissionData.EffectiveApiPermissionSources)) {
            switch ([string]$source.OriginType) {
                'Direct'             { $effectiveApiDebug.Direct++; break }
                'ConfirmedInherited' { $effectiveApiDebug.ConfirmedInherited++; break }
                'AssumedInherited'   { $effectiveApiDebug.AssumedInherited++; break }
            }
        }
        $effectiveApiDebug.ScoredUnique += [int]$effectivePermissionData.Summary.ApplicationCount + [int]$effectivePermissionData.Summary.DelegatedCount

        $effectiveDirectImpact = [double]$nonApiDirectImpact + [double]$effectivePermissionData.Summary.Impact
        $agentIdentity | Add-Member -NotePropertyName EffectiveAppApiPermission -NotePropertyValue @($effectivePermissionData.EffectiveAppApiPermission) -Force
        $agentIdentity | Add-Member -NotePropertyName EffectiveApiDelegatedDetails -NotePropertyValue @($effectivePermissionData.EffectiveApiDelegatedDetails) -Force
        $agentIdentity | Add-Member -NotePropertyName EffectiveApiPermissionSources -NotePropertyValue @($effectivePermissionData.EffectiveApiPermissionSources) -Force
        $agentIdentity | Add-Member -NotePropertyName DirectImpact -NotePropertyValue ([math]::Round($effectiveDirectImpact)) -Force
        $agentIdentity | Add-Member -NotePropertyName InheritedImpact -NotePropertyValue ([math]::Round($inheritedImpact)) -Force
        $agentIdentity | Add-Member -NotePropertyName ParentBlueprintPrincipalId -NotePropertyValue $parentPrincipalId -Force
        $agentIdentity | Add-Member -NotePropertyName ParentBlueprintPrincipalDisplayName -NotePropertyValue $parentPrincipalDisplayName -Force
        $agentIdentity | Add-Member -NotePropertyName ParentBlueprintPrincipalPublisherName -NotePropertyValue $parentPrincipalPublisherName -Force
        $agentIdentity | Add-Member -NotePropertyName ForeignBlueprintPrincipal -NotePropertyValue $foreignBlueprintPrincipal -Force
        $agentIdentity | Add-Member -NotePropertyName Foreign -NotePropertyValue ([bool]$agentIdentity.Foreign -or $foreignBlueprintPrincipal) -Force
        $agentIdentity.ApiDangerous = $effectivePermissionData.Summary.ApplicationCounts['Dangerous']
        $agentIdentity.ApiHigh = $effectivePermissionData.Summary.ApplicationCounts['High']
        $agentIdentity.ApiMedium = $effectivePermissionData.Summary.ApplicationCounts['Medium']
        $agentIdentity.ApiLow = $effectivePermissionData.Summary.ApplicationCounts['Low']
        $agentIdentity.ApiMisc = $effectivePermissionData.Summary.ApplicationCounts['Uncategorized']
        $agentIdentity.ApiDelegated = $effectivePermissionData.Summary.DelegatedCount
        $agentIdentity.ApiDelegatedDangerous = $effectivePermissionData.Summary.DelegatedCounts['Dangerous']
        $agentIdentity.ApiDelegatedHigh = $effectivePermissionData.Summary.DelegatedCounts['High']
        $agentIdentity.ApiDelegatedMedium = $effectivePermissionData.Summary.DelegatedCounts['Medium']
        $agentIdentity.ApiDelegatedLow = $effectivePermissionData.Summary.DelegatedCounts['Low']
        $agentIdentity.ApiDelegatedMisc = $effectivePermissionData.Summary.DelegatedCounts['Uncategorized']
        if ([string]::IsNullOrWhiteSpace([string]$agentIdentity.PublisherName) -or $agentIdentity.PublisherName -eq "-") {
            if (-not [string]::IsNullOrWhiteSpace([string]$parentPrincipalPublisherName) -and $parentPrincipalPublisherName -ne "-") {
                $agentIdentity.PublisherName = $parentPrincipalPublisherName
            }
        }
        $agentIdentity.AgentUsersDetails = @($enrichedAgentUsers | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'UPN'))
        $agentIdentity.AgentUsers = @($agentIdentity.AgentUsersDetails).Count
        if (-not $agentIdentity.DefaultMS) {
            if ($foreignBlueprintPrincipal) {
                $agentIdentity.Likelihood += $AgentIdentityLikelihoodAdjustments["ForeignApp"]
            } else {
                $agentIdentity.Likelihood += $AgentIdentityLikelihoodAdjustments["InternApp"]
            }
        }
        if ($null -eq $agentIdentity.Warnings) {
            $agentIdentity.Warnings = ''
        }
        if ($agentIdentity.ForeignBlueprintPrincipal) {
            $agentIdentity.Warnings = Add-UniqueWarningText -ExistingWarnings $agentIdentity.Warnings -NewWarning "Child of foreign blueprint principal"
        }
        foreach ($warning in @($effectivePermissionData.Warnings)) {
            $agentIdentity.Warnings = Add-UniqueWarningText -ExistingWarnings $agentIdentity.Warnings -NewWarning $warning
        }
        $applicationWarning = Get-ApiSeverityWarningText -Counts $effectivePermissionData.Summary.ApplicationCounts -Suffix 'API permission' -IncludeMedium:$foreignBlueprintPrincipal
        if (-not [string]::IsNullOrWhiteSpace($applicationWarning)) {
            $agentIdentity.Warnings = Add-UniqueWarningText -ExistingWarnings $agentIdentity.Warnings -NewWarning $applicationWarning
        }
        $delegatedWarning = Get-ApiSeverityWarningText -Counts $effectivePermissionData.Summary.DelegatedCounts -Suffix 'delegated API permission' -IncludeMedium:$foreignBlueprintPrincipal
        if (-not [string]::IsNullOrWhiteSpace($delegatedWarning)) {
            $agentIdentity.Warnings = Add-UniqueWarningText -ExistingWarnings $agentIdentity.Warnings -NewWarning $delegatedWarning
        }
        $agentIdentity.Impact = [math]::Round($effectiveDirectImpact + $inheritedImpact)
        $agentIdentity.Risk = [math]::Round(($agentIdentity.Impact * $agentIdentity.Likelihood))
    }

    $AgentIdentitiesByBlueprintLookup = Get-AgentIdentityLookupByBlueprintId -AgentIdentities $AgentIdentities

    Write-Host "[*] Finalizing agent identity blueprint principals"
    foreach ($principal in $AgentIdentityBlueprintsPrincipals.Values) {
        $principalKey = if ([string]::IsNullOrWhiteSpace("$($principal.AppId)")) { "$($principal.Id)" } else { "$($principal.AppId)" }
        $linkedAgentIdentities = @()
        if (-not [string]::IsNullOrWhiteSpace($principalKey) -and $AgentIdentitiesByBlueprintLookup.ContainsKey($principalKey)) {
            $linkedAgentIdentities = @($AgentIdentitiesByBlueprintLookup[$principalKey] | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'DisplayName'))
        }

        $principal.LinkedAgentIdentitiesDetails = @(
            foreach ($agentIdentity in $linkedAgentIdentities) {
                [pscustomobject]@{
                    Id = $agentIdentity.Id
                    DisplayName = $agentIdentity.DisplayName
                    Enabled = $agentIdentity.Enabled
                    Type = "AgentIdentity"
                    Impact = $agentIdentity.Impact
                    Risk = $agentIdentity.Risk
                    Warnings = if ([string]::IsNullOrWhiteSpace($agentIdentity.Warnings)) { "-" } else { $agentIdentity.Warnings }
                    AgentUsers = $agentIdentity.AgentUsers
                    ForeignBlueprintPrincipal = $agentIdentity.ForeignBlueprintPrincipal
                }
            }
        )
        $principal.LinkedAgentIdentities = @($principal.LinkedAgentIdentitiesDetails).Count

        $parentBlueprintId = $null
        $parentBlueprintDisplayName = $null
        $parentBlueprint = $null
        if (-not [string]::IsNullOrWhiteSpace("$($principal.AppId)") -and $BlueprintLookupByAppId.ContainsKey("$($principal.AppId)")) {
            $parentBlueprint = $BlueprintLookupByAppId["$($principal.AppId)"]
            $parentBlueprintId = $parentBlueprint.Id
            $parentBlueprintDisplayName = $parentBlueprint.DisplayName
        }
        $principal | Add-Member -NotePropertyName ParentBlueprintId -NotePropertyValue $parentBlueprintId -Force
        $principal | Add-Member -NotePropertyName ParentBlueprintDisplayName -NotePropertyValue $parentBlueprintDisplayName -Force

        $principal | Add-Member -NotePropertyName AgentUsersDetails -NotePropertyValue @(
            foreach ($agentIdentity in $linkedAgentIdentities) {
                foreach ($agentUser in @($agentIdentity.AgentUsersDetails)) {
                    [pscustomobject]@{
                        Id = $agentUser.Id
                        UPN = $agentUser.UPN
                        Enabled = $agentUser.Enabled
                        Impact = $agentUser.Impact
                        Warnings = $agentUser.Warnings
                        ParentAgentIdentityId = $agentIdentity.Id
                        ParentAgentIdentityDisplayName = $agentIdentity.DisplayName
                        ParentPrincipalId = $principal.Id
                        ParentPrincipalDisplayName = $principal.DisplayName
                    }
                }
            }
        ) -Force
        $principal.AgentUsersDetails = @($principal.AgentUsersDetails | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'UPN'))
        $principal | Add-Member -NotePropertyName AgentUsers -NotePropertyValue (@($principal.AgentUsersDetails | Group-Object Id).Count) -Force

        $baseDirectImpact = 1
        $effectiveBlueprintPrincipalAppPermissions = Get-BlueprintPrincipalEffectiveApplicationPermissions -BlueprintPrincipal $principal
        $effectiveBlueprintPrincipalApiSummary = Get-ApiPermissionImpactSummary -ApplicationPermissions @($effectiveBlueprintPrincipalAppPermissions) -DeduplicateApplication
        $inheritedImpact = [double](($linkedAgentIdentities | Measure-Object -Property Impact -Sum).Sum)
        $principal.Warnings = ''

        $confirmedChildInheritedAppPermissions = [System.Collections.ArrayList]::new()
        $confirmedChildInheritedDelegatedPermissions = [System.Collections.ArrayList]::new()
        $assumedChildInheritedAppPermissions = [System.Collections.ArrayList]::new()
        $assumedChildInheritedDelegatedPermissions = [System.Collections.ArrayList]::new()
        if ($null -ne $parentBlueprint) {
            $blueprintRuleLookup = Get-BlueprintInheritablePermissionLookup -Blueprint $parentBlueprint
            foreach ($permission in @($principal.AppApiPermission)) {
                if (-not (Test-AgentInheritableApplicationPermission -Permission $permission)) {
                    continue
                }

                $resourceAppId = if ($permission.PSObject.Properties['ResourceAppId']) { [string]$permission.ResourceAppId } else { '' }
                $permissionId = if ($permission.PSObject.Properties['PermissionId']) { [string]$permission.PermissionId } else { '' }
                $decision = Test-BlueprintPermissionInheritance -BlueprintRuleLookup $blueprintRuleLookup -PermissionType 'Application' -ResourceAppId $resourceAppId -PermissionValue $permissionId
                if ($decision.Allowed) {
                    [void]$confirmedChildInheritedAppPermissions.Add($permission)
                }
            }

            foreach ($permission in @($principal.ApiDelegatedDetails)) {
                $resourceAppId = if ($permission.PSObject.Properties['ResourceAppId']) { [string]$permission.ResourceAppId } else { '' }
                $scope = if ($permission.PSObject.Properties['Scope']) { [string]$permission.Scope } else { '' }
                $decision = Test-BlueprintPermissionInheritance -BlueprintRuleLookup $blueprintRuleLookup -PermissionType 'Delegated' -ResourceAppId $resourceAppId -PermissionValue $scope
                if ($decision.Allowed) {
                    [void]$confirmedChildInheritedDelegatedPermissions.Add($permission)
                }
            }
        } elseif ([bool]$principal.Foreign) {
            foreach ($permission in @($principal.AppApiPermission)) {
                if (-not (Test-AgentInheritableApplicationPermission -Permission $permission)) {
                    continue
                }

                [void]$assumedChildInheritedAppPermissions.Add($permission)
            }

            foreach ($permission in @($principal.ApiDelegatedDetails)) {
                [void]$assumedChildInheritedDelegatedPermissions.Add($permission)
            }
        }

        $confirmedChildInheritedSummary = Get-ApiPermissionImpactSummary -ApplicationPermissions @($confirmedChildInheritedAppPermissions) -DelegatedPermissions @($confirmedChildInheritedDelegatedPermissions) -DeduplicateApplication -DeduplicateDelegated
        $confirmedAppInheritanceWarning = Get-AgentInheritanceWarningText -Counts $confirmedChildInheritedSummary.ApplicationCounts -PermissionTypeLabel 'Application'
        if (-not [string]::IsNullOrWhiteSpace($confirmedAppInheritanceWarning)) {
            $principal.Warnings = Add-UniqueWarningText -ExistingWarnings $principal.Warnings -NewWarning $confirmedAppInheritanceWarning
        }
        $confirmedDelegatedInheritanceWarning = Get-AgentInheritanceWarningText -Counts $confirmedChildInheritedSummary.DelegatedCounts -PermissionTypeLabel 'Delegated'
        if (-not [string]::IsNullOrWhiteSpace($confirmedDelegatedInheritanceWarning)) {
            $principal.Warnings = Add-UniqueWarningText -ExistingWarnings $principal.Warnings -NewWarning $confirmedDelegatedInheritanceWarning
        }

        $assumedChildInheritedSummary = Get-ApiPermissionImpactSummary -ApplicationPermissions @($assumedChildInheritedAppPermissions) -DelegatedPermissions @($assumedChildInheritedDelegatedPermissions) -DeduplicateApplication -DeduplicateDelegated
        $assumedAppInheritanceWarning = Get-AgentInheritanceWarningText -Counts $assumedChildInheritedSummary.ApplicationCounts -PermissionTypeLabel 'Application' -Assumed -IncludeMedium
        if (-not [string]::IsNullOrWhiteSpace($assumedAppInheritanceWarning)) {
            $principal.Warnings = Add-UniqueWarningText -ExistingWarnings $principal.Warnings -NewWarning $assumedAppInheritanceWarning
        }
        $assumedDelegatedInheritanceWarning = Get-AgentInheritanceWarningText -Counts $assumedChildInheritedSummary.DelegatedCounts -PermissionTypeLabel 'Delegated' -Assumed -IncludeMedium
        if (-not [string]::IsNullOrWhiteSpace($assumedDelegatedInheritanceWarning)) {
            $principal.Warnings = Add-UniqueWarningText -ExistingWarnings $principal.Warnings -NewWarning $assumedDelegatedInheritanceWarning
        }

        $principal | Add-Member -NotePropertyName BlueprintPrincipalEffectiveAppApiPermission -NotePropertyValue @($effectiveBlueprintPrincipalAppPermissions) -Force
        $principal | Add-Member -NotePropertyName DirectImpact -NotePropertyValue ([math]::Round($baseDirectImpact + [double]$effectiveBlueprintPrincipalApiSummary.Impact)) -Force
        $principal | Add-Member -NotePropertyName InheritedImpact -NotePropertyValue ([math]::Round($inheritedImpact)) -Force
        $principal.Impact = [math]::Round($principal.DirectImpact + $inheritedImpact)
        $principal.Risk = [math]::Round(($principal.Impact * $principal.Likelihood))
    }

    $PrincipalsByAppLookup = Get-PrincipalLookupByAppId -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals

    Write-Host "[*] Finalizing agent identity blueprints"
    foreach ($blueprint in $AgentIdentityBlueprints.Values) {
        $blueprintPrincipals = @()
        $blueprintKey = "$($blueprint.AppId)".Trim()
        if (-not [string]::IsNullOrWhiteSpace($blueprintKey) -and $PrincipalsByAppLookup.ContainsKey($blueprintKey)) {
            $blueprintPrincipals = @($PrincipalsByAppLookup[$blueprintKey] | Sort-Object -Property @(@{ Expression = 'Risk'; Descending = $true }, 'DisplayName'))
        }

        $blueprint.BlueprintPrincipalsDetails = $blueprintPrincipals
        $blueprint.BlueprintPrincipals = @($blueprintPrincipals).Count
        $blueprint.LinkedAgentIdentitiesDetails = @(
            foreach ($principal in $blueprintPrincipals) {
                foreach ($agentIdentity in @($principal.LinkedAgentIdentitiesDetails)) {
                    [pscustomobject]@{
                        Id = $agentIdentity.Id
                        DisplayName = $agentIdentity.DisplayName
                        Enabled = $agentIdentity.Enabled
                        Impact = $agentIdentity.Impact
                        Risk = $agentIdentity.Risk
                        Warnings = $agentIdentity.Warnings
                        ParentPrincipalId = $principal.Id
                        ParentPrincipalDisplayName = $principal.DisplayName
                    }
                }
            }
        )
        $blueprint.LinkedAgentIdentitiesDetails = @($blueprint.LinkedAgentIdentitiesDetails | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'DisplayName'))
        $blueprint.LinkedAgentIdentities = @($blueprint.LinkedAgentIdentitiesDetails).Count
        $blueprint | Add-Member -NotePropertyName AgentUsersDetails -NotePropertyValue @(
            foreach ($principal in $blueprintPrincipals) {
                foreach ($agentUser in @($principal.AgentUsersDetails)) {
                    [pscustomobject]@{
                        Id = $agentUser.Id
                        UPN = $agentUser.UPN
                        Enabled = $agentUser.Enabled
                        Impact = $agentUser.Impact
                        Warnings = $agentUser.Warnings
                        ParentPrincipalId = $principal.Id
                        ParentPrincipalDisplayName = $principal.DisplayName
                        ParentAgentIdentityId = $agentUser.ParentAgentIdentityId
                        ParentAgentIdentityDisplayName = $agentUser.ParentAgentIdentityDisplayName
                    }
                }
            }
        ) -Force
        $blueprint.AgentUsersDetails = @($blueprint.AgentUsersDetails | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'UPN'))
        $blueprint | Add-Member -NotePropertyName AgentUsers -NotePropertyValue (@($blueprint.AgentUsersDetails | Group-Object Id).Count) -Force

        $directImpact = if ($null -ne $blueprint.DirectImpact) { [double]$blueprint.DirectImpact } else { 0 }
        $inheritedImpact = [double](($blueprintPrincipals | Measure-Object -Property Impact -Sum).Sum)
        $blueprint.DirectImpact = [math]::Round($directImpact)
        $blueprint.InheritedImpact = [math]::Round($inheritedImpact)
        $blueprint.Impact = [math]::Round($directImpact + $inheritedImpact)
        $blueprint.Risk = [math]::Round(($blueprint.Impact * $blueprint.Likelihood))
    }

    $totalLinkedAgentUsers = ($AgentIdentities.Values | Measure-Object -Property AgentUsers -Sum).Sum
    if ($null -eq $totalLinkedAgentUsers) { $totalLinkedAgentUsers = 0 }
    $linkedAgentIdentityCount = @($AgentIdentities.Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ParentBlueprintPrincipalId) }).Count
    $linkedPrincipalCount = @($AgentIdentityBlueprintsPrincipals.Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ParentBlueprintId) }).Count
    $linkedBlueprintCount = @($AgentIdentityBlueprints.Values | Where-Object { $null -ne $_.BlueprintPrincipals -and [int]$_.BlueprintPrincipals -gt 0 }).Count
    Write-Log -Level Debug -Message "Agent finalizer links: AgentUsers=$totalLinkedAgentUsers, LinkedAgentIdentities=$linkedAgentIdentityCount, LinkedPrincipals=$linkedPrincipalCount, LinkedBlueprints=$linkedBlueprintCount"
    Write-Log -Level Debug -Message "Agent finalizer missing links: MissingParentPrincipal=$missingParentPrincipalCount, MissingBlueprint=$missingBlueprintCount, ForeignMissingBlueprint=$foreignMissingBlueprintCount, LocalMissingBlueprint=$localMissingBlueprintCount"
    Write-Log -Level Debug -Message "Agent effective API permissions: Direct=$($effectiveApiDebug.Direct), ConfirmedInherited=$($effectiveApiDebug.ConfirmedInherited), AssumedInherited=$($effectiveApiDebug.AssumedInherited), ScoredUnique=$($effectiveApiDebug.ScoredUnique)"

    foreach ($agentIdentity in $AgentIdentities.Values) {
        $agentIdentity.Warnings = Normalize-AgentOwnerWarnings -Warnings $agentIdentity.Warnings
    }
    foreach ($principal in $AgentIdentityBlueprintsPrincipals.Values) {
        $principal.Warnings = Normalize-AgentOwnerWarnings -Warnings $principal.Warnings
    }
    foreach ($blueprint in $AgentIdentityBlueprints.Values) {
        $blueprint.Warnings = Normalize-AgentOwnerWarnings -Warnings $blueprint.Warnings
    }

    $AgentIdentityDetails = [System.Collections.ArrayList]::new()
    $AgentIdentityTxt = [System.Text.StringBuilder]::new()
    $AgentIdentityItems = @($AgentIdentities.Values | Sort-Object Risk -Descending)
    foreach ($item in $AgentIdentityItems) {
        $parentBlueprintPrincipalLink = if ($item.ParentBlueprintPrincipalId) { "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$EscapedTenantName.html#$($item.ParentBlueprintPrincipalId)>$($item.ParentBlueprintPrincipalDisplayName)</a>" } else { "-" }
        $lastSignInOverall = if ($item.AppsignInData.lastSignIn -and $item.AppsignInData.lastSignIn -ne "-") { "$($item.AppsignInData.lastSignIn) ($($item.AppsignInData.lastSignInDays) days ago)" } else { "-" }
        $lastSignInAppClient = if ($item.AppsignInData.lastSignInAppAsClient -and $item.AppsignInData.lastSignInAppAsClient -ne "-") { "$($item.AppsignInData.lastSignInAppAsClient) ($($item.AppsignInData.lastSignInAppAsClientDays) days ago)" } else { "-" }
        $lastSignInAppResource = if ($item.AppsignInData.lastSignInAppAsResource -and $item.AppsignInData.lastSignInAppAsResource -ne "-") { "$($item.AppsignInData.lastSignInAppAsResource) ($($item.AppsignInData.lastSignInAppAsResourceDays) days ago)" } else { "-" }
        $lastSignInDelegatedClient = if ($item.AppsignInData.lastSignInDelegatedAsClient -and $item.AppsignInData.lastSignInDelegatedAsClient -ne "-") { "$($item.AppsignInData.lastSignInDelegatedAsClient) ($($item.AppsignInData.lastSignInDelegatedAsClientDays) days ago)" } else { "-" }
        $lastSignInDelegatedResource = if ($item.AppsignInData.lastSignInDelegatedAsResource -and $item.AppsignInData.lastSignInDelegatedAsResource -ne "-") { "$($item.AppsignInData.lastSignInDelegatedAsResource) ($($item.AppsignInData.lastSignInDelegatedAsResourceDays) days ago)" } else { "-" }
        $ReportingRoles = @(
            foreach ($object in @($item.EntraRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.DisplayName
                    "Tier Level" = $object.RoleTier
                    "Privileged" = $object.isPrivileged
                    "IsBuiltin" = $object.IsBuiltin
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                }
            }
        )
        $ReportingEligibleRoles = @(
            foreach ($object in @($item.EligibleEntraRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.DisplayName
                    "Tier Level" = $object.RoleTier
                    "Privileged" = $object.isPrivileged
                    "IsBuiltin" = $object.IsBuiltin
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                }
            }
        )
        $ReportingAzureRoles = @(
            foreach ($object in @($item.AzureRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.RoleName
                    "RoleType" = $object.RoleType
                    "Tier Level" = $object.RoleTier
                    "Conditions" = $object.Conditions
                    "Scoped to" = $object.Scope
                }
            }
        )
        $ReportingEligibleAzureRoles = @(
            foreach ($object in @($item.EligibleAzureRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.RoleName
                    "RoleType" = $object.RoleType
                    "Tier Level" = $object.RoleTier
                    "Conditions" = $object.Conditions
                    "Scoped to" = $object.Scope
                }
            }
        )
        $ReportingGroupOwner = @(
            foreach ($object in @($item.GroupOwner)) {
                [pscustomobject]@{
                    DisplayName = "<a href=Groups_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                    SecurityEnabled = $object.SecurityEnabled
                    RoleAssignable = $object.RoleAssignable
                    EntraRoles = $object.AssignedRoleCount
                    AzureRoles = $object.AzureRoles
                    CAPs = $object.CAPs
                    ImpactOrg = $object.ImpactOrg
                    Warnings = $object.Warnings
                }
            }
        )
        $ReportingAppOwner = @(
            foreach ($object in @($item.OwnedApplicationsDetails)) {
                [pscustomobject]@{
                    DisplayName = "<a href=AppRegistration_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                }
            }
        )
        $ReportingSPOwner = @(
            foreach ($object in @($item.OwnedSPDetails)) {
                [pscustomobject]@{
                    DisplayName = "<a href=#$($object.id)>$($object.DisplayName)</a>"
                    Foreign = $object.Foreign
                    Impact = $object.Impact
                }
            }
        )
        $ReportingGroupMember = @(
            foreach ($object in @($item.GroupMember)) {
                [pscustomobject]@{
                    DisplayName = "<a href=Groups_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                    SecurityEnabled = $object.SecurityEnabled
                    RoleAssignable = $object.RoleAssignable
                    EntraRoles = $object.AssignedRoleCount
                    AzureRoles = $object.AzureRoles
                    CAPs = $object.CAPs
                    "Impact (No Eligible)" = $object.ImpactOrgActiveOnly
                    Warnings = $object.Warnings
                }
            }
        )
        $ReportingAppRoles = @(
            foreach ($object in @($item.AppRolesDetails)) {
                [pscustomobject]@{
                    Claim = $object.AppRoleClaim
                    Name = $object.AppRoleName
                    RoleEnabled = $object.RoleEnabled
                    AssignmentType = $object.AppRoleAssignmentType
                    Member = $object.AppRoleMember
                }
            }
        )
        $ReportingOwnersUser = @(
            foreach ($object in @($item.OwnerUserDetails)) {
                [pscustomobject]@{
                    UserName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.UPN)</a>"
                    Enabled = $object.Enabled
                    Type = $object.Type
                    OnPremSync = $object.OnPremSync
                    Department = $object.Department
                    JobTitle = $object.JobTitle
                }
            }
        )
        $ReportingOwnersSP = @(
            foreach ($object in @($item.OwnerSPDetails)) {
                $resolvedOwner = Resolve-FinalizedAgentNonUserOwner -Owner $object -CurrentTenant $CurrentTenant -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals
                if ($null -eq $resolvedOwner) {
                    continue
                }
                [pscustomobject]@{
                    DisplayName = Get-AgentOwnerLink -ResolvedOwner $resolvedOwner -StartTimestamp $StartTimestamp -EscapedTenantName $EscapedTenantName
                    Enabled = if ($null -ne $resolvedOwner.Enabled) { $resolvedOwner.Enabled } else { "-" }
                    PublisherName = $resolvedOwner.PublisherName
                    Type = if ($resolvedOwner.Type -in @('ServicePrincipal', 'ManagedIdentity')) { $resolvedOwner.ServicePrincipalType } else { $resolvedOwner.Type }
                }
            }
        )
        $resolveSource = {
            param($object)
            switch ([string]$object.OriginType) {
                'Direct'             { 'Direct' }
                'ConfirmedInherited' {
                    switch ([string]$object.RuleKind) {
                        'allAllowed' { 'Inherited (allAllowed)' }
                        'enumerated' { 'Inherited (enumerated)' }
                        default      { 'Inherited' }
                    }
                }
                'AssumedInherited'   { 'Inherited (assumed foreign)' }
                default {
                    if ([string]::IsNullOrWhiteSpace([string]$object.RuleKind) -or [string]$object.RuleKind -eq '-') {
                        [string]$object.OriginType
                    } else {
                        "$($object.OriginType) ($($object.RuleKind))"
                    }
                }
            }
        }

        $ReportingEffectiveAppPermissions = @(
            foreach ($object in @($item.EffectiveApiPermissionSources | Where-Object { $_.PermissionType -eq 'Application' })) {
                [pscustomobject]@{
                    ApiName    = $object.ApiName
                    Permission = $object.Permission
                    Category   = $object.Category
                    Source     = & $resolveSource $object
                }
            }
        )

        $ReportingEffectiveDelegatedPermissions = @(
            foreach ($object in @($item.EffectiveApiPermissionSources | Where-Object { $_.PermissionType -eq 'Delegated' })) {
                $principalRaw     = [string]$object.Principal
                $userDetails      = if ($principalRaw -and $principalRaw -ne '-') { $AllUsersBasicHT[$principalRaw] } else { $null }
                $principalDisplay = if ($userDetails) {
                    "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$principalRaw>$($userDetails.UserPrincipalName)</a>"
                } elseif ($principalRaw -and $principalRaw -ne '-') {
                    $principalRaw
                } else {
                    '-'
                }
                [pscustomobject]@{
                    ApiName     = $object.ApiName
                    Permission  = $object.Permission
                    Category    = $object.Category
                    ConsentType = if ([string]::IsNullOrWhiteSpace([string]$object.ConsentType)) { '-' } else { [string]$object.ConsentType }
                    Principal   = $principalDisplay
                    Source      = & $resolveSource $object
                }
            }
        )

        [void]$AgentIdentityTxt.AppendLine("############################################################################################################################################")
        [void]$AgentIdentityTxt.AppendLine(($item | Select-Object DisplayName,PublisherName,AppId,CreatedByAppId,AgentIdentityBlueprintId,ParentBlueprintPrincipalDisplayName,Foreign,AgentUsers,DirectImpact,InheritedImpact,Impact,Likelihood,Risk,Warnings | Out-String))
        if (($item.AgentUsersDetails | Measure-Object).Count -ge 1) {
            [void]$AgentIdentityTxt.AppendLine("Child Agent Users")
            [void]$AgentIdentityTxt.AppendLine(($item.AgentUsersDetails | Format-Table UPN,Enabled,Impact,Warnings | Out-String))
        }
        if (($ReportingEffectiveAppPermissions | Measure-Object).Count -ge 1) {
            [void]$AgentIdentityTxt.AppendLine("Effective Application API Permissions")
            [void]$AgentIdentityTxt.AppendLine(($ReportingEffectiveAppPermissions | Format-Table -Wrap | Out-String -Width 320))
        }
        if (($ReportingEffectiveDelegatedPermissions | Measure-Object).Count -ge 1) {
            [void]$AgentIdentityTxt.AppendLine("Effective Delegated API Permissions")
            [void]$AgentIdentityTxt.AppendLine(($ReportingEffectiveDelegatedPermissions | Select-Object ApiName,Permission,Category,ConsentType,Principal,Source | Format-Table -Wrap | Out-String -Width 320))
        }
        Add-ObjectDetails -Collection $AgentIdentityDetails -ObjectName $item.DisplayName -ObjectId $item.Id -Sections ([ordered]@{
            "General Information" = [pscustomobject]@{
                "App Name" = $item.DisplayName
                "Publisher Name" = $item.PublisherName
                "Client-ID" = $item.AppId
                "Object-ID" = $item.Id
                "Created By App ID" = $item.CreatedByAppId
                "Agent Identity Blueprint ID" = $item.AgentIdentityBlueprintId
                "Parent Blueprint Principal" = $parentBlueprintPrincipalLink
                "Foreign" = $item.Foreign
                "DirectImpact" = $item.DirectImpact
                "InheritedImpact" = $item.InheritedImpact
                "RiskScore" = $item.Risk
                "Warnings" = $item.Warnings
            }
            "Last Sign-Ins Details" = [pscustomobject]@{
                "Last sign-in overall" = $lastSignInOverall
                "Last sign-in as application (client)" = $lastSignInAppClient
                "Last sign-in as application (resource)" = $lastSignInAppResource
                "Last sign-in delegated (client)" = $lastSignInDelegatedClient
                "Last sign-in delegated (resource)" = $lastSignInDelegatedResource
            }
            "Child Agent Users" = @(
                foreach ($agentUser in @($item.AgentUsersDetails)) {
                    [pscustomobject]@{
                        UserPrincipalName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.Id)>$($agentUser.UPN)</a>"
                        Enabled = $agentUser.Enabled
                        Impact = $agentUser.Impact
                        Warnings = $agentUser.Warnings
                    }
                }
            )
            "Active Entra Role Assignments" = $ReportingRoles
            "Eligible Entra Role Assignments" = $ReportingEligibleRoles
            "Active Azure IAM assignments" = $ReportingAzureRoles
            "Eligible Azure IAM assignments" = $ReportingEligibleAzureRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owned App Registrations" = $ReportingAppOwner
            "Owned Service Principals" = $ReportingSPOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Assigned App Roles" = $ReportingAppRoles
            "Owners (Users)" = $ReportingOwnersUser
            "Owners (Service Principals / Agent Objects)" = $ReportingOwnersSP
            "Sponsors" = @(
                foreach ($sponsor in @($item.AppSponsorsDetails)) {
                    [pscustomobject]@{
                        Type = $sponsor.Type
                        DisplayName = $sponsor.DisplayName
                        UPN = $sponsor.UPN
                        Foreign = $sponsor.Foreign
                    }
                }
            )
            "Effective Application API Permissions"  = $ReportingEffectiveAppPermissions
            "Effective Delegated API Permissions"    = $ReportingEffectiveDelegatedPermissions
        })
    }

    $AgentIdentityWarnings = Get-AgentReportWarnings -ReportKey 'AgentIdentities'
    $AgentIdentityApiReference = Get-ApiPermissionReferenceData -Items $AgentIdentityItems -PermissionProperty 'EffectiveAppApiPermission'
    $AgentIdentityAppendixTxt = ""
    $AgentIdentityAppendixHtml = ""
    if ($AgentIdentityApiReference.Count -ge 1) {
        $AgentIdentityAppendixTxt = @"

=======================================================================================================================
Appendix: Used API Permission Reference
=======================================================================================================================
"@
        $AgentIdentityAppendixTxt += "`n" + (($AgentIdentityApiReference | Format-Table -AutoSize | Out-String).TrimEnd())
        $AgentIdentityAppendixHtml = $AgentIdentityApiReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
    }

    $GlobalAuditSummary.AgentIdentities.Count = $AgentIdentityItems.Count
    $GlobalAuditSummary.AgentIdentities.Foreign = @($AgentIdentityItems | Where-Object { $_.Foreign }).Count
    $GlobalAuditSummary.AgentIdentities.Inactive = @($AgentIdentityItems | Where-Object { $_.Inactive }).Count
    $TotalAgentUsers = ($AgentIdentityItems | Measure-Object -Property AgentUsers -Sum).Sum
    $GlobalAuditSummary.AgentIdentities.TotalAgentUsers = if ($null -eq $TotalAgentUsers) { 0 } else { [int]$TotalAgentUsers }
    $GlobalAuditSummary.AgentIdentities.ApiCategorization.Dangerous = @($AgentIdentityItems | Where-Object { $_.ApiDangerous -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentities.ApiCategorization.High = @($AgentIdentityItems | Where-Object { $_.ApiHigh -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentities.ApiCategorization.Medium = @($AgentIdentityItems | Where-Object { $_.ApiMedium -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentities.ApiCategorization.Low = @($AgentIdentityItems | Where-Object { $_.ApiLow -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentities.ApiCategorization.Misc = @($AgentIdentityItems | Where-Object { $_.ApiMisc -gt 0 }).Count

    if ($AgentIdentityItems.Count -gt 0) {
        New-ReportFileSet -Title "AgentIdentities" -ReportKey "AgentIdentities" -ReportName "Agent Identities Enumeration (BETA)" -HtmlTitle "EF - Agent Identities" -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -TableOutput $AgentIdentityItems -MainTable ($AgentIdentityItems | Select-Object @{Name = "DisplayName"; Expression = { $_.DisplayNameLink }},AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,CreationInDays,AgentUsers,Owners,Sponsors,AppRoles,GrpMem,GrpOwn,AppOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous,ApiHigh,ApiMedium,ApiLow,ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,Impact,Likelihood,Risk,Warnings) -AllObjectDetailsHTML $AgentIdentityDetails -DetailOutputTxt $AgentIdentityTxt.ToString() -TxtColumns @('DisplayName','AppRoleRequired','PublisherName','DefaultMS','Foreign','Enabled','Inactive','LastSignInDays','CreationInDays','AgentUsers','Owners','Sponsors','AppRoles','GrpMem','GrpOwn','AppOwn','SpOwn','EntraRoles','EntraMaxTier','AzureRoles','AzureMaxTier','ApiDangerous','ApiHigh','ApiMedium','ApiLow','ApiMisc','ApiDelegated','ApiDelegatedDangerous','ApiDelegatedHigh','ApiDelegatedMedium','ApiDelegatedLow','ApiDelegatedMisc','Impact','Likelihood','Risk','Warnings') -WarningList $AgentIdentityWarnings -AppendixTxt $AgentIdentityAppendixTxt -AppendixHtml $AgentIdentityAppendixHtml -Csv:$Csv
    } else {
        Write-Host "[*] No agent identities found. Skipping Agent Identities report output."
    }

    $PrincipalDetails = [System.Collections.ArrayList]::new()
    $PrincipalTxt = [System.Text.StringBuilder]::new()
    $PrincipalItems = @($AgentIdentityBlueprintsPrincipals.Values | Sort-Object Risk -Descending)
    foreach ($item in $PrincipalItems) {
        $lastSignInOverall = if ($item.AppsignInData.lastSignIn -and $item.AppsignInData.lastSignIn -ne "-") { "$($item.AppsignInData.lastSignIn) ($($item.AppsignInData.lastSignInDays) days ago)" } else { "-" }
        $lastSignInAppClient = if ($item.AppsignInData.lastSignInAppAsClient -and $item.AppsignInData.lastSignInAppAsClient -ne "-") { "$($item.AppsignInData.lastSignInAppAsClient) ($($item.AppsignInData.lastSignInAppAsClientDays) days ago)" } else { "-" }
        $lastSignInAppResource = if ($item.AppsignInData.lastSignInAppAsResource -and $item.AppsignInData.lastSignInAppAsResource -ne "-") { "$($item.AppsignInData.lastSignInAppAsResource) ($($item.AppsignInData.lastSignInAppAsResourceDays) days ago)" } else { "-" }
        $lastSignInDelegatedClient = if ($item.AppsignInData.lastSignInDelegatedAsClient -and $item.AppsignInData.lastSignInDelegatedAsClient -ne "-") { "$($item.AppsignInData.lastSignInDelegatedAsClient) ($($item.AppsignInData.lastSignInDelegatedAsClientDays) days ago)" } else { "-" }
        $lastSignInDelegatedResource = if ($item.AppsignInData.lastSignInDelegatedAsResource -and $item.AppsignInData.lastSignInDelegatedAsResource -ne "-") { "$($item.AppsignInData.lastSignInDelegatedAsResource) ($($item.AppsignInData.lastSignInDelegatedAsResourceDays) days ago)" } else { "-" }
        $ReportingRoles = @(
            foreach ($object in @($item.EntraRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.DisplayName
                    "Tier Level" = $object.RoleTier
                    "Privileged" = $object.isPrivileged
                    "IsBuiltin" = $object.IsBuiltin
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                }
            }
        )
        $ReportingAzureRoles = @(
            foreach ($object in @($item.AzureRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $object.RoleName
                    "RoleType" = $object.RoleType
                    "Tier Level" = $object.RoleTier
                    "Conditions" = $object.Conditions
                    "Scoped to" = $object.Scope
                }
            }
        )
        $ReportingGroupOwner = @(
            foreach ($object in @($item.GroupOwner)) {
                [pscustomobject]@{
                    DisplayName = "<a href=Groups_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                    SecurityEnabled = $object.SecurityEnabled
                    RoleAssignable = $object.RoleAssignable
                    EntraRoles = $object.AssignedRoleCount
                    AzureRoles = $object.AzureRoles
                    CAPs = $object.CAPs
                    ImpactOrg = $object.ImpactOrg
                    Warnings = $object.Warnings
                }
            }
        )
        $ReportingAppOwner = @(
            foreach ($object in @($item.OwnedApplicationsDetails)) {
                [pscustomobject]@{
                    DisplayName = "<a href=AppRegistration_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                }
            }
        )
        $ReportingSPOwner = @(
            foreach ($object in @($item.OwnedSPDetails)) {
                [pscustomobject]@{
                    DisplayName = "<a href=#$($object.id)>$($object.DisplayName)</a>"
                    Foreign = $object.Foreign
                    Impact = $object.Impact
                }
            }
        )
        $ReportingGroupMember = @(
            foreach ($object in @($item.GroupMember)) {
                [pscustomobject]@{
                    DisplayName = "<a href=Groups_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.DisplayName)</a>"
                    SecurityEnabled = $object.SecurityEnabled
                    RoleAssignable = $object.RoleAssignable
                    EntraRoles = $object.AssignedRoleCount
                    AzureRoles = $object.AzureRoles
                    CAPs = $object.CAPs
                    "Impact (No Eligible)" = $object.ImpactOrgActiveOnly
                    Warnings = $object.Warnings
                }
            }
        )
        [void]$PrincipalTxt.AppendLine("############################################################################################################################################")
        [void]$PrincipalTxt.AppendLine(($item | Select-Object DisplayName,AppId,ParentBlueprintDisplayName,@{Name = 'Child Agent Identities'; Expression = { $_.LinkedAgentIdentities }},@{Name = 'Child Agent Users'; Expression = { $_.AgentUsers }},DirectImpact,InheritedImpact,Impact,Likelihood,Risk,Warnings | Out-String))
        if (($item.LinkedAgentIdentitiesDetails | Measure-Object).Count -ge 1) {
            [void]$PrincipalTxt.AppendLine("Child Agent Identities")
            [void]$PrincipalTxt.AppendLine(($item.LinkedAgentIdentitiesDetails | Format-Table DisplayName,Enabled,Impact,Warnings | Out-String))
        }
        if (($item.AgentUsersDetails | Measure-Object).Count -ge 1) {
            [void]$PrincipalTxt.AppendLine("Child Agent Users")
            [void]$PrincipalTxt.AppendLine(($item.AgentUsersDetails | Format-Table ParentAgentIdentityDisplayName,UPN,Enabled,Impact,Warnings | Out-String))
        }
        $parentBlueprintLink = if ($item.ParentBlueprintId) { "<a href=AgentIdentityBlueprints_$($StartTimestamp)_$EscapedTenantName.html#$($item.ParentBlueprintId)>$($item.ParentBlueprintDisplayName)</a>" } else { "-" }
        Add-ObjectDetails -Collection $PrincipalDetails -ObjectName $item.DisplayName -ObjectId $item.Id -Sections ([ordered]@{
            "General Information" = [pscustomobject]@{
                "App Name" = $item.DisplayName
                "Publisher Name" = $item.PublisherName
                "Publisher TenantId" = $item.AppOwnerOrganizationId
                "Enabled" = $item.Enabled
                "CreationDate" = $item.CreationDate
                "Client-ID" = $item.AppId
                "Object-ID" = $item.Id
                "Parent Blueprint" = $parentBlueprintLink
                "MS Default" = $item.DefaultMS
                "Foreign" = $item.Foreign
                "Require AppRole" = $item.AppRoleRequired
                "Child Agent Identities" = $item.LinkedAgentIdentities
                "Child Agent Users" = $item.AgentUsers
                "DirectImpact" = $item.DirectImpact
                "InheritedImpact" = $item.InheritedImpact
                "RiskScore" = $item.Risk
                "Warnings" = $item.Warnings
            }
            "Last Sign-Ins Details" = [pscustomobject]@{
                "Last sign-in overall" = $lastSignInOverall
                "Last sign-in as application (client)" = $lastSignInAppClient
                "Last sign-in as application (resource)" = $lastSignInAppResource
                "Last sign-in delegated (client)" = $lastSignInDelegatedClient
                "Last sign-in delegated (resource)" = $lastSignInDelegatedResource
            }
            "Child Agent Identities" = @(
                foreach ($agentIdentity in @($item.LinkedAgentIdentitiesDetails)) {
                    [pscustomobject]@{
                        DisplayName = "<a href=AgentIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($agentIdentity.Id)>$($agentIdentity.DisplayName)</a>"
                        Enabled = $agentIdentity.Enabled
                        Impact = $agentIdentity.Impact
                        Warnings = $agentIdentity.Warnings
                    }
                }
            )
            "Child Agent Users" = @(
                foreach ($agentUser in @($item.AgentUsersDetails)) {
                    [pscustomobject]@{
                        ParentAgentIdentity = "<a href=AgentIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.ParentAgentIdentityId)>$($agentUser.ParentAgentIdentityDisplayName)</a>"
                        UserPrincipalName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.Id)>$($agentUser.UPN)</a>"
                        Enabled = $agentUser.Enabled
                        Impact = $agentUser.Impact
                        Warnings = $agentUser.Warnings
                    }
                }
            )
            "Blueprint Principal Effective Application API Permissions" = @(
                foreach ($object in @($item.BlueprintPrincipalEffectiveAppApiPermission)) {
                    [pscustomobject]@{
                        API = $object.ApiName
                        Category = $object.ApiPermissionCategorization
                        Permission = $object.ApiPermission
                        Reason = $object.Reason
                    }
                }
            )
            "Configured Application API Permissions" = @(
                foreach ($object in @($item.AppApiPermission)) {
                    if (Test-BlueprintPrincipalEffectiveApplicationPermission -Permission $object) {
                        continue
                    }
                    [pscustomobject]@{
                        API = $object.ApiName
                        Category = $object.ApiPermissionCategorization
                        Permission = $object.ApiPermission
                    }
                }
            )
            "Configured Delegated API Permissions" = @(
                foreach ($object in @($item.ApiDelegatedDetails)) {
                    $userDetails = $AllUsersBasicHT[$object.Principal]
                    if ($userDetails) {
                        $principalLink = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($object.Principal)>$($userDetails.UserPrincipalName)</a>"
                    } else {
                        $principalLink = $object.Principal
                    }
                    [pscustomobject]@{
                        APIName = $object.APIName
                        Permission = $object.Scope
                        Categorization = $object.ApiPermissionCategorization
                        ConsentType = $object.ConsentType
                        Principal = $principalLink
                    }
                }
            )
            "Active Entra Role Assignments" = $ReportingRoles
            "Azure IAM assignments" = $ReportingAzureRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owned App Registrations" = $ReportingAppOwner
            "Owned Service Principals" = $ReportingSPOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Assigned App Roles" = @(
                foreach ($object in @($item.AppRolesDetails)) {
                    [pscustomobject]@{
                        Claim = $object.AppRoleClaim
                        Name = $object.AppRoleName
                        RoleEnabled = $object.RoleEnabled
                        AssignmentType = $object.AppRoleAssignmentType
                        Member = $object.AppRoleMember
                    }
                }
            )
            "Owners (Users)" = @(
                foreach ($object in @($item.OwnerUserDetails)) {
                    [pscustomobject]@{
                        UserName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($object.id)>$($object.UPN)</a>"
                        Enabled = $object.Enabled
                        Type = $object.Type
                        OnPremSync = $object.OnPremSync
                        Department = $object.Department
                        JobTitle = $object.JobTitle
                    }
                }
            )
            "Owners (Service Principals / Agent Objects)" = @(
                foreach ($object in @($item.OwnerSPDetails)) {
                    $resolvedOwner = Resolve-FinalizedAgentNonUserOwner -Owner $object -CurrentTenant $CurrentTenant -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals
                    if ($null -eq $resolvedOwner) {
                        continue
                    }
                    [pscustomobject]@{
                        DisplayName = Get-AgentOwnerLink -ResolvedOwner $resolvedOwner -StartTimestamp $StartTimestamp -EscapedTenantName $EscapedTenantName
                        Enabled = if ($null -ne $resolvedOwner.Enabled) { $resolvedOwner.Enabled } else { "-" }
                        PublisherName = $resolvedOwner.PublisherName
                        Type = if ($resolvedOwner.Type -in @('ServicePrincipal', 'ManagedIdentity')) { $resolvedOwner.ServicePrincipalType } else { $resolvedOwner.Type }
                    }
                }
            )
        })
    }

    $PrincipalWarnings = Get-AgentReportWarnings -ReportKey 'AgentIdentityBlueprintsPrincipals'
    $PrincipalApiReference = Get-ApiPermissionReferenceData -Items $PrincipalItems
    $PrincipalAppendixTxt = ""
    $PrincipalAppendixHtml = ""
    if ($PrincipalApiReference.Count -ge 1) {
        $PrincipalAppendixTxt = @"

=======================================================================================================================
Appendix: Used API Permission Reference
=======================================================================================================================
"@
        $PrincipalAppendixTxt += "`n" + (($PrincipalApiReference | Format-Table -AutoSize | Out-String).TrimEnd())
        $PrincipalAppendixHtml = $PrincipalApiReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
    }

    $GlobalAuditSummary.AgentIdentityBlueprintsPrincipals.Count = $PrincipalItems.Count
    $GlobalAuditSummary.AgentIdentityBlueprintsPrincipals.Foreign = @($PrincipalItems | Where-Object { $_.Foreign }).Count

    $PrincipalTableOutput = @(
        $PrincipalItems | Select-Object DisplayName,ParentBlueprintDisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,CreationInDays,@{Name = 'AgentIdentities'; Expression = { $_.LinkedAgentIdentities }},AgentUsers,Owners,AppRoles,
        ApiDangerous,ApiHigh,ApiMedium,ApiLow,ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,
        Impact,Likelihood,Risk,Warnings
    )
    $PrincipalMainTable = @(
        $PrincipalItems | Select-Object @{Name = "DisplayName"; Expression = { $_.DisplayNameLink }},ParentBlueprintDisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,CreationInDays,@{Name = 'AgentIdentities'; Expression = { $_.LinkedAgentIdentities }},AgentUsers,Owners,AppRoles,
        ApiDangerous,ApiHigh,ApiMedium,ApiLow,ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,
        Impact,Likelihood,Risk,Warnings
    )

    if ($PrincipalItems.Count -gt 0) {
        New-ReportFileSet -Title "AgentIdentityBlueprintsPrincipals" -ReportKey "AgentIdentityBlueprintsPrincipals" -ReportName "Agent Identity Blueprint Principals Enumeration (BETA)" -HtmlTitle "EF - Agent Blueprint Principals" -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -TableOutput $PrincipalTableOutput -MainTable $PrincipalMainTable -AllObjectDetailsHTML $PrincipalDetails -DetailOutputTxt $PrincipalTxt.ToString() -TxtColumns @('DisplayName','ParentBlueprintDisplayName','AppRoleRequired','PublisherName','DefaultMS','Foreign','Enabled','Inactive','LastSignInDays','CreationInDays','AgentIdentities','AgentUsers','Owners','AppRoles','ApiDangerous','ApiHigh','ApiMedium','ApiLow','ApiMisc','ApiDelegated','ApiDelegatedDangerous','ApiDelegatedHigh','ApiDelegatedMedium','ApiDelegatedLow','ApiDelegatedMisc','Impact','Likelihood','Risk','Warnings') -WarningList $PrincipalWarnings -AppendixTxt $PrincipalAppendixTxt -AppendixHtml $PrincipalAppendixHtml -Csv:$Csv
    } else {
        Write-Host "[*] No agent identity blueprint principals found. Skipping Agent Blueprint Principals report output."
    }

    $BlueprintDetails = [System.Collections.ArrayList]::new()
    $BlueprintTxt = [System.Text.StringBuilder]::new()
    $BlueprintItems = @($AgentIdentityBlueprints.Values | Sort-Object Risk -Descending)
    foreach ($item in $BlueprintItems) {
        [void]$BlueprintTxt.AppendLine("############################################################################################################################################")
        [void]$BlueprintTxt.AppendLine(($item | Select-Object DisplayName,AppId,Enabled,@{Name = 'Child Blueprint Principals'; Expression = { $_.BlueprintPrincipals }},@{Name = 'Child Agent Identities'; Expression = { $_.LinkedAgentIdentities }},@{Name = 'Child Agent Users'; Expression = { $_.AgentUsers }},Impact,Likelihood,Risk,Warnings | Out-String))
        if (($item.BlueprintPrincipalsDetails | Measure-Object).Count -ge 1) {
            [void]$BlueprintTxt.AppendLine("Child Blueprint Principals")
            [void]$BlueprintTxt.AppendLine(($item.BlueprintPrincipalsDetails | Select-Object DisplayName,@{Name = 'Child Agent Identities'; Expression = { $_.LinkedAgentIdentities }},@{Name = 'Child Agent Users'; Expression = { $_.AgentUsers }},Impact,Warnings | Format-Table | Out-String))
        }
        if (($item.LinkedAgentIdentitiesDetails | Measure-Object).Count -ge 1) {
            [void]$BlueprintTxt.AppendLine("Child Agent Identities")
            [void]$BlueprintTxt.AppendLine(($item.LinkedAgentIdentitiesDetails | Format-Table ParentPrincipalDisplayName,DisplayName,Enabled,Impact,Warnings | Out-String))
        }
        if (($item.AgentUsersDetails | Measure-Object).Count -ge 1) {
            [void]$BlueprintTxt.AppendLine("Child Agent Users")
            [void]$BlueprintTxt.AppendLine(($item.AgentUsersDetails | Format-Table ParentPrincipalDisplayName,ParentAgentIdentityDisplayName,UPN,Enabled,Impact,Warnings | Out-String))
        }
        if (($item.Oauth2PermissionScopesDetails | Measure-Object).Count -ge 1) {
            [void]$BlueprintTxt.AppendLine("OAuth2 Permission Scopes")
            [void]$BlueprintTxt.AppendLine(($item.Oauth2PermissionScopesDetails | Format-Table Value,IsEnabled,Type,IsPrivate | Out-String))
        }
        if (($item.InheritablePermissionsDetails | Measure-Object).Count -ge 1) {
            [void]$BlueprintTxt.AppendLine("Inheritable Permissions")
            [void]$BlueprintTxt.AppendLine(($item.InheritablePermissionsDetails | Format-Table ResourceApiName,ResourceAppId,PermissionType,Kind,Permissions | Out-String -Width 320))
        }
        Add-ObjectDetails -Collection $BlueprintDetails -ObjectName $item.DisplayName -ObjectId $item.Id -Sections ([ordered]@{
            "General Information" = [pscustomobject]@{
                "Blueprint Name" = $item.DisplayName
                "Blueprint Client-ID" = $item.AppId
                "Blueprint Object-ID" = $item.Id
                "Enabled" = $item.Enabled
                "CreationDate" = $item.CreationDate
                "SignInAudience" = $item.SignInAudience
                "Child Blueprint Principals" = $item.BlueprintPrincipals
                "Child Agent Identities" = $item.LinkedAgentIdentities
                "Child Agent Users" = $item.AgentUsers
                "Impact" = $item.Impact
                "Likelihood" = $item.Likelihood
                "RiskScore" = $item.Risk
                "Warnings" = $item.Warnings
            }
            "Blueprint Credentials" = @(
                foreach ($object in @($item.AppCredentialsDetails)) {
                    [pscustomobject]@{
                        Type = $object.Type
                        DisplayName = $object.DisplayName
                        StartDateTime = if ($null -ne $object.StartDateTime) { $object.StartDateTime.ToString() } else { "-" }
                        EndDateTime = if ($null -ne $object.EndDateTime) { $object.EndDateTime.ToString() } else { "-" }
                    }
                }
            )
            "Blueprint Roles" = @(
                foreach ($object in @($item.AppRolesDetails)) {
                    [pscustomobject]@{
                        DisplayName = $object.DisplayName
                        Enabled = $object.Enabled
                        Claim = $object.Claim
                        MemberTypes = $object.MemberTypes
                        Description = $object.Description
                    }
                }
            )
            "OAuth2 Permission Scopes" = @(
                foreach ($object in @($item.Oauth2PermissionScopesDetails)) {
                    [pscustomobject]@{
                        Value = $object.Value
                        IsEnabled = $object.IsEnabled
                        Type = $object.Type
                        IsPrivate = $object.IsPrivate
                    }
                }
            )
            "Child Blueprint Principals" = @(
                foreach ($principal in @($item.BlueprintPrincipalsDetails)) {
                    [pscustomobject]@{
                        DisplayName = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$EscapedTenantName.html#$($principal.Id)>$($principal.DisplayName)</a>"
                        "Child Agent Identities" = $principal.LinkedAgentIdentities
                        "Child Agent Users" = $principal.AgentUsers
                        DirectImpact = $principal.DirectImpact
                        InheritedImpact = $principal.InheritedImpact
                        Impact = $principal.Impact
                        Warnings = $principal.Warnings
                    }
                }
            )
            "Child Agent Identities" = @(
                foreach ($agentIdentity in @($item.LinkedAgentIdentitiesDetails)) {
                    [pscustomobject]@{
                        ParentPrincipal = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$EscapedTenantName.html#$($agentIdentity.ParentPrincipalId)>$($agentIdentity.ParentPrincipalDisplayName)</a>"
                        DisplayName = "<a href=AgentIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($agentIdentity.Id)>$($agentIdentity.DisplayName)</a>"
                        Enabled = $agentIdentity.Enabled
                        Impact = $agentIdentity.Impact
                        Warnings = $agentIdentity.Warnings
                    }
                }
            )
            "Child Agent Users" = @(
                foreach ($agentUser in @($item.AgentUsersDetails)) {
                    [pscustomobject]@{
                        ParentPrincipal = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.ParentPrincipalId)>$($agentUser.ParentPrincipalDisplayName)</a>"
                        ParentAgentIdentity = "<a href=AgentIdentities_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.ParentAgentIdentityId)>$($agentUser.ParentAgentIdentityDisplayName)</a>"
                        UserPrincipalName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($agentUser.Id)>$($agentUser.UPN)</a>"
                        Enabled = $agentUser.Enabled
                        Impact = $agentUser.Impact
                        Warnings = $agentUser.Warnings
                    }
                }
            )
            "Owners (Users)" = @(
                foreach ($owner in @($item.AppOwnerUsers)) {
                    [pscustomobject]@{
                        UserName = "<a href=Users_$($StartTimestamp)_$EscapedTenantName.html#$($owner.id)>$($owner.userPrincipalName)</a>"
                        Enabled = $owner.accountEnabled
                        Type = $owner.userType
                    }
                }
            )
            "Owners (Service Principals / Agent Objects)" = @(
                foreach ($owner in @($item.AppOwnerSPs)) {
                    $resolvedOwner = Resolve-FinalizedAgentNonUserOwner -Owner $owner -CurrentTenant $CurrentTenant -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals
                    if ($null -eq $resolvedOwner) {
                        continue
                    }

                    [pscustomobject]@{
                        DisplayName   = Get-AgentOwnerLink -ResolvedOwner $resolvedOwner -StartTimestamp $StartTimestamp -EscapedTenantName $EscapedTenantName
                        Type          = if ($resolvedOwner.Type -in @('ServicePrincipal', 'ManagedIdentity')) { $resolvedOwner.ServicePrincipalType } else { $resolvedOwner.Type }
                        Foreign       = $resolvedOwner.Foreign
                        PublisherName = $resolvedOwner.PublisherName
                        OwnersCount   = $resolvedOwner.OwnersCount
                        Enabled       = if ($null -ne $resolvedOwner.Enabled) { $resolvedOwner.Enabled } else { "-" }
                    }
                }
            )
            "Sponsors" = @(
                foreach ($sponsor in @($item.AppSponsorsDetails)) {
                    [pscustomobject]@{
                        Type = $sponsor.Type
                        DisplayName = $sponsor.DisplayName
                        UPN = $sponsor.UPN
                        Foreign = $sponsor.Foreign
                    }
                }
            )
            "Inheritable Permissions" = @(
                foreach ($object in @($item.InheritablePermissionsDetails)) {
                    [pscustomobject]@{
                        ResourceApiName = $object.ResourceApiName
                        ResourceAppId = $object.ResourceAppId
                        PermissionType = $object.PermissionType
                        Kind = $object.Kind
                        Permissions = $object.Permissions
                    }
                }
            )
            "Federated Identity Credentials" = @(
                foreach ($object in @($item.FederatedIdentityCredentialsDetails)) {
                    [pscustomobject]@{
                        Name = $object.Name
                        Issuer = $object.Issuer
                        Subject = $object.Subject
                        Description = $object.Description
                        Audiences = $object.Audiences
                    }
                }
            )
        })
    }

    $BlueprintWarnings = Get-AgentReportWarnings -ReportKey 'AgentIdentityBlueprints'
    $BlueprintSecretsAppendix = Get-BlueprintSecretsAppendixData -Items $BlueprintItems
    $BlueprintAppendixTxt = ""
    $BlueprintAppendixHtml = ""
    $BlueprintAdditionalCsvExports = @()
    if ($BlueprintSecretsAppendix.Count -ge 1) {
        $BlueprintAppendixTxt = @"

===============================================================================================================================================
Appendix: Agent Identity Blueprints with Client Secrets
===============================================================================================================================================
"@
        $BlueprintAppendixTxt += "`n" + (($BlueprintSecretsAppendix | Format-Table | Out-String).TrimEnd())
        $BlueprintAppendixHtml = $BlueprintSecretsAppendix | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Blueprints With Secrets</h2>"
        $BlueprintAdditionalCsvExports += @{
            Path = "$OutputFolder\AgentIdentityBlueprints_Secrets_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv"
            Data = $BlueprintSecretsAppendix
        }
    }

    $GlobalAuditSummary.AgentIdentityBlueprints.Count = $BlueprintItems.Count
    $GlobalAuditSummary.AgentIdentityBlueprints.Credentials.Secrets = @($BlueprintItems | Where-Object { $_.SecretsCount -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentityBlueprints.Credentials.Certificates = @($BlueprintItems | Where-Object { $_.CertsCount -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentityBlueprints.Credentials.'Federated Credentials' = @($BlueprintItems | Where-Object { $_.FederatedCreds -gt 0 }).Count
    $GlobalAuditSummary.AgentIdentityBlueprints.Credentials.None = @($BlueprintItems | Where-Object { $_.SecretsCount -eq 0 -and $_.CertsCount -eq 0 -and $_.FederatedCreds -eq 0 }).Count

    $BlueprintTableOutput = @(
        $BlueprintItems | Select-Object DisplayName,SignInAudience,Enabled,CreationInDays,BlueprintPrincipals,@{Name = 'AgentIdentities'; Expression = { $_.LinkedAgentIdentities }},AgentUsers,AppRoles,Owners,Sponsors,@{Name = 'InheritableScopes'; Expression = { $_.InhScopes }},@{Name = 'InheritableRoles'; Expression = { $_.InhRoles }},FederatedCreds,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings
    )
    $BlueprintMainTable = @(
        $BlueprintItems | Select-Object @{Name = "DisplayName"; Expression = { $_.DisplayNameLink }},SignInAudience,Enabled,CreationInDays,BlueprintPrincipals,@{Name = 'AgentIdentities'; Expression = { $_.LinkedAgentIdentities }},AgentUsers,AppRoles,Owners,Sponsors,@{Name = 'InheritableScopes'; Expression = { $_.InhScopes }},@{Name = 'InheritableRoles'; Expression = { $_.InhRoles }},FederatedCreds,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings
    )

    if ($BlueprintItems.Count -gt 0) {
        New-ReportFileSet -Title "AgentIdentityBlueprints" -ReportKey "AgentIdentityBlueprints" -ReportName "Agent Identity Blueprints Enumeration (BETA)" -HtmlTitle "EF - Agent Blueprints" -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -TableOutput $BlueprintTableOutput -MainTable $BlueprintMainTable -AllObjectDetailsHTML $BlueprintDetails -DetailOutputTxt $BlueprintTxt.ToString() -TxtColumns @('DisplayName','SignInAudience','Enabled','CreationInDays','BlueprintPrincipals','AgentIdentities','AgentUsers','AppRoles','Owners','Sponsors','InheritableScopes','InheritableRoles','FederatedCreds','SecretsCount','CertsCount','Impact','Likelihood','Risk','Warnings') -WarningList $BlueprintWarnings -AppendixTxt $BlueprintAppendixTxt -AppendixHtml $BlueprintAppendixHtml -AdditionalCsvExports $BlueprintAdditionalCsvExports -Csv:$Csv
    } else {
        Write-Host "[*] No agent identity blueprints found. Skipping Agent Blueprints report output."
    }
}
