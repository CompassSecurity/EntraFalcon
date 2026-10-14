<#
.SYNOPSIS
   Collects and enriches Entra ID and Azure IAM role assignments, producing output in HTML, TXT, and CSV formats.
#>

function Get-RoleAssignmentIdentityCount {
    param([string]$PrincipalId, [string]$PrincipalType, [hashtable]$RoleGroupIdentityCountIndex = @{})

    if (-not [string]::IsNullOrWhiteSpace($PrincipalId) -and $RoleGroupIdentityCountIndex.ContainsKey($PrincipalId)) {
        return $RoleGroupIdentityCountIndex[$PrincipalId]
    }
    $normalizedType = ($PrincipalType -replace '[\s_-]', '').ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($PrincipalId) -and $normalizedType -in @('user', 'guest', 'guestuser', 'agentuser', 'serviceprincipal', 'enterpriseapplication', 'managedidentity', 'agentidentity', 'agentidentityblueprintprincipal', 'serviceidentity', 'foreignuser', 'foreignserviceprincipal')) {
        return [pscustomobject]@{ Count = 1; Complete = $true }
    }
    return [pscustomobject]@{ Count = 0; Complete = $false }
}

# Formats an Azure role definition timestamp as a UTC date; ARM values arrive as strings on 5.1 and as DateTime on 7.
function Format-AzureRoleDefinitionDate {
    param (
        [Parameter(Mandatory = $false)]
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }

    if ($Value -is [datetime]) {
        $dateValue = if ($Value.Kind -eq [System.DateTimeKind]::Local) { $Value.ToUniversalTime() } else { $Value }
        return $dateValue.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $parsedValue = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedValue)) {
        return $parsedValue.UtcDateTime.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    return [string]$Value
}

# Builds the report model for one Azure role definition from its definition and its assignments in this report.
function Get-AzureRoleDefinitionDetailModel {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RoleDefinitionId,

        [Parameter(Mandatory = $true)]
        [object[]]$Assignments,

        [Parameter(Mandatory = $false)]
        [object]$Definition
    )

    $firstAssignment = @($Assignments)[0]
    $roleName = [string]$firstAssignment.Role
    $roleType = [string]$firstAssignment.RoleType
    if ($null -ne $Definition) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Definition.RoleName)) { $roleName = [string]$Definition.RoleName }
        if (-not [string]::IsNullOrWhiteSpace([string]$Definition.RoleType)) { $roleType = [string]$Definition.RoleType }
    }
    $isCustomRole = $roleType -match 'Custom'

    $activeCount = 0
    $eligibleCount = 0
    $scopeTypeCounts = @{}
    $impacts = [System.Collections.Generic.List[int]]::new()
    foreach ($assignment in @($Assignments)) {
        if ([string]$assignment.AssignmentType -eq 'Eligible') { $eligibleCount++ } else { $activeCount++ }
        $scopeType = if ([string]::IsNullOrWhiteSpace([string]$assignment.ScopeType)) { 'Unknown' } else { [string]$assignment.ScopeType }
        if ($scopeTypeCounts.ContainsKey($scopeType)) { $scopeTypeCounts[$scopeType]++ } else { $scopeTypeCounts[$scopeType] = 1 }
        $impactValue = 0
        if ([int]::TryParse([string]$assignment.AssignmentImpact, [ref]$impactValue)) { $impacts.Add($impactValue) }
    }

    $scopeTypeOrder = @('Root', 'ManagementGroup', 'Subscription', 'ResourceGroup', 'Resource', 'Unknown')
    $orderedScopeTypes = @($scopeTypeOrder | Where-Object { $scopeTypeCounts.ContainsKey($_) }) + @($scopeTypeCounts.Keys | Where-Object { $scopeTypeOrder -notcontains $_ } | Sort-Object)
    $scopeTypeText = (@($orderedScopeTypes | ForEach-Object { "$_ ($($scopeTypeCounts[$_]))" }) -join ', ')

    $impactRange = '-'
    $highestLevel = '-'
    if ($impacts.Count -gt 0) {
        $impactStatistics = $impacts | Measure-Object -Minimum -Maximum
        $minimumImpact = [int]$impactStatistics.Minimum
        $maximumImpact = [int]$impactStatistics.Maximum
        $impactRange = if ($minimumImpact -eq $maximumImpact) { "$maximumImpact" } else { "$minimumImpact - $maximumImpact" }
        $highestLevel = Get-AzureImpactLevel -Impact $maximumImpact
    }

    $generalInformation = [ordered]@{
        'Role'        = $roleName
        'Role ID'     = $RoleDefinitionId
        'Type'        = $roleType
        'Description' = if ($null -ne $Definition) { [string]$Definition.Description } else { $null }
    }
    if ($null -eq $Definition) {
        $generalInformation['Role Definition'] = 'Not available'
    } elseif ($isCustomRole) {
        $generalInformation['Assignable Scopes'] = (@(@($Definition.AssignableScopes) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ', ')
        $generalInformation['Created'] = Format-AzureRoleDefinitionDate -Value $Definition.CreatedOn
        $generalInformation['Updated'] = Format-AzureRoleDefinitionDate -Value $Definition.UpdatedOn
    }
    $generalInformation['Assignments'] = @($Assignments).Count
    $generalInformation['Active / Eligible'] = "$activeCount / $eligibleCount"
    $generalInformation['Scope Types'] = $scopeTypeText
    $generalInformation['Highest Level'] = $highestLevel
    $generalInformation['Assignment Impact'] = $impactRange

    # Tier, source and reason are resolved per role ID, so every assignment of the role carries the same values.
    $tierReason = [string]$firstAssignment.TierReason
    $tierSource = [string]$firstAssignment.TierSource
    $sourceLabel = switch ($tierSource) {
        'Rated' { 'Curated rating' }
        'Derived' { 'Derived from permissions' }
        'Unknown' { 'Unknown' }
        default { '-' }
    }
    $reasonDescription = Get-AzureRoleTierReasonDescription -Reason $tierReason
    $tierLabel = if ([string]::IsNullOrWhiteSpace([string]$firstAssignment.RoleTier)) { 'Uncategorized' } else { [string]$firstAssignment.RoleTier }
    $baseImpact = Get-AzureRoleBaseImpact -RoleTier $tierLabel -RoleDefinitionId $RoleDefinitionId

    $classification = [ordered]@{
        'Tier'   = $tierLabel
        'Source' = $sourceLabel
        'Rule'   = $reasonDescription.Rule
    }
    # The cached classification exists for derived roles; curated roles are analysed here for display only and never cached.
    $permissionAnalysis = $null
    if ($GLOBALAzureRoleClassifications -and $GLOBALAzureRoleClassifications.ContainsKey($RoleDefinitionId)) {
        $permissionAnalysis = $GLOBALAzureRoleClassifications[$RoleDefinitionId]
    } elseif ($null -ne $Definition) {
        $permissionAnalysis = Get-AzureRoleTierFromPermissions -Permissions @($Definition.Permissions)
    }

    $writeResourceTypes = @()
    if ($null -ne $permissionAnalysis) {
        $writeResourceTypes = @(@($permissionAnalysis.WriteResourceTypes) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    }
    $definitionBlockCount = 0
    if ($null -ne $Definition) {
        $definitionBlockCount = @(@($Definition.Permissions) | Where-Object { $null -ne $_ }).Count
    }
    $operationLabels = Get-AzureRoleOperationLabels
    $operationCaveats = Get-AzureRoleOperationCaveats
    $operationDescriptions = Get-AzureRoleOperationDisplayDescriptions
    $ruleMatches = [System.Collections.Generic.List[object]]::new()
    $matchedRules = [System.Collections.Generic.List[object]]::new()
    $riskItems = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $permissionAnalysis) {
        foreach ($ruleMatch in @($permissionAnalysis.Matches)) {
            if ($null -eq $ruleMatch) { continue }
            $ruleMatches.Add($ruleMatch)
            $ruleId = [string]$ruleMatch.Rule
            $permission = [string]$ruleMatch.Permission
            $grantedBy = [string]$ruleMatch.GrantedBy
            $blockSuffix = if ($definitionBlockCount -gt 1) { " (block $($ruleMatch.Block))" } else { '' }
            $ruleDescription = (Get-AzureRoleTierReasonDescription -Reason ([string]$ruleMatch.Reason)).Rule
            if ($ruleId -eq 'B1' -and $operationLabels.Contains($permission)) {
                $ruleDescription = [string]$operationLabels[$permission]
                if ($operationCaveats.Contains($permission)) {
                    $ruleDescription += ". $($operationCaveats[$permission])"
                }
            }
            $matchedRules.Add([pscustomobject]@{
                Rule         = $ruleDescription
                Permission   = $permission
                'Granted By' = "$grantedBy$blockSuffix"
            })
        }
        foreach ($ruleMatch in @(Select-AzureRoleDisplayRuleMatches -RuleMatches $ruleMatches.ToArray())) {
            $ruleId = [string]$ruleMatch.Rule
            $permission = [string]$ruleMatch.Permission
            $grantedBy = [string]$ruleMatch.GrantedBy
            $blockSuffix = if ($definitionBlockCount -gt 1) { " (block $($ruleMatch.Block))" } else { '' }
            $viaSuffix = if (-not [string]::IsNullOrWhiteSpace($grantedBy) -and $grantedBy -ne $permission) { " (via $grantedBy)" } else { '' }
            $noteSuffix = ''
            if ($ruleId -eq 'A3') {
                $noteSuffix = ' - only effective at root scope'
            } elseif ($ruleId -eq 'B1' -and $operationDescriptions.Contains($permission)) {
                $noteSuffix = " - $($operationDescriptions[$permission])"
            } elseif ($ruleId -eq 'B1' -and $operationLabels.Contains($permission)) {
                $noteSuffix = " - $($operationLabels[$permission])"
                if ($operationCaveats.Contains($permission)) {
                    $noteSuffix += ". $($operationCaveats[$permission])"
                }
            }
            $itemGroup = switch -Wildcard ($ruleId) {
                'A*' { 'Access control' }
                'B1' { 'Potentially high-impact operations' }
                'B2' { 'Debug snapshots' }
                'B3' { 'Data plane' }
                default { 'Writes and actions' }
            }
            $riskItems.Add([pscustomobject]@{ Group = $itemGroup; Text = "$permission$viaSuffix$blockSuffix$noteSuffix" })
        }
    }

    # Keep supporting detail in the rule only when the matched permissions do not already cover it.
    $summaryCoversReason = ($ruleMatches.Count -gt 0 -and [string]$ruleMatches[0].Reason -eq $tierReason)
    if (-not [string]::IsNullOrWhiteSpace([string]$reasonDescription.Evidence) -and -not $summaryCoversReason) {
        $classification['Rule'] = "$($reasonDescription.Rule): $($reasonDescription.Evidence)"
    } elseif ($tierReason -in @('bounded resource write or delete', 'cross-family resource control') -and $writeResourceTypes.Count -gt 0) {
        $classification['Rule'] = "$($reasonDescription.Rule): $($writeResourceTypes -join ', ')"
    }

    $assignableRoles = [System.Collections.Generic.List[object]]::new()
    $cachedClassification = $null
    if ($tierSource -eq 'Derived' -and $GLOBALAzureRoleClassifications -and $GLOBALAzureRoleClassifications.ContainsKey($RoleDefinitionId)) {
        $cachedClassification = $GLOBALAzureRoleClassifications[$RoleDefinitionId]
    }
    if ($null -ne $cachedClassification -and $cachedClassification.ConstrainedAssignment) {
        # When an assignable role raised the tier, the displayed reason names that role; the permission rule is the role's own result.
        $permissionReason = [string]$cachedClassification.Reason
        if (-not [string]::IsNullOrWhiteSpace($permissionReason) -and $permissionReason -ne $tierReason) {
            $permissionDescription = Get-AzureRoleTierReasonDescription -Reason $permissionReason
            $classification['Permission Rule'] = if ([string]::IsNullOrWhiteSpace([string]$permissionDescription.Evidence)) {
                $permissionDescription.Rule
            } else {
                "$($permissionDescription.Rule): $($permissionDescription.Evidence)"
            }
        }

        foreach ($assignableRoleId in @($cachedClassification.AssignableRoleIds)) {
            $assignableRoleKey = [string]$assignableRoleId
            if ([string]::IsNullOrWhiteSpace($assignableRoleKey)) { continue }
            $assignableRoleName = $assignableRoleKey
            if ($GLOBALAzureRoleDefinitions -and $GLOBALAzureRoleDefinitions.ContainsKey($assignableRoleKey)) {
                $assignableRoleName = [string]$GLOBALAzureRoleDefinitions[$assignableRoleKey].RoleName
            }
            $assignableTier = Resolve-AzureRoleTier -RoleDefinitionId $assignableRoleKey
            $assignableSource = switch ([string]$assignableTier.Source) {
                'Rated' { 'Curated rating' }
                'Derived' { 'Derived from permissions' }
                default { 'Unknown' }
            }
            $assignableRoles.Add([pscustomobject]@{
                RoleDefinitionId = $assignableRoleKey
                Role             = $assignableRoleName
                Tier             = if ([string]$assignableTier.Tier -eq '?') { 'Uncategorized' } else { "Tier-$($assignableTier.Tier)" }
                Source           = $assignableSource
            })
        }
    }

    $permissionSections = [ordered]@{}
    if ($null -ne $Definition) {
        $permissionBlocks = @(@($Definition.Permissions) | Where-Object { $null -ne $_ })
        $blockIndex = 0
        foreach ($permissionBlock in $permissionBlocks) {
            $blockIndex++
            $sectionSuffix = if ($permissionBlocks.Count -gt 1) { " (block $blockIndex)" } else { '' }
            foreach ($sectionName in @('Actions', 'NotActions', 'DataActions', 'NotDataActions')) {
                $sectionValues = @(@($permissionBlock.$sectionName) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
                if ($sectionValues.Count -gt 0) {
                    $permissionSections["$sectionName$sectionSuffix"] = $sectionValues
                }
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$permissionBlock.condition)) {
                $permissionSections["Condition$sectionSuffix"] = @([string]$permissionBlock.condition)
            }
        }
    }

    return [pscustomobject]@{
        RoleDefinitionId    = $RoleDefinitionId
        RoleName            = $roleName
        DefinitionAvailable = ($null -ne $Definition)
        BaseImpact          = $baseImpact
        GeneralInformation  = $generalInformation
        Classification      = $classification
        TierLabel           = $tierLabel
        TierSource          = $tierSource
        HasRootAssignment   = $scopeTypeCounts.ContainsKey('Root')
        RuleMatches         = $ruleMatches.ToArray()
        MatchedRules        = $matchedRules.ToArray()
        RiskItems           = $riskItems.ToArray()
        AssignableRoles     = $assignableRoles.ToArray()
        PermissionSections  = $permissionSections
    }
}

# Plain-language labels for explicit potentially high-impact operations; the order decides which examples a summary names first.
function Get-AzureRoleOperationLabels {
    return [ordered]@{
        'Microsoft.Compute/virtualMachines/runCommand/action'                                  = 'executing commands inside VMs, potentially affecting workloads'
        'Microsoft.Storage/storageAccounts/listKeys/action'                                    = 'retrieving storage keys that may enable data access'
        'Microsoft.KeyVault/vaults/accessPolicies/write'                                       = 'changing Key Vault policies that may grant data access'
        'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write' = 'adding federated credentials that may enable managed-identity impersonation'
        'Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action'         = 'retrieving AKS admin credentials for potential cluster control'
        'Microsoft.Compute/virtualMachines/extensions/write'                                   = 'installing VM extensions that may execute code'
        'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'                       = 'attaching managed identities'
        'Microsoft.Web/sites/config/list/action'                                               = 'reading web app settings that may contain credentials'
        'Microsoft.Web/sites/host/listkeys/action'                                             = 'retrieving Function App keys that may enable invocation'
        'Microsoft.Web/sites/publishxml/action'                                                = 'retrieving publish credentials that may enable application deployment'
        'Microsoft.Sql/servers/administrators/write'                                           = 'setting SQL server administrators'
        'Microsoft.Automation/automationAccounts/runbooks/write'                               = 'changing automation runbooks'
        'Microsoft.Logic/workflows/write'                                                      = 'changing Logic Apps'
        'Microsoft.ContainerRegistry/registries/push/write'                                    = 'pushing container images'
        'Microsoft.Network/networkSecurityGroups/write'                                        = 'changing network security groups'
        'Microsoft.Security/policies/write'                                                    = 'changing security policies'
        'Microsoft.HybridCompute/machines/extensions/write'                                    = 'installing extensions on Arc servers'
        'Microsoft.Compute/virtualMachines/write'                                              = 'changing VMs'
        'Microsoft.KeyVault/vaults/write'                                                      = 'changing Key Vaults'
        'Microsoft.Storage/storageAccounts/write'                                              = 'changing storage accounts'
        'Microsoft.Web/sites/write'                                                            = 'changing web apps'
        'Microsoft.ContainerService/managedClusters/listClusterUserCredential/action'          = 'retrieving AKS user credentials for potential Kubernetes access'
        'Microsoft.RecoveryServices/vaults/write'                                              = 'changing backup vaults'
        'Microsoft.Compute/virtualMachines/runCommands/write' = 'executing managed VM commands, potentially affecting workloads'
        'Microsoft.ContainerService/managedClusters/runcommand/action' = 'executing AKS commands, potentially affecting cluster workloads'
        'Microsoft.Storage/storageAccounts/listAccountSas/action' = 'generating account SAS credentials for potential storage data access'
        'Microsoft.Storage/storageAccounts/listServiceSas/action' = 'generating service SAS credentials for potential storage data access'
        'Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action' = 'retrieving AKS access-profile credentials for potential Kubernetes access'
        'Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action' = 'retrieving AKS monitoring credentials for potential Kubernetes access'
        'Microsoft.Web/sites/functions/listkeys/action' = 'retrieving individual Function keys that may enable invocation'
        'Microsoft.Logic/workflows/triggers/listCallbackUrl/action' = 'retrieving signed trigger URLs that may enable workflow invocation'
        'Microsoft.Compute/disks/beginGetAccess/action' = 'generating disk export credentials that may expose disk contents'
        'Microsoft.Compute/snapshots/beginGetAccess/action' = 'generating snapshot export credentials that may expose snapshot contents'
        'Microsoft.KeyVault/vaults/deploy/action' = 'resolving Key Vault secret references with potential secret exposure'
    }
}

# Compact HTML notes; summaries and TXT audit descriptions retain the fuller labels and caveats.
function Get-AzureRoleOperationDisplayDescriptions {
    return [ordered]@{
        'Microsoft.Compute/virtualMachines/runCommands/write' = 'Executes VM commands; requires a working guest agent.'
        'Microsoft.ContainerService/managedClusters/runcommand/action' = 'Executes cluster commands; availability depends on configuration.'
        'Microsoft.Storage/storageAccounts/listAccountSas/action' = 'Issues storage access credentials; access depends on SAS scope and configuration.'
        'Microsoft.Storage/storageAccounts/listServiceSas/action' = 'Issues resource-specific storage credentials; access depends on SAS scope and configuration.'
        'Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action' = 'Returns cluster credentials; deprecated endpoint, configuration-dependent access.'
        'Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action' = 'Returns monitoring credentials; Kubernetes permissions vary.'
        'Microsoft.Web/sites/functions/listkeys/action' = 'Returns invocation keys; endpoint and authentication restrictions apply.'
        'Microsoft.Logic/workflows/triggers/listCallbackUrl/action' = 'Returns a signed invocation URL; trigger and network restrictions apply.'
        'Microsoft.Compute/disks/beginGetAccess/action' = 'Issues disk export credentials; configuration and network restrictions apply.'
        'Microsoft.Compute/snapshots/beginGetAccess/action' = 'Issues snapshot export credentials; configuration and network restrictions apply.'
        'Microsoft.KeyVault/vaults/deploy/action' = 'Resolves deployment secret references; requires deployment access and vault enablement.'
    }
}

function Get-AzureRoleOperationCaveats {
    return [ordered]@{
        'Microsoft.Compute/virtualMachines/runCommands/write' = 'Requires a compatible VM and working guest agent.'
        'Microsoft.ContainerService/managedClusters/runcommand/action' = 'Effective behavior depends on cluster configuration and Run Command availability.'
        'Microsoft.Storage/storageAccounts/listAccountSas/action' = 'Access depends on the requested services, permissions, expiry, and storage configuration.'
        'Microsoft.Storage/storageAccounts/listServiceSas/action' = 'Access depends on the requested resource, permissions, expiry, and storage configuration.'
        'Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action' = 'Uses a deprecated endpoint; effective cluster access depends on the returned credentials and cluster configuration.'
        'Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action' = 'Effective Kubernetes permissions depend on cluster configuration.'
        'Microsoft.Web/sites/functions/listkeys/action' = 'Invocation requires an applicable key and reachable endpoint; additional authentication controls may apply.'
        'Microsoft.Logic/workflows/triggers/listCallbackUrl/action' = 'Invocation depends on trigger configuration and network restrictions.'
        'Microsoft.Compute/disks/beginGetAccess/action' = 'Data access depends on disk configuration and network restrictions; export access can be revoked with endGetAccess.'
        'Microsoft.Compute/snapshots/beginGetAccess/action' = 'Data access depends on snapshot configuration and network restrictions; export access can be revoked with endGetAccess.'
        'Microsoft.KeyVault/vaults/deploy/action' = 'Requires template deployment to be enabled on the vault and permission to perform the deployment; the lab demonstrated reference resolution rather than extraction of the secret value.'
    }
}

# Prefer specific evidence and retain distinct blocks, granting patterns, and permission layers.
function Select-AzureRoleDisplayRuleMatches {
    param([object[]]$RuleMatches = @())

    function Get-DisplayMatchKey {
        param([object[]]$Values)
        # Length prefixes keep arbitrary reason text from colliding with another tuple.
        return (@($Values | ForEach-Object { $valueText = [string]$_; "$($valueText.Length):$valueText" }) -join '')
    }

    $matchesToDisplay = @($RuleMatches | Where-Object { $null -ne $_ })
    $explicitKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $broadControlKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenMatches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($match in $matchesToDisplay) {
        $tupleKey = Get-DisplayMatchKey -Values @($match.Permission, $match.Block, $match.GrantedBy)
        if ($match.Rule -in @('A1', 'A2', 'A3', 'B1')) {
            [void]$explicitKeys.Add($tupleKey)
        } elseif ($match.Rule -eq 'A4' -and $match.Permission -eq '*') {
            [void]$broadControlKeys.Add($tupleKey)
        }
    }
    foreach ($match in $matchesToDisplay) {
        if ($match.Rule -eq 'B4') {
            $tupleKey = Get-DisplayMatchKey -Values @($match.Permission, $match.Block, $match.GrantedBy)
            if ([string]$match.Permission -notmatch '[*?]' -and $explicitKeys.Contains($tupleKey)) { continue }
            if ($match.Permission -eq '*' -and $broadControlKeys.Contains($tupleKey)) { continue }
        }
        $matchKey = Get-DisplayMatchKey -Values @($match.Rule, $match.Tier, $match.Reason, $match.Permission, $match.Block, $match.GrantedBy)
        if (-not $seenMatches.Add($matchKey)) { continue }
        $match
    }
}

# Keeps summaries in plain language; technical permissions and granting patterns stay in the evidence list.
function Format-AzureRoleRiskSummary {
    param (
        [Parameter(Mandatory = $false)]
        [object[]]$RuleMatches = @(),

        [Parameter(Mandatory = $false)]
        [string]$TierSource,

        [Parameter(Mandatory = $false)]
        [string]$TierLabel,

        [Parameter(Mandatory = $false)]
        [switch]$HasRootAssignment,

        [Parameter(Mandatory = $false)]
        [switch]$Html
    )

    $ruleMatchList = @(Select-AzureRoleDisplayRuleMatches -RuleMatches $RuleMatches)
    if ($ruleMatchList.Count -eq 0) { return $null }

    $atRootScope = $HasRootAssignment.IsPresent
    $joinPhrases = {
        param([string[]]$Phrases)
        if ($Phrases.Count -le 1) { return ($Phrases -join '') }
        return (($Phrases[0..($Phrases.Count - 2)] -join ', ') + ' and ' + $Phrases[-1])
    }
    $countPhrase = {
        param([int]$Count, [string]$Singular, [string]$Plural)
        if ($Count -eq 1) { return "1 $Singular" }
        return "$Count $Plural"
    }
    # Names the resource providers of several matches, e.g. "across Compute, Network and Storage".
    $providerPhrase = {
        param([object[]]$ProviderMatches)
        if (@($ProviderMatches).Count -le 1) { return '' }
        $providers = [System.Collections.Generic.List[string]]::new()
        foreach ($providerMatch in @($ProviderMatches)) {
            if ([string]$providerMatch.Permission -match '^([^/*]+)/') {
                $provider = $Matches[1] -replace '^Microsoft\.', ''
                if (-not $providers.Contains($provider)) { $providers.Add($provider) }
            }
        }
        if ($providers.Count -eq 0) { return '' }
        if ($providers.Count -gt 3) {
            return " across $(($providers.GetRange(0, 3)) -join ', ') and $($providers.Count - 3) more"
        }
        return ' across ' + (& $joinPhrases $providers.ToArray())
    }

    $rules = @($ruleMatchList | ForEach-Object { [string]$_.Rule })
    $verbs = [System.Collections.Generic.List[string]]::new()
    if ($rules -contains 'A1') { $verbs.Add('assign roles') }
    if ($rules -contains 'A2') { $verbs.Add('change role definitions') }
    # Elevating access only works at the tenant root, so it is mentioned only for roles assigned there.
    if ($rules -contains 'A3' -and $atRootScope) { $verbs.Add('elevate access at root scope') }

    # Broad control covers the wildcard write and explicit-operation examples; keep their evidence in the list.
    $grantsBroadControl = $rules -contains 'A4'
    $writeMatches = @($ruleMatchList | Where-Object { [string]$_.Rule -eq 'B4' })
    $highRiskWrites = @($writeMatches | Where-Object { ([string]$_.Reason).StartsWith('high-risk write or action:') })
    $unrecognizedWrites = @($writeMatches | Where-Object { -not ([string]$_.Reason).StartsWith('high-risk write or action:') })
    $knownOperations = @($ruleMatchList | Where-Object { [string]$_.Rule -eq 'B1' })
    $dataPermissions = @($ruleMatchList | Where-Object { [string]$_.Rule -eq 'B3' })

    $nouns = [System.Collections.Generic.List[string]]::new()
    if ($grantsBroadControl) { $nouns.Add('broad resource-management permissions') }
    if ($knownOperations.Count -gt 0 -and -not $grantsBroadControl) {
        $operationLabels = Get-AzureRoleOperationLabels
        $knownPermissions = @($knownOperations | ForEach-Object { [string]$_.Permission })
        $matchedLabels = @(@($operationLabels.Keys) | Where-Object { $knownPermissions -contains $_ } | ForEach-Object { $operationLabels[$_] })
        $knownPhrase = & $countPhrase $knownOperations.Count 'potentially high-impact operation' 'potentially high-impact operations'
        if ($matchedLabels.Count -gt 0) {
            if ($ruleMatchList.Count -eq 1 -and $matchedLabels.Count -eq 1) {
                $knownPhrase += ': ' + $matchedLabels[0]
            } elseif ($matchedLabels.Count -gt 3) {
                $knownPhrase += ' (such as ' + (& $joinPhrases @($matchedLabels | Select-Object -First 3)) + ')'
            } else {
                $knownPhrase += ' (' + (& $joinPhrases $matchedLabels) + ')'
            }
        }
        $nouns.Add($knownPhrase)
    }
    if ($rules -contains 'B2') { $nouns.Add('debug snapshot read access') }
    foreach ($phraseGroup in @(
        @{ Matches = $dataPermissions; Singular = 'data-plane permission'; Plural = 'data-plane permissions' },
        @{ Matches = $highRiskWrites; Singular = 'potentially sensitive write or action'; Plural = 'potentially sensitive writes or actions' },
        @{ Matches = $unrecognizedWrites; Singular = 'write or action outside the reviewed low-risk set'; Plural = 'writes or actions outside the reviewed low-risk set' }
    )) {
        $groupMatches = @($phraseGroup.Matches)
        if ($groupMatches.Count -eq 0) { continue }
        $acrossProviders = & $providerPhrase $groupMatches
        $nouns.Add((& $countPhrase $groupMatches.Count $phraseGroup.Singular $phraseGroup.Plural) + $acrossProviders)
    }

    if ($verbs.Count -eq 0 -and $nouns.Count -eq 0) {
        # Only the elevate-access permission matched, and the role is not assigned at the root.
        $nouns.Add('the elevate access permission, which only takes effect at root scope')
    }

    if ($verbs.Count -gt 0) {
        $sentence = 'Can ' + (& $joinPhrases $verbs.ToArray())
        if ($nouns.Count -gt 0) {
            $separator = if ($verbs.Count -gt 1) { ', and grants ' } else { ' and grants ' }
            $sentence += $separator + (& $joinPhrases $nouns.ToArray())
        }
    } else {
        $sentence = 'Grants ' + (& $joinPhrases $nouns.ToArray())
    }

    $sentence += '.'

    # A curated rating stays authoritative even when the permission check would rate the role higher.
    if ($TierSource -eq 'Rated' -and $TierLabel -match '^Tier-(\d)$') {
        $curatedTier = [int]$Matches[1]
        $strongestMatchTier = [int](($ruleMatchList | ForEach-Object { [int]$_.Tier } | Measure-Object -Minimum).Minimum)
        if ($strongestMatchTier -lt $curatedTier) {
            $sentence += " The curated $TierLabel rating takes precedence over these matches."
        }
    }

    if ($Html.IsPresent) { return (ConvertTo-EntraFalconHtmlText -Value $sentence) }
    return $sentence
}

# Converts a role detail model into a report details object. Tenant-controlled values are HTML-encoded because the details renderer writes with innerHTML.
function ConvertTo-AzureRoleDefinitionDetailObject {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Model,

        [Parameter(Mandatory = $false)]
        [string[]]$LinkableRoleIds = @(),

        [Parameter(Mandatory = $false)]
        [int]$RiskItemLimit = 50
    )

    $detail = [ordered]@{
        # The details summary is set with textContent, so the name stays unencoded.
        'Object Name' = $Model.RoleName
        'Object ID'   = $Model.RoleDefinitionId
    }

    foreach ($sectionName in @('General Information', 'Classification')) {
        $sourceSection = if ($sectionName -eq 'General Information') { $Model.GeneralInformation } else { $Model.Classification }
        $encodedSection = [ordered]@{}
        foreach ($entryName in @($sourceSection.Keys)) {
            $entryValue = $sourceSection[$entryName]
            $encodedSection[$entryName] = if ($entryValue -is [int]) { $entryValue } else { ConvertTo-EntraFalconHtmlText -Value $entryValue -DefaultValue '-' }
        }
        $detail[$sectionName] = [pscustomobject]$encodedSection
    }

    # The renderer shows Summary as a sentence and keeps Items behind a toggle; the TXT report keeps every row.
    $riskItems = @($Model.RiskItems | Where-Object { $null -ne $_ })
    if ($riskItems.Count -gt 0) {
        # Items are grouped by rule family; headings are only worth showing when there is more than one group.
        $groupOrder = @('Access control', 'Potentially high-impact operations', 'Debug snapshots', 'Data plane', 'Writes and actions')
        $presentGroups = @($groupOrder | Where-Object { $groupName = $_; @($riskItems | Where-Object { $_.Group -eq $groupName }).Count -gt 0 })
        $showHeadings = $presentGroups.Count -gt 1
        $itemIndent = if ($showHeadings) { '  ' } else { '' }
        $shownLines = [System.Collections.Generic.List[string]]::new()
        $shownItemCount = 0
        foreach ($groupName in $presentGroups) {
            if ($shownItemCount -ge $RiskItemLimit) { break }
            if ($showHeadings) { $shownLines.Add("<strong>$groupName</strong>") }
            foreach ($riskItem in @($riskItems | Where-Object { $_.Group -eq $groupName })) {
                if ($shownItemCount -ge $RiskItemLimit) { break }
                $shownLines.Add($itemIndent + (ConvertTo-EntraFalconHtmlText -Value $riskItem.Text -DefaultValue '-'))
                $shownItemCount++
            }
        }
        if ($riskItems.Count -gt $shownItemCount) {
            $shownLines.Add("... and $($riskItems.Count - $shownItemCount) more (full list in the TXT report)")
        }
        $detail['Potential impact'] = [pscustomobject]@{
            Summary    = Format-AzureRoleRiskSummary -RuleMatches @($Model.RuleMatches) -TierSource $Model.TierSource -TierLabel $Model.TierLabel -HasRootAssignment:([bool]$Model.HasRootAssignment) -Html
            Toggle     = "Show matched permissions ($($riskItems.Count))"
            ToggleHide = 'Hide matched permissions'
            Items      = $shownLines.ToArray()
        }
    }

    $assignableRoles = @($Model.AssignableRoles)
    if ($assignableRoles.Count -gt 0) {
        $detail['Assignable Roles'] = @(foreach ($assignableRole in $assignableRoles) {
            $roleText = ConvertTo-EntraFalconHtmlText -Value $assignableRole.Role -DefaultValue '-'
            [pscustomobject]@{
                Role   = if ($LinkableRoleIds -contains [string]$assignableRole.RoleDefinitionId) { "<a href=#$($assignableRole.RoleDefinitionId)>$roleText</a>" } else { $roleText }
                Tier   = ConvertTo-EntraFalconHtmlText -Value $assignableRole.Tier -DefaultValue '-'
                Source = ConvertTo-EntraFalconHtmlText -Value $assignableRole.Source -DefaultValue '-'
            }
        })
    }

    foreach ($permissionSectionName in @($Model.PermissionSections.Keys)) {
        $detail[$permissionSectionName] = @(@($Model.PermissionSections[$permissionSectionName]) | ForEach-Object { ConvertTo-EntraFalconHtmlText -Value $_ })
    }

    return [pscustomobject]$detail
}

# Serializes role details for the object-data script block. PowerShell 7 does not escape "<", so "</" is escaped to keep a role name from closing the script element.
function ConvertTo-AzureRoleDefinitionDetailsJson {
    param (
        [Parameter(Mandatory = $false)]
        [object[]]$DetailObjects = @()
    )

    if (@($DetailObjects).Count -eq 0) { return '[]' }
    $detailsJson = ConvertTo-Json -InputObject @($DetailObjects) -Depth 6 -Compress
    return ($detailsJson -replace '</', '<\/')
}

# Formats a role detail model for the TXT report.
function Format-AzureRoleDefinitionDetailText {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Model
    )

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine("############################################################################################################################################")
    [void]$builder.AppendLine(([pscustomobject]$Model.GeneralInformation | Format-List | Out-String -Width 512))

    [void]$builder.AppendLine("================================================================================================")
    [void]$builder.AppendLine("Classification")
    [void]$builder.AppendLine("================================================================================================")
    [void]$builder.AppendLine(([pscustomobject]$Model.Classification | Format-List | Out-String -Width 512))

    if (@($Model.MatchedRules).Count -gt 0) {
        [void]$builder.AppendLine("Potential impact")
        [void]$builder.AppendLine("----------------")
        [void]$builder.AppendLine((Format-AzureRoleRiskSummary -RuleMatches @($Model.RuleMatches) -TierSource $Model.TierSource -TierLabel $Model.TierLabel -HasRootAssignment:([bool]$Model.HasRootAssignment)))
        [void]$builder.AppendLine((@($Model.MatchedRules) | Format-Table -Property Rule, Permission, 'Granted By' | Out-String -Width 512))
    }

    if (@($Model.AssignableRoles).Count -gt 0) {
        [void]$builder.AppendLine("Assignable Roles")
        [void]$builder.AppendLine("----------------")
        [void]$builder.AppendLine((@($Model.AssignableRoles) | Format-Table -Property Role, Tier, Source | Out-String -Width 512))
    }

    if (@($Model.PermissionSections.Keys).Count -gt 0) {
        [void]$builder.AppendLine("================================================================================================")
        [void]$builder.AppendLine("Permissions")
        [void]$builder.AppendLine("================================================================================================")
        foreach ($permissionSectionName in @($Model.PermissionSections.Keys)) {
            [void]$builder.AppendLine($permissionSectionName)
            [void]$builder.AppendLine(('-' * $permissionSectionName.Length))
            foreach ($permissionLine in @($Model.PermissionSections[$permissionSectionName])) {
                [void]$builder.AppendLine($permissionLine)
            }
            [void]$builder.AppendLine()
        }
    }

    return $builder.ToString()
}

function Invoke-CheckRoles {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$false)][hashtable]$RoleGroupIdentityCountIndex = @{},
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$ManagedIdentities,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentityBlueprintsPrincipals = @{},
        [Parameter(Mandatory=$false)][switch]$Csv = $false,
        [Parameter(Mandatory=$false)][switch]$ExportDataJson = $false,
        [Parameter(Mandatory=$false)][switch]$DebugObjectDump = $false
    )

    ############################## Function section ########################

    $ObjectDetailsCache = @{}

    function Format-RoleAssignmentDateTime {
        param(
            [Parameter(Mandatory = $false)]
            $Value
        )

        if ($null -eq $Value) { return "-" }

        $textValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($textValue)) { return "-" }
        if ($textValue -in @("-", "Permanent")) { return $textValue }

        [datetime]$parsedDateTime = [datetime]::MinValue
        $hasParsedDateTime = $false
        if ($Value -is [datetime]) {
            $parsedDateTime = $Value
            $hasParsedDateTime = $true
        } else {
            $hasParsedDateTime = [datetime]::TryParse($textValue, [ref]$parsedDateTime)
        }

        if ($hasParsedDateTime) {
            return $parsedDateTime.ToString("yyyy-MM-dd HH:mm")
        }

        return $textValue
    }

    #Function to get details about specific objects
    function Get-ObjectDetails($ObjectID, $type = "unknown") {
        $normalizedType = $type.ToString().ToLowerInvariant()
        $cacheKey = "$normalizedType|$ObjectID"

        if ($ObjectDetailsCache.ContainsKey($cacheKey)) {

            return $ObjectDetailsCache[$cacheKey]
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "user") {
            $MatchingUser = $Users[$($ObjectID)]
            if ($MatchingUser) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingUser.UPN
                    DisplayNameLink = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingUser.UPN)</a>"
                    Type = "User"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "group" ) {
            $MatchingGroup = $AllGroupsDetails[$($ObjectID)]
            if ($MatchingGroup) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingGroup.DisplayName
                    DisplayNameLink = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingGroup.DisplayName)</a>"
                    Type = "Group"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            } 
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal") {
            $MatchingBlueprintPrincipal = $AgentIdentityBlueprintsPrincipals[$ObjectID]
            if ($MatchingBlueprintPrincipal) {
                $object = [PSCustomObject]@{
                    DisplayName     = $MatchingBlueprintPrincipal.DisplayName
                    DisplayNameLink = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingBlueprintPrincipal.DisplayName)</a>"
                    Type            = "Agent Identity Blueprint Principal"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal") {
            $MatchingAgentIdentity = $AgentIdentities[$ObjectID]
            if ($MatchingAgentIdentity) {
                $object = [PSCustomObject]@{
                    DisplayName     = $MatchingAgentIdentity.DisplayName
                    DisplayNameLink = "<a href=AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingAgentIdentity.DisplayName)</a>"
                    Type            = "Agent Identity"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal") {
            $MatchingEnterpriseApp = $EnterpriseApps[$($ObjectID)]
            if ($MatchingEnterpriseApp) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingEnterpriseApp.DisplayName)</a>"
                    Type = "Enterprise Application"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "managedidentity" -or $normalizedType -eq "serviceprincipal") {
            $MatchingManagedIdentity = $ManagedIdentities[$($ObjectID)]
            if ($MatchingManagedIdentity) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingManagedIdentity.DisplayName
                    DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingManagedIdentity.DisplayName)</a>"
                    Type = "Managed Identity"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }
    
        if ($normalizedType -eq "unknown" -or $normalizedType -eq "AppRegistration" ) {
            $MatchingAppRegistration = $AppRegistrations[$($ObjectID)]
            if ($MatchingAppRegistration) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingAppRegistration.DisplayName
                    DisplayNameLink = "<a href=AppRegistration_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($ObjectID)>$($MatchingAppRegistration.DisplayName)</a>"
                    Type = "App Registration"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }
    
        if ($normalizedType -eq "unknown" -or $normalizedType -eq "administrativeunit") {
            $MatchingAdministrativeUnit = $AdminUnitWithMembers | Where-Object { $_.AuId -eq $ObjectID }
            if ($MatchingAdministrativeUnit) {
                $object = [PSCustomObject]@{ 
                    DisplayName = $MatchingAdministrativeUnit.DisplayName
                    DisplayNameLink = $MatchingAdministrativeUnit.DisplayName
                    Type = "Administrative Unit"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }


        # Fallback: resolve unknown objects via directoryObjects/getByIds (expensive but should be OK with caching)
        if ($normalizedType -eq "unknown" -or $normalizedType -like "*foreign*") {

        
            Write-Log -Level Trace -Message "Manually resolve $ObjectID"
            # Not sure if device make sense, but the Azure Portal use it as well
            $Body = @{
                ids   = @($ObjectID)
                types = @(
                    "user",
                    "group",
                    "servicePrincipal",
                    "device",
                    "directoryObjectPartnerReference",
                    "application",
                    "administrativeUnit"
                )
            }

            $GraphLookupError = $null
            $ResolvedDirectoryObject = Send-GraphRequest -AccessTokenProvider (New-EntraFalconGraphTokenProvider -Purpose MainAuth) -Method POST -Uri "/directoryObjects/getByIds" -Body $Body -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorVariable GraphLookupError

            if ($ResolvedDirectoryObject) {

                if ($ResolvedDirectoryObject -is [System.Array]) {
                    $ResolvedDirectoryObject = $ResolvedDirectoryObject | Select-Object -First 1
                }

                $odataType = $ResolvedDirectoryObject.'@odata.type'
                $resolvedType = "Unknown Object"

                #Special handling for foreign partner objects
                if ($odataType -eq "#microsoft.graph.directoryObjectPartnerReference") {
                    switch ($ResolvedDirectoryObject.objectType) {
                        "User" { $resolvedType = "User" }
                        "Group" { $resolvedType = "Group" }
                        "ServicePrincipal" { $resolvedType = "Enterprise Application" }
                        "Device" { $resolvedType = "Device" }
                        default { $resolvedType = "Unknown Object" }
                    }
                } else {
                    switch ($odataType) {
                        "#microsoft.graph.user" { $resolvedType = "User" }
                        "#microsoft.graph.group" { $resolvedType = "Group" }
                        "#microsoft.graph.servicePrincipal" { $resolvedType = "Service Principal" }
                        "#microsoft.graph.application" { $resolvedType = "App Registration" }
                        "#microsoft.graph.administrativeUnit" { $resolvedType = "Administrative Unit" }
                        "#microsoft.graph.device" { $resolvedType = "Device" }
                        default { $resolvedType = "Unknown Object" }
                    }
                }

                # Check what kind of SP
                if ($odataType -eq "#microsoft.graph.servicePrincipal") {
                    switch ($ResolvedDirectoryObject.servicePrincipalType) {
                        "Application" { $resolvedType = "Enterprise Application" }
                        "ManagedIdentity" { $resolvedType = "Managed Identity" }
                        "ServiceIdentity" { $resolvedType = "Service Identity" }
                        default { $resolvedType = "Service Principal" }
                    }
                }

                if ($normalizedType -eq "foreigngroup" -and $resolvedType -eq "Unknown Object") {
                    $resolvedType = "Group"
                }

                $resolvedName = $null
                if ($ResolvedDirectoryObject.PSObject.Properties.Match('userPrincipalName').Count -gt 0 -and $ResolvedDirectoryObject.userPrincipalName) {
                    $resolvedName = [string]$ResolvedDirectoryObject.userPrincipalName
                } elseif ($ResolvedDirectoryObject.PSObject.Properties.Match('displayName').Count -gt 0 -and $ResolvedDirectoryObject.displayName) {
                    $resolvedName = [string]$ResolvedDirectoryObject.displayName
                }

                if (-not $resolvedName) {
                    $resolvedName = $ObjectID
                }

                if ($normalizedType -like "*foreign*" -and $resolvedName -notlike "Foreign Principal*") {
                    $resolvedName = "$resolvedName (Foreign)"
                }

                # Define returned objects. Since the object have not been found in the internal lists they are not linked.
                switch ($resolvedType) {
                    "User" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "User"
                        }
                    }
                    "Group" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Group"
                        }
                    }
                    "Enterprise Application" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Enterprise Application"
                        }
                    }
                    "Managed Identity" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Managed Identity"
                        }
                    }
                    "Service Identity" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Service Identity"
                        }
                    }

                    "Service Principal" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Service Principal"
                        }
                    }

                    "App Registration" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "App Registration"
                        }
                    }
                    "Device" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Device"
                        }
                    }

                    default {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Unknown Object"
                        }
                    }
                }

                $ObjectDetailsCache[$cacheKey] = $object
                return $object
            }

            if ($normalizedType -like "*foreign*") {
                $fallbackType = "Unknown Object"
                if ($normalizedType -eq "foreigngroup") {
                    $fallbackType = "Group"
                }

                $object = [PSCustomObject]@{
                    DisplayName     = "$ObjectID (Foreign)"
                    DisplayNameLink = "$ObjectID (Foreign)"
                    Type            = $fallbackType
                }

                if (-not $GraphLookupError) {
                    $ObjectDetailsCache[$cacheKey] = $object
                }
                return $object
            }
        }

        #Unknown Object
        if ($normalizedType -eq "unknown") {

            $object = [PSCustomObject]@{ 
                DisplayName = $ObjectID
                DisplayNameLink = $ObjectID
                Type = "Unknown Object"
            }
            Write-Log -Level Debug -Message "Unknown Object: $ObjectID"
            $ObjectDetailsCache[$cacheKey] = $object
            Return $object
        }
    }

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "Role_Assignments"
    $WarningReport = @()
    if (-not $GLOBALGraphExtendedChecks) {$WarningReport += "Coverage gap: eligible role assignments not assessed; only active assignments are included."}

    ########################################## SECTION: DATACOLLECTION ##########################################

    write-host "[*] Process Entra role assignments"

    # Flatten the merged hash table into a single array
    $FlattenedAssignments = foreach ($entry in $TenantRoleAssignments.GetEnumerator()) {
        foreach ($a in @($entry.Value)) { $a }
    }

    $EntraRoles = foreach ($item in $FlattenedAssignments) {
        $PrincipalDetails = Get-ObjectDetails -ObjectID $item.PrincipalId

        $ScopeDetails = if ($item.DirectoryScopeId -eq "/") {
            [PSCustomObject]@{
                DisplayName = "/"
                DisplayNameLink = "/"
                Type        = "Tenant"
            }
        } elseif ($($item.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $($item.DirectoryScopeId).Replace("/administrativeUnits/", "")
            Get-ObjectDetails -ObjectID $ObjectID -type AdministrativeUnit
        }else {
            $ObjectID = $item.DirectoryScopeId.Replace("/", "")
            Get-ObjectDetails -ObjectID $ObjectID
        }
        #Convert Tier-Level to text
        switch ($item.RoleTier) {
            0 {$RoleTier = "Tier-0"; break}
            1 {$RoleTier = "Tier-1"; break}
            2 {$RoleTier = "Tier-2"; break}
            3 {$RoleTier = "Tier-3"; break}
            default {$RoleTier = "Uncategorized"}
        }
        [pscustomobject]@{ 
            "Role" = $($item.DisplayName)
            "PrincipalId" = $($item.PrincipalId)
            "PrincipalDisplayName" = $($PrincipalDetails.DisplayName)
            "PrincipalDisplayNameLink" = $($PrincipalDetails.DisplayNameLink)
            "PrincipalType" = $($PrincipalDetails.Type)
            "RoleTier" = $RoleTier
            "AssignmentType" = $($item.AssignmentType)
            "ActivatedViaPIM" = $($item.ActivatedViaPIM)
            "Start" = Format-RoleAssignmentDateTime -Value $item.StartDateTime
            "Expires" = Format-RoleAssignmentDateTime -Value $item.EndDateTime
            "DirectoryScopeId" = $($item.DirectoryScopeId)
            "IsPrivileged" = $($item.IsPrivileged)
            "IsBuiltIn" = $($item.IsBuiltIn)
            "ScopeResolved" = "$($ScopeDetails.DisplayName) ($($ScopeDetails.Type))"
            "ScopeResolvedLink" = "$($ScopeDetails.DisplayNameLink) ($($ScopeDetails.Type))"
        }
    }

    # Custom sort order
    $SortedEntraRoles = $EntraRoles | Sort-Object @{
        Expression = { $_.Role -eq "Global Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Privileged Role Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Privileged Authentication Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Application Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-0" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "User Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Groups Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-1" }
        Descending = $true
    }, @{
        Expression = { $_.IsPrivileged }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-2" }
        Descending = $true
    }, @{
        Expression = { $_.Role }
        Descending = $false
    }


    write-host "[*] Process Azure role assignments"
    # Convert hashtable to normal objects
    $SortedAzureRolesList = [System.Collections.Generic.List[object]]::new()

    $AzureIAMAssignments.GetEnumerator() | ForEach-Object {
        $PrincipalId = $_.Key
        $Assignments = @($_.Value)

        $PrincipalType = $null
        if ($Assignments.Count -gt 0) {
            $PrincipalType = $Assignments[0].PrincipalType
        }

        if ($PrincipalType -and $PrincipalType -notlike "Foreign*") {
            $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId -type $PrincipalType

            # Fallback
            if (-not $PrincipalDetails -or $PrincipalDetails.Type -eq "Unknown Object") {
                $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId
            }

            if (-not $PrincipalDetails -or $PrincipalDetails.Type -eq "Unknown Object") {
                $PrincipalDisplayName = "$PrincipalId (Unknown)"
                $PrincipalDisplayNameLink = "$PrincipalId (Unknown)"
            } else {
                $PrincipalDisplayName = $PrincipalDetails.DisplayName
                $PrincipalDisplayNameLink = $PrincipalDetails.DisplayNameLink
            }

            # Flatten one principal -> many Azure assignments into the same row
            foreach ($Assignment in $Assignments) {
                switch ($Assignment.RoleTier) {
                    0 { $RoleTier = "Tier-0"; break }
                    1 { $RoleTier = "Tier-1"; break }
                    2 { $RoleTier = "Tier-2"; break }
                    3 { $RoleTier = "Tier-3"; break }
                    default { $RoleTier = "Uncategorized" }
                }
                $CanonicalRawScope = if ($Assignment.PSObject.Properties["RawScope"]) { [string]$Assignment.RawScope } else { $null }
                $AssignmentRoleDefinitionId = if ($Assignment.PSObject.Properties["RoleDefinitionId"]) { [string]$Assignment.RoleDefinitionId } else { $null }
                $ImpactContext = if ($Assignment.PSObject.Properties["AssignmentImpact"]) {
                    $Assignment
                } else {
                    Get-AzureRoleAssignmentImpact -RoleTier $Assignment.RoleTier -RoleName $Assignment.RoleDefinitionName -RawScope $CanonicalRawScope -TenantId $CurrentTenant.Id -RoleDefinitionId $AssignmentRoleDefinitionId
                }
                $SortedAzureRolesList.Add([PSCustomObject]@{
                    PrincipalId               = $PrincipalId
                    PrincipalDisplayName      = $PrincipalDisplayName
                    PrincipalDisplayNameLink  = $PrincipalDisplayNameLink
                    PrincipalType             = if ($PrincipalDetails -and $PrincipalDetails.Type -ne "Unknown Object") { $PrincipalDetails.Type } else { $Assignment.PrincipalType }
                    RoleType                  = $Assignment.RoleType
                    RoleDefinitionId          = $AssignmentRoleDefinitionId
                    Conditions                = $Assignment.Conditions
                    Role                      = $Assignment.RoleDefinitionName
                    RawScope                  = if ($Assignment.PSObject.Properties["RawScope"]) { $Assignment.RawScope } else { $null }
                    Scope                     = $Assignment.Scope
                    RoleTier                  = $RoleTier
                    TierSource                = if ($Assignment.PSObject.Properties["TierSource"]) { $Assignment.TierSource } else { $null }
                    TierReason                = if ($Assignment.PSObject.Properties["TierReason"]) { $Assignment.TierReason } else { $null }
                    ScopeType                 = if ($ImpactContext.PSObject.Properties["ScopeType"]) { $ImpactContext.ScopeType } else { "Unknown" }
                    Environment               = if ($ImpactContext.PSObject.Properties["Environment"]) { $ImpactContext.Environment } else { "Unknown" }
                    ObservedResources = if ($ImpactContext.PSObject.Properties["ObservedResources"]) { $ImpactContext.ObservedResources } else { $null }
                    InventoryStatus           = if ($ImpactContext.PSObject.Properties["InventoryStatus"]) { $ImpactContext.InventoryStatus } else { $null }
                    AssignmentImpact          = $ImpactContext.AssignmentImpact
                    Level                     = Get-AzureImpactLevel -Impact $ImpactContext.AssignmentImpact
                    ImpactExplanation         = $ImpactContext.ImpactExplanation
                    ScoringPolicyVersion      = $ImpactContext.ScoringPolicyVersion
                    AssignmentType            = $Assignment.AssignmentType
                    ActivatedViaPIM           = $Assignment.ActivatedViaPIM
                    Start                     = Format-RoleAssignmentDateTime -Value $Assignment.StartDateTime
                    Expires                   = Format-RoleAssignmentDateTime -Value $Assignment.EndDateTime
                })
            }
        } else {
            $LookupType = if ($PrincipalType -like "Foreign*") { $PrincipalType } else { "unknown" }
            $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId -type $LookupType

            foreach ($Assignment in $Assignments) {
                switch ($Assignment.RoleTier) {
                    0 { $RoleTier = "Tier-0"; break }
                    1 { $RoleTier = "Tier-1"; break }
                    2 { $RoleTier = "Tier-2"; break }
                    3 { $RoleTier = "Tier-3"; break }
                    default { $RoleTier = "Uncategorized" }
                }
                $CanonicalRawScope = if ($Assignment.PSObject.Properties["RawScope"]) { [string]$Assignment.RawScope } else { $null }
                $AssignmentRoleDefinitionId = if ($Assignment.PSObject.Properties["RoleDefinitionId"]) { [string]$Assignment.RoleDefinitionId } else { $null }
                $ImpactContext = if ($Assignment.PSObject.Properties["AssignmentImpact"]) {
                    $Assignment
                } else {
                    Get-AzureRoleAssignmentImpact -RoleTier $Assignment.RoleTier -RoleName $Assignment.RoleDefinitionName -RawScope $CanonicalRawScope -TenantId $CurrentTenant.Id -RoleDefinitionId $AssignmentRoleDefinitionId
                }
                $SortedAzureRolesList.Add([PSCustomObject]@{
                    PrincipalId               = $PrincipalId
                    PrincipalDisplayName      = $PrincipalDetails.DisplayName
                    PrincipalDisplayNameLink  = $PrincipalDetails.DisplayNameLink
                    PrincipalType             = $PrincipalDetails.Type
                    RoleType                  = $Assignment.RoleType
                    RoleDefinitionId          = $AssignmentRoleDefinitionId
                    Conditions                = $Assignment.Conditions
                    Role                      = $Assignment.RoleDefinitionName
                    RawScope                  = if ($Assignment.PSObject.Properties["RawScope"]) { $Assignment.RawScope } else { $null }
                    Scope                     = $Assignment.Scope
                    RoleTier                  = $RoleTier
                    TierSource                = if ($Assignment.PSObject.Properties["TierSource"]) { $Assignment.TierSource } else { $null }
                    TierReason                = if ($Assignment.PSObject.Properties["TierReason"]) { $Assignment.TierReason } else { $null }
                    ScopeType                 = if ($ImpactContext.PSObject.Properties["ScopeType"]) { $ImpactContext.ScopeType } else { "Unknown" }
                    Environment               = if ($ImpactContext.PSObject.Properties["Environment"]) { $ImpactContext.Environment } else { "Unknown" }
                    ObservedResources = if ($ImpactContext.PSObject.Properties["ObservedResources"]) { $ImpactContext.ObservedResources } else { $null }
                    InventoryStatus           = if ($ImpactContext.PSObject.Properties["InventoryStatus"]) { $ImpactContext.InventoryStatus } else { $null }
                    AssignmentImpact          = $ImpactContext.AssignmentImpact
                    Level                     = Get-AzureImpactLevel -Impact $ImpactContext.AssignmentImpact
                    ImpactExplanation         = $ImpactContext.ImpactExplanation
                    ScoringPolicyVersion      = $ImpactContext.ScoringPolicyVersion
                    AssignmentType            = $Assignment.AssignmentType
                    ActivatedViaPIM           = $Assignment.ActivatedViaPIM
                    Start                     = Format-RoleAssignmentDateTime -Value $Assignment.StartDateTime
                    Expires                   = Format-RoleAssignmentDateTime -Value $Assignment.EndDateTime
                })
            }
        }
    }

    $SortedAzureRoles = $SortedAzureRolesList
    $identityCountsByPrincipal = @{}
    $identityWarningsByReport = @{}
    foreach ($reportKey in @('Entra', 'Azure')) {
        $assignmentRows = if ($reportKey -eq 'Entra') { $SortedEntraRoles } else { $SortedAzureRoles }
        $incompleteIdentityAssignments = 0
        foreach ($row in $assignmentRows) {
            $identityKey = "$($row.PrincipalType)|$($row.PrincipalId)"
            if (-not $identityCountsByPrincipal.ContainsKey($identityKey)) {
                $identityCountsByPrincipal[$identityKey] = Get-RoleAssignmentIdentityCount -PrincipalId $row.PrincipalId -PrincipalType $row.PrincipalType -RoleGroupIdentityCountIndex $RoleGroupIdentityCountIndex
            }
            $identityCount = $identityCountsByPrincipal[$identityKey]
            $row | Add-Member -NotePropertyName Identities -NotePropertyValue ([int]$identityCount.Count)
            if (-not $identityCount.Complete) { $incompleteIdentityAssignments++ }
        }
        $identityWarningsByReport[$reportKey] = @()
        if ($incompleteIdentityAssignments -gt 0) {
            $identityWarningsByReport[$reportKey] = @("Coverage gap: identity counts for $incompleteIdentityAssignments assignment(s) may be understated because membership, eligibility, or principal information was incomplete.")
        }
    }
    $entraIdentityWarnings = @($identityWarningsByReport['Entra'])
    $azureIdentityWarnings = @($identityWarningsByReport['Azure'])


    # Highest contextual impact first; scope hierarchy and role priority break ties
    $SortedAzureRoles = $SortedAzureRoles | Sort-Object -Property @{
        Expression = { [int]$_.AssignmentImpact }
        Descending = $true
    }, @{
        # Scope depth and specific path rules
        Expression = {
            if ($_.Scope -eq '/') {
                0  # Root path should come first
            } elseif ($_.Scope -like '/providers/Microsoft.Management/managementGroups/*') {
                1  # Management group paths come second
            } else {
                2 + ($_.Scope -split '/').Count  # Subscription paths sorted by depth
            }
        }
    }, @{
        # Scope alphabetically (to maintain proper order within same depth)
        Expression = {$_.Scope}
    }, @{
        # RoleDefinitionName priority (within same Scope)
        Expression = {
            switch ($_.Role) {
                "Owner" { 0 }                      # Owner comes first
                "User Access Administrator" { 1 }
                "Contributor" { 2 }
                "Role Based Access Control Administrator" { 3 }
                "Reservations Administrator" { 4 }
                default { 5 }
            }
        }
    }, @{
        # Alphabetical sorting for roles with the same priority
        Expression = {$_.Role}
    }

    # One details block per assigned role definition, ordered by the highest-impact assignment of each role
    $azureRoleAssignmentsById = [ordered]@{}
    foreach ($azureRoleAssignment in @($SortedAzureRoles)) {
        $roleDefinitionId = [string]$azureRoleAssignment.RoleDefinitionId
        if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) { continue }
        if (-not $azureRoleAssignmentsById.Contains($roleDefinitionId)) {
            $azureRoleAssignmentsById[$roleDefinitionId] = [System.Collections.Generic.List[object]]::new()
        }
        $azureRoleAssignmentsById[$roleDefinitionId].Add($azureRoleAssignment)
    }

    $linkableAzureRoleIds = @($azureRoleAssignmentsById.Keys | ForEach-Object { [string]$_ })
    $azureRoleDetailObjects = [System.Collections.Generic.List[object]]::new()
    $azureRoleDetailTxtBuilder = [System.Text.StringBuilder]::new()
    foreach ($roleDefinitionId in $linkableAzureRoleIds) {
        $roleDefinition = $null
        if ($GLOBALAzureRoleDefinitions -and $GLOBALAzureRoleDefinitions.ContainsKey($roleDefinitionId)) {
            $roleDefinition = $GLOBALAzureRoleDefinitions[$roleDefinitionId]
        }
        $roleDetailModel = Get-AzureRoleDefinitionDetailModel -RoleDefinitionId $roleDefinitionId -Assignments $azureRoleAssignmentsById[$roleDefinitionId].ToArray() -Definition $roleDefinition
        $azureRoleDetailObjects.Add((ConvertTo-AzureRoleDefinitionDetailObject -Model $roleDetailModel -LinkableRoleIds $linkableAzureRoleIds))
        [void]$azureRoleDetailTxtBuilder.Append((Format-AzureRoleDefinitionDetailText -Model $roleDetailModel))
    }

    # The HTML table links each role to its details block; the details renderer takes the anchor from the first column.
    $azureRoleLinkColumn = @{
        Name       = "Role"
        Expression = {
            $roleText = ConvertTo-EntraFalconHtmlText -Value $_.Role
            $rowRoleDefinitionId = [string]$_.RoleDefinitionId
            if (-not [string]::IsNullOrWhiteSpace($rowRoleDefinitionId) -and $linkableAzureRoleIds -contains $rowRoleDefinitionId) {
                "<a href=#$rowRoleDefinitionId>$roleText</a>"
            } else {
                $roleText
            }
        }
    }

    write-host "[*] Writing report files..."

    $mainEntraTable = $SortedEntraRoles | select-object -Property Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType,ActivatedViaPIM,Start,Expires,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}},PrincipalType,@{Name = "Scope"; Expression = { $_.ScopeResolvedLink}},Identities
    $mainEntraTableJson  = $mainEntraTable | ConvertTo-Json -Depth 5 -Compress

    $mainEntraTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainEntraTableJson + "`n" + '</script>'


    if ($DebugObjectDump) {
        $mainAzureTable = $SortedAzureRoles | Select-Object -Property $azureRoleLinkColumn,Scope,RoleTier,Level,@{Name = "Impact"; Expression = { $_.AssignmentImpact}},ScopeType,Environment,@{Name = "Resources"; Expression = { $_.ObservedResources}},ImpactExplanation,RoleType,Conditions,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}},Identities
    } else {
        $mainAzureTable = $SortedAzureRoles | Select-Object -Property $azureRoleLinkColumn,Scope,RoleTier,Level,@{Name = "Impact"; Expression = { $_.AssignmentImpact}},ScopeType,Environment,@{Name = "Resources"; Expression = { $_.ObservedResources}},RoleType,Conditions,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}},Identities
    }
    $mainAzureTableJson  = $mainAzureTable | ConvertTo-Json -Depth 5 -Compress

    $mainAzureTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainAzureTableJson + "`n" + '</script>'

    $azureRoleDetailsHEAD = @'
    <h2>Azure Role Details</h2>
    <div class="details-toolbar">
        <button id="toggle-expand">Expand All</button>
        <div class="details-search-wrapper">
            <div class="details-search-box">
                <input type="text" id="details-search" placeholder="Search details..." />
                <button class="details-search-help-btn" type="button" title="Search help">?</button>
                <div class="details-search-help-popover hidden">
                    <div class="search-help-title">Search guide</div>
                    <ul class="search-help-list">
                        <li><code>term</code> &mdash; substring match anywhere in object</li>
                        <li><code>!term</code> &mdash; exclude objects containing term</li>
                        <li><code>=value</code> &mdash; exact field value match</li>
                        <li><code>^prefix</code> &mdash; field value starts with</li>
                        <li><code>$suffix</code> &mdash; field value ends with</li>
                        <li><code>a && b</code> &mdash; both must match</li>
                        <li><code>a || b</code> &mdash; either must match</li>
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
    $azureRoleDetailsHTML = $azureRoleDetailsHEAD + "`n" + (ConvertTo-AzureRoleDefinitionDetailsJson -DetailObjects $azureRoleDetailObjects.ToArray()) + "`n" + '</script>'

    if ($ExportDataJson) {
        Export-EntraFalconDataJson -OutputFolder $outputFolder -DatasetName "EntraRoleAssignments" -Data $SortedEntraRoles | Out-Null
        $azureRoleReportData = $SortedAzureRoles | Select-Object -Property * -ExcludeProperty InventoryStatus,ImpactExplanation,ScoringPolicyVersion
        Export-EntraFalconDataJson -OutputFolder $outputFolder -DatasetName "AzureRoleAssignments" -Data $azureRoleReportData | Out-Null
    }



#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"
#Headers for the TXT output
$headerTXTEntraRoles = "
Entra Roles
****************************
Execution Warnings = $($entraIdentityWarnings -join ' / ')
"
$headerTXTAzureRoles = "
Azure Roles
****************************
Execution Warnings = $($azureIdentityWarnings -join ' / ')
"
$headerTXTAzureRoleDetails = "
Azure Role Details
****************************
"
    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

    #Generate and write HTML Entra role report
    Set-GlobalReportManifest -CurrentReportKey 'RoleEntra' -CurrentReportName 'Role Assignments Entra ID' -Warnings @($WarningReport + $entraIdentityWarnings)
    $Report = ConvertTo-HTML -Body "$headerHtml $mainEntraTableHTML" -Head ("<title>EF - Role Assignments (Entra)</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript
    $Report | Out-File "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $headerTXTEntraRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $SortedEntraRoles | format-table Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalDisplayName,PrincipalType,ScopeResolved,Identities | Out-File -Width 512 "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Csv) {
        $SortedEntraRoles | select-object Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalDisplayName,PrincipalType,ScopeResolved,Identities | Export-Csv -Path "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation -Encoding UTF8
    }
    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $(@($SortedEntraRoles).count) Entra ID role assignments stored in output files ($OutputFormats): $outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"

    #Add information to the enumeration summary
    $EntraEligibleCount = 0
    $Tier0Count = 0
    $Tier1Count = 0
    $Tier2Count = 0
    $TierUncatCount = 0
    $AssignmentsBuiltInRoles = 0
    $AssignmentPrincipalTypUsers = 0
    $AssignmentPrincipalTypGroups = 0
    $AssignmentPrincipalTypApps = 0
    $AssignmentPrincipalTypMIs = 0
    $AssignmentPrincipalTypAgentIdentities = 0
    $AssignmentPrincipalTypBlueprintPrincipals = 0
    $AssignmentPrincipalTypUnknown = 0

    foreach ($assignment in $SortedEntraRoles) {
        if ($assignment.AssignmentType -eq "eligible") {
            $EntraEligibleCount++
        }

        switch ($assignment.RoleTier) {
            "Tier-0" {$Tier0Count++; break}
            "Tier-1" {$Tier1Count++; break}
            "Tier-2" {$Tier2Count++; break}
            "Uncategorized" {$TierUncatCount++}
        }

        if ($Assignment.IsBuiltIn) {
            $AssignmentsBuiltInRoles++
        }

        switch ($assignment.PrincipalType) {
            "User" {$AssignmentPrincipalTypUsers++; break}
            "Group" {$AssignmentPrincipalTypGroups++; break}
            "Enterprise Application" {$AssignmentPrincipalTypApps++; break}
            "Agent Identity" {$AssignmentPrincipalTypAgentIdentities++; break}
            "Agent Identity Blueprint Principal" {$AssignmentPrincipalTypBlueprintPrincipals++; break}
            "Managed Identity" {$AssignmentPrincipalTypMIs++; break}
            "Unknown Object" {$AssignmentPrincipalTypUnknown++}
        }
    }

    # Store in global var
    $GlobalAuditSummary.EntraRoleAssignments.Count = @($SortedEntraRoles).count
    $GlobalAuditSummary.EntraRoleAssignments.Eligible = $EntraEligibleCount
    $GlobalAuditSummary.EntraRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles

    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.App = $AssignmentPrincipalTypApps
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.MI = $AssignmentPrincipalTypMIs
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.AgentIdentity = $AssignmentPrincipalTypAgentIdentities
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.BlueprintPrincipal = $AssignmentPrincipalTypBlueprintPrincipals
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown

    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-0" = $Tier0Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-1" = $Tier1Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-2" = $Tier2Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers.Uncategorized = $TierUncatCount
    


    # Wrap in @() because a single assignment is a bare object, which has no Count on PowerShell 5.1
    if (@($SortedAzureRoles).count -ge 1) {
        Set-GlobalReportManifest -CurrentReportKey 'RoleAz' -CurrentReportName 'Role Assignments Azure IAM' -Warnings $azureIdentityWarnings
        $Report = ConvertTo-HTML -Body "$headerHtml $mainAzureTableHTML" -Head ("<title>EF - Role Assignments (Azure)</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript -PreContent $azureRoleDetailsHTML
        $Report | Out-File "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"
        $headerTXTAzureRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $SortedAzureRoles | Format-Table Scope,Role,RoleTier,Level,@{Name = "Impact"; Expression = { $_.AssignmentImpact}},ScopeType,Environment,@{Name = "Resources"; Expression = { $_.ObservedResources}},RoleType,Conditions,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalDisplayName,PrincipalType,Identities | Out-File -Width 512 "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $headerTXTAzureRoleDetails | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $azureRoleDetailTxtBuilder.ToString() | Out-File "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        if ($Csv) {
            $SortedAzureRoles | Select-Object Scope,Role,RoleTier,Level,@{Name = "Impact"; Expression = { $_.AssignmentImpact}},ScopeType,Environment,@{Name = "Resources"; Expression = { $_.ObservedResources}},RoleType,Conditions,AssignmentType,ActivatedViaPIM,Start,Expires,PrincipalDisplayName,PrincipalType,Identities | Export-Csv -Path "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation -Encoding UTF8
        }
        write-host "[+] Details of $(@($SortedAzureRoles).count) Azure role assignments stored in output files ($OutputFormats): $outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
        
        #Add information to the enumeration summary
        $AzureEligibleCount = 0
        $AzureTier0Count = 0
        $AzureTier1Count = 0
        $AzureTier2Count = 0
        $AzureTier3Count = 0
        $AzureTierUncatCount = 0
        $AzureLevelCriticalCount = 0
        $AzureLevelHighCount = 0
        $AzureLevelMediumCount = 0
        $AzureLevelLowCount = 0
        $AzureLevelUnknownCount = 0
        $AssignmentsBuiltInRoles = 0
        $AssignmentPrincipalTypUsers = 0
        $AssignmentPrincipalTypGroups = 0
        $AssignmentPrincipalTypSPs = 0
        $AssignmentPrincipalTypMIs = 0
        $AssignmentPrincipalTypAgentIdentities = 0
        $AssignmentPrincipalTypBlueprintPrincipals = 0
        $AssignmentPrincipalTypUnknown = 0

        foreach ($assignment in $SortedAzureRoles) {
            if ($assignment.AssignmentType -eq "eligible") {
                $AzureEligibleCount++
            }
            if ($Assignment.RoleType -match "BuiltInRole") {
                $AssignmentsBuiltInRoles++
            }

            switch ($assignment.RoleTier) {
                "Tier-0" { $AzureTier0Count++; break }
                "Tier-1" { $AzureTier1Count++; break }
                "Tier-2" { $AzureTier2Count++; break }
                "Tier-3" { $AzureTier3Count++; break }
                "Uncategorized" { $AzureTierUncatCount++ }
            }

            switch ($assignment.Level) {
                "Critical" { $AzureLevelCriticalCount++; break }
                "High" { $AzureLevelHighCount++; break }
                "Medium" { $AzureLevelMediumCount++; break }
                "Low" { $AzureLevelLowCount++; break }
                default { $AzureLevelUnknownCount++ }
            }

            switch ($assignment.PrincipalType) {
                "User" {$AssignmentPrincipalTypUsers++; break}
                "Group" {$AssignmentPrincipalTypGroups++; break}
                "ServicePrincipal" {$AssignmentPrincipalTypSPs++; break}
                "Enterprise Application" {$AssignmentPrincipalTypSPs++; break}
                "Agent Identity" {$AssignmentPrincipalTypAgentIdentities++; break}
                "Agent Identity Blueprint Principal" {$AssignmentPrincipalTypBlueprintPrincipals++; break}
                "Managed Identity" {$AssignmentPrincipalTypMIs++; break}
                "Unknown Object" {$AssignmentPrincipalTypUnknown++}
            }
        }

        #Add information to the enumeration summary
        $GlobalAuditSummary.AzureRoleAssignments.Count = @($SortedAzureRoles).count
        $GlobalAuditSummary.AzureRoleAssignments.Eligible = $AzureEligibleCount
        $GlobalAuditSummary.AzureRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.SP = $AssignmentPrincipalTypSPs
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.MI = $AssignmentPrincipalTypMIs
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.AgentIdentity = $AssignmentPrincipalTypAgentIdentities
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.BlueprintPrincipal = $AssignmentPrincipalTypBlueprintPrincipals
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-0" = $AzureTier0Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-1" = $AzureTier1Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-2" = $AzureTier2Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-3" = $AzureTier3Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers.Uncategorized = $AzureTierUncatCount
        $GlobalAuditSummary.AzureRoleAssignments.Levels.Critical = $AzureLevelCriticalCount
        $GlobalAuditSummary.AzureRoleAssignments.Levels.High = $AzureLevelHighCount
        $GlobalAuditSummary.AzureRoleAssignments.Levels.Medium = $AzureLevelMediumCount
        $GlobalAuditSummary.AzureRoleAssignments.Levels.Low = $AzureLevelLowCount
        $GlobalAuditSummary.AzureRoleAssignments.Levels.Unknown = $AzureLevelUnknownCount

        $azureScopeTypeCounts = Get-AzureRoleScopeTypeCounts -Assignments $SortedAzureRoles
        $GlobalAuditSummary.AzureRoleAssignments.ScopeType = $azureScopeTypeCounts



    }

}

Export-ModuleMember -Function Invoke-CheckRoles

