<#
    .SYNOPSIS
       Generates the security findings HTML report.

#>
function Invoke-CheckTenant {
    ############################## Parameter section ########################
    #region Parameters
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object]$CurrentTenant,
        [Parameter(Mandatory=$true)][string]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory=$true)][hashtable]$AllCaps,
        [Parameter(Mandatory=$true)][hashtable]$ManagedIdentities,
        [Parameter(Mandatory=$true)][hashtable]$PimforEntraRoles,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$false)][hashtable]$Devices,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments,
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentityBlueprints,
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentities
    )
    #endregion

    ############################## Function section ########################
    #region Helper Functions
    function Set-FindingOverride {
        param(
            [string]$FindingId,
            [hashtable]$Props
        )
        # Apply partial updates to a single finding object by FindingId.
        if (-not $FindingsById.ContainsKey($FindingId)) { return }
        $target = $FindingsById[$FindingId]
        foreach ($kvp in $Props.GetEnumerator()) {
            $target | Add-Member -NotePropertyName $kvp.Key -NotePropertyValue $kvp.Value -Force
        }
    }

    function Get-IntSafe {
        param($Value)
        $n = 0
        if ($null -eq $Value) { return 0 }
        [int]::TryParse("$Value", [ref]$n) | Out-Null
        return $n
    }

    function Test-GroupHasEligibleOnlyPimAccessPath {
        param(
            [string]$GroupId
        )

        if ([string]::IsNullOrWhiteSpace($GroupId)) { return $false }
        if (-not $AllGroupsDetails.ContainsKey($GroupId)) { return $false }

        $group = $AllGroupsDetails[$GroupId]
        if (-not $group) { return $false }

        $eligibleMemberEntries = if ($EligiblePimGroupMembersByGroupId.ContainsKey($GroupId)) { @($EligiblePimGroupMembersByGroupId[$GroupId]) } else { @() }
        $eligibleOwnerEntries = if ($EligiblePimGroupOwnersByGroupId.ContainsKey($GroupId)) { @($EligiblePimGroupOwnersByGroupId[$GroupId]) } else { @() }
        $hasEligiblePath = ($eligibleMemberEntries.Count + $eligibleOwnerEntries.Count) -gt 0
        if (-not $hasEligiblePath) { return $false }

        $activeDirectUserCount = @(
            @($group.Userdetails) | Where-Object {
                $assignmentType = "$($_.AssignmentType)".Trim()
                [string]::IsNullOrWhiteSpace($assignmentType) -or $assignmentType -eq "Active"
            }
        ).Count
        if ($activeDirectUserCount -gt 0) { return $false }

        $spCount = Get-IntSafe $group.SPCount
        if ($spCount -gt 0) { return $false }

        $eligibleMemberGroupEntries = @($eligibleMemberEntries | Where-Object { "$($_.Type)".Trim().ToLowerInvariant() -eq "group" })
        $eligibleOwnerGroupEntries = @($eligibleOwnerEntries | Where-Object { "$($_.Type)".Trim().ToLowerInvariant() -eq "group" })
        $nestedGroupCount = Get-IntSafe $group.NestedGroups
        if ($nestedGroupCount -gt $eligibleMemberGroupEntries.Count) { return $false }

        $directOwnersCount = Get-IntSafe $group.DirectOwners
        if ($directOwnersCount -gt $eligibleOwnerEntries.Count) { return $false }

        return $true
    }

    function Get-CredentialDisplayName {
        param(
            $Credential,
            [string]$FallbackLabel = "-"
        )

        if ($null -eq $Credential) {
            return $FallbackLabel
        }

        foreach ($propertyName in @("DisplayName", "Name", "Hint")) {
            if ($Credential.PSObject.Properties[$propertyName]) {
                $value = "$($Credential.$propertyName)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne "-") {
                    return $value
                }
            }
        }

        return $FallbackLabel
    }

    function Get-NormalizedRoleTierLabel {
        param($RoleTier)
        $tierRaw = "$RoleTier".Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($tierRaw)) { return "Uncategorized" }
        switch -Regex ($tierRaw) {
            "^(0|tier-?0)$" { return "0" }
            "^(1|tier-?1)$" { return "1" }
            "^(2|tier-?2)$" { return "2" }
            "^(uncategorized|unknown|n/a|\\?)$" { return "Uncategorized" }
            default { return "Uncategorized" }
        }
    }

    function Test-ContainsToken {
        param(
            $Value,
            [string]$Token
        )
        if ([string]::IsNullOrWhiteSpace($Token) -or $null -eq $Value) { return $false }
        $candidateValues = @()
        if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
            foreach ($item in $Value) { $candidateValues += "$item" }
        } else {
            $candidateValues += "$Value"
        }
        foreach ($candidate in $candidateValues) {
            # Normalize common list separators used in CAP properties (comma, OR, AND, pipes).
            $parts = "$candidate" -split "(?i)\s*(?:,|;|\|\||\||\bor\b|\band\b)\s*"
            foreach ($part in $parts) {
                if ($part.Trim().ToLowerInvariant() -eq $Token.ToLowerInvariant()) { return $true }
            }
        }
        return $false
    }

    function Test-IsTier0OwnerId {
        param(
            [string]$OwnerId,
            [string]$OwnerType
        )
        if ([string]::IsNullOrWhiteSpace($OwnerId)) { return $false }
        $ownerTypeNormalized = "$OwnerType".Trim().ToLowerInvariant()
        if ($ownerTypeNormalized -eq "user") {
            return $tier0UserIds.Contains($OwnerId)
        }
        if ($ownerTypeNormalized -eq "managedidentity") {
            return $tier0ManagedIdentityIds.Contains($OwnerId)
        }
        if ($ownerTypeNormalized -eq "application" -or $ownerTypeNormalized -eq "serviceprincipal") {
            if ($tier0EnterpriseAppIds.Contains($OwnerId)) { return $true }
            if ($tier0ManagedIdentityIds.Contains($OwnerId)) { return $true }
            return $false
        }
        if ($tier0UserIds.Contains($OwnerId)) { return $true }
        if ($tier0EnterpriseAppIds.Contains($OwnerId)) { return $true }
        if ($tier0ManagedIdentityIds.Contains($OwnerId)) { return $true }
        return $false
    }

    function Test-CapSoftCompliance {
        param(
            $Policy,
            [switch]$SkipAllUsersCheck,
            [switch]$AllowGuestExclusions
        )
        $issues = [System.Collections.Generic.List[string]]::new()

        if (-not $SkipAllUsersCheck) {
            $incUsersText = "$($Policy.IncUsers)".Trim().ToLowerInvariant()
            if ($incUsersText -ne "all") { $issues.Add("Included users not set to <code>all</code>") }
        }

        $excludedUsersEffective = Get-IntSafe $Policy.ExcludedUsersEffective
        if ($AllowGuestExclusions) {
            $excludedUsersEffective = [Math]::Max(($excludedUsersEffective - (Get-IntSafe $Policy.ExcludedGuestUsersEffective)), 0)
        }
        if ($excludedUsersEffective -ge 3) { $issues.Add("Too many excluded users") }

        if ((Get-IntSafe $Policy.MissingRolesCount) -ne 0) { $issues.Add("Missing roles detected") }
        if ((Get-IntSafe $Policy.ScopedRolesCount) -ne 0) { $issues.Add("Scoped roles detected") }
        $additionalConditions = if ($null -ne $Policy.additionalConditionTypes) { $Policy.additionalConditionTypes } else { $Policy.AdditionalConditionTypes }
        if ((Get-IntSafe $additionalConditions) -ne 0) { $issues.Add("Additional conditions present") }

        return [pscustomobject]@{
            Pass = ($issues.Count -eq 0)
            Issues = @($issues)
        }
    }

    function Test-IsExcludedSyncUser {
        param($UserObject)

        if ($null -eq $UserObject) { return $false }

        $upn = "$($UserObject.UPN)".Trim()
        if ([string]::IsNullOrWhiteSpace($upn)) {
            $upn = "$($UserObject.UserPrincipalName)".Trim()
        }
        if ([string]::IsNullOrWhiteSpace($upn)) { return $false }

        return $upn.StartsWith("Sync_", [System.StringComparison]::OrdinalIgnoreCase) -or
               $upn.StartsWith("ADToAADSyncServiceAccount", [System.StringComparison]::OrdinalIgnoreCase)
    }

    function Get-AgentIdentityEffectiveRoleEntries {
        param(
            [Parameter(Mandatory = $true)]
            $AgentIdentity,
            [Parameter(Mandatory = $true)]
            [ValidateSet("Entra", "Azure")]
            [string]$RoleSystem
        )

        $detailsProperty = if ($RoleSystem -eq "Entra") { "EntraRoleDetails" } else { "AzureRoleDetails" }
        $entries = [System.Collections.Generic.List[object]]::new()

        foreach ($role in @($AgentIdentity.$detailsProperty)) {
            if (-not $role) { continue }
            if ($role.PSObject -and $role.PSObject.Properties.Count -eq 0) { continue }
            if ("$($role.AssignmentType)".Trim() -ne "Active") { continue }
            $hasMeaningfulFields = (
                -not [string]::IsNullOrWhiteSpace("$($role.RoleTier)") -or
                -not [string]::IsNullOrWhiteSpace("$($role.DisplayName)") -or
                -not [string]::IsNullOrWhiteSpace("$($role.RoleName)") -or
                -not [string]::IsNullOrWhiteSpace("$($role.RoleDefinitionId)") -or
                -not [string]::IsNullOrWhiteSpace("$($role.RoleDefinitionName)")
            )
            if (-not $hasMeaningfulFields) { continue }
            $entries.Add([pscustomobject]@{
                Source = "Direct"
                GroupDisplayName = $null
                Role = $role
            })
        }

        foreach ($sourceDefinition in @(
            @{ Source = "GroupMember"; Groups = @($AgentIdentity.GroupMember) },
            @{ Source = "GroupOwner"; Groups = @($AgentIdentity.GroupOwner) }
        )) {
            foreach ($group in $sourceDefinition.Groups) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                $addedDetailedRole = $false
                foreach ($role in @($group.$detailsProperty)) {
                    if (-not $role) { continue }
                    if ($role.PSObject -and $role.PSObject.Properties.Count -eq 0) { continue }
                    if ("$($role.AssignmentType)".Trim() -ne "Active") { continue }
                    $hasMeaningfulFields = (
                        -not [string]::IsNullOrWhiteSpace("$($role.RoleTier)") -or
                        -not [string]::IsNullOrWhiteSpace("$($role.DisplayName)") -or
                        -not [string]::IsNullOrWhiteSpace("$($role.RoleName)") -or
                        -not [string]::IsNullOrWhiteSpace("$($role.RoleDefinitionId)") -or
                        -not [string]::IsNullOrWhiteSpace("$($role.RoleDefinitionName)")
                    )
                    if (-not $hasMeaningfulFields) { continue }
                    $addedDetailedRole = $true
                    $entries.Add([pscustomobject]@{
                        Source = $sourceDefinition.Source
                        GroupDisplayName = $groupDisplayName
                        Role = $role
                    })
                }

                # Some group-derived role paths are only exposed as aggregate role counts / max tier.
                if ($addedDetailedRole) { continue }
                $groupMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem $RoleSystem
                $aggregateRoleCount = Get-IntSafe $groupMetrics.RoleCount
                $aggregateRoleTier = "$($groupMetrics.MaxTier)"
                $normalizedTier = Get-NormalizedRoleTierLabel -RoleTier $aggregateRoleTier
                if ($aggregateRoleCount -le 0) { continue }
                if ($normalizedTier -eq "Uncategorized") { continue }
                $entries.Add([pscustomobject]@{
                    Source = $sourceDefinition.Source
                    GroupDisplayName = $groupDisplayName
                    Role = [pscustomobject]@{
                        RoleTier = $aggregateRoleTier
                        AssignmentType = "Active"
                        IsSynthetic = $true
                    }
                })
            }
        }

        return @($entries)
    }

    function Write-CapHardFailureTrace {
        param(
            [string]$CapId,
            $Policy,
            $Issues
        )
        if ($null -eq $Issues -or $Issues.Count -eq 0) { return }
        $policyName = "$($Policy.DisplayName)"
        $policyId = "$($Policy.Id)"
        $issueText = (@($Issues) -join "; ")
        Write-Log -Level Trace -Message ("[{0}] Hard-check failed for policy '{1}' ({2}): {3}" -f $CapId, $policyName, $policyId, $issueText)
    }

    function Get-CapIssueSummaryHtml {
        param(
            [hashtable]$IssueCounts,
            [string]$Title
        )

        if ($null -eq $IssueCounts -or $IssueCounts.Count -eq 0) { return "" }

        $items = @()
        foreach ($issue in ($IssueCounts.Keys | Sort-Object)) {
            $issueCount = Get-IntSafe $IssueCounts[$issue]
            if ($issueCount -eq 1) {
                $items += "<li>1 policy: $issue</li>"
            } else {
                $items += "<li>$issueCount policies: $issue</li>"
            }
        }
        $summaryList = if ($items.Count -gt 0) { "<ul>$($items -join '')</ul>" } else { "<p>No details available.</p>" }

        if ([string]::IsNullOrWhiteSpace($Title)) {
            return $summaryList
        }

        return "<p><strong>${Title}:</strong></p>$summaryList"
    }

    function Get-CapAuthStrengthDisplay {
        param(
            $Policy,
            [hashtable]$AuthStrengthLookupById
        )

        $authStrengthDisplay = "$($Policy.AuthStrength)".Trim()
        if (-not [string]::IsNullOrWhiteSpace($authStrengthDisplay)) { return $authStrengthDisplay }
        return "$($Policy.AuthStrengthId)".Trim()
    }

    function New-CapUnifiedEvaluation {
        param(
            [System.Collections.IEnumerable]$Candidates,
            [System.Collections.IEnumerable]$HardPass,
            [System.Collections.IEnumerable]$SoftPass,
            [switch]$ResolveAuthStrength,
            [hashtable]$AuthStrengthLookupById
        )

        # Materialize the input enumerables once because the data is traversed multiple times below.
        $candidateList = @($Candidates)
        $hardPassList = @($HardPass)
        $softPassList = @($SoftPass)

        # Use ID-based lookups so each candidate can be classified without repeated collection scans.
        $hardPassIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($policy in $hardPassList) {
            [void]$hardPassIds.Add("$($policy.Id)")
        }

        $softPassIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($policy in $softPassList) {
            [void]$softPassIds.Add("$($policy.Id)")
        }

        $hardFailCount = 0
        $softFailCount = 0
        $passCount = 0
        $affectedSoftFail = [System.Collections.Generic.List[object]]::new()
        $affectedHardFail = [System.Collections.Generic.List[object]]::new()
        $affectedPass = [System.Collections.Generic.List[object]]::new()

        $authStrengthDisplayByPolicyId = @{}
        $showAuthStrength = $false
        $showMissingRoles = $false
        $showScopedRoles = $false
        $showAdditionalConditions = $false

        # Decide optional columns at the finding level so the affected-object table stays consistent across all rows.
        foreach ($policy in $candidateList) {
            $policyId = "$($policy.Id)"
            $authStrengthDisplay = if ($ResolveAuthStrength) {
                Get-CapAuthStrengthDisplay -Policy $policy -AuthStrengthLookupById $AuthStrengthLookupById
            } else {
                "$($policy.AuthStrength)"
            }

            $authStrengthDisplayByPolicyId[$policyId] = $authStrengthDisplay
            if (-not [string]::IsNullOrWhiteSpace($authStrengthDisplay)) {
                $showAuthStrength = $true
            }
            if ((Get-IntSafe $policy.MissingRolesCount) -gt 0) {
                $showMissingRoles = $true
            }
            if ((Get-IntSafe $policy.ScopedRolesCount) -gt 0) {
                $showScopedRoles = $true
            }
            $additionalConditions = if ($null -ne $policy.additionalConditionTypes) { $policy.additionalConditionTypes } else { $policy.AdditionalConditionTypes }
            if ((Get-IntSafe $additionalConditions) -gt 0) {
                $showAdditionalConditions = $true
            }
        }

        # Build one affected-object row per policy and group rows by evaluation result for stable ordering in the report.
        foreach ($policy in $candidateList) {
            $policyId = "$($policy.Id)"
            $evaluationResult = "HardFail"
            $evaluationSortRank = 2
            if ($hardPassIds.Contains($policyId)) {
                if ($softPassIds.Contains($policyId)) {
                    $evaluationResult = "Pass"
                    $evaluationSortRank = 0
                    $passCount += 1
                } else {
                    $evaluationResult = "SoftFail"
                    $evaluationSortRank = 1
                    $softFailCount += 1
                }
            } else {
                $hardFailCount += 1
            }

            $additionalConditions = if ($null -ne $policy.additionalConditionTypes) { $policy.additionalConditionTypes } else { $policy.AdditionalConditionTypes }
            $authStrengthDisplay = "$($authStrengthDisplayByPolicyId[$policyId])"
            $incUsersRaw = "$($policy.IncUsers)".Trim()
            $incUsersDisplay = if ($incUsersRaw.ToLowerInvariant() -eq "all") { "all" } else { "$(Get-IntSafe $policy.IncludedUsersEffective)" }

            $rowProps = [ordered]@{
                "DisplayName" = "<a href=`"ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($policy.Id)`" target=`"_blank`">$($policy.DisplayName)</a>"
                "Evaluation Result" = $evaluationResult
                "State" = $policy.State
                "Resources" = $policy.IncResources
                "Grant Controls" = $policy.GrantControls
            }
            if ($showAuthStrength) {
                $rowProps["Auth Strength"] = $authStrengthDisplay
            }
            $rowProps["Included Users (effective)"] = $incUsersDisplay
            $rowProps["Excluded Users (effective)"] = Get-IntSafe $policy.ExcludedUsersEffective
            if ($showMissingRoles) {
                $rowProps["Missing Roles"] = $policy.MissingRolesCount
            }
            if ($showScopedRoles) {
                $rowProps["Scoped Roles"] = $policy.ScopedRolesCount
            }
            if ($showAdditionalConditions) {
                $rowProps["Additional Conditions"] = $additionalConditions
            }
            $rowProps["Warning"] = $policy.Warnings
            $rowProps["_SortEvaluationRank"] = $evaluationSortRank

            $row = [pscustomobject]$rowProps

            if ($evaluationResult -eq "SoftFail") {
                $affectedSoftFail.Add($row)
            } elseif ($evaluationResult -eq "HardFail") {
                $affectedHardFail.Add($row)
            } else {
                $affectedPass.Add($row)
            }
        }

        $affected = [System.Collections.Generic.List[object]]::new()
        # Show passing policies first, then soft-fail, then hard-fail.
        foreach ($row in $affectedPass) { $affected.Add($row) }
        foreach ($row in $affectedSoftFail) { $affected.Add($row) }
        foreach ($row in $affectedHardFail) { $affected.Add($row) }

        return [pscustomobject]@{
            AffectedObjects = $affected
            HardFailCount = $hardFailCount
            SoftFailCount = $softFailCount
            PassCount = $passCount
        }
    }

    #endregion

    ############################## Data collection section ########################
    #region Data Collection
    $authFlowForLog = "Unknown"
    if ($GLOBALAuthMethods -and $GLOBALAuthMethods.ContainsKey("AuthFlow")) {
        $authFlowForLog = [string]$GLOBALAuthMethods.AuthFlow
    }
    Write-Log -Level Debug -Message ("[Invoke-CheckTenant] Input snapshot: AuthFlow={0}; AllCaps={1}; EnterpriseApps={2}; AppRegistrations={3}; ManagedIdentities={4}; PimforEntraRoles={5}; AllGroupsDetails={6}; Users={7}; AgentIdentityBlueprints={8}; AgentIdentities={9}" -f `
        $authFlowForLog, $AllCaps.Count, $EnterpriseApps.Count, $AppRegistrations.Count, $ManagedIdentities.Count, $PimforEntraRoles.Count, $AllGroupsDetails.Count, $Users.Count, $AgentIdentityBlueprints.Count, $AgentIdentities.Count)

    # Collect all Graph API data up-front so enumeration logic only evaluates data.
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get authorization policies"
    $authorizationPolicyQueryParameters = @{
        '$select' = "allowInvitesFrom,guestUserRoleId,defaultUserRolePermissions,permissionGrantPolicyIdsAssignedToDefaultUserRole,allowedToUseSSPR"
    }
    $AuthPolicy = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/policies/authorizationPolicy" -QueryParameters $authorizationPolicyQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    Write-Host "[*] Get consent permission classification"
    $consentClassificationQueryParameters = @{
        '$filter' = "hasPermissionClassifications eq true"
        '$select' = "id"
        '$expand' = "delegatedPermissionClassifications"
    }
    $ConsentPermissionClassification = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals" -QueryParameters $consentClassificationQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    Write-Host "[*] Get tenant directory settings"
    $tenantSettingsQueryParameters = @{
        '$select' = "templateId,values"
    }
    $TenantDirectorySettings = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/settings" -QueryParameters $tenantSettingsQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $UnifiedGroupSettingsTemplateId = "62375ab9-6b52-47ed-826b-58e47e0e304b"
    $PasswordProtectionSettingsTemplateId = "5cf42378-d67d-4f36-ba46-e8b86229381d"
    $TenantDirectorySettingsList = @()
    # Normalize /settings response shapes: envelope with .value or direct collection.
    if ($TenantDirectorySettings) {
        if ($TenantDirectorySettings.value -and (($TenantDirectorySettings.value | Select-Object -First 1) -and (($TenantDirectorySettings.value | Select-Object -First 1) | Get-Member -Name templateId -MemberType Properties))) {
            $TenantDirectorySettingsList = @($TenantDirectorySettings.value)
        } elseif ((($TenantDirectorySettings | Select-Object -First 1) -and (($TenantDirectorySettings | Select-Object -First 1) | Get-Member -Name templateId -MemberType Properties))) {
            $TenantDirectorySettingsList = @($TenantDirectorySettings)
        }
    }
    Write-Log -Level Debug -Message ("Tenant directory settings normalized count: {0}" -f $TenantDirectorySettingsList.Count)

    # Device registration policy needs a different token in some auth flows.
    # Authentication strengths are already resolved during Conditional Access enumeration and travel with $AllCaps.
    $deviceRegistrationPolicy = $null
    $DeviceRegistrationPolicyAvailable = $false
    $specialDataUnavailabilityReason = ""
    $specialDataAccessToken = $null

    $effectiveAuthFlow = $null
    if ($GLOBALAuthMethods -and $GLOBALAuthMethods.ContainsKey("AuthFlow")) {
        $effectiveAuthFlow = [string]$GLOBALAuthMethods.AuthFlow
    }
    $isBroCiFlow = @("BroCi", "BroCiManualCode", "BroCiToken") -contains $effectiveAuthFlow

    if ($isBroCiFlow -or $effectiveAuthFlow -eq "ServicePrincipal") {
        # BroCi and ServicePrincipal flows can use the primary Graph token for these endpoints.
        $specialDataAccessToken = $GLOBALMsGraphAccessToken.access_token
    } elseif ($effectiveAuthFlow -eq "DeviceCode") {
        $specialDataUnavailabilityReason = "DeviceCode flow does not support these endpoints."
        Write-Log -Level Verbose -Message "Skipping device registration policy lookup: $specialDataUnavailabilityReason"
    } else {
        $specialAuthContext = $global:GLOBALSecurityFindingsAccessContext
        $hasSpecialTokenContext = ($null -ne $specialAuthContext -and $specialAuthContext.PSObject.Properties.Name -contains "IsAvailable")

        if ($hasSpecialTokenContext -and -not [bool]$specialAuthContext.IsAvailable) {
            $specialDataUnavailabilityReason = "Special authentication failed earlier ($($specialAuthContext.Reason))."
            Write-Log -Level Verbose -Message "Skipping device registration policy lookup: $specialDataUnavailabilityReason"
        } else {
            $refreshOk = RefreshAuthenticationSecurityFindingsMsGraph
            if ($refreshOk -and $null -ne $GLOBALSecurityFindingsGraphAccessTokenSpecial) {
                $specialDataAccessToken = $GLOBALSecurityFindingsGraphAccessTokenSpecial.access_token
            } else {
                $specialDataUnavailabilityReason = "Special token is unavailable or refresh failed."
                Write-Log -Level Verbose -Message "Skipping device registration policy lookup: $specialDataUnavailabilityReason"
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($specialDataAccessToken)) {
        try {
            Write-Host "[*] Get device registration policy"
            $deviceRegistrationPolicy = Send-GraphRequest -AccessToken $specialDataAccessToken -Method GET -Uri "/policies/deviceRegistrationPolicy" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
            $DeviceRegistrationPolicyAvailable = ($null -ne $deviceRegistrationPolicy)
        } catch {
            Write-Log -Level Verbose -Message "Could not retrieve /policies/deviceRegistrationPolicy. CAP-004 device-settings context will require manual verification."
        }
    } else {
        Write-Host "[i] Security Findings device policy check skipped for current auth flow/token context."
    }
    Write-Log -Level Debug -Message ("Special endpoint availability: DeviceRegistrationPolicyAvailable={0}" -f $DeviceRegistrationPolicyAvailable)


    #endregion

    ############################## Constants section ########################
    #region Constants And Finding Definitions
    $Title = "SecurityFindings"
    $ReportKey = "SecurityFindings"
    $ReportName = "Security Findings"
    $ReportId = "SecurityFindings_$StartTimestamp_$($CurrentTenant.DisplayName)"
    $DeviceSettingsRequireMFAJoinKnown = $false
    $DeviceSettingsRequireMFAJoin = $false
    if ($DeviceRegistrationPolicyAvailable -and $null -ne $deviceRegistrationPolicy) {
        $DeviceSettingsRequireMFAJoinKnown = $true
        $DeviceSettingsRequireMFAJoin = ("$($deviceRegistrationPolicy.multiFactorAuthConfiguration)".Trim().ToLowerInvariant() -eq "required")
    }


    # Base findings (static definitions)
    $FindingsJson = @'
[
  {
    "FindingId": "COL-001",
    "Title": "Guest Access Level Not Set to Restricted",
    "Category": "External Collaboration",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "COL-002",
    "Title": "Weak Guest Invite Settings",
    "Category": "External Collaboration",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "COL-003",
    "Title": "Guests Allowed to Own M365 Groups",
    "Category": "External Collaboration",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PAS-001",
    "Title": "Custom Banned Password List Not Used",
    "Category": "Passwords",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PAS-002",
    "Title": "Custom Banned Password List Provides Limited Protection",
    "Category": "Passwords",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PAS-003",
    "Title": "Password Protection for On-Premises Not Enforced",
    "Category": "Passwords",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "PAS-004",
    "Title": "Weak Account Lockout Settings",
    "Category": "Passwords",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PAS-005",
    "Title": "Self-Service Password Reset is Enabled for Administrators",
    "Category": "Passwords",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-001",
    "Title": "App Creation Not Restricted",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-002",
    "Title": "Non-Admin Users Can Create New Tenants",
    "Category": "Users",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-003",
    "Title": "Users Can Read BitLocker Recovery Key of Owned Devices",
    "Category": "Users",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-004",
    "Title": "Users Are Allowed to Consent to Apps",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-005",
    "Title": "Inactive Users",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-006",
    "Title": "Least Privilege Principle Not Applied (Entra ID)",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-007",
    "Title": "Hybrid Users with Tier-0 Entra ID Roles",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-008",
    "Title": "Hybrid Users with Tier-0 Azure Roles",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-009",
    "Title": "Least Privilege Principle Not Applied (Azure)",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-010",
    "Title": "Weak Protection of Privileged Users (Entra ID)",
    "Category": "Users",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-011",
    "Title": "Weak Protection of Privileged Users (Azure)",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-012",
    "Title": "Users Without Registered MFA Factors",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "USR-013",
    "Title": "Unnecessary Synchronization of On-Premises Accounts to Entra ID",
    "Category": "Users",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "GRP-001",
    "Title": "Security Group Creation Not Restricted",
    "Category": "Groups",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  }
    ,
  {
    "FindingId": "GRP-002",
    "Title": "M365 Group Creation Not Restricted",
    "Category": "Groups",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "GRP-003",
    "Title": "Public M365 Groups",
    "Category": "Groups",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "GRP-004",
    "Title": "Dynamic Groups with Potentially Dangerous Membership Rules",
    "Category": "Groups",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "GRP-005",
    "Title": "Weak Protection of Sensitive Groups",
    "Category": "Groups",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-001",
    "Title": "Device Code Flow Not Restricted",
    "Category": "Conditional Access Policies",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-002",
    "Title": "Registration of Security Info Not Restricted",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-003",
    "Title": "Legacy Authentication Not Blocked",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-004",
    "Title": "No MFA Required for Joining or Registering a Device",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-005",
    "Title": "No Phishing-Resistant MFA Enforced",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-006",
    "Title": "Combined Risk Policy",
    "Category": "Conditional Access Policies",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-007",
    "Title": "Sign-In Risk Not Managed",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-008",
    "Title": "User Risk Not Managed",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-009",
    "Title": "MFA Not Enforced",
    "Category": "Conditional Access Policies",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-010",
    "Title": "Conditional Access Policy Missing Used Tier-0/Tier-1 Roles",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "Vulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "CAP-011",
    "Title": "Conditional Access Policy Includes Roles With Scoped Assignments",
    "Category": "Conditional Access Policies",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-001",
    "Title": "Enterprise Applications with Client Credentials",
    "Category": "Enterprise Applications",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-002",
    "Title": "Inactive Enterprise Applications",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-003",
    "Title": "Enterprise Applications with Non-Tier-0 Owner",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-004",
    "Title": "Foreign Enterprise Applications with Extensive API Privileges (as Application)",
    "Category": "Enterprise Applications",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-005",
    "Title": "Foreign Enterprise Applications with Extensive API Privileges (Delegated)",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-006",
    "Title": "Foreign Enterprise Applications with Entra ID Roles",
    "Category": "Enterprise Applications",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-007",
    "Title": "Foreign Enterprise Applications with Azure Roles",
    "Category": "Enterprise Applications",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-008",
    "Title": "Foreign Enterprise Applications Owning Objects",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-009",
    "Title": "Internal Enterprise Applications with Extensive API Privileges (as Application)",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-010",
    "Title": "Internal Enterprise Applications with Extensive API Privileges (Delegated)",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-011",
    "Title": "Internal Enterprise Applications with Privileged Entra ID Roles",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-012",
    "Title": "Internal Enterprise Applications with Privileged Azure Roles",
    "Category": "Enterprise Applications",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "ENT-013",
    "Title": "Known Malicious Enterprise Applications",
    "Category": "Enterprise Applications",
    "Severity": 4,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "APP-001",
    "Title": "App Registrations with Secrets",
    "Category": "App Registrations",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "APP-002",
    "Title": "App Registrations Missing App Instance Property Lock",
    "Category": "App Registrations",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "APP-003",
    "Title": "App Registration with Non-Tier-0 Owner",
    "Category": "App Registrations",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-001",
    "Title": "Blueprints With Client Secrets",
    "Category": "Agent Identities",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-002",
    "Title": "Foreign Agent Identities with Extensive API Privileges (as Application)",
    "Category": "Agent Identities",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-003",
    "Title": "Foreign Agent Identities with Extensive API Privileges (Delegated)",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-004",
    "Title": "Foreign Agent Identities with Entra ID Roles",
    "Category": "Agent Identities",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-005",
    "Title": "Foreign Agent Identities with Azure Roles",
    "Category": "Agent Identities",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-006",
    "Title": "Internal Agent Identities with Extensive API Privileges (as Application)",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-007",
    "Title": "Internal Agent Identities with Extensive API Privileges (Delegated)",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-008",
    "Title": "Internal Agent Identities with Privileged Entra ID Roles",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-009",
    "Title": "Internal Agent Identities with Privileged Azure Roles",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-010",
    "Title": "Inactive Agent Identities",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-011",
    "Title": "Foreign Agent Users with Entra ID Roles",
    "Category": "Agent Identities",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-012",
    "Title": "Foreign Agent Users with Azure Roles",
    "Category": "Agent Identities",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-013",
    "Title": "Internal Agent Users with Privileged Entra ID Roles",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-014",
    "Title": "Internal Agent Users with Privileged Azure Roles",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-015",
    "Title": "Agent Users Owning CAP-Related Groups",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-016",
    "Title": "Inactive Agent Users",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "AGT-017",
    "Title": "Blueprints with Non-Tier-0 Owner",
    "Category": "Agent Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "MAI-001",
    "Title": "Managed Identities with API Privileges",
    "Category": "Managed Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "MAI-002",
    "Title": "Managed Identities with Privileged Entra ID Roles",
    "Category": "Managed Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "MAI-003",
    "Title": "Managed Identities with Privileged Azure Roles",
    "Category": "Managed Identities",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-001",
    "Title": "PIM for Entra Roles Not Used",
    "Category": "PIM",
    "Severity": 3,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-002",
    "Title": "Tier-0 Roles With Active Assignments Outside PIM",
    "Category": "PIM",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-003",
    "Title": "Tier-0 Roles With Long Activation Duration (>4 Hours)",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-004",
    "Title": "Tier-0 Roles Which Do Not Require Justification on Activation",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-005",
    "Title": "Tier-0 Roles Allow Permanent Active Assignments",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-006",
    "Title": "Tier-0 Roles Without Justification on Active Assignments",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-007",
    "Title": "Tier-0 Roles Without MFA on Active Assignments",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-008",
    "Title": "Tier-0 Roles Without Notification",
    "Category": "PIM",
    "Severity": 1,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Requires Verification",
    "AffectedObjects": []
  },
  {
    "FindingId": "PIM-009",
    "Title": "Tier-0 Roles Without Authentication Context or Approval",
    "Category": "PIM",
    "Severity": 2,
    "Description": "",
    "Threat": "",
    "Status": "NotVulnerable",
    "Remediation": "",
    "Confidence": "Sure",
    "AffectedObjects": []
  }
]
'@

    # Build runtime objects from static finding definitions.
    $Findings = $FindingsJson | ConvertFrom-Json
    $FindingsById = @{}
    foreach ($finding in $Findings) { $FindingsById[$finding.FindingId] = $finding }


    # Default baseline: hidden by default unless a check marks vulnerable.
    foreach ($finding in $Findings) {
        $finding.Status = "NotVulnerable"
    }

    # Text variants for dynamic findings.
    # Enumeration logic selects one of these variants instead of duplicating prose.
    #region Variant Properties
    #region COL VariantProps
    $COL001VariantProps = @{
        Default = @{
            Remediation = '<p>The permissions for guest users should be limited. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>External Identities</strong></li><li>Select <strong>External collaboration settings</strong></li><li>Select <code>Guest user access is restricted to properties and memberships of their own directory objects</code></li></ol><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions</a></li></ul>'

        }
        Member = @{
            Status = "Vulnerable"
            Description = "<p>Guest users have the same permissions as internal users.</p>"
            Threat = "<p>Because guest users have the same permissions as internal users, they can:</p><ul><li>Read information about all users and groups</li><li>Read all device properties, including operating system details and last sign-in time</li><li>Create Microsoft 365 and security groups, if allowed for internal users</li><li>Register new applications, if allowed for internal users</li><li>Read properties of registered and enterprise applications</li><li>Read Entra ID roles and role assignments</li></ul>"

        }
        Limited = @{
            Status = "Vulnerable"
            Description = "<p>Guest users have limited access to the properties and memberships of directory objects (default setting).</p>"
            Threat = "<p>With the default guest permissions, guest users can access internal information such as:</p><ul><li>Properties of non-hidden groups, including membership and ownership, even for groups they have not joined</li><li>Properties of users</li><li>Permissions granted to applications</li></ul>"
            Severity = 1
        }
        Restricted = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Guest users are restricted to the properties and memberships of their own directory objects (most restrictive).</p>"
            Threat = "<p>Depending on the configured guest permission, guest users can access internal information various information.</p>"


        }
    }
    $COL002VariantProps = @{
        Default = @{
            Threat = "<p>There is no control over which guest users are onboarded. Depending on other guest access settings, guest users may gain access to internal Entra ID information such as details about users, groups, and devices.</p>"
            Remediation = '<p>Restrict which users can invite guest users. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>External Identities</strong></li><li>Select <strong>External collaboration settings</strong></li><li>Set <code>Guest invite restriction</code> to <code>Only users assigned to specific admin roles can invite guest users</code></li></ol> <p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure</a></li></ul>'


        }
        Everyone = @{
            Status = "Vulnerable"
            Description = "<p>Regular users and existing guest users can invite new guest users.</p>"
        }
        AdminsGuestInvitersAndAllMembers = @{
            Status = "Vulnerable"
            Description = "<p>All internal users can invite guest users.</p>"
        }
        AdminsAndGuestInviters = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Only users assigned to specific administrative roles can invite guest users.</p>"

        }
        None = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>No one in the organization, including administrators, can invite guest users (most restrictive).</p>"

        }
    }
    $COL003VariantProps = @{
        Default = @{
            Threat = '<p>Guest users owning Microsoft 365 groups introduce additional risk because external identities can influence membership and have access to data stored in SharePoint, Exchange, and Microsoft Teams associated with the group. A compromised guest account may be used to expose sensitive content, or maintain unauthorized access to internal resources.</p>'
            Remediation = '<p>Disable the possibility for guests owning M365 groups. Use the MS Graph API or PowerShell module to change the setting <code>AllowGuestsToBeGroupOwner</code> to <code>false</code>, which is the default in new tenants.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/graph/group-directory-settings" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/graph/group-directory-settings</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Description = "<p>Guest users are allowed to own Microsoft 365 groups.</p><p><strong>Note:</strong> This is not the default configuration.</p>"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Guest users cannot own Microsoft 365 groups.</p><p>This is the default configuration.</p>"
        }
    }
    #endregion
    #region PAS VariantProps
    $PAS001VariantProps = @{
        Default = @{
            Threat = '<p>Attackers may be able to guess valid user passwords through password spraying attacks. These attacks often use commonly used passwords or customized wordlists tailored to the target organization (for example, including the company name or product names).</p>'
            Remediation = '<p>Use the custom banned password list to prevent users from choosing weak or predictable passwords. Define terms that should not be allowed in passwords, such as the company name, product names, or commonly used internal terminology. After adding entries to the custom banned password list, the Entra password protection algorithm automatically blocks weak variants and similar combinations.</p><p>In hybrid environments, consider deploying Entra password protection on-premises (requires the password protection agent). This ensures that custom banned passwords and the global banned password list are also enforced during on-premises password changes.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#custom-banned-password-list" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#custom-banned-password-list</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Description = "<p>The custom banned password list is not enabled.</p>"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>The custom banned password list is enabled.</p>"
        }
    }
    $PAS002VariantProps = @{
        Default = @{
            Threat = '<p>If only a small number of entries are defined in the custom banned password list, its effectiveness is reduced. Attackers may still be able to guess commonly used or organization-specific passwords.</p>'
            Remediation = '<p>Expand the custom banned password list with organization-specific terms to improve password protection. Include variations of the company name, product names, internal project names, locations, and commonly used words that users might include in passwords.</p><p>Regularly review and update the list based on observed password trends or the introduction of new products or organization-specific terminology.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#custom-banned-password-list" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#custom-banned-password-list</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{ Status = "NotVulnerable" }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because the custom banned password list is not enabled (see <a href=`"#PAS-001`">PAS-001</a>).</p>"
        }
    }
    $PAS003VariantProps = @{
        Default = @{
            Threat = '<p>If Entra password protection is not enforced on on-premises domain controllers, global and custom banned password lists are not applied during on-premises password changes. As a result, weak or predictable passwords may still be synchronized to the cloud, reducing the overall effectiveness of password protection.</p>'
            Remediation = '<p>If identities are synchronized from on-premises Active Directory, consider extending Entra password protection to the on-premises environment. This ensures that both the global and custom banned password lists are enforced during on-premises password changes.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Description = "<p>Entra password protection is not enforced for the on-premises environment.</p>"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Entra password protection is enabled for the on-premises environment.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because the custom banned password list is not enabled (see <a href=`"#PAS-001`">PAS-001</a>).</p>"
            AffectedObjects = @()
        }
    }
    $PAS004VariantProps = @{
        Default = @{
            Threat = '<p>A high lockout threshold combined with a short lockout duration allows attackers to attempt a large number of password guesses within a short time frame, increasing the likelihood of identifying valid credentials through password spraying or brute-force attacks.</p>'
            Remediation = '<p>Consider lowering the lockout threshold and increasing the lockout duration to reduce the effectiveness of password guessing attacks. Microsoft default values are a lockout threshold of 10 and a lockout duration of 60 seconds.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{ Status = "NotVulnerable" }
    }
    $PAS005VariantProps = @{
        Default = @{
            Threat = '<p>If attackers obtain access to two configured authentication methods (for example, a lost device providing access to both email and SMS without additional protection), they may be able to reset the password of an administrator account without knowing the existing password.</p>'
            Remediation = '<p>Disable the use of Self-Service Password Reset (SSPR) for administrator accounts using the Microsoft Graph PowerShell module:</p><pre><code>Connect-MgGraph -Scopes Policy.ReadWrite.Authorization
Update-MgPolicyAuthorizationPolicy -AllowedToUseSspr:$false</code></pre><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy?tabs=ms-powershell#administrator-reset-policy-differences" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy?tabs=ms-powershell#administrator-reset-policy-differences</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{ Status = "NotVulnerable" }
    }
    #endregion
    #region USR VariantProps
    $USR001VariantProps = @{
        Default = @{
            Description = "<p>Regular users can register new applications in the tenant.</p>"
            Threat = "<p>An attacker can register a malicious application and distribute it to users through phishing or other social engineering techniques. If users are permitted to consent to applications, the malicious app may obtain extensive permissions, enabling access to Microsoft 365 data and other sensitive resources.</p>"
            Remediation = '<p>Restrict application registration in Entra ID to administrators only. Configure the following setting in the Entra admin portal:</p><ol><li>Users</li><li>User settings</li><li>Set <code>Users can register applications</code> to <code>No</code></li></ol><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot register applications.</p>"
        }
    }
    $USR002VariantProps = @{
        Default = @{
            Description = "<p>Non-admin users can create new tenants and automatically become Global Administrators in those tenants.</p>"
            Threat = "<p>Unauthorized tenant creation can lead to the proliferation of shadow IT environments and introduces the following risks:</p><ul><li>Loss of control over IT environments as users create disjointed and unmanaged tenants.</li><li>Compromised data security due to a lack of centralized oversight.</li><li>Unclear security ownership, as users may incorrectly assume security controls are in place.</li></ul><p>Note: Newly created tenants do not inherit settings or configurations from the existing tenant.</p>"
            Remediation = '<p>Restrict tenant creation to administrators. Configure the following setting in the Entra admin portal:</p><ol><li>Users</li><li>User settings</li><li>Set <code>Restrict non-admin users from creating tenants</code> to <code>Yes</code></li></ol><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/azure/active-directory-b2c/tenant-management-check-tenant-creation-permission" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/azure/active-directory-b2c/tenant-management-check-tenant-creation-permission</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot create new tenants.</p>"
        }
    }
    $USR003VariantProps = @{
        Default = @{
            Description = "<p>Users can read BitLocker recovery keys for devices they own.</p>"
            Threat = "<p>An attacker who compromises an Entra ID account may obtain the recovery key and fully decrypt the device after gaining physical access. This also increases insider risk, as recovery keys may be misused or stored insecurely outside organizational control.</p>"
            Remediation = '<p>Configure the following setting in the Entra admin portal:</p><ol><li>Devices</li><li>Device settings</li><li>Set <code>Restrict users from recovering the BitLocker key(s) for their owned devices</code> to <code>Yes</code></li></ol><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions</a></li></ul>'

        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot read BitLocker recovery keys for devices they own.</p>"

        }
    }
    $USR004VariantProps = @{
        Default = @{
            Threat = "<p>An attacker can register an application in Entra ID that requests access to data such as contact information, email, or documents. The attacker may then trick a user into granting consent, for example through a phishing attack or by injecting malicious code into a trusted website. Once consent is granted, the malicious application gains access to the user's data without requiring an organizational account.</p>"
            Remediation = '<p>Restrict application consent to administrators only. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>Enterprise Applications</strong></li><li>Select <strong>Consent and permissions</strong></li><li>Select <code>Do not allow user consent</code></li></ol><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies</a></li></ul>'

        }
        MicrosoftManaged = @{
            Status = "Vulnerable"
            Description = "<p>Users can consent to all scopes allowed by Microsoft. While some critical scopes are blocked, Microsoft still allows consent to extensive permissions such as:</p><ul><li>Full access to user contacts (Contacts.ReadWrite)</li><li>Read access to user devices (Device.Read)</li><li>Full access to user files (Files.ReadWrite)</li><li>Read and write access to all OneNote notebooks the user can access (Notes.ReadWrite.All)</li></ul>"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot consent to applications.</p>"
        }
        # Description is composed dynamically from enumerated permissions.
        LowExtensive = @{ Status = "Vulnerable" }
        # Description is composed dynamically; this variant keeps shared defaults.
        LowSpecific = @{
            Status = "Vulnerable"
            Severity = 0
            Threat = "<p>If attackers gain control over an application with consented permissions, they may leverage even limited access to facilitate further attacks.</p>"
            Remediation = '<p>Consider restricting application consent to administrators only. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>Enterprise Applications</strong></li><li>Select <strong>Consent and permissions</strong></li><li>Select <code>Do not allow user consent</code></li></ol><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies</a></li></ul>'
            
            Confidence = "Requires Verification"
        }
    }
    $USR005VariantProps = @{
        Default = @{
            Threat = '<p>Unused or unnecessary user accounts increase the attack surface and may provide attackers with additional entry points. In cloud environments, this risk is amplified because identities are inherently exposed to internet-based authentication attempts such as password spraying or credential stuffing.</p>'
            Remediation = '<p>Disable or remove inactive accounts whenever possible.</p><p>Additionally, review whether unnecessary accounts are synchronized to the cloud (for example, users who do not require cloud services or on-prem service accounts).</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        VulnerableWithGuests = @{
            Threat = '<p>Unused or unnecessary user accounts increase the attack surface and may provide attackers with additional entry points. In cloud environments, this risk is amplified because identities are inherently exposed to internet-based authentication attempts such as password spraying or credential stuffing.</p><p>This also applies to guest accounts, which are often subject to fewer Conditional Access restrictions (for example, IP-based controls or compliant/joined device requirements). Although guest accounts typically have fewer privileges and the setting <code>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</code> may be enabled, guests may still enumerate certain tenant information, such as properties of enterprise applications and assigned permissions, which can support reconnaissance and enable further attacks.</p>'
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No inactive users were identified.</p>"
        }
    }
    $USR006VariantProps = @{
        Default = @{
            Threat = '<p>A large number of Tier-0 role assignments increases the likelihood of a highly privileged identity being compromised. Since these roles allow direct or indirect control over authentication, role management, and Conditional Access policies, a single compromised account will lead to tenant-wide privilege escalation or full takeover.</p>'
            Remediation = '<p>Reduce Tier-0 role assignments to the minimum required and grant access strictly according to the least-privilege principle. For example, if a user is primarily responsible for Microsoft Teams administration, use the <code>Teams Administrator</code> role instead of <code>Global Administrator</code> to reduce the impact of credential compromise.</p><p>Microsoft recommends maintaining:</p><ul><li>Fewer than five Global Administrators</li><li>Fewer than ten privileged role assignments</li></ul><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Fewer than 5 users with Tier-0 Entra ID roles were identified.</p>"
        }
    }
    $USR007VariantProps = @{
        Default = @{
            Threat = '<p>If attackers compromise such an account in the on-premises environment, they may be able to pivot into the cloud with privileged access. This enables lateral movement across hybrid identities and can lead to full tenant compromise.</p><p>This technique is actively abused by multiple threat actors. For example, Microsoft has documented a campaign by Storm-0501 abusing such hybrid users: <a href="https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/" target="_blank" rel="noopener noreferrer">https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/</a></p>'
            Remediation = '<p>Use dedicated cloud-only accounts (not synchronized from on-premises Active Directory) for highly privileged cloud roles to reduce the risk of hybrid identity compromise.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No hybrid users with Tier-0 Entra ID roles were identified.</p>"
        }
    }
    $USR008VariantProps = @{
        Default = @{
            Threat = '<p>If attackers compromise such an account in the on-premises environment, they may be able to pivot into the cloud and obtain privileged access to Azure resources, potentially leading to lateral movement and further escalation.</p>'
            Remediation = '<p>Use dedicated cloud-only accounts (not synchronized from on-premises Active Directory) for highly privileged roles scoped to critical Azure resources (example Owner of the PROD Subscription).</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No hybrid users with Tier-0 Azure roles were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because Azure role assignments were not enumerated.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $USR009VariantProps = @{
        Default = @{
            Threat = '<p>A large number of Tier-0 role assignments increases the likelihood of a highly privileged identity being compromised. Because these roles grant direct privileged access to scoped resources, attackers may be able to access sensitive information or leverage secrets and service principals to further escalate their privileges.</p>'
            Remediation = '<p>Reduce Tier-0 role assignments to the minimum required and grant access strictly according to the least-privilege principle. Avoid assigning broad privileged roles when more specific job-function roles can be used. For example, if a user primarily manages virtual machines, use the <code>Virtual Machine Contributor</code> role instead of <code>Contributor</code> to reduce the impact of credential compromise. Additionally, use the narrowest possible scope (for example, resource group or individual resource) instead of broader scopes such as management group or subscription.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices#limit-privileged-administrator-role-assignments" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices#limit-privileged-administrator-role-assignments</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Fewer than 8 users with Tier-0 Azure roles were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because Azure role assignments were not enumerated.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $USR010VariantProps = @{
        Default = @{
            Threat = "<p>Various Tier-1 roles (for example, Authentication Administrator, Helpdesk Administrator, or User Administrator) and applications with permissions such as <code>UserAuthenticationMethod.ReadWrite.All</code> or <code>User-PasswordProfile.ReadWrite.All</code> can reset an unprotected user's password and/or MFA factor. An attacker with one of these roles or control over such an application may therefore be able to compromise an unprotected user and use the associated privileges.</p>"
            Remediation = '<p>Protect highly privileged users.</p><p>Consider the following hardening measures:</p><ul><li>Add the group to a Restricted Management Administrative Unit and assign scoped administrative roles only to dedicated administrators. This limits who can modify group membership.</li><li>Alternatively, add the user to a <code>role-assignable</code> group, even if no roles are currently assigned. This ensures that only privileged roles or group owners can modify authentication methods of active members.</li></ul><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected</a></li><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No users with Tier-0 Entra ID roles were identified that are not protected against modifications by lower-tier administrators or applications.</p>"
        }
    }
    $USR011VariantProps = @{
        Default = @{
            Threat = "<p>Various Tier-1 roles (for example, Authentication Administrator, Helpdesk Administrator, or User Administrator) and applications with permissions such as <code>UserAuthenticationMethod.ReadWrite.All</code> or <code>User-PasswordProfile.ReadWrite.All</code> can reset an unprotected user's password and/or MFA factor. An attacker with one of these roles or control over such an application may therefore be able to compromise an unprotected user and use the associated privileges.</p>"
            Remediation = '<p>Protect highly privileged users with broad access on Azure (e.g., owner of the PROD management group).</p><p>Consider the following hardening measures:</p><ul><li>Add the group to a Restricted Management Administrative Unit and assign scoped administrative roles only to dedicated administrators. This limits who can modify group membership.</li><li>Alternatively, add the user to a <code>role-assignable</code> group, even if no roles are currently assigned. This ensures that only privileged roles or group owners can modify authentication methods of active members.</li></ul><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected</a></li><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No users with Tier-0 Azure roles were identified that are not protected against modifications by lower-tier administrators or applications.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because Azure role assignments were not enumerated.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $USR012VariantProps = @{
        Default = @{
            Threat = '<p>Accounts without a registered MFA factor can be an indicator of missing MFA enforcement or that unnecessary accounts are synced to Entra ID.</p>'
            Remediation = '<p>Review why these users do not have any MFA methods registered and verify whether MFA enrollment and enforcement are configured correctly, and whether these users are required to exist in Entra ID.</p>'
        }
        VulnerableCapIssues = @{
            Status = "Vulnerable"
            Severity = 3
            Confidence = "Requires Verification"
            Threat = '<p>Since there are issues with the Conditional Access policy that manages the registration of security information, attackers who compromise a user''s password (for example, through password spraying or credential stuffing) may be able to register a new MFA factor. Because no policy limits this process, attackers could add their own authentication method and subsequently sign in to the account, unless sign-in is blocked by another policy.</p><p>Furthermore, accounts without a registered MFA factor can be an indicator of missing MFA enforcement or that unnecessary accounts are synced to Entra ID.</p>'
            Remediation = '<p>Ensure that attackers cannot register MFA methods for these users (see the recommendations in finding <a href="#CAP-002">CAP-002</a>, if applicable).</p><p>Additionally, review why these users do not have any MFA methods registered and verify whether MFA enrollment and enforcement are configured correctly, and whether these users are required to exist in Entra ID.</p>'
        }
        VulnerableCapSecure = @{
            Status = "Vulnerable"
            Severity = 2
            Confidence = "Sure"
            Threat = '<p>Accounts without a registered MFA factor can be an indicator of missing MFA enforcement or that unnecessary accounts are synced to Entra ID.</p>'
            Remediation = '<p>Review why these users do not have any MFA methods registered and verify whether MFA enrollment and enforcement are configured correctly, and whether these users are required to exist in Entra ID.</p>'
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled users without MFA capability were identified.</p>"
        }
    }
    $USR013VariantProps = @{
        Default = @{
            Threat = '<p>Synchronizing accounts to Entra ID exposes them to internet-facing authentication attacks such as password spraying.</p><p>Even if these accounts are not actively used in the cloud, they still increase the externally reachable attack surface. If one of these accounts is protected by a weak or reused password, attackers may be able to compromise it through cloud-based login attempts without first needing access to the internal network.</p>'
            Remediation = '<p>Review the affected accounts. If no legitimate cloud-related use case exists, these accounts should be excluded from synchronization. In general, only accounts that require access to Microsoft 365, Azure, or other Entra ID-integrated services should be synchronized to Entra ID.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Fewer than 5 enabled synchronized on-premises accounts older than 90 days were identified that never signed in to Entra ID.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because the current permissions or license do not allow retrieval of users SignInActivity properties. The usage of synchronized on-premises accounts in Entra ID could not be evaluated.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    #endregion
    #region GRP VariantProps
    $GRP001VariantProps = @{
        Default = @{
            Description = "Standard users can create security groups via the admin portal or APIs."
            Threat = "<p>Attackers can use APIs such as Microsoft Graph to create security groups with the same name as existing groups. If an administrator mistakenly authorizes such a group for a critical resource, the attackers may gain unauthorized access.</p>"
            Remediation = '<p>The creation of security groups should be restricted to administrators only. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>Groups</strong></li><li>Select <strong>General</strong></li><li>Set <code>Users can create security groups in Azure portals, API or PowerShell</code> to <code>No</code></li></ol><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot create security groups.</p>"
        }
    }
    $GRP002VariantProps = @{
        Default = @{
            Description = "Standard users can create M365 groups using the Management Portals or an API."
            Threat = "<p>Microsoft 365 groups can provide access to potentially sensitive data stored in SharePoint sites, group mailboxes, and Microsoft Teams channels.</p><p>Untrained users may create Microsoft 365 groups as public groups, allowing other internal users to join and gain access to sensitive information.</p>"
            Remediation = '<p>Ideally, M365 groups should only be created by administrators or trained personnel. Configure the following setting in the Entra admin portal:</p><ol><li>Select <strong>Groups</strong></li><li>Select <strong>General</strong></li><li>Set <code>Users can create Microsoft 365 groups in Azure portals, API or PowerShell</code> to <code>No</code></li></ol><p>Important: If the creation of Microsoft 365 groups is restricted, standard users will not be able to:</p><ul><li>Create new teams in MS Teams</li><li>Create new SharePoint sites</li><li>Create new mailboxes</li></ul><p>If self-service M365 group creation is required, enabling automatic expiration for unused groups is a useful way to help control and reduce the number of Microsoft 365 groups.</p><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/users/groups-lifecycle" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/users/groups-lifecycle</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>Secure configuration in place:<br>Users cannot create Microsoft 365 groups via the Azure portal, APIs, or PowerShell.</p>"
        }
    }
    $GRP003VariantProps = @{
        Default = @{
            Threat = '<p>Any user in the tenant can add themselves as a member of the group without owner approval. This may grant unauthorized access to sensitive data stored in SharePoint, OneDrive, shared mailboxes, Microsoft Teams channels or apps.</p><p>If the group is security-enabled, it may also be used to manage access to additional resources (for example, Power Apps or Azure subscriptions), increasing the risk of privilege escalation and unintended access.</p>'
            Remediation = '<p>Review whether the affected groups should be converted to private groups. Since Microsoft 365 does not support restricting group creation to private groups only, consider limiting the creation of Microsoft 365 groups to administrators or specifically trained users (see check GRP-002).</p><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#group-settings" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#group-settings</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No public Microsoft 365 groups were identified.</p>"
        }
    }
    $GRP004VariantProps = @{
        Default = @{
            Threat = '<p>If attributes which can be influenced by users are used in an unsafe way in dynamic group membership rules, users may be potentially able to grant themselves access to the group.</p><p>The following user properties can be modified by users through the Microsoft Graph API:</p><ul><li>businessPhones</li><li>mobilePhone</li><li>preferredLanguage</li></ul>'
            Remediation = '<p>Dynamic membership rules should avoid using attributes that can be influenced by standard users.</p><p>Identities that can invite guest users may manipulate the following attributes:</p><ul><li>userPrincipalName</li><li>mail</li></ul><p>Additionally, the following attributes can be modified by users through the Microsoft Graph API:</p><ul><li>businessPhones</li><li>mobilePhone</li><li>preferredLanguage</li></ul><p>It is recommended to avoid using these attributes in dynamic queries, or only use them in combination with additional trusted attributes. Moreover, prefer strict operators such as <code>endsWith</code> and avoid broad matching operators like <code>match</code> or <code>contains</code>.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership#supported-expression-operators" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership#supported-expression-operators</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No dynamic groups with potentially dangerous membership rules were identified.</p>"
        }
        InviteEveryone = @{
            Threat = '<p>Identities that can invite guest users may be able to manipulate properties such as UPN or email attributes and invite guest accounts they control, potentially granting themselves access to the group.</p><p>Furthermore, the following user properties can be modified through the Microsoft Graph API:</p><ul><li>businessPhones</li><li>mobilePhone</li><li>preferredLanguage</li></ul><p><strong>Note:</strong> Because all users, including existing guest users, can invite additional guests, dynamic membership rules that rely on UPN or email attributes may also be abused by guest users to gain unauthorized access.</p>'
        }
        InviteAdminsGuestInvitersAndAllMembers = @{
            Threat = '<p>Identities that can invite guest users may be able to manipulate properties such as UPN or email attributes and invite guest accounts they control, potentially granting themselves access to the group.</p><p>Furthermore, the following user properties can be modified through the Microsoft Graph API:</p><ul><li>businessPhones</li><li>mobilePhone</li><li>preferredLanguage</li></ul><p><strong>Note:</strong> Since guest invitations are restricted to internal users, only internal identities could abuse dynamic membership rules that rely on UPN or email attributes.</p>'
        }
        InviteAdminsAndGuestInviters = @{
            Threat = '<p>Identities that can invite guest users may be able to manipulate properties such as UPN or email attributes and invite guest accounts they control, potentially granting themselves access to the group.</p><p>Furthermore, the following user properties can be modified through the Microsoft Graph API:</p><ul><li>businessPhones</li><li>mobilePhone</li><li>preferredLanguage</li></ul><p><strong>Note:</strong> Because guest invitations are restricted to users with the Guest Inviter role, only these identities could abuse dynamic membership rules that rely on UPN or email attributes.</p>'
        }
    }
    $GRP005VariantProps = @{
        Default = @{
            Threat = '<p>Various roles (for example, Knowledge Manager, Groups Administrator, or User Administrator) and applications with permissions such as <code>Group.ReadWrite.All</code> can manage the membership of these groups. Additionally, several administrative roles can reset credentials or MFA methods for users who are active members of the group (for example, Authentication Administrator, Helpdesk Administrator, or User Administrator). An attacker with one of these roles may therefore add themselves or another account to a highly privileged group.</p><p>An attacker might be able to:</p><ul><li>Exclude accounts from Conditional Access if exclusions rely on an unprotected group.</li><li>Gain elevated Entra ID privileges if unprotected groups are eligible members of groups with Entra ID roles (PIM for Groups).</li><li>Obtain elevated privileges on Azure resources.</li></ul>'
            Remediation = '<p>Protect sensitive groups (for example, Tier-0 Azure role assignments or groups used in Conditional Access policies).</p><p>Consider the following hardening measures:</p><ul><li>Add the group to a Restricted Management Administrative Unit and assign scoped administrative roles only to dedicated administrators. This limits who can modify group membership.</li><li>Alternatively, recreate the group as a <code>role-assignable</code> group, even if no roles are currently assigned. This ensures that only privileged roles or group owners can manage membership and modify authentication methods of active members.</li></ul><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept#how-are-role-assignable-groups-protected</a></li><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups#what-are-entra-id-role-assignable-groups</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No unprotected groups with sensitive permissions detected.</p>"
        }
    }
    #endregion
    #region CAP VariantProps
    # CAP-001
    $CAP001VariantProps = @{
        Default = @{
            Threat = '<p>Device code flow is an authentication method that can be abused as part of phishing attacks. In this scenario, an attacker initiates a device code flow and sends the victim a legitimate-looking link together with a device code. If the victim enters the code on the official website, the attacker is authenticated on behalf of the victim and gains access to the tenant.</p><p>This technique is actively abused by multiple threat actors. Microsoft has documented a recent campaign (Storm-2372) using this method: <a href="https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/" target="_blank" rel="noopener noreferrer">https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/</a></p>'
            Remediation = '<p>Create a Conditional Access policy to block the device code flow for all users. If this authentication method is required, configure appropriate exceptions for affected accounts.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy blocks the device code flow without any detected issues.</p>"
        }
    }
    # CAP-002
    $CAP002VariantProps = @{
        Default = @{
            Threat = "<p>Attackers might be able to compromise the first factor (password), for example, through password spraying or credential stuffing. If an attacker successfully compromises the first factor, they will be prompted to add a new MFA factor. Since there is no Conditional Access policy restricting the registration of new security information, the attacker can add their own MFA factor and might be able to sign in to the account (if sign-in is not blocked by another policy).</p>"
            Remediation = '<p>Create a Conditional Access policy to restrict under which conditions users can register security information.</p><p>Recommended configuration:</p><ul><li>Require MFA and provide users with a Temporary Access Pass (TAP) to register a new authentication method or reset their password.</li><li>Alternatively, restrict registration to trusted locations and/or require a compliant or managed device.</li></ul><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy manages the registration of security information without any detected issues.</p>"
        }
    }
    # CAP-003
    $CAP003VariantProps = @{
        Default = @{
            Threat = "<p>Legacy authentication does not support multifactor authentication (MFA). Therefore, attackers may attempt to compromise an account using credential stuffing or password spraying attacks.</p>"
            Remediation = '<p>Create a Conditional Access policy to block legacy authentication.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy blocks legacy authentication without any detected issues.</p>"
        }
    }
    # CAP-004
    $CAP004VariantProps = @{
        Default = @{
            Threat = "<p>Standard Conditional Access policies that enforce MFA do not apply during device registration or join operations. Attackers who obtain valid credentials can exploit the absence of MFA to register rogue devices, potentially bypassing security controls and establishing persistence.</p>"
            Remediation = '<p>Enforce MFA when users join or register devices using a Conditional Access policy.</p><p>This Conditional Access policy applies only when users add or register devices in Microsoft Entra ID. Hybrid-joined devices are configured via Entra Connect Sync and do not require MFA during the join process. The policy should still be enabled to prevent attackers from registering devices without MFA.</p><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#require-multifactor-authentication-for-device-join-and-device-registration-using-user-action" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#require-multifactor-authentication-for-device-join-and-device-registration-using-user-action</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration</a></li><li><a href="https://learn.microsoft.com/en-au/answers/questions/1857331/conditional-access-user-action-register-or-join-de" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-au/answers/questions/1857331/conditional-access-user-action-register-or-join-de</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy manages joining or registering devices without any detected issues.</p>"
        }
    }
    # CAP-005
    $CAP005VariantProps = @{
        Default = @{
            Threat = "<p>Modern phishing attacks can bypass traditional MFA methods, reducing their effectiveness against advanced threats. As a result, even accounts protected by MFA may remain vulnerable, especially privileged accounts.</p><p>If compromised, these accounts could be abused by attackers to gain broad access to cloud resources, escalate privileges, or move laterally across the environment unless additional protections are in place.</p>"
            Remediation = '<p>At least sensitive and highly privileged accounts should be protected with phishing-resistant MFA.</p><p>To enforce this, a Conditional Access policy should be implemented that targets all critical accounts and requires an authentication strength configured for phishing-resistant methods.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#privileged-users-sign-in-with-phishing-resistant-methods" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#privileged-users-sign-in-with-phishing-resistant-methods</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy enforces phishing-resistant MFA without any detected issues.</p>"
        }
    }
    # CAP-006
    $CAP006VariantProps = @{
        Default = @{
            Threat = "<p>Conditions within Conditional Access policies are evaluated using a logical AND. As a result, the policy is only applied when all configured conditions are met, which renders the policy ineffective.</p>"
            Remediation = '<p>Create separate Conditional Access policies for high-risk users and high-risk sign-ins.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No Conditional Access policy combines user risk and sign-in risk in the same policy.</p>"
        }
    }
    # CAP-007
    $CAP007VariantProps = @{
        Default = @{
            Threat = "<p>Without enforcing Conditional Access policies that address sign-in risk, risky sign-ins may be detected but no automatic action (such as blocking access or triggering self-remediation) is enforced. This can delay response and investigation, allowing attackers to continue abusing a compromised account.</p>"
            Remediation = '<p>At a minimum, VIPs (for example, C-level executives) and highly privileged users (for example, Global Administrators) should be protected using Conditional Access policies that address at least medium and high sign-in risk. This requires a Microsoft Entra ID P2 license for each user covered by the policy.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy managing sign-in risk without any detected issues.</p>"
        }
    }
    # CAP-008
    $CAP008VariantProps = @{
        Default = @{
            Threat = "<p>Without enforcing Conditional Access policies that address user risk, risky users may be detected but no automatic action (such as blocking access or triggering self-remediation) is enforced. This can delay response and investigation, allowing attackers to continue abusing a compromised account.</p>"
            Remediation = '<p>At a minimum, VIPs (for example, C-level executives) and highly privileged users (for example, Global Administrators) should be protected using Conditional Access policies that address at least medium and high user risk. This requires a Microsoft Entra ID P2 license for each user covered by the policy.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk-user" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk-user</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy managing user risk without any detected issues.</p>"
        }
    }
    # CAP-009
    $CAP009VariantProps = @{
        Default = @{
            Threat = "<p>Passwords alone provide insufficient protection against modern threats for several reasons:</p><ul><li>Users may choose weak or easily guessable passwords and reuse them across multiple services.</li><li>Passwords can be exposed through data breaches.</li><li>Passwords can be captured through phishing attacks.</li><li>Passwords may be guessed through password-spraying attacks.</li></ul><p>If credentials are compromised and no additional protections are enforced, attackers may gain access to cloud resources.</p>"
            Remediation = '<p>Implement Conditional Access policies that require multifactor authentication (MFA) for all users and administrators. As a secure baseline, the policy should target all users and all cloud applications, with only well-justified exclusions.</p><p>General guidance:</p><ul><li>Create a baseline policy requiring MFA for all users.</li><li>Implement a separate, stricter policy for privileged roles and administrators.</li><li>Regularly review exclusions and emergency access accounts.</li></ul><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>At least one Conditional Access policy enforcing basic MFA without any detected issues.</p>"
        }
    }
    # CAP-010
    $CAP010VariantProps = @{
        Default = @{
            Threat = "<p>As a result, certain privileged users may authenticate without the intended Conditional Access protections (for example, MFA, device requirements, or network restrictions). If one of these accounts is compromised, attackers might obtain elevated privileges without being subject to the same security controls applied to other administrators.</p>"
            Remediation = '<p>Verify whether the policy still achieves its intended protection if these roles are not included. Review the roles that are currently excluded and assess whether users with these assignments should also be subject to the Conditional Access controls.</p><p>If necessary, extend the policy to include the missing Tier-0 or Tier-1 roles to ensure that all highly privileged accounts are consistently protected.</p>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled Conditional Access policy targeting five or more roles was identified with missing used roles.</p>"
        }
    }
    # CAP-011
    $CAP011VariantProps = @{
        Default = @{
            Threat = "<p>As a result, certain privileged users may authenticate without the intended Conditional Access protections (for example, MFA, device requirements, or network restrictions). If one of these accounts is compromised, attackers might obtain elevated privileges without being subject to the same security controls applied to other administrators.</p>"
            Remediation = '<p>Verify whether the policy still achieves its intended protection if these scoped role assignments are not included in the scope. Review the roles that are currently excluded and assess whether users with these assignments should also be subject to the Conditional Access controls.</p><p>If necessary, extend the policy to include the missing users directly or through a group.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups#include-users" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups#include-users</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Confidence = "Requires Verification"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled Conditional Access policies were identified that target roles with scoped assignments.</p>"
        }
    }
    #endregion
    #region ENT VariantProps
    $ENT001VariantProps = @{
        Default = @{
        Threat = "<p>Credentials directly assigned to enterprise applications are not visible in the Entra ID portal and are therefore harder to detect and manage. Attackers can abuse this to establish persistent access to the environment.</p>"
        Remediation = "<p>Verify whether the credentials are known and required. For internal applications, it is recommended to move the credentials to the corresponding app registration.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled enterprise applications were identified that are not configured for SAML and have at least one client credential.</p>"
        }
    }
    $ENT002VariantProps = @{
        Default = @{
            Threat = "<p>Inactive enterprise applications increase the attack surface, particularly when they are externally controlled (foreign service principals). If an external tenant is compromised or credentials are leaked, attackers may authenticate as the application within the tenant or obtain access to user tokens through the application.</p>"
            Remediation = '<p>Verify whether these applications are still required. Disable or remove applications that are no longer needed.</p><p>For internal applications, also delete the corresponding app registrations.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-apps" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-apps</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled inactive enterprise applications were identified.</p>"
        }
    }
    $ENT003VariantProps = @{
        Default = @{
            Threat = "<p>If attackers compromise the owner, they can add additional credentials to an application via the API if the app instance property lock is not configured properly. They can then authenticate as the application and perform actions for which the application is privileged.</p>"
            Remediation = "<p>Verify that application owners, especially for privileged enterprise applications (high impact score), are adequately protected. Standard user accounts should not be assigned ownership of highly privileged applications. If a user requires ownership of such applications, provision a dedicated administrative account. Secure this account with appropriate measures, such as phishing-resistant multi-factor authentication (e.g., FIDO2) and device requirements.</p><p>If the owner is a service principal, verify who can control that service principal. Foreign service principals should not own highly privileged applications.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled enterprise applications with directly assigned owners were identified.</p>"
        }
    }
    $ENT004VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of an application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its extensive API privileges. Conditional Access Policies do not apply to multi-tenant applications.</p>"
            Remediation = "<p>Highly privileged foreign access should be reviewed regularly and removed if not clearly required for the intended functionality.</p><p>If it is unclear whether assigned privileges are required, contact the application publisher to validate the permission model and confirm the expected usage of the application.</p><p>General guidance:</p><ul><li>API permissions should be limited to the absolute minimum required (for example, use <code>User.Read.All</code> instead of <code>User.ReadWrite.All</code>).</li><li>Where technically possible, the application should use <code>Delegated</code> permissions instead of <code>Application</code> permissions.</li></ul>"

        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign enterprise applications were identified that have extensive API privileges (as Application).</p>"
        }
    }
    $ENT005VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant is compromised, or if permissions are consented to a malicious application, attackers gain access to a user's access token as soon as the user authenticates with the compromised application.<br><br>Using this access token, attackers can abuse the consented permissions to perform malicious actions on behalf of the user, inheriting the user's identity and privileges. If attackers also obtain the refresh token (permission <code>offline_access</code>), they may be able to maintain persistent unauthorized access.</p>"
            Remediation = "<p>Review each application to determine whether access to the corresponding data is acceptable. Remove the permission or the application if the access is not justified.</p><p>If the justification is unclear, contact the application publisher to validate the required permissions and confirm the expected usage of the application.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign enterprise applications were identified that have extensive delegated API privileges.</p>"
        }
    }
    $ENT006VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of an enterprise application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its privileges. Conditional Access Policies do not apply to multi-tenant applications.</p>"
            Remediation = "<p>Restrict foreign applications to the minimum privileges required for their intended functionality. Regularly review assigned permissions and remove any that are not strictly necessary. Assess whether highly privileged foreign access to the tenant is justified and remove such access where it is not.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li></ul><p>If the justification is unclear, contact the application publisher to validate the required permissions and confirm the expected usage of the application.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign enterprise applications were identified that have Entra ID roles assigned.</p>"
        }
    }
    $ENT007VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of an enterprise application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its privileges. Conditional Access Policies do not apply to multi-tenant applications.</p>"
            Remediation = "<p>Restrict foreign applications to the minimum privileges required for their intended functionality. Regularly review assigned permissions and remove any that are not strictly necessary. Assess whether highly privileged foreign access to the tenant is justified and remove such access where it is not.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li></ul><p>If the justification is unclear, contact the application publisher to validate the required permissions and confirm the expected usage of the application.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign enterprise applications were identified that have Azure roles assigned.</p>"
        }
    }
    $ENT008VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of an enterprise application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its privileges. Conditional Access Policies do not apply to multi-tenant applications.</p>"
            Remediation = "<p>Restrict foreign applications to the minimum privileges required for their intended functionality. Regularly review assigned permissions and remove any that are not strictly necessary. Assess whether highly privileged foreign access to the tenant is justified and remove such access where it is not.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign enterprise applications owning objects were identified.</p>"
        }
    }
    $ENT009VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to an application secret (client secret or certificate), or if they are able to add their own, they can take control of the application. They can then authenticate in all tenants where the enterprise application exists and abuse its API privileges.</p>"
            Remediation = "<p>Review whether the applications require such high API privileges and remove any permissions that are not strictly necessary. Additionally, ensure that application credentials are managed securely.</p><p>General guidance:</p><ul><li>Limit API permissions to the absolute minimum required (for example, use <code>User.Read.All</code> instead of <code>User.ReadWrite.All</code>).</li><li>Where possible, use <code>Delegated</code> permissions instead of <code>Application</code> permissions.</li><li>Rotate client secrets regularly and remove unused credentials.</li><li>Prefer certificate-based authentication over client secrets.</li><li>Restrict who can add or modify application credentials.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal enterprise applications were identified that have extensive (dangerous or high) API privileges (as application).</p>"
        }
    }
    $ENT010VariantProps = @{
        Default = @{
            Threat = "<p>If attackers can manipulate the application, they might be able to obtain a user's access token as soon as the user authenticates with the compromised application.<br>Using this access token, attackers can abuse the consented permissions to perform malicious actions on behalf of the user, inheriting the user's identity and privileges. If attackers also obtain the refresh token (permission <code>offline_access</code>), they may be able to maintain persistent unauthorized access.</p>"
            Remediation = "<p>Review each application to determine whether access to the corresponding data is acceptable. Remove the permission or the application if the access is not justified.</p><p>General guidance:</p><ul><li>Limit API permissions to the absolute minimum required (for example, use <code>User.Read.All</code> instead of <code>User.ReadWrite.All</code>).</li><li>Restrict who can control the application.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal enterprise applications were identified that have extensive delegated API privileges.</p>"
        }
    }
    $ENT011VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to an application secret (client secret or certificate), or if they are able to add their own, they can take control of the application. They can then authenticate in all tenants where the enterprise application exists and abuse its privileges.</p>"
            Remediation = "<p>Review each application to determine whether access to the corresponding data is acceptable.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal enterprise applications were identified that have privileged Entra ID roles (tier-0 or tier-1) assigned.</p>"
        }
    }
    $ENT012VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to an application secret (client secret or certificate), or if they are able to add their own, they can take control of the application. They can then authenticate in all tenants where the enterprise application exists and abuse its privileges.</p>"
            Remediation = "<p>Review each application to determine whether access to the corresponding data is acceptable.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li></ul>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Confidence = "Requires Verification"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal enterprise applications were identified that have privileged Azure roles (tier-0 or tier-1) assigned.</p>"
        }
    }
    $ENT013VariantProps = @{
        Default = @{
            Threat = "<p>If the identified enterprise application is confirmed to be malicious and has been granted permissions in the tenant, attackers may be able to access sensitive Microsoft 365 or Entra ID resources, modify tenant configuration, or maintain persistence, depending on the assigned permissions.</p>"
            Remediation = "<p>Review the identified enterprise applications and the referenced source URLs. If the application is confirmed to be malicious, disable it immideatly, and conduct an investigation of related sign-in activity, consent events, credentials, and affected users.</p><p>To prevent similar incidents, normal users should not be allowed to add enterprise applications without review. A secure approval process should be established to ensure that third-party applications are thoroughly reviewed before they are added to the tenant.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
            Confidence = "Requires Verification"
        }
        Secure = @{
            Status = "NotVulnerable"
            Confidence = "Sure"
            Description = "<p>No enterprise applications were identified that match the list of known malicious applications.</p>"
        }
    }
    #endregion
    #region APP VariantProps
    $APP001VariantProps = @{
        Default = @{
            Threat = "<p>Client secrets are prone to accidental exposure through configuration files, scripts, or log files.</p><p>If an attacker obtains a client secret, they can authenticate as the application and perform any actions for which the application is authorized.</p>"
            Remediation = '<p>Replace client secrets with certificate-based authentication where possible. Microsoft recommends using certificates exclusively for applications running in production.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#applications-dont-have-secrets-configured" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/fundamentals/configure-security#applications-dont-have-secrets-configured</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No app registrations with secrets were identified.</p>"
        }
    }
    $APP002VariantProps = @{
        Default = @{
            Threat = "<p>If the app instance property lock is not configured properly, credentials can be added directly to enterprise applications. These credentials are not visible in the portal and may therefore remain undetected.</p><p>To add credentials, an attacker must gain ownership of the enterprise application or obtain an administrative role such as (Cloud) Application Administrator.</p>"
            Remediation = '<p>Enable the app instance property lock for all enterprise applications. Since March 2024, this setting is enabled by default for newly created applications.</p><p>To prevent credentials from being added to enterprise applications, configure at least the following settings:</p><ul><li>Enable property lock</li><li>Lock all properties</li></ul><p><strong>Note:</strong></p><ul><li>For multi-tenant applications used in other tenants, this setting also affects the corresponding enterprise application in those tenants.</li><li>Credentials that were added before the app instance property lock was enabled remain usable.</li></ul><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-app-instance-property-locks" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-app-instance-property-locks</a></li><li><a href="https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-instance-property-lock" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-instance-property-lock</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No app registrations without proper App Instance Property Lock were identified.</p>"
        }
    }
    $APP003VariantProps = @{
        Default = @{
            Threat = "<p>If attackers compromise the application owner, they can add additional credentials to the app registration. They can then authenticate as the application and perform actions for which the application is privileged.</p>"
            Remediation = '<p>Verify that application owners, especially for privileged applications (high impact score), are adequately protected. Standard user accounts should not be assigned ownership of highly privileged applications. If ownership is required, provision a dedicated administrative account. Secure this account with appropriate measures, such as phishing-resistant multi-factor authentication (e.g., FIDO2) and device compliance requirements.</p><p>If the owner is a service principal, verify who can control that service principal and ensure it is appropriately secured.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration#app-ownership-configuration" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration#app-ownership-configuration</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No app registrations with owners were identified.</p>"
        }
    }
    #endregion
    #region AGT VariantProps
    $AGT001VariantProps = @{
        Default = @{
            Threat = "<p>Client secrets are prone to accidental exposure through configuration files, scripts, or log files.</p><p>If attackers obtains a client secret, they may be able to authenticate as a child identity (Agent Identity, or Agent User) and perform any actions for which that identity is authorized.</p>"
            Remediation = '<p>Replace client secrets with certificate-based authentication where possible. Microsoft recommends using federated identity credentials (managed identities) or certificates in production.</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#manage-credentials-securely" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#manage-credentials-securely</a></li></ul>'
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No agent identity blueprints with client secrets were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identity blueprints were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT002VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent identity. They could then authenticate in all tenants where the Blueprint Principal exists, take over the child agent identity, and abuse its extensive API privileges.</p>"
            Remediation = "<p>Privileged foreign agent identity should be reviewed regularly and removed if not clearly required for the intended functionality.</p><p>If it is unclear whether assigned privileges are required, contact the publisher to validate the permission model and confirm the expected usage of the agent.</p><p>General guidance:</p><ul><li>API permissions should be limited to the absolute minimum required (for example, use <code>Mail.Read</code> instead of <code>Mail.ReadWrite</code>).</li><li>Where technically possible, the agent should use <code>Delegated</code> permissions instead of <code>Application</code> permissions.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent identities with extensive application API privileges were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT003VariantProps = @{
        Default = @{
            Threat = "<p>The parent blueprint of this agent identity is registered in an external organization's tenant.</p><p>If the external organization acts maliciously, or if its tenant or blueprint credentials are compromised by a third party, attackers may be able to abuse the delegated permissions associated with this agent identity on behalf of the affected user(s).</p>"
            Remediation = "<p>Privileged foreign agent identity should be reviewed regularly and removed if not clearly required for the intended functionality.</p><p>If it is unclear whether assigned privileges are required, contact the publisher to validate the permission model and confirm the expected usage of the agent.</p>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent identities with extensive delegated API privileges were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT004VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent identity and abuse its Entra ID role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged tenant resources.</p>"
            Remediation = "<p>Restrict foreign agent identities to the minimum privileges required for their intended functionality. Regularly review assigned Entra ID roles and remove any assignments that are not strictly necessary. Assess whether highly privileged foreign access to the tenant is justified, and remove such access where it is not.</p><p>If the justification is unclear, contact the publisher to validate the required role assignments and confirm the expected use of the agent.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent identities were identified that have Entra ID roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT005VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent identity and abuse its Azure role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged Azure resources.</p>"
            Remediation = "<p>Restrict foreign agent identities to the minimum privileges required for their intended functionality. Regularly review assigned permissions and remove any that are not strictly necessary. Assess whether highly privileged foreign access to the tenant is justified and remove such access where it is not.</p><p>If the justification is unclear, contact the publisher to validate the required permissions and confirm the expected usage of the application.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent identities were identified that have Azure roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT006VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity. They could then authenticate as the agent identity and abuse its assigned application API privileges.</p>"
            Remediation = "<p>Review whether the assigned API permissions are required for the intended functionality of the agent identity, and remove any permissions that are not strictly necessary.</p><p>General guidance:</p><ul><li>API permissions should be limited to the absolute minimum required (for example, use <code>Mail.Read</code> instead of <code>Mail.ReadWrite</code>).</li><li>Where technically possible, the agent should use <code>Delegated</code> permissions instead of <code>Application</code> permissions.</li><li>Review who can manage the corresponding blueprint credentials.</li></ul>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent identities with extensive application API privileges were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT007VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity. Depending on how the agent identity is used, they may then be able to abuse the delegated permissions associated with it on behalf of the affected user(s).</p>"
            Remediation = "<p>Review whether the assigned delegated API permissions are required for the intended functionality of the agent identity, and remove any permissions that are not strictly necessary.</p><p>General guidance:</p><ul><li>Delegated permissions should be limited to the absolute minimum required.</li><li>Review which users can authenticate to the agent identity and which actions the agent is expected to perform on their behalf.</li><li>Review who can manage the corresponding blueprint credentials.</li></ul>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent identities with extensive delegated API privileges were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT008VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity and abuse its Entra ID role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged tenant resources.</p>"
            Remediation = "<p>Restrict internal agent identities to the minimum privileges required for their intended functionality. Regularly review assigned Entra ID roles and remove any assignments that are not strictly necessary.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent identities were identified that have privileged Entra ID roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT009VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity and abuse its Azure role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged Azure resources.</p>"
            Remediation = "<p>Restrict internal agent identities to the minimum Azure privileges required for their intended functionality. Regularly review assigned Azure roles and remove any assignments that are not strictly necessary.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent identities were identified that have privileged Azure roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT010VariantProps = @{
        Default = @{
            Threat = "<p>Inactive but enabled agent identities increase the attack surface. If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to authenticate as the dormant agent identity without immediate detection.</p>"
            Remediation = '<p>Verify whether these agent identities are still required. Disable or remove agent identities that are no longer needed. If the identity is no longer used, also review whether the corresponding blueprint and credentials should be removed.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#govern-the-agent-lifecycle" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#govern-the-agent-lifecycle</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled inactive agent identities were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identities were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT011VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent user and abuse its Entra ID role assignments.</p>"
            Remediation = "<p>Restrict foreign agent users to the minimum Entra ID privileges required for their intended functionality. Regularly review assigned Entra ID roles and remove any assignments that are not strictly necessary. If privileged user context is not required, consider whether the agent user is needed at all.</p><p>If the justification is unclear, contact the publisher to validate the required role assignments and confirm the expected use of the agent user.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent users were identified that have Entra ID roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT012VariantProps = @{
        Default = @{
            Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent user and abuse its Azure role assignments.</p>"
            Remediation = "<p>Restrict foreign agent users to the minimum Azure privileges required for their intended functionality. Regularly review assigned Azure roles and remove any assignments that are not strictly necessary. If privileged user context is not required, consider whether the agent user is needed at all.</p><p>If the justification is unclear, contact the publisher to validate the required role assignments and confirm the expected use of the agent user.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled foreign agent users were identified that have Azure roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT013VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may gain control of the agent user and abuse its Entra ID role assignments.</p>"
            Remediation = "<p>Restrict internal agent users to the minimum Entra ID privileges required for their intended functionality. Regularly review assigned Entra ID roles and remove any assignments that are not strictly necessary. If privileged user context is not required, consider whether the agent user is needed at all.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent users were identified that have privileged Entra ID roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT014VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may gain control of the agent user and abuse its Azure role assignments.</p>"
            Remediation = "<p>Restrict internal agent users to the minimum Azure privileges required for their intended functionality. Regularly review assigned Azure roles and remove any assignments that are not strictly necessary. If privileged user context is not required, consider whether the agent user is needed at all.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled internal agent users were identified that have privileged Azure roles assigned.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT015VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain control of an agent user, they may be able to abuse ownership of groups that are referenced by Conditional Access policies. By changing group membership, attackers may be able to influence which users are included in or excluded from specific Conditional Access controls.</p>"
            Remediation = "<p>Review whether agent users really need to own groups that are referenced by Conditional Access policies. Remove unnecessary ownership assignments and use dedicated administrative identities for managing CAP-related groups.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled agent users were identified that own groups referenced by Conditional Access policies.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT016VariantProps = @{
        Default = @{
            Threat = "<p>Inactive but enabled agent users increase the attack surface. If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to authenticate as the dormant agent user without immediate detection.</p>"
            Remediation = '<p>Verify whether these agent users are still required. Disable or remove any agent users that are no longer needed.</p><p>In general, agent user accounts should only be created where a user object is truly required, such as for an agent that needs a mailbox or Teams presence. If the agent can operate with application credentials alone, avoid agent user accounts because they add complexity through licenses, group memberships, and user-level policies.</p><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#design-agent-identity-blueprints" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#design-agent-identity-blueprints</a></li><li><a href="https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#govern-the-agent-lifecycle" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/agent-id/best-practices-agent-id#govern-the-agent-lifecycle</a></li></ul>'
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No enabled inactive agent users were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent users were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    $AGT017VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain control of a non-Tier-0 owner of a high-impact blueprint, they may be able to add their own credentials and take over the corresponding child blueprint principals, agent identities, and agent users.</p>"
            Remediation = "<p>Verify that blueprint owners, especially for high-impact blueprints, are adequately protected. Standard user accounts should not be assigned ownership of high-impact blueprints. If ownership is required, provision a dedicated administrative account. Secure this account with appropriate measures, such as phishing-resistant multi-factor authentication (for example, FIDO2) and device requirements.</p><p>If the owner is a service principal, verify who can control that service principal and ensure it is appropriately secured.</p>"
        }
        Vulnerable = @{
            Status = "Vulnerable"
        }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No blueprints with an impact score of at least 200 and non-Tier-0 owners were identified.</p>"
        }
        Skipped = @{
            Status = "Skipped"
            Description = "<p>Check skipped because no agent identity blueprints were identified in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    }
    #endregion
    #region MAI VariantProps
    $MAI001VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain control over a resource that is allowed to use the managed identity (for example, a VM, Logic App, or Automation Account), they can obtain an access token for the identity. Using this token, they can authenticate as the managed identity and abuse its API privileges.</p>"
            Remediation = "<p>Review whether the managed identities require such high API privileges and remove any permissions that are not strictly necessary. Additionally, verify which identities have or can obtain access to the resources that are allowed to use the managed identity.</p><p>General guidance:</p><ul><li>Limit API permissions to the absolute minimum required (for example, use <code>User.Read.All</code> instead of <code>User.ReadWrite.All</code>).</li><li>Restrict which users or applications can control the resources that are allowed to use the managed identities.</li><li>Verify that users or applications with group management permissions cannot grant themselves access to resources that are allowed to use the managed identity.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No managed identities identified which have extensive API privileges.</p>"
        }
    }
    $MAI002VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain control over a resource that is allowed to use the managed identity (for example, a VM, Logic App, or Automation Account), they can obtain an access token for the identity. Using this token, they can authenticate as the managed identity and abuse its privileges.</p>"
            Remediation = "<p>Review whether the managed identities require those role assignments and remove any that are not strictly necessary. Additionally, verify which identities have or can obtain access to the resources that are allowed to use the managed identity.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li><li>Restrict which users or applications can control the resources that are allowed to use the managed identities.</li><li>Verify that users or applications with group management permissions cannot grant themselves access to resources that are allowed to use the managed identity.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No managed identities identified which have privileged Entra ID roles (tier-0 or tier-1) assigned.</p>"
        }
    }
    $MAI003VariantProps = @{
        Default = @{
            Threat = "<p>If attackers gain control over a resource that is allowed to use the managed identity (for example, a VM, Logic App, or Automation Account), they can obtain an access token for the identity. Using this token, they can authenticate as the managed identity and abuse its privileges.</p>"
            Remediation = "<p>Review whether the managed identities require those role assignments and remove any that are not strictly necessary. Additionally, verify which identities have or can obtain access to the resources that are allowed to use the managed identity.</p><p>General guidance:</p><ul><li>Limit privileges to the absolute minimum required (for example, use reader roles instead of roles that allow modifying objects).</li><li>Consider using a custom role that contains only the required privileges.</li><li>Restrict which users or applications can control the resources that are allowed to use the managed identities.</li><li>Verify that users or applications with group management permissions cannot grant themselves access to resources that are allowed to use the managed identity.</li></ul>"
        }
        Vulnerable = @{ Status = "Vulnerable" }
        Secure = @{
            Status = "NotVulnerable"
            Description = "<p>No managed identities identified which have privileged Azure roles (tier-0 or tier-1) assigned.</p>"
        }
    }
    #endregion
    #region PIM VariantProps
    $PIM001VariantProps = @{
        Default = @{
            Threat = '<p>Permanently assigned privileged roles significantly increase the attack surface. If a privileged account is compromised, attackers gain immediate and persistent access to highly sensitive administrative capabilities without additional safeguards.</p><p>Without just-in-time activation, approval workflows, or time-based restrictions, privileged access may remain active longer than necessary, increasing the risk of privilege abuse, lateral movement, and tenant-wide compromise.</p>'
            Remediation = '<p>Avoid permanently assigning privileged roles (for example, Global Administrator, Application Administrator, or Privileged Authentication Administrator) or privileged groups. Instead, use Privileged Identity Management with appropriate role activation and approval settings.</p><p><strong>Note:</strong></p><ul><li>Emergency access accounts should be excluded and may remain permanently assigned to required roles.</li><li>Microsoft Entra ID P2 (or an equivalent license) is required for each user utilizing PIM. At a minimum, this should be considered for highly privileged users.</li></ul><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started</a></li></ul>'
        }
    }
    $PIM002VariantProps = @{
        Default = @{
            Threat = '<p>The affected Tier-0 roles have active user or group assignments that are not activated through Privileged Identity Management (PIM). If a permanently assigned privileged account is compromised, attackers can immediately abuse the role without additional approval or time-based restrictions, potentially leading to full tenant compromise.</p>'
            Remediation = '<p>Do not permanently assign the affected roles. Grant privileged access exclusively through Privileged Identity Management (PIM) with limited activation duration. Configure secure activation settings, such as requiring an authentication context, or approval by an independent approver.</p><p><strong>Note:</strong> Emergency access accounts should be excluded and may remain permanently assigned to required roles.</p>'
        }
    }
    $PIM003VariantProps = @{
        Default = @{
            Threat = '<p>Highly privileged roles are typically required only for short, specific tasks (for example, assigning roles) and not for day-to-day operations. When roles remain active for extended periods, elevated permissions persist even after they are no longer needed. If an attacker obtains a valid access token during this time, they may continue to abuse the unnecessary privileges.</p><p>Although users can select shorter activation durations, default activation settings are often left unchanged, increasing the exposure window for privileged access.</p>'
            Remediation = '<p>Reduce the maximum activation duration to the minimum operationally required. For highly privileged roles, the activation period should not exceed 4 hours.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#activation-maximum-duration" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#activation-maximum-duration</a></li></ul>'
        }
    }
    $PIM004VariantProps = @{
        Default = @{
            Threat = '<p>Without justification or ticket information, it is difficult to review role activations and detect potential overprivileged usage.</p>'
            Remediation = '<p>Require justification and/or ticketing information when activating Tier-0 roles.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-activation" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-activation</a></li></ul>'
        }
    }
    $PIM005VariantProps = @{
        Default = @{
            Threat = '<p>Because permanent active assignments are allowed, administrators may create temporary active assignments that do not expire, increasing the risk of prolonged privileged access. If a privileged account is compromised during this period, attackers may retain elevated permissions without additional approval or time-based restrictions.</p>'
            Remediation = '<p>Configure active assignments for all Tier-0 roles to require an expiration date, except for roles that contain designated emergency access accounts (for example, the Global Administrator).</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#assignment-duration" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#assignment-duration</a></li></ul>'
        }
    }
    $PIM006VariantProps = @{
        Default = @{
            Threat = '<p>Without justification on active assignments, it is difficult to review role assignments and detect potential overprivileged assignments.</p>'
            Remediation = '<p>Configure active assignments for all Tier-0 roles to require justification on active assignments.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-active-assignment" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-active-assignment</a></li></ul>'
        }
    }
    $PIM007VariantProps = @{
        Default = @{
            Threat = '<p>While MFA should already be enforced through Conditional Access policies, this setting provides an additional safeguard. If there is a gap in Conditional Access policies and MFA is not required under specific conditions (for example, trusted IP ranges or joined devices), privileged roles may be assigned without MFA. This increases the risk that attackers can grant themselves or others elevated privileges if a privileged account is compromised.</p>'
            Remediation = '<p>Configure active assignments for all Tier-0 roles to require MFA on active assignments.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-multifactor-authentication-on-active-assignment" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-multifactor-authentication-on-active-assignment</a></li></ul>'
        }
    }
    $PIM008VariantProps = @{
        Default = @{
            Threat = '<p>Tier-0 roles are highly sensitive and should only be assigned or activated when strictly necessary. Without proper notifications or monitoring, suspicious assignments or activations may go unnoticed, delaying detection of potential misuse or account compromise.</p>'
            Remediation = '<p>Implement monitoring/notifications for Tier-0 role activities.</p><p>Monitor the following events:</p><ul><li>Eligible role assignments</li><li>Active role assignments</li><li>Role activations</li></ul><p>Configure PIM email notifications or integrate relevant audit logs into a SIEM solution for centralized monitoring and alerting.</p><p>Reference:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-active-assignment" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#require-justification-on-active-assignment</a></li></ul>'
        }
    }
    $PIM009VariantProps = @{
        Default = @{
            Threat = '<p>Because no additional MFA is enforced during role activation, attackers who obtain an access token with the required scopes may activate privileged roles without further verification.</p><p>Additionally, if reauthentication is not required, attackers in possession of a valid refresh token may wait for a legitimate user to activate the role and then obtain a new access token to operate with elevated privileges.</p>'
            Remediation = '<p>Require reauthentication using an authentication context that enforces MFA during activation of Tier-0 roles.</p><p><strong>Note:</strong> Session controls are not enforced within five minutes after successful authentication. During this grace period, users may not be prompted to reauthenticate.</p><p>Additionally or alternatively, require approval for role activation and enforce limited session duration through Conditional Access policies. While this does not fully prevent abuse of stolen refresh tokens, it reduces the likelihood.</p><p>References:</p><ul><li><a href="https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#on-activation-require-multifactor-authentication" target="_blank" rel="noopener noreferrer">https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings#on-activation-require-multifactor-authentication</a></li><li><a href="https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/enhancing-security-with-entra-pim-and-conditional-access-policy-using-authentica/4368002" target="_blank" rel="noopener noreferrer">https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/enhancing-security-with-entra-pim-and-conditional-access-policy-using-authentica/4368002</a></li></ul>'
        }
    }

    #endregion
    #endregion

    # Apply default text variants for findings with dynamic overrides.
    $DefaultVariantById = @{
        "COL-001" = $COL001VariantProps.Default
        "COL-002" = $COL002VariantProps.Default
        "COL-003" = $COL003VariantProps.Default
        "PAS-001" = $PAS001VariantProps.Default
        "PAS-002" = $PAS002VariantProps.Default
        "PAS-003" = $PAS003VariantProps.Default
        "PAS-004" = $PAS004VariantProps.Default
        "PAS-005" = $PAS005VariantProps.Default
        "USR-001" = $USR001VariantProps.Default
        "USR-002" = $USR002VariantProps.Default
        "USR-003" = $USR003VariantProps.Default
        "USR-004" = $USR004VariantProps.Default
        "USR-005" = $USR005VariantProps.Default
        "USR-006" = $USR006VariantProps.Default
        "USR-007" = $USR007VariantProps.Default
        "USR-008" = $USR008VariantProps.Default
        "USR-009" = $USR009VariantProps.Default
        "USR-010" = $USR010VariantProps.Default
        "USR-011" = $USR011VariantProps.Default
        "USR-012" = $USR012VariantProps.Default
        "USR-013" = $USR013VariantProps.Default
        "GRP-001" = $GRP001VariantProps.Default
        "GRP-002" = $GRP002VariantProps.Default
        "GRP-003" = $GRP003VariantProps.Default
        "GRP-004" = $GRP004VariantProps.Default
        "GRP-005" = $GRP005VariantProps.Default
        "CAP-001" = $CAP001VariantProps.Default
        "CAP-002" = $CAP002VariantProps.Default
        "CAP-003" = $CAP003VariantProps.Default
        "CAP-004" = $CAP004VariantProps.Default
        "CAP-005" = $CAP005VariantProps.Default
        "CAP-006" = $CAP006VariantProps.Default
        "CAP-007" = $CAP007VariantProps.Default
        "CAP-008" = $CAP008VariantProps.Default
        "CAP-009" = $CAP009VariantProps.Default
        "CAP-010" = $CAP010VariantProps.Default
        "CAP-011" = $CAP011VariantProps.Default
        "ENT-001" = $ENT001VariantProps.Default
        "ENT-002" = $ENT002VariantProps.Default
        "ENT-003" = $ENT003VariantProps.Default
        "ENT-004" = $ENT004VariantProps.Default
        "ENT-005" = $ENT005VariantProps.Default
        "ENT-006" = $ENT006VariantProps.Default
        "ENT-007" = $ENT007VariantProps.Default
        "ENT-008" = $ENT008VariantProps.Default
        "ENT-009" = $ENT009VariantProps.Default
        "ENT-010" = $ENT010VariantProps.Default
        "ENT-011" = $ENT011VariantProps.Default
        "ENT-012" = $ENT012VariantProps.Default
        "ENT-013" = $ENT013VariantProps.Default
        "APP-001" = $APP001VariantProps.Default
        "APP-002" = $APP002VariantProps.Default
        "APP-003" = $APP003VariantProps.Default
        "AGT-001" = $AGT001VariantProps.Default
        "AGT-002" = $AGT002VariantProps.Default
        "AGT-003" = $AGT003VariantProps.Default
        "AGT-004" = $AGT004VariantProps.Default
        "AGT-005" = $AGT005VariantProps.Default
        "AGT-006" = $AGT006VariantProps.Default
        "AGT-007" = $AGT007VariantProps.Default
        "AGT-008" = $AGT008VariantProps.Default
        "AGT-009" = $AGT009VariantProps.Default
        "AGT-010" = $AGT010VariantProps.Default
        "AGT-011" = $AGT011VariantProps.Default
        "AGT-012" = $AGT012VariantProps.Default
        "AGT-013" = $AGT013VariantProps.Default
        "AGT-014" = $AGT014VariantProps.Default
        "AGT-015" = $AGT015VariantProps.Default
        "AGT-016" = $AGT016VariantProps.Default
        "AGT-017" = $AGT017VariantProps.Default
        "MAI-001" = $MAI001VariantProps.Default
        "MAI-002" = $MAI002VariantProps.Default
        "MAI-003" = $MAI003VariantProps.Default
        "PIM-001" = $PIM001VariantProps.Default
        "PIM-002" = $PIM002VariantProps.Default
        "PIM-003" = $PIM003VariantProps.Default
        "PIM-004" = $PIM004VariantProps.Default
        "PIM-005" = $PIM005VariantProps.Default
        "PIM-006" = $PIM006VariantProps.Default
        "PIM-007" = $PIM007VariantProps.Default
        "PIM-008" = $PIM008VariantProps.Default
        "PIM-009" = $PIM009VariantProps.Default
    }
    foreach ($entry in $DefaultVariantById.GetEnumerator()) {
        if ($entry.Value) {
            Set-FindingOverride -FindingId $entry.Key -Props $entry.Value
        }
    }



    #endregion

    ############################## Enumeration section ########################
    #region Enumeration And Check Evaluation
    #region Enumeration: Enterprise Applications
    # ENT-001/ENT-002/ENT-003/ENT-004/ENT-005/ENT-006/ENT-007/ENT-008/ENT-009/ENT-010/ENT-011/ENT-012/ENT-013: Reuse a single pass over enterprise apps.
    # ENT-001 = enabled + non-SAML + credentials; ENT-002 = enabled + inactive; ENT-003 = enabled + owners + impact>=threshold;
    # ENT-004 = enabled + foreign + extensive API permissions (application); ENT-005 = enabled + foreign + extensive API permissions (delegated);
    # ENT-006 = enabled + foreign + Entra ID roles; ENT-007 = enabled + foreign + Azure roles; ENT-008 = enabled + foreign + owns groups/apps/SPs;
    # ENT-009 = enabled + internal + extensive API permissions (application) excluding ConnectSyncProvisioning_;
    # ENT-010 = enabled + internal + extensive API permissions (delegated);
    # ENT-011 = enabled + internal + Entra max tier 0/1; ENT-012 = enabled + internal + Azure max tier 0/1; ENT-013 = known malicious AppId match.
    $ownerFindingMinImpact = 50
    $blueprintOwnerFindingMinImpact = 200
    $entAppsWithSecrets = [System.Collections.Generic.List[object]]::new()
    $entAppsInactiveEnabled = [System.Collections.Generic.List[object]]::new()
    $entAppsWithOwners = [System.Collections.Generic.List[object]]::new()
    $entAppsForeignExtensive = [System.Collections.Generic.List[object]]::new()
    $entAppsForeignDelegated = [System.Collections.Generic.List[object]]::new()
    $entAppsForeignRoles = [System.Collections.Generic.List[object]]::new()
    $entAppsForeignAzureRoles = [System.Collections.Generic.List[object]]::new()
    $entAppsForeignOwningObjects = [System.Collections.Generic.List[object]]::new()
    $entAppsInternalExtensive = [System.Collections.Generic.List[object]]::new()
    $entAppsInternalDelegated = [System.Collections.Generic.List[object]]::new()
    $entAppsInternalTier0 = [System.Collections.Generic.List[object]]::new()
    $entAppsInternalAzureTier = [System.Collections.Generic.List[object]]::new()
    $entAppsKnownMalicious = [System.Collections.Generic.List[object]]::new()
    $enterpriseAppIds = @{}
    if ($EnterpriseApps) {
        write-host "[*] Analyzing Enterprise Applications"
        foreach ($entry in $EnterpriseApps.GetEnumerator()) {
            $enterpriseAppIds[$entry.Key] = $true
            $app = $entry.Value
            if (-not $app) { continue }
            if (-not [string]::IsNullOrWhiteSpace("$($app.KnownMaliciousSourceUrl)")) {
                $entAppsKnownMalicious.Add($app)
            }
            if ($app.Enabled -eq $true -and $app.SAML -eq $false -and $app.Credentials -gt 0) {
                $entAppsWithSecrets.Add($app)
            }
            if ($app.Enabled -eq $true -and $app.Inactive -eq $true) {
                $entAppsInactiveEnabled.Add($app)
            }
            $impactValue = Get-IntSafe $app.Impact
            if ($app.Enabled -eq $true -and $app.Owners -gt 0 -and $impactValue -ge $ownerFindingMinImpact) {
                $entAppsWithOwners.Add($app)
            }
            $apiDangerous = 0
            $apiHigh = 0
            $apiMedium = 0
            if ($null -ne $app.ApiDangerous) { [int]::TryParse("$($app.ApiDangerous)", [ref]$apiDangerous) | Out-Null }
            if ($null -ne $app.ApiHigh) { [int]::TryParse("$($app.ApiHigh)", [ref]$apiHigh) | Out-Null }
            if ($null -ne $app.ApiMedium) { [int]::TryParse("$($app.ApiMedium)", [ref]$apiMedium) | Out-Null }
            if ($app.Enabled -eq $true -and $app.Foreign -eq $true -and (($apiDangerous + $apiHigh + $apiMedium) -gt 0)) {
                $entAppsForeignExtensive.Add($app)
            }
            $apiDelegatedDangerous = 0
            $apiDelegatedHigh = 0
            $apiDelegatedMedium = 0
            if ($null -ne $app.ApiDelegatedDangerous) { [int]::TryParse("$($app.ApiDelegatedDangerous)", [ref]$apiDelegatedDangerous) | Out-Null }
            if ($null -ne $app.ApiDelegatedHigh) { [int]::TryParse("$($app.ApiDelegatedHigh)", [ref]$apiDelegatedHigh) | Out-Null }
            if ($null -ne $app.ApiDelegatedMedium) { [int]::TryParse("$($app.ApiDelegatedMedium)", [ref]$apiDelegatedMedium) | Out-Null }
            if ($app.Enabled -eq $true -and $app.Foreign -eq $true -and (($apiDelegatedDangerous + $apiDelegatedHigh + $apiDelegatedMedium) -gt 0)) {
                $entAppsForeignDelegated.Add($app)
            }
            $entraRolesValue = 0
            if ($null -ne $app.EntraRolesEffective) {
                [int]::TryParse("$($app.EntraRolesEffective)", [ref]$entraRolesValue) | Out-Null
            } elseif ($null -ne $app.EntraRoles) {
                [int]::TryParse("$($app.EntraRoles)", [ref]$entraRolesValue) | Out-Null
            }
            if ($app.Enabled -eq $true -and $app.Foreign -eq $true -and $entraRolesValue -gt 0) {
                $entAppsForeignRoles.Add($app)
            }
            $azureRolesValue = 0
            if ($null -ne $app.AzureRolesEffective) {
                [int]::TryParse("$($app.AzureRolesEffective)", [ref]$azureRolesValue) | Out-Null
            } elseif ($null -ne $app.AzureRoles) {
                [int]::TryParse("$($app.AzureRoles)", [ref]$azureRolesValue) | Out-Null
            }
            if ($app.Enabled -eq $true -and $app.Foreign -eq $true -and $azureRolesValue -gt 0) {
                $entAppsForeignAzureRoles.Add($app)
            }
            $grpOwnValue = Get-IntSafe $app.GrpOwn
            $appOwnValue = Get-IntSafe $app.AppOwn
            $blueprintOwnValue = Get-IntSafe $app.BlueprintOwn
            $spOwnValue = Get-IntSafe $app.SpOwn
            if ($app.Enabled -eq $true -and $app.Foreign -eq $true -and ($grpOwnValue -gt 0 -or $appOwnValue -gt 0 -or $blueprintOwnValue -gt 0 -or $spOwnValue -gt 0)) {
                $entAppsForeignOwningObjects.Add($app)
            }
            $isExcludedName = $false
            if ($app.DisplayName -and $app.DisplayName.StartsWith("ConnectSyncProvisioning_")) {
                $isExcludedName = $true
            }
            if ($app.Enabled -eq $true -and $app.Foreign -ne $true -and -not $isExcludedName -and ($apiDangerous -gt 0 -or $apiHigh -gt 0)) {
                $entAppsInternalExtensive.Add($app)
            }
            if ($app.Enabled -eq $true -and $app.Foreign -ne $true -and ($apiDelegatedDangerous -gt 0 -or $apiDelegatedHigh -gt 0)) {
                $entAppsInternalDelegated.Add($app)
            }
            $entraMaxTier = "$($app.EntraMaxTier)"
            if ($app.Enabled -eq $true -and $app.Foreign -ne $true -and ($entraMaxTier -eq "Tier-0" -or $entraMaxTier -eq "Tier-1")) {
                $entAppsInternalTier0.Add($app)
            }
            $azureMaxTier = "$($app.AzureMaxTier)"
            if ($app.Enabled -eq $true -and $app.Foreign -ne $true -and ($azureMaxTier -eq "Tier-0" -or $azureMaxTier -eq "Tier-1")) {
                $entAppsInternalAzureTier.Add($app)
            }
        }
    }

    #endregion

    #region Enumeration: App Registrations
    # APP-001/APP-002/APP-003: Reuse a single pass over app registrations.
    # APP-003 = owners + impact>=threshold.
    $appRegsWithSecrets = [System.Collections.Generic.List[object]]::new()
    $appRegsMissingAppLock = [System.Collections.Generic.List[object]]::new()
    $appRegsWithOwners = [System.Collections.Generic.List[object]]::new()
    if ($AppRegistrations) {
        write-host "[*] Analyzing App Registrations"
        foreach ($entry in $AppRegistrations.GetEnumerator()) {
            $app = $entry.Value
            if (-not $app) { continue }
            if ($app.SecretsCount -gt 0) {
                $appRegsWithSecrets.Add($app)
            }
            if ($app.AppLock -eq $false) {
                $appRegsMissingAppLock.Add($app)
            }
            $appImpactValue = Get-IntSafe $app.Impact
            if ($app.Owners -gt 0 -and $appImpactValue -ge $ownerFindingMinImpact) {
                $appRegsWithOwners.Add($app)
            }
        }
    }

    #endregion

    #region Enumeration: Agent Identity Blueprints
    # AGT-001 / AGT-017: Reuse the blueprint enumeration output to identify blueprints with client secrets or high-impact owners.
    $agentBlueprintsWithSecrets = [System.Collections.Generic.List[object]]::new()
    $agentBlueprintsWithOwners = [System.Collections.Generic.List[object]]::new()
    $agentBlueprintCount = 0
    if ($AgentIdentityBlueprints) {
        $agentBlueprintCount = $AgentIdentityBlueprints.Count
        if ($agentBlueprintCount -gt 0) {
            write-host "[*] Analyzing Agent Identity Blueprints"
            foreach ($entry in $AgentIdentityBlueprints.GetEnumerator()) {
                $blueprint = $entry.Value
                if (-not $blueprint) { continue }
                if ((Get-IntSafe $blueprint.SecretsCount) -gt 0) {
                    $agentBlueprintsWithSecrets.Add($blueprint)
                }
                $blueprintImpactValue = Get-IntSafe $blueprint.Impact
                if ((Get-IntSafe $blueprint.Owners) -gt 0 -and $blueprintImpactValue -ge $blueprintOwnerFindingMinImpact) {
                    $agentBlueprintsWithOwners.Add($blueprint)
                }
            }
        }
    }

    #endregion

    #region Enumeration: Agent Identities
    # AGT-002/AGT-003/AGT-004/AGT-005/AGT-006/AGT-007/AGT-008/AGT-009/AGT-010: Identify internal/foreign agent identities with extensive API permissions, inactivity, or Entra ID/Azure role assignments.
    $foreignAgentIdentitiesWithExtensiveApi = [System.Collections.Generic.List[object]]::new()
    $foreignAgentIdentitiesWithDelegatedExtensiveApi = [System.Collections.Generic.List[object]]::new()
    $foreignAgentIdentitiesWithPrivilegedEntraRoles = [System.Collections.Generic.List[object]]::new()
    $foreignAgentIdentitiesWithPrivilegedAzureRoles = [System.Collections.Generic.List[object]]::new()
    $internalAgentIdentitiesWithExtensiveApi = [System.Collections.Generic.List[object]]::new()
    $internalAgentIdentitiesWithDelegatedExtensiveApi = [System.Collections.Generic.List[object]]::new()
    $internalAgentIdentitiesWithPrivilegedEntraRoles = [System.Collections.Generic.List[object]]::new()
    $internalAgentIdentitiesWithPrivilegedAzureRoles = [System.Collections.Generic.List[object]]::new()
    $inactiveEnabledAgentIdentities = [System.Collections.Generic.List[object]]::new()
    $agentIdentityCount = 0
    if ($AgentIdentities) {
        $agentIdentityCount = $AgentIdentities.Count
        if ($agentIdentityCount -gt 0) {
            write-host "[*] Analyzing Agent Identities"
            foreach ($entry in $AgentIdentities.GetEnumerator()) {
                $agentIdentity = $entry.Value
                if (-not $agentIdentity) { continue }

                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Inactive -eq $true) {
                    $inactiveEnabledAgentIdentities.Add($agentIdentity)
                }

                $apiDangerous = Get-IntSafe $agentIdentity.ApiDangerous
                $apiHigh = Get-IntSafe $agentIdentity.ApiHigh
                $apiMedium = Get-IntSafe $agentIdentity.ApiMedium
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $true -and (($apiDangerous + $apiHigh + $apiMedium) -gt 0)) {
                    $foreignAgentIdentitiesWithExtensiveApi.Add($agentIdentity)
                }

                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $false -and ($apiDangerous -gt 0 -or $apiHigh -gt 0)) {
                    $internalAgentIdentitiesWithExtensiveApi.Add($agentIdentity)
                }

                $apiDelegatedDangerous = Get-IntSafe $agentIdentity.ApiDelegatedDangerous
                $apiDelegatedHigh = Get-IntSafe $agentIdentity.ApiDelegatedHigh
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $true -and ($apiDelegatedDangerous -gt 0 -or $apiDelegatedHigh -gt 0)) {
                    $foreignAgentIdentitiesWithDelegatedExtensiveApi.Add($agentIdentity)
                }
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $false -and ($apiDelegatedDangerous -gt 0 -or $apiDelegatedHigh -gt 0)) {
                    $internalAgentIdentitiesWithDelegatedExtensiveApi.Add($agentIdentity)
                }

                $entraMaxTier = "$($agentIdentity.EntraMaxTier)"
                $effectiveEntraRoleEntries = @()
                if ($agentIdentity.Enabled -eq $true) {
                    $effectiveEntraRoleEntries = @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Entra)
                }
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $true -and $effectiveEntraRoleEntries.Count -gt 0) {
                    $foreignAgentIdentitiesWithPrivilegedEntraRoles.Add($agentIdentity)
                }
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $false -and ($entraMaxTier -eq "Tier-0" -or $entraMaxTier -eq "Tier-1")) {
                    $internalAgentIdentitiesWithPrivilegedEntraRoles.Add($agentIdentity)
                }

                $azureMaxTier = "$($agentIdentity.AzureMaxTier)"
                $effectiveAzureRoleEntries = @()
                if ($agentIdentity.Enabled -eq $true) {
                    $effectiveAzureRoleEntries = @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Azure)
                }
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $true -and $effectiveAzureRoleEntries.Count -gt 0) {
                    $foreignAgentIdentitiesWithPrivilegedAzureRoles.Add($agentIdentity)
                }
                if ($agentIdentity.Enabled -eq $true -and $agentIdentity.Foreign -eq $false -and ($azureMaxTier -eq "Tier-0" -or $azureMaxTier -eq "Tier-1")) {
                    $internalAgentIdentitiesWithPrivilegedAzureRoles.Add($agentIdentity)
                }
            }
        }
    }

    #endregion

    #region Enumeration: Users
    # USR-005/USR-006/USR-007/USR-008/USR-009/USR-010/USR-011/USR-012/USR-013 and AGT-011/AGT-012/AGT-013/AGT-014/AGT-015/AGT-016: Reuse a single pass over users.
    # Track inactive users, tier-0 Entra users, tier-0 Azure users (all + hybrid), users without MFA capability, and likely unnecessary synced accounts.
    $inactiveEnabledUsers = [System.Collections.Generic.List[object]]::new()
    $enabledTier0Users = [System.Collections.Generic.List[object]]::new()
    $enabledTier0OnPremUsers = [System.Collections.Generic.List[object]]::new()
    $enabledTier0UnprotectedUsers = [System.Collections.Generic.List[object]]::new()
    $enabledTier0AzureUsers = [System.Collections.Generic.List[object]]::new()
    $enabledTier0AzureOnPremUsers = [System.Collections.Generic.List[object]]::new()
    $enabledTier0AzureUnprotectedUsers = [System.Collections.Generic.List[object]]::new()
    $enabledUsersWithoutMfaCap = [System.Collections.Generic.List[object]]::new()
    $enabledOnPremNeverSignedInOlderThan90Users = [System.Collections.Generic.List[object]]::new()
    $foreignAgentUsersWithPrivilegedEntraRoles = [System.Collections.Generic.List[object]]::new()
    $foreignAgentUsersWithPrivilegedAzureRoles = [System.Collections.Generic.List[object]]::new()
    $internalAgentUsersWithPrivilegedEntraRoles = [System.Collections.Generic.List[object]]::new()
    $internalAgentUsersWithPrivilegedAzureRoles = [System.Collections.Generic.List[object]]::new()
    $agentUsersOwningCapRelatedGroups = [System.Collections.Generic.List[object]]::new()
    $inactiveEnabledAgentUsers = [System.Collections.Generic.List[object]]::new()
    $enabledUsersForMfaCapCheckCount = 0
    $agentUserCount = 0
    if ($Users) {
        write-host "[*] Analyzing Users"
        foreach ($entry in $Users.GetEnumerator()) {
            $user = $entry.Value
            if (-not $user) { continue }

            $isEnabled = $user.Enabled -eq $true -or "$($user.Enabled)".Trim().ToLowerInvariant() -eq "true"
            $isInactive = $user.Inactive -eq $true -or "$($user.Inactive)".Trim().ToLowerInvariant() -eq "true"
            $isOnPrem = $user.OnPrem -eq $true -or "$($user.OnPrem)".Trim().ToLowerInvariant() -eq "true"
            $isProtected = -not ($user.Protected -eq $false -or "$($user.Protected)".Trim().ToLowerInvariant() -eq "false")
            $isAgent = $user.Agent -eq $true
            $isForeignAgent = $user.ForeignAgent -eq $true -or "$($user.ForeignAgent)".Trim().ToLowerInvariant() -eq "true"
            $mfaCapRaw = "$($user.MfaCap)".Trim()
            $hasMfaCap = $user.MfaCap -eq $true -or $mfaCapRaw.ToLowerInvariant() -eq "true"
            $isUnknownMfaCap = $mfaCapRaw -eq "?"
            $entraMaxTier = "$($user.EntraMaxTier)".Trim()
            $azureMaxTier = "$($user.AzureMaxTier)".Trim()
            $lastSignInDays = "$($user.LastSignInDays)".Trim()
            $createdDays = Get-IntSafe $user.CreatedDays
            $excludeSyncUser = Test-IsExcludedSyncUser -UserObject $user
            if ($isAgent) {
                $agentUserCount += 1
            }
            if ($isEnabled -and -not $excludeSyncUser -and -not $isAgent) {
                $enabledUsersForMfaCapCheckCount += 1
            }
            if ($isEnabled -and $isInactive) {
                $inactiveEnabledUsers.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isAgent -and $isInactive) {
                $inactiveEnabledAgentUsers.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and -not $hasMfaCap -and -not $isUnknownMfaCap -and -not $excludeSyncUser -and -not $isAgent) {
                $enabledUsersWithoutMfaCap.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isOnPrem -and $lastSignInDays -eq "-" -and $createdDays -gt 90 -and -not $excludeSyncUser) {
                $enabledOnPremNeverSignedInOlderThan90Users.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $entraMaxTier -eq "Tier-0") {
                $enabledTier0Users.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
                if (-not $isProtected -and -not $isAgent) {
                    $enabledTier0UnprotectedUsers.Add([pscustomobject]@{
                        Id = $entry.Key
                        User = $user
                    })
                }
                if ($isOnPrem) {
                    $enabledTier0OnPremUsers.Add([pscustomobject]@{
                        Id = $entry.Key
                        User = $user
                    })
                }
            }
            if ($isEnabled -and $isAgent -and $isForeignAgent -and (Get-IntSafe $user.EntraRoles) -gt 0) {
                $foreignAgentUsersWithPrivilegedEntraRoles.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isAgent -and -not $isForeignAgent -and ($entraMaxTier -eq "Tier-0" -or $entraMaxTier -eq "Tier-1")) {
                $internalAgentUsersWithPrivilegedEntraRoles.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isAgent -and $isForeignAgent -and (Get-IntSafe $user.AzureRoles) -gt 0) {
                $foreignAgentUsersWithPrivilegedAzureRoles.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isAgent -and -not $isForeignAgent -and ($azureMaxTier -eq "Tier-0" -or $azureMaxTier -eq "Tier-1")) {
                $internalAgentUsersWithPrivilegedAzureRoles.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
            }
            if ($isEnabled -and $isAgent) {
                $ownedCapRelatedGroups = [System.Collections.Generic.List[object]]::new()
                $ownedCapReferences = 0
                foreach ($group in @($user.GroupOwnerDetails)) {
                    $groupCapCount = Get-IntSafe $group.CAPs
                    if ($groupCapCount -gt 0) {
                        $ownedCapRelatedGroups.Add($group)
                        $ownedCapReferences += $groupCapCount
                    }
                }
                if ($ownedCapRelatedGroups.Count -gt 0) {
                    $agentUsersOwningCapRelatedGroups.Add([pscustomobject]@{
                        Id = $entry.Key
                        User = $user
                        OwnedCapRelatedGroups = @($ownedCapRelatedGroups)
                        OwnedCapReferences = $ownedCapReferences
                    })
                }
            }
            if ($isEnabled -and $azureMaxTier -eq "Tier-0") {
                $enabledTier0AzureUsers.Add([pscustomobject]@{
                    Id = $entry.Key
                    User = $user
                })
                if (-not $isProtected) {
                    $enabledTier0AzureUnprotectedUsers.Add([pscustomobject]@{
                        Id = $entry.Key
                        User = $user
                    })
                }
                if ($isOnPrem) {
                    $enabledTier0AzureOnPremUsers.Add([pscustomobject]@{
                        Id = $entry.Key
                        User = $user
                    })
                }
            }
        }
    }

    #endregion

    #region Enumeration: Tier-0 Owner Lookup Sets
    # Build Tier-0 owner lookup sets for ENT-003 and APP-003 owner filtering.
    $tier0UserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $tier0EnterpriseAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $tier0ManagedIdentityIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Users) {
        foreach ($entry in $Users.GetEnumerator()) {
            $obj = $entry.Value
            if (-not $obj) { continue }
            if ("$($obj.EntraMaxTier)".Trim() -ne "Tier-0") { continue }
            $entryId = "$($entry.Key)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($entryId)) { $tier0UserIds.Add($entryId) | Out-Null }
            $objectId = "$($obj.Id)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($objectId)) { $tier0UserIds.Add($objectId) | Out-Null }
        }
    }
    if ($EnterpriseApps) {
        foreach ($entry in $EnterpriseApps.GetEnumerator()) {
            $obj = $entry.Value
            if (-not $obj) { continue }
            if ("$($obj.EntraMaxTier)".Trim() -ne "Tier-0") { continue }
            $entryId = "$($entry.Key)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($entryId)) { $tier0EnterpriseAppIds.Add($entryId) | Out-Null }
            $objectId = "$($obj.Id)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($objectId)) { $tier0EnterpriseAppIds.Add($objectId) | Out-Null }
        }
    }
    if ($ManagedIdentities) {
        foreach ($entry in $ManagedIdentities.GetEnumerator()) {
            $obj = $entry.Value
            if (-not $obj) { continue }
            if ("$($obj.EntraMaxTier)".Trim() -ne "Tier-0") { continue }
            $entryId = "$($entry.Key)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($entryId)) { $tier0ManagedIdentityIds.Add($entryId) | Out-Null }
            $objectId = "$($obj.Id)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($objectId)) { $tier0ManagedIdentityIds.Add($objectId) | Out-Null }
        }
    }
    Write-Log -Level Debug -Message ("Tier-0 owner lookup sizes: Users={0}; EnterpriseApps={1}; ManagedIdentities={2}" -f $tier0UserIds.Count, $tier0EnterpriseAppIds.Count, $tier0ManagedIdentityIds.Count)

    #endregion

    #region Enumeration: Groups
    # GRP-003/GRP-004/GRP-005: Reuse a single pass over groups.
    # Track public M365 groups, dynamic-rule risk, and unprotected sensitive groups.
    $publicM365Groups = [System.Collections.Generic.List[object]]::new()
    $dynamicGroupsWithDangerousRules = [System.Collections.Generic.List[object]]::new()
    $unprotectedSensitiveGroups = [System.Collections.Generic.List[object]]::new()
    $dangerousDynamicAttributeCounts = [ordered]@{
        "user.preferredLanguage" = 0
        "user.mobilePhone" = 0
        "user.businessPhones" = 0
        "user.userPrincipalName" = 0
        "user.mail" = 0
    }
    $allowInvitesFromForDynamicRules = ""
    if ($AuthPolicy -and $AuthPolicy.allowInvitesFrom) {
        $allowInvitesFromForDynamicRules = "$($AuthPolicy.allowInvitesFrom)"
    }
    $checkGuestInviteLinkedAttributes = -not [string]::IsNullOrWhiteSpace($allowInvitesFromForDynamicRules) -and $allowInvitesFromForDynamicRules.Trim().ToLowerInvariant() -ne "none"
    if ($AllGroupsDetails) {
        write-host "[*] Analyzing Groups"
        foreach ($entry in $AllGroupsDetails.GetEnumerator()) {
            $group = $entry.Value
            if (-not $group) { continue }
            if ("$($group.Type)" -eq "M365 Group" -and "$($group.Visibility)" -eq "Public" -and -not $group.Dynamic) {
                $publicM365Groups.Add([pscustomobject]@{
                    Id = $entry.Key
                    Group = $group
                })
            }

            # GRP-005 helper flags: identify unprotected groups used in sensitive contexts.
            $isProtected = $true
            if ($group.Protected -eq $false -or "$($group.Protected)".Trim().ToLowerInvariant() -eq "false") {
                $isProtected = $false
            }
            if (-not $isProtected) {
                $capsCount = Get-IntSafe $group.CAPs
                $entraRolesCount = Get-IntSafe $group.EntraRoles
                $azureRolesCount = Get-IntSafe $group.AzureRoles
                $azureMaxTierNormalized = Get-NormalizedRoleTierLabel -RoleTier $group.AzureMaxTier

                $hasCapsUsage = $capsCount -gt 0
                $hasEntraRolesUsage = $entraRolesCount -gt 0
                $hasAzureRolesUsage = $azureRolesCount -gt 0 -and @("0", "1", "Uncategorized") -contains $azureMaxTierNormalized

                if ($hasCapsUsage -or $hasEntraRolesUsage -or $hasAzureRolesUsage) {
                    $unprotectedSensitiveGroups.Add([pscustomobject]@{
                        Id = $entry.Key
                        Group = $group
                        HasCapsUsage = $hasCapsUsage
                        HasAzureRolesUsage = $hasAzureRolesUsage
                        HasEntraRolesUsage = $hasEntraRolesUsage
                    })
                }
            }

            $isDynamicGroup = $false
            if ($group.Dynamic -eq $true -or "$($group.Dynamic)".Trim().ToLowerInvariant() -eq "true") {
                $isDynamicGroup = $true
            }

            if ($isDynamicGroup) {
                $membershipRuleText = "$($group.MembershipRule)"
                if ([string]::IsNullOrWhiteSpace($membershipRuleText)) { continue }

                $matchedAttributes = [System.Collections.Generic.List[string]]::new()

                # Always risky: attributes users can change via Graph API.
                if ($membershipRuleText -match "(?i)\buser\.preferredlanguage\b") { $matchedAttributes.Add("user.preferredLanguage") }
                if ($membershipRuleText -match "(?i)\buser\.mobilephone\b") { $matchedAttributes.Add("user.mobilePhone") }
                if ($membershipRuleText -match "(?i)\buser\.businessphones\b") { $matchedAttributes.Add("user.businessPhones") }

                # Invite-dependent risk: only relevant when guest invitations are allowed.
                if ($checkGuestInviteLinkedAttributes) {
                    if ($membershipRuleText -match "(?i)\buser\.userprincipalname\b") { $matchedAttributes.Add("user.userPrincipalName") }
                    if ($membershipRuleText -match "(?i)\buser\.mail\b") { $matchedAttributes.Add("user.mail") }
                }

                if ($matchedAttributes.Count -gt 0) {
                    foreach ($attributeName in $matchedAttributes) {
                        if ($dangerousDynamicAttributeCounts.Contains($attributeName)) {
                            $dangerousDynamicAttributeCounts[$attributeName] = [int]$dangerousDynamicAttributeCounts[$attributeName] + 1
                        }
                    }

                    $dynamicGroupsWithDangerousRules.Add([pscustomobject]@{
                        Id = $entry.Key
                        Group = $group
                        MatchedAttributes = @($matchedAttributes)
                    })
                }
            }
        }
    }

    #endregion

    #region Enumeration: Managed Identities
    # MAI-001/MAI-002/MAI-003: Reuse a single pass over managed identities.
    $managedIdentitiesWithApi = [System.Collections.Generic.List[object]]::new()
    $managedIdentitiesWithPrivRoles = [System.Collections.Generic.List[object]]::new()
    $managedIdentitiesWithAzurePrivRoles = [System.Collections.Generic.List[object]]::new()
    $managedIdentityCount = 0
    if ($ManagedIdentities) {
        write-host "[*] Analyzing Managed Identities"
        foreach ($entry in $ManagedIdentities.GetEnumerator()) {
            $app = $entry.Value
            if (-not $app) { continue }
            $managedIdentityCount += 1
            # Normalize API counters to avoid nulls and string values.
            $apiDangerous = 0
            $apiHigh = 0
            $apiMedium = 0
            if ($null -ne $app.ApiDangerous) { [int]::TryParse("$($app.ApiDangerous)", [ref]$apiDangerous) | Out-Null }
            if ($null -ne $app.ApiHigh) { [int]::TryParse("$($app.ApiHigh)", [ref]$apiHigh) | Out-Null }
            if ($null -ne $app.ApiMedium) { [int]::TryParse("$($app.ApiMedium)", [ref]$apiMedium) | Out-Null }
            # Track identities with any elevated API permission counts.
            if (($apiDangerous + $apiHigh + $apiMedium) -gt 0) {
                $managedIdentitiesWithApi.Add($app)
            }

            $roleCount = 0
            if ($null -ne $app.EntraRolesEffective) {
                [int]::TryParse("$($app.EntraRolesEffective)", [ref]$roleCount) | Out-Null
            } elseif ($null -ne $app.EntraRoles) {
                [int]::TryParse("$($app.EntraRoles)", [ref]$roleCount) | Out-Null
            }
            $maxTier = "$($app.EntraMaxTier)"
            # Track identities with tier-0 or tier-1 Entra roles.
            if ($roleCount -gt 0 -and ($maxTier -eq "Tier-0" -or $maxTier -eq "Tier-1")) {
                $managedIdentitiesWithPrivRoles.Add($app)
            }

            $azureMaxTier = "$($app.AzureMaxTier)"
            # Track identities with tier-0 or tier-1 Azure roles.
            if ($azureMaxTier -eq "Tier-0" -or $azureMaxTier -eq "Tier-1") {
                $managedIdentitiesWithAzurePrivRoles.Add($app)
            }

        }
    }

    #endregion

    #region Enumeration: PIM Role Buckets
    # PIM-001/PIM-002/PIM-003/PIM-004/PIM-005/PIM-006/PIM-007/PIM-008/PIM-009: Collect PIM role subsets in one pass for reuse in multiple checks.
    $pimRolesWithEligibleAssignments = [System.Collections.Generic.List[object]]::new()
    $pimTier0LongActivationDuration = [System.Collections.Generic.List[object]]::new()
    $pimTier0MissingJustificationOrTicketing = [System.Collections.Generic.List[object]]::new()
    $pimTier0AllowPermanentActiveAssignments = [System.Collections.Generic.List[object]]::new()
    $pimTier0WithoutActiveAssignmentJustification = [System.Collections.Generic.List[object]]::new()
    $pimTier0WithoutActiveAssignmentMfa = [System.Collections.Generic.List[object]]::new()
    $pimTier0WithoutAllNotifications = [System.Collections.Generic.List[object]]::new()
    $pimTier0WithoutApprovalAndStrongReauth = [System.Collections.Generic.List[object]]::new()
    if ($PimforEntraRoles) {
        write-host "[*] Analyzing PIM for Entra Assignments"
        foreach ($entry in $PimforEntraRoles.GetEnumerator()) {
            $roleConfig = $entry.Value
            if (-not $roleConfig) { continue }
            $eligibleCount = 0
            $activationDurationHours = 0.0
            $requiresJustification = $false
            $requiresTicketing = $false
            $activeAssignmentsExpire = $false
            $isGlobalAdministrator = $false
            $requiresActiveAssignmentJustification = $false
            $requiresActiveAssignmentMfa = $false
            $alertAssignEligible = $false
            $alertAssignActive = $false
            $alertActivation = $false
            $requiresActivationApproval = $false
            $usesActivationAuthContext = $false
            $linkedCapsCount = 0
            $linkedCapsHaveIssues = $false
            if ($null -ne $roleConfig.Eligible) { [int]::TryParse("$($roleConfig.Eligible)", [ref]$eligibleCount) | Out-Null }
            if ($null -ne $roleConfig.ActivationDuration) {
                try { $activationDurationHours = [double]$roleConfig.ActivationDuration } catch { $activationDurationHours = 0.0 }
            }
            if ($null -ne $roleConfig.ActivationJustification) {
                try { $requiresJustification = [System.Convert]::ToBoolean($roleConfig.ActivationJustification) } catch { $requiresJustification = $false }
            }
            if ($null -ne $roleConfig.ActivationTicketing) {
                try { $requiresTicketing = [System.Convert]::ToBoolean($roleConfig.ActivationTicketing) } catch { $requiresTicketing = $false }
            }
            if ($null -ne $roleConfig.ActiveExpiration) {
                try { $activeAssignmentsExpire = [System.Convert]::ToBoolean($roleConfig.ActiveExpiration) } catch { $activeAssignmentsExpire = $false }
            }
            if ($null -ne $roleConfig.ActiveAssignJustification) {
                try { $requiresActiveAssignmentJustification = [System.Convert]::ToBoolean($roleConfig.ActiveAssignJustification) } catch { $requiresActiveAssignmentJustification = $false }
            }
            if ($null -ne $roleConfig.ActiveAssignMFA) {
                try { $requiresActiveAssignmentMfa = [System.Convert]::ToBoolean($roleConfig.ActiveAssignMFA) } catch { $requiresActiveAssignmentMfa = $false }
            }
            if ($null -ne $roleConfig.AlertAssignEligible) {
                try { $alertAssignEligible = [System.Convert]::ToBoolean($roleConfig.AlertAssignEligible) } catch { $alertAssignEligible = $false }
            }
            if ($null -ne $roleConfig.AlertAssignActive) {
                try { $alertAssignActive = [System.Convert]::ToBoolean($roleConfig.AlertAssignActive) } catch { $alertAssignActive = $false }
            }
            if ($null -ne $roleConfig.AlertActivation) {
                try { $alertActivation = [System.Convert]::ToBoolean($roleConfig.AlertActivation) } catch { $alertActivation = $false }
            }
            if ($null -ne $roleConfig.ActivationApproval) {
                try { $requiresActivationApproval = [System.Convert]::ToBoolean($roleConfig.ActivationApproval) } catch { $requiresActivationApproval = $false }
            }
            if ($null -ne $roleConfig.ActivationAuthContext) {
                try { $usesActivationAuthContext = [System.Convert]::ToBoolean($roleConfig.ActivationAuthContext) } catch { $usesActivationAuthContext = $false }
            }
            if ($null -ne $roleConfig.LinkedCaps) { [int]::TryParse("$($roleConfig.LinkedCaps)", [ref]$linkedCapsCount) | Out-Null }
            if ($null -ne $roleConfig.LinkedCapsDetails) {
                $linkedCapDetails = @()
                if ($roleConfig.LinkedCapsDetails -is [System.Collections.IEnumerable] -and -not ($roleConfig.LinkedCapsDetails -is [string])) {
                    $linkedCapDetails = @($roleConfig.LinkedCapsDetails)
                } else {
                    $linkedCapDetails = @($roleConfig.LinkedCapsDetails)
                }
                foreach ($capDetail in $linkedCapDetails) {
                    if (-not $capDetail) { continue }
                    $issueItems = @()
                    if ($null -ne $capDetail.Issues) {
                        if ($capDetail.Issues -is [System.Collections.IEnumerable] -and -not ($capDetail.Issues -is [string])) {
                            $issueItems = @($capDetail.Issues)
                        } else {
                            $issueItems = @($capDetail.Issues)
                        }
                    }
                    foreach ($issue in $issueItems) {
                        $issueText = "$issue".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($issueText) -and $issueText -ne "-") {
                            $linkedCapsHaveIssues = $true
                            break
                        }
                    }
                    if ($linkedCapsHaveIssues) { break }
                }
            }
            $isGlobalAdministrator = ("$($roleConfig.Role)" -ieq "Global Administrator")
            if ($eligibleCount -gt 0) {
                $pimRolesWithEligibleAssignments.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and $eligibleCount -gt 0 -and $activationDurationHours -gt 4.0) {
                $pimTier0LongActivationDuration.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and $eligibleCount -gt 0 -and (-not $requiresJustification) -and (-not $requiresTicketing)) {
                $pimTier0MissingJustificationOrTicketing.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and (-not $isGlobalAdministrator) -and (-not $activeAssignmentsExpire)) {
                $pimTier0AllowPermanentActiveAssignments.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and (-not $requiresActiveAssignmentJustification)) {
                $pimTier0WithoutActiveAssignmentJustification.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and (-not $requiresActiveAssignmentMfa)) {
                $pimTier0WithoutActiveAssignmentMfa.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and ((-not $alertAssignEligible) -or (-not $alertAssignActive) -or (-not $alertActivation))) {
                $pimTier0WithoutAllNotifications.Add($roleConfig)
            }
            if ("$($roleConfig.Tier)" -eq "Tier-0" -and $eligibleCount -gt 0 -and (-not $requiresActivationApproval) -and ((-not $usesActivationAuthContext) -or $linkedCapsCount -eq 0 -or $linkedCapsHaveIssues)) {
                $pimTier0WithoutApprovalAndStrongReauth.Add($roleConfig)
            }
        }
    }

    #endregion

    #region CAP Evaluation: Candidate Selection
    # CAP-001 / CAP-002 / CAP-003 / CAP-004 / CAP-005 / CAP-006 / CAP-007 / CAP-008 / CAP-009 / CAP-010 / CAP-011: Evaluate all Conditional Access policies once and apply per-finding checks.
    # CAP-001 target: AuthFlow contains deviceCodeFlow
    # CAP-002 target: UserActions contains urn:user:registersecurityinfo
    # CAP-003 target: AppTypes contains exchangeActiveSync + other only (no all/browser/mobileAppsAndDesktopClients)
    # CAP-004 target: UserActions contains urn:user:registerdevice
    # CAP-005 target: AuthContext = 0 and AuthStrengthId is not empty, with SignInRisk = 0, UserRisk = 0, AuthFlow empty, UserActions empty
    # CAP-006 target: SignInRisk > 0 and UserRisk > 0
    # CAP-007 target: SignInRisk > 0 and UserRisk = 0
    # CAP-008 target: SignInRisk = 0 and UserRisk > 0
    # CAP-009 target: MFA/auth strength policy without risk/auth-context/auth-flow/user-action conditions
    # CAP-010 target: Enabled policy with at least five included roles and at least one missing used role
    # CAP-011 target: Enabled policy with one or more scoped roles
    $cap001Candidates = [System.Collections.Generic.List[object]]::new()
    $cap001HardPass = [System.Collections.Generic.List[object]]::new()
    $cap001SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap001HardIssueCounts = @{}
    $cap001SoftIssueCounts = @{}
    $cap001ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AuthFlow=deviceCodeFlow&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap001HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AuthFlow=deviceCodeFlow&State=enabled&GrantControls=block&IncResources=all&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncExternals=%3E0&or_IncRoles=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

    $cap002Candidates = [System.Collections.Generic.List[object]]::new()
    $cap002HardPass = [System.Collections.Generic.List[object]]::new()
    $cap002SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap002HardIssueCounts = @{}
    $cap002SoftIssueCounts = @{}
    $cap002ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?UserActions=urn:user:registersecurityinfo&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap002HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?UserActions=urn%3Auser%3Aregistersecurityinfo&State=enabled&GrantControls=block%7C%7CdomainJoinedDevice%7C%7CcompliantDevice&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncExternals=%3E0&or_IncRoles=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

    $cap003Candidates = [System.Collections.Generic.List[object]]::new()
    $cap003HardPass = [System.Collections.Generic.List[object]]::new()
    $cap003SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap003HardIssueCounts = @{}
    $cap003SoftIssueCounts = @{}
    $cap003ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AppTypes=%3DexchangeActiveSync%2C+other&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap003HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AppTypes=%3DexchangeActiveSync%2C+other&State=enabled&GrantControls=block&IncResources=all&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncExternals=%3E0&or_IncRoles=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

    $cap004Candidates = [System.Collections.Generic.List[object]]::new()
    $cap004HardPass = [System.Collections.Generic.List[object]]::new()
    $cap004SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap004HardIssueCounts = @{}
    $cap004SoftIssueCounts = @{}
    $cap004ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?UserActions=urn%3Auser%3Aregisterdevice&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap004HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?UserActions=urn%3Auser%3Aregisterdevice&State=enabled&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

    $cap005Candidates = [System.Collections.Generic.List[object]]::new()
    $cap005HardPass = [System.Collections.Generic.List[object]]::new()
    $cap005SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap005HardIssueCounts = @{}
    $cap005SoftIssueCounts = @{}
    $cap005ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AuthStrength=%21%3Dempty&AuthContext=%3D0&SignInRisk=%3D0&UserRisk=%3D0&AuthFlow=%3Dempty&UserActions=%3Dempty&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap005HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AuthStrength=%21%3Dempty&AuthContext=%3D0&SignInRisk=%3D0&UserRisk=%3D0&AuthFlow=%3Dempty&UserActions=%3Dempty&State=enabled&IncResources=all&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncRoles=%3E0&or_IncExternals=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap005SecureReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AuthStrength=%21%3Dempty&AuthContext=%3D0&SignInRisk=%3D0&UserRisk=%3D0&AuthFlow=%3Dempty&UserActions=%3Dempty&State=enabled&IncResources=all&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncRoles=%3E0&or_IncExternals=%3E0&ExcUsersViaGroups=%3C3&ExcUsers=%3C3&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"

    $cap006Candidates = [System.Collections.Generic.List[object]]::new()
    $cap006ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SignInRisk=%3E0&UserRisk=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

    $cap007Candidates = [System.Collections.Generic.List[object]]::new()
    $cap007HardPass = [System.Collections.Generic.List[object]]::new()
    $cap007SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap007HardIssueCounts = @{}
    $cap007SoftIssueCounts = @{}
    $cap007ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SignInRisk=%3E0&UserRisk=%3D0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CSignInFrequencyInterval%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap007HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SignInRisk=%3E0&UserRisk=%3D0&State=%3Denabled&IncResources=all&or_GrantControls=block%7C%7Cmfa&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CSignInFrequencyInterval%2CAuthStrength%2CWarnings#conditional-access-policies-details"

    $cap008Candidates = [System.Collections.Generic.List[object]]::new()
    $cap008HardPass = [System.Collections.Generic.List[object]]::new()
    $cap008SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap008HardIssueCounts = @{}
    $cap008SoftIssueCounts = @{}
    $cap008ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SignInRisk=%3D0&UserRisk=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CSignInFrequencyInterval%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap008HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SignInRisk=%3D0&UserRisk=%3E0&State=%3Denabled&IncResources=all&or_GrantControls=block%7C%7Cmfa%7C%7CpasswordChange%7C%7CriskRemediation&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CSignInFrequencyInterval%2CAuthStrength%2CWarnings#conditional-access-policies-details"

    $cap009Candidates = [System.Collections.Generic.List[object]]::new()
    $cap009HardPass = [System.Collections.Generic.List[object]]::new()
    $cap009SoftPass = [System.Collections.Generic.List[object]]::new()
    $cap009HardIssueCounts = @{}
    $cap009SoftIssueCounts = @{}
    $cap009ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?or_GrantControls=mfa&or_AuthStrength=%21%3Dempty&AuthContext=0&SignInRisk=0&UserRisk=0&AuthFlow=%3Dempty&UserActions=%3Dempty&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap009HardPassReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?or_GrantControls=mfa&or_AuthStrength=%21%3Dempty&AuthContext=0&SignInRisk=0&UserRisk=0&AuthFlow=%3Dempty&UserActions=%3Dempty&State=%3Denabled&IncResources=%3DAll&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings#conditional-access-policies-details"
    $cap010Candidates = [System.Collections.Generic.List[object]]::new()
    $cap010ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?State=enabled&IncRoles=%3E%3D5&Warnings=missing+used+roles&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings"
    $cap011Candidates = [System.Collections.Generic.List[object]]::new()
    $cap011ReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?State=enabled&IncRoles=%3E0&Warnings=scoped&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CAuthContext%2CIncUsers%2CExcUsers%2CIncGroups%2CExcGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CSignInRisk%2CUserRisk%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CAuthStrength%2CWarnings"

    if ($AllCaps) {
        write-host "[*] Analyzing Conditional Access Policies"
        foreach ($entry in $AllCaps.GetEnumerator()) {
            $policy = $entry.Value
            if (-not $policy) { continue }

            # CAP-001 hard checks.
            if (Test-ContainsToken -Value $policy.AuthFlow -Token "deviceCodeFlow") {
                $cap001Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if (-not (Test-ContainsToken -Value $policy.GrantControls -Token "block")) {
                    $hardIssues.Add("missing block grant control")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }
                $hasIncludedTargets = $false
                $incUsersText = "$($policy.IncUsers)".Trim().ToLowerInvariant()
                if ($incUsersText -eq "all" -or (Get-IntSafe $policy.IncUsers) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncGroups) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncExternals) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncRoles) -gt 0) { $hasIncludedTargets = $true }
                if (-not $hasIncludedTargets) {
                    $hardIssues.Add("missing included users, groups, roles, or externals")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap001HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-001" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap001HardIssueCounts.ContainsKey($issue)) {
                            $cap001HardIssueCounts[$issue] = (Get-IntSafe $cap001HardIssueCounts[$issue]) + 1
                        } else {
                            $cap001HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-002 hard checks.
            if (Test-ContainsToken -Value $policy.UserActions -Token "urn:user:registersecurityinfo") {
                $cap002Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                $hasGrantControl = $false
                foreach ($requiredGrant in @("mfa", "domainJoinedDevice", "compliantDevice", "block")) {
                    if (Test-ContainsToken -Value $policy.GrantControls -Token $requiredGrant) {
                        $hasGrantControl = $true
                        break
                    }
                }
                $hasAuthStrength = -not [string]::IsNullOrWhiteSpace("$($policy.AuthStrength)".Trim()) -and [bool]$policy.AuthStrengthMfaCombinationsOnly
                if (-not ($hasGrantControl -or $hasAuthStrength)) {
                    $hardIssues.Add("missing required grant control (mfa, domainJoinedDevice, compliantDevice, or block) or MFA-enforcing authentication strength")
                }
                $hasIncludedTargets = $false
                $incUsersText = "$($policy.IncUsers)".Trim().ToLowerInvariant()
                if ($incUsersText -eq "all" -or (Get-IntSafe $policy.IncUsers) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncGroups) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncExternals) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncRoles) -gt 0) { $hasIncludedTargets = $true }
                if (-not $hasIncludedTargets) {
                    $hardIssues.Add("missing included users, groups, roles, or externals")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap002HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-002" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap002HardIssueCounts.ContainsKey($issue)) {
                            $cap002HardIssueCounts[$issue] = (Get-IntSafe $cap002HardIssueCounts[$issue]) + 1
                        } else {
                            $cap002HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-003 hard checks.
            $isLegacyPolicy = (Test-ContainsToken -Value $policy.AppTypes -Token "exchangeActiveSync") -and
                (Test-ContainsToken -Value $policy.AppTypes -Token "other") -and
                -not (Test-ContainsToken -Value $policy.AppTypes -Token "all") -and
                -not (Test-ContainsToken -Value $policy.AppTypes -Token "browser") -and
                -not (Test-ContainsToken -Value $policy.AppTypes -Token "mobileAppsAndDesktopClients")
            if ($isLegacyPolicy) {
                $cap003Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if (-not (Test-ContainsToken -Value $policy.GrantControls -Token "block")) {
                    $hardIssues.Add("missing block grant control")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }
                $hasIncludedTargets = $false
                $incUsersText = "$($policy.IncUsers)".Trim().ToLowerInvariant()
                if ($incUsersText -eq "all" -or (Get-IntSafe $policy.IncUsers) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncGroups) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncExternals) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncRoles) -gt 0) { $hasIncludedTargets = $true }
                if (-not $hasIncludedTargets) {
                    $hardIssues.Add("missing included users, groups, roles, or externals")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap003HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-003" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap003HardIssueCounts.ContainsKey($issue)) {
                            $cap003HardIssueCounts[$issue] = (Get-IntSafe $cap003HardIssueCounts[$issue]) + 1
                        } else {
                            $cap003HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-004 hard checks.
            if (Test-ContainsToken -Value $policy.UserActions -Token "urn:user:registerdevice") {
                $cap004Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                $hasMfaGrant = Test-ContainsToken -Value $policy.GrantControls -Token "mfa"
                $hasAuthStrength = -not [string]::IsNullOrWhiteSpace("$($policy.AuthStrength)".Trim()) -and [bool]$policy.AuthStrengthMfaCombinationsOnly
                if (-not ($hasMfaGrant -or $hasAuthStrength)) {
                    $hardIssues.Add("missing mfa grant control or MFA-enforcing authentication strength")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap004HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-004" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap004HardIssueCounts.ContainsKey($issue)) {
                            $cap004HardIssueCounts[$issue] = (Get-IntSafe $cap004HardIssueCounts[$issue]) + 1
                        } else {
                            $cap004HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-005 hard checks.
            $authStrengthId = "$($policy.AuthStrengthId)".Trim()
            $hasNoAuthFlow = [string]::IsNullOrWhiteSpace("$($policy.AuthFlow)".Trim())
            $hasNoUserActions = [string]::IsNullOrWhiteSpace("$($policy.UserActions)".Trim())
            $isAuthStrengthPolicy = (
                ((Get-IntSafe $policy.AuthContext) -eq 0) -and
                ((Get-IntSafe $policy.SignInRisk) -eq 0) -and
                ((Get-IntSafe $policy.UserRisk) -eq 0) -and
                $hasNoAuthFlow -and
                $hasNoUserActions -and
                -not [string]::IsNullOrWhiteSpace($authStrengthId)
            )
            if ($isAuthStrengthPolicy) {
                $cap005Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }

                $authStrengthResolved = $false
                $authStrengthPhishingResistantOnly = $false
                if ($policy.PSObject.Properties.Name -contains "AuthStrengthResolved") {
                    try { $authStrengthResolved = [System.Convert]::ToBoolean($policy.AuthStrengthResolved) } catch { $authStrengthResolved = $false }
                }
                if ($policy.PSObject.Properties.Name -contains "AuthStrengthPhishingResistantOnly") {
                    try { $authStrengthPhishingResistantOnly = [System.Convert]::ToBoolean($policy.AuthStrengthPhishingResistantOnly) } catch { $authStrengthPhishingResistantOnly = $false }
                }
                if (-not $authStrengthResolved) {
                    Write-Log -Level Trace -Message ("[CAP-005] Policy '{0}' ({1}) authStrengthId='{2}' does not expose enough inline detail for validation." -f $policy.DisplayName, $policy.Id, $authStrengthId)
                } else {
                    Write-Log -Level Trace -Message ("[CAP-005] Policy '{0}' ({1}) authStrengthId='{2}' resolved inline with phishingResistantOnly={3}." -f $policy.DisplayName, $policy.Id, $authStrengthId, $authStrengthPhishingResistantOnly)
                }
                if (-not $authStrengthResolved) {
                    $hardIssues.Add("authentication strength lacks enough inline detail for validation")
                } elseif (-not $authStrengthPhishingResistantOnly) {
                    $hardIssues.Add("authentication strength is not phishing-resistant only")
                }

                $hasIncludedTargets = $false
                $incUsersText = "$($policy.IncUsers)".Trim().ToLowerInvariant()
                if ($incUsersText -eq "all" -or (Get-IntSafe $policy.IncUsers) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncGroups) -gt 0) { $hasIncludedTargets = $true }
                if ((Get-IntSafe $policy.IncRoles) -gt 0) { $hasIncludedTargets = $true }
                if (-not $hasIncludedTargets) {
                    $hardIssues.Add("missing included users, groups, or roles")
                }

                if ($hardIssues.Count -eq 0) {
                    $cap005HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-005" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap005HardIssueCounts.ContainsKey($issue)) {
                            $cap005HardIssueCounts[$issue] = (Get-IntSafe $cap005HardIssueCounts[$issue]) + 1
                        } else {
                            $cap005HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-006 check.
            if ((Get-IntSafe $policy.SignInRisk) -gt 0 -and (Get-IntSafe $policy.UserRisk) -gt 0) {
                $cap006Candidates.Add($policy)
            }

            # CAP-007 hard checks.
            if ((Get-IntSafe $policy.SignInRisk) -gt 0 -and (Get-IntSafe $policy.UserRisk) -eq 0) {
                $cap007Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }
                $hasBlockGrant = Test-ContainsToken -Value $policy.GrantControls -Token "block"
                $hasMfaGrant = Test-ContainsToken -Value $policy.GrantControls -Token "mfa"
                $hasAuthStrength = -not [string]::IsNullOrWhiteSpace("$($policy.AuthStrength)".Trim()) -and [bool]$policy.AuthStrengthMfaCombinationsOnly
                $hasGrantOrAuthStrength = $hasBlockGrant -or $hasMfaGrant -or $hasAuthStrength
                if (-not $hasGrantOrAuthStrength) {
                    $hardIssues.Add("missing block/mfa grant control or MFA-enforcing authentication strength")
                }
                if (-not $hasBlockGrant -and "$($policy.SignInFrequencyInterval)".Trim().ToLowerInvariant() -ne "everytime") {
                    $hardIssues.Add("sign-in frequency interval not set to EveryTime")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap007HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-007" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap007HardIssueCounts.ContainsKey($issue)) {
                            $cap007HardIssueCounts[$issue] = (Get-IntSafe $cap007HardIssueCounts[$issue]) + 1
                        } else {
                            $cap007HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-008 hard checks.
            if ((Get-IntSafe $policy.SignInRisk) -eq 0 -and (Get-IntSafe $policy.UserRisk) -gt 0) {
                $cap008Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }
                $hasBlockGrant = Test-ContainsToken -Value $policy.GrantControls -Token "block"
                $hasMfaGrant = Test-ContainsToken -Value $policy.GrantControls -Token "mfa"
                $hasPasswordChangeGrant = Test-ContainsToken -Value $policy.GrantControls -Token "passwordChange"
                $hasRiskRemediationGrant = Test-ContainsToken -Value $policy.GrantControls -Token "riskRemediation"
                $hasAuthStrength = -not [string]::IsNullOrWhiteSpace("$($policy.AuthStrength)".Trim()) -and [bool]$policy.AuthStrengthMfaCombinationsOnly
                $hasGrantOrAuthStrength = $hasBlockGrant -or $hasMfaGrant -or $hasPasswordChangeGrant -or $hasRiskRemediationGrant -or $hasAuthStrength
                if (-not $hasGrantOrAuthStrength) {
                    $hardIssues.Add("missing block/mfa/passwordChange/riskRemediation grant control or MFA-enforcing authentication strength")
                }
                if (-not $hasBlockGrant -and "$($policy.SignInFrequencyInterval)".Trim().ToLowerInvariant() -ne "everytime") {
                    $hardIssues.Add("sign-in frequency interval not set to EveryTime")
                }
                if ($hardIssues.Count -eq 0) {
                    $cap008HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-008" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap008HardIssueCounts.ContainsKey($issue)) {
                            $cap008HardIssueCounts[$issue] = (Get-IntSafe $cap008HardIssueCounts[$issue]) + 1
                        } else {
                            $cap008HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-009 hard checks.
            $mfaBaselineCandidate = $false
            $mfaEquivalentEnforced = $false
            $mfaEvaluationWarning = "$($policy.MfaEvaluationWarning)".Trim()
            if ($policy.PSObject.Properties.Name -contains "MfaBaselineCandidate") {
                try { $mfaBaselineCandidate = [System.Convert]::ToBoolean($policy.MfaBaselineCandidate) } catch { $mfaBaselineCandidate = $false }
            }
            if ($policy.PSObject.Properties.Name -contains "MfaEquivalentEnforced") {
                try { $mfaEquivalentEnforced = [System.Convert]::ToBoolean($policy.MfaEquivalentEnforced) } catch { $mfaEquivalentEnforced = $false }
            }
            $hasNoAuthFlow = [string]::IsNullOrWhiteSpace("$($policy.AuthFlow)".Trim())
            $hasNoUserActions = [string]::IsNullOrWhiteSpace("$($policy.UserActions)".Trim())
            $isMfaBaselinePolicy = $mfaBaselineCandidate -and
                ((Get-IntSafe $policy.SignInRisk) -eq 0) -and
                ((Get-IntSafe $policy.UserRisk) -eq 0) -and
                ((Get-IntSafe $policy.AuthContext) -eq 0) -and
                $hasNoAuthFlow -and
                $hasNoUserActions
            if ($isMfaBaselinePolicy) {
                $cap009Candidates.Add($policy)
                $hardIssues = [System.Collections.Generic.List[string]]::new()
                if ("$($policy.State)".Trim().ToLowerInvariant() -ne "enabled") {
                    $hardIssues.Add("not enabled")
                }
                if ("$($policy.IncResources)".Trim().ToLowerInvariant() -ne "all") {
                    $hardIssues.Add("not targeting all resources")
                }
                if (-not $mfaEquivalentEnforced) {
                    if ([string]::IsNullOrWhiteSpace($mfaEvaluationWarning)) {
                        $hardIssues.Add("mfa-equivalent assurance is not enforced across all grant paths")
                    } else {
                        $hardIssues.Add($mfaEvaluationWarning)
                    }
                }
                if ($hardIssues.Count -eq 0) {
                    $cap009HardPass.Add($policy)
                } else {
                    Write-CapHardFailureTrace -CapId "CAP-009" -Policy $policy -Issues $hardIssues
                    foreach ($issue in $hardIssues) {
                        if ($cap009HardIssueCounts.ContainsKey($issue)) {
                            $cap009HardIssueCounts[$issue] = (Get-IntSafe $cap009HardIssueCounts[$issue]) + 1
                        } else {
                            $cap009HardIssueCounts[$issue] = 1
                        }
                    }
                }
            }

            # CAP-010 selector checks.
            $isEnabledPolicy = ("$($policy.State)".Trim().ToLowerInvariant() -eq "enabled")
            $includedRolesCount = Get-IntSafe $policy.IncRoles
            $missingRolesCount = Get-IntSafe $policy.MissingRolesCount
            if ($isEnabledPolicy -and $includedRolesCount -ge 5 -and $missingRolesCount -ge 1) {
                $cap010Candidates.Add($policy)
            }

            # CAP-011 selector checks.
            $scopedRolesCount = Get-IntSafe $policy.ScopedRolesCount
            if ($isEnabledPolicy -and $scopedRolesCount -ge 1) {
                $cap011Candidates.Add($policy)
            }
        }
    }

    #endregion

    #region CAP Evaluation: Finding Processing
    # CAP-001 processing.
    if ($cap001Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-001] No policy targets deviceCodeFlow."
        Set-FindingOverride -FindingId "CAP-001" -Props $CAP001VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-001" -Props @{
            Description = "<p>No Conditional Access policy targets the device code flow.</p>"
            RelatedReportUrl = $cap001ReportUrl
        }
    } else {
        foreach ($policy in $cap001HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy -AllowGuestExclusions
            if ($softResult.Pass) { $cap001SoftPass.Add($policy) } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap001SoftIssueCounts.ContainsKey($issue)) {
                        $cap001SoftIssueCounts[$issue] = (Get-IntSafe $cap001SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap001SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap001Eval = New-CapUnifiedEvaluation -Candidates $cap001Candidates -HardPass $cap001HardPass -SoftPass $cap001SoftPass
        $cap001Summary = "<p>Policy evaluation summary: <strong>$($cap001Candidates.Count) candidates</strong> ($($cap001Eval.HardFailCount) hard-fail, $($cap001Eval.SoftFailCount) soft-fail, $($cap001Eval.PassCount) pass).</p>"
        $cap001HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap001HardIssueCounts -Title "Hard-check failures"
        $cap001SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap001SoftIssueCounts -Title "Soft-check failures"

        if ($cap001Eval.PassCount -eq 0) {
            if ($cap001HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-001] Device code flow policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-001] Policies passed hard checks, but none passed soft checks."
            }

            $cap001RelatedUrl = if ($cap001HardPass.Count -eq 0) { $cap001ReportUrl } else { $cap001HardPassReportUrl }
            $cap001Props = @{
                Description = "<p>Conditional Access policies target the device code flow, but no policy fully passed hard and soft checks.</p>$cap001Summary$cap001HardIssueSummary$cap001SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
                AffectedObjects = $cap001Eval.AffectedObjects
                RelatedReportUrl = $cap001RelatedUrl
            }
            if ($cap001HardPass.Count -gt 0) {
                $cap001Props.Severity = 2
                $cap001Props.Confidence = "Requires Verification"
            }
            Set-FindingOverride -FindingId "CAP-001" -Props $CAP001VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-001" -Props $cap001Props
        } else {
            Write-Log -Level Verbose -Message "[CAP-001] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-001" -Props $CAP001VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-001" -Props @{
                Description = "<p>At least one Conditional Access policy controlling device code flow passed hard and soft checks.</p>$cap001Summary"
                AffectedObjects = $cap001Eval.AffectedObjects
                RelatedReportUrl = $cap001ReportUrl
            }
        }
    }

    # CAP-002 processing.
    if ($cap002Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-002] No policy targets urn:user:registersecurityinfo."
        Set-FindingOverride -FindingId "CAP-002" -Props $CAP002VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-002" -Props @{
            Description = "<p>There is no conditional access policy which sets conditions for registering security info (MFA factors and SSPR password).</p>"
            RelatedReportUrl = $cap002ReportUrl
        }
    } else {
        foreach ($policy in $cap002HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) { $cap002SoftPass.Add($policy) } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap002SoftIssueCounts.ContainsKey($issue)) {
                        $cap002SoftIssueCounts[$issue] = (Get-IntSafe $cap002SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap002SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap002Eval = New-CapUnifiedEvaluation -Candidates $cap002Candidates -HardPass $cap002HardPass -SoftPass $cap002SoftPass
        $cap002Summary = "<p>Policy evaluation summary: <strong>$($cap002Candidates.Count) candidates</strong> ($($cap002Eval.HardFailCount) hard-fail, $($cap002Eval.SoftFailCount) soft-fail, $($cap002Eval.PassCount) pass).</p>"
        $cap002HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap002HardIssueCounts -Title "Hard-check failures"
        $cap002SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap002SoftIssueCounts -Title "Soft-check failures"

        if ($cap002Eval.PassCount -eq 0) {
            if ($cap002HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-002] Security info registration policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-002] Policies passed hard checks, but none passed soft checks."
            }

            $cap002RelatedUrl = if ($cap002HardPass.Count -eq 0) { $cap002ReportUrl } else { $cap002HardPassReportUrl }
            $cap002Props = @{
                Description = "<p>Conditional Access policies target the registration of security information, but no policy fully passed hard and soft checks.</p>$cap002Summary$cap002HardIssueSummary$cap002SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
                AffectedObjects = $cap002Eval.AffectedObjects
                RelatedReportUrl = $cap002RelatedUrl
            }
            if ($cap002HardPass.Count -gt 0) {
                $cap002Props.Confidence = "Requires Verification"
            }
            Set-FindingOverride -FindingId "CAP-002" -Props $CAP002VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-002" -Props $cap002Props
        } else {
            Write-Log -Level Verbose -Message "[CAP-002] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-002" -Props $CAP002VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-002" -Props @{
                Description = "<p>At least one Conditional Access policy controlling security info registration passed hard and soft checks.</p>$cap002Summary"
                AffectedObjects = $cap002Eval.AffectedObjects
                RelatedReportUrl = $cap002ReportUrl
            }
        }
    }

    # CAP-003 processing.
    if ($cap003Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-003] No policy targets legacy authentication app types."
        Set-FindingOverride -FindingId "CAP-003" -Props $CAP003VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-003" -Props @{
            Description = "<p>There is no conditional access policy blocking legacy authentication.</p>"
            RelatedReportUrl = $cap003ReportUrl
        }
    } else {
        foreach ($policy in $cap003HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) {
                $cap003SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap003SoftIssueCounts.ContainsKey($issue)) {
                        $cap003SoftIssueCounts[$issue] = (Get-IntSafe $cap003SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap003SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap003Eval = New-CapUnifiedEvaluation -Candidates $cap003Candidates -HardPass $cap003HardPass -SoftPass $cap003SoftPass
        $cap003Summary = "<p>Policy evaluation summary: <strong>$($cap003Candidates.Count) candidates</strong> ($($cap003Eval.HardFailCount) hard-fail, $($cap003Eval.SoftFailCount) soft-fail, $($cap003Eval.PassCount) pass).</p>"
        $cap003HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap003HardIssueCounts -Title "Hard-check failures"
        $cap003SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap003SoftIssueCounts -Title "Soft-check failures"

        if ($cap003Eval.PassCount -eq 0) {
            if ($cap003HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-003] Legacy authentication policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-003] Policies passed hard checks, but none passed soft checks."
            }

            $cap003RelatedUrl = if ($cap003HardPass.Count -eq 0) { $cap003ReportUrl } else { $cap003HardPassReportUrl }
            $cap003Props = @{
                Description = "<p>Conditional Access policies target legacy authentication, but no policy fully passed hard and soft checks.</p>$cap003Summary$cap003HardIssueSummary$cap003SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
                AffectedObjects = $cap003Eval.AffectedObjects
                RelatedReportUrl = $cap003RelatedUrl
            }
            if ($cap003HardPass.Count -gt 0) {
                $cap003Props.Confidence = "Requires Verification"
            }
            Set-FindingOverride -FindingId "CAP-003" -Props $CAP003VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-003" -Props $cap003Props
        } else {
            Write-Log -Level Verbose -Message "[CAP-003] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-003" -Props $CAP003VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-003" -Props @{
                Description = "<p>At least one Conditional Access policy blocking legacy authentication passed hard and soft checks.</p>$cap003Summary"
                AffectedObjects = $cap003Eval.AffectedObjects
                RelatedReportUrl = $cap003ReportUrl
            }
        }
    }

    # CAP-004 processing.
    if ($cap004Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-004] No policy targets urn:user:registerdevice."
        Set-FindingOverride -FindingId "CAP-004" -Props $CAP004VariantProps.Vulnerable
        if (-not $DeviceSettingsRequireMFAJoinKnown) {
            Set-FindingOverride -FindingId "CAP-004" -Props @{
                Confidence = "Requires Verification"
                Description = "<p>There is no conditional access policy which requires MFA to join or register new devices.</p><p>The device registration policy could not be evaluated with the current authentication flow or token. It is therefore unknown whether MFA is enforced in device settings.</p><p><strong>Important:</strong> Manual verification is required.</p>"
                RelatedReportUrl = $cap004ReportUrl
            }
        } elseif (-not $DeviceSettingsRequireMFAJoin) {
            Set-FindingOverride -FindingId "CAP-004" -Props @{
                Description = "<p>There is no conditional access policy which requires MFA to join or register new devices.</p><p>Furthermore, MFA is not enforced in the device settings.</p>"
                RelatedReportUrl = $cap004ReportUrl
            }
        } else {
            Set-FindingOverride -FindingId "CAP-004" -Props @{
                Severity = 0
                Description = "<p>There is no conditional access policy which requires MFA to join or register new devices.</p><p>However, MFA is enforced in the device settings.</p><p>Microsoft recommends implementing this requirement through a Conditional Access policy rather than relying on device settings.</p>"
                RelatedReportUrl = $cap004ReportUrl
            }
        }
    } else {
        foreach ($policy in $cap004HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) {
                $cap004SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap004SoftIssueCounts.ContainsKey($issue)) {
                        $cap004SoftIssueCounts[$issue] = (Get-IntSafe $cap004SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap004SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap004Eval = New-CapUnifiedEvaluation -Candidates $cap004Candidates -HardPass $cap004HardPass -SoftPass $cap004SoftPass
        $cap004Summary = "<p>Policy evaluation summary: <strong>$($cap004Candidates.Count) candidates</strong> ($($cap004Eval.HardFailCount) hard-fail, $($cap004Eval.SoftFailCount) soft-fail, $($cap004Eval.PassCount) pass).</p>"
        $cap004HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap004HardIssueCounts -Title "Hard-check failures"
        $cap004SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap004SoftIssueCounts -Title "Soft-check failures"
        $cap004SecureReportUrl = "ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?UserActions=urn%3Auser%3Aregisterdevice&State=enabled&or_IncUsers=%3E0%7C%7Call&or_IncGroups=%3E0&or_IncExternals=%3E0&or_IncRoles=%3E0&columns=DisplayName%2CUserCoverage%2CState%2CIncResources%2CExcResources%2CIncUsers%2CExcUsers%2CIncGroups%2CIncUsersViaGroups%2CExcGroups%2CExcUsersViaGroups%2CIncRoles%2CIncUsersViaRoles%2CExcRoles%2CExcUsersViaRoles%2CIncExternals%2CExcExternals%2CDeviceFilter%2CIncPlatforms%2CExcPlatforms%2CIncNw%2CExcNw%2CAppTypes%2CAuthFlow%2CUserActions%2CGrantControls%2CSessionControls%2CWarnings#conditional-access-policies-details"

        if ($cap004Eval.PassCount -eq 0) {
            if ($cap004HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-004] Device registration policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-004] Policies passed hard checks, but none passed soft checks."
            }

            $cap004RelatedUrl = if ($cap004HardPass.Count -eq 0) { $cap004ReportUrl } else { $cap004HardPassReportUrl }
            $cap004DescriptionBase = "<p>Conditional Access policies target joining or registering of devices, but no policy fully passed hard and soft checks.</p>$cap004Summary$cap004HardIssueSummary$cap004SoftIssueSummary"
            $cap004ImportantLayered = "<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"

            Set-FindingOverride -FindingId "CAP-004" -Props $CAP004VariantProps.Vulnerable
            if (-not $DeviceSettingsRequireMFAJoinKnown) {
                $cap004Description = "$cap004DescriptionBase<p>The device registration policy could not be evaluated with the current authentication flow or token. It is therefore unknown whether MFA is enforced in device settings.</p><p><strong>Important:</strong> Manual verification is required.</p>"
                if ($cap004HardPass.Count -gt 0) {
                    $cap004Description = "$cap004Description$cap004ImportantLayered"
                }
                Set-FindingOverride -FindingId "CAP-004" -Props @{
                    Confidence = "Requires Verification"
                    Description = $cap004Description
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004RelatedUrl
                }
            } elseif (-not $DeviceSettingsRequireMFAJoin) {
                $cap004Description = "$cap004DescriptionBase<p>Furthermore, MFA is not enforced in the device settings.</p>"
                if ($cap004HardPass.Count -gt 0) {
                    $cap004Description = "$cap004Description$cap004ImportantLayered"
                }
                $cap004Props = @{
                    Description = $cap004Description
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004RelatedUrl
                }
                if ($cap004HardPass.Count -gt 0) {
                    $cap004Props.Confidence = "Requires Verification"
                }
                Set-FindingOverride -FindingId "CAP-004" -Props $cap004Props
            } else {
                $cap004Description = "$cap004DescriptionBase<p>However, MFA is enforced in the device settings.</p><p>Microsoft recommends implementing this requirement through a Conditional Access policy rather than relying on device settings.</p>"
                if ($cap004HardPass.Count -gt 0) {
                    $cap004Description = "$cap004Description$cap004ImportantLayered"
                }
                $cap004Props = @{
                    Severity = 0
                    Description = $cap004Description
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004RelatedUrl
                }
                if ($cap004HardPass.Count -gt 0) {
                    $cap004Props.Confidence = "Requires Verification"
                }
                Set-FindingOverride -FindingId "CAP-004" -Props $cap004Props
            }
        } else {
            Write-Log -Level Verbose -Message "[CAP-004] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-004" -Props $CAP004VariantProps.Secure
            if (-not $DeviceSettingsRequireMFAJoinKnown) {
                Set-FindingOverride -FindingId "CAP-004" -Props @{
                    Description = "<p>At least one Conditional Access policy controlling device join or registration passed hard and soft checks.</p>$cap004Summary"
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004SecureReportUrl
                }
            } elseif (-not $DeviceSettingsRequireMFAJoin) {
                Set-FindingOverride -FindingId "CAP-004" -Props @{
                    Description = "<p>At least one Conditional Access policy controlling device join or registration passed hard and soft checks.</p>$cap004Summary"
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004SecureReportUrl
                }
            } else {
                Set-FindingOverride -FindingId "CAP-004" -Props @{
                    Severity = 0
                    Description = "<p>At least one Conditional Access policy controls device join or registration and no issues were identified.</p>$cap004Summary<p>However, MFA for device registration or join is also enforced in the device settings.</p><p>Microsoft recommends disabling the enforcement in the device settings and relying solely on Conditional Access policies.</p>"
                    AffectedObjects = $cap004Eval.AffectedObjects
                    RelatedReportUrl = $cap004SecureReportUrl
                }
            }
        }
    }

    # CAP-005 processing.
    if ($cap005Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-005] No policy enforces an authentication strength."
        Set-FindingOverride -FindingId "CAP-005" -Props $CAP005VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-005" -Props @{
            Description = "<p>There is no Conditional Access policy enforcing an authentication strength.</p>"
            RelatedReportUrl = $cap005ReportUrl
        }
    } else {
        foreach ($policy in $cap005HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy -SkipAllUsersCheck
            if ($softResult.Pass) {
                $cap005SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap005SoftIssueCounts.ContainsKey($issue)) {
                        $cap005SoftIssueCounts[$issue] = (Get-IntSafe $cap005SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap005SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap005Eval = New-CapUnifiedEvaluation -Candidates $cap005Candidates -HardPass $cap005HardPass -SoftPass $cap005SoftPass -ResolveAuthStrength
        $cap005Summary = "<p>Policy evaluation summary: <strong>$($cap005Candidates.Count) candidates</strong> ($($cap005Eval.HardFailCount) hard-fail, $($cap005Eval.SoftFailCount) soft-fail, $($cap005Eval.PassCount) pass).</p>"
        $cap005HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap005HardIssueCounts -Title "Hard-check failures"
        $cap005SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap005SoftIssueCounts -Title "Soft-check failures"

        if ($cap005Eval.PassCount -eq 0) {
            if ($cap005HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-005] Authentication strength policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-005] Policies passed hard checks, but none passed soft checks."
            }

            $cap005RelatedUrl = if ($cap005HardPass.Count -eq 0) { $cap005ReportUrl } else { $cap005HardPassReportUrl }
            $cap005Props = @{
                Description = "<p>Conditional Access policies enforce an authentication strength, but no policy fully passed hard and soft checks.</p>$cap005Summary$cap005HardIssueSummary$cap005SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
                AffectedObjects = $cap005Eval.AffectedObjects
                RelatedReportUrl = $cap005RelatedUrl
            }
            if ($cap005HardPass.Count -gt 0) {
                $cap005Props.Confidence = "Requires Verification"
            }
            Set-FindingOverride -FindingId "CAP-005" -Props $CAP005VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-005" -Props $cap005Props
        } else {
            Write-Log -Level Verbose -Message "[CAP-005] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-005" -Props $CAP005VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-005" -Props @{
                Description = "<p>At least one Conditional Access policy enforcing an authentication strength passed hard and soft checks.</p>$cap005Summary"
                AffectedObjects = $cap005Eval.AffectedObjects
                RelatedReportUrl = $cap005SecureReportUrl
            }
        }
    }

    # CAP-006 processing.
    if ($cap006Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-006] No policy combines sign-in risk and user risk."
        Set-FindingOverride -FindingId "CAP-006" -Props $CAP006VariantProps.Secure
        Set-FindingOverride -FindingId "CAP-006" -Props @{
            RelatedReportUrl = $cap006ReportUrl
        }
    } else {
        # Any combined risk policy is a finding; enabled ones keep severity 3.
        $enabledCombinedPolicies = @($cap006Candidates | Where-Object { "$($_.State)".Trim().ToLowerInvariant() -eq "enabled" })
        $capAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($policy in $cap006Candidates) {
            $capAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($policy.Id)`" target=`"_blank`">$($policy.DisplayName)</a>"
                "State" = $policy.State
                "Sign-In Risk Configs" = $policy.SignInRisk
                "UserRisk Risk Configs" = $policy.UserRisk
                "Warning" = $policy.Warnings
            })
        }
        Set-FindingOverride -FindingId "CAP-006" -Props $CAP006VariantProps.Vulnerable
        if ($enabledCombinedPolicies.Count -gt 0) {
            Set-FindingOverride -FindingId "CAP-006" -Props @{
                Description = "<p>An enabled Conditional Access policy addresses both user risk and sign-in risk within the same policy.</p>"
                AffectedObjects = $capAffected
                RelatedReportUrl = $cap006ReportUrl
            }
        } else {
            $state = "$($cap006Candidates[0].State)"
            if ([string]::IsNullOrWhiteSpace($state)) { $state = "non-enabled" }
            Set-FindingOverride -FindingId "CAP-006" -Props @{
                Severity = 0
                Description = "<p>A $state Conditional Access policy addresses both user risk and sign-in risk within the same policy.</p>"
                AffectedObjects = $capAffected
                RelatedReportUrl = $cap006ReportUrl
            }
        }
    }

    # CAP-007 processing.
    if ($cap007Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-007] No policy targets sign-in risk without user risk."
        Set-FindingOverride -FindingId "CAP-007" -Props $CAP007VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-007" -Props @{
            Description = "<p>No Conditional Access policy targets sign-in risk.</p><p><strong>Important:</strong> This finding requires manual verification. It is not verified whether sign-in risk is managed using the legacy risk policies (scheduled to retire on 1 October 2026).</p>"
            RelatedReportUrl = $cap007ReportUrl
        }
    } else {
        foreach ($policy in $cap007HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) {
                $cap007SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap007SoftIssueCounts.ContainsKey($issue)) {
                        $cap007SoftIssueCounts[$issue] = (Get-IntSafe $cap007SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap007SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap007Eval = New-CapUnifiedEvaluation -Candidates $cap007Candidates -HardPass $cap007HardPass -SoftPass $cap007SoftPass
        $cap007Summary = "<p>Policy evaluation summary: <strong>$($cap007Candidates.Count) candidates</strong> ($($cap007Eval.HardFailCount) hard-fail, $($cap007Eval.SoftFailCount) soft-fail, $($cap007Eval.PassCount) pass).</p>"
        $cap007HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap007HardIssueCounts -Title "Hard-check failures"
        $cap007SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap007SoftIssueCounts -Title "Soft-check failures"
        $cap007LegacyRiskNote = "<p><strong>Note:</strong> It is not verified whether sign-in risk is managed using the legacy risk policies (scheduled to retire on 1 October 2026).</p>"

        if ($cap007Eval.PassCount -eq 0) {
            if ($cap007HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-007] Sign-in risk policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-007] Policies passed hard checks, but none passed soft checks."
            }

            $cap007RelatedUrl = if ($cap007HardPass.Count -eq 0) { $cap007ReportUrl } else { $cap007HardPassReportUrl }
            Set-FindingOverride -FindingId "CAP-007" -Props $CAP007VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-007" -Props @{
                Description = "<p>Conditional Access policies target sign-in risk, but no policy fully passed hard and soft checks.</p>$cap007Summary$cap007HardIssueSummary$cap007SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>$cap007LegacyRiskNote"
                AffectedObjects = $cap007Eval.AffectedObjects
                RelatedReportUrl = $cap007RelatedUrl
            }
        } else {
            Write-Log -Level Verbose -Message "[CAP-007] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-007" -Props $CAP007VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-007" -Props @{
                Description = "<p>At least one Conditional Access policy for sign-in risk passed hard and soft checks.</p>$cap007Summary"
                AffectedObjects = $cap007Eval.AffectedObjects
                RelatedReportUrl = $cap007HardPassReportUrl
            }
        }
    }

    # CAP-008 processing.
    if ($cap008Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-008] No policy targets user risk without sign-in risk."
        Set-FindingOverride -FindingId "CAP-008" -Props $CAP008VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-008" -Props @{
            Description = "<p>No Conditional Access policy targets user risk.</p><p><strong>Important:</strong> This finding requires manual verification. It is not verified whether user risk is managed using the legacy risk policies (scheduled to retire on 1 October 2026).</p>"
            RelatedReportUrl = $cap008ReportUrl
        }
    } else {
        foreach ($policy in $cap008HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) {
                $cap008SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap008SoftIssueCounts.ContainsKey($issue)) {
                        $cap008SoftIssueCounts[$issue] = (Get-IntSafe $cap008SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap008SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap008Eval = New-CapUnifiedEvaluation -Candidates $cap008Candidates -HardPass $cap008HardPass -SoftPass $cap008SoftPass
        $cap008Summary = "<p>Policy evaluation summary: <strong>$($cap008Candidates.Count) candidates</strong> ($($cap008Eval.HardFailCount) hard-fail, $($cap008Eval.SoftFailCount) soft-fail, $($cap008Eval.PassCount) pass).</p>"
        $cap008HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap008HardIssueCounts -Title "Hard-check failures"
        $cap008SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap008SoftIssueCounts -Title "Soft-check failures"
        $cap008LegacyRiskNote = "<p><strong>Note:</strong> It is not verified whether user risk is managed using the legacy risk policies (scheduled to retire on 1 October 2026).</p>"

        if ($cap008Eval.PassCount -eq 0) {
            if ($cap008HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-008] User risk policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-008] Policies passed hard checks, but none passed soft checks."
            }

            $cap008RelatedUrl = if ($cap008HardPass.Count -eq 0) { $cap008ReportUrl } else { $cap008HardPassReportUrl }
            Set-FindingOverride -FindingId "CAP-008" -Props $CAP008VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-008" -Props @{
                Description = "<p>Conditional Access policies target user risk, but no policy fully passed hard and soft checks.</p>$cap008Summary$cap008HardIssueSummary$cap008SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>$cap008LegacyRiskNote"
                AffectedObjects = $cap008Eval.AffectedObjects
                RelatedReportUrl = $cap008RelatedUrl
            }
        } else {
            Write-Log -Level Verbose -Message "[CAP-008] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-008" -Props $CAP008VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-008" -Props @{
                Description = "<p>At least one Conditional Access policy for user risk passed hard and soft checks.</p>$cap008Summary"
                AffectedObjects = $cap008Eval.AffectedObjects
                RelatedReportUrl = $cap008HardPassReportUrl
            }
        }
    }

    # CAP-009 processing.
    if ($cap009Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-009] No policy enforces basic MFA baseline."
        Set-FindingOverride -FindingId "CAP-009" -Props $CAP009VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-009" -Props @{
            Description = "<p>No Conditional Access enforcing basic MFA.</p>"
            RelatedReportUrl = $cap009ReportUrl
        }
    } else {
        foreach ($policy in $cap009HardPass) {
            $softResult = Test-CapSoftCompliance -Policy $policy
            if ($softResult.Pass) {
                $cap009SoftPass.Add($policy)
            } else {
                foreach ($issue in $softResult.Issues) {
                    if ($cap009SoftIssueCounts.ContainsKey($issue)) {
                        $cap009SoftIssueCounts[$issue] = (Get-IntSafe $cap009SoftIssueCounts[$issue]) + 1
                    } else {
                        $cap009SoftIssueCounts[$issue] = 1
                    }
                }
            }
        }

        $cap009Eval = New-CapUnifiedEvaluation -Candidates $cap009Candidates -HardPass $cap009HardPass -SoftPass $cap009SoftPass
        $cap009Summary = "<p>Policy evaluation summary: <strong>$($cap009Candidates.Count) candidates</strong> ($($cap009Eval.HardFailCount) hard-fail, $($cap009Eval.SoftFailCount) soft-fail, $($cap009Eval.PassCount) pass).</p>"
        $cap009HardIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap009HardIssueCounts -Title "Hard-check failures"
        $cap009SoftIssueSummary = Get-CapIssueSummaryHtml -IssueCounts $cap009SoftIssueCounts -Title "Soft-check failures"

        if ($cap009Eval.PassCount -eq 0) {
            if ($cap009HardPass.Count -eq 0) {
                Write-Log -Level Verbose -Message "[CAP-009] MFA baseline policies found, but no policy passed hard checks."
            } else {
                Write-Log -Level Verbose -Message "[CAP-009] Policies passed hard checks, but none passed soft checks."
            }

            $relatedUrl = if ($cap009HardPass.Count -eq 0) { $cap009ReportUrl } else { $cap009HardPassReportUrl }
            $props = @{
                Description = "<p>Conditional Access policies enforce MFA, but no policy fully passed hard and soft checks.</p>$cap009Summary$cap009HardIssueSummary$cap009SoftIssueSummary<p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
                AffectedObjects = $cap009Eval.AffectedObjects
                RelatedReportUrl = $relatedUrl
            }
            if ($cap009HardPass.Count -gt 0) {
                $props.Confidence = "Requires Verification"
            }
            Set-FindingOverride -FindingId "CAP-009" -Props $CAP009VariantProps.Vulnerable
            Set-FindingOverride -FindingId "CAP-009" -Props $props
        } else {
            Write-Log -Level Verbose -Message "[CAP-009] At least one policy passed hard and soft checks."
            Set-FindingOverride -FindingId "CAP-009" -Props $CAP009VariantProps.Secure
            Set-FindingOverride -FindingId "CAP-009" -Props @{
                Description = "<p>At least one Conditional Access policy enforcing basic MFA passed hard and soft checks.</p>$cap009Summary"
                AffectedObjects = $cap009Eval.AffectedObjects
                RelatedReportUrl = $cap009HardPassReportUrl
            }
        }
    }

    # CAP-010 processing.
    if ($cap010Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-010] No enabled policy targeting at least five roles with missing used roles."
        Set-FindingOverride -FindingId "CAP-010" -Props $CAP010VariantProps.Secure
        Set-FindingOverride -FindingId "CAP-010" -Props @{
            RelatedReportUrl = $cap010ReportUrl
        }
    } else {
        Write-Log -Level Verbose -Message "[CAP-010] Found $($cap010Candidates.Count) enabled policies with missing used Tier-0/Tier-1 roles."
        $cap010Affected = [System.Collections.Generic.List[object]]::new()
        $cap010Tier0MissingPolicies = 0

        foreach ($object in $cap010Candidates) {
            $missingRoleLines = [System.Collections.Generic.List[string]]::new()
            $policyHasTier0Missing = $false
            $missingRoles = @()
            if ($object.MissingRoles) {
                if ($object.MissingRoles -is [System.Collections.IEnumerable] -and -not ($object.MissingRoles -is [string])) {
                    $missingRoles = @($object.MissingRoles)
                } else {
                    $missingRoles = @($object.MissingRoles)
                }
            }

            foreach ($missingRole in $missingRoles) {
                $tierLabel = Get-NormalizedRoleTierLabel -RoleTier $missingRole.RoleTier
                if ($tierLabel -eq "0") { $policyHasTier0Missing = $true }
                $tierText = "Tier-$tierLabel"
                $roleName = "$($missingRole.RoleName)".Trim()
                if ([string]::IsNullOrWhiteSpace($roleName)) { $roleName = "Unknown role" }
                $assignmentCount = Get-IntSafe $missingRole.Assignments
                $assignmentLabel = if ($assignmentCount -eq 1) { "assignment" } else { "assignments" }
                $missingRoleLines.Add("$tierText : $roleName ($assignmentCount $assignmentLabel)")
            }

            if ($policyHasTier0Missing) { $cap010Tier0MissingPolicies += 1 }
            $missingRolesDisplay = if ($missingRoleLines.Count -gt 0) {
                ($missingRoleLines -join "<br>")
            } else {
                "$($object.MissingRolesCount)"
            }

            $cap010Affected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.DisplayName)</a>"
                "State" = $object.State
                "Grant Controls" = $object.GrantControls
                "Included Roles" = $object.IncRoles
                "Missing Roles" = $missingRolesDisplay
            })
        }

        $cap010Description = "<p>There are $($cap010Candidates.Count) Conditional Access policies targeting five or more roles but not including some Tier-0 or Tier-1 roles that have assignments.</p><p><strong>Important:</strong> This finding requires manual verification. The effective access decision depends on the combined evaluation of multiple Conditional Access policies. Automated checks may not fully account for all cases (e.g., layered controls).</p>"
        $cap010Severity = 2
        if ($cap010Tier0MissingPolicies -gt 0) {
            $cap010Severity = 3
            $cap010Description = "$cap010Description<p><strong>Note:</strong> $cap010Tier0MissingPolicies policies have missing Tier-0 roles.</p>"
        }

        Set-FindingOverride -FindingId "CAP-010" -Props $CAP010VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-010" -Props @{
            Severity = $cap010Severity
            Description = $cap010Description
            AffectedObjects = $cap010Affected
            RelatedReportUrl = $cap010ReportUrl
        }
    }

    # CAP-011 processing.
    if ($cap011Candidates.Count -eq 0) {
        Write-Log -Level Verbose -Message "[CAP-011] No enabled policies target roles with scoped assignments."
        Set-FindingOverride -FindingId "CAP-011" -Props $CAP011VariantProps.Secure
        Set-FindingOverride -FindingId "CAP-011" -Props @{
            Description = "<p>No enabled Conditional Access policies were identified that target roles with scoped assignments.</p>"
            RelatedReportUrl = $cap011ReportUrl
        }
    } else {
        Write-Log -Level Verbose -Message "[CAP-011] Found $($cap011Candidates.Count) enabled policies targeting roles with scoped assignments."
        $cap011Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $cap011Candidates) {
            $scopedRoleLines = [System.Collections.Generic.List[string]]::new()
            $scopedRoles = @()
            if ($object.ScopedRoles) {
                if ($object.ScopedRoles -is [System.Collections.IEnumerable] -and -not ($object.ScopedRoles -is [string])) {
                    $scopedRoles = @($object.ScopedRoles)
                } else {
                    $scopedRoles = @($object.ScopedRoles)
                }
            }

            foreach ($scopedRole in $scopedRoles) {
                $tierLabel = Get-NormalizedRoleTierLabel -RoleTier $scopedRole.RoleTier
                $tierText = "Tier-$tierLabel"
                $roleName = "$($scopedRole.RoleName)".Trim()
                if ([string]::IsNullOrWhiteSpace($roleName)) { $roleName = "Unknown role" }
                $assignmentCount = Get-IntSafe $scopedRole.Assignments
                $scopedRoleLines.Add("$tierText : $roleName ($assignmentCount scoped assignments)")
            }

            $scopedRolesDisplay = if ($scopedRoleLines.Count -gt 0) {
                ($scopedRoleLines -join "<br>")
            } else {
                "$($object.ScopedRolesCount)"
            }

            $cap011Affected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.DisplayName)</a>"
                "State" = $object.State
                "Grant Controls" = $object.GrantControls
                "Included Roles" = $object.IncRoles
                "Roles With Scoped Assignments" = $scopedRolesDisplay
            })
        }

        Set-FindingOverride -FindingId "CAP-011" -Props $CAP011VariantProps.Vulnerable
        Set-FindingOverride -FindingId "CAP-011" -Props @{
            Description = "<p>There are $($cap011Candidates.Count) enabled Conditional Access policies targeting some roles that have scoped assignments.</p><p>Conditional Access policies do not support users whose directory role assignments are scoped to specific objects (for example, Administrative Units or applications).</p>"
            AffectedObjects = $cap011Affected
            RelatedReportUrl = $cap011ReportUrl
        }
    }

    # CAP post-processing: remove report links when no affected objects are present.
    # This avoids rendering an "Affected Objects" action section with no object rows.
    $capFindingIds = @(
        "CAP-001","CAP-002","CAP-003","CAP-004","CAP-005","CAP-006",
        "CAP-007","CAP-008","CAP-009","CAP-010","CAP-011"
    )
    foreach ($capFindingId in $capFindingIds) {
        if (-not $FindingsById.ContainsKey($capFindingId)) { continue }
        $capFinding = $FindingsById[$capFindingId]
        $affectedObjects = @($capFinding.AffectedObjects)
        if ($affectedObjects.Count -gt 0 -and @($affectedObjects | Where-Object { $_.PSObject.Properties.Name -contains "_SortEvaluationRank" }).Count -gt 0) {
            Set-FindingOverride -FindingId $capFindingId -Props @{
                AffectedSortKey = "_SortEvaluationRank"
                AffectedSortDir = "ASC"
            }
        }
        if ($affectedObjects.Count -eq 0) {
            Set-FindingOverride -FindingId $capFindingId -Props @{
                RelatedReportUrl = ""
            }
        }
    }

    #endregion

    #region ENT Evaluation
    # ENT-001: Apply result for apps with client credentials.
    if ($entAppsWithSecrets.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-001] Found $($entAppsWithSecrets.Count) enterprise apps with client credentials."
        Set-FindingOverride -FindingId "ENT-001" -Props $ENT001VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-001" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Credentials=%3E0&SAML=%3Dfalse&columns=DisplayName%2CPublisherName%2CForeign%2CSAML%2CCredentials%2CGrpMem%2CGrpOwn%2CAppOwn%2CSpOwn%2CEntraRoles%2CAzureRoles%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CApiDelegated%2CImpact%2CLikelihood%2CRisk%2CWarnings#enterprise-applications-details"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $entAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsWithSecrets) {
            $credentialLines = [System.Collections.Generic.List[string]]::new()
            $credentialDetails = @()
            if ($app.AppCredentialsDetails) {
                if ($app.AppCredentialsDetails -is [System.Collections.IEnumerable] -and -not ($app.AppCredentialsDetails -is [string])) {
                    $credentialDetails = @($app.AppCredentialsDetails)
                } else {
                    $credentialDetails = @($app.AppCredentialsDetails)
                }
            }
            foreach ($credType in @("Secret", "Certificate")) {
                foreach ($cred in $credentialDetails) {
                    if ($cred.Type -ne $credType) { continue }
                    $name = Get-CredentialDisplayName -Credential $cred -FallbackLabel "-"
                    $start = $cred.StartDateTime
                    $end = $cred.EndDateTime
                    if ($start) {
                        if ($start -is [datetime]) {
                            $start = $start.ToString("yyyy-MM-dd")
                        } else {
                            $startText = "$start"
                            if ($startText -match "^\d{4}-\d{2}-\d{2}") {
                                $start = $startText.Substring(0, 10)
                            } else {
                                try { $start = ([datetime]$startText).ToString("yyyy-MM-dd") } catch {}
                            }
                        }
                    }
                    if ($end) {
                        if ($end -is [datetime]) {
                            $end = $end.ToString("yyyy-MM-dd")
                        } else {
                            $endText = "$end"
                            if ($endText -match "^\d{4}-\d{2}-\d{2}") {
                                $end = $endText.Substring(0, 10)
                            } else {
                                try { $end = ([datetime]$endText).ToString("yyyy-MM-dd") } catch {}
                            }
                        }
                    }
                    $dateSuffix = ""
                    if ($start -and $end) {
                        $dateSuffix = " ($start - $end)"
                    } elseif ($start) {
                        $dateSuffix = " (from $start)"
                    } elseif ($end) {
                        $dateSuffix = " (until $end)"
                    }
                    if ($name) {
                        $credentialLines.Add("$credType : $name$dateSuffix")
                    }
                }
            }
            $credentialDisplay = if ($credentialLines.Count -gt 0) { ($credentialLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $entAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Credential Count" = $app.Credentials
                "Last sign-in (days)" = $app.LastSignInDays
                "Credentials" = $credentialDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-001" -Props @{
            Description = "<p>$($entAppsWithSecrets.Count) enabled enterprise applications were identified that are not configured for SAML and have at least one client secret.</p>"
            AffectedObjects = $entAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-001] No enterprise apps with client credentials found."
        Set-FindingOverride -FindingId "ENT-001" -Props $ENT001VariantProps.Secure
    }

    # ENT-002: Apply result for inactive enabled apps.
    if ($entAppsInactiveEnabled.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-002] Found $($entAppsInactiveEnabled.Count) inactive enterprise apps that are enabled."
        Set-FindingOverride -FindingId "ENT-002" -Props $ENT002VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-002" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Inactive=%3Dtrue&Enabled=%3Dtrue&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2COwners%2CGrpMem%2CGrpOwn%2CAppOwn%2CSpOwn%2CEntraRoles%2CAzureRoles%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CApiDelegated%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=LastSignInDays&sortDir=desc"
            AffectedSortKey = "Last sign-in (days)"
            AffectedSortDir = "DESC"
        }
        $entInactiveAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsInactiveEnabled) {
            $entInactiveAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Inactive" = $app.Inactive
                "Last sign-in (days)" = $app.LastSignInDays
                "Foreign Application" = $app.Foreign
                "Publisher Name" = $app.PublisherName
            })
        }
        Set-FindingOverride -FindingId "ENT-002" -Props @{
            Description = "<p>There are $($entAppsInactiveEnabled.Count) enterprise applications with no sign-in activities (delegated or app-only flows) over the last 180 days.</p>"
            AffectedObjects = $entInactiveAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-002] No inactive enterprise apps found."
        Set-FindingOverride -FindingId "ENT-002" -Props $ENT002VariantProps.Secure
    }

    # ENT-003: Apps with owners
    if ($entAppsWithOwners.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-003] Found $($entAppsWithOwners.Count) enabled enterprise apps with owners and impact >= $ownerFindingMinImpact (before Tier-0 owner filtering)."
        $entOwnerAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsWithOwners) {
            $ownerLinks = [System.Collections.Generic.List[string]]::new()
            $nonTier0OwnerCount = 0
            $ownerDetailsEnumerated = 0
            if ($app.OwnerUserDetails) {
                foreach ($owner in $app.OwnerUserDetails) {
                    $ownerDetailsEnumerated += 1
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType "User") { continue }
                    $name = if ($owner.UPN) { $owner.UPN } else { $owner.displayName }
                    if (-not $name) { $name = $owner.Id }
                    $label = "$name (User)"
                    if ($owner.Id) {
                        $ownerLinks.Add("<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)`" target=`"_blank`">$label</a>")
                    } else {
                        $ownerLinks.Add($label)
                    }
                    $nonTier0OwnerCount += 1
                }
            }
            if ($app.OwnerSPDetails) {
                foreach ($owner in $app.OwnerSPDetails) {
                    $ownerDetailsEnumerated += 1
                    $name = $owner.displayName
                    if (-not $name) { $name = $owner.Id }
                    $spLink = $null
                    $spTypeLabel = if ($owner.servicePrincipalType) { $owner.servicePrincipalType } else { "ServicePrincipal" }
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType $spTypeLabel) { continue }
                    if ($owner.servicePrincipalType -eq "Application") {
                        if ($owner.Id -and $enterpriseAppIds.ContainsKey($owner.Id)) {
                            $spLink = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)"
                        }
                    } elseif ($owner.servicePrincipalType -eq "ManagedIdentity") {
                        if ($owner.Id) {
                            $spLink = "ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)"
                        }
                    }
                    if ($spLink) {
                        $ownerLinks.Add("<a href=`"$spLink`" target=`"_blank`">$name ($spTypeLabel)</a>")
                    } else {
                        $ownerLinks.Add("$name ($spTypeLabel)")
                    }
                    $nonTier0OwnerCount += 1
                }
            }

            $rawOwnerCount = Get-IntSafe $app.Owners
            if ($ownerDetailsEnumerated -eq 0 -and $rawOwnerCount -gt 0) {
                # Keep findings conservative when owner details are not available for Tier-0 filtering.
                $nonTier0OwnerCount = $rawOwnerCount
                if ($ownerLinks.Count -eq 0) {
                    $ownerLinks.Add("Owner details unavailable for Tier-0 filtering")
                }
            }
            if ($nonTier0OwnerCount -eq 0) { continue }

            $ownerDisplay = ""
            if ($ownerLinks.Count -gt 0) {
                $maxOwners = 10
                $shown = $ownerLinks
                if ($ownerLinks.Count -gt $maxOwners) {
                    $shown = $ownerLinks.GetRange(0, $maxOwners)
                    $shown.Add("+$($ownerLinks.Count - $maxOwners) more")
                }
                $ownerDisplay = $shown -join "<br>"
            }

            $entOwnerAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Owners Count" = $nonTier0OwnerCount
                "Owners" = $ownerDisplay
                "App Impact Score" = $app.Impact
                "Warnings" = $app.Warnings
            })
        }
        if ($entOwnerAffected.Count -gt 0) {
            Set-FindingOverride -FindingId "ENT-003" -Props $ENT003VariantProps.Vulnerable
            Set-FindingOverride -FindingId "ENT-003" -Props @{
                RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Owners=%3E0&Enabled=%3Dtrue&Impact=%3E%3D$ownerFindingMinImpact&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2COwners%2CGrpMem%2CGrpOwn%2CAppOwn%2CSpOwn%2CEntraRoles%2CAzureRoles%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CApiDelegated%2CImpact%2CLikelihood%2CRisk%2CWarnings"
                Description = "<p>$($entOwnerAffected.Count) enabled enterprise applications with an impact score of at least $ownerFindingMinImpact have one or more assigned non-Tier-0 owners.</p><p><strong>Important:</strong> This finding requires manual verification. If the owners are Tier-1 administrators and the application has only low privileges (low impact score), this may be acceptable.</p>"
                AffectedObjects = $entOwnerAffected
                AffectedSortKey = "App Impact Score"
                AffectedSortDir = "DESC"
            }
        } else {
            Write-Log -Level Verbose -Message "[ENT-003] Owners were found, but all resolvable owners are Tier-0 and therefore excluded."
            Set-FindingOverride -FindingId "ENT-003" -Props $ENT003VariantProps.Secure
            Set-FindingOverride -FindingId "ENT-003" -Props @{
                Description = "<p>No enabled enterprise applications with an impact score of at least $ownerFindingMinImpact and non-Tier-0 owners were identified.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-003] No enterprise apps with owners found."
        Set-FindingOverride -FindingId "ENT-003" -Props $ENT003VariantProps.Secure
    }

    # ENT-004: Apply result for foreign apps with extensive API permissions.
    if ($entAppsForeignExtensive.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-004] Found $($entAppsForeignExtensive.Count) foreign enterprise apps with extensive API permissions."
        Set-FindingOverride -FindingId "ENT-004" -Props $ENT004VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-004" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DTrue&or_ApiDangerous=%3E0&or_ApiHigh=%3E0&or_ApiMedium=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $entForeignAffected = [System.Collections.Generic.List[object]]::new()
        $entDangerousCount = 0
        $entHighCount = 0
        $entMediumCount = 0
        foreach ($app in $entAppsForeignExtensive) {
            # Count apps with dangerous permissions for severity escalation.
            if ($null -ne $app.ApiDangerous) {
                $apiDangerousValue = 0
                if ([int]::TryParse("$($app.ApiDangerous)", [ref]$apiDangerousValue)) {
                    if ($apiDangerousValue -gt 0) { $entDangerousCount += 1 }
                }
            }
            if ($null -ne $app.ApiHigh) {
                $apiHighValue = 0
                if ([int]::TryParse("$($app.ApiHigh)", [ref]$apiHighValue)) {
                    if ($apiHighValue -gt 0) { $entHighCount += 1 }
                }
            }
            if ($null -ne $app.ApiMedium) {
                $apiMediumValue = 0
                if ([int]::TryParse("$($app.ApiMedium)", [ref]$apiMediumValue)) {
                    if ($apiMediumValue -gt 0) { $entMediumCount += 1 }
                }
            }
            $permissions = @()
            $rawPerms = @()
            if ($app.AppApiPermission) {
                if ($app.AppApiPermission -is [System.Collections.IEnumerable] -and -not ($app.AppApiPermission -is [string])) {
                    $rawPerms = @($app.AppApiPermission)
                } else {
                    $rawPerms = @($app.AppApiPermission)
                }
            }
            # Preserve severity order for permission listings.
            foreach ($level in @("Dangerous", "High", "Medium")) {
                foreach ($perm in $rawPerms) {
                    if ($perm.ApiPermissionCategorization -eq $level) {
                        $permName = $perm.ApiPermission
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = "API" }
                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName"
                        }
                    }
                }
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }
            $entForeignAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Publisher Name" = $app.PublisherName
                "Inactive" = $app.Inactive
                "Dangerous" = $app.ApiDangerous
                "High" = $app.ApiHigh
                "Medium" = $app.ApiMedium
                "API Permissions (>= Medium)" = $permissionDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-004" -Props @{
            Description = "<p>$($entAppsForeignExtensive.Count) enabled foreign enterprise applications have extensive API privileges assigned as application permissions.</p><p>Applications with the following privilege levels:</p><ul><li>Dangerous: $entDangerousCount</li><li>High: $entHighCount</li><li>Medium: $entMediumCount</li></ul>"
            AffectedObjects = $entForeignAffected
        }
        if ($entDangerousCount -gt 0) {
            # Escalate severity and threat text when dangerous permissions exist.
            Set-FindingOverride -FindingId "ENT-004" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of an application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its extensive API privileges. Conditional Access Policies do not apply to multi-tenant applications.</p><p>Since at least one application has highly dangerous privileges assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-004] No foreign enterprise apps with extensive API permissions found."
        Set-FindingOverride -FindingId "ENT-004" -Props $ENT004VariantProps.Secure
    }

    # ENT-005: Apply result for foreign apps with extensive delegated permissions.
    if ($entAppsForeignDelegated.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-005] Found $($entAppsForeignDelegated.Count) foreign enterprise apps with extensive delegated permissions."
        Set-FindingOverride -FindingId "ENT-005" -Props $ENT005VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-005" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DTrue&or_ApiDelegatedDangerous=%3E0&or_ApiDelegatedHigh=%3E0&or_ApiDelegatedMedium=%3E0&Enabled=%3Dtrue&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CApiDelegatedMedium%2CApiDelegatedLow%2CApiDelegatedMisc%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $entDelegatedAffected = [System.Collections.Generic.List[object]]::new()
        $entDelegatedDangerousCount = 0
        $entDelegatedHighCount = 0
        $entDelegatedMediumCount = 0
        foreach ($app in $entAppsForeignDelegated) {
            # Count apps by delegated privilege level for summary text.
            if ($null -ne $app.ApiDelegatedDangerous) {
                $value = 0
                if ([int]::TryParse("$($app.ApiDelegatedDangerous)", [ref]$value)) {
                    if ($value -gt 0) { $entDelegatedDangerousCount += 1 }
                }
            }
            if ($null -ne $app.ApiDelegatedHigh) {
                $value = 0
                if ([int]::TryParse("$($app.ApiDelegatedHigh)", [ref]$value)) {
                    if ($value -gt 0) { $entDelegatedHighCount += 1 }
                }
            }
            if ($null -ne $app.ApiDelegatedMedium) {
                $value = 0
                if ([int]::TryParse("$($app.ApiDelegatedMedium)", [ref]$value)) {
                    if ($value -gt 0) { $entDelegatedMediumCount += 1 }
                }
            }

            $permissions = @()
            $rawPerms = @()
            if ($app.ApiDelegatedDetails) {
                if ($app.ApiDelegatedDetails -is [System.Collections.IEnumerable] -and -not ($app.ApiDelegatedDetails -is [string])) {
                    $rawPerms = @($app.ApiDelegatedDetails)
                } else {
                    $rawPerms = @($app.ApiDelegatedDetails)
                }
            }
            foreach ($level in @("Dangerous", "High", "Medium")) {
                foreach ($perm in $rawPerms) {
                    if ($perm.ApiPermissionCategorization -eq $level) {
                        $scope = $perm.Scope
                        if (-not $scope) { $scope = $perm.ApiPermission }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = "API" }
                        if ($scope) {
                            $consentInfo = ""
                            if ($perm.ConsentType -eq "AllPrincipals") {
                                $consentInfo = " (All users)"
                            } elseif ($perm.ConsentType -eq "Principal") {
                                $consentCount = $perm.ConsentCount
                                if ($null -eq $consentCount) { $consentCount = $perm.PrincipalCount }
                                if ($null -eq $consentCount) {
                                    $consentInfo = " (some users)"
                                } elseif ($consentCount -is [string] -and $consentCount -match "\busers?\b") {
                                    $consentInfo = " ($consentCount)"
                                } else {
                                    $consentInfo = " ($consentCount users)"
                                }
                            }
                            $permissions += "${level}: $scope on API $apiName$consentInfo"
                        }
                    }
                }
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }
            $entDelegatedAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Publisher Name" = $app.PublisherName
                "Inactive" = $app.Inactive
                "Dangerous" = $app.ApiDelegatedDangerous
                "High" = $app.ApiDelegatedHigh
                "Medium" = $app.ApiDelegatedMedium
                "Delegated API Permissions (>= Medium)" = $permissionDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-005" -Props @{
            Description = "<p>$($entAppsForeignDelegated.Count) enabled foreign enterprise applications have extensive delegated API privileges.</p><p>Applications with the following privilege levels:</p><ul><li>Dangerous: $entDelegatedDangerousCount</li><li>High: $entDelegatedHighCount</li><li>Medium: $entDelegatedMediumCount</li></ul>"
            AffectedObjects = $entDelegatedAffected
        }
        if ($entDelegatedDangerousCount -gt 0) {
            # Escalate severity and threat when dangerous delegated permissions exist.
            Set-FindingOverride -FindingId "ENT-005" -Props @{
                Severity = 3
                Threat = "<p>If the external tenant is compromised, or if permissions are consented to a malicious application, attackers gain access to a user's access token as soon as the user authenticates with the compromised application.<br>Using this access token, attackers can abuse the consented permissions to perform malicious actions on behalf of the user, inheriting the user's identity and privileges. If attackers also obtain the refresh token (permission <code>offline_access</code>), they may be able to maintain persistent unauthorized access.</p><p>Since at least one application has highly dangerous privileges assigned, attackers may be able to compromise the entire tenant if a highly privileged user authenticates to the application.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-005] No foreign enterprise apps with delegated extensive permissions found."
        Set-FindingOverride -FindingId "ENT-005" -Props $ENT005VariantProps.Secure
    }

    # ENT-006: Apply result for foreign apps with Entra ID roles assigned.
    if ($entAppsForeignRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-006] Found $($entAppsForeignRoles.Count) foreign enterprise apps with Entra ID roles."
        Set-FindingOverride -FindingId "ENT-006" -Props $ENT006VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-006" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DTrue&EntraRoles=%3E0&Enabled=%3Dtrue&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }

        $entTier0 = 0
        $entTier1 = 0
        $entTier2 = 0
        $entTierUncat = 0
        $entRoleAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsForeignRoles) {
            $entraRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.EntraRoleDetails)) {
                if ($role) {
                    $entraRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $tiersSeen = @{}
            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($tier in @("0", "1", "2", "Uncategorized")) {
                foreach ($entry in $entraRoleEntries) {
                    $role = $entry.Role
                    # Group membership path is evaluated as active-only; ownership can include eligible paths.
                    if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }
                    $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                    if ($roleTier -ne $tier) { continue }
                    $tiersSeen[$roleTier] = $true
                    $roleName = $role.DisplayName
                    if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                    $scopeName = $role.ScopeResolved.DisplayName
                    $scopeType = $role.ScopeResolved.Type
                    if (-not $scopeName) { $scopeName = "Tenant" }
                    if (-not $scopeType) { $scopeType = "Directory" }
                    if ($roleName) {
                        switch ($entry.Source) {
                            "Direct" {
                                $roleLines.Add("Tier ${roleTier}: $roleName scoped to $scopeName ($scopeType)")
                            }
                            "GroupMember" {
                                $roleLines.Add("Tier ${roleTier}: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                            }
                            "GroupOwner" {
                                $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                                $roleLines.Add("Tier ${roleTier}: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scoped to $scopeName ($scopeType)")
                            }
                        }
                    }
                }
            }

            if ($tiersSeen.ContainsKey("0")) { $entTier0 += 1 }
            if ($tiersSeen.ContainsKey("1")) { $entTier1 += 1 }
            if ($tiersSeen.ContainsKey("2")) { $entTier2 += 1 }
            if ($tiersSeen.ContainsKey("Uncategorized") -or $tiersSeen.Keys.Count -eq 0) { $entTierUncat += 1 }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $entRoleAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Publisher Name" = $app.PublisherName
                "Role Count" = $(if ($null -ne $app.EntraRolesEffective) { $app.EntraRolesEffective } else { $app.EntraRoles })
                "Roles" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }

        Set-FindingOverride -FindingId "ENT-006" -Props @{
            Description = "<p>$($entAppsForeignRoles.Count) enabled foreign enterprise applications have Entra ID roles assigned.</p><p>Applications by role tier:</p><ul><li>Tier 0: $entTier0</li><li>Tier 1: $entTier1</li><li>Tier 2: $entTier2</li><li>Uncategorized tier: $entTierUncat</li></ul>"
            AffectedObjects = $entRoleAffected
        }
        if ($entTier0 -gt 0) {
            # Escalate severity and threat when tier-0 roles exist.
            Set-FindingOverride -FindingId "ENT-006" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of an enterprise application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its privileges. Conditional Access Policies do not apply to multi-tenant applications.</p><p>Since at least one application has a tier-0 role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-006] No foreign enterprise apps with Entra roles found."
        Set-FindingOverride -FindingId "ENT-006" -Props $ENT006VariantProps.Secure
    }

    # ENT-007: Apply result for foreign apps with Azure roles assigned.
    if ($entAppsForeignAzureRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-007] Found $($entAppsForeignAzureRoles.Count) foreign enterprise apps with Azure roles."
        Set-FindingOverride -FindingId "ENT-007" -Props $ENT007VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-007" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DTrue&AzureRoles=%3E0&Enabled=%3Dtrue&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }

        # Track role tier distribution to build summary text.
        $azTier0 = 0
        $azTier1 = 0
        $azTier2 = 0
        $azTierUncat = 0
        $entAzureRoleAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsForeignAzureRoles) {
            $azureRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.AzureRoleDetails)) {
                if ($role) {
                    $azureRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $tiersSeen = @{}
            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($tier in @("0", "1", "2", "Uncategorized")) {
                foreach ($entry in $azureRoleEntries) {
                    $role = $entry.Role
                    # Group membership path is evaluated as active-only; ownership can include eligible paths.
                    if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }
                    $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                    if ($roleTier -ne $tier) { continue }
                    $tiersSeen[$roleTier] = $true
                    $roleName = $role.RoleName
                    if (-not $roleName) { $roleName = $role.DisplayName }
                    if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                    $scope = $role.Scope
                    if (-not $scope -and $role.ScopeResolved) { $scope = $role.ScopeResolved.DisplayName }
                    if (-not $scope) { $scope = "Unknown scope" }
                    if ($roleName) {
                        switch ($entry.Source) {
                            "Direct" {
                                $roleLines.Add("Tier ${roleTier}: $roleName scoped to $scope")
                            }
                            "GroupMember" {
                                $roleLines.Add("Tier ${roleTier}: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scope")
                            }
                            "GroupOwner" {
                                $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                                $roleLines.Add("Tier ${roleTier}: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scoped to $scope")
                            }
                        }
                    }
                }
            }

            if ($tiersSeen.ContainsKey("0")) { $azTier0 += 1 }
            if ($tiersSeen.ContainsKey("1")) { $azTier1 += 1 }
            if ($tiersSeen.ContainsKey("2")) { $azTier2 += 1 }
            if ($tiersSeen.ContainsKey("Uncategorized") -or $tiersSeen.Keys.Count -eq 0) { $azTierUncat += 1 }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $roleCount = $null
            if ($null -ne $app.AzureRolesEffective) {
                $roleCount = $app.AzureRolesEffective
            } elseif ($null -ne $app.AzureRoles) {
                $roleCount = $app.AzureRoles
            } else {
                $roleCount = $azureRoleEntries.Count
            }
            $entAzureRoleAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Publisher Name" = $app.PublisherName
                "Role Count" = $roleCount
                "Roles" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }

        Set-FindingOverride -FindingId "ENT-007" -Props @{
            Description = "<p>$($entAppsForeignAzureRoles.Count) enabled foreign enterprise applications have Azure roles assigned.</p><p>Applications by role tier:</p><ul><li>Tier 0: $azTier0</li><li>Tier 1: $azTier1</li><li>Tier 2: $azTier2</li><li>Uncategorized tier: $azTierUncat</li></ul><p><strong>Important:</strong> This finding requires manual verification. The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Azure provides more than 850 built-in roles, and the actual impact depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
            AffectedObjects = $entAzureRoleAffected
        }
        if ($azTier0 -gt 0) {
            # Escalate severity and threat when tier-0 roles exist.
            Set-FindingOverride -FindingId "ENT-007" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of an enterprise application is compromised or its client credentials are leaked, attackers can gain control of the application. They can then authenticate in all tenants where the enterprise application exists without a user account and abuse its privileges. Conditional Access Policies do not apply to multi-tenant applications.</p><p>Since at least one application has a tier-0 role assigned, attackers may be able to compromise important Azure resources.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-007] No foreign enterprise apps with Azure roles found."
        Set-FindingOverride -FindingId "ENT-007" -Props $ENT007VariantProps.Secure
    }

    # ENT-008: Apply result for foreign apps owning objects.
    if ($entAppsForeignOwningObjects.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-008] Found $($entAppsForeignOwningObjects.Count) foreign enterprise apps owning objects."
        Set-FindingOverride -FindingId "ENT-008" -Props $ENT008VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-008" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Enabled=%3Dtrue&Foreign=%3Dtrue&or_GrpOwn=%3E0&or_AppOwn=%3E0&or_BlueprintOwn=%3E0&or_SpOwn=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2COwners%2CCredentials%2CAppRoles%2CGrpMem%2CGrpOwn%2CAppOwn%2CBlueprintOwn%2CSpOwn%2CEntraRoles%2CAzureRoles%2CApiDelegated%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }

        $entOwnershipAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsForeignOwningObjects) {
            $grpOwnValue = Get-IntSafe $app.GrpOwn
            $appOwnValue = Get-IntSafe $app.AppOwn
            $blueprintOwnValue = Get-IntSafe $app.BlueprintOwn
            $spOwnValue = Get-IntSafe $app.SpOwn
            $entOwnershipAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Publisher Name" = $app.PublisherName
                "Owned Groups" = $grpOwnValue
                "Owned App Registrations" = $appOwnValue
                "Owned Blueprints" = $blueprintOwnValue
                "Owned Enterprise Applications" = $spOwnValue
                "Warnings" = $app.Warnings
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-008" -Props @{
            Description = "<p>$($entAppsForeignOwningObjects.Count) enabled foreign enterprise applications own other objects (groups, app registrations, agent identity blueprints, or enterprise applications).</p><p><strong>Important:</strong> This finding requires manual verification.</p>"
            AffectedObjects = $entOwnershipAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-008] No foreign enterprise apps owning other objects found."
        Set-FindingOverride -FindingId "ENT-008" -Props $ENT008VariantProps.Secure
    }

    # ENT-009: Apply result for internal apps with extensive API permissions (application).
    if ($entAppsInternalExtensive.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-009] Found $($entAppsInternalExtensive.Count) internal enterprise apps with extensive API permissions."
        Set-FindingOverride -FindingId "ENT-009" -Props $ENT009VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-009" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DFalse&or_ApiDangerous=%3E0&or_ApiHigh=%3E0&Enabled=%3Dtrue&DisplayName=%21%5EConnectSyncProvisioning_&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $entInternalAffected = [System.Collections.Generic.List[object]]::new()
        $entInternalDangerous = 0
        $entInternalHigh = 0
        foreach ($app in $entAppsInternalExtensive) {
            # Count apps with dangerous permissions for severity escalation.
            if ($null -ne $app.ApiDangerous) {
                $apiDangerousValue = 0
                if ([int]::TryParse("$($app.ApiDangerous)", [ref]$apiDangerousValue)) {
                    if ($apiDangerousValue -gt 0) { $entInternalDangerous += 1 }
                }
            }
            if ($null -ne $app.ApiHigh) {
                $apiHighValue = 0
                if ([int]::TryParse("$($app.ApiHigh)", [ref]$apiHighValue)) {
                    if ($apiHighValue -gt 0) { $entInternalHigh += 1 }
                }
            }
            $permissions = @()
            $rawPerms = @()
            if ($app.AppApiPermission) {
                if ($app.AppApiPermission -is [System.Collections.IEnumerable] -and -not ($app.AppApiPermission -is [string])) {
                    $rawPerms = @($app.AppApiPermission)
                } else {
                    $rawPerms = @($app.AppApiPermission)
                }
            }
            # Preserve severity order for permission listings.
            foreach ($level in @("Dangerous", "High")) {
                foreach ($perm in $rawPerms) {
                    if ($perm.ApiPermissionCategorization -eq $level) {
                        $permName = $perm.ApiPermission
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = "API" }
                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName"
                        }
                    }
                }
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }
            $entInternalAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Inactive" = $app.Inactive
                "Dangerous" = $app.ApiDangerous
                "High" = $app.ApiHigh
                "API Permissions (>= High)" = $permissionDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-009" -Props @{
            Description = "<p>$($entAppsInternalExtensive.Count) enabled internal enterprise applications have extensive API privileges assigned as application permissions.</p><p>Applications with the following privilege levels:</p><ul><li>Dangerous: $entInternalDangerous</li><li>High: $entInternalHigh</li></ul>"
            AffectedObjects = $entInternalAffected
        }
        if ($entInternalDangerous -gt 0) {
            # Escalate severity and threat text when dangerous permissions exist.
            Set-FindingOverride -FindingId "ENT-009" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to an application secret (client secret or certificate), or if they are able to add their own, they can take control of the application. They can then authenticate in all tenants where the enterprise application exists and abuse its API privileges.</p><p>Since at least one application has highly dangerous privileges assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-009] No internal enterprise apps with extensive API permissions found."
        Set-FindingOverride -FindingId "ENT-009" -Props $ENT009VariantProps.Secure
    }

    # ENT-010: Apply result for internal apps with extensive delegated API permissions.
    if ($entAppsInternalDelegated.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-010] Found $($entAppsInternalDelegated.Count) internal enterprise apps with delegated extensive permissions."
        Set-FindingOverride -FindingId "ENT-010" -Props $ENT010VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-010" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DFalse&or_ApiDelegatedDangerous=%3E0&or_ApiDelegatedHigh=%3E0&Enabled=%3Dtrue&columns=DisplayName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CApiDelegatedMedium%2CApiDelegatedLow%2CApiDelegatedMisc%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $entInternalDelegatedAffected = [System.Collections.Generic.List[object]]::new()
        $entInternalDelegatedDangerous = 0
        $entInternalDelegatedHigh = 0
        foreach ($app in $entAppsInternalDelegated) {
            # Count apps with dangerous delegated permissions for escalation.
            if ($null -ne $app.ApiDelegatedDangerous) {
                $apiDangerousValue = 0
                if ([int]::TryParse("$($app.ApiDelegatedDangerous)", [ref]$apiDangerousValue)) {
                    if ($apiDangerousValue -gt 0) { $entInternalDelegatedDangerous += 1 }
                }
            }
            if ($null -ne $app.ApiDelegatedHigh) {
                $apiHighValue = 0
                if ([int]::TryParse("$($app.ApiDelegatedHigh)", [ref]$apiHighValue)) {
                    if ($apiHighValue -gt 0) { $entInternalDelegatedHigh += 1 }
                }
            }
            $permissions = @()
            $rawPerms = @()
            if ($app.ApiDelegatedDetails) {
                if ($app.ApiDelegatedDetails -is [System.Collections.IEnumerable] -and -not ($app.ApiDelegatedDetails -is [string])) {
                    $rawPerms = @($app.ApiDelegatedDetails)
                } else {
                    $rawPerms = @($app.ApiDelegatedDetails)
                }
            }
            # Preserve severity order and include consent scope for delegated permissions.
            foreach ($level in @("Dangerous", "High")) {
                foreach ($perm in $rawPerms) {
                    if ($perm.ApiPermissionCategorization -eq $level) {
                        $scope = $perm.Scope
                        if (-not $scope) { $scope = $perm.ApiPermission }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = "API" }
                        if ($scope) {
                            $consentInfo = ""
                            if ($perm.ConsentType -eq "AllPrincipals") {
                                $consentInfo = " (All users)"
                            } elseif ($perm.ConsentType -eq "Principal") {
                                $consentCount = $perm.ConsentCount
                                if ($null -eq $consentCount) { $consentCount = $perm.PrincipalCount }
                                if ($null -eq $consentCount) {
                                    $consentInfo = " (some users)"
                                } elseif ($consentCount -is [string] -and $consentCount -match "\busers?\b") {
                                    $consentInfo = " ($consentCount)"
                                } else {
                                    $consentInfo = " ($consentCount users)"
                                }
                            }
                            $permissions += "${level}: $scope on API $apiName$consentInfo"
                        }
                    }
                }
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }
            $entInternalDelegatedAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Inactive" = $app.Inactive
                "Dangerous" = $app.ApiDelegatedDangerous
                "High" = $app.ApiDelegatedHigh
                "Delegated API Permissions (>= High)" = $permissionDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "ENT-010" -Props @{
            Description = "<p>$($entAppsInternalDelegated.Count) enabled internal enterprise applications have extensive delegated API privileges.</p><p>Applications with the following privilege levels:</p><ul><li>Dangerous: $entInternalDelegatedDangerous</li><li>High: $entInternalDelegatedHigh</li></ul>"
            AffectedObjects = $entInternalDelegatedAffected
        }
        if ($entInternalDelegatedDangerous -gt 0) {
            # Escalate threat when dangerous delegated permissions exist.
            Set-FindingOverride -FindingId "ENT-010" -Props @{
                Severity = 3
                Threat = "<p>If attackers can manipulate the application, they might be able to a user's access token as soon as the user authenticates with the compromised application.<br>Using this access token, attackers can abuse the consented permissions to perform malicious actions on behalf of the user, inheriting the user's identity and privileges. If attackers also obtain the refresh token (permission <code>offline_access</code>), they may be able to maintain persistent unauthorized access.</p><p>Since at least one application has highly dangerous privileges assigned, attackers may be able to compromise the entire tenant if a highly privileged user authenticates to the application.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-010] No internal enterprise apps with delegated extensive permissions found."
        Set-FindingOverride -FindingId "ENT-010" -Props $ENT010VariantProps.Secure
    }

    # ENT-011: Apply result for internal apps with privileged Entra ID roles.
    if ($entAppsInternalTier0.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-011] Found $($entAppsInternalTier0.Count) internal enterprise apps with privileged Entra ID roles."
        Set-FindingOverride -FindingId "ENT-011" -Props $ENT011VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-011" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DFalse&Enabled=%3Dtrue&EntraMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }

        $entTier0Apps = 0
        $entTier1Apps = 0
        $entTierAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsInternalTier0) {
            $entraRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.EntraRoleDetails)) {
                if ($role) {
                    $entraRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $entraTierEntries = @()
            foreach ($entry in $entraRoleEntries) {
                $role = $entry.Role
                if (-not $role) { continue }
                if ($role.RoleTier -ne 0 -and $role.RoleTier -ne 1) { continue }
                # Group membership path is evaluated as active-only; ownership can include eligible paths.
                if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }
                $entraTierEntries += $entry
            }

            $tier0Count = @($entraTierEntries | Where-Object { $_.Role.RoleTier -eq 0 }).Count
            $tier1Count = @($entraTierEntries | Where-Object { $_.Role.RoleTier -eq 1 }).Count
            if ($tier0Count -gt 0) { $entTier0Apps += 1 }
            if ($tier1Count -gt 0) { $entTier1Apps += 1 }

            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in @($entraTierEntries | Where-Object { $_.Role.RoleTier -eq 0 })) {
                $role = $entry.Role
                $roleName = $role.DisplayName
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scopeName = $role.ScopeResolved.DisplayName
                $scopeType = $role.ScopeResolved.Type
                if (-not $scopeName) { $scopeName = "Tenant" }
                if (-not $scopeType) { $scopeType = "Directory" }
                if ($roleName) {
                    switch ($entry.Source) {
                        "Direct" {
                            $roleLines.Add("Tier 0 Entra Role: $roleName scoped to $scopeName ($scopeType)")
                        }
                        "GroupMember" {
                            $roleLines.Add("Tier 0 Entra Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roleLines.Add("Tier 0 Entra Role: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scoped to $scopeName ($scopeType)")
                        }
                    }
                }
            }
            foreach ($entry in @($entraTierEntries | Where-Object { $_.Role.RoleTier -eq 1 })) {
                $role = $entry.Role
                $roleName = $role.DisplayName
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scopeName = $role.ScopeResolved.DisplayName
                $scopeType = $role.ScopeResolved.Type
                if (-not $scopeName) { $scopeName = "Tenant" }
                if (-not $scopeType) { $scopeType = "Directory" }
                if ($roleName) {
                    switch ($entry.Source) {
                        "Direct" {
                            $roleLines.Add("Tier 1 Entra Role: $roleName scoped to $scopeName ($scopeType)")
                        }
                        "GroupMember" {
                            $roleLines.Add("Tier 1 Entra Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roleLines.Add("Tier 1 Entra Role: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scoped to $scopeName ($scopeType)")
                        }
                    }
                }
            }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $entTierAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Tier 0 Entra Roles" = $tier0Count
                "Tier 1 Entra Roles" = $tier1Count
                "Entra Roles" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }

        Set-FindingOverride -FindingId "ENT-011" -Props @{
            Description = "<p>$($entAppsInternalTier0.Count) enabled internal enterprise applications have privileged Entra ID roles (tier-0 or tier-1) assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $entTier0Apps</li><li>Tier 1: $entTier1Apps</li></ul>"
            AffectedObjects = $entTierAffected
        }
        if ($entTier0Apps -gt 0) {
            # Escalate severity and threat when tier-0 Entra roles exist.
            Set-FindingOverride -FindingId "ENT-011" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to an application secret (client secret or certificate), or if they are able to add their own, they can take control of the application. They can then authenticate in all tenants where the enterprise application exists and abuse its privileges.</p><p>Since at least one application has a tier-0 role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-011] No internal enterprise apps with privileged Entra ID roles found."
        Set-FindingOverride -FindingId "ENT-011" -Props $ENT011VariantProps.Secure
    }

    # ENT-012: Apply result for internal apps with privileged Azure roles.
    if ($entAppsInternalAzureTier.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-012] Found $($entAppsInternalAzureTier.Count) internal enterprise apps with privileged Azure roles."
        Set-FindingOverride -FindingId "ENT-012" -Props $ENT012VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-012" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3DFalse&Enabled=%3Dtrue&AzureMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }

        $entAzureTier0Apps = 0
        $entAzureTier1Apps = 0
        $entAzureAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsInternalAzureTier) {
            $azureRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.AzureRoleDetails)) {
                if ($role) {
                    $azureRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $azureTierEntries = @()
            foreach ($entry in $azureRoleEntries) {
                $role = $entry.Role
                if (-not $role) { continue }
                if ($role.RoleTier -ne 0 -and $role.RoleTier -ne 1) { continue }
                # Group membership path is evaluated as active-only; ownership can include eligible paths.
                if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }
                $azureTierEntries += $entry
            }

            $tier0Count = @($azureTierEntries | Where-Object { $_.Role.RoleTier -eq 0 }).Count
            $tier1Count = @($azureTierEntries | Where-Object { $_.Role.RoleTier -eq 1 }).Count
            if ($tier0Count -gt 0) { $entAzureTier0Apps += 1 }
            if ($tier1Count -gt 0) { $entAzureTier1Apps += 1 }

            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in @($azureTierEntries | Where-Object { $_.Role.RoleTier -eq 0 })) {
                $role = $entry.Role
                $roleName = $role.RoleName
                if (-not $roleName) { $roleName = $role.DisplayName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scope = $role.Scope
                if (-not $scope -and $role.ScopeResolved) { $scope = $role.ScopeResolved.DisplayName }
                if (-not $scope) { $scope = "Unknown scope" }
                if ($roleName) {
                    switch ($entry.Source) {
                        "Direct" {
                            $roleLines.Add("Tier 0 Azure Role: $roleName scope to $scope")
                        }
                        "GroupMember" {
                            $roleLines.Add("Tier 0 Azure Role: $roleName through group membership '$($entry.GroupDisplayName)' scope to $scope")
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roleLines.Add("Tier 0 Azure Role: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scope to $scope")
                        }
                    }
                }
            }
            foreach ($entry in @($azureTierEntries | Where-Object { $_.Role.RoleTier -eq 1 })) {
                $role = $entry.Role
                $roleName = $role.RoleName
                if (-not $roleName) { $roleName = $role.DisplayName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scope = $role.Scope
                if (-not $scope -and $role.ScopeResolved) { $scope = $role.ScopeResolved.DisplayName }
                if (-not $scope) { $scope = "Unknown scope" }
                if ($roleName) {
                    switch ($entry.Source) {
                        "Direct" {
                            $roleLines.Add("Tier 1 Azure Role: $roleName scope to $scope")
                        }
                        "GroupMember" {
                            $roleLines.Add("Tier 1 Azure Role: $roleName through group membership '$($entry.GroupDisplayName)' scope to $scope")
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roleLines.Add("Tier 1 Azure Role: $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scope to $scope")
                        }
                    }
                }
            }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $entAzureAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Tier 0 Azure Roles" = $tier0Count
                "Tier 1 Azure Roles" = $tier1Count
                "Azure Roles" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }

        Set-FindingOverride -FindingId "ENT-012" -Props @{
            Description = "<p>$($entAppsInternalAzureTier.Count) enabled internal enterprise applications which have privileged Azure roles (tier-0 or tier-1) assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $entAzureTier0Apps</li><li>Tier 1: $entAzureTier1Apps</li></ul><p><strong>Important:</strong> This finding requires manual verification. The tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Additionally, Azure provides more than 850 built-in roles, and the actual impact highly depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
            AffectedObjects = $entAzureAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-012] No internal enterprise apps with privileged Azure roles found."
        Set-FindingOverride -FindingId "ENT-012" -Props $ENT012VariantProps.Secure
    }

    # ENT-013: Apply result for enterprise apps matching known malicious AppIds.
    if ($entAppsKnownMalicious.Count -gt 0) {
        Write-Log -Level Verbose -Message "[ENT-013] Found $($entAppsKnownMalicious.Count) enterprise applications matching known malicious AppIds."
        Set-FindingOverride -FindingId "ENT-013" -Props $ENT013VariantProps.Vulnerable
        Set-FindingOverride -FindingId "ENT-013" -Props @{
            RelatedReportUrl = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Warnings=Known+malicious+application!&columns=DisplayName%2CPublisherName%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2COwners%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CApiDelegatedMedium%2CImpact%2CLikelihood%2CWarnings&sort=Impact&sortDir=desc"
            AffectedSortKey = "_SortLastSignIn"
            AffectedSortDir = "DESC"
            Confidence = "Requires Verification"
        }
        $entKnownMaliciousAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $entAppsKnownMalicious) {
            $lastSignInTimestamp = if ($app.AppsignInData -and $app.AppsignInData.lastSignIn -and $app.AppsignInData.lastSignIn -ne "-") { $app.AppsignInData.lastSignIn } else { "-" }
            $creationTimestamp = if ($app.CreationDate) { $app.CreationDate } else { "-" }
            $entKnownMaliciousAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Enabled" = $app.Enabled
                "Created" = $creationTimestamp
                "Last sign-in" = $lastSignInTimestamp
                "Indicator Source" = if (-not [string]::IsNullOrWhiteSpace($app.KnownMaliciousSourceUrl)) { "<a href=`"$($app.KnownMaliciousSourceUrl)`" target=`"_blank`">$($app.KnownMaliciousSourceUrl)</a>" } else { "-" }
                "_SortLastSignIn" = if ("$($app.LastSignInDays)" -eq "-") { 999999 } else { (Get-IntSafe $app.LastSignInDays) }
            })
        }
        Set-FindingOverride -FindingId "ENT-013" -Props @{
            Description = "<p>$($entAppsKnownMalicious.Count) enterprise application(s) were identified whose AppId matches the list of known malicious OAuth applications.</p><p><strong>Important:</strong> This finding requires manual verification. This finding is based on a match against a public list of known malicious OAuth applications. Since the accuracy of public lists cannot be guaranteed, the referenced source URL and the identified application should be manually reviewed.</p>"
            AffectedObjects = $entKnownMaliciousAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[ENT-013] No enterprise applications matching known malicious AppIds found."
        Set-FindingOverride -FindingId "ENT-013" -Props $ENT013VariantProps.Secure
    }

    #endregion

    #region APP Evaluation
    # APP-001: Apply result for app registrations with secrets.
    if ($appRegsWithSecrets.Count -gt 0) {
        Write-Log -Level Verbose -Message "[APP-001] Found $($appRegsWithSecrets.Count) app registrations with secrets."
        Set-FindingOverride -FindingId "APP-001" -Props $APP001VariantProps.Vulnerable
        Set-FindingOverride -FindingId "APP-001" -Props @{
            RelatedReportUrl = "AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SecretsCount=%3E0&columns=DisplayName%2CSignInAudience%2CAppLock%2CAppRoles%2COwnerCount%2CCloudAppAdmins%2CAppAdmins%2CSecretsCount%2CCertsCount%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=SecretsCount&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $appAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $appRegsWithSecrets) {
            $secretLines = [System.Collections.Generic.List[string]]::new()
            $credentialDetails = @()
            if ($app.AppCredentialsDetails) {
                if ($app.AppCredentialsDetails -is [System.Collections.IEnumerable] -and -not ($app.AppCredentialsDetails -is [string])) {
                    $credentialDetails = @($app.AppCredentialsDetails)
                } else {
                    $credentialDetails = @($app.AppCredentialsDetails)
                }
            }
            foreach ($cred in $credentialDetails) {
                if ($cred.Type -ne "Secret") { continue }
                $name = Get-CredentialDisplayName -Credential $cred -FallbackLabel "-"
                $start = $cred.StartDateTime
                $end = $cred.EndDateTime
                if ($start) {
                    if ($start -is [datetime]) {
                        $start = $start.ToString("yyyy-MM-dd")
                    } else {
                        $startText = "$start"
                        if ($startText -match "^\d{4}-\d{2}-\d{2}") {
                            $start = $startText.Substring(0, 10)
                        } else {
                            try { $start = ([datetime]$startText).ToString("yyyy-MM-dd") } catch {}
                        }
                    }
                }
                if ($end) {
                    if ($end -is [datetime]) {
                        $end = $end.ToString("yyyy-MM-dd")
                    } else {
                        $endText = "$end"
                        if ($endText -match "^\d{4}-\d{2}-\d{2}") {
                            $end = $endText.Substring(0, 10)
                        } else {
                            try { $end = ([datetime]$endText).ToString("yyyy-MM-dd") } catch {}
                        }
                    }
                }
                $dateSuffix = ""
                if ($start -and $end) {
                    $dateSuffix = " ($start - $end)"
                } elseif ($start) {
                    $dateSuffix = " (from $start)"
                } elseif ($end) {
                    $dateSuffix = " (until $end)"
                }
                if ($name) {
                    $secretLines.Add("Secret: $name$dateSuffix")
                }
            }
            $secretDisplay = if ($secretLines.Count -gt 0) { ($secretLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $appAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Secrets" = $app.SecretsCount
                "Secret Details" = $secretDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "APP-001" -Props @{
            Description = "<p>$($appRegsWithSecrets.Count) app registrations have secrets configured.</p>"
            AffectedObjects = $appAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[APP-001] No app registrations with secrets found."
        Set-FindingOverride -FindingId "APP-001" -Props $APP001VariantProps.Secure
    }

    # APP-002: Apply result for app registrations missing app instance property lock.
    if ($appRegsMissingAppLock.Count -gt 0) {
        Write-Log -Level Verbose -Message "[APP-002] Found $($appRegsMissingAppLock.Count) app registrations without app instance property lock."
        Set-FindingOverride -FindingId "APP-002" -Props $APP002VariantProps.Vulnerable
        Set-FindingOverride -FindingId "APP-002" -Props @{
            RelatedReportUrl = "AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AppLock=%3Dfalse&columns=DisplayName%2CSignInAudience%2CAppLock%2CAppRoles%2COwnerCount%2CCloudAppAdmins%2CAppAdmins%2CSecretsCount%2CCertsCount%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $appLockAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $appRegsMissingAppLock) {
            $appLockAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "App Lock" = $app.AppLock
                "Sign-in Audience" = $app.SignInAudience
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "APP-002" -Props @{
            Description = "<p>$($appRegsMissingAppLock.Count) app registrations do not have the app instance property lock properly configured.</p>"
            AffectedObjects = $appLockAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[APP-002] No app registrations missing app instance property lock found."
        Set-FindingOverride -FindingId "APP-002" -Props $APP002VariantProps.Secure
    }

    # APP-003: Apply result for app registrations with owners.
    if ($appRegsWithOwners.Count -gt 0) {
        Write-Log -Level Verbose -Message "[APP-003] Found $($appRegsWithOwners.Count) app registrations with owners and impact >= $ownerFindingMinImpact (before Tier-0 owner filtering)."
        $appOwnerAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $appRegsWithOwners) {
            $ownerLinks = [System.Collections.Generic.List[string]]::new()
            $nonTier0OwnerCount = 0
            $ownerDetailsEnumerated = 0
            if ($app.AppOwnerUsers) {
                foreach ($owner in $app.AppOwnerUsers) {
                    $ownerDetailsEnumerated += 1
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType "User") { continue }
                    $name = $owner.userPrincipalName
                    if (-not $name) { $name = $owner.displayName }
                    if (-not $name) { $name = $owner.Id }
                    $label = "$name (User)"
                    if ($owner.Id) {
                        $ownerLinks.Add("<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)`" target=`"_blank`">$label</a>")
                    } else {
                        $ownerLinks.Add("$label")
                    }
                    $nonTier0OwnerCount += 1
                }
            }
            if ($app.AppOwnerSPs) {
                $ownerSpList = @()
                if ($app.AppOwnerSPs -is [System.Collections.IEnumerable] -and -not ($app.AppOwnerSPs -is [string])) {
                    $ownerSpList = @($app.AppOwnerSPs)
                } else {
                    $ownerSpList = @($app.AppOwnerSPs)
                }
                foreach ($owner in $ownerSpList) {
                    $ownerDetailsEnumerated += 1
                    $name = $owner.displayName
                    if (-not $name) { $name = $owner.Id }
                    $spLink = $null
                    $spType = $owner.servicePrincipalType
                    if (-not $spType) { $spType = $owner.Type }
                    if (-not $spType) { $spType = "ServicePrincipal" }
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType $spType) { continue }
                    if ($spType -eq "ServicePrincipal") {
                        if ($owner.Id -and $enterpriseAppIds.ContainsKey($owner.Id)) {
                            $spLink = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)"
                        }
                    }
                    $label = "$name ($spType)"
                    if ($spLink) {
                        $ownerLinks.Add("<a href=`"$spLink`" target=`"_blank`">$label</a>")
                    } else {
                        $ownerLinks.Add("$label")
                    }
                    $nonTier0OwnerCount += 1
                }
            }

            $rawOwnerCount = Get-IntSafe $app.Owners
            if ($ownerDetailsEnumerated -eq 0 -and $rawOwnerCount -gt 0) {
                # Keep findings conservative when owner details are not available for Tier-0 filtering.
                $nonTier0OwnerCount = $rawOwnerCount
                if ($ownerLinks.Count -eq 0) {
                    $ownerLinks.Add("Owner details unavailable for Tier-0 filtering")
                }
            }
            if ($nonTier0OwnerCount -eq 0) { continue }

            $ownerDisplay = ""
            if ($ownerLinks.Count -gt 0) {
                $maxOwners = 10
                $shown = $ownerLinks
                if ($ownerLinks.Count -gt $maxOwners) {
                    $shown = $ownerLinks.GetRange(0, $maxOwners)
                    $shown.Add("+$($ownerLinks.Count - $maxOwners) more")
                }
                $ownerDisplay = $shown -join "<br>"
            }

            $appOwnerAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Owners Count" = $nonTier0OwnerCount
                "Owners" = $ownerDisplay
                "App Impact Score" = $app.Impact
            })
        }
        if ($appOwnerAffected.Count -gt 0) {
            Set-FindingOverride -FindingId "APP-003" -Props $APP003VariantProps.Vulnerable
            Set-FindingOverride -FindingId "APP-003" -Props @{
                RelatedReportUrl = "AppRegistration_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Owners=%3E0&Impact=%3E%3D$ownerFindingMinImpact&columns=DisplayName%2CSignInAudience%2CAppLock%2CAppRoles%2COwners%2CCloudAppAdmins%2CAppAdmins%2CSecretsCount%2CCertsCount%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
		        AffectedSortKey = "App Impact Score"
                AffectedSortDir = "DESC"
                Description = "<p>$($appOwnerAffected.Count) app registrations with an impact score of at least $ownerFindingMinImpact have one or more assigned non-Tier-0 owners.</p><p><strong>Important:</strong> This finding requires manual verification. If the owners are Tier-1 administrators and the application has only low privileges (low impact score), this may be acceptable.</p>"
                AffectedObjects = $appOwnerAffected
            }
        } else {
            Write-Log -Level Verbose -Message "[APP-003] Owners were found, but all resolvable owners are Tier-0 and therefore excluded."
            Set-FindingOverride -FindingId "APP-003" -Props $APP003VariantProps.Secure
            Set-FindingOverride -FindingId "APP-003" -Props @{
                Description = "<p>No app registrations with an impact score of at least $ownerFindingMinImpact and non-Tier-0 owners were identified.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[APP-003] No app registrations with owners found."
        Set-FindingOverride -FindingId "APP-003" -Props $APP003VariantProps.Secure
    }

    $maiSkippedProps = @{
        Status = "Skipped"
        Description = "<p>Check skipped because no managed identities were identified.</p>"
        AffectedObjects = @()
        RelatedReportUrl = ""
    }

    #endregion

    #region AGT Evaluation
    # AGT-001: Apply result for agent identity blueprints with client secrets.
    if ($agentBlueprintCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-001] Skipped because no agent identity blueprints were found."
        Set-FindingOverride -FindingId "AGT-001" -Props $AGT001VariantProps.Skipped
    } elseif ($agentBlueprintsWithSecrets.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-001] Found $($agentBlueprintsWithSecrets.Count) agent identity blueprints with client secrets."
        Set-FindingOverride -FindingId "AGT-001" -Props $AGT001VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-001" -Props @{
            RelatedReportUrl = "AgentIdentityBlueprints_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?SecretsCount=%3E0&columns=DisplayName%2CSignInAudience%2CBlueprintPrincipals%2CAgentIdentities%2CAgentUsers%2COwners%2CInheritableScopes%2CInheritableRoles%2CFederatedCreds%2CSecretsCount%2CCertsCount%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agtAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($blueprint in $agentBlueprintsWithSecrets) {
            $secretLines = [System.Collections.Generic.List[string]]::new()
            $credentialDetails = @()
            if ($blueprint.AppCredentialsDetails) {
                $credentialDetails = @($blueprint.AppCredentialsDetails)
            }
            foreach ($cred in $credentialDetails) {
                if ($cred.Type -ne "Secret") { continue }
                $name = $cred.DisplayName
                if (-not $name) { $name = "-" }
                $start = $cred.StartDateTime
                $end = $cred.EndDateTime
                if ($start) {
                    if ($start -is [datetime]) {
                        $start = $start.ToString("yyyy-MM-dd HH:mm:ss")
                    } else {
                        $startText = "$start"
                        if ($startText -match "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}") {
                            $start = $startText.Substring(0, 19).Replace("T", " ")
                        } elseif ($startText -match "^\d{4}-\d{2}-\d{2}") {
                            $start = $startText.Substring(0, 10)
                        } else {
                            try { $start = ([datetime]$startText).ToString("yyyy-MM-dd HH:mm:ss") } catch {}
                        }
                    }
                }
                if ($end) {
                    if ($end -is [datetime]) {
                        $end = $end.ToString("yyyy-MM-dd HH:mm:ss")
                    } else {
                        $endText = "$end"
                        if ($endText -match "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}") {
                            $end = $endText.Substring(0, 19).Replace("T", " ")
                        } elseif ($endText -match "^\d{4}-\d{2}-\d{2}") {
                            $end = $endText.Substring(0, 10)
                        } else {
                            try { $end = ([datetime]$endText).ToString("yyyy-MM-dd HH:mm:ss") } catch {}
                        }
                    }
                }
                $dateSuffix = ""
                if ($start -and $end) {
                    $dateSuffix = " ($start - $end)"
                } elseif ($start) {
                    $dateSuffix = " (from $start)"
                } elseif ($end) {
                    $dateSuffix = " (until $end)"
                }
                $secretLines.Add("Secret: $name$dateSuffix")
            }
            $secretDisplay = if ($secretLines.Count -gt 0) { $secretLines -join "<br>" } else { "" }
            $agtAffected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"AgentIdentityBlueprints_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($blueprint.Id)`" target=`"_blank`">$($blueprint.DisplayName)</a>"
                "Secrets" = $blueprint.SecretsCount
                "Secret Details" = $secretDisplay
                "_SortRisk" = $blueprint.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-001" -Props @{
            Description = "<p>$($agentBlueprintsWithSecrets.Count) agent identity blueprints have client secrets configured.</p>"
            AffectedObjects = $agtAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-001] No agent identity blueprints with client secrets found."
        Set-FindingOverride -FindingId "AGT-001" -Props $AGT001VariantProps.Secure
    }

    # AGT-017: Apply result for high-impact blueprints with non-Tier-0 owners.
    if ($agentBlueprintCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-017] Skipped because no agent identity blueprints were found."
        Set-FindingOverride -FindingId "AGT-017" -Props $AGT017VariantProps.Skipped
    } elseif ($agentBlueprintsWithOwners.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-017] Found $($agentBlueprintsWithOwners.Count) blueprints with owners and impact >= $blueprintOwnerFindingMinImpact (before Tier-0 owner filtering)."
        $agt017Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($blueprint in $agentBlueprintsWithOwners) {
            $ownerLinks = [System.Collections.Generic.List[string]]::new()
            $nonTier0OwnerCount = 0
            $ownerDetailsEnumerated = 0

            if ($blueprint.AppOwnerUsers) {
                foreach ($owner in $blueprint.AppOwnerUsers) {
                    $ownerDetailsEnumerated += 1
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType "User") { continue }
                    $name = $owner.userPrincipalName
                    if (-not $name) { $name = $owner.displayName }
                    if (-not $name) { $name = $owner.Id }
                    $label = "$name (User)"
                    if ($owner.Id) {
                        $ownerLinks.Add("<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)`" target=`"_blank`">$label</a>")
                    } else {
                        $ownerLinks.Add("$label")
                    }
                    $nonTier0OwnerCount += 1
                }
            }

            if ($blueprint.AppOwnerSPs) {
                $ownerSpList = @()
                $ownerSpList = @($blueprint.AppOwnerSPs)
                foreach ($owner in $ownerSpList) {
                    $ownerDetailsEnumerated += 1
                    $name = $owner.displayName
                    if (-not $name) { $name = $owner.Id }
                    $spLink = $null
                    $spType = $owner.servicePrincipalType
                    if (-not $spType) { $spType = $owner.Type }
                    if (-not $spType) { $spType = "ServicePrincipal" }
                    $ownerId = "$($owner.Id)".Trim()
                    if (Test-IsTier0OwnerId -OwnerId $ownerId -OwnerType $spType) { continue }
                    if ($spType -eq "ServicePrincipal" -and $owner.Id -and $enterpriseAppIds.ContainsKey($owner.Id)) {
                        $spLink = "EnterpriseApps_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($owner.Id)"
                    }
                    $label = "$name ($spType)"
                    if ($spLink) {
                        $ownerLinks.Add("<a href=`"$spLink`" target=`"_blank`">$label</a>")
                    } else {
                        $ownerLinks.Add("$label")
                    }
                    $nonTier0OwnerCount += 1
                }
            }

            $rawOwnerCount = Get-IntSafe $blueprint.Owners
            if ($ownerDetailsEnumerated -eq 0 -and $rawOwnerCount -gt 0) {
                $nonTier0OwnerCount = $rawOwnerCount
                if ($ownerLinks.Count -eq 0) {
                    $ownerLinks.Add("Owner details unavailable for Tier-0 filtering")
                }
            }
            if ($nonTier0OwnerCount -eq 0) { continue }

            $ownerDisplay = ""
            if ($ownerLinks.Count -gt 0) {
                $maxOwners = 10
                $shown = $ownerLinks
                if ($ownerLinks.Count -gt $maxOwners) {
                    $shown = $ownerLinks.GetRange(0, $maxOwners)
                    $shown.Add("+$($ownerLinks.Count - $maxOwners) more")
                }
                $ownerDisplay = $shown -join "<br>"
            }

            $agt017Affected.Add([pscustomobject]@{
                "DisplayName" = "<a href=`"AgentIdentityBlueprints_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($blueprint.Id)`" target=`"_blank`">$($blueprint.DisplayName)</a>"
                "Owners Count" = $nonTier0OwnerCount
                "Owners" = $ownerDisplay
                "Blueprint Principals" = $blueprint.BlueprintPrincipals
                "Agent Identities" = $blueprint.LinkedAgentIdentities
                "Agent Users" = $blueprint.AgentUsers
                "Impact Score" = $blueprint.Impact
            })
        }
        if ($agt017Affected.Count -gt 0) {
            Set-FindingOverride -FindingId "AGT-017" -Props $AGT017VariantProps.Vulnerable
            Set-FindingOverride -FindingId "AGT-017" -Props @{
                RelatedReportUrl = "AgentIdentityBlueprints_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Owners=%3E0&Impact=%3E%3D$blueprintOwnerFindingMinImpact&columns=DisplayName%2CSignInAudience%2CBlueprintPrincipals%2CAgentIdentities%2CAgentUsers%2COwners%2CSponsors%2CInheritableScopes%2CInheritableRoles%2CFederatedCreds%2CSecretsCount%2CCertsCount%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
                AffectedSortKey = "Impact Score"
                AffectedSortDir = "DESC"
                Description = "<p>$($agt017Affected.Count) blueprints with an impact score of at least $blueprintOwnerFindingMinImpact have one or more assigned non-Tier-0 owners.</p><p><strong>Important:</strong> This finding requires manual verification. If the owners are Tier-1 administrators and the blueprint has only limited effective privileges, this may be acceptable.</p>"
                AffectedObjects = $agt017Affected
            }
        } else {
            Write-Log -Level Verbose -Message "[AGT-017] Owners were found, but all resolvable owners are Tier-0 and therefore excluded."
            Set-FindingOverride -FindingId "AGT-017" -Props $AGT017VariantProps.Secure
            Set-FindingOverride -FindingId "AGT-017" -Props @{
                Description = "<p>No blueprints with an impact score of at least $blueprintOwnerFindingMinImpact and non-Tier-0 owners were identified.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-017] No high-impact blueprints with owners found."
        Set-FindingOverride -FindingId "AGT-017" -Props $AGT017VariantProps.Secure
    }

    # AGT-002: Apply result for enabled foreign agent identities with extensive application API permissions.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-002] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-002" -Props $AGT002VariantProps.Skipped
    } elseif ($foreignAgentIdentitiesWithExtensiveApi.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-002] Found $($foreignAgentIdentitiesWithExtensiveApi.Count) enabled foreign agent identities with extensive application API privileges."
        Set-FindingOverride -FindingId "AGT-002" -Props $AGT002VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-002" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dtrue&Enabled=%3Dtrue&or_ApiDangerous=%3E0&or_ApiHigh=%3E0&or_ApiMedium=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CAgentUsers%2COwners%2CSponsors%2CApiDangerous%2CApiHigh%2CApiMedium%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt002Affected = [System.Collections.Generic.List[object]]::new()
        $agt002DangerousCount = 0
        $agt002HighCount = 0
        $agt002MediumCount = 0
        $agt002AssumedInheritedPermissionCount = 0
        $agt002AssumedInheritedIdentityCount = 0
        foreach ($agentIdentity in $foreignAgentIdentitiesWithExtensiveApi) {
            $apiDangerousValue = Get-IntSafe $agentIdentity.ApiDangerous
            $apiHighValue = Get-IntSafe $agentIdentity.ApiHigh
            $apiMediumValue = Get-IntSafe $agentIdentity.ApiMedium
            if ($apiDangerousValue -gt 0) { $agt002DangerousCount += 1 }
            if ($apiHighValue -gt 0) { $agt002HighCount += 1 }
            if ($apiMediumValue -gt 0) { $agt002MediumCount += 1 }

            $permissions = @()
            $identityHasAssumedInheritedPermissions = $false
            $permissionSourceRows = @()
            if ($agentIdentity.EffectiveApiPermissionSources) {
                $permissionSourceRows = @($agentIdentity.EffectiveApiPermissionSources)
            }
            if ($permissionSourceRows.Count -gt 0) {
                foreach ($level in @("Dangerous", "High", "Medium")) {
                    foreach ($source in $permissionSourceRows) {
                        if ($source.PermissionType -ne "Application" -or $source.Category -ne $level) { continue }

                        $permName = $source.Permission
                        $apiName = $source.ApiName
                        if (-not $apiName) { $apiName = "API" }

                        $originType = "$($source.OriginType)"
                        $originName = "$($source.OriginObjectDisplayName)"
                        if ([string]::IsNullOrWhiteSpace($originName)) { $originName = "$($source.OriginObjectId)" }
                        $originSuffix = switch ($originType) {
                            "Direct" { "direct" }
                            "ConfirmedInherited" { "inherited" }
                            "AssumedInherited" {
                                $agt002AssumedInheritedPermissionCount += 1
                                $identityHasAssumedInheritedPermissions = $true
                                "assumed inherited"
                            }
                            default {
                                if ([string]::IsNullOrWhiteSpace($originType)) { "source unknown" } else { $originType }
                            }
                        }

                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName ($originSuffix)"
                        }
                    }
                }
            } else {
                $rawPerms = @()
                if ($agentIdentity.EffectiveAppApiPermission) {
                    $rawPerms = @($agentIdentity.EffectiveAppApiPermission)
                } elseif ($agentIdentity.AppApiPermission) {
                    $rawPerms = @($agentIdentity.AppApiPermission)
                }
                foreach ($level in @("Dangerous", "High", "Medium")) {
                    foreach ($perm in $rawPerms) {
                        if ($perm.ApiPermissionCategorization -ne $level) { continue }
                        $permName = $perm.ApiPermission
                        if (-not $permName) { $permName = $perm.PermissionName }
                        if (-not $permName) { $permName = $perm.PermissionId }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = $perm.ResourceAppId }
                        if (-not $apiName) { $apiName = "API" }
                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName"
                        }
                    }
                }
            }
            if ($identityHasAssumedInheritedPermissions) {
                $agt002AssumedInheritedIdentityCount += 1
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }

            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt002Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Publisher Name" = $agentIdentity.PublisherName
                "Dangerous" = $agentIdentity.ApiDangerous
                "High" = $agentIdentity.ApiHigh
                "Medium" = $agentIdentity.ApiMedium
                "Application Permissions (>= Medium)" = $permissionDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }
        $agt002AssumedInheritanceNote = ""
        if ($agt002AssumedInheritedPermissionCount -gt 0) {
            $agt002AssumedInheritanceNote = "<p><strong>Note:</strong> $agt002AssumedInheritedPermissionCount displayed permissions across $agt002AssumedInheritedIdentityCount agent identities are marked as assumed inherited. This happens when the parent blueprint principal is foreign and the parent blueprint inheritance configuration cannot be read from this tenant.</p>"
        }
        Set-FindingOverride -FindingId "AGT-002" -Props @{
            Description = "<p>$($foreignAgentIdentitiesWithExtensiveApi.Count) enabled foreign agent identities have extensive API privileges assigned as application permissions.</p><p>Agent identities with the following privilege levels:</p><ul><li>Dangerous: $agt002DangerousCount</li><li>High: $agt002HighCount</li><li>Medium: $agt002MediumCount</li></ul>$agt002AssumedInheritanceNote"
            AffectedObjects = $agt002Affected
        }
        if ($agt002DangerousCount -gt 0) {
            # Escalate severity and threat text when dangerous permissions exist.
            Set-FindingOverride -FindingId "AGT-002" -Props @{
                Severity = 4
                Threat = "<p>Agent identities perform token acquisition and access resources directly. If a foreign agent identity has extensive application API permissions, compromise or misuse of the foreign parent relationship may allow access to sensitive tenant data or administrative actions.</p><p>Since at least one foreign agent identity has highly dangerous application API privileges, attackers may be able to compromise the whole tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-002] No enabled foreign agent identities with extensive application API privileges found."
        Set-FindingOverride -FindingId "AGT-002" -Props $AGT002VariantProps.Secure
    }

    # AGT-003: Apply result for enabled foreign agent identities with extensive delegated API permissions.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-003] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-003" -Props $AGT003VariantProps.Skipped
    } elseif ($foreignAgentIdentitiesWithDelegatedExtensiveApi.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-003] Found $($foreignAgentIdentitiesWithDelegatedExtensiveApi.Count) enabled foreign agent identities with extensive delegated API privileges."
        Set-FindingOverride -FindingId "AGT-003" -Props $AGT003VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-003" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dtrue&Enabled=%3Dtrue&or_ApiDelegatedDangerous=%3E0&or_ApiDelegatedHigh=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CAgentUsers%2COwners%2CSponsors%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CApiDelegatedMedium%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt003Affected = [System.Collections.Generic.List[object]]::new()
        $agt003DangerousCount = 0
        $agt003HighCount = 0
        $agt003AssumedInheritedPermissionCount = 0
        $agt003AssumedInheritedIdentityCount = 0
        foreach ($agentIdentity in $foreignAgentIdentitiesWithDelegatedExtensiveApi) {
            $apiDelegatedDangerousValue = Get-IntSafe $agentIdentity.ApiDelegatedDangerous
            $apiDelegatedHighValue = Get-IntSafe $agentIdentity.ApiDelegatedHigh
            if ($apiDelegatedDangerousValue -gt 0) { $agt003DangerousCount += 1 }
            if ($apiDelegatedHighValue -gt 0) { $agt003HighCount += 1 }

            $permissions = @()
            $identityHasAssumedInheritedPermissions = $false
            $permissionSourceRows = @()
            if ($agentIdentity.EffectiveApiPermissionSources) {
                $permissionSourceRows = @($agentIdentity.EffectiveApiPermissionSources)
            }
            if ($permissionSourceRows.Count -gt 0) {
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($source in $permissionSourceRows) {
                        if ($source.PermissionType -ne "Delegated" -or $source.Category -ne $level) { continue }

                        $scope = $source.Permission
                        $apiName = $source.ApiName
                        if (-not $apiName) { $apiName = "API" }
                        $detailParts = [System.Collections.Generic.List[string]]::new()
                        if ($source.ConsentType -eq "AllPrincipals") {
                            $detailParts.Add("All users")
                        } elseif ($source.ConsentType -eq "Principal") {
                            $detailParts.Add("some users")
                        }

                        $originType = "$($source.OriginType)"
                        $originName = "$($source.OriginObjectDisplayName)"
                        if ([string]::IsNullOrWhiteSpace($originName)) { $originName = "$($source.OriginObjectId)" }
                        $originSuffix = switch ($originType) {
                            "Direct" { "direct" }
                            "ConfirmedInherited" { "inherited" }
                            "AssumedInherited" {
                                $agt003AssumedInheritedPermissionCount += 1
                                $identityHasAssumedInheritedPermissions = $true
                                "assumed inherited"
                            }
                            default {
                                if ([string]::IsNullOrWhiteSpace($originType)) { "source unknown" } else { $originType }
                            }
                        }
                        if (-not [string]::IsNullOrWhiteSpace($originSuffix)) {
                            $detailParts.Add($originSuffix)
                        }
                        $detailSuffix = if ($detailParts.Count -gt 0) { " (" + ($detailParts -join ", ") + ")" } else { "" }

                        if ($scope) {
                            $permissions += "${level}: $scope on API $apiName$detailSuffix"
                        }
                    }
                }
            } else {
                $rawPerms = @()
                if ($agentIdentity.EffectiveApiDelegatedDetails) {
                    $rawPerms = @($agentIdentity.EffectiveApiDelegatedDetails)
                } elseif ($agentIdentity.ApiDelegatedDetails) {
                    $rawPerms = @($agentIdentity.ApiDelegatedDetails)
                }
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($perm in $rawPerms) {
                        if ($perm.ApiPermissionCategorization -ne $level) { continue }
                        $scope = $perm.Scope
                        if (-not $scope) { $scope = $perm.ApiPermission }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = $perm.ResourceAppId }
                        if (-not $apiName) { $apiName = "API" }
                        $consentInfo = ""
                        if ($perm.ConsentType -eq "AllPrincipals") {
                            $consentInfo = " (All users)"
                        } elseif ($perm.ConsentType -eq "Principal") {
                            $consentInfo = " (some users)"
                        }
                        if ($scope) {
                            $permissions += "${level}: $scope on API $apiName$consentInfo"
                        }
                    }
                }
            }
            if ($identityHasAssumedInheritedPermissions) {
                $agt003AssumedInheritedIdentityCount += 1
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }

            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt003Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Publisher Name" = $agentIdentity.PublisherName
                "Dangerous" = $agentIdentity.ApiDelegatedDangerous
                "High" = $agentIdentity.ApiDelegatedHigh
                "Delegated API Permissions (>= High)" = $permissionDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }
        $agt003AssumedInheritanceNote = ""
        if ($agt003AssumedInheritedPermissionCount -gt 0) {
            $agt003AssumedInheritanceNote = "<p><strong>Note:</strong> $agt003AssumedInheritedPermissionCount displayed permissions across $agt003AssumedInheritedIdentityCount agent identities are marked as assumed inherited. This happens when the parent blueprint principal is foreign and the parent blueprint inheritance configuration cannot be read from this tenant.</p>"
        }
        Set-FindingOverride -FindingId "AGT-003" -Props @{
            Description = "<p>$($foreignAgentIdentitiesWithDelegatedExtensiveApi.Count) enabled foreign agent identities have extensive delegated API privileges.</p><p>Agent identities with the following privilege levels:</p><ul><li>Dangerous: $agt003DangerousCount</li><li>High: $agt003HighCount</li></ul>$agt003AssumedInheritanceNote"
            AffectedObjects = $agt003Affected
        }
        if ($agt003DangerousCount -gt 0) {
            # Escalate severity and threat when dangerous delegated permissions exist.
            Set-FindingOverride -FindingId "AGT-003" -Props @{
                Severity = 3
                Threat = "<p>The parent blueprint of this agent identity is registered in an external organization's tenant.</p><p>If the external organization acts maliciously, or if its tenant or blueprint credentials are compromised by a third party, attackers may be able to abuse the delegated permissions associated with this agent identity on behalf of the affected user(s).</p><p>Since at least one foreign agent identity has highly dangerous delegated privileges, attackers may be able to compromise the tenant if a highly privileged user authenticates to the agent.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-003] No enabled foreign agent identities with extensive delegated API privileges found."
        Set-FindingOverride -FindingId "AGT-003" -Props $AGT003VariantProps.Secure
    }

    # AGT-004: Apply result for enabled foreign agent identities with Entra ID roles assigned.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-004] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-004" -Props $AGT004VariantProps.Skipped
    } elseif ($foreignAgentIdentitiesWithPrivilegedEntraRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-004] Found $($foreignAgentIdentitiesWithPrivilegedEntraRoles.Count) enabled foreign agent identities with Entra ID roles."
        Set-FindingOverride -FindingId "AGT-004" -Props $AGT004VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-004" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dtrue&Enabled=%3Dtrue&EntraMaxTier=Tier-0%7C%7CTier-1%7C%7CTier-2%7C%7CUncategorized&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }

        $agt004Tier0 = 0
        $agt004Tier1 = 0
        $agt004Tier2 = 0
        $agt004TierUncat = 0
        $agt004Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($agentIdentity in $foreignAgentIdentitiesWithPrivilegedEntraRoles) {
            $entraRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Entra)) {
                if (-not $entry.Role) { continue }
                $entraRoleEntries.Add($entry)
            }

            $tiersSeen = @{}
            $tier0Count = 0
            $tier1Count = 0
            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($tier in @("0", "1", "2", "Uncategorized")) {
                foreach ($entry in $entraRoleEntries) {
                    $role = $entry.Role
                    $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                    if ($roleTier -ne $tier) { continue }
                    $tiersSeen[$roleTier] = $true
                    if ($roleTier -eq "0") { $tier0Count += 1 }
                    if ($roleTier -eq "1") { $tier1Count += 1 }
                    $roleName = $role.DisplayName
                    if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                    if (-not $roleName) { $roleName = $role.RoleTemplateId }
                    $scopeName = $role.ScopeResolved.DisplayName
                    $scopeType = $role.ScopeResolved.Type
                    if (-not $scopeName) { $scopeName = "Tenant" }
                    if (-not $scopeType) { $scopeType = "Directory" }
                    if ($roleName -or $role.IsSynthetic) {
                        switch ($entry.Source) {
                            "Direct" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier} Entra Role (details not expanded)")
                                } else {
                                    $roleLines.Add("Tier ${roleTier} Entra Role: $roleName scoped to $scopeName ($scopeType)")
                                }
                            }
                            "GroupMember" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier} Entra Role through group membership '$($entry.GroupDisplayName)'")
                                } else {
                                    $roleLines.Add("Tier ${roleTier} Entra Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                                }
                            }
                            "GroupOwner" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier} Entra Role through group ownership '$($entry.GroupDisplayName)'")
                                } else {
                                    $roleLines.Add("Tier ${roleTier} Entra Role: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                                }
                            }
                        }
                    }
                }
            }

            if ($tiersSeen.ContainsKey("0")) { $agt004Tier0 += 1 }
            if ($tiersSeen.ContainsKey("1")) { $agt004Tier1 += 1 }
            if ($tiersSeen.ContainsKey("2")) { $agt004Tier2 += 1 }
            if ($tiersSeen.ContainsKey("Uncategorized") -or $tiersSeen.Keys.Count -eq 0) { $agt004TierUncat += 1 }
            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt004Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Publisher Name" = $agentIdentity.PublisherName
                "Tier 0 Entra Roles" = $tier0Count
                "Tier 1 Entra Roles" = $tier1Count
                "Entra Roles" = $roleDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-004" -Props @{
            Description = "<p>$($foreignAgentIdentitiesWithPrivilegedEntraRoles.Count) enabled foreign agent identities have Entra ID roles assigned.</p><p>Agent identities by role tier:</p><ul><li>Tier 0: $agt004Tier0</li><li>Tier 1: $agt004Tier1</li><li>Tier 2: $agt004Tier2</li><li>Uncategorized tier: $agt004TierUncat</li></ul>"
            AffectedObjects = $agt004Affected
        }
        if ($agt004Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-004" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent identity and abuse its Entra ID role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged tenant resources.</p><p>Since at least one foreign agent identity has a Tier-0 Entra ID role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-004] No enabled foreign agent identities with Entra ID roles found."
        Set-FindingOverride -FindingId "AGT-004" -Props $AGT004VariantProps.Secure
    }

    # AGT-005: Apply result for enabled foreign agent identities with Azure roles.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-005] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-005" -Props $AGT005VariantProps.Skipped
    } elseif ($foreignAgentIdentitiesWithPrivilegedAzureRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-005] Found $($foreignAgentIdentitiesWithPrivilegedAzureRoles.Count) enabled foreign agent identities with Azure roles."
        Set-FindingOverride -FindingId "AGT-005" -Props $AGT005VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-005" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dtrue&Enabled=%3Dtrue&AzureMaxTier=Tier-0%7C%7CTier-1%7C%7CTier-2%7C%7CUncategorized&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }

        $agt005Tier0 = 0
        $agt005Tier1 = 0
        $agt005Tier2 = 0
        $agt005TierUncat = 0
        $agt005Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($agentIdentity in $foreignAgentIdentitiesWithPrivilegedAzureRoles) {
            $azureRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Azure)) {
                if (-not $entry.Role) { continue }
                $azureRoleEntries.Add($entry)
            }

            $tiersSeen = @{}
            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($tier in @("0", "1", "2", "Uncategorized")) {
                foreach ($entry in $azureRoleEntries) {
                    $role = $entry.Role
                    $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                    if ($roleTier -ne $tier) { continue }
                    $tiersSeen[$roleTier] = $true
                    $roleName = $role.RoleName
                    if (-not $roleName) { $roleName = $role.DisplayName }
                    if (-not $roleName) { $roleName = $role.RoleDefinitionName }
                    if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                    $scope = $role.Scope
                    if (-not $scope -and $role.ScopeResolved) {
                        $scopeResolvedName = "$($role.ScopeResolved.DisplayName)".Trim()
                        $scopeResolvedType = "$($role.ScopeResolved.Type)".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($scopeResolvedName) -and -not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                            $scope = "$scopeResolvedName ($scopeResolvedType)"
                        } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedName)) {
                            $scope = $scopeResolvedName
                        } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                            $scope = $scopeResolvedType
                        }
                    }
                    if (-not $scope) { $scope = "Unknown scope" }
                    if ($roleName -or $role.IsSynthetic) {
                        switch ($entry.Source) {
                            "Direct" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier}: Azure role details not expanded")
                                } else {
                                    $roleLines.Add("Tier ${roleTier}: $roleName scoped to $scope")
                                }
                            }
                            "GroupMember" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier}: Azure role through group membership '$($entry.GroupDisplayName)' (details not expanded)")
                                } else {
                                    $roleLines.Add("Tier ${roleTier}: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scope")
                                }
                            }
                            "GroupOwner" {
                                if ($role.IsSynthetic) {
                                    $roleLines.Add("Tier ${roleTier}: Azure role through group ownership '$($entry.GroupDisplayName)' (details not expanded)")
                                } else {
                                    $roleLines.Add("Tier ${roleTier}: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scope")
                                }
                            }
                        }
                    }
                }
            }

            if ($tiersSeen.ContainsKey("0")) { $agt005Tier0 += 1 }
            if ($tiersSeen.ContainsKey("1")) { $agt005Tier1 += 1 }
            if ($tiersSeen.ContainsKey("2")) { $agt005Tier2 += 1 }
            if ($tiersSeen.ContainsKey("Uncategorized") -or $tiersSeen.Keys.Count -eq 0) { $agt005TierUncat += 1 }

            $tier0Count = @($azureRoleEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "0" }).Count
            $tier1Count = @($azureRoleEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "1" }).Count
            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt005Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Publisher Name" = $agentIdentity.PublisherName
                "Tier 0 Azure Roles" = $tier0Count
                "Tier 1 Azure Roles" = $tier1Count
                "Azure Roles" = $roleDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }

        Set-FindingOverride -FindingId "AGT-005" -Props @{
            Description = "<p>$($foreignAgentIdentitiesWithPrivilegedAzureRoles.Count) enabled foreign agent identities have Azure roles assigned.</p><p>Agent identities by role tier:</p><ul><li>Tier 0: $agt005Tier0</li><li>Tier 1: $agt005Tier1</li><li>Tier 2: $agt005Tier2</li><li>Uncategorized tier: $agt005TierUncat</li></ul><p><strong>Note:</strong> The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission. The effective impact depends on the resources to which the role is scoped.</p>"
            AffectedObjects = $agt005Affected
        }
        if ($agt005Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-005" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent identity and abuse its Azure role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged Azure resources.</p><p>Since at least one foreign agent identity has a Tier-0 Azure role assigned, attackers may be able to compromise critical Azure resources.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-005] No enabled foreign agent identities with Azure roles found."
        Set-FindingOverride -FindingId "AGT-005" -Props $AGT005VariantProps.Secure
    }

    # AGT-006: Apply result for enabled internal agent identities with extensive application API permissions.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-006] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-006" -Props $AGT006VariantProps.Skipped
    } elseif ($internalAgentIdentitiesWithExtensiveApi.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-006] Found $($internalAgentIdentitiesWithExtensiveApi.Count) enabled internal agent identities with extensive application API privileges."
        Set-FindingOverride -FindingId "AGT-006" -Props $AGT006VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-006" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dfalse&Enabled=%3Dtrue&or_ApiDangerous=%3E0&or_ApiHigh=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CAgentUsers%2COwners%2CSponsors%2CApiDangerous%2CApiHigh%2CApiMedium%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt006Affected = [System.Collections.Generic.List[object]]::new()
        $agt006DangerousCount = 0
        $agt006HighCount = 0
        $agt006AssumedInheritedPermissionCount = 0
        $agt006AssumedInheritedIdentityCount = 0
        foreach ($agentIdentity in $internalAgentIdentitiesWithExtensiveApi) {
            $apiDangerousValue = Get-IntSafe $agentIdentity.ApiDangerous
            $apiHighValue = Get-IntSafe $agentIdentity.ApiHigh
            if ($apiDangerousValue -gt 0) { $agt006DangerousCount += 1 }
            if ($apiHighValue -gt 0) { $agt006HighCount += 1 }

            $permissions = @()
            $identityHasAssumedInheritedPermissions = $false
            $permissionSourceRows = @()
            if ($agentIdentity.EffectiveApiPermissionSources) {
                $permissionSourceRows = @($agentIdentity.EffectiveApiPermissionSources)
            }
            if ($permissionSourceRows.Count -gt 0) {
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($source in $permissionSourceRows) {
                        if ($source.PermissionType -ne "Application" -or $source.Category -ne $level) { continue }

                        $permName = $source.Permission
                        $apiName = $source.ApiName
                        if (-not $apiName) { $apiName = "API" }

                        $originType = "$($source.OriginType)"
                        $originName = "$($source.OriginObjectDisplayName)"
                        if ([string]::IsNullOrWhiteSpace($originName)) { $originName = "$($source.OriginObjectId)" }
                        $originSuffix = switch ($originType) {
                            "Direct" { "direct" }
                            "ConfirmedInherited" { "inherited" }
                            "AssumedInherited" {
                                $agt006AssumedInheritedPermissionCount += 1
                                $identityHasAssumedInheritedPermissions = $true
                                "assumed inherited"
                            }
                            default {
                                if ([string]::IsNullOrWhiteSpace($originType)) { "source unknown" } else { $originType }
                            }
                        }

                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName ($originSuffix)"
                        }
                    }
                }
            } else {
                $rawPerms = @()
                if ($agentIdentity.EffectiveAppApiPermission) {
                    $rawPerms = @($agentIdentity.EffectiveAppApiPermission)
                } elseif ($agentIdentity.AppApiPermission) {
                    $rawPerms = @($agentIdentity.AppApiPermission)
                }
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($perm in $rawPerms) {
                        if ($perm.ApiPermissionCategorization -ne $level) { continue }
                        $permName = $perm.ApiPermission
                        if (-not $permName) { $permName = $perm.PermissionName }
                        if (-not $permName) { $permName = $perm.PermissionId }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = $perm.ResourceAppId }
                        if (-not $apiName) { $apiName = "API" }
                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName"
                        }
                    }
                }
            }
            if ($identityHasAssumedInheritedPermissions) {
                $agt006AssumedInheritedIdentityCount += 1
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }

            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt006Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Dangerous" = $agentIdentity.ApiDangerous
                "High" = $agentIdentity.ApiHigh
                "Application Permissions (>= High)" = $permissionDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }
        $agt006AssumedInheritanceNote = ""
        if ($agt006AssumedInheritedPermissionCount -gt 0) {
            $agt006AssumedInheritanceNote = "<p><strong>Note:</strong> $agt006AssumedInheritedPermissionCount displayed permissions across $agt006AssumedInheritedIdentityCount agent identities are marked as assumed inherited. This happens when the parent blueprint inheritance configuration cannot be fully read from this tenant.</p>"
        }
        Set-FindingOverride -FindingId "AGT-006" -Props @{
            Description = "<p>$($internalAgentIdentitiesWithExtensiveApi.Count) enabled internal agent identities have extensive API privileges assigned as application permissions.</p><p>Agent identities with the following privilege levels:</p><ul><li>Dangerous: $agt006DangerousCount</li><li>High: $agt006HighCount</li></ul>$agt006AssumedInheritanceNote"
            AffectedObjects = $agt006Affected
        }
        if ($agt006DangerousCount -gt 0) {
            Set-FindingOverride -FindingId "AGT-006" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity. They could then authenticate as the agent identity and abuse its assigned application API privileges.</p><p>Since at least one internal agent identity has highly dangerous application API privileges, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-006] No enabled internal agent identities with extensive application API privileges found."
        Set-FindingOverride -FindingId "AGT-006" -Props $AGT006VariantProps.Secure
    }

    # AGT-007: Apply result for enabled internal agent identities with extensive delegated API permissions.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-007] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-007" -Props $AGT007VariantProps.Skipped
    } elseif ($internalAgentIdentitiesWithDelegatedExtensiveApi.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-007] Found $($internalAgentIdentitiesWithDelegatedExtensiveApi.Count) enabled internal agent identities with extensive delegated API privileges."
        Set-FindingOverride -FindingId "AGT-007" -Props $AGT007VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-007" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dfalse&Enabled=%3Dtrue&or_ApiDelegatedDangerous=%3E0&or_ApiDelegatedHigh=%3E0&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CAgentUsers%2COwners%2CSponsors%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CApiDelegatedMedium%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt007Affected = [System.Collections.Generic.List[object]]::new()
        $agt007DangerousCount = 0
        $agt007HighCount = 0
        $agt007AssumedInheritedPermissionCount = 0
        $agt007AssumedInheritedIdentityCount = 0
        foreach ($agentIdentity in $internalAgentIdentitiesWithDelegatedExtensiveApi) {
            $apiDelegatedDangerousValue = Get-IntSafe $agentIdentity.ApiDelegatedDangerous
            $apiDelegatedHighValue = Get-IntSafe $agentIdentity.ApiDelegatedHigh
            if ($apiDelegatedDangerousValue -gt 0) { $agt007DangerousCount += 1 }
            if ($apiDelegatedHighValue -gt 0) { $agt007HighCount += 1 }

            $permissions = @()
            $identityHasAssumedInheritedPermissions = $false
            $permissionSourceRows = @()
            if ($agentIdentity.EffectiveApiPermissionSources) {
                $permissionSourceRows = @($agentIdentity.EffectiveApiPermissionSources)
            }
            if ($permissionSourceRows.Count -gt 0) {
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($source in $permissionSourceRows) {
                        if ($source.PermissionType -ne "Delegated" -or $source.Category -ne $level) { continue }

                        $scope = $source.Permission
                        $apiName = $source.ApiName
                        if (-not $apiName) { $apiName = "API" }
                        $detailParts = [System.Collections.Generic.List[string]]::new()
                        if ($source.ConsentType -eq "AllPrincipals") {
                            $detailParts.Add("All users")
                        } elseif ($source.ConsentType -eq "Principal") {
                            $detailParts.Add("some users")
                        }

                        $originType = "$($source.OriginType)"
                        $originSuffix = switch ($originType) {
                            "Direct" { "direct" }
                            "ConfirmedInherited" { "inherited" }
                            "AssumedInherited" {
                                $agt007AssumedInheritedPermissionCount += 1
                                $identityHasAssumedInheritedPermissions = $true
                                "assumed inherited"
                            }
                            default {
                                if ([string]::IsNullOrWhiteSpace($originType)) { "source unknown" } else { $originType }
                            }
                        }
                        if (-not [string]::IsNullOrWhiteSpace($originSuffix)) {
                            $detailParts.Add($originSuffix)
                        }
                        $detailSuffix = if ($detailParts.Count -gt 0) { " (" + ($detailParts -join ", ") + ")" } else { "" }

                        if ($scope) {
                            $permissions += "${level}: $scope on API $apiName$detailSuffix"
                        }
                    }
                }
            } else {
                $rawPerms = @()
                if ($agentIdentity.EffectiveApiDelegatedDetails) {
                    $rawPerms = @($agentIdentity.EffectiveApiDelegatedDetails)
                } elseif ($agentIdentity.ApiDelegatedDetails) {
                    $rawPerms = @($agentIdentity.ApiDelegatedDetails)
                }
                foreach ($level in @("Dangerous", "High")) {
                    foreach ($perm in $rawPerms) {
                        if ($perm.ApiPermissionCategorization -ne $level) { continue }
                        $scope = $perm.Scope
                        if (-not $scope) { $scope = $perm.ApiPermission }
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = $perm.ResourceAppId }
                        if (-not $apiName) { $apiName = "API" }
                        $consentInfo = ""
                        if ($perm.ConsentType -eq "AllPrincipals") {
                            $consentInfo = " (All users)"
                        } elseif ($perm.ConsentType -eq "Principal") {
                            $consentInfo = " (some users)"
                        }
                        if ($scope) {
                            $permissions += "${level}: $scope on API $apiName$consentInfo"
                        }
                    }
                }
            }
            if ($identityHasAssumedInheritedPermissions) {
                $agt007AssumedInheritedIdentityCount += 1
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }

            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt007Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Dangerous" = $agentIdentity.ApiDelegatedDangerous
                "High" = $agentIdentity.ApiDelegatedHigh
                "Delegated API Permissions (>= High)" = $permissionDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }
        $agt007AssumedInheritanceNote = ""
        if ($agt007AssumedInheritedPermissionCount -gt 0) {
            $agt007AssumedInheritanceNote = "<p><strong>Note:</strong> $agt007AssumedInheritedPermissionCount displayed permissions across $agt007AssumedInheritedIdentityCount agent identities are marked as assumed inherited. This happens when the parent blueprint inheritance configuration cannot be fully read from this tenant.</p>"
        }
        Set-FindingOverride -FindingId "AGT-007" -Props @{
            Description = "<p>$($internalAgentIdentitiesWithDelegatedExtensiveApi.Count) enabled internal agent identities have extensive delegated API privileges.</p><p>Agent identities with the following privilege levels:</p><ul><li>Dangerous: $agt007DangerousCount</li><li>High: $agt007HighCount</li></ul>$agt007AssumedInheritanceNote"
            AffectedObjects = $agt007Affected
        }
        if ($agt007DangerousCount -gt 0) {
            Set-FindingOverride -FindingId "AGT-007" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity. Depending on how the agent identity is used, they may then be able to abuse the delegated permissions associated with it on behalf of the affected user(s).</p><p>Since at least one internal agent identity has highly dangerous delegated API privileges, attackers may be able to compromise the entire tenant if a highly privileged user authenticates to the agent.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-007] No enabled internal agent identities with extensive delegated API privileges found."
        Set-FindingOverride -FindingId "AGT-007" -Props $AGT007VariantProps.Secure
    }

    # AGT-008: Apply result for enabled internal agent identities with privileged Entra ID roles.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-008] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-008" -Props $AGT008VariantProps.Skipped
    } elseif ($internalAgentIdentitiesWithPrivilegedEntraRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-008] Found $($internalAgentIdentitiesWithPrivilegedEntraRoles.Count) enabled internal agent identities with privileged Entra ID roles."
        Set-FindingOverride -FindingId "AGT-008" -Props $AGT008VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-008" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dfalse&Enabled=%3Dtrue&EntraMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }

        $agt008Tier0 = 0
        $agt008Tier1 = 0
        $agt008Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($agentIdentity in $internalAgentIdentitiesWithPrivilegedEntraRoles) {
            $entraRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Entra)) {
                if (-not $entry.Role) { continue }
                $entraRoleEntries.Add($entry)
            }

            $entraTierEntries = @()
            foreach ($entry in $entraRoleEntries) {
                $role = $entry.Role
                if (-not $role) { continue }
                $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                if ($roleTier -ne "0" -and $roleTier -ne "1") { continue }
                $entraTierEntries += $entry
            }

            $tier0Count = @($entraTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "0" }).Count
            $tier1Count = @($entraTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "1" }).Count
            if ($tier0Count -gt 0) { $agt008Tier0 += 1 }
            if ($tier1Count -gt 0) { $agt008Tier1 += 1 }

            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in @($entraTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "0" })) {
                $role = $entry.Role
                $roleName = $role.DisplayName
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scopeName = $role.ScopeResolved.DisplayName
                $scopeType = $role.ScopeResolved.Type
                if (-not $scopeName) { $scopeName = "Tenant" }
                if (-not $scopeType) { $scopeType = "Directory" }
                if ($roleName -or $role.IsSynthetic) {
                    switch ($entry.Source) {
                        "Direct" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Entra Role (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Entra Role: $roleName scoped to $scopeName ($scopeType)")
                            }
                        }
                        "GroupMember" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Entra Role through group membership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Entra Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                            }
                        }
                        "GroupOwner" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Entra Role through group ownership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Entra Role: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                            }
                        }
                    }
                }
            }
            foreach ($entry in @($entraTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "1" })) {
                $role = $entry.Role
                $roleName = $role.DisplayName
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scopeName = $role.ScopeResolved.DisplayName
                $scopeType = $role.ScopeResolved.Type
                if (-not $scopeName) { $scopeName = "Tenant" }
                if (-not $scopeType) { $scopeType = "Directory" }
                if ($roleName -or $role.IsSynthetic) {
                    switch ($entry.Source) {
                        "Direct" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Entra Role (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Entra Role: $roleName scoped to $scopeName ($scopeType)")
                            }
                        }
                        "GroupMember" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Entra Role through group membership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Entra Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                            }
                        }
                        "GroupOwner" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Entra Role through group ownership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Entra Role: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scopeName ($scopeType)")
                            }
                        }
                    }
                }
            }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt008Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Tier 0 Entra Roles" = $tier0Count
                "Tier 1 Entra Roles" = $tier1Count
                "Entra Roles" = $roleDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }

        Set-FindingOverride -FindingId "AGT-008" -Props @{
            Description = "<p>$($internalAgentIdentitiesWithPrivilegedEntraRoles.Count) enabled internal agent identities have privileged Entra ID roles (tier-0 or tier-1) assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $agt008Tier0</li><li>Tier 1: $agt008Tier1</li></ul>"
            AffectedObjects = $agt008Affected
        }
        if ($agt008Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-008" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity and abuse its Entra ID role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged tenant resources.</p><p>Since at least one internal agent identity has a Tier-0 Entra ID role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-008] No enabled internal agent identities with privileged Entra ID roles found."
        Set-FindingOverride -FindingId "AGT-008" -Props $AGT008VariantProps.Secure
    }

    # AGT-009: Apply result for enabled internal agent identities with privileged Azure roles.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-009] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-009" -Props $AGT009VariantProps.Skipped
    } elseif ($internalAgentIdentitiesWithPrivilegedAzureRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-009] Found $($internalAgentIdentitiesWithPrivilegedAzureRoles.Count) enabled internal agent identities with privileged Azure roles."
        Set-FindingOverride -FindingId "AGT-009" -Props $AGT009VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-009" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Foreign=%3Dfalse&Enabled=%3Dtrue&AzureMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }

        $agt009Tier0 = 0
        $agt009Tier1 = 0
        $agt009Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($agentIdentity in $internalAgentIdentitiesWithPrivilegedAzureRoles) {
            $azureRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in @(Get-AgentIdentityEffectiveRoleEntries -AgentIdentity $agentIdentity -RoleSystem Azure)) {
                if (-not $entry.Role) { continue }
                $azureRoleEntries.Add($entry)
            }

            $azureTierEntries = @()
            foreach ($entry in $azureRoleEntries) {
                $role = $entry.Role
                if (-not $role) { continue }
                $roleTier = Get-NormalizedRoleTierLabel -RoleTier $role.RoleTier
                if ($roleTier -ne "0" -and $roleTier -ne "1") { continue }
                $azureTierEntries += $entry
            }

            $tier0Count = @($azureTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "0" }).Count
            $tier1Count = @($azureTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "1" }).Count
            if ($tier0Count -gt 0) { $agt009Tier0 += 1 }
            if ($tier1Count -gt 0) { $agt009Tier1 += 1 }

            $roleLines = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in @($azureTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "0" })) {
                $role = $entry.Role
                $roleName = $role.RoleName
                if (-not $roleName) { $roleName = $role.DisplayName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scope = $role.Scope
                if (-not $scope -and $role.ScopeResolved) {
                    $scopeResolvedName = "$($role.ScopeResolved.DisplayName)".Trim()
                    $scopeResolvedType = "$($role.ScopeResolved.Type)".Trim()
                    if (-not [string]::IsNullOrWhiteSpace($scopeResolvedName) -and -not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                        $scope = "$scopeResolvedName ($scopeResolvedType)"
                    } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedName)) {
                        $scope = $scopeResolvedName
                    } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                        $scope = $scopeResolvedType
                    }
                }
                if (-not $scope) { $scope = "Unknown scope" }
                if ($roleName -or $role.IsSynthetic) {
                    switch ($entry.Source) {
                        "Direct" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Azure Role (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Azure Role: $roleName scoped to $scope")
                            }
                        }
                        "GroupMember" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Azure Role through group membership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Azure Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scope")
                            }
                        }
                        "GroupOwner" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 0 Azure Role through group ownership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 0 Azure Role: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scope")
                            }
                        }
                    }
                }
            }
            foreach ($entry in @($azureTierEntries | Where-Object { (Get-NormalizedRoleTierLabel -RoleTier $_.Role.RoleTier) -eq "1" })) {
                $role = $entry.Role
                $roleName = $role.RoleName
                if (-not $roleName) { $roleName = $role.DisplayName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionName }
                if (-not $roleName) { $roleName = $role.RoleDefinitionId }
                $scope = $role.Scope
                if (-not $scope -and $role.ScopeResolved) {
                    $scopeResolvedName = "$($role.ScopeResolved.DisplayName)".Trim()
                    $scopeResolvedType = "$($role.ScopeResolved.Type)".Trim()
                    if (-not [string]::IsNullOrWhiteSpace($scopeResolvedName) -and -not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                        $scope = "$scopeResolvedName ($scopeResolvedType)"
                    } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedName)) {
                        $scope = $scopeResolvedName
                    } elseif (-not [string]::IsNullOrWhiteSpace($scopeResolvedType)) {
                        $scope = $scopeResolvedType
                    }
                }
                if (-not $scope) { $scope = "Unknown scope" }
                if ($roleName -or $role.IsSynthetic) {
                    switch ($entry.Source) {
                        "Direct" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Azure Role (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Azure Role: $roleName scoped to $scope")
                            }
                        }
                        "GroupMember" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Azure Role through group membership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Azure Role: $roleName through group membership '$($entry.GroupDisplayName)' scoped to $scope")
                            }
                        }
                        "GroupOwner" {
                            if ($role.IsSynthetic) {
                                $roleLines.Add("Tier 1 Azure Role through group ownership '$($entry.GroupDisplayName)' (details not expanded)")
                            } else {
                                $roleLines.Add("Tier 1 Azure Role: $roleName through group ownership '$($entry.GroupDisplayName)' scoped to $scope")
                            }
                        }
                    }
                }
            }

            $roleDisplay = if ($roleLines.Count -gt 0) { ($roleLines | Sort-Object -Unique) -join "<br>" } else { "" }
            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt009Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Tier 0 Azure Roles" = $tier0Count
                "Tier 1 Azure Roles" = $tier1Count
                "Azure Roles" = $roleDisplay
                "_SortRisk" = $agentIdentity.Risk
            })
        }

        Set-FindingOverride -FindingId "AGT-009" -Props @{
            Description = "<p>$($internalAgentIdentitiesWithPrivilegedAzureRoles.Count) enabled internal agent identities have privileged Azure roles (tier-0 or tier-1) assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $agt009Tier0</li><li>Tier 1: $agt009Tier1</li></ul><p><strong>Note:</strong> The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission. The effective impact depends on the resources to which the role is scoped.</p>"
            AffectedObjects = $agt009Affected
        }
        if ($agt009Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-009" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may be able to take control of the agent identity and abuse its Azure role assignments. As agent identities authenticate without an interactive user, such a compromise could directly affect privileged Azure resources.</p><p>Since at least one internal agent identity has a Tier-0 Azure role assigned, attackers may be able to compromise critical Azure resources.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-009] No enabled internal agent identities with privileged Azure roles found."
        Set-FindingOverride -FindingId "AGT-009" -Props $AGT009VariantProps.Secure
    }

    # AGT-010: Apply result for enabled inactive agent identities.
    if ($agentIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-010] Skipped because no agent identities were found."
        Set-FindingOverride -FindingId "AGT-010" -Props $AGT010VariantProps.Skipped
    } elseif ($inactiveEnabledAgentIdentities.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-010] Found $($inactiveEnabledAgentIdentities.Count) inactive agent identities that are enabled."
        Set-FindingOverride -FindingId "AGT-010" -Props $AGT010VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-010" -Props @{
            RelatedReportUrl = "AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Inactive=%3Dtrue&Enabled=%3Dtrue&columns=DisplayName%2CPublisherName%2CForeign%2CEnabled%2CInactive%2CLastSignInDays%2CCreationInDays%2CAgentUsers%2COwners%2CSponsors%2CEntraRoles%2CAzureRoles%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiDelegatedDangerous%2CApiDelegatedHigh%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=LastSignInDays&sortDir=desc"
            AffectedSortKey = "Last sign-in (days)"
            AffectedSortDir = "DESC"
        }
        $agt010Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($agentIdentity in $inactiveEnabledAgentIdentities) {
            $parentPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($agentIdentity.ParentBlueprintPrincipalId)")) {
                $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalDisplayName
                if (-not $parentPrincipalName) { $parentPrincipalName = $agentIdentity.ParentBlueprintPrincipalId }
                $parentPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentPrincipalName</a>"
            }

            $agt010Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($agentIdentity.Id)`" target=`"_blank`">$($agentIdentity.DisplayName)</a>"
                "Parent Blueprint Principal" = $parentPrincipal
                "Inactive" = $agentIdentity.Inactive
                "Last sign-in (days)" = $agentIdentity.LastSignInDays
                "Foreign Agent" = $agentIdentity.Foreign
            })
        }
        Set-FindingOverride -FindingId "AGT-010" -Props @{
            Description = "<p>There are $($inactiveEnabledAgentIdentities.Count) enabled agent identities with no sign-in activities over the last 180 days.</p>"
            AffectedObjects = $agt010Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-010] No inactive agent identities found."
        Set-FindingOverride -FindingId "AGT-010" -Props $AGT010VariantProps.Secure
    }

    # AGT-011: Apply result for enabled foreign agent users with Entra ID roles assigned.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-011] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-011" -Props $AGT011VariantProps.Skipped
    } elseif ($foreignAgentUsersWithPrivilegedEntraRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-011] Found $($foreignAgentUsersWithPrivilegedEntraRoles.Count) enabled foreign agent users with Entra ID roles."
        Set-FindingOverride -FindingId "AGT-011" -Props $AGT011VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-011" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&ForeignAgent=%3Dtrue&Enabled=%3Dtrue&EntraRoles=%3E0&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt011Tier0 = 0
        $agt011Tier1 = 0
        $agt011Tier2 = 0
        $agt011TierUncat = 0
        $agt011Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $foreignAgentUsersWithPrivilegedEntraRoles) {
            $user = $entry.User
            $entraMaxTier = "$($user.EntraMaxTier)".Trim()
            switch ($entraMaxTier) {
                "Tier-0" { $agt011Tier0 += 1 }
                "Tier-1" { $agt011Tier1 += 1 }
                "Tier-2" { $agt011Tier2 += 1 }
                default { $agt011TierUncat += 1 }
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $agt011Affected.Add([pscustomobject][ordered]@{
                "UPN" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Entra Roles" = $user.EntraRoles
                "Entra Max Tier" = $user.EntraMaxTier
                "Warnings" = $user.Warnings
                "_SortRisk" = $user.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-011" -Props @{
            Description = "<p>$($foreignAgentUsersWithPrivilegedEntraRoles.Count) enabled foreign agent users have Entra ID roles assigned.</p><p>Agent users by highest role tier:</p><ul><li>Tier 0: $agt011Tier0</li><li>Tier 1: $agt011Tier1</li><li>Tier 2: $agt011Tier2</li><li>Uncategorized tier: $agt011TierUncat</li></ul>"
            AffectedObjects = $agt011Affected
        }
        if ($agt011Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-011" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent user and abuse its Entra ID role assignments.</p><p>Since at least one foreign agent user has a Tier-0 Entra ID role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-011] No enabled foreign agent users with Entra ID roles found."
        Set-FindingOverride -FindingId "AGT-011" -Props $AGT011VariantProps.Secure
    }

    # AGT-012: Apply result for enabled foreign agent users with Azure roles.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-012] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-012" -Props $AGT012VariantProps.Skipped
    } elseif ($foreignAgentUsersWithPrivilegedAzureRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-012] Found $($foreignAgentUsersWithPrivilegedAzureRoles.Count) enabled foreign agent users with Azure roles."
        Set-FindingOverride -FindingId "AGT-012" -Props $AGT012VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-012" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&ForeignAgent=%3Dtrue&Enabled=%3Dtrue&AzureRoles=%3E0&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt012Tier0 = 0
        $agt012Tier1 = 0
        $agt012Tier2 = 0
        $agt012TierUncat = 0
        $agt012Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $foreignAgentUsersWithPrivilegedAzureRoles) {
            $user = $entry.User
            $azureMaxTier = "$($user.AzureMaxTier)".Trim()
            switch ($azureMaxTier) {
                "Tier-0" { $agt012Tier0 += 1 }
                "Tier-1" { $agt012Tier1 += 1 }
                "Tier-2" { $agt012Tier2 += 1 }
                default { $agt012TierUncat += 1 }
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $agt012Affected.Add([pscustomobject][ordered]@{
                "UPN" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Azure Roles" = $user.AzureRoles
                "Azure Max Tier" = $user.AzureMaxTier
                "Warnings" = $user.Warnings
                "_SortRisk" = $user.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-012" -Props @{
            Description = "<p>$($foreignAgentUsersWithPrivilegedAzureRoles.Count) enabled foreign agent users have Azure roles assigned.</p><p>Agent users by highest role tier:</p><ul><li>Tier 0: $agt012Tier0</li><li>Tier 1: $agt012Tier1</li><li>Tier 2: $agt012Tier2</li><li>Uncategorized tier: $agt012TierUncat</li></ul><p><strong>Note:</strong> The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission. The effective impact depends on the resources to which the role is scoped.</p>"
            AffectedObjects = $agt012Affected
        }
        if ($agt012Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-012" -Props @{
                Severity = 4
                Threat = "<p>If the external tenant of the corresponding parent blueprint is compromised or its client credentials are leaked, attackers may gain control of the agent user and abuse its Azure role assignments.</p><p>Since at least one foreign agent user has a Tier-0 Azure role assigned, attackers may be able to compromise critical Azure resources.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-012] No enabled foreign agent users with Azure roles found."
        Set-FindingOverride -FindingId "AGT-012" -Props $AGT012VariantProps.Secure
    }

    # AGT-013: Apply result for enabled internal agent users with privileged Entra ID roles.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-013] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-013" -Props $AGT013VariantProps.Skipped
    } elseif ($internalAgentUsersWithPrivilegedEntraRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-013] Found $($internalAgentUsersWithPrivilegedEntraRoles.Count) enabled internal agent users with privileged Entra ID roles."
        Set-FindingOverride -FindingId "AGT-013" -Props $AGT013VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-013" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&ForeignAgent=%3Dfalse&Enabled=%3Dtrue&EntraMaxTier=Tier-0%7C%7CTier-1&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt013Tier0 = 0
        $agt013Tier1 = 0
        $agt013Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $internalAgentUsersWithPrivilegedEntraRoles) {
            $user = $entry.User
            $entraMaxTier = "$($user.EntraMaxTier)".Trim()
            switch ($entraMaxTier) {
                "Tier-0" { $agt013Tier0 += 1 }
                "Tier-1" { $agt013Tier1 += 1 }
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $agt013Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Entra Roles" = $user.EntraRoles
                "Entra Max Tier" = $user.EntraMaxTier
                "Warnings" = $user.Warnings
                "_SortRisk" = $user.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-013" -Props @{
            Description = "<p>$($internalAgentUsersWithPrivilegedEntraRoles.Count) enabled internal agent users have privileged Entra ID roles assigned.</p><p>Agent users by highest role tier:</p><ul><li>Tier 0: $agt013Tier0</li><li>Tier 1: $agt013Tier1</li></ul>"
            AffectedObjects = $agt013Affected
        }
        if ($agt013Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-013" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may gain control of the agent user and abuse its Entra ID role assignments.</p><p>Since at least one internal agent user has a Tier-0 Entra ID role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-013] No enabled internal agent users with privileged Entra ID roles found."
        Set-FindingOverride -FindingId "AGT-013" -Props $AGT013VariantProps.Secure
    }

    # AGT-014: Apply result for enabled internal agent users with privileged Azure roles.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-014] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-014" -Props $AGT014VariantProps.Skipped
    } elseif ($internalAgentUsersWithPrivilegedAzureRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-014] Found $($internalAgentUsersWithPrivilegedAzureRoles.Count) enabled internal agent users with privileged Azure roles."
        Set-FindingOverride -FindingId "AGT-014" -Props $AGT014VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-014" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&ForeignAgent=%3Dfalse&Enabled=%3Dtrue&AzureMaxTier=Tier-0%7C%7CTier-1&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt014Tier0 = 0
        $agt014Tier1 = 0
        $agt014Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $internalAgentUsersWithPrivilegedAzureRoles) {
            $user = $entry.User
            $azureMaxTier = "$($user.AzureMaxTier)".Trim()
            switch ($azureMaxTier) {
                "Tier-0" { $agt014Tier0 += 1 }
                "Tier-1" { $agt014Tier1 += 1 }
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $agt014Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Azure Roles" = $user.AzureRoles
                "Azure Max Tier" = $user.AzureMaxTier
                "Warnings" = $user.Warnings
                "_SortRisk" = $user.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-014" -Props @{
            Description = "<p>$($internalAgentUsersWithPrivilegedAzureRoles.Count) enabled internal agent users have privileged Azure roles assigned.</p><p>Agent users by highest role tier:</p><ul><li>Tier 0: $agt014Tier0</li><li>Tier 1: $agt014Tier1</li></ul><p><strong>Note:</strong> The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission. The effective impact depends on the resources to which the role is scoped.</p>"
            AffectedObjects = $agt014Affected
        }
        if ($agt014Tier0 -gt 0) {
            Set-FindingOverride -FindingId "AGT-014" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain access to the corresponding blueprint's credentials, or if they are able to add their own credentials, they may gain control of the agent user and abuse its Azure role assignments.</p><p>Since at least one internal agent user has a Tier-0 Azure role assigned, attackers may be able to compromise critical Azure resources.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-014] No enabled internal agent users with privileged Azure roles found."
        Set-FindingOverride -FindingId "AGT-014" -Props $AGT014VariantProps.Secure
    }

    # AGT-015: Apply result for enabled agent users owning CAP-related groups.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-015] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-015" -Props $AGT015VariantProps.Skipped
    } elseif ($agentUsersOwningCapRelatedGroups.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-015] Found $($agentUsersOwningCapRelatedGroups.Count) enabled agent users owning CAP-related groups."
        Set-FindingOverride -FindingId "AGT-015" -Props $AGT015VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-015" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&Enabled=%3Dtrue&GrpOwn=%3E0&Warnings=CAPs%3A&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CGrpOwn%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortRisk"
            AffectedSortDir = "DESC"
        }
        $agt015Foreign = 0
        $agt015Internal = 0
        $agt015OwnedGroups = 0
        $agt015CapReferences = 0
        $agt015Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $agentUsersOwningCapRelatedGroups) {
            $user = $entry.User
            $ownedCapGroups = @($entry.OwnedCapRelatedGroups)
            $agt015OwnedGroups += $ownedCapGroups.Count
            $agt015CapReferences += (Get-IntSafe $entry.OwnedCapReferences)
            if ($user.ForeignAgent -eq $true -or "$($user.ForeignAgent)".Trim().ToLowerInvariant() -eq "true") {
                $agt015Foreign += 1
            } else {
                $agt015Internal += 1
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $ownedGroupDisplay = foreach ($group in $ownedCapGroups) {
                $groupDisplayName = $group.Id
                if ($AllGroupsDetails -and $AllGroupsDetails.ContainsKey($group.Id) -and $AllGroupsDetails[$group.Id]) {
                    $matchingGroup = $AllGroupsDetails[$group.Id]
                    if (-not [string]::IsNullOrWhiteSpace("$($matchingGroup.DisplayName)")) {
                        $groupDisplayName = $matchingGroup.DisplayName
                    }
                }
                "<a href=`"Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($group.Id)`" target=`"_blank`">$groupDisplayName</a> (CAPs: $(Get-IntSafe $group.CAPs))"
            }

            $agt015Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Foreign Agent" = if ($user.ForeignAgent -eq $true -or "$($user.ForeignAgent)".Trim().ToLowerInvariant() -eq "true") { "true" } else { "false" }
                "CAP Groups Owned" = $ownedCapGroups.Count
                "Owned CAP-Related Groups" = ($ownedGroupDisplay -join "<br>")
                "_SortRisk" = $user.Risk
            })
        }
        Set-FindingOverride -FindingId "AGT-015" -Props @{
            Description = "<p>$($agentUsersOwningCapRelatedGroups.Count) enabled agent users own $agt015OwnedGroups groups that are referenced by Conditional Access policies.</p><p>Affected agent users by parent type:</p><ul><li>Foreign agent users: $agt015Foreign</li><li>Internal agent users: $agt015Internal</li></ul><p>Total Conditional Access references across owned groups: $agt015CapReferences</p>"
            AffectedObjects = $agt015Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-015] No enabled agent users owning CAP-related groups found."
        Set-FindingOverride -FindingId "AGT-015" -Props $AGT015VariantProps.Secure
    }

    # AGT-016: Apply result for enabled inactive agent users.
    if ($agentUserCount -eq 0) {
        Write-Log -Level Verbose -Message "[AGT-016] Skipped because no agent users were found."
        Set-FindingOverride -FindingId "AGT-016" -Props $AGT016VariantProps.Skipped
    } elseif ($inactiveEnabledAgentUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[AGT-016] Found $($inactiveEnabledAgentUsers.Count) enabled inactive agent users."
        Set-FindingOverride -FindingId "AGT-016" -Props $AGT016VariantProps.Vulnerable
        Set-FindingOverride -FindingId "AGT-016" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Agent=%3Dtrue&Enabled=%3Dtrue&Inactive=%3Dtrue&columns=UPN%2CEnabled%2CAgent%2CForeignAgent%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=LastSignInDays&sortDir=desc"
            AffectedSortKey = "_SortLastSignInDays"
            AffectedSortDir = "DESC"
        }
        $agt016Foreign = 0
        $agt016Internal = 0
        $agt016Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $inactiveEnabledAgentUsers) {
            $user = $entry.User
            if ($user.ForeignAgent -eq $true -or "$($user.ForeignAgent)".Trim().ToLowerInvariant() -eq "true") {
                $agt016Foreign += 1
            } else {
                $agt016Internal += 1
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }

            $parentBlueprintPrincipal = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentBlueprintPrincipalId)")) {
                $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentBlueprintPrincipalName")) { $parentBlueprintPrincipalName = $user.ParentBlueprintPrincipalId }
                $parentBlueprintPrincipal = "<a href=`"AgentIdentityBlueprintsPrincipals_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentBlueprintPrincipalId)`" target=`"_blank`">$parentBlueprintPrincipalName</a>"
            }

            $parentAgentIdentity = "-"
            if (-not [string]::IsNullOrWhiteSpace("$($user.ParentAgentIdentityId)")) {
                $parentAgentIdentityName = $user.ParentAgentIdentityDisplayName
                if ([string]::IsNullOrWhiteSpace("$parentAgentIdentityName")) { $parentAgentIdentityName = $user.ParentAgentIdentityId }
                $parentAgentIdentity = "<a href=`"AgentIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($user.ParentAgentIdentityId)`" target=`"_blank`">$parentAgentIdentityName</a>"
            }

            $sortLastSignInDays = -1
            $lastSignInDaysRaw = "$($user.LastSignInDays)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($lastSignInDaysRaw) -and $lastSignInDaysRaw -ne "-" -and $lastSignInDaysRaw -ne "?") {
                [int]::TryParse($lastSignInDaysRaw, [ref]$sortLastSignInDays) | Out-Null
            }

            $agt016Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Parent Blueprint Principal" = $parentBlueprintPrincipal
                "Parent Agent Identity" = $parentAgentIdentity
                "Foreign Agent" = if ($user.ForeignAgent -eq $true -or "$($user.ForeignAgent)".Trim().ToLowerInvariant() -eq "true") { "true" } else { "false" }
                "Inactive" = $user.Inactive
                "Last sign-in (days)" = $user.LastSignInDays
                "_SortLastSignInDays" = $sortLastSignInDays
            })
        }
        Set-FindingOverride -FindingId "AGT-016" -Props @{
            Description = "<p>There are $($inactiveEnabledAgentUsers.Count) inactive enabled agent users.</p><ul><li>Foreign agent users: $agt016Foreign</li><li>Internal agent users: $agt016Internal</li></ul><p><strong>Note:</strong> Users are considered inactive if they have no successful sign-in for 180 days or if they never signed in and were created more than 180 days ago.</p>"
            AffectedObjects = $agt016Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[AGT-016] No enabled inactive agent users found."
        Set-FindingOverride -FindingId "AGT-016" -Props $AGT016VariantProps.Secure
    }

    #endregion

    #region MAI Evaluation
    # MAI-001: Managed identities with extensive API privileges.
    if ($managedIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[MAI-001] Skipped because no managed identities were found."
        Set-FindingOverride -FindingId "MAI-001" -Props $maiSkippedProps
    } elseif ($managedIdentitiesWithApi.Count -gt 0) {
        Write-Log -Level Verbose -Message "[MAI-001] Found $($managedIdentitiesWithApi.Count) managed identities with API privileges."
        Set-FindingOverride -FindingId "MAI-001" -Props $MAI001VariantProps.Vulnerable
        Set-FindingOverride -FindingId "MAI-001" -Props @{
            RelatedReportUrl = "ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?or_ApiDangerous=%3E0&or_ApiHigh=%3E0&or_ApiMedium=%3E0&columns=DisplayName%2CIsExplicit%2CGroupMembership%2CGroupOwnership%2CAppOwnership%2CSpOwn%2CEntraRoles%2CAzureRoles%2CApiDangerous%2CApiHigh%2CApiMedium%2CApiLow%2CApiMisc%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $maiAffected = [System.Collections.Generic.List[object]]::new()
        $maiDangerousCount = 0
        $maiHighCount = 0
        $maiMediumCount = 0
        foreach ($app in $managedIdentitiesWithApi) {
            # Count identities by privilege level for summary text.
            $apiDangerousValue = 0
            $apiHighValue = 0
            $apiMediumValue = 0
            if ($null -ne $app.ApiDangerous) { [int]::TryParse("$($app.ApiDangerous)", [ref]$apiDangerousValue) | Out-Null }
            if ($null -ne $app.ApiHigh) { [int]::TryParse("$($app.ApiHigh)", [ref]$apiHighValue) | Out-Null }
            if ($null -ne $app.ApiMedium) { [int]::TryParse("$($app.ApiMedium)", [ref]$apiMediumValue) | Out-Null }
            if ($apiDangerousValue -gt 0) { $maiDangerousCount += 1 }
            if ($apiHighValue -gt 0) { $maiHighCount += 1 }
            if ($apiMediumValue -gt 0) { $maiMediumCount += 1 }

            $permissions = @()
            $rawPerms = @()
            if ($app.AppApiPermission) {
                if ($app.AppApiPermission -is [System.Collections.IEnumerable] -and -not ($app.AppApiPermission -is [string])) {
                    $rawPerms = @($app.AppApiPermission)
                } else {
                    $rawPerms = @($app.AppApiPermission)
                }
            }
            # Build a severity-ordered list of API permissions for display.
            foreach ($level in @("Dangerous", "High", "Medium")) {
                foreach ($perm in $rawPerms) {
                    if ($perm.ApiPermissionCategorization -eq $level) {
                        $permName = $perm.ApiPermission
                        $apiName = $perm.ApiName
                        if (-not $apiName) { $apiName = $perm.ResourceDisplayName }
                        if (-not $apiName) { $apiName = "API" }
                        if ($permName) {
                            $permissions += "${level}: $permName on API $apiName"
                        }
                    }
                }
            }
            $permissionDisplay = if ($permissions.Count -gt 0) { ($permissions | Sort-Object -Unique) -join "<br>" } else { "" }

            $maiAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Dangerous" = $app.ApiDangerous
                "High" = $app.ApiHigh
                "Medium" = $app.ApiMedium
                "API Permissions (>= Medium)" = $permissionDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "MAI-001" -Props @{
            Description = "<p>$($managedIdentitiesWithApi.Count) managed identities have extensive API privileges assigned.</p><p>Managed identities with the following privilege levels:</p><ul><li>Dangerous privileges: $maiDangerousCount</li><li>High privileges: $maiHighCount</li><li>Medium privileges: $maiMediumCount</li></ul>"
            AffectedObjects = $maiAffected
        }
        if ($maiDangerousCount -gt 0) {
            # Escalate severity and threat text when dangerous permissions exist.
            Set-FindingOverride -FindingId "MAI-001" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain control over a resource that is allowed to use the managed identity (for example, a VM, Logic App, or Automation Account), they can obtain an access token for the identity. Using this token, they can authenticate as the managed identity and abuse its API privileges.</p><p>Since at least one application has highly dangerous privileges assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        } elseif ($maiHighCount -eq 0 -and $maiMediumCount -gt 0) {
            # Lower severity when only medium privileges are present.
            Set-FindingOverride -FindingId "MAI-001" -Props @{ Severity = 1 }
        }
    } else {
        Write-Log -Level Verbose -Message "[MAI-001] No managed identities with extensive API privileges found."
        Set-FindingOverride -FindingId "MAI-001" -Props $MAI001VariantProps.Secure
    }

    # MAI-002: Managed identities with privileged Entra ID roles.
    if ($managedIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[MAI-002] Skipped because no managed identities were found."
        Set-FindingOverride -FindingId "MAI-002" -Props $maiSkippedProps
    } elseif ($managedIdentitiesWithPrivRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[MAI-002] Found $($managedIdentitiesWithPrivRoles.Count) managed identities with privileged Entra ID roles."
        Set-FindingOverride -FindingId "MAI-002" -Props $MAI002VariantProps.Vulnerable
        Set-FindingOverride -FindingId "MAI-002" -Props @{
            RelatedReportUrl = "ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?EntraMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CIsExplicit%2CGroupMembership%2CGroupOwnership%2CAppOwnership%2CSpOwn%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $maiRoleAffected = [System.Collections.Generic.List[object]]::new()
        $maiTier0Count = 0
        $maiTier1Count = 0
        foreach ($app in $managedIdentitiesWithPrivRoles) {
            # Count identities by tier for summary text.
            $maxTier = "$($app.EntraMaxTier)"
            if ($maxTier -eq "Tier-0") { $maiTier0Count += 1 }
            elseif ($maxTier -eq "Tier-1") { $maiTier1Count += 1 }

            $roleCount = 0
            if ($null -ne $app.EntraRolesEffective) {
                [int]::TryParse("$($app.EntraRolesEffective)", [ref]$roleCount) | Out-Null
            } elseif ($null -ne $app.EntraRoles) {
                [int]::TryParse("$($app.EntraRoles)", [ref]$roleCount) | Out-Null
            }

            $entraRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.EntraRoleDetails)) {
                if ($role) {
                    $entraRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.EntraRoleDetails)) {
                    if ($role) {
                        $entraRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $roles = @()
            # Build a tier-ordered list of Entra roles (tier 0, then tier 1), including group-derived paths.
            foreach ($tier in @("0", "1")) {
                foreach ($entry in $entraRoleEntries) {
                    $role = $entry.Role
                    if ("$($role.RoleTier)" -ne $tier) { continue }

                    # Group membership path is evaluated as active-only; ownership can include eligible paths.
                    if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }

                    $scopeName = $role.ScopeResolved.DisplayName
                    $scopeType = $role.ScopeResolved.Type
                    if (-not $scopeName) { $scopeName = $role.ScopeResolved }
                    if (-not $scopeName) { $scopeName = "scope" }
                    $scopeText = if ($scopeType) { "$scopeName ($scopeType)" } else { "$scopeName" }
                    $roleName = if ($role.DisplayName) { $role.DisplayName } else { $role.Id }
                    if (-not $roleName) { continue }

                    switch ($entry.Source) {
                        "Direct" {
                            $roles += "Tier $tier : $roleName scope to $scopeText"
                        }
                        "GroupMember" {
                            $roles += "Tier $tier : $roleName through group membership '$($entry.GroupDisplayName)' scope to $scopeText"
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roles += "Tier $tier : $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scope to $scopeText"
                        }
                    }
                }
            }
            $roleDisplay = if ($roles.Count -gt 0) { ($roles | Sort-Object -Unique) -join "<br>" } else { "" }

            $maiRoleAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Role Count" = $roleCount
                "Roles" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "MAI-002" -Props @{
            Description = "<p>$($managedIdentitiesWithPrivRoles.Count) managed identities which have privileged Entra ID roles assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $maiTier0Count</li><li>Tier 1: $maiTier1Count</li></ul>"
            AffectedObjects = $maiRoleAffected
        }
        if ($maiTier0Count -gt 0) {
            # Escalate severity and threat text when tier-0 roles exist.
            Set-FindingOverride -FindingId "MAI-002" -Props @{
                Severity = 3
                Threat = "<p>If attackers gain control over a resource that is allowed to use the managed identity (for example, a VM, Logic App, or Automation Account), they can obtain an access token for the identity. Using this token, they can authenticate as the managed identity and abuse its privileges.</p><p>Since at least one managed identity has a tier-0 role assigned, attackers may be able to compromise the entire tenant.</p>"
            }
        }
    } else {
        Write-Log -Level Verbose -Message "[MAI-002] No managed identities with privileged Entra ID roles found."
        Set-FindingOverride -FindingId "MAI-002" -Props $MAI002VariantProps.Secure
    }

    # MAI-003: Managed identities with privileged Azure roles.
    if ($managedIdentityCount -eq 0) {
        Write-Log -Level Verbose -Message "[MAI-003] Skipped because no managed identities were found."
        Set-FindingOverride -FindingId "MAI-003" -Props $maiSkippedProps
    } elseif ($managedIdentitiesWithAzurePrivRoles.Count -gt 0) {
        Write-Log -Level Verbose -Message "[MAI-003] Found $($managedIdentitiesWithAzurePrivRoles.Count) managed identities with privileged Azure roles."
        Set-FindingOverride -FindingId "MAI-003" -Props $MAI003VariantProps.Vulnerable
        Set-FindingOverride -FindingId "MAI-003" -Props @{
            RelatedReportUrl = "ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AzureMaxTier=Tier-0%7C%7CTier-1&columns=DisplayName%2CIsExplicit%2CGroupMembership%2CGroupOwnership%2CAppOwnership%2CSpOwn%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
        }
        $maiAzureAffected = [System.Collections.Generic.List[object]]::new()
        $maiAzureTier0Count = 0
        $maiAzureTier1Count = 0
        foreach ($app in $managedIdentitiesWithAzurePrivRoles) {
            # Count identities by tier for summary text.
            $maxTier = "$($app.AzureMaxTier)"
            if ($maxTier -eq "Tier-0") { $maiAzureTier0Count += 1 }
            elseif ($maxTier -eq "Tier-1") { $maiAzureTier1Count += 1 }

            $roleCount = 0
            if ($null -ne $app.AzureRolesEffective) {
                [int]::TryParse("$($app.AzureRolesEffective)", [ref]$roleCount) | Out-Null
            } elseif ($null -ne $app.AzureRoles) {
                [int]::TryParse("$($app.AzureRoles)", [ref]$roleCount) | Out-Null
            }

            $azureRoleEntries = [System.Collections.Generic.List[object]]::new()
            foreach ($role in @($app.AzureRoleDetails)) {
                if ($role) {
                    $azureRoleEntries.Add([pscustomobject]@{
                        Source = "Direct"
                        GroupDisplayName = $null
                        Role = $role
                    })
                }
            }
            foreach ($group in @($app.GroupMember)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupMember"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }
            foreach ($group in @($app.GroupOwner)) {
                if (-not $group) { continue }
                $groupDisplayName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                foreach ($role in @($group.AzureRoleDetails)) {
                    if ($role) {
                        $azureRoleEntries.Add([pscustomobject]@{
                            Source = "GroupOwner"
                            GroupDisplayName = $groupDisplayName
                            Role = $role
                        })
                    }
                }
            }

            $roles = @()
            # Build a tier-ordered list of Azure roles (tier 0, then tier 1), including group-derived paths.
            foreach ($tier in @("0", "1")) {
                foreach ($entry in $azureRoleEntries) {
                    $role = $entry.Role
                    if ("$($role.RoleTier)" -ne $tier) { continue }

                    # Group membership path is evaluated as active-only; ownership can include eligible paths.
                    if ($entry.Source -eq "GroupMember" -and "$($role.AssignmentType)" -ne "Active") { continue }

                    $scopeText = if ($role.Scope) { $role.Scope } elseif ($role.ScopeResolved.DisplayName) { $role.ScopeResolved.DisplayName } else { "scope" }
                    $roleName = if ($role.RoleName) { $role.RoleName } elseif ($role.DisplayName) { $role.DisplayName } else { $role.RoleDefinitionId }
                    if (-not $roleName) { continue }

                    switch ($entry.Source) {
                        "Direct" {
                            $roles += "Tier $tier : $roleName scope to $scopeText"
                        }
                        "GroupMember" {
                            $roles += "Tier $tier : $roleName through group membership '$($entry.GroupDisplayName)' scope to $scopeText"
                        }
                        "GroupOwner" {
                            $assignmentType = if ($role.AssignmentType) { $role.AssignmentType } else { "Unknown" }
                            $roles += "Tier $tier : $roleName through group ownership '$($entry.GroupDisplayName)' ($assignmentType) scope to $scopeText"
                        }
                    }
                }
            }
            $roleDisplay = if ($roles.Count -gt 0) { ($roles | Sort-Object -Unique) -join "<br>" } else { "" }

            $maiAzureAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"ManagedIdentities_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($app.Id)`" target=`"_blank`">$($app.DisplayName)</a>"
                "Role Count" = $roleCount
                "Roles (>= Tier 1)" = $roleDisplay
                "_SortImpact" = $app.Impact
            })
        }
        Set-FindingOverride -FindingId "MAI-003" -Props @{
            Description = "<p>$($managedIdentitiesWithAzurePrivRoles.Count) managed identities which have privileged Azure roles assigned.</p><p>Identities by role tier:</p><ul><li>Tier 0: $maiAzureTier0Count</li><li>Tier 1: $maiAzureTier1Count</li></ul><p><strong>Important:</strong> This finding requires manual verification. The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Additionally, Azure provides more than 850 built-in roles, and the actual impact highly depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
            AffectedObjects = $maiAzureAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[MAI-003] No managed identities with privileged Azure roles found."
        Set-FindingOverride -FindingId "MAI-003" -Props $MAI003VariantProps.Secure
    }

    #endregion

    #region PIM Evaluation
    # PIM-001: Basic adoption check for PIM in Entra role assignments.
    # If PIM licensing is missing or no eligible assignments exist, mark as vulnerable and
    # set a flag to skip follow-up PIM configuration checks.
    $skipAdditionalPimChecks = $false
    $EligiblePimGroupMembersByGroupId = @{}
    $EligiblePimGroupOwnersByGroupId = @{}
    $EligiblePimPrincipalMembershipParentsByPrincipalId = @{}
    $EligiblePimPrincipalOwnershipParentsByPrincipalId = @{}
    if ($TenantPimForGroupsAssignments) {
        foreach ($assignment in @($TenantPimForGroupsAssignments)) {
            if (-not $assignment) { continue }
            $groupId = "$($assignment.groupId)".Trim()
            $principalId = "$($assignment.principalId)".Trim()
            $accessId = "$($assignment.accessId)".Trim().ToLowerInvariant()
            $principalType = "$($assignment.Type)".Trim()
            if ([string]::IsNullOrWhiteSpace($groupId) -or [string]::IsNullOrWhiteSpace($principalId)) { continue }
            if ($accessId -ne "member" -and $accessId -ne "owner") { continue }

            $entry = [pscustomobject]@{
                GroupId = $groupId
                PrincipalId = $principalId
                Type = $principalType
                AccessId = $accessId
            }
            if ($accessId -eq "member") {
                if (-not $EligiblePimGroupMembersByGroupId.ContainsKey($groupId)) {
                    $EligiblePimGroupMembersByGroupId[$groupId] = [System.Collections.Generic.List[object]]::new()
                }
                $EligiblePimGroupMembersByGroupId[$groupId].Add($entry)
                if (-not $EligiblePimPrincipalMembershipParentsByPrincipalId.ContainsKey($principalId)) {
                    $EligiblePimPrincipalMembershipParentsByPrincipalId[$principalId] = [System.Collections.Generic.List[object]]::new()
                }
                $EligiblePimPrincipalMembershipParentsByPrincipalId[$principalId].Add($entry)
            } else {
                if (-not $EligiblePimGroupOwnersByGroupId.ContainsKey($groupId)) {
                    $EligiblePimGroupOwnersByGroupId[$groupId] = [System.Collections.Generic.List[object]]::new()
                }
                $EligiblePimGroupOwnersByGroupId[$groupId].Add($entry)
                if (-not $EligiblePimPrincipalOwnershipParentsByPrincipalId.ContainsKey($principalId)) {
                    $EligiblePimPrincipalOwnershipParentsByPrincipalId[$principalId] = [System.Collections.Generic.List[object]]::new()
                }
                $EligiblePimPrincipalOwnershipParentsByPrincipalId[$principalId].Add($entry)
            }
        }
    }
    $pimLicensedForEntraRoles = ($global:GLOBALPIMForEntraRolesChecked -eq $true)
    if (-not $pimLicensedForEntraRoles) {
        Write-Log -Level Verbose -Message "[PIM-001] PIM license check failed. Marking finding as vulnerable."
        Set-FindingOverride -FindingId "PIM-001" -Props @{
            Status = "Vulnerable"
            Description = "<p>Privileged Identity Management (PIM) is not in use because the required licenses are not assigned in the tenant.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
        $skipAdditionalPimChecks = $true
    } elseif ($pimRolesWithEligibleAssignments.Count -eq 0) {
        Write-Log -Level Verbose -Message "[PIM-001] No eligible PIM assignments found. Marking finding as vulnerable."
        Set-FindingOverride -FindingId "PIM-001" -Props @{
            Status = "Vulnerable"
            Description = "<p>Privileged Identity Management (PIM) for Entra ID roles is not actively used, as no eligible role assignments are configured.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
        $skipAdditionalPimChecks = $true
    } else {
        Write-Log -Level Verbose -Message "[PIM-001] Found $($pimRolesWithEligibleAssignments.Count) PIM role settings with eligible assignments."
        $pimEligibleAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimRolesWithEligibleAssignments) {
            $tierSortRank = switch ("$($object.Tier)") {
                "Tier-0" { 0 }
                "Tier-1" { 1 }
                "Tier-2" { 2 }
                default { 9 }
            }
            $pimEligibleAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Users" = $object.Eligible
                "_SortTier" = $tierSortRank
            })
        }

        Set-FindingOverride -FindingId "PIM-001" -Props @{
            Status = "NotVulnerable"
            Description = "<p>Privileged Identity Management (PIM) for Entra ID roles is in use. There are $($pimRolesWithEligibleAssignments.Count) roles with eligible assignments.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Eligible=%3E0&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CWarnings"
            AffectedSortKey = "_SortTier"
            AffectedSortDir = "ASC"
            AffectedObjects = $pimEligibleAffected
        }
    }

    # PIM-002: Validate that Tier-0 roles do not have active user/group assignments outside PIM activation.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-002] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-002" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } else {
        $pim002CandidateAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($assignmentSet in $TenantRoleAssignments.Values) {
            foreach ($assignment in @($assignmentSet)) {
                if ($null -eq $assignment) { continue }
                if ("$($assignment.AssignmentType)" -ne "Active") { continue }
                if ($assignment.ActivatedViaPIM -eq $true) { continue }
                if ((Get-NormalizedRoleTierLabel $assignment.RoleTier) -ne "0") { continue }

                $principalId = "$($assignment.PrincipalId)"
                if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

                $principalType = $null
                $principalDisplayName = $null
                $principalLink = $null

                if ($Users.ContainsKey($principalId)) {
                    $principalType = "User"
                    $principalDisplayName = $Users[$principalId].UPN
                    $principalLink = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId"
                } elseif ($AllGroupsDetails.ContainsKey($principalId)) {
                    $principalType = "Group"
                    $principalDisplayName = $AllGroupsDetails[$principalId].DisplayName
                    $principalLink = "Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$principalId"
                } else {
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($principalDisplayName)) {
                    $principalDisplayName = $principalId
                }

                $scopeDisplayName = if ($assignment.ScopeResolved.DisplayName) { $assignment.ScopeResolved.DisplayName } elseif ($assignment.DirectoryScopeId) { $assignment.DirectoryScopeId } else { "/" }
                $scopeType = if ($assignment.ScopeResolved.Type) { $assignment.ScopeResolved.Type } else { "Tenant" }
                $roleDisplayName = if ($assignment.DisplayName) { $assignment.DisplayName } else { $assignment.RoleDefinitionId }
                $roleGroupingKey = "$($assignment.RoleDefinitionId)|$($assignment.DirectoryScopeId)"

                $pim002CandidateAssignments.Add([pscustomobject]@{
                    RoleGroupingKey = $roleGroupingKey
                    RoleDefinitionId = $assignment.RoleDefinitionId
                    Role = $roleDisplayName
                    RoleTier = "Tier-0"
                    DirectoryScopeId = $assignment.DirectoryScopeId
                    Scope = "$scopeDisplayName ($scopeType)"
                    PrincipalId = $principalId
                    PrincipalType = $principalType
                    PrincipalDisplayName = $principalDisplayName
                    PrincipalLink = $principalLink
                    PrincipalDisplayNameLink = "<a href=`"$principalLink`" target=`"_blank`">$principalDisplayName</a>"
                })
            }
        }

        $pim002Violations = [System.Collections.Generic.List[object]]::new()
        foreach ($roleGroup in ($pim002CandidateAssignments | Group-Object -Property RoleGroupingKey)) {
            $entries = @($roleGroup.Group)
            if ($entries.Count -eq 0) { continue }

            $userEntries = @($entries | Where-Object { $_.PrincipalType -eq "User" })
            $groupEntries = @($entries | Where-Object { $_.PrincipalType -eq "Group" })
            if ($TenantPimForGroupsAssignments -and $groupEntries.Count -gt 0) {
                $filteredGroupEntries = [System.Collections.Generic.List[object]]::new()
                foreach ($groupEntry in $groupEntries) {
                    $groupId = "$($groupEntry.PrincipalId)".Trim()
                    $eligibleOnlyAccess = Test-GroupHasEligibleOnlyPimAccessPath -GroupId $groupId
                    if ($eligibleOnlyAccess) {
                        Write-Log -Level Verbose -Message "[PIM-002] Suppressing group '$($groupEntry.PrincipalDisplayName)' because all reachable access paths are only through eligible PIM-for-Groups relationships."
                        continue
                    }
                    $filteredGroupEntries.Add($groupEntry)
                }
                $groupEntries = @($filteredGroupEntries)
                $entries = @($userEntries + $groupEntries)
                if ($entries.Count -eq 0) { continue }
            }

            $sampleEntry = $entries[0]
            $userCount = $userEntries.Count
            $groupCount = $groupEntries.Count

            $isAllowedGlobalAdminException = $false
            if ("$($sampleEntry.Role)" -eq "Global Administrator") {
                if (($userCount -le 2 -and $groupCount -eq 0) -or ($userCount -eq 0 -and $groupCount -eq 1)) {
                    $isAllowedGlobalAdminException = $true
                }
            }

            if ($isAllowedGlobalAdminException) { continue }

            $assignedPrincipals = if ($entries.Count -gt 0) {
                ($entries | ForEach-Object {
                    $typedLabel = "$($_.PrincipalDisplayName) ($($_.PrincipalType))"
                    "<a href=`"$($_.PrincipalLink)`" target=`"_blank`">$typedLabel</a>"
                } | Sort-Object -Unique) -join "<br>"
            } else {
                "-"
            }
            $reportRoleFilter = [System.Uri]::EscapeDataString("$($sampleEntry.Role)")
            $reportScopeFilter = [System.Uri]::EscapeDataString("$($sampleEntry.Scope)")
            $reportUrl = "Role_Assignments_Entra_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Role=$reportRoleFilter&Scope=$reportScopeFilter&AssignmentType=Active&ActivatedViaPIM=false&PrincipalType=User%7C%7CGroup&columns=Role%2CRoleTier%2CAssignmentType%2CActivatedViaPIM%2CStart%2CExpires%2CPrincipal%2CPrincipalType%2CScope"

            $pim002Violations.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"$reportUrl`" target=`"_blank`">$($sampleEntry.Role)</a>"
                "Role Tier" = $sampleEntry.RoleTier
                "Scope" = $sampleEntry.Scope
                "Assignments" = $entries.Count
                "Assigned Principals" = $assignedPrincipals
            })
        }

        if ($pim002Violations.Count -gt 0) {
            Write-Log -Level Verbose -Message "[PIM-002] Found $($pim002Violations.Count) Tier-0 roles with active user/group assignments that are not activated via PIM."
            $pim002RoleReportUrl = "Role_Assignments_Entra_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?RoleTier=Tier-0&AssignmentType=Active&ActivatedViaPIM=false&PrincipalType=User%7C%7CGroup&columns=Role%2CRoleTier%2CAssignmentType%2CActivatedViaPIM%2CStart%2CExpires%2CPrincipal%2CPrincipalType%2CScope"
            Set-FindingOverride -FindingId "PIM-002" -Props @{
                Status = "Vulnerable"
                Description = "<p>There are $($pim002Violations.Count) Tier-0 Entra roles with active user or group assignments that are not activated via PIM.</p><p><strong>Note:</strong> Active group assignments are excluded when access is only possible through eligible PIM-for-Groups assignments.</p>"
                RelatedReportUrl = $pim002RoleReportUrl
                AffectedObjects = $pim002Violations
            }
        } else {
            Write-Log -Level Verbose -Message "[PIM-002] No Tier-0 roles found with disallowed active user/group assignments outside PIM activation."
            $pim002RoleReportUrl = "Role_Assignments_Entra_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?RoleTier=Tier-0&AssignmentType=Active&ActivatedViaPIM=false&PrincipalType=User%7C%7CGroup&columns=Role%2CRoleTier%2CAssignmentType%2CActivatedViaPIM%2CStart%2CExpires%2CPrincipal%2CPrincipalType%2CScope"
            Set-FindingOverride -FindingId "PIM-002" -Props @{
                Status = "NotVulnerable"
                Description = "<p>No Tier-0 Entra roles identified with disallowed active user or group assignments outside PIM activation.</p><p><strong>Allowed exception:</strong> the Global Administrator role may have up to two directly assigned users or one directly assigned group.</p><p><strong>Note:</strong> Active group assignments are excluded when access is only possible through eligible PIM-for-Groups assignments.</p>"
                RelatedReportUrl = $pim002RoleReportUrl
                AffectedObjects = @()
            }
        }
    }

    # PIM-003: Validate Tier-0 role settings for long activation windows (>4 hours).
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-003] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-003" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0LongActivationDuration.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-003] Found $($pimTier0LongActivationDuration.Count) Tier-0 roles with activation duration >4 hours."
        $pimTier0LongActivationAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0LongActivationDuration) {
            $pimTier0LongActivationAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Activation Duration" = "$($object.ActivationDuration) $($object.ActivationDurationUnit)"
            })
        }
        Set-FindingOverride -FindingId "PIM-003" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0LongActivationDuration.Count) Tier-0 roles with eligible assignments and a maximum activation duration greater than 4 hours.</p><p><strong>Note:</strong> Users may choose a shorter activation duration during role activation.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&Eligible=%3E0&ActivationDuration=%3E4&columns=Role%2CTier%2CEligible%2CActivationDuration%2CWarnings"
            AffectedObjects = $pimTier0LongActivationAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-003] No Tier-0 roles found with activation duration >4 hours."
        Set-FindingOverride -FindingId "PIM-003" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No tier-0 Entra ID roles identified which allow long activation duration (>4 hours).</p>"
            AffectedObjects = @()
        }
    }

    # PIM-004: Validate Tier-0 activation settings require justification or ticketing.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-004] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-004" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0MissingJustificationOrTicketing.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-004] Found $($pimTier0MissingJustificationOrTicketing.Count) Tier-0 roles that do not require justification or ticketing."
        $pimTier0MissingJustificationAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0MissingJustificationOrTicketing) {
            $pimTier0MissingJustificationAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Require Justification" = $object.ActivationJustification
                "Require Ticket Information" = $object.ActivationTicketing
            })
        }
        Set-FindingOverride -FindingId "PIM-004" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0MissingJustificationOrTicketing.Count) Tier-0 roles with eligible assignments that do not require justification or ticketing information on activation.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&Eligible=%3E0&ActivationJustification=%3Dfalse&ActivationTicketing=%3Dfalse&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CWarnings"
            AffectedObjects = $pimTier0MissingJustificationAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-004] No Tier-0 roles found with eligible assignments missing justification and ticketing."
        Set-FindingOverride -FindingId "PIM-004" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No Tier-0 Entra ID roles with eligible assignments were identified that do not require justification or ticketing information.</p>"
            AffectedObjects = @()
        }
    }

    # PIM-005: Validate Tier-0 roles (excluding Global Administrator) do not allow permanent active assignments.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-005] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-005" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0AllowPermanentActiveAssignments.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-005] Found $($pimTier0AllowPermanentActiveAssignments.Count) Tier-0 roles (excluding Global Administrator) allowing permanent active assignments."
        $pimTier0PermanentActiveAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0AllowPermanentActiveAssignments) {
            $pimTier0PermanentActiveAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Direct Assignments" = $object.Direct
                "Expire Active Assignments" = $object.ActiveExpiration
            })
        }
        Set-FindingOverride -FindingId "PIM-005" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0AllowPermanentActiveAssignments.Count) Tier-0 roles, excluding Global Administrator, that allow permanent active assignments.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&ActiveExpiration=%3Dfalse&Role=%21Global+Administrator&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CWarnings"
            AffectedObjects = $pimTier0PermanentActiveAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-005] No Tier-0 roles (excluding Global Administrator) found that allow permanent active assignments."
        Set-FindingOverride -FindingId "PIM-005" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No Tier-0 Entra ID roles, excluding Global Administrator, were identified that allow permanent active assignments.</p>"
            AffectedObjects = @()
        }
    }

    # PIM-006: Validate Tier-0 roles require justification for active assignments.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-006] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-006" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0WithoutActiveAssignmentJustification.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-006] Found $($pimTier0WithoutActiveAssignmentJustification.Count) Tier-0 roles without active assignment justification requirement."
        $pimTier0WithoutActiveJustificationAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0WithoutActiveAssignmentJustification) {
            $pimTier0WithoutActiveJustificationAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Direct Assignments" = $object.Direct
                "Justification on Active Assignments" = $object.ActiveAssignJustification
            })
        }
        Set-FindingOverride -FindingId "PIM-006" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0WithoutActiveAssignmentJustification.Count) Tier-0 roles that do not require justification on active assignments.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&ActiveAssignJustification=%3Dfalse&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CActiveAssignJustification%2CWarnings"
            AffectedObjects = $pimTier0WithoutActiveJustificationAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-006] No Tier-0 roles found without active assignment justification requirement."
        Set-FindingOverride -FindingId "PIM-006" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No Tier-0 Entra ID roles were identified that do not require justification on active assignments.</p>"
            AffectedObjects = @()
        }
    }

    # PIM-007: Validate Tier-0 roles require MFA for active assignments.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-007] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-007" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0WithoutActiveAssignmentMfa.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-007] Found $($pimTier0WithoutActiveAssignmentMfa.Count) Tier-0 roles without active assignment MFA requirement."
        $pimTier0WithoutActiveMfaAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0WithoutActiveAssignmentMfa) {
            $pimTier0WithoutActiveMfaAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Direct Assignments" = $object.Direct
                "MFA on Active Assignments" = $object.ActiveAssignMFA
            })
        }
        Set-FindingOverride -FindingId "PIM-007" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0WithoutActiveAssignmentMfa.Count) Tier-0 roles that do not require MFA on active assignments.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&ActiveAssignMFA=false&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CWarnings"
            AffectedObjects = $pimTier0WithoutActiveMfaAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-007] No Tier-0 roles found without active assignment MFA requirement."
        Set-FindingOverride -FindingId "PIM-007" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No Tier-0 Entra ID roles were identified that do not require MFA on active assignments.</p>"
            AffectedObjects = @()
        }
    }

    # PIM-008: Validate Tier-0 roles have all PIM notifications enabled.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-008] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-008" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0WithoutAllNotifications.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-008] Found $($pimTier0WithoutAllNotifications.Count) Tier-0 roles without all notifications enabled."
        $pimTier0WithoutNotificationsAffected = [System.Collections.Generic.List[object]]::new()
        foreach ($object in $pimTier0WithoutAllNotifications) {
            $pimTier0WithoutNotificationsAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Notify on Eligible Assignments" = $object.AlertAssignEligible
                "Notify on Active Assignments" = $object.AlertAssignActive
                "Notify on Role Activation" = $object.AlertActivation
            })
        }
        Set-FindingOverride -FindingId "PIM-008" -Props @{
            Status = "Vulnerable"
            Description = "<p>There are $($pimTier0WithoutAllNotifications.Count) Tier-0 roles that do not have all notifications enabled.</p><p><strong>Important:</strong> This finding requires manual verification. If these events are already monitored by another solution (for example, a SIEM ingesting audit logs), this finding may be considered not applicable.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Tier=%3DTier-0&or_AlertAssignEligible=false&or_AlertAssignActive=false&or_AlertActivation=false&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationJustification%2CActivationTicketing%2CActivationDuration%2CActivationApproval%2CEligibleExpiration%2CActiveExpiration%2CActiveAssignMFA%2CAlertAssignEligible%2CAlertAssignActive%2CAlertActivation%2CWarnings"
            AffectedObjects = $pimTier0WithoutNotificationsAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-008] No Tier-0 roles found with disabled notifications."
        Set-FindingOverride -FindingId "PIM-008" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No Tier-0 Entra ID roles were identified that have disabled notifications.</p>"
            AffectedObjects = @()
        }
    }

    # PIM-009: Validate Tier-0 roles require approval and enforce strong reauthentication via auth context + CAPs.
    # Reuse the pre-filtered role set from the shared PIM enumeration loop.
    if ($skipAdditionalPimChecks) {
        Write-Log -Level Verbose -Message "[PIM-009] Skipping check because PIM is not in use for Entra roles."
        Set-FindingOverride -FindingId "PIM-009" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because Privileged Identity Management (PIM) is not in use.</p>"
            AffectedObjects = @()
            RelatedReportUrl = ""
        }
    } elseif ($pimTier0WithoutApprovalAndStrongReauth.Count -gt 0) {
        Write-Log -Level Verbose -Message "[PIM-009] Found $($pimTier0WithoutApprovalAndStrongReauth.Count) Tier-0 roles without approval and strong reauthentication."
        $pimTier0WeakActivationControlsAffected = [System.Collections.Generic.List[object]]::new()
        $pim009HasCapIssues = $false
        foreach ($object in $pimTier0WithoutApprovalAndStrongReauth) {
            $linkedCapLinks = [System.Collections.Generic.List[string]]::new()
            $linkedCapIssues = [System.Collections.Generic.List[string]]::new()

            if ($null -ne $object.LinkedCapsDetails) {
                $linkedCapDetails = @()
                if ($object.LinkedCapsDetails -is [System.Collections.IEnumerable] -and -not ($object.LinkedCapsDetails -is [string])) {
                    $linkedCapDetails = @($object.LinkedCapsDetails)
                } else {
                    $linkedCapDetails = @($object.LinkedCapsDetails)
                }

                foreach ($capDetail in $linkedCapDetails) {
                    if (-not $capDetail) { continue }
                    $capName = "$($capDetail.DisplayName)"
                    if ([string]::IsNullOrWhiteSpace($capName)) { $capName = "$($capDetail.Id)" }
                    if (-not [string]::IsNullOrWhiteSpace("$($capDetail.Id)")) {
                        $linkedCapLinks.Add("<a href=`"ConditionalAccessPolicies_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($capDetail.Id)`" target=`"_blank`">$capName</a>")
                    } elseif (-not [string]::IsNullOrWhiteSpace($capName)) {
                        $linkedCapLinks.Add($capName)
                    }

                    $issueItems = @()
                    if ($null -ne $capDetail.Issues) {
                        if ($capDetail.Issues -is [System.Collections.IEnumerable] -and -not ($capDetail.Issues -is [string])) {
                            $issueItems = @($capDetail.Issues)
                        } else {
                            $issueItems = @($capDetail.Issues)
                        }
                    }
                    foreach ($issue in $issueItems) {
                        $issueText = "$issue".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($issueText) -and $issueText -ne "-") {
                            $linkedCapIssues.Add($issueText)
                            $pim009HasCapIssues = $true
                        }
                    }
                }
            }

            $linkedCapDisplay = if ($linkedCapLinks.Count -gt 0) { $linkedCapLinks -join "<br>" } else { "" }
            $issuesDisplay = if ($linkedCapIssues.Count -gt 0) { $linkedCapIssues -join "<br>" } else { "" }

            $pimTier0WeakActivationControlsAffected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)`" target=`"_blank`">$($object.Role)</a>"
                "Role Tier" = $object.Tier
                "Eligible Assignments" = $object.Eligible
                "Require Approval" = $object.ActivationApproval
                "Uses Auth Context" = $object.ActivationAuthContext
                "Linked CAP" = $linkedCapDisplay
                "Issues in CAP" = $issuesDisplay
            })
        }

        $pim009Confidence = if ($pim009HasCapIssues) { "Requires Verification" } else { "Sure" }
        Set-FindingOverride -FindingId "PIM-009" -Props @{
            Status = "Vulnerable"
            Confidence = $pim009Confidence
            Description = "<p>There are $($pimTier0WithoutApprovalAndStrongReauth.Count) Tier-0 roles with eligible assignments that do not require approval, do not enforce re-authentication with MFA using an Authentication Context, or have issues or gaps in the linked Conditional Access policies.</p><p>Important: The setting <code>On activation, require: Azure MFA</code> does not require the user to provide MFA again if he authenticated with strong credentials or provided multifactor authentication earlier in the session.</p>"
            RelatedReportUrl = "PIM_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?or_Warnings=CAP&or_ActivationAuthContext=false&Tier=%3DTier-0&ActivationApproval=%3Dfalse&Eligible=%3E0&columns=Role%2CTier%2CEligible%2CDirect%2CActivated%2CActivationAuthContext%2CActivationMFA%2CActivationApproval%2CWarnings"
            AffectedObjects = $pimTier0WeakActivationControlsAffected
        }
    } else {
        Write-Log -Level Verbose -Message "[PIM-009] No used Tier-0 roles found with missing approval/auth-context controls."
        Set-FindingOverride -FindingId "PIM-009" -Props @{
            Status = "NotVulnerable"
            Description = "<p>No used Tier-0 Entra ID roles were identified that require approval, lack an enforced authentication context, or have misconfigured related Conditional Access policies.</p>"
            AffectedObjects = @()
        }
    }

    # Evaluate findings from pre-collected authorization policy data.
    ### CHECKS COL-001 COL-002 COL-003 PAS-001 PAS-002 PAS-003 PAS-004 PAS-005 USR-001 USR-002 USR-003 USR-004 USR-005 USR-006 USR-007 USR-008 USR-009 USR-010 USR-011 USR-012 USR-013 GRP-001 GRP-002 GRP-003 GRP-004 GRP-005
    #endregion

    #region COL Evaluation
    # COL-001: Map guestUserRoleId to access model and risk level.
    $guestUserRoleId = $null
    if ($AuthPolicy) {
        $guestUserRoleId = $AuthPolicy.guestUserRoleId
    }
    if ([string]::IsNullOrWhiteSpace($guestUserRoleId)) {
        Write-Log -Level Debug -Message "[COL-001] Authorization policy guestUserRoleId not found."
    } else {
        Write-Log -Level Verbose -Message "[COL-001] Authorization policy guestUserRoleId: $guestUserRoleId"
    }


    if (-not [string]::IsNullOrWhiteSpace($guestUserRoleId)) {
        switch ($guestUserRoleId) {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" {
                Write-Log -Level Trace -Message "[COL-001] Guest access level: Same as members."
                Set-FindingOverride -FindingId "COL-001" -Props $COL001VariantProps.Member
            }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" {
                Write-Log -Level Trace -Message "[COL-001] Guest access level: Limited (default)."
                Set-FindingOverride -FindingId "COL-001" -Props $COL001VariantProps.Limited
            }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" {
                Write-Log -Level Trace -Message "[COL-001] Guest access level: Restricted (most restrictive)."
                Set-FindingOverride -FindingId "COL-001" -Props $COL001VariantProps.Restricted
            }
            default {
                Write-Log -Level Debug -Message "[COL-001] Guest access level: Unknown guestUserRoleId $guestUserRoleId."
            }
        }
    }

    # COL-002: Evaluate who can invite guest users.
    $allowInvitesFrom = $null
    if ($AuthPolicy) {
        $allowInvitesFrom = $AuthPolicy.allowInvitesFrom
    }
    if ([string]::IsNullOrWhiteSpace($allowInvitesFrom)) {
        Write-Log -Level Debug -Message "[COL-002] Authorization policy allowInvitesFrom not found."
    } else {
        Write-Log -Level Verbose -Message "[COL-002] Authorization policy allowInvitesFrom: $allowInvitesFrom"
        switch ($allowInvitesFrom) {
            "everyone" {
                Write-Log -Level Trace -Message "[COL-002] Guest invite restriction: Everyone."
                Set-FindingOverride -FindingId "COL-002" -Props $COL002VariantProps.Everyone
            }
            "adminsGuestInvitersAndAllMembers" {
                Write-Log -Level Trace -Message "[COL-002] Guest invite restriction: Admins, guest inviters, and all members."
                Set-FindingOverride -FindingId "COL-002" -Props $COL002VariantProps.AdminsGuestInvitersAndAllMembers
            }
            "adminsAndGuestInviters" {
                Write-Log -Level Trace -Message "[COL-002] Guest invite restriction: Admins and guest inviters."
                Set-FindingOverride -FindingId "COL-002" -Props $COL002VariantProps.AdminsAndGuestInviters
            }
            "none" {
                Write-Log -Level Trace -Message "[COL-002] Guest invite restriction: None (most restrictive)."
                Set-FindingOverride -FindingId "COL-002" -Props $COL002VariantProps.None
            }
            default {
                Write-Log -Level Debug -Message "[COL-002] Guest invite restriction: Unknown allowInvitesFrom value $allowInvitesFrom."
            }
        }
    }

    # COL-003: Evaluate whether guests can own Microsoft 365 groups.
    # Read AllowGuestsToBeGroupOwner from tenant directory settings (unified group template).
    $allowGuestsToBeGroupOwner = $null
    if ($TenantDirectorySettingsList.Count -gt 0) {
        $groupSettingsCOL003 = $TenantDirectorySettingsList | Where-Object { $_.templateId -eq $UnifiedGroupSettingsTemplateId } | Select-Object -First 1
        if ($groupSettingsCOL003 -and $groupSettingsCOL003.values) {
            $allowGuestsOwnerEntry = $groupSettingsCOL003.values | Where-Object { $_.name -eq "AllowGuestsToBeGroupOwner" } | Select-Object -First 1
            if ($allowGuestsOwnerEntry) {
                $allowGuestsToBeGroupOwner = $allowGuestsOwnerEntry.value
            }
        }
    }
    if ($null -eq $allowGuestsToBeGroupOwner) {
        Write-Log -Level Debug -Message "[COL-003] Tenant directory settings AllowGuestsToBeGroupOwner not found in the unified group template."
    } else {
        if ($allowGuestsToBeGroupOwner -is [string]) {
            $allowGuestsToBeGroupOwner = $allowGuestsToBeGroupOwner.Trim().ToLowerInvariant() -eq "true"
        } else {
            $allowGuestsToBeGroupOwner = [bool]$allowGuestsToBeGroupOwner
        }
        Write-Log -Level Verbose -Message "[COL-003] Tenant directory settings AllowGuestsToBeGroupOwner: $allowGuestsToBeGroupOwner"
        if ($allowGuestsToBeGroupOwner) {
            Write-Log -Level Trace -Message "[COL-003] Guest users are allowed to own M365 groups."
            Set-FindingOverride -FindingId "COL-003" -Props $COL003VariantProps.Vulnerable
        } else {
            Write-Log -Level Trace -Message "[COL-003] Guest users cannot own M365 groups."
            Set-FindingOverride -FindingId "COL-003" -Props $COL003VariantProps.Secure
        }
    }

    #endregion

    #region PAS Evaluation
    # PAS-001 / PAS-002: Evaluate password protection settings once.
    # Read EnableBannedPasswordCheck and BannedPasswordList from the password protection template.
    $passwordProtectionSettings = $null
    $enableBannedPasswordCheck = $null
    $bannedPasswordListValue = $null
    if ($TenantDirectorySettingsList.Count -gt 0) {
        $passwordProtectionSettings = $TenantDirectorySettingsList | Where-Object { $_.templateId -eq $PasswordProtectionSettingsTemplateId } | Select-Object -First 1
        if ($passwordProtectionSettings -and $passwordProtectionSettings.values) {
            $enableBannedPasswordCheckEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "EnableBannedPasswordCheck" } | Select-Object -First 1
            if ($enableBannedPasswordCheckEntry) {
                $enableBannedPasswordCheck = $enableBannedPasswordCheckEntry.value
            }
            $bannedPasswordListEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "BannedPasswordList" } | Select-Object -First 1
            if ($bannedPasswordListEntry) {
                $bannedPasswordListValue = $bannedPasswordListEntry.value
            }
        }
    }

    $isBannedPasswordCheckEnabled = $false
    if ($null -eq $enableBannedPasswordCheck) {
        Write-Log -Level Verbose -Message "[PAS-001] Password protection setting EnableBannedPasswordCheck not found."
        Set-FindingOverride -FindingId "PAS-001" -Props $PAS001VariantProps.Vulnerable
    } else {
        if ($enableBannedPasswordCheck -is [string]) {
            $isBannedPasswordCheckEnabled = $enableBannedPasswordCheck.Trim().ToLowerInvariant() -eq "true"
        } else {
            $isBannedPasswordCheckEnabled = [bool]$enableBannedPasswordCheck
        }
        Write-Log -Level Verbose -Message "[PAS-001] Password protection setting EnableBannedPasswordCheck: $isBannedPasswordCheckEnabled"
        if ($isBannedPasswordCheckEnabled) {
            Set-FindingOverride -FindingId "PAS-001" -Props $PAS001VariantProps.Secure
        } else {
            Set-FindingOverride -FindingId "PAS-001" -Props $PAS001VariantProps.Vulnerable
        }
    }

    # PAS-002: Assess if the custom banned password list has enough entries.
    # Skip this check when custom banned password check is not enabled (covered by PAS-001).
    if (-not $isBannedPasswordCheckEnabled) {
        Write-Log -Level Verbose -Message "[PAS-002] Skipping check because custom banned password list is not enabled."
        Set-FindingOverride -FindingId "PAS-002" -Props $PAS002VariantProps.Skipped
        Set-FindingOverride -FindingId "PAS-002" -Props @{
            AffectedObjects = @()
        }
    } else {
        $bannedPasswordEntries = [System.Collections.Generic.List[string]]::new()
        $rawBannedPasswordValues = @()
        if ($null -ne $bannedPasswordListValue) {
            if ($bannedPasswordListValue -is [System.Collections.IEnumerable] -and -not ($bannedPasswordListValue -is [string])) {
                $rawBannedPasswordValues = @($bannedPasswordListValue)
            } else {
                $rawBannedPasswordValues = @($bannedPasswordListValue)
            }
        }
        foreach ($rawValue in $rawBannedPasswordValues) {
            $normalizedValue = "$rawValue"
            if ([string]::IsNullOrWhiteSpace($normalizedValue)) { continue }
            # BannedPasswordList is typically whitespace/newline separated; also handle commas and semicolons.
            $normalizedValue = $normalizedValue -replace "[\r\n\t,;]+", " "
            foreach ($part in ($normalizedValue -split "\s+")) {
                $token = "$part".Trim()
                if (-not [string]::IsNullOrWhiteSpace($token)) {
                    $bannedPasswordEntries.Add($token)
                }
            }
        }

        # Build a clean per-entry list for the affected objects table.
        $uniqueBannedPasswordEntries = @($bannedPasswordEntries | Sort-Object -Unique)
        $pas002Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entryValue in $uniqueBannedPasswordEntries) {
            $pas002Affected.Add([pscustomobject][ordered]@{
                "Banned Password Entry" = $entryValue
            })
        }

        $bannedPasswordEntryCount = $uniqueBannedPasswordEntries.Count
        Write-Log -Level Verbose -Message "[PAS-002] BannedPasswordList entry count: $bannedPasswordEntryCount"
        if ($bannedPasswordEntryCount -lt 10) {
            Set-FindingOverride -FindingId "PAS-002" -Props $PAS002VariantProps.Vulnerable
            Set-FindingOverride -FindingId "PAS-002" -Props @{
                Description = "<p>The custom banned password list contains only $bannedPasswordEntryCount entries.</p>"
                AffectedSortKey = "Banned Password Entry"
                AffectedSortDir = "ASC"
                AffectedObjects = $pas002Affected
            }
            if ($bannedPasswordEntryCount -eq 0) {
                Set-FindingOverride -FindingId "PAS-002" -Props @{ Severity = 2 }
            }
        } else {
            Set-FindingOverride -FindingId "PAS-002" -Props $PAS002VariantProps.Secure
            Set-FindingOverride -FindingId "PAS-002" -Props @{
                Description = "<p>The custom banned password list contains $bannedPasswordEntryCount entries.</p>"
                AffectedSortKey = "Banned Password Entry"
                AffectedSortDir = "ASC"
                AffectedObjects = $pas002Affected
            }
        }
    }

    # PAS-003: Evaluate whether Entra password protection is enforced on-premises.
    # Skip this check when the custom banned password list feature is not enabled (covered by PAS-001).
    if (-not $isBannedPasswordCheckEnabled) {
        Write-Log -Level Verbose -Message "[PAS-003] Skipping check because custom banned password list is not enabled."
        Set-FindingOverride -FindingId "PAS-003" -Props $PAS003VariantProps.Skipped
    } else {
        $enableBannedPasswordCheckOnPremises = $null
        $bannedPasswordCheckOnPremisesMode = $null
        if ($passwordProtectionSettings -and $passwordProtectionSettings.values) {
            $enableOnPremEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "EnableBannedPasswordCheckOnPremises" } | Select-Object -First 1
            if ($enableOnPremEntry) {
                $enableBannedPasswordCheckOnPremises = $enableOnPremEntry.value
            }
            $modeOnPremEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "BannedPasswordCheckOnPremisesMode" } | Select-Object -First 1
            if ($modeOnPremEntry) {
                $bannedPasswordCheckOnPremisesMode = $modeOnPremEntry.value
            }
        }

        $isOnPremBannedPasswordCheckEnabled = $false
        if ($null -ne $enableBannedPasswordCheckOnPremises) {
            if ($enableBannedPasswordCheckOnPremises -is [string]) {
                $isOnPremBannedPasswordCheckEnabled = $enableBannedPasswordCheckOnPremises.Trim().ToLowerInvariant() -eq "true"
            } else {
                $isOnPremBannedPasswordCheckEnabled = [bool]$enableBannedPasswordCheckOnPremises
            }
        }
        $onPremMode = if ($null -ne $bannedPasswordCheckOnPremisesMode) { "$bannedPasswordCheckOnPremisesMode".Trim() } else { "" }
        $onPremModeNormalized = $onPremMode.ToLowerInvariant()
        $isOnPremModeEnforced = @("enforce", "enforced") -contains $onPremModeNormalized

        Write-Log -Level Verbose -Message "[PAS-003] EnableBannedPasswordCheckOnPremises: $isOnPremBannedPasswordCheckEnabled; BannedPasswordCheckOnPremisesMode: $onPremMode"
        if ($isOnPremBannedPasswordCheckEnabled -and $isOnPremModeEnforced) {
            Set-FindingOverride -FindingId "PAS-003" -Props $PAS003VariantProps.Secure
            Set-FindingOverride -FindingId "PAS-003" -Props @{ AffectedObjects = @() }
        } else {
            $pas003Issues = [System.Collections.Generic.List[string]]::new()
            if (-not $isOnPremBannedPasswordCheckEnabled) {
                $pas003Issues.Add("<li><code>EnableBannedPasswordCheckOnPremises</code> is not enabled.</li>") | Out-Null
            }
            if (-not $isOnPremModeEnforced) {
                $modeDisplay = if ([string]::IsNullOrWhiteSpace($onPremMode)) { "(empty)" } else { $onPremMode }
                $pas003Issues.Add("<li><code>BannedPasswordCheckOnPremisesMode</code> is set to <code>$modeDisplay</code> (expected <code>Enforce</code>).</li>") | Out-Null
            }
            Set-FindingOverride -FindingId "PAS-003" -Props $PAS003VariantProps.Vulnerable
            Set-FindingOverride -FindingId "PAS-003" -Props @{
                Description = "<p>Entra password protection is not enforced for the on-premises environment.</p><p>Detected configuration issue(s):</p><ul>$($pas003Issues -join '')</ul>"
                AffectedObjects = @()
            }
        }
    }

    # PAS-004: Evaluate account lockout settings used for smart lockout.
    # If the password protection template is missing, or Microsoft defaults are used, they are treated as secure.
    $lockoutDurationInSeconds = $null
    $lockoutThreshold = $null
    if ($passwordProtectionSettings -and $passwordProtectionSettings.values) {
        $lockoutDurationEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "LockoutDurationInSeconds" } | Select-Object -First 1
        if ($lockoutDurationEntry) {
            $lockoutDurationInSeconds = $lockoutDurationEntry.value
        }
        $lockoutThresholdEntry = $passwordProtectionSettings.values | Where-Object { $_.name -eq "LockoutThreshold" } | Select-Object -First 1
        if ($lockoutThresholdEntry) {
            $lockoutThreshold = $lockoutThresholdEntry.value
        }
    }

    $parsedLockoutDurationInSeconds = 0
    $parsedLockoutThreshold = 0
    $hasValidLockoutDuration = [int]::TryParse("$lockoutDurationInSeconds", [ref]$parsedLockoutDurationInSeconds)
    $hasValidLockoutThreshold = [int]::TryParse("$lockoutThreshold", [ref]$parsedLockoutThreshold)
    $lockoutDurationRawDisplay = if ([string]::IsNullOrWhiteSpace("$lockoutDurationInSeconds")) { "(empty)" } else { "$lockoutDurationInSeconds" }
    $lockoutThresholdRawDisplay = if ([string]::IsNullOrWhiteSpace("$lockoutThreshold")) { "(empty)" } else { "$lockoutThreshold" }

    $isDefaultLockoutSettings = (
        $hasValidLockoutDuration -and
        $hasValidLockoutThreshold -and
        $parsedLockoutDurationInSeconds -eq 60 -and
        $parsedLockoutThreshold -eq 10
    )

    if ((-not $passwordProtectionSettings) -or $isDefaultLockoutSettings) {
        Write-Log -Level Verbose -Message "[PAS-004] Password protection template missing or defaults in use. Duration: $parsedLockoutDurationInSeconds; Threshold: $parsedLockoutThreshold"
        Set-FindingOverride -FindingId "PAS-004" -Props $PAS004VariantProps.Secure
        Set-FindingOverride -FindingId "PAS-004" -Props @{
            Description = "<p>The secure default settings are used.</p>"
            AffectedObjects = @()
        }
    } elseif ((-not $hasValidLockoutDuration) -or (-not $hasValidLockoutThreshold) -or $parsedLockoutThreshold -le 0 -or $parsedLockoutDurationInSeconds -lt 0) {
        Write-Log -Level Verbose -Message "[PAS-004] Lockout settings are not parseable or invalid. Raw duration: $lockoutDurationInSeconds; raw threshold: $lockoutThreshold"
        Set-FindingOverride -FindingId "PAS-004" -Props $PAS004VariantProps.Vulnerable
        Set-FindingOverride -FindingId "PAS-004" -Props @{
            Description = "<p>The configured combination of <code>Lockout threshold</code> and <code>Lockout duration in seconds</code> could not be validated and was assessed as potentially weak.</p><p>Current settings: <code>LockoutThreshold=$lockoutThresholdRawDisplay</code>, <code>LockoutDurationInSeconds=$lockoutDurationRawDisplay</code>.</p>"
            AffectedObjects = @()
        }
    } else {
        # Estimate max guesses/hour:
        # - each lockout cycle allows <threshold> attempts;
        # - lockout starts at configured duration;
        # - after each lockout, duration is assumed to increase by 60 seconds.
        # Microsoft does not publish the exact increase curve, so this is an approximation.
        $estimatedAttemptsPerHour = 0
        $elapsedSeconds = 0
        $lockoutCycles = 0
        while ($elapsedSeconds -lt 3600) {
            $estimatedAttemptsPerHour += $parsedLockoutThreshold
            $lockoutCycles++
            $currentLockoutDuration = $parsedLockoutDurationInSeconds + (($lockoutCycles - 1) * 60)
            if ($currentLockoutDuration -lt 0) {
                $currentLockoutDuration = 0
            }
            $elapsedSeconds += $currentLockoutDuration
        }

        Write-Log -Level Verbose -Message "[PAS-004] Estimated guessing rate: $estimatedAttemptsPerHour attempts/hour (threshold: $parsedLockoutThreshold, duration: $parsedLockoutDurationInSeconds)"
        $rateNote = "<p><strong>Note:</strong> Because the lockout duration automatically increases after repeated attempts and Microsoft does not disclose the exact increase rate, the effective number of attempts per hour cannot be calculated precisely. Assuming the lockout duration increases by one minute per lockout, the estimated password guessing rate is approximately $estimatedAttemptsPerHour attempts per hour (for comparison, default settings with a threshold of 10 and a duration of 60 seconds allow roughly 110 attempts per hour).</p>"

        if ($estimatedAttemptsPerHour -gt 150) {
            Set-FindingOverride -FindingId "PAS-004" -Props $PAS004VariantProps.Vulnerable
            Set-FindingOverride -FindingId "PAS-004" -Props @{
                Description = "<p>The configured combination of <code>Lockout threshold</code> and <code>Lockout duration in seconds</code> is relatively permissive.</p><p>Current settings: <code>LockoutThreshold=$parsedLockoutThreshold</code>, <code>LockoutDurationInSeconds=$parsedLockoutDurationInSeconds</code>.</p>$rateNote"
                AffectedObjects = @()
            }
        } else {
            Set-FindingOverride -FindingId "PAS-004" -Props $PAS004VariantProps.Secure
            Set-FindingOverride -FindingId "PAS-004" -Props @{
                Description = "<p>The configured combination of <code>Lockout threshold</code> and <code>Lockout duration in seconds</code> was assessed as reasonable.</p>$rateNote"
                AffectedObjects = @()
            }
        }
    }

    # PAS-005: Evaluate if self-service password reset is enabled for administrators.
    # If enabled, adjust severity/confidence based on CAP-002 status (security info registration protection).
    $allowedToUseSspr = $false
    if ($AuthPolicy -and $null -ne $AuthPolicy.allowedToUseSSPR) {
        if ($AuthPolicy.allowedToUseSSPR -is [string]) {
            $allowedToUseSspr = $AuthPolicy.allowedToUseSSPR.Trim().ToLowerInvariant() -eq "true"
        } else {
            $allowedToUseSspr = [bool]$AuthPolicy.allowedToUseSSPR
        }
    }

    Write-Log -Level Verbose -Message "[PAS-005] Authorization policy allowedToUseSSPR: $allowedToUseSspr"
    if ($allowedToUseSspr) {
        $cap002IsVulnerable = $false
        if ($FindingsById.ContainsKey("CAP-002")) {
            $cap002Status = "$($FindingsById["CAP-002"].Status)".Trim().ToLowerInvariant()
            $cap002IsVulnerable = $cap002Status -eq "vulnerable"
        }

        Set-FindingOverride -FindingId "PAS-005" -Props $PAS005VariantProps.Vulnerable
        if ($cap002IsVulnerable) {
            Set-FindingOverride -FindingId "PAS-005" -Props @{
                Severity = 2
                Confidence = "Sure"
                Description = "<p>Users who are members of one of the 27 administrator roles are, by default, enabled for Self-Service Password Reset (SSPR). They must use two of the following authentication methods to reset their password:</p><ul><li>Email</li><li>SMS</li><li>Mobile phone call</li><li>Office phone call</li><li>Microsoft Authenticator app (code or notification)</li></ul><p><strong>Note:</strong> The email addresses and phone numbers used for SSPR can be configured by the user. This allows administrator accounts to register private email addresses or phone numbers as SSPR methods.</p><p>Additionally, multiple authentication methods can be registered on the same device (for example, email access and SMS on a single mobile phone), which reduces the practical security benefit of requiring two separate factors.</p><p>Furthermore, issues were identified with the Conditional Access policies that define the conditions for registering MFA methods (see <a href=`"#CAP-002`">CAP-002</a>).</p>"
                AffectedObjects = @()
            }
        } else {
            Set-FindingOverride -FindingId "PAS-005" -Props @{
                Severity = 1
                Confidence = "Requires Verification"
                Description = "<p>Users who are members of one of the 27 administrator roles are, by default, enabled for Self-Service Password Reset (SSPR). They must use two of the following authentication methods to reset their password:</p><ul><li>Email</li><li>SMS</li><li>Mobile phone call</li><li>Office phone call</li><li>Microsoft Authenticator app (code or notification)</li></ul><p><strong>Note:</strong> The email addresses and phone numbers used for SSPR can be configured by the user. This allows administrator accounts to register private email addresses or phone numbers as SSPR methods.</p><p>Additionally, multiple authentication methods can be registered on the same device (for example, email access and SMS on a single mobile phone), which reduces the practical security benefit of requiring two separate factors.</p><p><strong>Note:</strong> A Conditional Access policy defines the conditions for registering MFA methods (see <a href=`"#CAP-002`">CAP-002</a>), which likely reduces the risk of abuse.</p>"
                AffectedObjects = @()
            }
        }
    } else {
        Set-FindingOverride -FindingId "PAS-005" -Props $PAS005VariantProps.Secure
        Set-FindingOverride -FindingId "PAS-005" -Props @{
            Description = "<p>Self-service password reset (SSPR) is disabled for administrators.</p>"
            AffectedObjects = @()
        }
    }

    #endregion

    #region USR Evaluation
    # USR-001: Check if regular users can register applications.
    $allowedToCreateApps = $null
    if ($AuthPolicy -and $AuthPolicy.defaultUserRolePermissions) {
        $allowedToCreateApps = $AuthPolicy.defaultUserRolePermissions.allowedToCreateApps
    }
    if ($null -eq $allowedToCreateApps) {
        Write-Log -Level Debug -Message "[USR-001] Authorization policy defaultUserRolePermissions.allowedToCreateApps not found."
    } else {
        Write-Log -Level Verbose -Message "[USR-001] Authorization policy allowedToCreateApps: $allowedToCreateApps"
        if ($allowedToCreateApps) {
            Write-Log -Level Trace -Message "[USR-001] App registration allowed for default users."
            Set-FindingOverride -FindingId "USR-001" -Props $USR001VariantProps.Vulnerable
        } else {
            Write-Log -Level Trace -Message "[USR-001] App registration not allowed for default users."
            Set-FindingOverride -FindingId "USR-001" -Props $USR001VariantProps.Secure
        }
    }

    # USR-002: Check if regular users can create new tenants.
    $allowedToCreateTenants = $null
    if ($AuthPolicy -and $AuthPolicy.defaultUserRolePermissions) {
        $allowedToCreateTenants = $AuthPolicy.defaultUserRolePermissions.allowedToCreateTenants
    }
    if ($null -eq $allowedToCreateTenants) {
        Write-Log -Level Debug -Message "[USR-002] Authorization policy defaultUserRolePermissions.allowedToCreateTenants not found."
    } else {
        Write-Log -Level Verbose -Message "[USR-002] Authorization policy allowedToCreateTenants: $allowedToCreateTenants"
        if ($allowedToCreateTenants) {
            Write-Log -Level Trace -Message "[USR-002] Tenant creation allowed for default users."
            Set-FindingOverride -FindingId "USR-002" -Props $USR002VariantProps.Vulnerable
        } else {
            Write-Log -Level Trace -Message "[USR-002] Tenant creation not allowed for default users."
            Set-FindingOverride -FindingId "USR-002" -Props $USR002VariantProps.Secure
        }
    }

    # USR-003: Check BitLocker recovery key visibility for owned devices.
    $tenantDeviceCount = 0
    if ($null -ne $Devices) {
        if ($Devices -is [System.Collections.IDictionary]) {
            $tenantDeviceCount = $Devices.Count
        } elseif ($Devices -is [System.Collections.ICollection]) {
            $tenantDeviceCount = $Devices.Count
        } elseif ($Devices -is [System.Collections.IEnumerable] -and -not ($Devices -is [string])) {
            $tenantDeviceCount = @($Devices).Count
        } else {
            $tenantDeviceCount = 1
        }
    }

    if ($tenantDeviceCount -le 0) {
        Write-Log -Level Verbose -Message "[USR-003] Skipping check because no devices were identified in the tenant."
        Set-FindingOverride -FindingId "USR-003" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because no devices were identified in the tenant.</p><p>Detected device count: <code>0</code>.</p>"
            AffectedObjects = @()
        }
    } else {
    $allowedToReadBitlockerKeys = $null
    if ($AuthPolicy -and $AuthPolicy.defaultUserRolePermissions) {
        $allowedToReadBitlockerKeys = $AuthPolicy.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
    }
    if ($null -eq $allowedToReadBitlockerKeys) {
        Write-Log -Level Debug -Message "[USR-003] Authorization policy defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice not found."
    } else {
        Write-Log -Level Verbose -Message "[USR-003] Authorization policy allowedToReadBitlockerKeysForOwnedDevice: $allowedToReadBitlockerKeys"
        if ($allowedToReadBitlockerKeys) {
            Write-Log -Level Trace -Message "[USR-003] BitLocker recovery key access allowed for owned devices."
            Set-FindingOverride -FindingId "USR-003" -Props $USR003VariantProps.Vulnerable
            Set-FindingOverride -FindingId "USR-003" -Props @{
                Description = "<p>Users can read BitLocker recovery keys for devices they own.</p><p>Detected device count: <code>$tenantDeviceCount</code>.</p>"
            }
        } else {
            Write-Log -Level Trace -Message "[USR-003] BitLocker recovery key access not allowed for owned devices."
            Set-FindingOverride -FindingId "USR-003" -Props $USR003VariantProps.Secure
            Set-FindingOverride -FindingId "USR-003" -Props @{
                Description = "<p>Secure configuration in place:<br>Users cannot read BitLocker recovery keys for devices they own.</p><p>Detected device count: <code>$tenantDeviceCount</code>.</p>"
            }
        }
    }
    }

    # USR-004 (user consent to apps)
    # Interpret the default user consent policy and derive the finding state.
    $permissionGrantPolicyIds = $null
    if ($AuthPolicy) {
        $permissionGrantPolicyIds = $AuthPolicy.permissionGrantPolicyIdsAssignedToDefaultUserRole
    }
    if (-not $permissionGrantPolicyIds) {
        Write-Log -Level Debug -Message "[USR-004] Authorization policy permissionGrantPolicyIdsAssignedToDefaultUserRole not found."
    } else {
        $policyIds = @($permissionGrantPolicyIds)
        Write-Log -Level Verbose -Message "[USR-004] permissionGrantPolicyIdsAssignedToDefaultUserRole: $($policyIds -join ', ')"

        # Microsoft-managed policy allows consent to Microsoft-allowed scopes.
        if ($policyIds -contains "ManagePermissionGrantsForSelf.microsoft-user-default-recommended") {
            Write-Log -Level Trace -Message "[USR-004] User consent policy: Microsoft managed."
            Set-FindingOverride -FindingId "USR-004" -Props $USR004VariantProps.MicrosoftManaged
            
        # Low policy: evaluate classified permissions to identify extensive scopes.
        } elseif ($policyIds -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low") {
            Write-Log -Level Trace -Message "[USR-004] User consent policy: low with classified permissions."

            # Build the list of low-classified permission names from pre-collected data.
            $lowPermissions = @()
            if ($ConsentPermissionClassification -and $ConsentPermissionClassification.delegatedPermissionClassifications) {
                $lowPermissions = @($ConsentPermissionClassification.delegatedPermissionClassifications | Where-Object { $_.classification -eq "low" } | Select-Object -ExpandProperty permissionName)
            }

            # Cross-check low permissions against the internal categorization list.
            $extensiveLevels = @("Dangerous", "High", "Medium", "Critical")
            $extensivePermissions = @()
            foreach ($perm in $lowPermissions) {
                $rating = $global:GLOBALDelegatedApiPermissionCategorizationList[$perm]
                if ($rating -and ($extensiveLevels -contains $rating)) {
                    $extensivePermissions += $perm
                }
            }

            # Extensive permission found
            if ($extensivePermissions.Count -gt 0) {
                Write-Log -Level Trace -Message "[USR-004] Low-classified permissions include extensive items: $($extensivePermissions -join ', ')"
                $items = ($extensivePermissions | Sort-Object -Unique | ForEach-Object { "<li>$_</li>" }) -join ""
                # Apply base variant and then inject dynamic permission list.
                Set-FindingOverride -FindingId "USR-004" -Props $USR004VariantProps.LowExtensive
                Set-FindingOverride -FindingId "USR-004" -Props @{
                    Description = "<p>Users are allowed to consent to known extensive permissions:</p><ul>$items</ul>"
                }

            } else {
                Write-Log -Level Trace -Message "[USR-004] Low-classified permissions found, none categorized as extensive."
                $items = if ($lowPermissions.Count -gt 0) { ($lowPermissions | Sort-Object -Unique | ForEach-Object { "<li>$_</li>" }) -join "" } else { "" }
                $detail = if ($items) { "<ul>$items</ul>" } else { "" }
                # Apply base variant and then inject dynamic permission list.
                Set-FindingOverride -FindingId "USR-004" -Props $USR004VariantProps.LowSpecific
                Set-FindingOverride -FindingId "USR-004" -Props @{
                    Description = "<p>Users are allowed to consent to specific permissions. However none of these permissions is categorized as extensive.</p>$detail"
                }
            }
        } else {
            Write-Log -Level Trace -Message "[USR-004] User consent policy: no self-consent policy found."
            Set-FindingOverride -FindingId "USR-004" -Props $USR004VariantProps.Secure
        }
    }

    # USR-005: Enabled users marked as inactive.
    # Reuse pre-filtered data from the shared users enumeration loop.
    if ($global:GLOBALUserSignInActivityAvailable -eq $false) {
        Write-Log -Level Verbose -Message "[USR-005] Skipping check because SignInActivity could not be retrieved during user enumeration."
        Set-FindingOverride -FindingId "USR-005" -Props @{
            Status = "Skipped"
            Description = "<p>Check skipped because the current permissions or license do not allow retrieval of users SignInActivity properties. Inactive user status could not be evaluated.</p>"
            RelatedReportUrl = ""
            AffectedObjects = @()
        }
    } elseif ($inactiveEnabledUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-005] Found $($inactiveEnabledUsers.Count) enabled inactive users."

        $usr005Affected = [System.Collections.Generic.List[object]]::new()
        $inactiveMembers = 0
        $inactiveGuests = 0

        foreach ($entry in $inactiveEnabledUsers) {
            $user = $entry.User
            $userType = "$($user.UserType)"
            if ($userType -eq "Guest") {
                $inactiveGuests += 1
            } elseif ($userType -eq "Member") {
                $inactiveMembers += 1
            }

            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr005Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Type" = $user.UserType
                "Inactive" = $user.Inactive
                "Last sign-in (days)" = $user.LastSignInDays
                "Entra Roles" = $user.EntraRoles
                "Azure Roles" = $user.AzureRoles
                "Impact" = $user.Impact
            })
        }

        Set-FindingOverride -FindingId "USR-005" -Props $USR005VariantProps.Vulnerable
        if ($inactiveGuests -gt 0) {
            Set-FindingOverride -FindingId "USR-005" -Props $USR005VariantProps.VulnerableWithGuests
        }
        Set-FindingOverride -FindingId "USR-005" -Props @{
            Description = "<p>There are $($inactiveEnabledUsers.Count) inactive users.</p><ul><li>Internal users: $inactiveMembers</li><li>Guest users: $inactiveGuests</li></ul><p><strong>Note:</strong> Users are considered inactive if they have no successful sign-in for 180 days or if they never signed in and were created more than 180 days ago.</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Inactive=%3Dtrue&Enabled=%3Dtrue&columns=UPN%2CEnabled%2CUserType%2CEntraRoles%2CAzureRoles%2CInactive%2CLastSignInDays%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Impact&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr005Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-005] No inactive users found."
        Set-FindingOverride -FindingId "USR-005" -Props $USR005VariantProps.Secure
    }

    # USR-006: Enabled users with tier-0 Entra roles.
    # Reuse pre-filtered data from the shared users enumeration loop.
    $usr006Count = $enabledTier0Users.Count
    if ($usr006Count -lt 5) {
        Write-Log -Level Verbose -Message "[USR-006] Found $usr006Count users with tier-0 Entra roles (below threshold)."
        Set-FindingOverride -FindingId "USR-006" -Props $USR006VariantProps.Secure
        Set-FindingOverride -FindingId "USR-006" -Props @{
            AffectedObjects = @()
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-006] Found $usr006Count users with tier-0 Entra roles."
        $usr006Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledTier0Users) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr006Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Entra Roles" = $user.EntraRoles
                "Entra Max Tier" = $user.EntraMaxTier
                "Impact" = $user.Impact
                "Warnings" = $user.Warnings
            })
        }

        $usr006Props = @{
            Description = "<p>There are $usr006Count users with a Tier-0 Entra ID role assigned (directly or through groups).</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?EntraMaxTier=%3DTier-0&Enabled=%3Dtrue&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CEntraRoles%2CEntraMaxTier%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr006Affected
        }

        if ($usr006Count -le 7) {
            $usr006Props.Status = "Vulnerable"
            $usr006Props.Confidence = "Requires Verification"
            $usr006Props.Severity = 1
        } elseif ($usr006Count -le 15) {
            $usr006Props.Status = "Vulnerable"
            $usr006Props.Confidence = "Requires Verification"
        } else {
            $usr006Props.Status = "Vulnerable"
            $usr006Props.Confidence = "Sure"
            $usr006Props.Severity = 3
        }

        Set-FindingOverride -FindingId "USR-006" -Props $usr006Props
    }

    # USR-007: Hybrid (on-prem synced) users with tier-0 Entra roles.
    # Reuse pre-filtered data from the shared users enumeration loop.
    if ($enabledTier0OnPremUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-007] Found $($enabledTier0OnPremUsers.Count) hybrid users with tier-0 Entra roles."
        $usr007Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledTier0OnPremUsers) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr007Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "OnPrem" = $user.OnPrem
                "Entra Roles" = $user.EntraRoles
                "Entra Max Tier" = $user.EntraMaxTier
                "Impact" = $user.Impact
                "Warnings" = $user.Warnings
            })
        }

        Set-FindingOverride -FindingId "USR-007" -Props $USR007VariantProps.Vulnerable
        Set-FindingOverride -FindingId "USR-007" -Props @{
            Description = "<p>There are $($enabledTier0OnPremUsers.Count) hybrid (on-premises synchronized) users with a Tier-0 Entra ID role assigned (directly or through groups)</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?EntraMaxTier=%3DTier-0&Enabled=%3Dtrue&OnPrem=%3Dtrue&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CEntraRoles%2CEntraMaxTier%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr007Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-007] No hybrid users with tier-0 Entra roles found."
        Set-FindingOverride -FindingId "USR-007" -Props $USR007VariantProps.Secure
    }

    # USR-008: Hybrid (on-prem synced) users with tier-0 Azure roles.
    # Skip this check when Azure role assignment enumeration was not performed.
    if (-not $GLOBALAzurePsChecks) {
        Write-Log -Level Verbose -Message "[USR-008] Skipping check because Azure role assignments were not enumerated."
        Set-FindingOverride -FindingId "USR-008" -Props $USR008VariantProps.Skipped
    } elseif ($enabledTier0AzureOnPremUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-008] Found $($enabledTier0AzureOnPremUsers.Count) hybrid users with tier-0 Azure roles."
        $usr008Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledTier0AzureOnPremUsers) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr008Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "OnPrem" = $user.OnPrem
                "Azure Roles" = $user.AzureRoles
                "Azure Max Tier" = $user.AzureMaxTier
                "Impact" = $user.Impact
                "Warnings" = $user.Warnings
            })
        }

        Set-FindingOverride -FindingId "USR-008" -Props $USR008VariantProps.Vulnerable
        Set-FindingOverride -FindingId "USR-008" -Props @{
            Description = "<p>There are $($enabledTier0AzureOnPremUsers.Count) hybrid (on-premises synchronized) users with a Tier-0 Azure role assigned (directly or through groups).</p><p><strong>Important:</strong> This finding requires manual verification. The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Azure provides more than 850 built-in roles, and the actual impact depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AzureMaxTier=%3DTier-0&Enabled=%3Dtrue&OnPrem=%3Dtrue&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CAzureRoles%2CAzureMaxTier%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr008Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-008] No hybrid users with tier-0 Azure roles found."
        Set-FindingOverride -FindingId "USR-008" -Props $USR008VariantProps.Secure
    }

    # USR-009: Enabled users with tier-0 Azure roles.
    # Skip this check when Azure role assignment enumeration was not performed.
    if (-not $GLOBALAzurePsChecks) {
        Write-Log -Level Verbose -Message "[USR-009] Skipping check because Azure role assignments were not enumerated."
        Set-FindingOverride -FindingId "USR-009" -Props $USR009VariantProps.Skipped
    } else {
        $usr009Count = $enabledTier0AzureUsers.Count
        if ($usr009Count -lt 8) {
            Write-Log -Level Verbose -Message "[USR-009] Found $usr009Count users with tier-0 Azure roles (below threshold)."
            Set-FindingOverride -FindingId "USR-009" -Props $USR009VariantProps.Secure
            Set-FindingOverride -FindingId "USR-009" -Props @{
                AffectedObjects = @()
            }
        } else {
            Write-Log -Level Verbose -Message "[USR-009] Found $usr009Count users with tier-0 Azure roles."
            $usr009Affected = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in $enabledTier0AzureUsers) {
                $user = $entry.User
                $displayName = "$($user.UPN)"
                if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
                $usr009Affected.Add([pscustomobject][ordered]@{
                    "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                    "Azure Roles" = $user.AzureRoles
                    "Azure Max Tier" = $user.AzureMaxTier
                    "Impact" = $user.Impact
                    "Warnings" = $user.Warnings
                })
            }

            Set-FindingOverride -FindingId "USR-009" -Props $USR009VariantProps.Vulnerable
            Set-FindingOverride -FindingId "USR-009" -Props @{
                Description = "<p>There are $usr009Count users with a Tier-0 Azure role assigned (directly or through groups).</p><p><strong>Important:</strong> This finding requires manual verification. The Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Azure provides more than 850 built-in roles, and the actual impact depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
                RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?AzureMaxTier=%3DTier-0&Enabled=%3Dtrue&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CAzureRoles%2CAzureMaxTier%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
                AffectedSortKey = "Impact"
                AffectedSortDir = "DESC"
                AffectedObjects = $usr009Affected
            }
        }
    }

    # USR-010: Enabled tier-0 Entra users that are not protected.
    # Reuse pre-filtered data from the shared users enumeration loop.
    if ($enabledTier0UnprotectedUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-010] Found $($enabledTier0UnprotectedUsers.Count) unprotected users with tier-0 Entra roles."
        $usr010Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledTier0UnprotectedUsers) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr010Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Protected" = $user.Protected
                "Entra Roles" = $user.EntraRoles
                "Entra Max Tier" = $user.EntraMaxTier
                "Impact" = $user.Impact
                "Warnings" = $user.Warnings
            })
        }

        Set-FindingOverride -FindingId "USR-010" -Props $USR010VariantProps.Vulnerable
        Set-FindingOverride -FindingId "USR-010" -Props @{
            Description = "<p>There are $($enabledTier0UnprotectedUsers.Count) users with a Tier-0 Entra ID role assigned (through groups) who are not protected against modifications by lower-tier administrators or applications. They are considered unprotected because they are:</p><ul><li>Not direct members of a privileged role</li><li>Not members of a role-assignable group</li><li>Not members of a Restricted Management Administrative Unit</li></ul><p>This situation commonly occurs when non-role-assignable groups are eligible members of groups with Tier-0 roles (PIM for Groups).</p><p><strong>Important:</strong> This finding requires manual verification. Exploitability also depends on additional factors (for example, password hash synchronization or password write-back configuration).</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Protected=%3Dfalse&Enabled=%3Dtrue&Agent=%3Dfalse&EntraMaxTier=%3DTier-0&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CGrpMem%2CGrpOwn%2CAuUnits%2CEntraRoles%2CEntraMaxTier%2CAppRoles%2CAppRegOwn%2CSPOwn%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr010Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-010] No unprotected users with tier-0 Entra roles found."
        Set-FindingOverride -FindingId "USR-010" -Props $USR010VariantProps.Secure
    }

    # USR-011: Enabled tier-0 Azure users that are not protected.
    # Skip this check when Azure role assignment enumeration was not performed.
    if (-not $GLOBALAzurePsChecks) {
        Write-Log -Level Verbose -Message "[USR-011] Skipping check because Azure role assignments were not enumerated."
        Set-FindingOverride -FindingId "USR-011" -Props $USR011VariantProps.Skipped
    } elseif ($enabledTier0AzureUnprotectedUsers.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-011] Found $($enabledTier0AzureUnprotectedUsers.Count) unprotected users with tier-0 Azure roles."
        $usr011Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledTier0AzureUnprotectedUsers) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr011Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "Protected" = $user.Protected
                "Azure Roles" = $user.AzureRoles
                "Azure Max Tier" = $user.AzureMaxTier
                "Impact" = $user.Impact
                "Warnings" = $user.Warnings
            })
        }

        Set-FindingOverride -FindingId "USR-011" -Props $USR011VariantProps.Vulnerable
        Set-FindingOverride -FindingId "USR-011" -Props @{
            Description = "<p>There are $($enabledTier0AzureUnprotectedUsers.Count) users with Tier-0 Azure roles assigned (directly or through groups) who are not protected against modifications by lower-tier administrators or applications. They are considered unprotected because they are:</p><ul><li>Not direct members of a privileged role</li><li>Not members of a role-assignable group</li><li>Not members of a Restricted Management Administrative Unit</li></ul><p><strong>Important:</strong> This finding requires manual verification. Exploitability also depends on additional factors (for example, password hash synchronization or password write-back configuration). Furthermore, the Azure role tier classification is based solely on the assigned role and does not consider the scope of the permission (for example, whether it is assigned at the subscription level or to a specific resource). Azure provides more than 850 built-in roles, and the actual impact depends on the resources to which the role is scoped. For example, a Tier 0 role may only be assigned to a non-critical resource in a test subscription.</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Protected=%3Dfalse&Enabled=%3Dtrue&AzureMaxTier=%3DTier-0&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CProtected%2CGrpMem%2CGrpOwn%2CAuUnits%2CAzureRoles%2CAzureMaxTier%2CAppRoles%2CAppRegOwn%2CSPOwn%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr011Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-011] No unprotected users with tier-0 Azure roles found."
        Set-FindingOverride -FindingId "USR-011" -Props $USR011VariantProps.Secure
    }

    # USR-012: Enabled users without registered MFA factors.
    # Reuse pre-filtered data from the shared users enumeration loop and adjust risk based on CAP-002.
    if ($enabledUsersWithoutMfaCap.Count -gt 0) {
        Write-Log -Level Verbose -Message "[USR-012] Found $($enabledUsersWithoutMfaCap.Count) enabled users without MFA capability."
        $usr012PopulationText = "$($enabledUsersWithoutMfaCap.Count) of $enabledUsersForMfaCapCheckCount enabled users"
        $usr012Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledUsersWithoutMfaCap) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr012Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "MFA Capable" = $user.MfaCap
                "Type" = $user.UserType
                "Entra Max Tier" = $user.EntraMaxTier
                "Azure Max Tier" = $user.AzureMaxTier
                "Impact" = $user.Impact
            })
        }

        $cap002IsVulnerable = $false
        if ($FindingsById.ContainsKey("CAP-002")) {
            $cap002Status = "$($FindingsById["CAP-002"].Status)".Trim().ToLowerInvariant()
            $cap002IsVulnerable = $cap002Status -eq "vulnerable"
        }

        if ($cap002IsVulnerable) {
            Set-FindingOverride -FindingId "USR-012" -Props $USR012VariantProps.VulnerableCapIssues
            Set-FindingOverride -FindingId "USR-012" -Props @{
                Description = "<p>There are $usr012PopulationText without any registered MFA methods in Entra ID.</p><p>Additionally, issues were identified with the Conditional Access policies that set the conditions for registering MFA methods (check <a href=`"#CAP-002`">CAP-002</a>).</p><p><strong>Important:</strong> This finding requires manual verification.</p>"
                Remediation = "<p>Ensure that attackers cannot register MFA methods for these users (see the recommendations in finding <a href=`"#CAP-002`">CAP-002</a>, if applicable).</p><p>Additionally, review why these users do not have any MFA methods registered and verify whether MFA enrollment and enforcement are configured correctly, and whether these users are required to exist in Entra ID.</p>"
            }
        } else {
            Set-FindingOverride -FindingId "USR-012" -Props $USR012VariantProps.VulnerableCapSecure
            Set-FindingOverride -FindingId "USR-012" -Props @{
                Description = "<p>There are $usr012PopulationText without any registered MFA methods in Entra ID.</p><p><strong>Note:</strong> Finding CAP-002 was assessed as not vulnerable. Therefore, attackers should not be able to register new MFA methods even if a user`s password is compromised.</p>"
            }
        }

        Set-FindingOverride -FindingId "USR-012" -Props @{
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Enabled=%3Dtrue&Agent=%3Dfalse&MfaCap=false&Warnings=%21Sync&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CGrpMem%2CGrpOwn%2CAuUnits%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CAppRoles%2CAppRegOwn%2CSPOwn%2CInactive%2CMfaCap%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Impact&sortDir=desc"
            AffectedSortKey = "Impact"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr012Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-012] No enabled users without MFA capability found."
        Set-FindingOverride -FindingId "USR-012" -Props $USR012VariantProps.Secure
    }

    # USR-013: Enabled synchronized on-premises accounts older than 90 days that never signed in to Entra ID.
    if ($global:GLOBALUserSignInActivityAvailable -eq $false) {
        Write-Log -Level Verbose -Message "[USR-013] Skipping check because SignInActivity could not be retrieved during user enumeration."
        Set-FindingOverride -FindingId "USR-013" -Props $USR013VariantProps.Skipped
    } elseif ($enabledOnPremNeverSignedInOlderThan90Users.Count -ge 5) {
        Write-Log -Level Verbose -Message "[USR-013] Found $($enabledOnPremNeverSignedInOlderThan90Users.Count) enabled synchronized on-premises accounts older than 90 days without recorded sign-in to Entra ID."
        $usr013Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $enabledOnPremNeverSignedInOlderThan90Users) {
            $user = $entry.User
            $displayName = "$($user.UPN)"
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "$($entry.Id)" }
            $usr013Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$displayName</a>"
                "OnPrem" = $user.OnPrem
                "CreatedDays" = $user.CreatedDays
                "Last sign-in (days)" = $user.LastSignInDays
            })
        }

        Set-FindingOverride -FindingId "USR-013" -Props $USR013VariantProps.Vulnerable
        Set-FindingOverride -FindingId "USR-013" -Props @{
            Description = "<p>$($enabledOnPremNeverSignedInOlderThan90Users.Count) enabled accounts are synchronized from on-premises Active Directory to Entra ID even though they appear not to be used in the cloud.</p><p>These accounts have all of the following characteristics:</p><ul><li>Synchronized from on-premises Active Directory</li><li>Enabled</li><li>Older than three months</li><li>No recorded authentication to Entra ID</li></ul><p>This indicates that these accounts are likely not required for cloud services, but are still exposed through the cloud identity plane.</p>"
            RelatedReportUrl = "Users_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Enabled=%3Dtrue&OnPrem=%3Dtrue&LastSignInDays=%3D-&CreatedDays=%3E90&columns=UPN%2CEnabled%2CUserType%2COnPrem%2CLicenseStatus%2CGrpMem%2CGrpOwn%2CAuUnits%2CEntraRoles%2CEntraMaxTier%2CAzureRoles%2CAzureMaxTier%2CAppRoles%2CAppRegOwn%2CSPOwn%2CInactive%2CLastSignInDays%2CCreatedDays%2CMfaCap%2CPerUserMfa%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Impact&sortDir=desc"
            AffectedSortKey = "CreatedDays"
            AffectedSortDir = "DESC"
            AffectedObjects = $usr013Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[USR-013] Found $($enabledOnPremNeverSignedInOlderThan90Users.Count) enabled synchronized on-premises accounts older than 90 days without recorded sign-in to Entra ID (below threshold)."
        Set-FindingOverride -FindingId "USR-013" -Props $USR013VariantProps.Secure
    }

    #endregion

    #region GRP Evaluation
    # GRP-001: Check if regular users can create security groups.
    $allowedToCreateSecurityGroups = $null
    if ($AuthPolicy -and $AuthPolicy.defaultUserRolePermissions) {
        $allowedToCreateSecurityGroups = $AuthPolicy.defaultUserRolePermissions.allowedToCreateSecurityGroups
    }
    if ($null -eq $allowedToCreateSecurityGroups) {
        Write-Log -Level Debug -Message "[GRP-001] Authorization policy defaultUserRolePermissions.allowedToCreateSecurityGroups not found."
    } else {
        Write-Log -Level Verbose -Message "[GRP-001] Authorization policy allowedToCreateSecurityGroups: $allowedToCreateSecurityGroups"
        if ($allowedToCreateSecurityGroups) {
            Write-Log -Level Trace -Message "[GRP-001] Security group creation allowed for default users."
            Set-FindingOverride -FindingId "GRP-001" -Props $GRP001VariantProps.Vulnerable
        } else {
            Write-Log -Level Trace -Message "[GRP-001] Security group creation not allowed for default users."
            Set-FindingOverride -FindingId "GRP-001" -Props $GRP001VariantProps.Secure
        }
    }

    ### GRP-002
    # Evaluate tenant directory settings from pre-collected data.
    # GRP-002: Find EnableGroupCreation in the unified group settings template.
    $enableGroupCreation = $null
    if ($TenantDirectorySettingsList.Count -gt 0) {
        $groupSettings = $TenantDirectorySettingsList | Where-Object { $_.templateId -eq $UnifiedGroupSettingsTemplateId } | Select-Object -First 1
        if ($groupSettings -and $groupSettings.values) {
            $enableGroupCreationEntry = $groupSettings.values | Where-Object { $_.name -eq "EnableGroupCreation" } | Select-Object -First 1
            if ($enableGroupCreationEntry) {
                $enableGroupCreation = $enableGroupCreationEntry.value
            }
        }
    }

    if ($null -eq $enableGroupCreation) {
        Write-Log -Level Debug -Message "[GRP-002] Tenant directory settings EnableGroupCreation not found in the unified group template."
    } else {
        if ($enableGroupCreation -is [string]) {
            $enableGroupCreation = $enableGroupCreation.Trim().ToLowerInvariant() -eq "true"
        } else {
            $enableGroupCreation = [bool]$enableGroupCreation
        }
        Write-Log -Level Verbose -Message "[GRP-002] Tenant directory settings EnableGroupCreation: $enableGroupCreation"
        if ($enableGroupCreation) {
            Write-Log -Level Trace -Message "[GRP-002] M365 group creation allowed for default users."
            Set-FindingOverride -FindingId "GRP-002" -Props $GRP002VariantProps.Vulnerable
        } else {
            Write-Log -Level Trace -Message "[GRP-002] M365 group creation not allowed for default users."
            Set-FindingOverride -FindingId "GRP-002" -Props $GRP002VariantProps.Secure
        }
    }

    # GRP-003: Public Microsoft 365 groups.
    # Reuse pre-filtered group data from the shared group enumeration loop.
    if ($publicM365Groups.Count -gt 0) {
        Write-Log -Level Verbose -Message "[GRP-003] Found $($publicM365Groups.Count) public M365 groups."
        $grp003Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $publicM365Groups) {
            $group = $entry.Group
            $groupDisplayName = "$($group.DisplayName)"
            if ([string]::IsNullOrWhiteSpace($groupDisplayName)) { $groupDisplayName = "$($entry.Id)" }
            $grp003Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$groupDisplayName</a>"
                "Type" = $group.Type
                "Visibility" = $group.Visibility
                "Security Enabled" = $group.SecurityEnabled
                "Warnings" = $group.Warnings
                "_SortImpact" = $group.Impact
            })
        }
        Set-FindingOverride -FindingId "GRP-003" -Props $GRP003VariantProps.Vulnerable
        Set-FindingOverride -FindingId "GRP-003" -Props @{
            Description = "<p>There are $($publicM365Groups.Count) public M365 groups.</p>"
            RelatedReportUrl = "Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Visibility=%3DPublic&Type=%3DM365+Group&Dynamic=%3Dfalse&columns=DisplayName%2CType%2CSecurityEnabled%2CVisibility%2CUsers%2CNestedInGroups%2CAppRoles%2CCAPs%2CEntraRoles%2CAzureRoles%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
            AffectedObjects = $grp003Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[GRP-003] No public M365 groups found."
        Set-FindingOverride -FindingId "GRP-003" -Props $GRP003VariantProps.Secure
    }

    # GRP-004: Dynamic groups using potentially manipulable membership-rule attributes.
    # Reuse the pre-evaluated result from the shared group loop.
    if ($dynamicGroupsWithDangerousRules.Count -gt 0) {
        Write-Log -Level Verbose -Message "[GRP-004] Found $($dynamicGroupsWithDangerousRules.Count) dynamic groups with potentially dangerous membership rules."

        $grp004Affected = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $dynamicGroupsWithDangerousRules) {
            $group = $entry.Group
            $groupDisplayName = "$($group.DisplayName)"
            if ([string]::IsNullOrWhiteSpace($groupDisplayName)) { $groupDisplayName = "$($entry.Id)" }
            $grp004Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$groupDisplayName</a>"
                "Dynamic" = $group.Dynamic
                "Membership Rule" = $group.MembershipRule
                "Warnings" = $group.Warnings
                "_SortImpact" = $group.Impact
            })
        }

        $attributeSummaryItems = [System.Collections.Generic.List[string]]::new()
        foreach ($attributeName in $dangerousDynamicAttributeCounts.Keys) {
            $count = [int]$dangerousDynamicAttributeCounts[$attributeName]
            if ($count -gt 0) {
                $attributeSummaryItems.Add("<li>${attributeName}: $count</li>")
            }
        }
        $attributeSummaryHtml = if ($attributeSummaryItems.Count -gt 0) { "<ul>$($attributeSummaryItems -join '')</ul>" } else { "" }

        $usesInviteSensitiveAttributes = ([int]$dangerousDynamicAttributeCounts["user.userPrincipalName"] -gt 0) -or ([int]$dangerousDynamicAttributeCounts["user.mail"] -gt 0)
        $threatVariant = $null
        if ($usesInviteSensitiveAttributes) {
            switch ("$allowInvitesFromForDynamicRules") {
                "everyone" { $threatVariant = $GRP004VariantProps.InviteEveryone }
                "adminsGuestInvitersAndAllMembers" { $threatVariant = $GRP004VariantProps.InviteAdminsGuestInvitersAndAllMembers }
                "adminsAndGuestInviters" { $threatVariant = $GRP004VariantProps.InviteAdminsAndGuestInviters }
            }
        }

        Set-FindingOverride -FindingId "GRP-004" -Props $GRP004VariantProps.Vulnerable
        if ($threatVariant) {
            Set-FindingOverride -FindingId "GRP-004" -Props $threatVariant
        }
        Set-FindingOverride -FindingId "GRP-004" -Props @{
            Description = "<p>There are $($dynamicGroupsWithDangerousRules.Count) dynamic groups with potentially dangerous membership rules.</p><p>Used potentially dangerous attributes:</p>$attributeSummaryHtml<p><strong>Important:</strong> This finding requires manual verification. Whether a rule using one of these manipulable attributes is exploitable depends on the operator used, the assigned values, and how it is combined with other conditions in the rule.</p>"
            RelatedReportUrl = "Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Dynamic=%3Dtrue&Warnings=dangerous+query&columns=DisplayName%2CType%2CSecurityEnabled%2CDynamic%2CVisibility%2CUsers%2CDevices%2CNestedInGroups%2CAppRoles%2CCAPs%2CEntraRoles%2CAzureRoles%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Risk&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
            AffectedObjects = $grp004Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[GRP-004] No dynamic groups with potentially dangerous membership rules found."
        Set-FindingOverride -FindingId "GRP-004" -Props $GRP004VariantProps.Secure
    }

    # GRP-005: Unprotected groups used in sensitive contexts (CAP/Azure/Entra role assignments).
    # Reuse pre-evaluated results from the shared group enumeration loop.
    if ($unprotectedSensitiveGroups.Count -gt 0) {
        Write-Log -Level Verbose -Message "[GRP-005] Found $($unprotectedSensitiveGroups.Count) unprotected sensitive groups."

        $grp005Affected = [System.Collections.Generic.List[object]]::new()
        $groupsUsedInCaps = 0
        $groupsUsedInAzureRoles = 0
        $groupsUsedInEntraRoles = 0

        foreach ($entry in $unprotectedSensitiveGroups) {
            $group = $entry.Group
            $groupDisplayName = "$($group.DisplayName)"
            if ([string]::IsNullOrWhiteSpace($groupDisplayName)) { $groupDisplayName = "$($entry.Id)" }

            if ($entry.HasCapsUsage) { $groupsUsedInCaps += 1 }
            if ($entry.HasAzureRolesUsage) { $groupsUsedInAzureRoles += 1 }
            if ($entry.HasEntraRolesUsage) { $groupsUsedInEntraRoles += 1 }

            $grp005Affected.Add([pscustomobject][ordered]@{
                "DisplayName" = "<a href=`"Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($entry.Id)`" target=`"_blank`">$groupDisplayName</a>"
                "Protected" = $group.Protected
                "Entra Roles" = $group.EntraRoles
                "Entra Tier" = $group.EntraMaxTier
                "Azure Roles" = $group.AzureRoles
                "Azure Tier" = $group.AzureMaxTier
                "CAPs" = $group.CAPs
                "Warnings" = $group.Warnings
                "_SortImpact" = $group.Impact
            })
        }

        Set-FindingOverride -FindingId "GRP-005" -Props $GRP005VariantProps.Vulnerable
        Set-FindingOverride -FindingId "GRP-005" -Props @{
            Description = "<p>There are $($unprotectedSensitiveGroups.Count) sensitive groups that are insufficiently protected. They are:</p><ul><li>Not synchronized from on-premises</li><li>Not configured as role-assignable</li><li>Not protected by a Restricted Management Administrative Unit</li></ul><p>Unprotected group usage:</p><ul><li>$groupsUsedInCaps groups are used in Conditional Access policies</li><li>$groupsUsedInAzureRoles groups are used for Azure role assignments with a highest tier of Tier-0, Tier-1, or Uncategorized</li><li>$groupsUsedInEntraRoles groups are used for Entra ID role assignments</li></ul><p><strong>Important:</strong> This finding requires manual verification. Assess the impact if a lower-tier administrator or application can manage the membership of these groups.</p>"
            RelatedReportUrl = "Groups_$StartTimestamp`_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Protected=%3Dfalse&or_EntraRoles=%3E0&or_AzureMaxTier=Tier-0%7C%7CTier-1%7C%7CUncategorized&or_CAPs=%3E0&columns=DisplayName%2CType%2CSecurityEnabled%2CDynamic%2CVisibility%2CProtected%2CUsers%2CEntraMaxTier%2C%2CAzureMaxTier%2CNestedInGroups%2CAppRoles%2CCAPs%2CEntraRoles%2CAzureRoles%2CImpact%2CLikelihood%2CRisk%2CWarnings&sort=Impact&sortDir=desc"
            AffectedSortKey = "_SortImpact"
            AffectedSortDir = "DESC"
            AffectedObjects = $grp005Affected
        }
    } else {
        Write-Log -Level Verbose -Message "[GRP-005] No unprotected sensitive groups found."
        Set-FindingOverride -FindingId "GRP-005" -Props $GRP005VariantProps.Secure
    }







    #endregion
    #endregion

    # Report generation input
    $FindingsJson = $Findings | ConvertTo-Json -Depth 6


    ############################## Reporting section ########################
    #region Reporting
    $extraCss = @"
<style>
    .finding-controls {
        margin: 12px 0 16px 0;
        padding: 12px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.12);
    }
    body.dark-mode .finding-controls { border-color: rgba(255,255,255,0.16); }

    .top-panel {
        margin-bottom: 10px;
    }

    .top-panel > summary {
        list-style: none;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 0px;
        margin: 0 0 0px 0;
        font-size: 12px;
        font-weight: 600;
        line-height: 1;
        padding: 0;
        user-select: none;
    }

    .top-panel > summary::-webkit-details-marker {
        display: none;
    }

    .top-panel > summary::before {
        content: "\25B8";
        display: inline-block;
        width: 12px;
        text-align: center;
    }

    .top-panel[open] > summary::before {
        content: "\25BE";
    }

    .top-panel:not([open]) > summary::after {
        content: "Show section";
    }

    .finding-controls-row {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
    }
    .finding-controls-row.quick-row #visibleCount {
        margin-left: auto;
    }
    .finding-controls-row.advanced-row {
        margin-top: 8px;
        padding-top: 8px;
        border-top: 1px dashed rgba(0,0,0,0.14);
    }
    body.dark-mode .finding-controls-row.advanced-row {
        border-top-color: rgba(255,255,255,0.18);
    }
    .inline-confirm {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 8px;
        border-radius: 8px;
        border: 1px solid rgba(0,0,0,0.18);
        background: rgba(255,255,255,0.9);
        font-size: 12px;
    }
    .inline-confirm.hidden {
        display: none;
    }
    .inline-confirm button {
        padding: 4px 8px;
        font-size: 12px;
    }
    body.dark-mode .inline-confirm {
        border-color: rgba(255,255,255,0.2);
        background: rgba(20,20,20,0.88);
    }
    @media (max-width: 900px) {
        .finding-controls-row.quick-row #visibleCount {
            margin-left: 0;
        }
    }

    .export-menu {
        position: relative;
        display: inline-block;
    }

    .export-menu-panel {
        position: absolute;
        top: calc(100% + 6px);
        right: 0;
        min-width: 150px;
        padding: 6px;
        border-radius: 8px;
        border: 1px solid rgba(0,0,0,0.18);
        background: rgba(255,255,255,0.98);
        box-shadow: 0 8px 20px rgba(0,0,0,0.18);
        z-index: 5;
    }
    body.dark-mode .export-menu-panel {
        border-color: rgba(255,255,255,0.18);
        background: rgba(25,25,25,0.98);
        box-shadow: 0 8px 20px rgba(0,0,0,0.45);
    }

    .export-menu-panel.hidden {
        display: none;
    }

    .export-menu-panel button {
        width: 100%;
        text-align: left;
        padding: 6px 8px;
        border-radius: 6px;
        border: 0;
        background: transparent;
        cursor: pointer;
        font-size: 12px;
    }

    .export-menu-panel button:hover {
        background: rgba(0,0,0,0.06);
    }
    body.dark-mode .export-menu-panel button:hover {
        background: rgba(255,255,255,0.08);
    }

    .finding-controls input[type="search"] {
        min-width: 220px;
        padding: 6px 10px;
        border-radius: 6px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 13px;
    }
    body.dark-mode .finding-controls input[type="search"] {
        border-color: rgba(255,255,255,0.25);
        background: rgba(0,0,0,0.35);
        color: inherit;
    }

    .search-box {
        position: relative;
        display: inline-flex;
        align-items: center;
    }

    .search-box #findingSearch {
        padding-right: 34px;
        min-width: 320px;
    }

    .search-help-btn {
        position: absolute;
        right: 6px;
        top: 50%;
        transform: translateY(-50%);
        width: 22px;
        height: 22px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.24);
        background: rgba(0,0,0,0.05);
        color: inherit;
        font-size: 12px;
        font-weight: 700;
        line-height: 1;
        cursor: pointer;
        padding: 0;
    }
    .search-help-btn:hover {
        background: rgba(0,0,0,0.12);
    }
    body.dark-mode .search-help-btn {
        border-color: rgba(255,255,255,0.28);
        background: rgba(255,255,255,0.08);
    }
    body.dark-mode .search-help-btn:hover {
        background: rgba(255,255,255,0.16);
    }

    .search-help-popover {
        position: absolute;
        left: 0;
        top: calc(100% + 6px);
        width: min(480px, 92vw);
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.2);
        background: rgba(255,255,255,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.18);
        z-index: 20;
        font-size: 12px;
    }
    .search-help-popover.hidden {
        display: none;
    }
    body.dark-mode .search-help-popover {
        border-color: rgba(255,255,255,0.2);
        background: rgba(28,28,28,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.45);
    }
    .search-help-title {
        font-weight: 700;
        margin-bottom: 6px;
    }
    .search-help-list {
        margin: 0;
        padding-left: 18px;
    }
    .search-help-list li {
        margin: 2px 0;
    }
    .search-help-example {
        margin-top: 8px;
    }
    .search-help-example code {
        white-space: normal;
        overflow-wrap: anywhere;
    }

    @media (max-width: 900px) {
        .search-box #findingSearch {
            min-width: 220px;
        }
    }

    .search-fields-menu {
        position: relative;
        display: inline-block;
    }

    .search-fields-panel {
        position: absolute;
        left: 0;
        top: calc(100% + 6px);
        min-width: 220px;
        padding: 8px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.2);
        background: rgba(255,255,255,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.18);
        z-index: 20;
    }

    .search-fields-panel.hidden {
        display: none;
    }

    .search-fields-panel label {
        display: flex;
        align-items: center;
        gap: 6px;
        margin: 4px 0;
        font-size: 12px;
        white-space: nowrap;
    }

    .search-fields-actions {
        display: flex;
        gap: 6px;
        margin-top: 4px;
        margin-bottom: 6px;
    }

    .search-fields-actions button {
        flex: 1 1 auto;
        padding: 3px 6px;
        font-size: 11px;
        border-radius: 6px;
    }

    .search-fields-note {
        margin-top: 6px;
        font-size: 11px;
        opacity: 0.7;
    }

    body.dark-mode .search-fields-panel {
        border-color: rgba(255,255,255,0.2);
        background: rgba(28,28,28,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.45);
    }

    .finding-filters {
        margin-top: 12px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 12px;
    }

    .filter-group {
        padding: 10px;
        border-radius: 10px;
        border: 1px dashed rgba(0,0,0,0.18);
    }
    body.dark-mode .filter-group { border-color: rgba(255,255,255,0.2); }

    .filter-title {
        font-weight: bold;
        margin-bottom: 6px;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        opacity: 0.8;
    }

    .filter-options label {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        margin: 4px 0;
    }
    .filter-options label.disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .filter-count {
        opacity: 0.6;
        font-size: 11px;
    }

    .finding-category {
        margin-top: 18px;
    }

    .category-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        padding-bottom: 6px;
        margin-bottom: 8px;
    }

    .category-header h2 {
        margin: 0;
    }

    .category-summary {
        display: flex;
        flex-wrap: nowrap;
        gap: 8px;
        align-items: center;
        margin: 0;
    }

    .summary-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 12px;
        border: 1px solid var(--color-border);
        background: rgba(0, 0, 0, 0.04);
        white-space: nowrap;
    }
    body.dark-mode .summary-chip {
        background: rgba(255, 255, 255, 0.06);
    }

    .summary-chip.vuln {
        border-color: rgba(160, 60, 60, 0.9);
        color: rgba(140, 40, 40, 0.95);
    }

    .summary-chip.ok {
        border-color: rgba(40, 130, 80, 0.9);
        color: rgba(30, 110, 70, 0.95);
    }

    .summary-chip.coverage {
        border-color: rgba(50, 110, 150, 0.9);
        color: rgba(35, 95, 130, 0.95);
    }

    .summary-chip.skipped {
        border-color: rgba(120, 120, 120, 0.9);
        color: rgba(95, 95, 95, 0.95);
    }

    body.dark-mode .summary-chip.vuln {
        border-color: rgba(180, 80, 80, 0.8);
        color: rgba(255, 190, 190, 0.95);
    }
    body.dark-mode .summary-chip.ok {
        border-color: rgba(60, 160, 110, 0.8);
        color: rgba(190, 255, 220, 0.95);
    }
    body.dark-mode .summary-chip.coverage {
        border-color: rgba(70, 140, 170, 0.9);
        color: rgba(185, 230, 245, 0.95);
    }

    body.dark-mode .summary-chip.skipped {
        border-color: rgba(150, 150, 150, 0.85);
        color: rgba(220, 220, 220, 0.95);
    }

    .category-coverage-bar {
        flex: 1 1 160px;
        height: 8px;
        border-radius: 999px;
        background: rgba(0, 0, 0, 0.08);
        border: 1px solid rgba(0, 0, 0, 0.2);
        overflow: hidden;
        min-width: 140px;
    }
    body.dark-mode .category-coverage-bar {
        background: rgba(255, 255, 255, 0.08);
        border-color: rgba(255, 255, 255, 0.18);
    }

    .category-coverage-fill {
        height: 100%;
        width: 0%;
        background: rgba(180, 80, 80, 0.92);
        transition: width 160ms ease, background-color 160ms ease;
    }

    .finding-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .finding-summary {
        margin: 16px 0 6px 0;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 10px;
        width: 100%;
    }

    .summary-card.score {
        grid-column: 1 / -1;
    }

    .summary-card.wide {
        grid-column: auto;
    }

    @media (min-width: 1100px) {
        .finding-summary {
            grid-template-columns: repeat(4, minmax(180px, 1fr));
        }
    }

    .overview-charts {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 16px;
        margin: 8px 0 14px 0;
    }

    .overview-kpis {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin: 8px 0 16px 0;
    }

    .overview-kpi-card {
        display: grid;
        gap: 8px;
        padding: 14px;
        border-radius: 12px;
        border: 1px solid rgba(0,0,0,0.15);
        background: rgba(0,0,0,0.02);
    }
    body.dark-mode .overview-kpi-card {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .overview-kpi-card.vulnerable {
        border-color: rgba(160, 60, 60, 0.32);
        background: rgba(180, 60, 60, 0.06);
    }
    .overview-kpi-card.not-vulnerable {
        border-color: rgba(40, 130, 80, 0.30);
        background: rgba(60, 150, 90, 0.06);
    }
    .overview-kpi-card.skipped {
        border-color: rgba(70, 130, 190, 0.30);
        background: rgba(70, 130, 190, 0.08);
    }

    body.dark-mode .overview-kpi-card.vulnerable {
        border-color: rgba(200, 90, 90, 0.35);
        background: rgba(170, 70, 70, 0.12);
    }
    body.dark-mode .overview-kpi-card.not-vulnerable {
        border-color: rgba(70, 170, 110, 0.34);
        background: rgba(60, 150, 90, 0.12);
    }
    body.dark-mode .overview-kpi-card.skipped {
        border-color: rgba(110, 165, 220, 0.32);
        background: rgba(70, 120, 180, 0.16);
    }

    .overview-kpi-label {
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        opacity: 0.8;
        line-height: 1.4;
    }

    .overview-kpi-value {
        font-size: 30px;
        font-weight: 700;
        line-height: 1;
    }

    .overview-chart-box {
        position: relative;
        padding: 8px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.15);
        background: rgba(0,0,0,0.02);
        height: 220px;
        display: flex;
        flex-direction: column;
    }
    body.dark-mode .overview-chart-box {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .overview-chart-box canvas {
        width: 100% !important;
        flex: 1 1 auto;
    }

    .chart-help-btn {
        position: absolute;
        top: 8px;
        right: 8px;
        width: 22px;
        height: 22px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.24);
        background: rgba(0,0,0,0.05);
        color: inherit;
        font-size: 12px;
        font-weight: 700;
        line-height: 1;
        cursor: pointer;
        padding: 0;
        z-index: 3;
    }
    .chart-help-btn:hover {
        background: rgba(0,0,0,0.12);
    }
    body.dark-mode .chart-help-btn {
        border-color: rgba(255,255,255,0.28);
        background: rgba(255,255,255,0.08);
    }
    body.dark-mode .chart-help-btn:hover {
        background: rgba(255,255,255,0.16);
    }

    .chart-help-popover {
        position: absolute;
        top: 36px;
        right: 8px;
        width: min(340px, calc(100vw - 48px));
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.2);
        background: rgba(255,255,255,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.18);
        z-index: 4;
        font-size: 12px;
    }
    .chart-help-popover.hidden {
        display: none;
    }
    body.dark-mode .chart-help-popover {
        border-color: rgba(255,255,255,0.2);
        background: rgba(28,28,28,0.98);
        box-shadow: 0 10px 24px rgba(0,0,0,0.45);
    }
    .chart-help-title {
        font-weight: 700;
        margin-bottom: 6px;
        padding-right: 12px;
    }
    .chart-help-list {
        margin: 0;
        padding-left: 18px;
    }
    .chart-help-list li {
        margin: 3px 0;
    }


    .overview-charts.primary .overview-chart-box {
        height: 260px;
    }

    .overview-charts.full {
        grid-template-columns: 1fr;
    }

    .overview-charts.full .overview-chart-box {
        height: 260px;
    }

    .summary-card {
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.15);
        background: rgba(0,0,0,0.02);
        font-size: 12px;
    }
    body.dark-mode .summary-card {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .summary-title {
        font-weight: bold;
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        opacity: 0.8;
        font-size: 11px;
    }

    .summary-list {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .summary-item {
        display: flex;
        justify-content: space-between;
        gap: 10px;
    }

    .finding-count {
        margin-left: auto;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.18);
        background: rgba(0,0,0,0.04);
        font-size: 12px;
    }
    body.dark-mode .finding-count {
        border-color: rgba(255,255,255,0.2);
        background: rgba(255,255,255,0.05);
    }

    .finding-card {
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.15);
        background: rgba(0,0,0,0.02);
    }
    body.dark-mode .finding-card {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .finding-card.not-vulnerable {
        border-style: solid;
        border-left-width: 6px;
        border-left-color: rgba(80, 190, 120, 0.6);
        background: rgba(0,0,0,0.01);
        opacity: 0.9;
    }
    body.dark-mode .finding-card.not-vulnerable {
        border-left-color: rgba(110, 210, 140, 0.55);
        background: rgba(255,255,255,0.02);
    }

    .finding-card.not-vulnerable .sev-badge {
        filter: grayscale(1);
        opacity: 0.7;
    }

    .finding-card.not-vulnerable .finding-title {
        opacity: 0.85;
    }

    .finding-card.skipped {
        border-style: solid;
        border-left-width: 6px;
        border-left-color: rgba(130, 130, 130, 0.7);
        background: rgba(0,0,0,0.01);
        opacity: 0.9;
    }
    body.dark-mode .finding-card.skipped {
        border-left-color: rgba(170, 170, 170, 0.65);
        background: rgba(255,255,255,0.02);
    }

    .finding-card.skipped .sev-badge {
        filter: grayscale(1);
        opacity: 0.7;
    }

    .finding-card.skipped .finding-title {
        opacity: 0.85;
    }

    .finding-card.hash-target {
        --hash-target-rgb: 70, 140, 230;
        animation: hashTargetPulse 2s ease-out 1;
    }
    body.dark-mode .finding-card.hash-target {
        --hash-target-rgb: 120, 180, 255;
    }
    @keyframes hashTargetPulse {
        0% { box-shadow: 0 0 0 0 rgba(var(--hash-target-rgb), 0.58); }
        20% { box-shadow: 0 0 0 2px rgba(var(--hash-target-rgb), 0.5); }
        100% { box-shadow: 0 0 0 10px rgba(var(--hash-target-rgb), 0); }
    }

    .finding-toggle {
        width: 100%;
        text-align: left;
        background: transparent;
        border: 0;
        border-radius: 10px;
        box-shadow: none;
        cursor: pointer;
        padding: 12px 12px;
        display: flex;
        flex-direction: row;
        align-items: center;
        gap: 8px;
        font-size: 14px;
        transition: background-color 120ms ease;
    }

    body.dark-mode .finding-toggle,
    body.light-mode .finding-toggle {
        background: transparent;
        border: 0;
        box-shadow: none;
        border-radius: 10px;
    }

    body.dark-mode .finding-toggle:hover,
    body.light-mode .finding-toggle:hover {
        background: rgba(0, 0, 0, 0.04);
        border: 0;
        box-shadow: none;
    }
    body.dark-mode .finding-toggle:hover {
        background: rgba(255, 255, 255, 0.08);
    }

    .finding-card.expanded .finding-toggle {
        border-bottom-left-radius: 0;
        border-bottom-right-radius: 0;
    }

    .finding-toggle:focus {
        outline: none;
    }

    .finding-toggle:focus-visible {
        outline: 2px solid rgba(0,120,212,0.6);
        outline-offset: 2px;
        border: 0;
        box-shadow: none;
    }

    .finding-title {
        font-weight: 600;
        font-size: 1.03rem;
        line-height: 1.3;
        flex: 1;
    }

    .finding-header-left {
        display: flex;
        flex-direction: column;
        gap: 6px;
        flex: 1;
        min-width: 0;
    }

    .finding-header-meta {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        margin: 0;
        padding: 0;
    }

    .finding-header-meta > * {
        margin: 0;
    }

    .finding-header-right {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .caret {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 10px;
        font-size: 14px;
        line-height: 1;
        opacity: 0.85;
        user-select: none;
    }

    .finding-toggle .caret::before {
        content: "\25B8";
    }

    .finding-toggle[aria-expanded="true"] .caret::before {
        content: "\25BE";
    }

    .certainty-pill {
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.2);
        opacity: 0.9;
        white-space: nowrap;
    }
    body.dark-mode .certainty-pill { border-color: rgba(255,255,255,0.2); }
    .certainty-pill.conf-sure {
        background: rgba(120, 200, 140, 0.25);
        color: #0f4b25;
        border-color: rgba(15, 75, 37, 0.35);
    }
    .certainty-pill.conf-requires {
        background: rgba(245, 200, 90, 0.30);
        color: #6b4a00;
        border-color: rgba(107, 74, 0, 0.35);
    }
    .certainty-pill.conf-inconclusive {
        background: rgba(140, 155, 175, 0.22);
        color: #2d3b4a;
        border-color: rgba(45, 59, 74, 0.28);
    }
    body.dark-mode .certainty-pill.conf-sure {
        background: rgba(120, 200, 140, 0.22);
        color: #d7f1da;
        border-color: rgba(160, 220, 170, 0.35);
    }
    body.dark-mode .certainty-pill.conf-requires {
        background: rgba(245, 200, 90, 0.22);
        color: #fff0c2;
        border-color: rgba(255, 230, 160, 0.35);
    }
    body.dark-mode .certainty-pill.conf-inconclusive {
        background: rgba(135, 150, 170, 0.20);
        color: #d8e2ee;
        border-color: rgba(180, 195, 215, 0.30);
    }

    .sev-badge {
        font-size: 12px;
        padding: 3px 10px;
        border-radius: 999px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        white-space: nowrap;
    }

    .sev-0 { background: #d6e7ff; color: #103a68; }
    .sev-1 { background: #d7f1da; color: #0f4b25; }
    .sev-2 { background: #fff0c2; color: #6b4a00; }
    .sev-3 { background: #ffd7b3; color: #6b2f00; }
    .sev-4 { background: #ffb8b8; color: #6b0000; }

    body.dark-mode .sev-0 { background: #1d3a5c; color: #d6e7ff; }
    body.dark-mode .sev-1 { background: #164027; color: #d7f1da; }
    body.dark-mode .sev-2 { background: #4d3b12; color: #fff0c2; }
    body.dark-mode .sev-3 { background: #4b2a12; color: #ffd7b3; }
    body.dark-mode .sev-4 { background: #5a1a1a; color: #ffb8b8; }

    .finding-details {
        padding: 0 14px 14px 14px;
        display: none;
    }

    .finding-details-header {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        gap: 10px;
        padding: 10px 12px;
        margin: 8px 0 10px 0;
        border-radius: 8px;
        border: 1px solid rgba(0,0,0,0.12);
        background: rgba(0,0,0,0.02);
        font-size: 12px;
    }
    body.dark-mode .finding-details-header {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .finding-details-header-title {
        flex: 0 0 auto;
        font-weight: bold;
        letter-spacing: 0.4px;
        text-transform: uppercase;
        opacity: 0.7;
        padding-right: 12px;
        margin-right: 4px;
        border-right: 1px solid rgba(0,0,0,0.10);
    }
    body.dark-mode .finding-details-header-title {
        border-right-color: rgba(255,255,255,0.14);
    }

    .finding-details-header-actions {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        gap: 10px;
        flex-wrap: wrap;
    }

    .tag-group {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    .tag-group-title {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.4px;
        text-transform: uppercase;
        opacity: 0.7;
        white-space: nowrap;
    }

    .tag-group-options {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    .tag-group-separator {
        width: 1px;
        align-self: stretch;
        background: rgba(0,0,0,0.10);
    }
    body.dark-mode .tag-group-separator {
        background: rgba(255,255,255,0.14);
    }

    .finding-card.expanded .finding-details {
        display: block;
    }

    .finding-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(240px, 1fr));
        gap: 12px;
        margin-top: 8px;
        align-items: stretch;
    }

    @media (max-width: 900px) {
        .finding-grid {
            grid-template-columns: 1fr;
        }
    }

    .finding-block {
        padding: 10px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.14);
        background: rgba(0,0,0,0.02);
    }
    body.dark-mode .finding-block {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .finding-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        opacity: 0.7;
        margin-bottom: 8px;
        font-weight: bold;
        display: flex;
        align-items: center;
        gap: 8px;
        padding-bottom: 6px;
        border-bottom: 1px solid rgba(0,0,0,0.12);
    }
    body.dark-mode .finding-label {
        border-bottom-color: rgba(255,255,255,0.16);
    }

    .finding-body {
        font-size: 13px;
        line-height: 1.45;
        white-space: pre-wrap;
    }

    .finding-body ul,
    .finding-body ol {
        margin: 6px 0 0 18px;
        padding: 0;
    }

    .finding-body li {
        margin: 4px 0;
    }

    .finding-body a {
        text-decoration: underline;
        overflow-wrap: anywhere;
        word-break: break-word;
    }

    .finding-body code {
        padding: 1px 4px;
        border-radius: 4px;
        font-size: 12px;
    }

    .finding-affected {
        margin-top: 12px;
        padding: 10px;
        border-radius: 10px;
        border: 1px solid rgba(0,0,0,0.12);
        background: rgba(0,0,0,0.02);
    }
    body.dark-mode .finding-affected {
        border-color: rgba(255,255,255,0.18);
        background: rgba(255,255,255,0.03);
    }

    .affected-header {
        display: flex;
        align-items: center;
        gap: 10px;
        justify-content: space-between;
        margin-bottom: 8px;
    }

    .affected-title {
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        font-size: 12px;
        opacity: 0.75;
    }

    .affected-actions {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-wrap: wrap;
    }

    .affected-actions button {
        font-size: 12px;
        padding: 4px 8px;
    }
    .affected-page-size {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
    }

    .affected-page-size select {
        padding: 4px 6px;
        border-radius: 6px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 12px;
    }
    body.dark-mode .affected-page-size select {
        border-color: rgba(255,255,255,0.2);
        background: rgba(0,0,0,0.35);
        color: inherit;
    }

    .affected-search {
        padding: 4px 8px;
        border-radius: 6px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 12px;
        min-width: 180px;
    }
    body.dark-mode .affected-search {
        border-color: rgba(255,255,255,0.2);
        background: rgba(0,0,0,0.35);
        color: inherit;
    }

    .affected-export-menu {
        position: relative;
        display: inline-block;
    }

    .affected-export-panel {
        position: absolute;
        top: calc(100% + 6px);
        right: 0;
        min-width: 140px;
        padding: 6px;
        border-radius: 8px;
        border: 1px solid rgba(0,0,0,0.18);
        background: rgba(255,255,255,0.98);
        box-shadow: 0 8px 20px rgba(0,0,0,0.18);
        z-index: 5;
    }
    body.dark-mode .affected-export-panel {
        border-color: rgba(255,255,255,0.18);
        background: rgba(25,25,25,0.98);
        box-shadow: 0 8px 20px rgba(0,0,0,0.45);
    }

    .affected-export-panel.hidden {
        display: none;
    }

    .affected-export-panel button {
        width: 100%;
        text-align: left;
        padding: 6px 8px;
        border-radius: 6px;
        border: 0;
        background: transparent;
        cursor: pointer;
        font-size: 12px;
    }

    .affected-export-panel button:hover {
        background: rgba(0,0,0,0.06);
    }
    body.dark-mode .affected-export-panel button:hover {
        background: rgba(255,255,255,0.08);
    }

    .affected-link {
        margin-bottom: 10px;
        font-size: 13px;
    }

    .affected-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
    }

    .affected-table th,
    .affected-table td {
        padding: 6px 8px;
        border-bottom: 1px solid rgba(0,0,0,0.1);
        text-align: left;
        vertical-align: top;
    }
    body.dark-mode .affected-table th,
    body.dark-mode .affected-table td {
        border-bottom-color: rgba(255,255,255,0.12);
    }

    .affected-table th.sortable {
        cursor: pointer;
        user-select: none;
    }

    .affected-sort-indicator {
        margin-left: 6px;
        opacity: 0.6;
        font-size: 11px;
    }

    .affected-pager {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 8px;
        margin-top: 8px;
        font-size: 12px;
    }

    .affected-pager button {
        font-size: 12px;
        padding: 4px 8px;
    }
    .affected-pager .page-info {
        flex: 1 1 auto;
        text-align: center;
    }

    @media (min-width: 1400px) {
        .tenant-report-wrap {
            max-width: 1360px;
            margin: 0 auto;
        }
    }

    .finding-meta-line {
        font-size: 12px;
        opacity: 0.85;
        margin-top: 10px;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }

    .meta-pill {
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 11px;
        opacity: 0.95;
    }
    body.dark-mode .meta-pill { border-color: rgba(255,255,255,0.2); }

    .id-pill {
        font-family: Consolas, "Courier New", monospace;
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.2);
        opacity: 0.9;
    }
    body.dark-mode .id-pill { border-color: rgba(255,255,255,0.2); }

    .finding-status {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 10px;
        font-size: 12px;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 11px;
    }
    body.dark-mode .status-pill { border-color: rgba(255,255,255,0.2); }

    .status-chip {
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid rgba(0,0,0,0.2);
        opacity: 0.9;
    }
    body.dark-mode .status-chip { border-color: rgba(255,255,255,0.2); }

    .status-chip.fp { background: rgba(255, 208, 100, 0.35); }
    .status-chip.fx { background: rgba(190, 170, 255, 0.25); }
    .status-chip.rs { background: rgba(120, 200, 255, 0.25); }
    .status-chip.imp { background: rgba(255, 160, 120, 0.28); }
    .status-chip.cf { background: rgba(120, 230, 180, 0.28); }
    .status-chip.nr { background: rgba(150, 190, 255, 0.28); }
    .status-chip.ar { background: rgba(180, 205, 130, 0.30); }

    .status-toggle {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 2px 6px;
        border-radius: 6px;
        border: 1px solid rgba(0,0,0,0.2);
        font-size: 11px;
        opacity: 0.9;
    }
    body.dark-mode .status-toggle { border-color: rgba(255,255,255,0.2); }

    .status-toggle input {
        margin: 0;
    }

    @media (max-width: 720px) {
        .finding-details-header {
            flex-direction: column;
            align-items: flex-start;
        }

        .finding-details-header-title {
            padding-right: 0;
            margin-right: 0;
            border-right: 0;
        }

        .tag-group-separator {
            display: none;
        }
    }

    .affected-table {
        margin-top: 8px;
        font-size: 12px;
    }

    .finding-empty {
        margin: 18px 0;
        padding: 12px;
        border-radius: 8px;
        border: 1px dashed rgba(0,0,0,0.25);
        font-size: 13px;
    }
    body.dark-mode .finding-empty { border-color: rgba(255,255,255,0.25); }

    .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip: rect(0, 0, 0, 0);
        white-space: nowrap;
        border: 0;
    }
</style>
"@

    $chartJsEmbedded = ""
    if ($global:GLOBALJavaScript_Chart) {
        $chartJsEmbedded = "<script type='text/javascript'>`n$global:GLOBALJavaScript_Chart`n</script>"
    }

    $customScript = @'
<script>
    (function () {
        "use strict";

        function safeJsonParse(text) {
            try { return JSON.parse(text); } catch (e) { return []; }
        }

        function toText(value, fallback) {
            var v = value == null ? "" : String(value);
            v = v.trim();
            return v ? v : (fallback || "");
        }

        function normalizeSeverity(value) {
            var n = Number(value);
            if (Number.isNaN(n) || n < 0 || n > 4) return 0;
            return Math.floor(n);
        }

        function normalizeStatus(value) {
            var v = toText(value, "").toLowerCase();
            if (v === "vulnerable") return "Vulnerable";
            if (v === "skipped") return "Skipped";
            return "NotVulnerable";
        }

        function normalizeFinding(raw) {
            return {
                Title: toText(raw.Title, "Untitled finding"),
                Category: toText(raw.Category, "Uncategorized"),
                Severity: normalizeSeverity(raw.Severity),
                Description: toText(raw.Description, ""),
                Threat: toText(raw.Threat, ""),
                Status: normalizeStatus(raw.Status),
                Remediation: toText(raw.Remediation, ""),
                Confidence: toText(raw.Confidence || raw.Certainty, "Inconclusive"),
                AffectedObjects: Array.isArray(raw.AffectedObjects) ? raw.AffectedObjects : [],
                FindingId: toText(raw.FindingId, ""),
                RelatedReportUrl: toText(raw.RelatedReportUrl, ""),
                AffectedSortKey: toText(raw.AffectedSortKey, ""),
                AffectedSortDir: toText(raw.AffectedSortDir, "")
            };
        }

        function getFindingKey(finding) {
            if (finding.FindingId) return finding.FindingId;
            return (finding.Category + "::" + finding.Title).trim().toLowerCase();
        }

        function buildSummaryFingerprint(visibleItems) {
            if (!Array.isArray(visibleItems) || !visibleItems.length) return "";
            return visibleItems.map(function (finding) {
                var key = getFindingKey(finding);
                var state = getStateFor(finding);
                return [
                    key,
                    finding.Status,
                    finding.Severity,
                    finding.Confidence,
                    state.FalsePositive ? "1" : "0",
                    state.Fixing ? "1" : "0",
                    state.Resolved ? "1" : "0",
                    state.AcceptedRisk ? "1" : "0",
                    state.NeedsReview ? "1" : "0",
                    state.Confirmed ? "1" : "0",
                    state.Important ? "1" : "0"
                ].join("|");
            }).join(";");
        }

        function getReportId() {
            var root = document.getElementById("findingsRoot");
            if (root) {
                var attr = root.getAttribute("data-report-id");
                if (attr) return attr;
            }
            var path = (window.location.pathname || "").split("/").pop();
            if (path) return path;
            var title = document.title || "report";
            return title.replace(/\s+/g, " ").trim().toLowerCase();
        }

        function loadState(storageKey) {
            var raw = localStorage.getItem(storageKey);
            if (!raw) return {};
            return safeJsonParse(raw) || {};
        }

        function saveState(storageKey, state) {
            try { localStorage.setItem(storageKey, JSON.stringify(state)); } catch (e) {}
        }

        function debounce(fn, delay) {
            var timer = null;
            return function () {
                var args = arguments;
                clearTimeout(timer);
                timer = setTimeout(function () { fn.apply(null, args); }, delay);
            };
        }

        var filterCountElements = {};

        function buildFilters(data, filters, onChange) {
            var host = document.getElementById("findingFilters");
            if (!host) return;
            host.innerHTML = "";
            filterCountElements = {};

            function buildGroup(title, values, groupKey, formatter) {
                var group = document.createElement("div");
                group.className = "filter-group";

                var label = document.createElement("div");
                label.className = "filter-title";
                label.textContent = title;
                group.appendChild(label);

                var opts = document.createElement("div");
                opts.className = "filter-options";

                values.forEach(function (value) {
                    var itemLabel = document.createElement("label");
                    var input = document.createElement("input");
                    input.type = "checkbox";
                    input.value = value;
                    input.setAttribute("data-group", groupKey);
                    input.setAttribute("data-value", String(value));
                    input.addEventListener("change", function () {
                        // Keep at least one finding status selected to avoid ambiguous "show all" behavior.
                        if (groupKey === "findingStatus" && !input.checked) {
                            var selectedStatuses = filters[groupKey];
                            if (selectedStatuses && selectedStatuses.size <= 1 && selectedStatuses.has(value)) {
                                input.checked = true;
                                return;
                            }
                        }
                        if (input.checked) {
                            filters[groupKey].add(value);
                        } else {
                            filters[groupKey].delete(value);
                        }
                        onChange();
                    });

                    var displayText = formatter ? formatter(value) : value;
                    var countSpan = document.createElement("span");
                    countSpan.className = "filter-count";
                    countSpan.textContent = " (0)";
                    countSpan.setAttribute("data-group", groupKey);
                    countSpan.setAttribute("data-value", String(value));
                    filterCountElements[groupKey + "::" + value] = countSpan;

                    itemLabel.appendChild(input);
                    itemLabel.appendChild(document.createTextNode(displayText));
                    itemLabel.appendChild(countSpan);
                    opts.appendChild(itemLabel);
                });

                group.appendChild(opts);
                host.appendChild(group);
            }

            buildGroup("Category", data.categories, "category");
            buildGroup("Severity", data.severities, "severity", function (value) {
                return severityLabels[value];
            });
            buildGroup("Confidence", data.certainties, "confidence");
            buildGroup("Status", ["Vulnerable", "NotVulnerable", "Skipped"], "findingStatus", function (value) {
                if (value === "NotVulnerable") return "Not Vulnerable";
                return value;
            });
            buildGroup("Tags", ["HideFalsePositive", "HideFixing", "HideResolved", "HideAccepted", "ShowImportant", "ShowConfirmed", "ShowNeedsReview", "ShowTaggedOnly"], "status", function (value) {
                if (value === "HideFalsePositive") return "Hide false-positive";
                if (value === "HideFixing") return "Hide fixing";
                if (value === "HideResolved") return "Hide resolved";
                if (value === "HideAccepted") return "Hide accepted";
                if (value === "ShowConfirmed") return "Show confirmed only";
                if (value === "ShowNeedsReview") return "Show needs review only";
                if (value === "ShowTaggedOnly") return "Show tagged only";
                return "Show important only";
            });
        }

        function buildElement(tag, className, text) {
            var el = document.createElement(tag);
            if (className) el.className = className;
            if (text != null) el.textContent = text;
            return el;
        }

        function stripHtml(value) {
            var div = document.createElement("div");
            div.innerHTML = value || "";
            return (div.textContent || div.innerText || "").trim();
        }

        function htmlToPlainFormatted(value) {
            if (value == null) return "";
            var html = String(value);
            if (!html) return "";

            // Keep readability in exports: preserve paragraph/list structure as plain text.
            var normalized = html
                .replace(/\r\n?/g, "\n")
                .replace(/<\s*br\s*\/?>/gi, "\n")
                .replace(/<\s*\/p\s*>/gi, "\n\n")
                .replace(/<\s*p[^>]*>/gi, "")
                .replace(/<\s*li[^>]*>/gi, "- ")
                .replace(/<\s*\/li\s*>/gi, "\n")
                .replace(/<\s*\/(?:ul|ol)\s*>/gi, "\n")
                .replace(/<\s*(?:ul|ol)[^>]*>/gi, "")
                .replace(/<\s*\/div\s*>/gi, "\n")
                .replace(/<\s*div[^>]*>/gi, "");

            var div = document.createElement("div");
            div.innerHTML = normalized;
            var text = (div.textContent || div.innerText || "")
                .replace(/\u00A0/g, " ")
                .replace(/[ \t]+\n/g, "\n")
                .replace(/\n[ \t]+/g, "\n")
                .replace(/\n{3,}/g, "\n\n")
                .trim();

            return text;
        }

        function splitMultiValueField(key, value) {
            var text = toText(value, "").replace(/\r\n?/g, "\n").trim();
            if (!text) return [];

            var lineParts = text
                .split(/\n+/)
                .map(function (part) { return part.replace(/^\s*-\s*/, "").trim(); })
                .filter(function (part) { return !!part; });

            if (lineParts.length > 1) {
                return lineParts;
            }

            var keyHint = /owner|owners|member|members|role|roles|permission|permissions|group|groups|warning|warnings|api permissions/i.test(toText(key, ""));

            if (keyHint && text.indexOf(";") !== -1) {
                var semicolonParts = text.split(/\s*;\s*/).map(function (part) { return part.trim(); }).filter(function (part) { return !!part; });
                if (semicolonParts.length > 1) return semicolonParts;
            }

            if (keyHint && text.indexOf(",") !== -1 && text.indexOf(":") === -1) {
                var commaParts = text.split(/\s*,\s*/).map(function (part) { return part.trim(); }).filter(function (part) { return !!part; });
                if (commaParts.length > 1) return commaParts;
            }

            return [text];
        }

        function buildSearchGroups(query) {
            var input = toText(query, "");
            if (!input) return [];

            var groups = [];
            var current = { include: [], exclude: [] };
            var matcher = /(!?"[^"]+"|!?\S+)/g;
            var match;

            function pushCurrentIfNeeded() {
                if (current.include.length || current.exclude.length) {
                    groups.push(current);
                }
                current = { include: [], exclude: [] };
            }

            while ((match = matcher.exec(input)) !== null) {
                var rawToken = toText(match[0], "");
                if (!rawToken) continue;

                if (rawToken.charAt(0) !== "!" && (rawToken.toLowerCase() === "or" || rawToken === "|")) {
                    pushCurrentIfNeeded();
                    continue;
                }

                var isNegated = rawToken.charAt(0) === "!";
                var token = isNegated ? rawToken.slice(1) : rawToken;
                token = token.trim();
                if (!token) continue;

                if (token.length >= 2 && token.charAt(0) === "\"" && token.charAt(token.length - 1) === "\"") {
                    token = token.slice(1, -1);
                }

                token = toText(token, "").toLowerCase();
                if (!token) continue;

                var bucket = isNegated ? current.exclude : current.include;
                if (bucket.indexOf(token) === -1) {
                    bucket.push(token);
                }
            }

            pushCurrentIfNeeded();
            return groups;
        }

        function getFindingSearchFieldBlobs(finding) {
            if (finding._searchFieldBlobs) return finding._searchFieldBlobs;
            var fields = {
                id: toText(getFindingKey(finding), ""),
                title: toText(finding.Title, ""),
                description: stripHtml(toText(finding.Description, "")),
                threat: stripHtml(toText(finding.Threat, "")),
                remediation: stripHtml(toText(finding.Remediation, "")),
                affected: ""
            };

            var affectedChunks = [];
            var affected = Array.isArray(finding.AffectedObjects) ? finding.AffectedObjects : [];
            affected.forEach(function (obj) {
                if (!obj || typeof obj !== "object") return;
                Object.keys(obj).forEach(function (key) {
                    var text = stripHtml(toText(obj[key], ""));
                    if (text) affectedChunks.push(text);
                });
            });
            fields.affected = affectedChunks.join(" ");

            Object.keys(fields).forEach(function (key) {
                fields[key] = toText(fields[key], "").toLowerCase();
            });

            finding._searchFieldBlobs = fields;
            return fields;
        }

        function matchesSearchQuery(finding) {
            if (!searchGroups.length) return true;
            var fieldBlobs = getFindingSearchFieldBlobs(finding);

            function termExistsInSelectedFields(term) {
                if (!selectedSearchFields || !selectedSearchFields.size) {
                    return Object.keys(fieldBlobs).some(function (key) {
                        return fieldBlobs[key].indexOf(term) !== -1;
                    });
                }
                var found = false;
                selectedSearchFields.forEach(function (fieldKey) {
                    if (!found && (fieldBlobs[fieldKey] || "").indexOf(term) !== -1) found = true;
                });
                if (found) return true;
                return false;
            }

            for (var g = 0; g < searchGroups.length; g++) {
                var group = searchGroups[g];
                var includeOk = true;
                for (var i = 0; i < group.include.length; i++) {
                    if (!termExistsInSelectedFields(group.include[i])) {
                        includeOk = false;
                        break;
                    }
                }
                if (!includeOk) continue;

                var excludeOk = true;
                for (var j = 0; j < group.exclude.length; j++) {
                    if (termExistsInSelectedFields(group.exclude[j])) {
                        excludeOk = false;
                        break;
                    }
                }
                if (excludeOk) return true;
            }

            return false;
        }

        function confidenceOrder(value) {
            switch (String(value || "").toLowerCase()) {
                case "sure": return 1;
                case "requires verification": return 2;
                case "unconclusive": return 3;
                default: return 4;
            }
        }

        function getCoverageColor(percent, alpha) {
            var p = Number(percent);
            if (!isFinite(p)) p = 0;
            p = Math.max(0, Math.min(100, p));
            var hue = Math.round((p / 100) * 120); // 0=red, 120=green
            var a = (alpha == null) ? 1 : alpha;
            return "hsla(" + hue + ", 70%, 44%, " + a + ")";
        }

        function sortFindings(items, key) {
            return items.slice().sort(function (a, b) {
                var result = 0;
                if (key === "severity") {
                    result = b.Severity - a.Severity;
                } else if (key === "title") {
                    result = a.Title.localeCompare(b.Title);
                } else if (key === "confidence") {
                    result = confidenceOrder(a.Confidence) - confidenceOrder(b.Confidence);
                } else {
                    if (b.Severity !== a.Severity) return b.Severity - a.Severity;
                    result = a.Title.localeCompare(b.Title);
                }

                if (result === 0) {
                    result = a.Title.localeCompare(b.Title);
                }

                return result;
            });
        }

        function isStatusVulnerable(finding) {
            return !!finding && finding.Status === "Vulnerable";
        }

        function isStatusSkipped(finding) {
            return !!finding && finding.Status === "Skipped";
        }

        function isStatusCovered(finding) {
            return !!finding && finding.Status !== "Skipped";
        }

        function hasAnyTagState(state) {
            if (!state) return false;
            return !!(state.FalsePositive || state.Fixing || state.Resolved || state.Important || state.Confirmed || state.NeedsReview || state.AcceptedRisk);
        }

        function getFindingStatusFilterValue(finding) {
            return normalizeStatus(finding && finding.Status);
        }

        function matchesFiltersBase(finding, skipGroup) {
            if (!matchesSearchQuery(finding)) return false;

            if (skipGroup !== "findingStatus" && filterState.findingStatus.size && !filterState.findingStatus.has(getFindingStatusFilterValue(finding))) return false;
            if (skipGroup !== "category" && filterState.category.size && !filterState.category.has(finding.Category)) return false;
            if (skipGroup !== "severity" && filterState.severity.size && !filterState.severity.has(finding.Severity)) return false;
            if (skipGroup !== "confidence" && filterState.confidence.size && !filterState.confidence.has(finding.Confidence)) return false;

            if (skipGroup !== "status") {
                var state = getStateFor(finding);
                if (filterState.status.has("HideFalsePositive") && state.FalsePositive) return false;
                if (filterState.status.has("HideFixing") && state.Fixing) return false;
                if (filterState.status.has("HideResolved") && state.Resolved) return false;
                if (filterState.status.has("HideAccepted") && state.AcceptedRisk) return false;
                if (filterState.status.has("ShowImportant") && !state.Important) return false;
                if (filterState.status.has("ShowConfirmed") && !state.Confirmed) return false;
                if (filterState.status.has("ShowNeedsReview") && !state.NeedsReview) return false;
                if (filterState.status.has("ShowTaggedOnly") && !hasAnyTagState(state)) return false;
            }

            return true;
        }

        function matchesFiltersNoVulnGate(finding, skipGroup) {
            if (!matchesSearchQuery(finding)) return false;

            if (skipGroup !== "findingStatus" && filterState.findingStatus.size && !filterState.findingStatus.has(getFindingStatusFilterValue(finding))) return false;
            if (skipGroup !== "category" && filterState.category.size && !filterState.category.has(finding.Category)) return false;
            if (skipGroup !== "severity" && filterState.severity.size && !filterState.severity.has(finding.Severity)) return false;
            if (skipGroup !== "confidence" && filterState.confidence.size && !filterState.confidence.has(finding.Confidence)) return false;

            if (skipGroup !== "status") {
                var state = getStateFor(finding);
                if (filterState.status.has("HideFalsePositive") && state.FalsePositive) return false;
                if (filterState.status.has("HideFixing") && state.Fixing) return false;
                if (filterState.status.has("HideResolved") && state.Resolved) return false;
                if (filterState.status.has("HideAccepted") && state.AcceptedRisk) return false;
                if (filterState.status.has("ShowImportant") && !state.Important) return false;
                if (filterState.status.has("ShowConfirmed") && !state.Confirmed) return false;
                if (filterState.status.has("ShowNeedsReview") && !state.NeedsReview) return false;
                if (filterState.status.has("ShowTaggedOnly") && !hasAnyTagState(state)) return false;
            }

            return true;
        }

        function updateFilterCounts() {
            var counts = {
                category: {},
                severity: {},
                confidence: {},
                findingStatus: { Vulnerable: 0, NotVulnerable: 0, Skipped: 0 },
                status: { HideFalsePositive: 0, HideFixing: 0, HideResolved: 0, HideAccepted: 0, ShowImportant: 0, ShowConfirmed: 0, ShowNeedsReview: 0, ShowTaggedOnly: 0 }
            };

            findings.forEach(function (finding) {
                if (matchesFiltersBase(finding, "findingStatus")) {
                    var findingStatusValue = getFindingStatusFilterValue(finding);
                    counts.findingStatus[findingStatusValue] = (counts.findingStatus[findingStatusValue] || 0) + 1;
                }
                if (matchesFiltersBase(finding, "category")) {
                    counts.category[finding.Category] = (counts.category[finding.Category] || 0) + 1;
                }
                if (matchesFiltersBase(finding, "severity")) {
                    counts.severity[finding.Severity] = (counts.severity[finding.Severity] || 0) + 1;
                }
                if (matchesFiltersBase(finding, "confidence")) {
                    counts.confidence[finding.Confidence] = (counts.confidence[finding.Confidence] || 0) + 1;
                }
                if (matchesFiltersBase(finding, "status")) {
                    var state = getStateFor(finding);
                    if (state.FalsePositive) counts.status.HideFalsePositive += 1;
                    if (state.Fixing) counts.status.HideFixing += 1;
                    if (state.Resolved) counts.status.HideResolved += 1;
                    if (state.AcceptedRisk) counts.status.HideAccepted += 1;
                    if (state.Important) counts.status.ShowImportant += 1;
                    if (state.Confirmed) counts.status.ShowConfirmed += 1;
                    if (state.NeedsReview) counts.status.ShowNeedsReview += 1;
                    if (hasAnyTagState(state)) counts.status.ShowTaggedOnly += 1;
                }
            });

            Object.keys(filterCountElements).forEach(function (key) {
                var parts = key.split("::");
                var groupKey = parts[0];
                var value = parts.slice(1).join("::");
                var count = 0;
                if (groupKey === "category") {
                    count = counts.category[value] || 0;
                } else if (groupKey === "severity") {
                    count = counts.severity[Number(value)] || 0;
                } else if (groupKey === "confidence") {
                    count = counts.confidence[value] || 0;
                } else if (groupKey === "findingStatus") {
                    count = counts.findingStatus[value] || 0;
                } else if (groupKey === "status") {
                    count = counts.status[value] || 0;
                }
                filterCountElements[key].textContent = " (" + count + ")";
                var filterHost = document.getElementById("findingFilters");
                if (filterHost) {
                    var input = filterHost.querySelector("input[data-group=\"" + groupKey + "\"][data-value=\"" + value + "\"]");
                    if (input) {
                        var shouldDisable = (count === 0 && !input.checked);
                        if (groupKey === "findingStatus") {
                            var selectedStatusCount = (filterState.findingStatus && filterState.findingStatus.size) ? filterState.findingStatus.size : 0;
                            if (input.checked && selectedStatusCount === 1) {
                                shouldDisable = true;
                            }
                        }
                        input.disabled = shouldDisable;
                        if (input.parentElement) {
                            input.parentElement.classList.toggle("disabled", shouldDisable);
                        }
                    }
                }
            });
        }

        function downloadBlob(filename, content, type) {
            var payload = content;
            var mimeType = type || "application/octet-stream";
            if (mimeType.toLowerCase() === "text/csv") {
                payload = "\uFEFF" + String(content == null ? "" : content);
                mimeType += ";charset=utf-8";
            }
            var blob = new Blob([payload], { type: mimeType });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function sanitizeFilePart(value, fallback) {
            var text = toText(value, fallback || "tenant");
            text = text
                .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
                .replace(/\s+/g, "_")
                .replace(/_+/g, "_")
                .replace(/^_+|_+$/g, "");
            return text || (fallback || "tenant");
        }

        function getCurrentTimestampToken() {
            var now = new Date();
            function pad2(value) { return String(value).padStart(2, "0"); }
            var yyyy = now.getFullYear();
            var mm = pad2(now.getMonth() + 1);
            var dd = pad2(now.getDate());
            var hh = pad2(now.getHours());
            var mi = pad2(now.getMinutes());
            return String(yyyy) + mm + dd + "_" + hh + mi;
        }

        function getFindingsExportContext() {
            var root = document.getElementById("findingsRoot");
            var reportId = toText(getReportId(), "");
            var timestamp = "";
            var tenantLabel = "";

            if (root) {
                timestamp = toText(root.getAttribute("data-start-timestamp"), "");
                tenantLabel = toText(root.getAttribute("data-tenant-name"), "");
            }

            try {
                reportId = decodeURIComponent(reportId);
            } catch (e) {}

            if (!timestamp || !tenantLabel) {
                var match = reportId.match(/^SecurityFindings_(\d{8}_\d{4})_(.+?)(?:\.html)?$/i);
                if (match) {
                    if (!timestamp) timestamp = match[1];
                    if (!tenantLabel) tenantLabel = match[2];
                } else {
                    var fallbackMatch = reportId.match(/(\d{8}_\d{4})/);
                    if (!timestamp && fallbackMatch) {
                        timestamp = fallbackMatch[1];
                    }
                }
            }

            if (!tenantLabel && reportId) {
                var fallbackTenant = reportId
                    .replace(/^SecurityFindings_/i, "")
                    .replace(/^\d{8}_\d{4}_?/, "")
                    .replace(/\.html?$/i, "")
                    .trim();
                if (fallbackTenant) tenantLabel = fallbackTenant;
            }

            if (!timestamp) timestamp = getCurrentTimestampToken();
            if (!tenantLabel) tenantLabel = "tenant";

            return {
                timestamp: sanitizeFilePart(timestamp, "timestamp"),
                tenantLabel: sanitizeFilePart(tenantLabel, "tenant")
            };
        }

        function buildFindingsExportFilename(scope, extension) {
            var context = getFindingsExportContext();
            return "tenant_findings_" + scope + "_" + context.timestamp + "_" + context.tenantLabel + "." + extension;
        }

        function getAffectedFindingIdForFilename(finding) {
            var directId = toText(finding && finding.FindingId, "");
            if (directId) return sanitizeFilePart(directId, "finding");
            return sanitizeFilePart(getFindingKey(finding), "finding");
        }

        function buildAffectedExportFilename(finding, extension, useMultilineSuffix) {
            var context = getFindingsExportContext();
            var findingId = getAffectedFindingIdForFilename(finding);
            var multilineSuffix = useMultilineSuffix ? "_multiline" : "";
            return "tenant_findings_affected_" + context.timestamp + "_" + context.tenantLabel + "_" + findingId + multilineSuffix + "." + extension;
        }

        function exportCsv(items, scope) {
            function formatAffectedObjectsFirstColumn(finding) {
                var objects = Array.isArray(finding && finding.AffectedObjects) ? finding.AffectedObjects : [];
                if (!objects.length) return "";

                var values = [];
                objects.forEach(function (obj) {
                    if (!obj || typeof obj !== "object") return;
                    var keys = Object.keys(obj).filter(function (key) {
                        return key && key.charAt(0) !== "_";
                    });
                    if (!keys.length) return;

                    var firstKey = keys[0];
                    var raw = obj[firstKey];
                    var text = "";
                    if (raw == null) {
                        text = "";
                    } else if (typeof raw === "string") {
                        // Strip links/HTML and keep visible text only.
                        text = htmlToPlainFormatted(raw);
                    } else if (Array.isArray(raw)) {
                        text = raw.map(function (entry) {
                            return typeof entry === "string" ? htmlToPlainFormatted(entry) : String(entry);
                        }).join(", ");
                    } else {
                        text = String(raw);
                    }

                    text = text.replace(/\s*\n+\s*/g, " / ").trim();
                    if (text) values.push(text);
                });

                return values.join(", ");
            }

            var headers = [
                "FindingId",
                "Title",
                "Category",
                "Severity",
                "Confidence",
                "Status",
                "Description",
                "Threat",
                "Remediation",
                "AffectedObjects"
            ];

            var lines = [headers.join(",")];
            items.forEach(function (item) {
                var row = [
                    getFindingKey(item),
                    item.Title,
                    item.Category,
                    item.Severity,
                    item.Confidence,
                    item.Status,
                    stripHtml(item.Description),
                    stripHtml(item.Threat),
                    stripHtml(item.Remediation),
                    formatAffectedObjectsFirstColumn(item)
                ].map(function (cell) {
                    var v = String(cell == null ? "" : cell).replace(/\"/g, "\"\"");
                    return "\"" + v + "\"";
                });
                lines.push(row.join(","));
            });

            downloadBlob(buildFindingsExportFilename(scope, "csv"), lines.join("\n"), "text/csv");
        }

        function exportJson(items, scope) {
            function sanitizeAffectedObject(obj) {
                if (!obj || typeof obj !== "object") return obj;
                var clean = {};
                Object.keys(obj).forEach(function (key) {
                    if (key && key.charAt(0) === "_") return; // drop hidden sort helpers
                    var val = obj[key];
                    if (key === "Warnings") {
                        if (val == null) {
                            clean[key] = "";
                        } else if (typeof val === "string") {
                            clean[key] = htmlToPlainFormatted(val);
                        } else if (Array.isArray(val)) {
                            var warningParts = [];
                            val.forEach(function (entry) {
                                if (entry == null) return;
                                if (typeof entry === "string") {
                                    warningParts.push(htmlToPlainFormatted(entry));
                                    return;
                                }
                                if (typeof entry === "object") {
                                    warningParts.push(JSON.stringify(sanitizeAffectedObject(entry)));
                                    return;
                                }
                                warningParts.push(String(entry));
                            });
                            clean[key] = warningParts.join(" / ");
                        } else if (typeof val === "object") {
                            clean[key] = JSON.stringify(sanitizeAffectedObject(val));
                        } else {
                            clean[key] = String(val);
                        }
                        return;
                    }
                    if (val == null) {
                        clean[key] = "";
                    } else if (typeof val === "string") {
                        var text = htmlToPlainFormatted(val);
                        var split = splitMultiValueField(key, text);
                        clean[key] = split.length > 1 ? split : (split[0] || "");
                    } else if (Array.isArray(val)) {
                        var objectEntries = val.filter(function (entry) {
                            return entry && typeof entry === "object" && !Array.isArray(entry);
                        });
                        if (objectEntries.length === val.length) {
                            clean[key] = objectEntries.map(sanitizeAffectedObject);
                        } else {
                            var scalarEntries = [];
                            val.forEach(function (entry) {
                                if (entry == null) return;
                                if (typeof entry === "string") {
                                    var parts = splitMultiValueField(key, htmlToPlainFormatted(entry));
                                    Array.prototype.push.apply(scalarEntries, parts);
                                    return;
                                }
                                if (typeof entry === "object") {
                                    scalarEntries.push(JSON.stringify(sanitizeAffectedObject(entry)));
                                    return;
                                }
                                scalarEntries.push(String(entry));
                            });
                            clean[key] = scalarEntries.length > 1 ? scalarEntries : (scalarEntries[0] || "");
                        }
                    } else if (typeof val === "object") {
                        clean[key] = sanitizeAffectedObject(val);
                    } else {
                        clean[key] = val;
                    }
                });
                return clean;
            }

            var plain = (items || []).map(function (item) {
                var clean = {};
                var orderedKeys = [];

                if (Object.prototype.hasOwnProperty.call(item || {}, "FindingId")) {
                    orderedKeys.push("FindingId");
                }

                Object.keys(item || {}).forEach(function (key) {
                    if (key === "FindingId") return;
                    orderedKeys.push(key);
                });

                orderedKeys.forEach(function (key) {
                    if (key && key.charAt(0) === "_") return; // drop runtime cache fields
                    if (key === "Description" || key === "Threat" || key === "Remediation") {
                        clean[key] = htmlToPlainFormatted(item[key]);
                        return;
                    }
                    if (key === "AffectedObjects") {
                        var objects = Array.isArray(item.AffectedObjects) ? item.AffectedObjects : [];

                        // Resolve sort key from AffectedSortKey, mirroring the HTML panel logic.
                        var allCols = [];
                        var seenCols = {};
                        objects.forEach(function (obj) {
                            if (!obj) return;
                            Object.keys(obj).forEach(function (k) {
                                if (!k || seenCols[k]) return;
                                seenCols[k] = true;
                                allCols.push(k);
                            });
                        });
                        var visCols = allCols.filter(function (k) { return k.charAt(0) !== "_"; });
                        var affSortKey = "";
                        if (item.AffectedSortKey) {
                            var desired = String(item.AffectedSortKey).toLowerCase();
                            affSortKey = allCols.find(function (k) { return String(k).toLowerCase() === desired; }) || "";
                            if (!affSortKey) {
                                affSortKey = allCols.find(function (k) { return String(k).toLowerCase().indexOf(desired) !== -1; }) || "";
                            }
                        }
                        if (!affSortKey) affSortKey = visCols[0] || "";

                        // Resolve sort direction.
                        var affSortDir = 1;
                        if (typeof item.AffectedSortDir === "string") {
                            if (item.AffectedSortDir.toLowerCase() === "desc") affSortDir = -1;
                        } else if (item.AffectedSortDir === -1) {
                            affSortDir = -1;
                        }

                        // Sort a copy using the same comparator as getSortedObjects().
                        var sorted = objects.slice().sort(function (a, b) {
                            var avRaw = toText(a[affSortKey], "");
                            var bvRaw = toText(b[affSortKey], "");
                            var av = stripHtml(avRaw).trim();
                            var bv = stripHtml(bvRaw).trim();
                            var aMissing = av === "" || av === "?";
                            var bMissing = bv === "" || bv === "?";
                            if (aMissing && !bMissing) return 1;
                            if (!aMissing && bMissing) return -1;
                            var aNum = /^-?\d+(\.\d+)?$/.test(av) ? Number(av) : null;
                            var bNum = /^-?\d+(\.\d+)?$/.test(bv) ? Number(bv) : null;
                            if (aNum !== null && bNum !== null) {
                                if (aNum < bNum) return -1 * affSortDir;
                                if (aNum > bNum) return 1 * affSortDir;
                                return 0;
                            }
                            av = av.toLowerCase();
                            bv = bv.toLowerCase();
                            if (av < bv) return -1 * affSortDir;
                            if (av > bv) return 1 * affSortDir;
                            return 0;
                        });

                        clean.AffectedObjects = sorted.map(sanitizeAffectedObject);
                        return;
                    }
                    clean[key] = item[key];
                });

                var tags = [];
                var itemState = getStateFor(item);
                if (itemState.Important) tags.push("Important");
                if (itemState.NeedsReview) tags.push("NeedsReview");
                if (itemState.AcceptedRisk) tags.push("AcceptedRisk");
                if (itemState.FalsePositive) tags.push("FalsePositive");
                if (itemState.Fixing) tags.push("Fixing");
                if (itemState.Resolved) tags.push("Resolved");
                if (itemState.Confirmed) tags.push("Confirmed");
                clean.Tags = tags;

                return clean;
            });

            downloadBlob(buildFindingsExportFilename(scope, "json"), JSON.stringify(plain, null, 2), "application/json");
        }

        function snapshotFilterState() {
            return {
                category: Array.from(filterState.category || []),
                severity: Array.from(filterState.severity || []),
                confidence: Array.from(filterState.confidence || []),
                findingStatus: Array.from(filterState.findingStatus || []),
                status: Array.from(filterState.status || [])
            };
        }

        function restoreFilterState(snapshot) {
            function copyArrayToSet(targetSet, values) {
                targetSet.clear();
                (values || []).forEach(function (value) {
                    targetSet.add(value);
                });
            }

            copyArrayToSet(filterState.category, snapshot && snapshot.category);
            copyArrayToSet(filterState.severity, snapshot && snapshot.severity);
            copyArrayToSet(filterState.confidence, snapshot && snapshot.confidence);
            copyArrayToSet(filterState.findingStatus, snapshot && snapshot.findingStatus);
            copyArrayToSet(filterState.status, snapshot && snapshot.status);
        }

        function syncFilterInputsFromState() {
            var filterInputs = document.querySelectorAll("#findingFilters input[type='checkbox']");
            Array.prototype.forEach.call(filterInputs, function (input) {
                var group = input.getAttribute("data-group");
                var rawValue = input.getAttribute("data-value");
                if (!group || !Object.prototype.hasOwnProperty.call(filterState, group)) return;

                var value = rawValue;
                if (group === "severity") {
                    value = Number(rawValue);
                }

                input.checked = filterState[group].has(value);
            });
        }

        function syncSearchFieldsInputsFromState() {
            Array.prototype.forEach.call(searchFieldInputs || [], function (input) {
                var key = input.getAttribute("data-search-field");
                input.checked = selectedSearchFields.has(key);
            });
            updateSearchFieldsButtonLabel();
        }

        function captureInteractiveSnapshot() {
            var overviewPanel = document.getElementById("overviewPanel");
            return {
                filterState: snapshotFilterState(),
                searchQuery: searchQuery,
                selectedSearchFields: Array.from(selectedSearchFields || []),
                expandedKeys: getExpandedKeys(),
                forcedVisibleFindingKey: forcedVisibleFindingKey,
                toggleAllLabel: toggleAllBtn ? toggleAllBtn.textContent : "",
                overviewPanelOpen: overviewPanel ? !!overviewPanel.open : null
            };
        }

        function restoreInteractiveSnapshot(snapshot) {
            if (!snapshot) return;

            restoreFilterState(snapshot.filterState);
            searchQuery = toText(snapshot.searchQuery, "");
            searchGroups = buildSearchGroups(searchQuery);
            selectedSearchFields = new Set(snapshot.selectedSearchFields || searchFieldDefinitions.map(function (field) { return field.key; }));

            if (searchInput) {
                searchInput.value = searchQuery;
            }
            syncSearchFieldsInputsFromState();
            syncFilterInputsFromState();

            forcedVisibleFindingKey = snapshot.forcedVisibleFindingKey || null;
            applyFilters(snapshot.expandedKeys || new Set());

            if (toggleAllBtn && snapshot.toggleAllLabel) {
                toggleAllBtn.textContent = snapshot.toggleAllLabel;
            }

            var overviewPanel = document.getElementById("overviewPanel");
            if (overviewPanel && snapshot.overviewPanelOpen !== null) {
                overviewPanel.open = !!snapshot.overviewPanelOpen;
            }
        }

        function expandVisibleCardsForPrint() {
            var root = document.getElementById("findingsRoot");
            if (!root) return;

            var cards = root.querySelectorAll(".finding-card");
            Array.prototype.forEach.call(cards, function (card) {
                if (card._ensureAffectedPanelBuilt) {
                    card._ensureAffectedPanelBuilt();
                }
                card.classList.add("expanded");
                var toggle = card.querySelector(".finding-toggle");
                if (toggle) toggle.setAttribute("aria-expanded", "true");
            });
        }

        function prepareAffectedObjectsForPrint() {
            var root = document.getElementById("findingsRoot");
            if (!root) {
                return function () {};
            }

            var restoreItems = [];
            var panels = root.querySelectorAll(".finding-affected");
            Array.prototype.forEach.call(panels, function (panel) {
                if (!panel || typeof panel._setRowsAllForPrint !== "function" || typeof panel._restoreRowsAfterPrint !== "function") {
                    return;
                }
                var state = panel._setRowsAllForPrint();
                restoreItems.push({ panel: panel, state: state });
            });

            return function () {
                restoreItems.forEach(function (item) {
                    try {
                        item.panel._restoreRowsAfterPrint(item.state);
                    } catch (e) {}
                });
            };
        }

        function ensureOverviewChartsReadyForSnapshot() {
            var overviewPanel = document.getElementById("overviewPanel");
            var previousOpen = null;
            if (overviewPanel) {
                previousOpen = !!overviewPanel.open;
                if (!overviewPanel.open) {
                    overviewPanel.open = true;
                }
            }

            forcePrintLightCharts = true;
            var last = overviewCharts.last;
            if (last) {
                renderOverviewCharts(
                    last.scorePct,
                    last.coveredPoints,
                    last.riskPoints,
                    last.totalPossible,
                    last.categoryPossible,
                    last.categoryRisk,
                    last.severityCounts,
                    last.statusCounts,
                    last.certaintyCounts,
                    last.categorySeverityCounts
                );
            }

            [
                overviewCharts.score,
                overviewCharts.categoryCoverage,
                overviewCharts.points,
                overviewCharts.severity,
                overviewCharts.status,
                overviewCharts.certainty || overviewCharts.confidence
            ].forEach(function (chart) {
                if (!chart) return;
                try {
                    if (typeof chart.resize === "function") chart.resize();
                    if (typeof chart.stop === "function") chart.stop();
                    if (typeof chart.update === "function") chart.update("none");
                    if (typeof chart.render === "function") chart.render();
                } catch (e) {}
            });

            return function () {
                forcePrintLightCharts = false;
                if (overviewPanel && previousOpen !== null) {
                    overviewPanel.open = previousOpen;
                }
                var last = overviewCharts.last;
                if (last) {
                    renderOverviewCharts(
                        last.scorePct,
                        last.coveredPoints,
                        last.riskPoints,
                        last.totalPossible,
                        last.categoryPossible,
                        last.categoryRisk,
                        last.severityCounts,
                        last.statusCounts,
                        last.certaintyCounts,
                        last.categorySeverityCounts
                    );
                }
            };
        }

        function captureOverviewChartImages() {
            var defs = [
                { id: "scoreChart", chartKey: "score", title: "Weighted Coverage Score" },
                { id: "categoryCoverageChart", chartKey: "categoryCoverage", title: "Coverage by Category" },
                { id: "pointsChart", chartKey: "points", title: "Covered vs Vulnerable Points" },
                { id: "severityChart", chartKey: "severity", title: "Severity Distribution" },
                { id: "statusChart", chartKey: "status", title: "Tag Distribution" },
                { id: "certaintyChart", chartKey: "certainty", title: "Confidence Distribution" }
            ];
            var images = [];

            defs.forEach(function (def) {
                var dataUrl = "";
                var chart = overviewCharts[def.chartKey];
                if (!chart && def.chartKey === "certainty") {
                    chart = overviewCharts.confidence;
                }
                if (chart && typeof chart.toBase64Image === "function") {
                    try {
                        dataUrl = chart.toBase64Image();
                    } catch (e) {
                        dataUrl = "";
                    }
                }

                var canvas = document.getElementById(def.id);
                if ((!dataUrl || dataUrl.length < 150) && canvas && typeof canvas.toDataURL === "function") {
                    try {
                        dataUrl = canvas.toDataURL("image/png");
                    } catch (e) {
                        dataUrl = "";
                    }
                }

                if (!dataUrl || dataUrl.length < 150) return;
                images.push({
                    title: def.title,
                    dataUrl: dataUrl
                });
            });

            return images;
        }

        function escapeHtml(value) {
            return String(value == null ? "" : value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function stripLinksFromAffectedObjects(rootNode) {
            if (!rootNode || typeof rootNode.querySelectorAll !== "function") return;
            var links = rootNode.querySelectorAll(".finding-affected a");
            Array.prototype.forEach.call(links, function (link) {
                var text = document.createTextNode(link.textContent || "");
                if (link.parentNode) {
                    link.parentNode.replaceChild(text, link);
                }
            });
        }

        function populatePrintTagSummaries(rootNode) {
            if (!rootNode || typeof rootNode.querySelectorAll !== "function") return;
            var cards = rootNode.querySelectorAll(".finding-card");
            Array.prototype.forEach.call(cards, function (card) {
                var detailsHeader = card.querySelector(".finding-details-header");
                if (!detailsHeader) return;

                var oldInline = detailsHeader.querySelector(".print-tags-inline");
                if (oldInline && oldInline.parentNode) {
                    oldInline.parentNode.removeChild(oldInline);
                }

                var sourceChips = card.querySelectorAll(".finding-header-meta .status-chip");
                var inline = document.createElement("div");
                inline.className = "print-tags-inline";

                Array.prototype.forEach.call(sourceChips, function (chip) {
                    var tag = document.createElement("span");
                    tag.className = "print-tag-chip";
                    if (chip.classList.contains("imp")) tag.classList.add("imp");
                    if (chip.classList.contains("fp")) tag.classList.add("fp");
                    if (chip.classList.contains("fx")) tag.classList.add("fx");
                    if (chip.classList.contains("rs")) tag.classList.add("rs");
                    if (chip.classList.contains("cf")) tag.classList.add("cf");
                    tag.textContent = chip.textContent || "";
                    inline.appendChild(tag);
                });

                detailsHeader.appendChild(inline);
            });
        }

        function populatePrintFindingStatus(rootNode) {
            if (!rootNode || typeof rootNode.querySelectorAll !== "function") return;
            var cards = rootNode.querySelectorAll(".finding-card");
            Array.prototype.forEach.call(cards, function (card) {
                var metaLine = card.querySelector(".finding-header-left .finding-header-meta");
                if (!metaLine) return;

                var confidenceText = "";
                var certainty = metaLine.querySelector(".certainty-pill");
                if (certainty) {
                    confidenceText = toText(certainty.textContent, "");
                }

                var existingCertainty = metaLine.querySelectorAll(".certainty-pill");
                Array.prototype.forEach.call(existingCertainty, function (el) {
                    if (el.parentNode) el.parentNode.removeChild(el);
                });

                var existingStatusChips = metaLine.querySelectorAll(".status-chip");
                Array.prototype.forEach.call(existingStatusChips, function (el) {
                    if (el.parentNode) el.parentNode.removeChild(el);
                });

                var nestedMeta = metaLine.querySelectorAll(".finding-header-meta");
                Array.prototype.forEach.call(nestedMeta, function (wrap) {
                    if (!wrap.textContent || !wrap.textContent.trim()) {
                        if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
                    }
                });

                var oldStatus = metaLine.querySelector(".print-finding-status");
                if (oldStatus && oldStatus.parentNode) oldStatus.parentNode.removeChild(oldStatus);

                var status = "Vulnerable";
                var cssClass = "vul";
                if (card.classList.contains("not-vulnerable")) {
                    status = "Not Vulnerable";
                    cssClass = "nv";
                } else if (card.classList.contains("skipped")) {
                    status = "Skipped";
                    cssClass = "sk";
                }

                var pill = document.createElement("span");
                pill.className = "print-finding-status " + cssClass;
                pill.textContent = status;
                metaLine.appendChild(pill);

                var detailsHeader = card.querySelector(".finding-details-header");
                if (detailsHeader) {
                    var inline = detailsHeader.querySelector(".print-tags-inline");
                    if (inline) {
                        var oldConfidence = inline.querySelector(".print-confidence-chip");
                        if (oldConfidence && oldConfidence.parentNode) {
                            oldConfidence.parentNode.removeChild(oldConfidence);
                        }
                        var confidenceChip = document.createElement("span");
                        confidenceChip.className = "print-tag-chip conf print-confidence-chip";
                        confidenceChip.textContent = confidenceText || "Confidence: Inconclusive";
                        inline.insertBefore(confidenceChip, inline.firstChild);
                    }
                }
            });
        }

        function buildPrintTocFromRoot(rootNode) {
            if (!rootNode || typeof rootNode.querySelectorAll !== "function") return "";

            function slugifyId(text, fallback) {
                var slug = toText(text, fallback || "section")
                    .toLowerCase()
                    .replace(/\s+/g, "-")
                    .replace(/[^a-z0-9\-]/g, "")
                    .replace(/-+/g, "-")
                    .replace(/^-+|-+$/g, "");
                return slug || (fallback || "section");
            }

            var used = {};
            function reserveUniqueId(base) {
                var seed = slugifyId(base, "section");
                if (!Object.prototype.hasOwnProperty.call(used, seed)) {
                    used[seed] = 1;
                    return seed;
                }
                var idx = used[seed];
                used[seed] = idx + 1;
                return seed + "-" + idx;
            }

            var tocItems = [];

            var headings = rootNode.querySelectorAll(".finding-category .category-header h2");
            Array.prototype.forEach.call(headings, function (h2, index) {
                var label = toText(h2.textContent, "Category " + (index + 1));
                var id = reserveUniqueId(label);
                h2.id = id;
                tocItems.push('<li><a href="#' + id + '">' + escapeHtml(label) + "</a></li>");
            });

            if (!tocItems.length) {
                return "";
            }

            return (
                '<nav class="toc" aria-label="Table of contents">' +
                    '<h2 class="section-title toc-title">Table of Contents</h2>' +
                    '<ul class="toc-list">' + tocItems.join("") + "</ul>" +
                "</nav>"
            );
        }

        function buildCleanPrintHtml(scopeLabel, chartImages, findingsHtml, tocMarkup) {
            var context = getFindingsExportContext();
            function findChart(title) {
                var charts = chartImages || [];
                for (var i = 0; i < charts.length; i++) {
                    if (charts[i] && charts[i].title === title) return charts[i];
                }
                return null;
            }

            function buildChartFigure(entry, fallbackTitle) {
                var title = entry && entry.title ? entry.title : fallbackTitle;
                var image = entry && entry.dataUrl ? ('<img src="' + entry.dataUrl + '" alt="' + escapeHtml(title) + '">') : '<div class="chart-missing">Chart unavailable: ' + escapeHtml(title) + "</div>";
                return (
                    '<figure class="chart-card">' +
                        image +
                    "</figure>"
                );
            }

            var chartMarkup =
                '<div class="charts-row charts-row-two">' +
                    buildChartFigure(findChart("Weighted Coverage Score"), "Weighted Coverage Score") +
                    buildChartFigure(findChart("Coverage by Category"), "Coverage by Category") +
                "</div>" +
                '<div class="charts-row charts-row-one">' +
                    buildChartFigure(findChart("Covered vs Vulnerable Points"), "Covered vs Vulnerable Points") +
                "</div>" +
                '<div class="charts-row charts-row-three">' +
                    buildChartFigure(findChart("Severity Distribution"), "Severity Distribution") +
                    buildChartFigure(findChart("Tag Distribution"), "Tag Distribution") +
                    buildChartFigure(findChart("Confidence Distribution"), "Confidence Distribution") +
                "</div>";

            var generatedAt = new Date().toLocaleString();

            return (
                "<!doctype html>" +
                '<html lang="en">' +
                "<head>" +
                    '<meta charset="utf-8">' +
                    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
                    "<title>EF - Security Findings</title>" +
                    "<style>" +
                        "body{font-family:Segoe UI,Arial,sans-serif;color:#111;margin:0;padding:20px;line-height:1.4;background:#fff;}" +
                        "h1{margin:0 0 6px;font-size:22px;}" +
                        ".meta{margin:0 0 16px;color:#555;font-size:12px;}" +
                        ".section-title{margin:18px 0 10px;font-size:16px;border-bottom:1px solid #ddd;padding-bottom:4px;}" +
                        ".toc{margin:0 0 14px;}" +
                        ".toc-title{margin-top:6px;}" +
                        ".toc-list{margin:8px 0 0 16px;padding:0;columns:2;column-gap:24px;}" +
                        ".toc-list li{margin:0 0 6px;break-inside:avoid;}" +
                        ".toc-list a{text-decoration:none;color:#0b4d92;}" +
                        ".toc-list a:hover{text-decoration:underline;}" +
                        ".charts-row{display:grid;gap:12px;margin:0 0 12px 0;}" +
                        ".charts-row-two{grid-template-columns:repeat(2,minmax(280px,1fr));}" +
                        ".charts-row-one{grid-template-columns:1fr;}" +
                        ".charts-row-three{grid-template-columns:repeat(3,minmax(220px,1fr));}" +
                        ".chart-card{margin:0;border:1px solid #ddd;border-radius:8px;padding:10px;background:#fff;break-inside:avoid;}" +
                        ".chart-card img{width:100%;height:auto;display:block;}" +
                        ".chart-missing{border:1px dashed #bbb;border-radius:6px;padding:24px 12px;text-align:center;color:#666;font-size:12px;}" +
                        ".finding-category{margin:0 0 16px;break-inside:avoid;}" +
                        ".category-header{display:flex;align-items:center;justify-content:space-between;gap:8px;border-bottom:1px solid #ddd;padding-bottom:4px;margin-bottom:10px;}" +
                        ".category-header h2{margin:0;font-size:16px;}" +
                        ".category-summary{display:flex;gap:6px;align-items:center;}" +
                        ".summary-chip{display:inline-block;padding:2px 8px;border:1px solid #ccc;border-radius:999px;font-size:11px;}" +
                        ".finding-card{border:1px solid #ddd;border-radius:10px;margin:0 0 10px;padding:10px;break-inside:avoid;}" +
                        ".finding-toggle{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;text-align:left;border:0;background:transparent;padding:0;cursor:default;color:#111;}" +
                        ".finding-header-left{flex:1 1 auto;min-width:0;}" +
                        ".finding-header-right{float:none;display:flex;align-items:center;justify-content:flex-end;margin-left:10px;align-self:center;}" +
                        ".finding-title{font-weight:700;font-size:15px;margin-bottom:6px;}" +
                        ".finding-header-meta{display:flex;flex-wrap:wrap;gap:6px;}" +
                        ".sev-badge{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid transparent;font-size:12px;font-weight:700;line-height:1.1;white-space:nowrap;}" +
                        ".sev-0{background:#d6e7ff;color:#103a68;border-color:#9db8d6;}" +
                        ".sev-1{background:#d7f1da;color:#0f4b25;border-color:#a8cfae;}" +
                        ".sev-2{background:#fff0c2;color:#6b4a00;border-color:#d9c186;}" +
                        ".sev-3{background:#ffd7b3;color:#6b2f00;border-color:#d1ab8a;}" +
                        ".sev-4{background:#ffb8b8;color:#6b0000;border-color:#cf8f8f;}" +
                        ".finding-details{display:block !important;margin-top:10px;border-top:1px solid #eee;padding-top:8px;}" +
                        ".finding-details-header-actions,.affected-actions,.finding-toggle .caret,.affected-pager,.affected-page-size{display:none !important;}" +
                        ".finding-details-header{display:flex;align-items:center;justify-content:flex-start;gap:8px;margin-bottom:14px;}" +
                        ".finding-details-header-title{margin:0;font-weight:700;letter-spacing:.35px;text-transform:uppercase;flex:0 0 auto;}" +
                        ".print-finding-status{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #bbb;font-size:11px;font-weight:600;}" +
                        ".print-finding-status.vul{background:rgba(255,130,130,0.2);border-color:#d88;color:#7a1515;}" +
                        ".print-finding-status.nv{background:rgba(130,210,130,0.18);border-color:#9ac89a;color:#1d5a1d;}" +
                        ".print-finding-status.sk{background:rgba(190,190,190,0.18);border-color:#b9b9b9;color:#555;}" +
                        ".finding-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px;}" +
                        ".finding-details h4{margin:0 0 6px;font-size:13px;}" +
                        ".finding-block{margin-bottom:10px;padding:10px;border:1px solid #ddd;border-radius:8px;background:#fafafa;}" +
                        ".finding-label{font-size:12px;text-transform:uppercase;letter-spacing:.35px;font-weight:700;margin:0 0 8px;padding-bottom:6px;border-bottom:1px solid #ddd;}" +
                        ".finding-body{font-size:13px;line-height:1.45;}" +
                        ".finding-block p,.finding-block ul{margin:6px 0;}" +
                        ".print-tags-inline{display:flex;flex-wrap:wrap;justify-content:flex-end;align-items:center;gap:6px;margin-left:auto;}" +
                        ".print-tag-chip{display:inline-block;padding:3px 8px;border:1px solid #bbb;border-radius:999px;font-size:11px;background:#fff;}" +
                        ".print-tag-chip.conf{background:rgba(220,230,255,0.32);border-color:#9cb1da;color:#1e3f70;}" +
                        ".print-tag-chip.imp{background:rgba(255,160,120,0.24);}" +
                        ".print-tag-chip.fp{background:rgba(255,208,100,0.28);}" +
                        ".print-tag-chip.fx{background:rgba(190,170,255,0.22);}" +
                        ".print-tag-chip.rs{background:rgba(120,200,255,0.22);}" +
                        ".print-tag-chip.cf{background:rgba(120,230,180,0.22);}" +
                        ".finding-affected{margin-top:10px;}" +
                        ".affected-table-wrap{overflow:visible;}" +
                        ".affected-table{width:100%;border-collapse:collapse;font-size:12px;}" +
                        ".affected-table th,.affected-table td{border:1px solid #ddd;padding:6px;vertical-align:top;text-align:left;}" +
                        "@media print{" +
                            "@page{size:auto;margin:12mm;}" +
                            "body{padding:0;}" +
                            ".toc-list{columns:1;}" +
                            ".charts-row-two{grid-template-columns:repeat(2,minmax(240px,1fr));}" +
                            ".charts-row-three{grid-template-columns:repeat(3,minmax(180px,1fr));}" +
                            ".finding-grid{grid-template-columns:repeat(3,minmax(220px,1fr));}" +
                            ".findings-content{break-before:page;page-break-before:always;}" +
                            ".chart-card,.finding-card,.finding-category{break-inside:avoid-page;}" +
                        "}" +
                    "</style>" +
                "</head>" +
                "<body>" +
                    "<h1>EntraFalcon Security Findings</h1>" +
                    '<p class="meta">Scope: ' + escapeHtml(scopeLabel) + " | Tenant: " + escapeHtml(context.tenantLabel) + " | Generated: " + escapeHtml(generatedAt) + "</p>" +
                    '<h2 id="overview-charts-section" class="section-title">Overview Charts</h2>' +
                    chartMarkup +
                    (tocMarkup || "") +
                    '<div class="findings-content">' + findingsHtml + "</div>" +
                "</body>" +
                "</html>"
            );
        }

        function openPrintWindowAndPrint(html, printWindow) {
            var targetWindow = printWindow || null;
            if (!targetWindow) {
                try {
                    // Keep this call minimal; some browsers return null with noopener/noreferrer even when a tab opens.
                    targetWindow = window.open("about:blank", "_blank");
                } catch (e) {
                    targetWindow = null;
                }
            }
            if (!targetWindow) {
                alert("Popup blocked. Allow popups for this report to export PDF.");
                return false;
            }

            targetWindow.document.open();
            targetWindow.document.write(html);
            targetWindow.document.close();

            var triggerPrint = function () {
                try { targetWindow.focus(); } catch (e) {}
                setTimeout(function () {
                    try { targetWindow.print(); } catch (e) {}
                }, 120);
            };

            if (targetWindow.document.readyState === "complete") {
                triggerPrint();
            } else {
                targetWindow.addEventListener("load", triggerPrint, { once: true });
            }
            return true;
        }

        function exportPdfClean() {
            var preOpenedPrintWindow = null;
            try {
                preOpenedPrintWindow = window.open("about:blank", "_blank");
            } catch (e) {
                preOpenedPrintWindow = null;
            }
            if (!preOpenedPrintWindow) {
                alert("Popup blocked. Allow popups for this report to export PDF.");
                return;
            }

            try {
                preOpenedPrintWindow.document.open();
                preOpenedPrintWindow.document.write("<!doctype html><html><head><title>Preparing PDF...</title></head><body><p>Preparing PDF export...</p></body></html>");
                preOpenedPrintWindow.document.close();
            } catch (e) {}

            var snapshot = captureInteractiveSnapshot();
            var restoreOverviewPanel = null;
            var restoreAffectedObjects = null;
            var finalized = false;
            function finalizeStateRestore() {
                if (finalized) return;
                finalized = true;
                if (typeof restoreAffectedObjects === "function") {
                    restoreAffectedObjects();
                }
                if (typeof restoreOverviewPanel === "function") {
                    restoreOverviewPanel();
                }
                restoreInteractiveSnapshot(snapshot);
            }

            try {
                expandVisibleCardsForPrint();
                restoreAffectedObjects = prepareAffectedObjectsForPrint();
                restoreOverviewPanel = ensureOverviewChartsReadyForSnapshot();

                var root = document.getElementById("findingsRoot");
                if (!root) {
                    finalizeStateRestore();
                    return;
                }

                var clonedRoot = root.cloneNode(true);
                stripLinksFromAffectedObjects(clonedRoot);
                populatePrintTagSummaries(clonedRoot);
                populatePrintFindingStatus(clonedRoot);
                var tocMarkup = buildPrintTocFromRoot(clonedRoot);
                var clonedCards = clonedRoot.querySelectorAll(".finding-card");
                Array.prototype.forEach.call(clonedCards, function (card) {
                    card.classList.add("expanded");
                    var toggle = card.querySelector(".finding-toggle");
                    if (toggle) toggle.setAttribute("aria-expanded", "true");
                });

                setTimeout(function () {
                    try {
                        var chartImages = captureOverviewChartImages();
                        var scopeLabel = "Visible findings";
                        var printHtml = buildCleanPrintHtml(scopeLabel, chartImages, clonedRoot.innerHTML, tocMarkup);
                        openPrintWindowAndPrint(printHtml, preOpenedPrintWindow);
                    } finally {
                        finalizeStateRestore();
                    }
                }, 420);
            } catch (e) {
                finalizeStateRestore();
                throw e;
            }
        }

        function ensureHeadingIds() {
            var headings = document.querySelectorAll("h2");
            for (var i = 0; i < headings.length; i++) {
                var h2 = headings[i];
                if (!h2 || h2.id) continue;
                if (h2.closest && h2.closest("#helpModalOverlay")) continue;

                var id = (h2.textContent || "")
                    .trim()
                    .toLowerCase()
                    .replace(/\s+/g, "-")
                    .replace(/[^a-z0-9\-]/g, "");

                h2.id = id || ("section-" + i);
            }
        }

        function rebuildSectionStrip() {
            var inner = document.getElementById("sectionStripInner");
            if (!inner) return;

            while (inner.firstChild) inner.removeChild(inner.firstChild);

            var headings = document.querySelectorAll("h2");
            var added = 0;

            for (var i = 0; i < headings.length; i++) {
                var h2 = headings[i];
                if (!h2 || !h2.id) continue;
                if (h2.closest && h2.closest("#helpModalOverlay")) continue;

                if (added > 0) {
                    var sep = document.createElement("span");
                    sep.className = "section-sep";
                    sep.textContent = "\u2022";
                    inner.appendChild(sep);
                }

                var a = document.createElement("a");
                a.className = "section-link";
                a.href = "#" + h2.id;
                a.textContent = (h2.textContent || "").replace(/\s+/g, " ").trim();
                inner.appendChild(a);
                added++;
            }
        }

        function buildAffectedPanel(finding) {
            var objects = finding.AffectedObjects || [];
            var hasObjects = objects.length > 0;
            var hasLink = !!finding.RelatedReportUrl;
            if (!hasObjects && !hasLink) return null;

            var wrap = document.createElement("div");
            wrap.className = "finding-affected";

            var header = document.createElement("div");
            header.className = "affected-header";
            header.appendChild(buildElement("div", "affected-title", "\uD83C\uDFAF Affected Objects"));

            var actions = document.createElement("div");
            actions.className = "affected-actions";
            header.appendChild(actions);
            wrap.appendChild(header);

            if (hasLink) {
                var linkBtn = document.createElement("button");
                linkBtn.type = "button";
                linkBtn.className = "affected-link-btn";
                linkBtn.textContent = "Show in related report";
                linkBtn.addEventListener("click", function () {
                    window.open(finding.RelatedReportUrl, "_blank", "noopener");
                });
                actions.appendChild(linkBtn);
            }

            if (!hasObjects) return wrap;

            var searchInput = document.createElement("input");
            searchInput.type = "search";
            searchInput.placeholder = "Filter objects...";
            searchInput.className = "affected-search";
            actions.appendChild(searchInput);

            var exportMenu = document.createElement("div");
            exportMenu.className = "affected-export-menu";
            var exportBtn = document.createElement("button");
            exportBtn.type = "button";
            exportBtn.textContent = "Export";
            exportBtn.setAttribute("aria-haspopup", "true");
            exportBtn.setAttribute("aria-expanded", "false");
            var exportPanel = document.createElement("div");
            exportPanel.className = "affected-export-panel hidden";
            var exportCsvBtn = document.createElement("button");
            exportCsvBtn.type = "button";
            exportCsvBtn.textContent = "Export CSV";
            var exportJsonBtn = document.createElement("button");
            exportJsonBtn.type = "button";
            exportJsonBtn.textContent = "Export JSON";
            var exportCopyBtn = document.createElement("button");
            exportCopyBtn.type = "button";
            exportCopyBtn.textContent = "Copy TSV";
            var exportCopyCsvBtn = document.createElement("button");
            exportCopyCsvBtn.type = "button";
            exportCopyCsvBtn.textContent = "Copy CSV";
            var exportCsvMultilineBtn = document.createElement("button");
            exportCsvMultilineBtn.type = "button";
            exportCsvMultilineBtn.textContent = "Export CSV (Multiline)";
            var exportCopyCsvMultilineBtn = document.createElement("button");
            exportCopyCsvMultilineBtn.type = "button";
            exportCopyCsvMultilineBtn.textContent = "Copy CSV (Multiline)";
            exportPanel.appendChild(exportCsvBtn);
            exportPanel.appendChild(exportJsonBtn);
            exportPanel.appendChild(exportCsvMultilineBtn);
            exportPanel.appendChild(exportCopyBtn);
            exportPanel.appendChild(exportCopyCsvBtn);
            exportPanel.appendChild(exportCopyCsvMultilineBtn);
            exportMenu.appendChild(exportBtn);
            exportMenu.appendChild(exportPanel);
            actions.appendChild(exportMenu);

            var pageSize = 10;
            var pageIndex = 0;
            function getObjectColumns(items) {
                var ordered = [];
                var seen = {};
                items.forEach(function (obj) {
                    if (!obj) return;
                    Object.keys(obj).forEach(function (key) {
                        if (!key || seen[key]) return;
                        seen[key] = true;
                        ordered.push(key);
                    });
                });
                return ordered;
            }

            function renderCellValue(cell, value) {
                var text = toText(value, "");
                if (text && text.indexOf("<") !== -1 && text.indexOf(">") !== -1) {
                    cell.innerHTML = text;
                } else {
                    cell.textContent = text;
                }
            }

            var allColumns = getObjectColumns(objects);
            var columns = allColumns.filter(function (key) {
                return key && key.charAt(0) !== "_";
            });
            var sortKey = "";
            if (finding.AffectedSortKey) {
                var desired = String(finding.AffectedSortKey).toLowerCase();
                sortKey = allColumns.find(function (key) { return String(key).toLowerCase() === desired; }) || "";
                if (!sortKey) {
                    sortKey = allColumns.find(function (key) { return String(key).toLowerCase().indexOf(desired) !== -1; }) || "";
                }
            }
            if (!sortKey) sortKey = columns[0] || "";
            var sortDir = 1;
            if (typeof finding.AffectedSortDir === "string") {
                var dir = finding.AffectedSortDir.toLowerCase();
                if (dir === "desc") sortDir = -1;
                if (dir === "asc") sortDir = 1;
            } else if (finding.AffectedSortDir === -1) {
                sortDir = -1;
            }
            var searchQuery = "";
            var sortTouched = false;

            var table = document.createElement("table");
            table.className = "affected-table";

            var thead = document.createElement("thead");
            var headRow = document.createElement("tr");
            var sortIndicators = {};
            columns.forEach(function (key) {
                var th = document.createElement("th");
                th.textContent = key;
                th.className = "sortable";
                th.setAttribute("data-key", key);
                var indicator = document.createElement("span");
                indicator.className = "affected-sort-indicator";
                indicator.textContent = "";
                sortIndicators[key] = indicator;
                th.appendChild(indicator);
                th.addEventListener("click", function () {
                    if (sortKey === key) {
                        sortDir = sortDir * -1;
                    } else {
                        sortKey = key;
                        sortDir = 1;
                    }
                    sortTouched = true;
                    renderTable();
                });
                headRow.appendChild(th);
            });
            thead.appendChild(headRow);
            table.appendChild(thead);

            var tbody = document.createElement("tbody");
            table.appendChild(tbody);
            wrap.appendChild(table);

            var pager = document.createElement("div");
            pager.className = "affected-pager";

            var prevBtn = document.createElement("button");
            prevBtn.type = "button";
            prevBtn.textContent = "Prev";
            prevBtn.addEventListener("click", function () {
                if (pageIndex > 0) {
                    pageIndex -= 1;
                    renderTable();
                }
            });

            var nextBtn = document.createElement("button");
            nextBtn.type = "button";
            nextBtn.textContent = "Next";
            nextBtn.addEventListener("click", function () {
                var maxPage = Math.max(0, Math.ceil(objects.length / pageSize) - 1);
                if (pageIndex < maxPage) {
                    pageIndex += 1;
                    renderTable();
                }
            });

            var pageInfo = document.createElement("div");
            pageInfo.className = "page-info";
            pager.appendChild(prevBtn);
            pager.appendChild(pageInfo);
            pager.appendChild(nextBtn);
            wrap.appendChild(pager);

            exportCsvBtn.addEventListener("click", function () {
                var headers = columns.slice();
                var lines = [headers.join(",")];
                getSortedObjects().forEach(function (obj) {
                    var row = columns.map(function (key) {
                        var text = toText(obj[key], "");
                        text = text.replace(/<br\s*\/?>/gi, "; ");
                        return stripHtml(text);
                    }).map(function (cell) {
                        var v = String(cell == null ? "" : cell).replace(/\"/g, "\"\"");
                        return "\"" + v + "\"";
                    });
                    lines.push(row.join(","));
                });
                downloadBlob(buildAffectedExportFilename(finding, "csv", false), lines.join("\n"), "text/csv");
                closeExportMenu();
            });

            exportJsonBtn.addEventListener("click", function () {
                var rows = getSortedObjects().map(function (obj) {
                    var cleaned = {};
                    columns.forEach(function (key) {
                        var text = htmlToPlainFormatted(toText(obj[key], ""));
                        var split = splitMultiValueField(key, text);
                        cleaned[key] = split.length > 1 ? split : (split[0] || "");
                    });
                    return cleaned;
                });
                downloadBlob(buildAffectedExportFilename(finding, "json", false), JSON.stringify(rows, null, 2), "application/json");
                closeExportMenu();
            });

            exportCopyBtn.addEventListener("click", function () {
                var rows = getSortedObjects();
                var lines = [columns.join("\t")];
                rows.forEach(function (obj) {
                    var row = columns.map(function (key) {
                        var text = toText(obj[key], "");
                        text = text.replace(/<br\s*\/?>/gi, "; ");
                        var cell = stripHtml(text);
                        return String(cell == null ? "" : cell).replace(/\t/g, " ").replace(/\r?\n/g, " ");
                    });
                    lines.push(row.join("\t"));
                });
                var content = lines.join("\n");
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(content).catch(function () {});
                }
                closeExportMenu();
            });

            exportCopyCsvBtn.addEventListener("click", function () {
                var rows = getSortedObjects();
                var lines = [columns.join(",")];
                rows.forEach(function (obj) {
                    var row = columns.map(function (key) {
                        var text = toText(obj[key], "");
                        text = text.replace(/<br\s*\/?>/gi, "; ");
                        return stripHtml(text);
                    }).map(function (cell) {
                        var v = String(cell == null ? "" : cell).replace(/\"/g, "\"\"").replace(/\r?\n/g, " ");
                        return "\"" + v + "\"";
                    });
                    lines.push(row.join(","));
                });
                var content = lines.join("\n");
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(content).catch(function () {});
                }
                closeExportMenu();
            });

            exportCsvMultilineBtn.addEventListener("click", function () {
                var headers = columns.slice();
                var lines = [headers.join(",")];
                getSortedObjects().forEach(function (obj) {
                    var row = columns.map(function (key) {
                        var text = toText(obj[key], "");
                        text = text.replace(/<br\s*\/?>/gi, "\n");
                        return stripHtml(text);
                    }).map(function (cell) {
                        var v = String(cell == null ? "" : cell).replace(/\"/g, "\"\"");
                        return "\"" + v + "\"";
                    });
                    lines.push(row.join(","));
                });
                downloadBlob(buildAffectedExportFilename(finding, "csv", true), lines.join("\n"), "text/csv");
                closeExportMenu();
            });

            exportCopyCsvMultilineBtn.addEventListener("click", function () {
                var rows = getSortedObjects();
                var lines = [columns.join(",")];
                rows.forEach(function (obj) {
                    var row = columns.map(function (key) {
                        var text = toText(obj[key], "");
                        text = text.replace(/<br\s*\/?>/gi, "\n");
                        return stripHtml(text);
                    }).map(function (cell) {
                        var v = String(cell == null ? "" : cell).replace(/\"/g, "\"\"");
                        return "\"" + v + "\"";
                    });
                    lines.push(row.join(","));
                });
                var content = lines.join("\n");
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(content).catch(function () {});
                }
                closeExportMenu();
            });

            exportBtn.addEventListener("click", function (event) {
                event.stopPropagation();
                toggleExportMenu();
            });

            document.addEventListener("click", function (event) {
                if (!exportPanel.contains(event.target) && event.target !== exportBtn) {
                    closeExportMenu();
                }
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeExportMenu();
            });

            searchInput.addEventListener("input", function () {
                searchQuery = searchInput.value.trim().toLowerCase();
                pageIndex = 0;
                renderTable();
            });

            function toggleExportMenu() {
                var isHidden = exportPanel.classList.contains("hidden");
                if (isHidden) {
                    exportPanel.classList.remove("hidden");
                    exportBtn.setAttribute("aria-expanded", "true");
                } else {
                    closeExportMenu();
                }
            }

            function closeExportMenu() {
                exportPanel.classList.add("hidden");
                exportBtn.setAttribute("aria-expanded", "false");
            }

            function getFilteredObjects() {
                if (!searchQuery) return objects.slice();
                return objects.filter(function (obj) {
                    return columns.some(function (key) {
                        return stripHtml(toText(obj[key], "")).toLowerCase().indexOf(searchQuery) !== -1;
                    });
                });
            }

            function getSortedObjects() {
                return getFilteredObjects().slice().sort(function (a, b) {
                    var avRaw = toText(a[sortKey], "");
                    var bvRaw = toText(b[sortKey], "");
                    var av = stripHtml(avRaw).trim();
                    var bv = stripHtml(bvRaw).trim();
                    var aMissing = av === "" || av === "?";
                    var bMissing = bv === "" || bv === "?";
                    if (aMissing && !bMissing) return 1;
                    if (!aMissing && bMissing) return -1;
                    var aNum = /^-?\d+(\.\d+)?$/.test(av) ? Number(av) : null;
                    var bNum = /^-?\d+(\.\d+)?$/.test(bv) ? Number(bv) : null;
                    if (aNum !== null && bNum !== null) {
                        if (aNum < bNum) return -1 * sortDir;
                        if (aNum > bNum) return 1 * sortDir;
                        return 0;
                    }
                    av = av.toLowerCase();
                    bv = bv.toLowerCase();
                    if (av < bv) return -1 * sortDir;
                    if (av > bv) return 1 * sortDir;
                    return 0;
                });
            }

            var sizeWrap = document.createElement("div");
            sizeWrap.className = "affected-page-size";
            sizeWrap.appendChild(document.createTextNode("Rows"));
            var sizeSelect = document.createElement("select");
            ["10", "20", "50", "100", "All"].forEach(function (value) {
                var option = document.createElement("option");
                option.value = value;
                option.textContent = value;
                if (value === "10") option.selected = true;
                sizeSelect.appendChild(option);
            });
            sizeSelect.addEventListener("change", function () {
                pageSize = sizeSelect.value === "All" ? Number.MAX_SAFE_INTEGER : Number(sizeSelect.value);
                pageIndex = 0;
                renderTable();
            });
            sizeWrap.appendChild(sizeSelect);
            actions.appendChild(sizeWrap);

            function renderTable() {
                var sorted = getSortedObjects();

                var start = pageIndex * pageSize;
                var end = start + pageSize;
                var pageItems = sorted.slice(start, end);

                tbody.innerHTML = "";
                if (!pageItems.length) {
                    var emptyRow = document.createElement("tr");
                    var emptyCell = document.createElement("td");
                    emptyCell.colSpan = Math.max(1, columns.length);
                    emptyCell.textContent = "No matching objects.";
                    emptyCell.style.opacity = "0.7";
                    emptyRow.appendChild(emptyCell);
                    tbody.appendChild(emptyRow);
                } else {
                    pageItems.forEach(function (obj) {
                        var row = document.createElement("tr");
                        columns.forEach(function (key) {
                            var cell = document.createElement("td");
                            renderCellValue(cell, obj[key]);
                            row.appendChild(cell);
                        });
                        tbody.appendChild(row);
                    });
                }

                var maxPage = Math.max(0, Math.ceil(sorted.length / pageSize) - 1);
                pageInfo.textContent = "Page " + (pageIndex + 1) + " of " + (maxPage + 1) + " (" + pageItems.length + " of " + sorted.length + " objects)";
                var singlePage = maxPage <= 0;
                prevBtn.style.display = singlePage ? "none" : "";
                nextBtn.style.display = singlePage ? "none" : "";
                prevBtn.disabled = pageIndex === 0;
                nextBtn.disabled = pageIndex >= maxPage;

                Object.keys(sortIndicators).forEach(function (key) {
                    sortIndicators[key].textContent = "";
                });
                if (sortTouched && sortIndicators[sortKey]) {
                    sortIndicators[sortKey].textContent = sortDir === 1 ? " \u25B2" : " \u25BC";
                }
            }

            wrap._setRowsAllForPrint = function () {
                var state = {
                    pageSize: pageSize,
                    pageIndex: pageIndex,
                    sizeValue: sizeSelect ? sizeSelect.value : "",
                    searchValue: searchInput ? searchInput.value : ""
                };
                pageSize = Number.MAX_SAFE_INTEGER;
                pageIndex = 0;
                if (sizeSelect) sizeSelect.value = "All";
                renderTable();
                return state;
            };

            wrap._restoreRowsAfterPrint = function (state) {
                var s = state || {};
                pageSize = Number(s.pageSize || 10);
                pageIndex = Number(s.pageIndex || 0);
                if (sizeSelect && s.sizeValue) sizeSelect.value = s.sizeValue;
                if (searchInput && typeof s.searchValue === "string") searchInput.value = s.searchValue;
                searchQuery = searchInput ? searchInput.value.trim().toLowerCase() : "";
                renderTable();
            };

            renderTable();
            return wrap;
        }

        function getExpandedKeys() {
            var expanded = new Set();
            document.querySelectorAll(".finding-card.expanded").forEach(function (card) {
                var key = card.getAttribute("data-finding-key");
                if (key) expanded.add(key);
            });
            return expanded;
        }

        function buildFindingCard(finding, state, onStateChange) {
            var card = buildElement("div", "finding-card");
            card.setAttribute("data-finding-key", getFindingKey(finding));
            if (finding.Status === "NotVulnerable") {
                card.classList.add("not-vulnerable");
            } else if (finding.Status === "Skipped") {
                card.classList.add("skipped");
            }

            var header = buildElement("button", "finding-toggle");
            header.type = "button";
            header.setAttribute("aria-expanded", "false");

            var title = buildElement("div", "finding-title");
            title.textContent = finding.Title;
            var headerLeft = buildElement("div", "finding-header-left");
            var metaLine = buildElement("div", "finding-header-meta");
            var headerRight = buildElement("div", "finding-header-right");
            var statusWrap = buildElement("div", "finding-header-meta");
            var idPill = buildElement("span", "id-pill", "ID: " + getFindingKey(finding).toUpperCase());
            var confidenceClass = "conf-inconclusive";
            if ((finding.Confidence || "").toLowerCase() === "sure") {
                confidenceClass = "conf-sure";
            } else if ((finding.Confidence || "").toLowerCase() === "requires verification") {
                confidenceClass = "conf-requires";
            }
            var certaintyPill = buildElement("span", "certainty-pill " + confidenceClass, "Confidence: " + finding.Confidence);
            var sevBadge = buildElement("span", "sev-badge sev-" + finding.Severity, severityLabels[finding.Severity]);
            var caret = buildElement("span", "caret", "");
            caret.setAttribute("aria-hidden", "true");

            metaLine.appendChild(idPill);
            metaLine.appendChild(certaintyPill);
            metaLine.appendChild(statusWrap);
            headerRight.appendChild(sevBadge);

            headerLeft.appendChild(title);
            headerLeft.appendChild(metaLine);

            header.appendChild(caret);
            header.appendChild(headerLeft);
            header.appendChild(headerRight);
            card.appendChild(header);

            var details = buildElement("div", "finding-details");

            var detailsHeader = buildElement("div", "finding-details-header");
            detailsHeader.appendChild(buildElement("div", "finding-details-header-title", "\uD83C\uDFF7\uFE0F Tags"));
            var detailsHeaderActions = buildElement("div", "finding-details-header-actions");

            function buildTagGroup(title, labels) {
                var group = buildElement("div", "tag-group");
                group.appendChild(buildElement("div", "tag-group-title", title));
                var options = buildElement("div", "tag-group-options");
                labels.forEach(function (label) {
                    options.appendChild(label);
                });
                group.appendChild(options);
                return group;
            }

            function buildTagSeparator() {
                return buildElement("div", "tag-group-separator");
            }

            var fpLabel = buildElement("label", "status-toggle");
            var fpInput = document.createElement("input");
            fpInput.type = "checkbox";
            fpInput.checked = !!state.FalsePositive;
            fpInput.addEventListener("change", function () {
                state.FalsePositive = fpInput.checked;
                updateStatusChips();
                onStateChange();
            });
            fpLabel.appendChild(fpInput);
            fpLabel.appendChild(document.createTextNode("False-positive"));

            var importantLabel = buildElement("label", "status-toggle");
            var importantInput = document.createElement("input");
            importantInput.type = "checkbox";
            importantInput.checked = !!state.Important;
            importantInput.addEventListener("change", function () {
                state.Important = importantInput.checked;
                updateStatusChips();
                onStateChange();
            });
            importantLabel.appendChild(importantInput);
            importantLabel.appendChild(document.createTextNode("Important"));

            var needsReviewLabel = buildElement("label", "status-toggle");
            var needsReviewInput = document.createElement("input");
            needsReviewInput.type = "checkbox";
            needsReviewInput.checked = !!state.NeedsReview;
            needsReviewInput.addEventListener("change", function () {
                state.NeedsReview = needsReviewInput.checked;
                updateStatusChips();
                onStateChange();
            });
            needsReviewLabel.appendChild(needsReviewInput);
            needsReviewLabel.appendChild(document.createTextNode("Needs Review"));

            var acceptedRiskLabel = buildElement("label", "status-toggle");
            var acceptedRiskInput = document.createElement("input");
            acceptedRiskInput.type = "checkbox";
            acceptedRiskInput.checked = !!state.AcceptedRisk;
            acceptedRiskInput.addEventListener("change", function () {
                state.AcceptedRisk = acceptedRiskInput.checked;
                updateStatusChips();
                onStateChange();
            });
            acceptedRiskLabel.appendChild(acceptedRiskInput);
            acceptedRiskLabel.appendChild(document.createTextNode("Accepted Risk"));

            var confirmedLabel = buildElement("label", "status-toggle");
            var confirmedInput = document.createElement("input");
            confirmedInput.type = "checkbox";
            confirmedInput.checked = !!state.Confirmed;
            confirmedInput.addEventListener("change", function () {
                state.Confirmed = confirmedInput.checked;
                updateStatusChips();
                onStateChange();
            });
            confirmedLabel.appendChild(confirmedInput);
            confirmedLabel.appendChild(document.createTextNode("Confirmed"));

            var resolvedLabel = buildElement("label", "status-toggle");
            var resolvedInput = document.createElement("input");
            resolvedInput.type = "checkbox";
            resolvedInput.checked = !!state.Resolved;
            resolvedInput.addEventListener("change", function () {
                state.Resolved = resolvedInput.checked;
                updateStatusChips();
                onStateChange();
            });
            resolvedLabel.appendChild(resolvedInput);
            resolvedLabel.appendChild(document.createTextNode("Resolved"));

            var fixingLabel = buildElement("label", "status-toggle");
            var fixingInput = document.createElement("input");
            fixingInput.type = "checkbox";
            fixingInput.checked = !!state.Fixing;
            fixingInput.addEventListener("change", function () {
                state.Fixing = fixingInput.checked;
                updateStatusChips();
                onStateChange();
            });
            fixingLabel.appendChild(fixingInput);
            fixingLabel.appendChild(document.createTextNode("Fixing"));

            detailsHeaderActions.appendChild(buildTagGroup("Assessment", [confirmedLabel, fpLabel]));
            detailsHeaderActions.appendChild(buildTagSeparator());
            detailsHeaderActions.appendChild(buildTagGroup("Progress", [fixingLabel, resolvedLabel]));
            detailsHeaderActions.appendChild(buildTagSeparator());
            detailsHeaderActions.appendChild(buildTagGroup("Priority", [importantLabel, needsReviewLabel, acceptedRiskLabel]));
            detailsHeader.appendChild(detailsHeaderActions);
            details.appendChild(detailsHeader);

            var grid = buildElement("div", "finding-grid");

            if (finding.Description) {
                var descBlock = buildElement("div", "finding-block");
                descBlock.appendChild(buildElement("div", "finding-label", "\uD83D\uDCDD Description"));
                var descBody = buildElement("div", "finding-body");
                descBody.innerHTML = finding.Description;
                descBlock.appendChild(descBody);
                grid.appendChild(descBlock);
            }

            if (finding.Threat) {
                var threatBlock = buildElement("div", "finding-block");
                threatBlock.appendChild(buildElement("div", "finding-label", "\u26A1 Threat"));
                var threatBody = buildElement("div", "finding-body");
                threatBody.innerHTML = finding.Threat;
                threatBlock.appendChild(threatBody);
                grid.appendChild(threatBlock);
            }

            if (finding.Remediation) {
                var remBlock = buildElement("div", "finding-block");
                remBlock.appendChild(buildElement("div", "finding-label", "\uD83D\uDEE1\uFE0F Remediation"));
                var remBody = buildElement("div", "finding-body");
                remBody.innerHTML = finding.Remediation;
                remBlock.appendChild(remBody);
                grid.appendChild(remBlock);
            }

            details.appendChild(grid);

            var affectedBuilt = false;
            function ensureAffectedPanelBuilt() {
                if (affectedBuilt) return;
                affectedBuilt = true;
                var affected = buildAffectedPanel(finding);
                if (affected) details.appendChild(affected);
            }
            card._ensureAffectedPanelBuilt = ensureAffectedPanelBuilt;

            card.appendChild(details);

        function updateStatusChips() {
            while (statusWrap.firstChild) statusWrap.removeChild(statusWrap.firstChild);
            if (state.Important) {
                statusWrap.appendChild(buildElement("span", "status-chip imp", "Important"));
            }
            if (state.NeedsReview) {
                statusWrap.appendChild(buildElement("span", "status-chip nr", "Needs Review"));
            }
            if (state.AcceptedRisk) {
                statusWrap.appendChild(buildElement("span", "status-chip ar", "Accepted Risk"));
            }
            if (state.Confirmed) {
                statusWrap.appendChild(buildElement("span", "status-chip cf", "Confirmed"));
            }
            if (state.FalsePositive) {
                statusWrap.appendChild(buildElement("span", "status-chip fp", "False-positive"));
            }
            if (state.Fixing) {
                statusWrap.appendChild(buildElement("span", "status-chip fx", "Fixing"));
            }
            if (state.Resolved) {
                statusWrap.appendChild(buildElement("span", "status-chip rs", "Resolved"));
            }
        }

            updateStatusChips();

            header.addEventListener("click", function () {
                var expanded = card.classList.toggle("expanded");
                header.setAttribute("aria-expanded", expanded ? "true" : "false");
                if (expanded && card._ensureAffectedPanelBuilt) {
                    card._ensureAffectedPanelBuilt();
                }
            });

            return card;
        }

        var severityLabels = {
            0: "Info",
            1: "Low",
            2: "Medium",
            3: "High",
            4: "Critical"
        };

        var severityPoints = {
            0: 0,
            1: 1,
            2: 3,
            3: 7,
            4: 10
        };

        var overviewCharts = {
            score: null,
            points: null,
            severity: null,
            status: null,
            confidence: null,
            observer: null
        };
        var forcePrintLightCharts = false;

        var dataEl = document.getElementById("findingsData");
        var rawData = dataEl ? dataEl.textContent : "[]";
        var findings = safeJsonParse(rawData);
        if (!Array.isArray(findings)) findings = [];
        findings = findings.map(normalizeFinding);

        var reportId = getReportId();
        var storageKey = "EntraFalcon_findingState_" + reportId;
        var stateStore = loadState(storageKey);

        function getStateFor(finding) {
            var key = getFindingKey(finding);
            if (!stateStore[key]) {
                stateStore[key] = { FalsePositive: false, Fixing: false, Resolved: false, Important: false, Confirmed: false, NeedsReview: false, AcceptedRisk: false };
            }
            if (stateStore[key].Important === undefined) {
                stateStore[key].Important = false;
            }
            if (stateStore[key].Fixing === undefined) {
                stateStore[key].Fixing = false;
            }
            if (stateStore[key].Confirmed === undefined) {
                stateStore[key].Confirmed = false;
            }
            if (stateStore[key].NeedsReview === undefined) {
                stateStore[key].NeedsReview = false;
            }
            if (stateStore[key].AcceptedRisk === undefined) {
                stateStore[key].AcceptedRisk = false;
            }
            return stateStore[key];
        }

        function isEffectivelyVulnerable(finding) {
            if (!isStatusVulnerable(finding)) return false;
            var state = getStateFor(finding);
            if (state.FalsePositive || state.Resolved) return false;
            return true;
        }

        var filterState = {
            category: new Set(),
            severity: new Set(),
            confidence: new Set(),
            findingStatus: new Set(),
            status: new Set()
        };

        var categoryList = Array.from(new Set(findings.map(function (f) { return f.Category; }))).sort();
        var certaintyList = Array.from(new Set(findings.map(function (f) { return f.Confidence; }))).sort(function (a, b) {
            return confidenceOrder(a) - confidenceOrder(b);
        });
        var severityList = [4,3,2,1,0];

        var forcedVisibleFindingKey = null;

        function clearForcedFindingReveal() {
            forcedVisibleFindingKey = null;
        }

        function applyFiltersFromUser(expandedKeys) {
            clearForcedFindingReveal();
            applyFilters(expandedKeys);
        }

        buildFilters({
            categories: categoryList,
            certainties: certaintyList,
            severities: severityList
        }, filterState, applyFiltersFromUser);

        function applyDefaultFindingStatusFilterSelection() {
            filterState.findingStatus.clear();
            filterState.findingStatus.add("Vulnerable");
            var statusInputs = document.querySelectorAll("#findingFilters input[type='checkbox'][data-group='findingStatus']");
            Array.prototype.forEach.call(statusInputs, function (input) {
                input.checked = input.value === "Vulnerable";
            });
        }
        applyDefaultFindingStatusFilterSelection();
        var searchQuery = "";
        var searchGroups = [];
        var searchFieldDefinitions = [
            { key: "id", label: "ID" },
            { key: "title", label: "Title" },
            { key: "description", label: "Description" },
            { key: "threat", label: "Threat" },
            { key: "remediation", label: "Remediation" },
            { key: "affected", label: "Affected objects" }
        ];
        var selectedSearchFields = new Set(searchFieldDefinitions.map(function (field) { return field.key; }));
        var sortState = { key: "category" };
        var lastVisibleFindings = [];
        var lastSummaryFingerprint = "";
        var findingCardCache = Object.create(null);

        function getOrCreateFindingCard(finding) {
            var key = getFindingKey(finding);
            if (findingCardCache[key]) return findingCardCache[key];

            var state = getStateFor(finding);
            var card = buildFindingCard(finding, state, function () {
                var expandedKeys = getExpandedKeys();
                saveState(storageKey, stateStore);
                applyFiltersFromUser(expandedKeys);
            });
            findingCardCache[key] = card;
            return card;
        }

        var searchInput = document.getElementById("findingSearch");
        if (searchInput) {
            searchInput.addEventListener("input", debounce(function (evt) {
                searchQuery = evt.target.value || "";
                searchGroups = buildSearchGroups(searchQuery);
                applyFiltersFromUser();
            }, 400));
        }

        var searchHelpToggle = document.getElementById("searchHelpToggle");
        var searchHelpPopover = document.getElementById("searchHelpPopover");

        function closeSearchHelp() {
            if (!searchHelpPopover || !searchHelpToggle) return;
            searchHelpPopover.classList.add("hidden");
            searchHelpToggle.setAttribute("aria-expanded", "false");
        }

        function toggleSearchHelp() {
            if (!searchHelpPopover || !searchHelpToggle) return;
            var isHidden = searchHelpPopover.classList.contains("hidden");
            if (isHidden) {
                searchHelpPopover.classList.remove("hidden");
                searchHelpToggle.setAttribute("aria-expanded", "true");
            } else {
                closeSearchHelp();
            }
        }

        if (searchHelpToggle && searchHelpPopover) {
            searchHelpToggle.addEventListener("click", function (event) {
                event.stopPropagation();
                toggleSearchHelp();
            });

            searchHelpPopover.addEventListener("click", function (event) {
                event.stopPropagation();
            });

            document.addEventListener("click", function (event) {
                if (!searchHelpPopover.contains(event.target) && event.target !== searchHelpToggle) {
                    closeSearchHelp();
                }
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeSearchHelp();
            });
        }

        var chartHelpButtons = document.querySelectorAll(".chart-help-btn");

        function closeAllChartHelp(exceptButton) {
            Array.prototype.forEach.call(chartHelpButtons, function (button) {
                var popoverId = button.getAttribute("aria-controls");
                var popover = popoverId ? document.getElementById(popoverId) : null;
                var shouldKeepOpen = exceptButton && button === exceptButton;
                if (!popover || shouldKeepOpen) return;
                popover.classList.add("hidden");
                button.setAttribute("aria-expanded", "false");
            });
        }

        Array.prototype.forEach.call(chartHelpButtons, function (button) {
            var popoverId = button.getAttribute("aria-controls");
            var popover = popoverId ? document.getElementById(popoverId) : null;
            if (!popover) return;

            button.addEventListener("click", function (event) {
                event.stopPropagation();
                var isHidden = popover.classList.contains("hidden");
                closeAllChartHelp(isHidden ? button : null);
                if (isHidden) {
                    popover.classList.remove("hidden");
                    button.setAttribute("aria-expanded", "true");
                } else {
                    popover.classList.add("hidden");
                    button.setAttribute("aria-expanded", "false");
                }
            });

            popover.addEventListener("click", function (event) {
                event.stopPropagation();
            });
        });

        if (chartHelpButtons.length) {
            document.addEventListener("click", function () {
                closeAllChartHelp();
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeAllChartHelp();
            });
        }

        var searchFieldsToggle = document.getElementById("searchFieldsToggle");
        var searchFieldsMenu = document.getElementById("searchFieldsMenu");
        var searchFieldInputs = searchFieldsMenu ? searchFieldsMenu.querySelectorAll("input[data-search-field]") : [];
        var searchFieldsSelectAllBtn = document.getElementById("searchFieldsSelectAll");
        var searchFieldsDeselectAllBtn = document.getElementById("searchFieldsDeselectAll");

        function updateSearchFieldsButtonLabel() {
            if (!searchFieldsToggle) return;
            var total = searchFieldDefinitions.length;
            var selected = selectedSearchFields.size;
            if (!selected || selected === total) {
                searchFieldsToggle.textContent = "Fields: All";
                return;
            }
            searchFieldsToggle.textContent = "Fields: " + selected + "/" + total;
        }

        function syncSelectedSearchFieldsFromInputs() {
            selectedSearchFields = new Set();
            Array.prototype.forEach.call(searchFieldInputs, function (input) {
                if (input.checked) selectedSearchFields.add(input.getAttribute("data-search-field"));
            });

            updateSearchFieldsButtonLabel();
        }

        function closeSearchFieldsMenu() {
            if (!searchFieldsMenu || !searchFieldsToggle) return;
            searchFieldsMenu.classList.add("hidden");
            searchFieldsToggle.setAttribute("aria-expanded", "false");
        }

        function toggleSearchFieldsMenu() {
            if (!searchFieldsMenu || !searchFieldsToggle) return;
            var isHidden = searchFieldsMenu.classList.contains("hidden");
            if (isHidden) {
                searchFieldsMenu.classList.remove("hidden");
                searchFieldsToggle.setAttribute("aria-expanded", "true");
            } else {
                closeSearchFieldsMenu();
            }
        }

        if (searchFieldsToggle && searchFieldsMenu) {
            updateSearchFieldsButtonLabel();

            searchFieldsToggle.addEventListener("click", function (event) {
                event.stopPropagation();
                toggleSearchFieldsMenu();
            });

            searchFieldsMenu.addEventListener("click", function (event) {
                event.stopPropagation();
            });

            Array.prototype.forEach.call(searchFieldInputs, function (input) {
                input.addEventListener("change", function () {
                    syncSelectedSearchFieldsFromInputs();
                    applyFiltersFromUser();
                });
            });

            if (searchFieldsSelectAllBtn) {
                searchFieldsSelectAllBtn.addEventListener("click", function () {
                    Array.prototype.forEach.call(searchFieldInputs, function (input) {
                        input.checked = true;
                    });
                    syncSelectedSearchFieldsFromInputs();
                    applyFiltersFromUser();
                });
            }

            if (searchFieldsDeselectAllBtn) {
                searchFieldsDeselectAllBtn.addEventListener("click", function () {
                    Array.prototype.forEach.call(searchFieldInputs, function (input) {
                        input.checked = false;
                    });
                    syncSelectedSearchFieldsFromInputs();
                    applyFiltersFromUser();
                });
            }

            document.addEventListener("click", function (event) {
                if (!searchFieldsMenu.contains(event.target) && event.target !== searchFieldsToggle) {
                    closeSearchFieldsMenu();
                }
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeSearchFieldsMenu();
            });
        }

        var sortSelect = document.getElementById("findingSort");
        if (sortSelect) {
            sortSelect.addEventListener("change", function () {
                sortState.key = sortSelect.value || "category";
                applyFiltersFromUser();
            });
        }

        var clearFiltersBtn = document.getElementById("btnClearFilters");
        function resetAllFilters() {
            searchQuery = "";
            searchGroups = [];
            if (searchInput) searchInput.value = "";

            if (searchFieldInputs && searchFieldInputs.length) {
                Array.prototype.forEach.call(searchFieldInputs, function (input) { input.checked = true; });
                syncSelectedSearchFieldsFromInputs();
            }

            Object.keys(filterState).forEach(function (key) {
                if (filterState[key] && typeof filterState[key].clear === "function") {
                    filterState[key].clear();
                }
            });

            sortState = { key: "category" };
            if (sortSelect) sortSelect.value = "category";

            var filterInputs = document.querySelectorAll("#findingFilters input[type='checkbox']");
            Array.prototype.forEach.call(filterInputs, function (input) {
                input.checked = false;
            });

            applyDefaultFindingStatusFilterSelection();
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener("click", function () {
                resetAllFilters();
                applyFiltersFromUser();
            });
        }

        var clearTagsBtn = document.getElementById("btnClearTags");
        var clearTagsConfirm = document.getElementById("clearTagsConfirm");
        var clearTagsYesBtn = document.getElementById("btnClearTagsYes");
        var clearTagsNoBtn = document.getElementById("btnClearTagsNo");

        function closeClearTagsConfirm() {
            if (!clearTagsConfirm || !clearTagsBtn) return;
            clearTagsConfirm.classList.add("hidden");
            clearTagsBtn.setAttribute("aria-expanded", "false");
        }

        function openClearTagsConfirm() {
            if (!clearTagsConfirm || !clearTagsBtn) return;
            clearTagsConfirm.classList.remove("hidden");
            clearTagsBtn.setAttribute("aria-expanded", "true");
        }

        if (clearTagsBtn && clearTagsConfirm && clearTagsYesBtn && clearTagsNoBtn) {
            clearTagsBtn.addEventListener("click", function (event) {
                event.stopPropagation();
                if (clearTagsConfirm.classList.contains("hidden")) {
                    openClearTagsConfirm();
                } else {
                    closeClearTagsConfirm();
                }
            });

            clearTagsConfirm.addEventListener("click", function (event) {
                event.stopPropagation();
            });

            clearTagsNoBtn.addEventListener("click", function () {
                closeClearTagsConfirm();
            });

            clearTagsYesBtn.addEventListener("click", function () {
                findings.forEach(function (finding) {
                    var state = getStateFor(finding);
                    state.FalsePositive = false;
                    state.Fixing = false;
                    state.Resolved = false;
                    state.Important = false;
                    state.Confirmed = false;
                    state.NeedsReview = false;
                    state.AcceptedRisk = false;
                });

                if (filterState.status && typeof filterState.status.clear === "function") {
                    filterState.status.clear();
                }
                var statusFilterInputs = document.querySelectorAll("#findingFilters input[type='checkbox'][data-group='status']");
                Array.prototype.forEach.call(statusFilterInputs, function (input) {
                    input.checked = false;
                });

                saveState(storageKey, stateStore);
                findingCardCache = Object.create(null);
                closeClearTagsConfirm();
                applyFiltersFromUser();
            });

            document.addEventListener("click", function (event) {
                if (event.target !== clearTagsBtn && !clearTagsConfirm.contains(event.target)) {
                    closeClearTagsConfirm();
                }
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeClearTagsConfirm();
            });
        }

        function getHashFindingToken() {
            var hash = window.location.hash || "";
            if (!hash || hash.length < 2) return "";
            var token = hash.slice(1).trim();
            if (!token) return "";
            try { token = decodeURIComponent(token); } catch (e) {}
            return token.trim();
        }

        function resolveFindingKeyFromToken(token) {
            var normalized = String(token || "").trim().toLowerCase();
            if (!normalized) return "";
            for (var i = 0; i < findings.length; i++) {
                var key = getFindingKey(findings[i]);
                if (String(key || "").toLowerCase() === normalized) return key;
            }
            return "";
        }

        function getFindingScrollOffset() {
            var offset = 120;
            if (typeof getNavOffset === "function") {
                try {
                    offset = getNavOffset();
                } catch (e) {}
            } else {
                try {
                    var raw = getComputedStyle(document.documentElement).getPropertyValue("--report-header-offset") || "";
                    var parsed = parseInt(String(raw).trim(), 10);
                    if (!isNaN(parsed)) offset = parsed;
                } catch (e) {}
            }
            return Math.max(60, offset + 8);
        }

        function focusFindingCardByKey(findingKey) {
            var root = document.getElementById("findingsRoot");
            if (!root || !findingKey) return false;
            var cards = root.querySelectorAll(".finding-card");
            var targetCard = null;
            Array.prototype.forEach.call(cards, function (card) {
                if (targetCard) return;
                var cardKey = card.getAttribute("data-finding-key");
                if (String(cardKey || "").toLowerCase() === String(findingKey).toLowerCase()) {
                    targetCard = card;
                }
            });
            if (!targetCard) return false;

            Array.prototype.forEach.call(root.querySelectorAll(".finding-card.hash-target"), function (card) {
                card.classList.remove("hash-target");
            });

            if (!targetCard.classList.contains("expanded")) {
                targetCard.classList.add("expanded");
                var toggle = targetCard.querySelector(".finding-toggle");
                if (toggle) toggle.setAttribute("aria-expanded", "true");
                if (targetCard._ensureAffectedPanelBuilt) targetCard._ensureAffectedPanelBuilt();
            }

            targetCard.classList.add("hash-target");
            var hashTargetCleaned = false;
            var cleanupHashTarget = function () {
                if (hashTargetCleaned) return;
                hashTargetCleaned = true;
                targetCard.classList.remove("hash-target");
                targetCard.removeEventListener("animationend", cleanupHashTarget);
            };
            targetCard.addEventListener("animationend", cleanupHashTarget);
            setTimeout(cleanupHashTarget, 2200);
            targetCard.style.scrollMarginTop = getFindingScrollOffset() + "px";
            try {
                targetCard.scrollIntoView({ behavior: "smooth", block: "start" });
            } catch (e) {
                targetCard.scrollIntoView();
            }
            return true;
        }

        function navigateToHashFinding() {
            var token = getHashFindingToken();
            if (!token) {
                if (forcedVisibleFindingKey) {
                    clearForcedFindingReveal();
                    applyFilters();
                }
                return;
            }

            var resolvedKey = resolveFindingKeyFromToken(token);
            if (!resolvedKey) {
                if (forcedVisibleFindingKey) {
                    clearForcedFindingReveal();
                    applyFilters();
                }
                return;
            }

            if (focusFindingCardByKey(resolvedKey)) {
                if (forcedVisibleFindingKey && String(forcedVisibleFindingKey).toLowerCase() !== String(resolvedKey).toLowerCase()) {
                    clearForcedFindingReveal();
                    applyFilters();
                    focusFindingCardByKey(resolvedKey);
                }
                return;
            }
            forcedVisibleFindingKey = resolvedKey;
            applyFilters();
            focusFindingCardByKey(resolvedKey);
        }

        window.addEventListener("hashchange", function () {
            navigateToHashFinding();
        });

        var toggleAllBtn = document.getElementById("btnToggleAll");
        if (toggleAllBtn) {
            toggleAllBtn.addEventListener("click", function () {
                var cards = document.querySelectorAll(".finding-card");
                var shouldExpand = false;
                Array.prototype.forEach.call(cards, function (card) {
                    if (!card.classList.contains("expanded")) shouldExpand = true;
                });
                Array.prototype.forEach.call(cards, function (card) {
                    if (shouldExpand) {
                        card.classList.add("expanded");
                        var toggle = card.querySelector(".finding-toggle");
                        if (toggle) toggle.setAttribute("aria-expanded", "true");
                        if (card._ensureAffectedPanelBuilt) card._ensureAffectedPanelBuilt();
                    } else {
                        card.classList.remove("expanded");
                        var toggleCollapsed = card.querySelector(".finding-toggle");
                        if (toggleCollapsed) toggleCollapsed.setAttribute("aria-expanded", "false");
                    }
                });
                toggleAllBtn.textContent = shouldExpand ? "Collapse all" : "Expand all";
            });
        }

        var exportBtn = document.getElementById("btnExport");
        var exportMenu = document.getElementById("exportMenu");
        var exportCsvFilteredBtn = document.getElementById("exportCsvFiltered");
        var exportCsvAllBtn = document.getElementById("exportCsvAll");
        var exportJsonFilteredBtn = document.getElementById("exportJsonFiltered");
        var exportJsonAllBtn = document.getElementById("exportJsonAll");
        var exportPdfVisibleBtn = document.getElementById("exportPdfVisible");

        function closeExportMenu() {
            if (!exportMenu || !exportBtn) return;
            exportMenu.classList.add("hidden");
            exportBtn.setAttribute("aria-expanded", "false");
        }

        function toggleExportMenu() {
            if (!exportMenu || !exportBtn) return;
            var isHidden = exportMenu.classList.contains("hidden");
            if (isHidden) {
                exportMenu.classList.remove("hidden");
                exportBtn.setAttribute("aria-expanded", "true");
            } else {
                closeExportMenu();
            }
        }

        if (exportBtn && exportMenu) {
            exportBtn.addEventListener("click", function (event) {
                event.stopPropagation();
                toggleExportMenu();
            });

            document.addEventListener("click", function (event) {
                if (!exportMenu.contains(event.target) && event.target !== exportBtn) {
                    closeExportMenu();
                }
            });

            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape") closeExportMenu();
            });
        }

        if (exportCsvFilteredBtn) {
            exportCsvFilteredBtn.addEventListener("click", function () {
                exportCsv(lastVisibleFindings || [], "filtered");
                closeExportMenu();
            });
        }

        if (exportCsvAllBtn) {
            exportCsvAllBtn.addEventListener("click", function () {
                exportCsv(findings || [], "all");
                closeExportMenu();
            });
        }

        if (exportJsonFilteredBtn) {
            exportJsonFilteredBtn.addEventListener("click", function () {
                exportJson(lastVisibleFindings || [], "filtered");
                closeExportMenu();
            });
        }

        if (exportJsonAllBtn) {
            exportJsonAllBtn.addEventListener("click", function () {
                exportJson(findings || [], "all");
                closeExportMenu();
            });
        }

        if (exportPdfVisibleBtn) {
            exportPdfVisibleBtn.addEventListener("click", function () {
                exportPdfClean();
                closeExportMenu();
            });
        }

        function matchesFilters(finding) {
            var findingKey = getFindingKey(finding);
            if (forcedVisibleFindingKey && String(findingKey || "").toLowerCase() === String(forcedVisibleFindingKey).toLowerCase()) {
                return true;
            }
            if (!matchesSearchQuery(finding)) return false;

            if (filterState.findingStatus.size && !filterState.findingStatus.has(getFindingStatusFilterValue(finding))) return false;
            if (filterState.category.size && !filterState.category.has(finding.Category)) return false;
            if (filterState.severity.size && !filterState.severity.has(finding.Severity)) return false;
            if (filterState.confidence.size && !filterState.confidence.has(finding.Confidence)) return false;

            var state = getStateFor(finding);
            if (filterState.status.has("HideFalsePositive") && state.FalsePositive) return false;
            if (filterState.status.has("HideFixing") && state.Fixing) return false;
            if (filterState.status.has("HideResolved") && state.Resolved) return false;
            if (filterState.status.has("HideAccepted") && state.AcceptedRisk) return false;
            if (filterState.status.has("ShowImportant") && !state.Important) return false;
            if (filterState.status.has("ShowConfirmed") && !state.Confirmed) return false;
            if (filterState.status.has("ShowNeedsReview") && !state.NeedsReview) return false;
            if (filterState.status.has("ShowTaggedOnly") && !hasAnyTagState(state)) return false;

            return true;
        }

        function matchesFiltersForScore(finding) {
            if (!matchesSearchQuery(finding)) return false;

            if (filterState.category.size && !filterState.category.has(finding.Category)) return false;
            if (filterState.severity.size && !filterState.severity.has(finding.Severity)) return false;
            if (filterState.confidence.size && !filterState.confidence.has(finding.Confidence)) return false;

            var state = getStateFor(finding);
            if (filterState.status.has("HideFalsePositive") && state.FalsePositive) return false;
            if (filterState.status.has("HideFixing") && state.Fixing) return false;
            if (filterState.status.has("HideResolved") && state.Resolved) return false;
            if (filterState.status.has("HideAccepted") && state.AcceptedRisk) return false;
            if (filterState.status.has("ShowImportant") && !state.Important) return false;
            if (filterState.status.has("ShowConfirmed") && !state.Confirmed) return false;
            if (filterState.status.has("ShowNeedsReview") && !state.NeedsReview) return false;
            if (filterState.status.has("ShowTaggedOnly") && !hasAnyTagState(state)) return false;

            return true;
        }

        function matchesFiltersForOverviewMetrics(finding, ignoreFindingStatus) {
            if (!matchesSearchQuery(finding)) return false;

            if (!ignoreFindingStatus && filterState.findingStatus.size && !filterState.findingStatus.has(getFindingStatusFilterValue(finding))) return false;
            if (filterState.category.size && !filterState.category.has(finding.Category)) return false;
            if (filterState.severity.size && !filterState.severity.has(finding.Severity)) return false;
            if (filterState.confidence.size && !filterState.confidence.has(finding.Confidence)) return false;

            var state = getStateFor(finding);
            if (filterState.status.has("ShowImportant") && !state.Important) return false;
            if (filterState.status.has("ShowConfirmed") && !state.Confirmed) return false;
            if (filterState.status.has("ShowNeedsReview") && !state.NeedsReview) return false;
            if (filterState.status.has("ShowTaggedOnly") && !hasAnyTagState(state)) return false;

            return true;
        }

        function renderSummary(visibleFindings) {
            var host = document.getElementById("findingsSummary");
            if (!host) return;
            host.innerHTML = "";

            var severityCounts = {};
            var categoryCounts = {};
            var categoryPoints = {};
            var categorySeverityCounts = {};
            var categoryPossible = {};
            var statusCounts = { falsePositive: 0, fixing: 0, resolved: 0, important: 0, confirmed: 0, needsReview: 0, acceptedRisk: 0, other: 0 };
            var certaintyCounts = {};
            var overviewFindingCounts = { Vulnerable: 0, NotVulnerable: 0, Skipped: 0 };
            var visibleRiskPoints = 0;
            var totalPossible = 0;
            var chartScopeFindings = findings.filter(function (finding) {
                return matchesFiltersNoVulnGate(finding, "findingStatus");
            });
            var overviewMetricFindings = findings.filter(function (finding) {
                return matchesFiltersForOverviewMetrics(finding, true);
            });

            findings.forEach(function (finding) {
                if (!matchesFiltersForOverviewMetrics(finding, true)) return;
                if (!isStatusCovered(finding)) return;
                var pts = severityPoints[finding.Severity] || 0;
                totalPossible += pts;
                categoryPossible[finding.Category] = (categoryPossible[finding.Category] || 0) + pts;
            });

            overviewMetricFindings.forEach(function (finding) {
                if (isStatusSkipped(finding)) {
                    overviewFindingCounts.Skipped += 1;
                } else if (isEffectivelyVulnerable(finding)) {
                    overviewFindingCounts.Vulnerable += 1;
                } else {
                    overviewFindingCounts.NotVulnerable += 1;
                }
            });

            chartScopeFindings.forEach(function (finding) {
                var statusState = getStateFor(finding);
                if (statusState.Important) statusCounts.important += 1;
                if (statusState.Confirmed) statusCounts.confirmed += 1;
                if (statusState.FalsePositive) statusCounts.falsePositive += 1;
                if (statusState.Fixing) statusCounts.fixing += 1;
                if (statusState.Resolved) statusCounts.resolved += 1;
                if (statusState.NeedsReview) statusCounts.needsReview += 1;
                if (statusState.AcceptedRisk) statusCounts.acceptedRisk += 1;
                if (!statusState.Important && !statusState.Confirmed && !statusState.FalsePositive && !statusState.Fixing && !statusState.Resolved && !statusState.NeedsReview && !statusState.AcceptedRisk) {
                    statusCounts.other += 1;
                }
            });

            overviewMetricFindings.forEach(function (finding) {
                if (isEffectivelyVulnerable(finding)) {
                    severityCounts[finding.Severity] = (severityCounts[finding.Severity] || 0) + 1;
                    categoryCounts[finding.Category] = (categoryCounts[finding.Category] || 0) + 1;
                    if (!categorySeverityCounts[finding.Category]) {
                        categorySeverityCounts[finding.Category] = {};
                    }
                    categorySeverityCounts[finding.Category][finding.Severity] =
                        (categorySeverityCounts[finding.Category][finding.Severity] || 0) + 1;
                    var pts = severityPoints[finding.Severity] || 0;
                    visibleRiskPoints += pts;
                    categoryPoints[finding.Category] = (categoryPoints[finding.Category] || 0) + pts;

                    var certaintyKey = finding.Confidence || "Unknown";
                    certaintyCounts[certaintyKey] = (certaintyCounts[certaintyKey] || 0) + 1;
                }
            });

            var scorePct = totalPossible > 0 ? Math.round(((totalPossible - visibleRiskPoints) / totalPossible) * 100) : 100;

            var visibleCountEl = document.getElementById("visibleCount");
            if (visibleCountEl) {
                visibleCountEl.textContent = "Visible findings: " + visibleFindings.length;
            }

            renderOverviewFindingKpis(overviewFindingCounts);
            renderOverviewCharts(
                scorePct,
                totalPossible - visibleRiskPoints,
                visibleRiskPoints,
                totalPossible,
                categoryPossible,
                categoryPoints,
                severityCounts,
                statusCounts,
                certaintyCounts,
                categorySeverityCounts
            );

        }

        function renderOverviewFindingKpis(counts) {
            var host = document.getElementById("overviewKpis");
            if (!host) return;

            var items = [
                { key: "Vulnerable", label: "Vulnerable", className: "vulnerable" },
                { key: "NotVulnerable", label: "Passed", className: "not-vulnerable" },
                { key: "Skipped", label: "Skipped", className: "skipped" }
            ];

            host.innerHTML = items.map(function (item) {
                var value = counts && typeof counts[item.key] === "number" ? counts[item.key] : 0;
                return '' +
                    '<div class="overview-kpi-card ' + item.className + '">' +
                        '<div class="overview-kpi-label">' + item.label + '</div>' +
                        '<div class="overview-kpi-value">' + value + '</div>' +
                    '</div>';
            }).join("");
        }

        function renderOverviewCharts(scorePct, coveredPoints, riskPoints, totalPossible, categoryPossible, categoryRisk, severityCounts, statusCounts, certaintyCounts, categorySeverityCounts) {
            if (typeof Chart === "undefined") return;

            severityCounts = severityCounts || {};
            statusCounts = statusCounts || { falsePositive: 0, fixing: 0, resolved: 0, important: 0, confirmed: 0, needsReview: 0, acceptedRisk: 0, other: 0 };
            certaintyCounts = certaintyCounts || {};
            categoryPossible = categoryPossible || {};
            categoryRisk = categoryRisk || {};
            categorySeverityCounts = categorySeverityCounts || {};

            overviewCharts.last = {
                scorePct: scorePct,
                coveredPoints: coveredPoints,
                riskPoints: riskPoints,
                totalPossible: totalPossible,
                categoryPossible: categoryPossible,
                categoryRisk: categoryRisk,
                severityCounts: severityCounts,
                statusCounts: statusCounts,
                certaintyCounts: certaintyCounts,
                categorySeverityCounts: categorySeverityCounts
            };

            var scoreCtx = document.getElementById("scoreChart");
            var categoryCoverageCtx = document.getElementById("categoryCoverageChart");
            var pointsCtx = document.getElementById("pointsChart");
            var severityCtx = document.getElementById("severityChart");
            var statusCtx = document.getElementById("statusChart");
            var certaintyCtx = document.getElementById("certaintyChart");
            if (!scoreCtx || !categoryCoverageCtx || !pointsCtx || !severityCtx || !statusCtx || !certaintyCtx) return;

            var isDark = document.body.classList.contains("dark-mode") && !forcePrintLightCharts;
            var textColor = isDark ? "rgba(255,255,255,0.85)" : "rgba(0,0,0,0.75)";
            var gridColor = isDark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)";

            var coveredColor = "rgba(90, 200, 120, 0.85)";
            var riskColor = "rgba(230, 90, 90, 0.85)";

            Chart.defaults.color = textColor;
            Chart.defaults.borderColor = gridColor;

            Chart.register({
                id: "centerText",
                beforeDraw: function (chart, args, options) {
                    var cfg = chart.config;
                    var text = cfg.options && cfg.options.plugins && cfg.options.plugins.centerText && cfg.options.plugins.centerText.text;
                    if (!text) return;
                    var ctx = chart.ctx;
                    var area = chart.chartArea;
                    if (!area) return;
                    var isDark = document.body.classList.contains("dark-mode") && !forcePrintLightCharts;
                    var centerColor = isDark ? "rgba(255,255,255,0.9)" : "rgba(0,0,0,0.75)";
                    ctx.save();
                    ctx.textAlign = "center";
                    ctx.textBaseline = "middle";
                    ctx.fillStyle = centerColor;
                    ctx.font = "bold 14px sans-serif";
                    ctx.fillText(text, (area.left + area.right) / 2, (area.top + area.bottom) / 2);
                    ctx.restore();
                }
            });

            if (overviewCharts.score) overviewCharts.score.destroy();
            if (overviewCharts.categoryCoverage) overviewCharts.categoryCoverage.destroy();
            if (overviewCharts.points) overviewCharts.points.destroy();
            if (overviewCharts.severity) overviewCharts.severity.destroy();
            if (overviewCharts.status) overviewCharts.status.destroy();
            if (overviewCharts.certainty) overviewCharts.certainty.destroy();

            overviewCharts.score = new Chart(scoreCtx, {
                type: "doughnut",
                data: {
                    labels: ["Covered points", "Vulnerable points"],
                    datasets: [{
                        data: [coveredPoints, riskPoints],
                        backgroundColor: [coveredColor, riskColor],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    plugins: {
                        legend: {
                            labels: { color: textColor },
                            onClick: function () {}
                        },
                        centerText: { text: "Score " + scorePct + "%" },
                        title: {
                            display: true,
                            text: "Weighted Coverage",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            var coverageCategories = Object.keys(categoryPossible || {}).sort();
            var coverageData = coverageCategories.map(function (cat) {
                var possible = categoryPossible[cat] || 0;
                var risk = categoryRisk[cat] || 0;
                if (possible <= 0) return 100;
                return Math.round(((possible - risk) / possible) * 100);
            });
            var coverageColors = [
                "rgba(90, 200, 120, 0.65)",
                "rgba(110, 210, 130, 0.65)",
                "rgba(70, 185, 115, 0.65)",
                "rgba(130, 215, 145, 0.65)",
                "rgba(80, 175, 110, 0.65)",
                "rgba(100, 205, 135, 0.65)"
            ];
            var coverageFill = coverageCategories.map(function (_, idx) {
                return coverageColors[idx % coverageColors.length];
            });

            overviewCharts.categoryCoverage = new Chart(categoryCoverageCtx, {
                type: "polarArea",
                data: {
                    labels: coverageCategories,
                    datasets: [{
                        label: "Coverage %",
                        data: coverageData,
                        backgroundColor: coverageFill,
                        borderColor: "rgba(90, 200, 120, 0.9)",
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        r: {
                            min: 0,
                            max: 100,
                            ticks: {
                                stepSize: 20,
                                callback: function (value) { return value + "%"; },
                                color: textColor,
                                showLabelBackdrop: false,
                                backdropColor: "rgba(0,0,0,0)"
                            },
                            grid: { color: gridColor },
                            angleLines: { color: gridColor },
                            pointLabels: {
                                display: true,
                                centerPointLabels: true,
                                padding: 4,
                                color: textColor,
                                font: { size: 12 }
                            }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                            text: "Weighted Coverage per Category",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            var categories = Object.keys(categorySeverityCounts || {}).sort();
            var severityColors = {
                4: "rgba(230, 90, 90, 0.85)",
                3: "rgba(245, 155, 95, 0.85)",
                2: "rgba(245, 200, 90, 0.85)",
                1: "rgba(120, 200, 140, 0.85)",
                0: "rgba(120, 170, 230, 0.85)"
            };
            var severityOrder = [4, 3, 2, 1, 0];
            var severityDatasets = severityOrder.map(function (sev) {
                return {
                    label: severityLabels[sev],
                    data: categories.map(function (cat) {
                        var bucket = categorySeverityCounts[cat] || {};
                        return bucket[sev] || 0;
                    }),
                    backgroundColor: severityColors[sev],
                    borderWidth: 0
                };
            });
            var pointsChartBox = pointsCtx.closest(".overview-chart-box");
            if (pointsChartBox) {
                var pointsChartMinHeight = 260;
                var pointsChartRowHeight = 28;
                var pointsChartPadding = 72;
                var pointsChartMaxHeight = 820;
                var pointsChartHeight = Math.min(
                    pointsChartMaxHeight,
                    Math.max(pointsChartMinHeight, pointsChartPadding + (categories.length * pointsChartRowHeight))
                );
                pointsChartBox.style.height = pointsChartHeight + "px";
            }

            overviewCharts.points = new Chart(pointsCtx, {
                type: "bar",
                data: {
                    labels: categories,
                    datasets: severityDatasets
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        x: { stacked: true, ticks: { color: textColor, precision: 0 }, grid: { color: gridColor } },
                        y: { stacked: true, ticks: { color: textColor }, grid: { color: gridColor } }
                    },
                    plugins: {
                        legend: { labels: { color: textColor } },
                        title: {
                            display: true,
                            text: "Findings by Category",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            var sevLabels = ["Critical", "High", "Medium", "Low", "Info"];
            var sevData = [
                severityCounts[4] || 0,
                severityCounts[3] || 0,
                severityCounts[2] || 0,
                severityCounts[1] || 0,
                severityCounts[0] || 0
            ];

            overviewCharts.severity = new Chart(severityCtx, {
                type: "bar",
                data: {
                    labels: sevLabels,
                    datasets: [{
                        label: "Findings",
                        data: sevData,
                        backgroundColor: [
                            "rgba(220, 80, 80, 0.85)",
                            "rgba(230, 130, 70, 0.85)",
                            "rgba(240, 200, 90, 0.85)",
                            "rgba(120, 200, 140, 0.85)",
                            "rgba(120, 160, 220, 0.85)"
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        x: { ticks: { color: textColor }, grid: { color: gridColor } },
                        y: { ticks: { color: textColor, precision: 0 }, grid: { color: gridColor } }
                    },
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                            text: "Severity Distribution",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            overviewCharts.status = new Chart(statusCtx, {
                type: "bar",
                data: {
                    labels: ["Confirmed", "False-positive", "Fixing", "Resolved", "Important", "Needs Review", "Accepted Risk"],
                    datasets: [{
                        label: "Findings",
                        data: [
                            statusCounts.confirmed || 0,
                            statusCounts.falsePositive || 0,
                            statusCounts.fixing || 0,
                            statusCounts.resolved || 0,
                            statusCounts.important || 0,
                            statusCounts.needsReview || 0,
                            statusCounts.acceptedRisk || 0
                        ],
                        backgroundColor: [
                            "rgba(120, 230, 180, 0.85)",
                            "rgba(255, 200, 90, 0.85)",
                            "rgba(190, 170, 255, 0.85)",
                            "rgba(120, 170, 255, 0.85)",
                            "rgba(255, 170, 120, 0.85)",
                            "rgba(145, 180, 255, 0.85)",
                            "rgba(180, 205, 120, 0.85)"
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        x: { ticks: { color: textColor }, grid: { color: gridColor } },
                        y: { ticks: { color: textColor, precision: 0 }, grid: { color: gridColor } }
                    },
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                            text: "Tags",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            // Keep confidence chart focused on supported confidence states.
            var certaintyOrder = ["Sure", "Requires Verification"];
            var certaintyData = certaintyOrder.map(function (key) {
                return certaintyCounts[key] || 0;
            });

            overviewCharts.certainty = new Chart(certaintyCtx, {
                type: "bar",
                data: {
                    labels: certaintyOrder,
                    datasets: [{
                        label: "Vulnerable findings",
                        data: certaintyData,
                        backgroundColor: [
                            "rgba(120, 200, 140, 0.85)",
                            "rgba(170, 200, 120, 0.85)"
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        x: { ticks: { color: textColor }, grid: { color: gridColor } },
                        y: { ticks: { color: textColor, precision: 0 }, grid: { color: gridColor } }
                    },
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                        text: "Confidence",
                            color: textColor,
                            font: { size: 14 }
                        }
                    }
                }
            });

            if (!overviewCharts.observer && document.body) {
                overviewCharts.observer = new MutationObserver(function () {
                    var last = overviewCharts.last;
                    if (!last) return;
                    renderOverviewCharts(
                        last.scorePct,
                        last.coveredPoints,
                        last.riskPoints,
                        last.totalPossible,
                        last.categoryPossible,
                        last.categoryRisk,
                        last.severityCounts,
                        last.statusCounts,
                        last.certaintyCounts,
                        last.categorySeverityCounts
                    );
                });
                overviewCharts.observer.observe(document.body, { attributes: true, attributeFilter: ["class"] });
            }
        }

        function applyFilters(expandedKeys) {
            var root = document.getElementById("findingsRoot");
            if (!root) return;
            root.innerHTML = "";

            var grouped = {};
            findings.forEach(function (finding) {
                var groupKey = "Uncategorized";
                if (sortState.key === "severity") {
                    groupKey = severityLabels[finding.Severity];
                } else if (sortState.key === "title") {
                    groupKey = "All findings";
                } else if (sortState.key === "confidence") {
                    groupKey = finding.Confidence || "Inconclusive";
                } else {
                    groupKey = finding.Category;
                }

                if (!grouped[groupKey]) grouped[groupKey] = [];
                grouped[groupKey].push(finding);
            });

            var categories = Object.keys(grouped);
            if (sortState.key === "severity") {
                categories.sort(function (a, b) {
                    var order = { "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0 };
                    return (order[b] || 0) - (order[a] || 0);
                });
            } else if (sortState.key === "confidence") {
                categories.sort(function (a, b) {
                    return confidenceOrder(a) - confidenceOrder(b);
                });
            } else if (sortState.key === "title") {
                categories = ["All findings"];
            } else {
                categories.sort();
            }
            var visibleCount = 0;
            var visibleFindings = [];

            categories.forEach(function (category) {
                var items = sortFindings(grouped[category], sortState.key);

                var section = buildElement("section", "finding-category");
                var headerWrap = buildElement("div", "category-header");
                var header = buildElement("h2", null, category);
                headerWrap.appendChild(header);

                var list = buildElement("div", "finding-list");
                var categoryVisible = 0;
                var categoryVulnerable = 0;
                var categoryEligible = 0;
                var categorySkipped = 0;
                var categoryPossiblePoints = 0;
                var categoryRiskPoints = 0;

                items.forEach(function (finding) {
                    // Keep section stats independent from STATUS (Vulnerable/NotVulnerable/Skipped) filter.
                    if (matchesFiltersNoVulnGate(finding, "findingStatus")) {
                        if (isStatusSkipped(finding)) {
                            categorySkipped += 1;
                        } else {
                            categoryEligible += 1;
                            var pts = severityPoints[finding.Severity] || 0;
                            categoryPossiblePoints += pts;
                            if (isEffectivelyVulnerable(finding)) {
                                categoryVulnerable += 1;
                                categoryRiskPoints += pts;
                            }
                        }
                    }

                    if (!matchesFilters(finding)) return;

                    var card = getOrCreateFindingCard(finding);
                    list.appendChild(card);
                    categoryVisible += 1;
                    visibleCount += 1;
                    visibleFindings.push(finding);
                });

                if (categoryVisible > 0) {
                    var categoryCoverage = 100;
                    if (categoryPossiblePoints > 0) {
                        categoryCoverage = Math.round(((categoryPossiblePoints - categoryRiskPoints) / categoryPossiblePoints) * 100);
                    }
                    var categorySummary = buildElement("div", "category-summary");
                    var vulnChip = buildElement("span", "summary-chip vuln", "\u26A0\uFE0F " + categoryVulnerable);
                    vulnChip.title = "Vulnerable findings";
                    categorySummary.appendChild(vulnChip);
                    var okChip = buildElement("span", "summary-chip ok", "\u2705 " + Math.max(0, categoryEligible - categoryVulnerable));
                    okChip.title = "Not vulnerable findings";
                    categorySummary.appendChild(okChip);
                    var skipChip = buildElement("span", "summary-chip skipped", "\u23ED\uFE0F " + categorySkipped);
                    skipChip.title = "Skipped findings";
                    categorySummary.appendChild(skipChip);
                    var covChip = buildElement("span", "summary-chip coverage", "\uD83C\uDFAF " + categoryCoverage + "%");
                    covChip.title = "Weighted Coverage for this category";
                    covChip.style.borderColor = getCoverageColor(categoryCoverage, 0.85);
                    covChip.style.color = getCoverageColor(categoryCoverage, 0.95);
                    categorySummary.appendChild(covChip);
                    var bar = buildElement("div", "category-coverage-bar");
                    bar.title = "Weighted Coverage for this category";
                    var fill = buildElement("div", "category-coverage-fill");
                    fill.style.width = Math.max(0, Math.min(100, categoryCoverage)) + "%";
                    fill.style.background = getCoverageColor(categoryCoverage, 0.92);
                    bar.appendChild(fill);
                    categorySummary.appendChild(bar);
                    headerWrap.appendChild(categorySummary);
                    section.appendChild(headerWrap);
                    section.appendChild(list);
                    root.appendChild(section);
                }
            });

            if (visibleCount === 0) {
                root.appendChild(buildElement("div", "finding-empty", "No findings match the current filters."));
            }

            lastVisibleFindings = visibleFindings;
            var currentSummaryFingerprint = buildSummaryFingerprint(visibleFindings);
            if (currentSummaryFingerprint !== lastSummaryFingerprint) {
                renderSummary(visibleFindings);
                lastSummaryFingerprint = currentSummaryFingerprint;
            }
            updateFilterCounts();
            ensureHeadingIds();
            rebuildSectionStrip();

            if (expandedKeys && expandedKeys.size) {
                root.querySelectorAll(".finding-card").forEach(function (card) {
                    var key = card.getAttribute("data-finding-key");
                    if (key && expandedKeys.has(key)) {
                        card.classList.add("expanded");
                        var toggle = card.querySelector(".finding-toggle");
                        if (toggle) toggle.setAttribute("aria-expanded", "true");
                        if (card._ensureAffectedPanelBuilt) card._ensureAffectedPanelBuilt();
                    }
                });
            }

            var loadingOverlay = document.getElementById("loadingOverlay");
            if (loadingOverlay) loadingOverlay.style.display = "none";
        }

        applyFilters();
        navigateToHashFinding();
    })();
</script>
'@

    $headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<div class="tenant-report-wrap" data-report-id="$ReportId">
<h2>Overview</h2>
<details id="overviewPanel" class="top-panel" open>
<summary aria-label="Toggle overview section"></summary>
<div id="overviewKpis" class="overview-kpis"></div>
<div class="overview-charts primary">
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Weighted Coverage help" aria-expanded="false" aria-controls="scoreChartHelp">?</button>
    <div id="scoreChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Weighted Coverage help">
      <div class="chart-help-title">Weighted Coverage</div>
      <ul class="chart-help-list">
        <li>Shows the severity-weighted share of covered findings.</li>
        <li>Uses Critical=10, High=7, Medium=3, Low=1, Info=0.</li>
        <li>False-positive and resolved findings increase the coverages.</li>
      </ul>
    </div>
    <canvas id="scoreChart"></canvas>
  </div>
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Weighted Coverage per Category help" aria-expanded="false" aria-controls="categoryCoverageChartHelp">?</button>
    <div id="categoryCoverageChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Weighted Coverage per Category help">
      <div class="chart-help-title">Weighted Coverage per Category</div>
      <ul class="chart-help-list">
        <li>Breaks the weighted coverage score down by finding category.</li>
        <li>Higher percentages mean fewer effective issues remain in that category.</li>
        <li>Uses the same severity weights and skipped-item exclusion as the main score.</li>
      </ul>
    </div>
    <canvas id="categoryCoverageChart"></canvas>
  </div>
</div>
<div class="overview-charts full">
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Findings by Category help" aria-expanded="false" aria-controls="pointsChartHelp">?</button>
    <div id="pointsChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Findings by Category help">
      <div class="chart-help-title">Findings by Category</div>
      <ul class="chart-help-list">
        <li>Shows effectively vulnerable findings grouped by category and split by severity.</li>
        <li>Useful for seeing where the most findings are concentrated.</li>
        <li>False-positive and resolved findings are excluded from this chart.</li>
      </ul>
    </div>
    <canvas id="pointsChart"></canvas>
  </div>
</div>
<div class="overview-charts">
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Severity Distribution help" aria-expanded="false" aria-controls="severityChartHelp">?</button>
    <div id="severityChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Severity Distribution help">
      <div class="chart-help-title">Severity Distribution</div>
      <ul class="chart-help-list">
        <li>Counts effectively vulnerable findings by severity.</li>
        <li>False-positive and resolved findings are excluded from this chart.</li>
      </ul>
    </div>
    <canvas id="severityChart"></canvas>
  </div>
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Tags Overview help" aria-expanded="false" aria-controls="statusChartHelp">?</button>
    <div id="statusChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Tags Overview help">
      <div class="chart-help-title">Tags Overview</div>
      <ul class="chart-help-list">
        <li>Shows tag counts across findings in the current overview scope.</li>
      </ul>
    </div>
    <canvas id="statusChart"></canvas>
  </div>
  <div class="overview-chart-box">
    <button type="button" class="chart-help-btn" aria-label="Confidence help" aria-expanded="false" aria-controls="certaintyChartHelp">?</button>
    <div id="certaintyChartHelp" class="chart-help-popover hidden" role="dialog" aria-label="Confidence help">
      <div class="chart-help-title">Confidence</div>
      <ul class="chart-help-list">
        <li>Shows confidence levels for effectively vulnerable findings.</li>
        <li>Helps separate strong findings from those that may need verification.</li>
      </ul>
    </div>
    <canvas id="certaintyChart"></canvas>
  </div>
</div>
</details>
<h2>Filters</h2>
<details id="filtersPanel" class="top-panel" open>
<summary aria-label="Toggle filters section"></summary>
<div class="finding-controls">
  <div class="finding-controls-row quick-row">
    <div class="search-box">
      <label class="sr-only" for="findingSearch">Search findings</label>
      <input id="findingSearch" type="search" placeholder="Search findings..." />
      <button id="searchHelpToggle" type="button" class="search-help-btn" aria-label="Search syntax help" aria-expanded="false" aria-controls="searchHelpPopover">?</button>
      <div id="searchHelpPopover" class="search-help-popover hidden" role="dialog" aria-label="Search syntax guide">
        <div class="search-help-title">Search guide</div>
        <ul class="search-help-list">
          <li><code>word</code> = find term</li>
          <li><code>"exact phrase"</code> = exact match</li>
          <li><code>term1 term2</code> = AND</li>
          <li><code>term1 OR term2</code> or <code>term1 | term2</code> = OR</li>
          <li><code>!term</code> = exclude term</li>
          <li>Use <strong>Fields</strong> to limit search scope</li>
          <li>Case-insensitive search</li>
          <li>Searches title, ID, description, threat, remediation, affected objects</li>
        </ul>
        <div class="search-help-example"><strong>Example:</strong> <code>"tier-0 role" OR "global admin" !guest</code></div>
      </div>
    </div>
    <div class="search-fields-menu">
      <button id="searchFieldsToggle" type="button" aria-haspopup="true" aria-expanded="false" aria-controls="searchFieldsMenu">Fields: All</button>
      <div id="searchFieldsMenu" class="search-fields-panel hidden" role="menu" aria-label="Search fields">
        <div class="search-fields-actions">
          <button id="searchFieldsSelectAll" type="button">Select all</button>
          <button id="searchFieldsDeselectAll" type="button">Deselect all</button>
        </div>
        <label><input type="checkbox" data-search-field="id" checked /> ID</label>
        <label><input type="checkbox" data-search-field="title" checked /> Title</label>
        <label><input type="checkbox" data-search-field="description" checked /> Description</label>
        <label><input type="checkbox" data-search-field="threat" checked /> Threat</label>
        <label><input type="checkbox" data-search-field="remediation" checked /> Remediation</label>
        <label><input type="checkbox" data-search-field="affected" checked /> Affected objects</label>
        <div class="search-fields-note">If none selected, all fields are used.</div>
      </div>
    </div>
    <div id="visibleCount" class="finding-count">Visible findings: 0</div>
    <div class="export-menu">
      <button id="btnExport" type="button" aria-haspopup="true" aria-expanded="false">Export</button>
      <div id="exportMenu" class="export-menu-panel hidden" role="menu">
        <button id="exportCsvFiltered" type="button" role="menuitem">CSV (Filtered)</button>
        <button id="exportCsvAll" type="button" role="menuitem">CSV (All)</button>
        <button id="exportJsonFiltered" type="button" role="menuitem">JSON (Filtered)</button>
        <button id="exportJsonAll" type="button" role="menuitem">JSON (All)</button>
        <button id="exportPdfVisible" type="button" role="menuitem">PDF (Visible)</button>
      </div>
    </div>
  </div>
  <div class="finding-controls-row advanced-row">
    <label>
      Group by
      <select id="findingSort">
        <option value="category" selected>Category</option>
        <option value="severity">Severity</option>
        <option value="title">Title</option>
        <option value="confidence">Confidence</option>
      </select>
    </label>
    <button id="btnToggleAll" type="button">Expand all</button>
    <button id="btnClearFilters" type="button">Clear filters</button>
    <button id="btnClearTags" type="button" aria-haspopup="true" aria-expanded="false" aria-controls="clearTagsConfirm">Clear tags</button>
    <div id="clearTagsConfirm" class="inline-confirm hidden" role="dialog" aria-label="Confirm clear tags">
      <span>Clear all tags?</span>
      <button id="btnClearTagsYes" type="button">Clear</button>
      <button id="btnClearTagsNo" type="button">Cancel</button>
    </div>
  </div>
  <div id="findingFilters" class="finding-filters"></div>
</div>
</details>
<div id="findingsSummary" class="finding-summary"></div>
<script>
(() => {
  const root = document.querySelector(".tenant-report-wrap");
  const reportId = root?.getAttribute("data-report-id") || "tenant-report";
  const key = "EntraFalcon_panelState_" + reportId;
  const filtersPanel = document.getElementById("filtersPanel");
  const overviewPanel = document.getElementById("overviewPanel");
  if (!filtersPanel || !overviewPanel) return;

  const read = () => {
    try { return JSON.parse(localStorage.getItem(key) || "{}"); } catch { return {}; }
  };
  const write = () => {
    const state = {
      filtersOpen: !!filtersPanel.open,
      overviewOpen: !!overviewPanel.open
    };
    localStorage.setItem(key, JSON.stringify(state));
  };

  const state = read();
  if (state.filtersOpen === false) filtersPanel.open = false;
  if (state.overviewOpen === false) overviewPanel.open = false;

  filtersPanel.addEventListener("toggle", write);
  overviewPanel.addEventListener("toggle", write);
})();
</script>
<script id="findingsData" type="application/json">
$FindingsJson
</script>
<div id="findingsRoot" data-report-id="$ReportId" data-start-timestamp="$StartTimestamp" data-tenant-name="$($CurrentTenant.DisplayName)"></div>
</div>
"@

    Set-GlobalReportManifest -CurrentReportKey $ReportKey -CurrentReportName $ReportName
    $HeadCombined = "<title>EF - Security Findings</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss + $extraCss
    $PostContentCombined = $global:GLOBALJavaScript_Nav + "`n" + $chartJsEmbedded + "`n" + $customScript

    $statusCounts = @{
        Vulnerable = 0
        NotVulnerable = 0
        Skipped = 0
    }
    foreach ($finding in $Findings) {
        $status = "$($finding.Status)".Trim()
        switch ($status) {
            "Vulnerable" { $statusCounts.Vulnerable++; break }
            "NotVulnerable" { $statusCounts.NotVulnerable++; break }
            "Skipped" { $statusCounts.Skipped++; break }
            default { break }
        }
    }
    Write-Log -Level Debug -Message ("Final status counts: Vulnerable={0}; NotVulnerable={1}; Skipped={2}; Total={3}" -f `
        $statusCounts.Vulnerable, $statusCounts.NotVulnerable, $statusCounts.Skipped, $Findings.Count)
    if ($null -eq $global:GlobalAuditSummary.SecurityFindings) {
        $global:GlobalAuditSummary.SecurityFindings = @{ Vulnerable = 0; NotVulnerable = 0; Skipped = 0; Total = 0 }
    }
    $global:GlobalAuditSummary.SecurityFindings.Vulnerable = $statusCounts.Vulnerable
    $global:GlobalAuditSummary.SecurityFindings.NotVulnerable = $statusCounts.NotVulnerable
    $global:GlobalAuditSummary.SecurityFindings.Skipped = $statusCounts.Skipped
    $global:GlobalAuditSummary.SecurityFindings.Total = $Findings.Count

    $reportPath = Join-Path $OutputFolder "$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"
    Write-Log -Level Debug -Message "Writing report file: $reportPath"

    $Report = ConvertTo-HTML -Body $headerHtml -Head $HeadCombined -PostContent $PostContentCombined
    $Report | Out-File $reportPath
    return $Findings
    #endregion
}


