<#
.SYNOPSIS
   Enumerate CAPs

#>
function Invoke-CheckCaps {
    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$false)][switch]$Csv = $false,
        [Parameter(Mandatory=$false)][switch]$ExportCapUncoveredUsers = $false
    )


    ############################## Function section ########################

    # Cache group-to-user expansion once per group ID.
    # CAP evaluation often reuses the same large groups across multiple policies and role assignments.
    # Keeping the expanded metrics in memory avoids repeatedly walking the same member lists.
    $GroupUsersMetricsCache = @{}

    #Function to check if a string is a GUID
    function Test-IsGuid {
        param (
            [string]$Value
        )

        try {
            $null = [guid]$Value
            return $true
        } catch {
            return $false
        }
    }
        
    # Function to check if an object is empty, considering nested properties
    function Is-Empty {
        param ([Object]$Obj)

        if ($null -eq $Obj -or $Obj -eq "") {
            return $true
        }

        if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
            foreach ($item in $Obj) {
                if (-not (Is-Empty $item)) {
                    return $false
                }
            }
            return $true
        }

        if ($Obj -is [PSCustomObject]) {
            foreach ($property in $Obj.PSObject.Properties) {
                if (-not (Is-Empty $property.Value)) {
                    return $false
                }
            }
            return $true
        }

        return $false
    }

    function Test-CapSelectorHasConfiguredValue {
        param (
            [Parameter(Mandatory=$false)]$InputObject,
            [Parameter(Mandatory=$true)][string]$PropertyName
        )

        if ($null -eq $InputObject) {
            return $false
        }

        $property = $InputObject.PSObject.Properties[$PropertyName]
        if ($null -eq $property) {
            return $false
        }

        foreach ($value in @($property.Value)) {
            if ($null -eq $value) { continue }
            $valueString = ([string]$value).Trim()
            if ([string]::IsNullOrWhiteSpace($valueString)) { continue }
            if ($valueString -eq "None") { continue }
            return $true
        }

        return $false
    }

    function Get-CapTargetType {
        param (
            [Parameter(Mandatory=$true)]$Policy
        )

        $conditions = $Policy.Conditions
        $agents = $conditions.Agents
        $clientApplications = $conditions.ClientApplications

        if (
            (Test-CapSelectorHasConfiguredValue -InputObject $agents -PropertyName "IncludeAgentUsers") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $agents -PropertyName "ExcludeAgentUsers") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $agents -PropertyName "AgentFilter") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $clientApplications -PropertyName "IncludeAgentIdServicePrincipals") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $clientApplications -PropertyName "ExcludeAgentIdServicePrincipals") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $conditions -PropertyName "AgentIdRiskLevels")
        ) {
            return "Agents"
        }

        if (
            (Test-CapSelectorHasConfiguredValue -InputObject $clientApplications -PropertyName "IncludeServicePrincipals") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $clientApplications -PropertyName "ExcludeServicePrincipals") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $clientApplications -PropertyName "ServicePrincipalFilter") -or
            (Test-CapSelectorHasConfiguredValue -InputObject $conditions -PropertyName "ServicePrincipalRiskLevels")
        ) {
            return "Workloads"
        }

        return "Users"
    }

    function Test-CapLegacyGuestsOrExternalUsersSelector {
        param (
            [Parameter(Mandatory=$false)][Object[]]$UserIds
        )

        foreach ($userId in @($UserIds)) {
            if ($null -eq $userId) { continue }
            if ("$userId".Trim().Equals("GuestsOrExternalUsers", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }

        return $false
    }

    function Remove-CapLegacyGuestsOrExternalUsersSelector {
        param (
            [Parameter(Mandatory=$false)][Object[]]$UserIds
        )

        return @(
            foreach ($userId in @($UserIds)) {
                if ($null -eq $userId) { continue }
                if ("$userId".Trim().Equals("GuestsOrExternalUsers", [System.StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }
                $userId
            }
        )
    }

    function Get-CapExternalSelector {
        param (
            [Parameter(Mandatory=$false)]$StructuredSelector,
            [Parameter(Mandatory=$false)][Object[]]$UserIds
        )

        if (-not (Test-CapLegacyGuestsOrExternalUsersSelector -UserIds $UserIds)) {
            return $StructuredSelector
        }

        $legacyExternalUserTypes = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
        $existingExternalUserTypes = ""
        $externalTenants = $null

        if ($null -ne $StructuredSelector) {
            if ($StructuredSelector.PSObject.Properties.Name -contains 'GuestOrExternalUserTypes') {
                $existingExternalUserTypes = [string]$StructuredSelector.GuestOrExternalUserTypes
            }
            if ($StructuredSelector.PSObject.Properties.Name -contains 'ExternalTenants') {
                $externalTenants = $StructuredSelector.ExternalTenants
            }
        }

        $externalUserTypes = @(
            ($existingExternalUserTypes, $legacyExternalUserTypes -join ",") -split "," |
            ForEach-Object { "$_".Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
        )

        $selector = [ordered]@{
            GuestOrExternalUserTypes = ($externalUserTypes -join ",")
            LegacyGuestsOrExternalUsersSelector = $true
        }
        if ($null -ne $externalTenants) {
            $selector.ExternalTenants = $externalTenants
        }

        return [pscustomobject]$selector
    }
        
    # Normalize direct include/exclude user selectors into count and user-id metrics.
    function Get-ExplicitUserMetrics {
        param (
            [Parameter(Mandatory=$false)][Object[]]$UserIds
        )

        $uniqueUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $hasAll = $false
        $hasNone = $false

        foreach ($userId in @($UserIds)) {
            if ($null -eq $userId) { continue }
            $userIdString = [string]$userId
            if ([string]::IsNullOrWhiteSpace($userIdString)) { continue }

            switch ($userIdString) {
                "All" {
                    $hasAll = $true
                    continue
                }
                "None" {
                    $hasNone = $true
                    continue
                }
            }

            if ($CapRelevantUserIds -and -not $CapRelevantUserIds.Contains($userIdString)) {
                continue
            }

            [void]$uniqueUserIds.Add($userIdString)
        }

        return [pscustomobject]@{
            UserIds = $uniqueUserIds
            Count   = $uniqueUserIds.Count
            HasAll  = $hasAll
            HasNone = $hasNone
        }
    }

    # Expand one group into active and eligible CAP-relevant users and cache the result.
    # The returned metrics object is treated as read-only by callers.
    function Get-GroupUsersMetricsCached {
        param (
            [Parameter(Mandatory=$true)][string]$GroupId
        )

        if ($GroupUsersMetricsCache.ContainsKey($GroupId)) {
            return $GroupUsersMetricsCache[$GroupId]
        }

        $groupMetrics = [pscustomobject]@{
            UserIds              = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            EligibleUserIds      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            FallbackGroups       = @{}
            Count                = 0
            EligibleCount        = 0
            Approximate          = $false
        }

        if ($AllGroupsDetails.ContainsKey($GroupId)) {
            $groupDetails = $AllGroupsDetails[$GroupId]
            $groupUserDetails = @($groupDetails.Userdetails)

            if ($groupUserDetails.Count -gt 0) {
                foreach ($groupUser in $groupUserDetails) {
                    $userIdString = [string]$groupUser.Id
                    if (-not [string]::IsNullOrWhiteSpace($userIdString) -and $CapRelevantUserIds.Contains($userIdString)) {
                        if ([string]$groupUser.AssignmentType -eq "Eligible") {
                            [void]$groupMetrics.EligibleUserIds.Add($userIdString)
                        } else {
                            [void]$groupMetrics.UserIds.Add($userIdString)
                        }
                    }
                }
            } else {
                $groupUsersRaw = $groupDetails.Users
                $groupUsers = 0
                if ($null -ne $groupUsersRaw -and [int]::TryParse([string]$groupUsersRaw, [ref]$groupUsers)) {
                    $groupMetrics.FallbackGroups[$GroupId] = $groupUsers
                    $groupDisplayName = if ($groupDetails.PSObject.Properties.Name -contains 'DisplayName') { [string]$groupDetails.DisplayName } else { "" }
                    $groupDisplayNameSuffix = if (-not [string]::IsNullOrWhiteSpace($groupDisplayName)) { " ($groupDisplayName)" } else { "" }
                    Write-Log -Level Trace -Message "CAP group fallback for '$GroupId'${groupDisplayNameSuffix}: using raw group user count=$groupUsers because no Userdetails were available."
                }
            }
        }

        $fallbackUsersCount = 0
        foreach ($fallbackUsers in $groupMetrics.FallbackGroups.Values) {
            $fallbackUsersCount += [int]$fallbackUsers
        }

        $groupMetrics.Count = $groupMetrics.UserIds.Count + $fallbackUsersCount
        $groupMetrics.EligibleCount = $groupMetrics.EligibleUserIds.Count
        $groupMetrics.Approximate = ($fallbackUsersCount -gt 0)
        $GroupUsersMetricsCache[$GroupId] = $groupMetrics
        return $groupMetrics
    }

    # Aggregate user impact across multiple targeted groups, including eligible PIM-for-Groups members.
    function Get-UsersThroughGroupsMetrics {
        param (
            [Parameter(Mandatory=$false)][Object[]]$GroupIds
        )

        $uniqueUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $eligibleUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fallbackGroups = @{}

        foreach ($groupId in @($GroupIds)) {
            if ($null -eq $groupId) { continue }
            $groupIdString = [string]$groupId
            if ([string]::IsNullOrWhiteSpace($groupIdString)) { continue }

            $groupMetrics = Get-GroupUsersMetricsCached -GroupId $groupIdString

            foreach ($userId in $groupMetrics.UserIds) {
                [void]$uniqueUserIds.Add([string]$userId)
            }

            foreach ($userId in $groupMetrics.EligibleUserIds) {
                [void]$eligibleUserIds.Add([string]$userId)
            }

            foreach ($fallbackEntry in $groupMetrics.FallbackGroups.GetEnumerator()) {
                $fallbackGroups[$fallbackEntry.Key] = $fallbackEntry.Value
            }
        }

        $fallbackUsersCount = 0
        foreach ($fallbackUsers in $fallbackGroups.Values) {
            $fallbackUsersCount += [int]$fallbackUsers
        }

        return [pscustomobject]@{
            UserIds          = $uniqueUserIds
            EligibleUserIds  = $eligibleUserIds
            FallbackGroups   = $fallbackGroups
            Count            = ($uniqueUserIds.Count + $fallbackUsersCount)
            EligibleCount    = $eligibleUserIds.Count
            Approximate      = ($fallbackUsersCount -gt 0)
        }
    }

    # Aggregate user impact across targeted roles using precomputed role-to-user lookups.
    function Get-UsersThroughRolesMetrics {
        param (
            [Parameter(Mandatory=$false)][Object[]]$RoleIds,
            [Parameter(Mandatory=$true)][hashtable]$RoleUsersLookup
        )

        $uniqueUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $eligibleUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fallbackUsersByGroup = @{}

        foreach ($roleId in @($RoleIds)) {
            if ($null -eq $roleId) { continue }
            $roleIdString = [string]$roleId
            if ([string]::IsNullOrWhiteSpace($roleIdString)) { continue }

            if ($RoleUsersLookup.ContainsKey($roleIdString)) {
                $roleImpact = $RoleUsersLookup[$roleIdString]

                foreach ($userId in $roleImpact.UserIds) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$userId)) {
                        [void]$uniqueUserIds.Add([string]$userId)
                    }
                }

                foreach ($userId in $roleImpact.EligibleUserIds) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$userId)) {
                        [void]$eligibleUserIds.Add([string]$userId)
                    }
                }

                foreach ($fallbackEntry in $roleImpact.FallbackGroups.GetEnumerator()) {
                    $fallbackUsersByGroup[$fallbackEntry.Key] = $fallbackEntry.Value
                }
            }
        }

        $fallbackUsersCount = 0
        foreach ($fallbackUsers in $fallbackUsersByGroup.Values) {
            $fallbackUsersCount += [int]$fallbackUsers
        }

        return [pscustomobject]@{
            UserIds         = $uniqueUserIds
            EligibleUserIds = $eligibleUserIds
            FallbackGroups  = $fallbackUsersByGroup
            Count           = ($uniqueUserIds.Count + $fallbackUsersCount)
            EligibleCount   = $eligibleUserIds.Count
            Approximate     = ($fallbackUsersCount -gt 0)
        }
    }

    # Resolve supported external-user categories into user metrics using cached tenant users.
    function Get-ExternalUserMetricsApprox {
        param (
            [Parameter(Mandatory=$false)][string]$GuestOrExternalUserTypes,
            [Parameter(Mandatory=$true)][hashtable]$ExternalUserLookup
        )

        $userIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $approximate = $false
        $normalizedTypes = @(
            "$GuestOrExternalUserTypes" -split "," |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
        )

        if ($normalizedTypes -contains "b2bcollaborationguest" -and $ExternalUserLookup.ContainsKey("b2bcollaborationguest")) {
            foreach ($userId in $ExternalUserLookup["b2bcollaborationguest"].UserIds) {
                [void]$userIds.Add([string]$userId)
            }
        }

        return [pscustomobject]@{
            UserIds     = $userIds
            Count       = $userIds.Count
            Approximate = $approximate
        }
    }

    # Inspect external-user selectors to identify cases where the concrete affected users
    # cannot be resolved from the data we have locally.
    function Get-ExternalTargetingResolution {
        param (
            [Parameter(Mandatory=$false)]$ExternalSelector
        )

        $guestOrExternalUserTypes = ""
        $externalTenants = $null
        $legacyGuestsOrExternalUsersSelector = $false

        if ($null -ne $ExternalSelector) {
            if ($ExternalSelector.PSObject.Properties.Name -contains 'GuestOrExternalUserTypes') {
                $guestOrExternalUserTypes = [string]$ExternalSelector.GuestOrExternalUserTypes
            }
            if ($ExternalSelector.PSObject.Properties.Name -contains 'ExternalTenants') {
                $externalTenants = $ExternalSelector.ExternalTenants
            }
            if ($ExternalSelector.PSObject.Properties.Name -contains 'LegacyGuestsOrExternalUsersSelector') {
                $legacyGuestsOrExternalUsersSelector = [bool]$ExternalSelector.LegacyGuestsOrExternalUsersSelector
            }
        }

        $normalizedTypes = @(
            "$guestOrExternalUserTypes" -split "," |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
        )

        $supportedTypes = @('b2bcollaborationguest')
        $unknownTypes = @($normalizedTypes | Where-Object { $_ -notin $supportedTypes })

        $membershipKind = ""
        $tenantMembers = @()
        if ($null -ne $externalTenants) {
            if ($externalTenants.PSObject.Properties.Name -contains 'MembershipKind') {
                $membershipKind = [string]$externalTenants.MembershipKind
            }
            if ($externalTenants.PSObject.Properties.Name -contains 'Members') {
                $tenantMembers = @($externalTenants.Members)
            }
        }

        $hasEnumeratedTenants = ("$membershipKind".Trim().ToLowerInvariant() -eq 'enumerated' -and $tenantMembers.Count -gt 0)

        return [pscustomobject]@{
            GuestOrExternalUserTypes   = $guestOrExternalUserTypes
            NormalizedTypes            = $normalizedTypes
            UnknownTypes               = $unknownTypes
            HasUnknownTypes            = ($unknownTypes.Count -gt 0)
            MembershipKind             = $membershipKind
            TenantMembers              = $tenantMembers
            TenantMembersCount         = $tenantMembers.Count
            HasEnumeratedTenants       = $hasEnumeratedTenants
            IsLegacyGuestsOrExternalUsersSelector = $legacyGuestsOrExternalUsersSelector
            RequiresVisualApproximation = (($unknownTypes.Count -gt 0) -or $hasEnumeratedTenants)
        }
    }

    # Merge direct, group, role, and external metrics into one effective targeting summary.
    function Merge-EffectiveTargetingMetrics {
        param (
            [Parameter(Mandatory=$true)]$DirectMetrics,
            [Parameter(Mandatory=$true)]$GroupMetrics,
            [Parameter(Mandatory=$true)]$RoleMetrics,
            [Parameter(Mandatory=$true)]$ExternalMetrics
        )

        $effectiveUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fallbackGroups = @{}

        foreach ($userId in $DirectMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $GroupMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $RoleMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $ExternalMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }

        foreach ($entry in $GroupMetrics.FallbackGroups.GetEnumerator()) {
            $fallbackGroups[$entry.Key] = $entry.Value
        }
        foreach ($entry in $RoleMetrics.FallbackGroups.GetEnumerator()) {
            if ($fallbackGroups.ContainsKey($entry.Key)) {
                $fallbackGroups[$entry.Key] = [Math]::Max([int]$fallbackGroups[$entry.Key], [int]$entry.Value)
            } else {
                $fallbackGroups[$entry.Key] = $entry.Value
            }
        }

        $fallbackUsersCount = 0
        foreach ($fallbackUsers in $fallbackGroups.Values) {
            $fallbackUsersCount += [int]$fallbackUsers
        }

        $effectiveCount = $effectiveUserIds.Count + $fallbackUsersCount
        $rawCount = [int]$DirectMetrics.Count + [int]$GroupMetrics.Count + [int]$RoleMetrics.Count + [int]$ExternalMetrics.Count
        $overlapCount = [Math]::Max(($rawCount - $effectiveCount), 0)
        $isApproximate = ($fallbackUsersCount -gt 0 -or [bool]$ExternalMetrics.Approximate)

        return [pscustomobject]@{
            EffectiveCount = $effectiveCount
            OverlapCount   = $overlapCount
            IsApproximate  = $isApproximate
        }
    }

    # Build the deduplicated effective user-id set for one targeting side.
    function Get-EffectiveTargetingUserIds {
        param (
            [Parameter(Mandatory=$true)]$DirectMetrics,
            [Parameter(Mandatory=$true)]$GroupMetrics,
            [Parameter(Mandatory=$true)]$RoleMetrics,
            [Parameter(Mandatory=$true)]$ExternalMetrics,
            [Parameter(Mandatory=$true)][System.Collections.Generic.HashSet[string]]$AllUserIds,
            [Parameter(Mandatory=$false)][bool]$HasAll = $false
        )

        $effectiveUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        if ($HasAll) {
            foreach ($userId in $AllUserIds) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }

        foreach ($userId in $DirectMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $GroupMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $RoleMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }
        foreach ($userId in $ExternalMetrics.UserIds) {
            if ($CapRelevantUserIds.Contains([string]$userId)) {
                [void]$effectiveUserIds.Add([string]$userId)
            }
        }

        # Return the HashSet as a single object so PowerShell does not enumerate it into an array.
        return ,$effectiveUserIds
    }

    # Sanitize policy names before using them in per-policy export file paths.
    function Get-SafeFileName {
        param (
            [Parameter(Mandatory=$true)][string]$Name
        )

        $safeName = "$Name"
        foreach ($invalidChar in [System.IO.Path]::GetInvalidFileNameChars()) {
            $safeName = $safeName.Replace([string]$invalidChar, "_")
        }

        $safeName = $safeName.Trim()
        if ([string]::IsNullOrWhiteSpace($safeName)) {
            return "Unnamed"
        }

        if ($safeName.Length -gt 120) {
            $safeName = $safeName.Substring(0, 120).Trim()
        }

        return $safeName
    }

    # Format user coverage percentages with guards for near-zero and near-100 rounding edge cases.
    function Format-UserCoverageValue {
        param (
            [Parameter(Mandatory=$true)][int]$EffectiveUsers,
            [Parameter(Mandatory=$true)][int]$TotalUsers
        )

        if ($TotalUsers -le 0) {
            return "0.0%"
        }

        $coveragePercent = ([double]$EffectiveUsers / [double]$TotalUsers) * 100
        $roundedCoverage = [Math]::Round($coveragePercent, 1)

        # Avoid misleading edge-case output such as 100.0% when exclusions exist but the
        # actual coverage only falls just below 100% and rounds up at one decimal place.
        if ($coveragePercent -lt 100 -and $roundedCoverage -ge 100) {
            return "99.9%"
        }

        # Mirror the same guard near zero so very small but non-zero coverage does not display as 0.0%.
        if ($coveragePercent -gt 0 -and $roundedCoverage -le 0) {
            return "0.1%"
        }

        return ("{0:0.0}%" -f $roundedCoverage)
    }

    # Prefix approximate displays without changing the numeric values used for calculations.
    function Format-ApproximateDisplayValue {
        param (
            [Parameter(Mandatory=$false)]$Value,
            [Parameter(Mandatory=$false)][bool]$Approximate = $false
        )

        if (-not $Approximate -or $null -eq $Value) {
            return $Value
        }

        $displayValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($displayValue)) {
            return $Value
        }

        if ($displayValue.StartsWith('~')) {
            return $displayValue
        }

        return "~$displayValue"
    }

    # Prefix approximate breakdown cells without altering exact zero values unless explicitly requested.
    function Format-ApproximateBreakdownDisplayValue {
        param (
            [Parameter(Mandatory=$false)]$Value,
            [Parameter(Mandatory=$false)][bool]$Approximate = $false,
            [Parameter(Mandatory=$false)][bool]$AllowZeroApproximate = $false
        )

        if (-not $Approximate -or $null -eq $Value) {
            return $Value
        }

        $displayValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($displayValue) -or $displayValue -eq "-") {
            return $Value
        }

        if ($displayValue.StartsWith('~')) {
            return $displayValue
        }

        if (-not $AllowZeroApproximate) {
            $normalizedDisplayValue = $displayValue.Trim()
            if ($normalizedDisplayValue -eq "0" -or $normalizedDisplayValue -eq "0.0" -or $normalizedDisplayValue -eq "0.0%") {
                return $Value
            }
        }

        return Format-ApproximateDisplayValue -Value $Value -Approximate $true
    }

    # Render the all-users effective targeting display using the filtered CAP user population.
    function Get-AllUsersEffectiveDisplay {
        param (
            [Parameter(Mandatory=$false)][hashtable]$Users
        )

        if ($null -eq $Users) {
            return "All users (count unavailable)"
        }

        return "$($Users.Count) (All users)"
    }

    # Show unresolved external selectors visually without changing the underlying counts.
    function Test-ExternalTargetingConfiguredUnresolved {
        param (
            [Parameter(Mandatory=$false)]$TargetingResolution
        )

        if ($null -eq $TargetingResolution) {
            return $false
        }

        $hasConfiguredSelector = (
            @($TargetingResolution.NormalizedTypes).Count -gt 0 -or
            [int]$TargetingResolution.TenantMembersCount -gt 0
        )

        return ($TargetingResolution.RequiresVisualApproximation -and $hasConfiguredSelector)
    }

    # Return the base external breakdown display value, preserving unresolved zero as '~0'
    # before the later generic approximation formatter can prefix non-zero values as needed.
    function Get-ExternalUsersBreakdownDisplayValue {
        param (
            [Parameter(Mandatory=$false)]$ResolvedCount,
            [Parameter(Mandatory=$false)]$TargetingResolution
        )

        $resolvedCountText = [string]$ResolvedCount
        $resolvedCountIsZero = (
            [string]::IsNullOrWhiteSpace($resolvedCountText) -or
            $resolvedCountText -eq "0"
        )

        if ($resolvedCountIsZero -and (Test-ExternalTargetingConfiguredUnresolved -TargetingResolution $TargetingResolution)) {
            return "~0"
        }

        return $ResolvedCount
    }

    # Parse display values such as '~12' or '62.8%' so detail summaries can add context.
    function Convert-EffectiveTargetingDisplayValueToNumber {
        param (
            [Parameter(Mandatory=$false)]$Value
        )

        if ($null -eq $Value) {
            return $null
        }

        $normalized = [string]$Value
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            return $null
        }

        $normalized = [regex]::Replace($normalized.Trim(), '^\s*~\s*', '')
        if ($normalized -eq '-' -or $normalized.ToLowerInvariant() -eq 'none') {
            return $null
        }

        $match = [regex]::Match($normalized, '\d+(?:\.\d+)?')
        if (-not $match.Success) {
            return $null
        }

        $parsedValue = 0.0
        if ([double]::TryParse($match.Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)) {
            return $parsedValue
        }

        return $null
    }

    # Suppress rows that only contain empty or zero-equivalent display values.
    function Test-EffectiveTargetingDetailValueMeaningful {
        param (
            [Parameter(Mandatory=$false)]$Value
        )

        if ($null -eq $Value) {
            return $false
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $false
        }

        $text = $text.Trim()
        if ($text -eq '-') {
            return $false
        }

        return ($text -ne '0' -and $text -ne '0.0' -and $text -ne '0.0%')
    }

    # Reformat the raw effective-targeting rows into the summary/breakdown/eligible sections used in report details.
    function Get-CapEffectiveTargetingDetailLayout {
        param (
            [Parameter(Mandatory=$false)][Object[]]$EffectiveTargeting
        )

        $included = $null
        $excluded = $null
        $total = $null
        foreach ($row in @($EffectiveTargeting)) {
            $scopeName = [string]$row.Scope
            switch ($scopeName.Trim().ToLowerInvariant()) {
                'included' { $included = $row; continue }
                'excluded' { $excluded = $row; continue }
                'total' { $total = $row; continue }
            }
        }

        if ($null -eq $included) { $included = [pscustomobject]@{} }
        if ($null -eq $excluded) { $excluded = [pscustomobject]@{} }
        if ($null -eq $total) { $total = [pscustomobject]@{} }

        $totalEffectiveUsers = Convert-EffectiveTargetingDisplayValueToNumber -Value $total.EffectiveUsers
        $uncoveredUsers = Convert-EffectiveTargetingDisplayValueToNumber -Value $total.UncoveredUsers
        $summaryUserCoverage = [string]$total.UserCoverage
        if ($null -ne $totalEffectiveUsers -and $null -ne $uncoveredUsers) {
            $totalUsers = [int]($totalEffectiveUsers + $uncoveredUsers)
            $summaryUserCoverage = "$($total.UserCoverage) ($($total.EffectiveUsers) / $totalUsers)"
        }

        $summaryRows = @(
            [pscustomobject]@{ Metric = 'UserCoverage'; Value = $summaryUserCoverage }
            [pscustomobject]@{ Metric = 'Included Effective Users'; Value = $included.EffectiveUsers }
            [pscustomobject]@{ Metric = 'Excluded Effective Users'; Value = $excluded.EffectiveUsers }
            [pscustomobject]@{ Metric = 'Total Uncovered Users'; Value = $total.UncoveredUsers }
        )

        $breakdownRows = @(
            [pscustomobject]@{ Metric = 'Direct Users'; Included = $included.DirectUsers; Excluded = $excluded.DirectUsers }
            [pscustomobject]@{ Metric = 'Users from Groups'; Included = $included.UsersViaGroups; Excluded = $excluded.UsersViaGroups }
            [pscustomobject]@{ Metric = 'Users from Roles'; Included = $included.UsersViaRoles; Excluded = $excluded.UsersViaRoles }
            [pscustomobject]@{ Metric = 'External Users'; Included = $included.UsersViaExternalCategories; Excluded = $excluded.UsersViaExternalCategories }
            [pscustomobject]@{ Metric = 'Deduplicated Overlap'; Included = $included.Overlap; Excluded = $excluded.Overlap }
        )

        $eligibleRows = [System.Collections.Generic.List[object]]::new()
        foreach ($row in @(
            [pscustomobject]@{ Metric = 'Eligible via Groups'; Included = $included.PotentialUsersViaGroups; Excluded = $excluded.PotentialUsersViaGroups }
            [pscustomobject]@{ Metric = 'Eligible via Roles'; Included = $included.PotentialUsersViaRoles; Excluded = $excluded.PotentialUsersViaRoles }
        )) {
            if (
                (Test-EffectiveTargetingDetailValueMeaningful -Value $row.Included) -or
                (Test-EffectiveTargetingDetailValueMeaningful -Value $row.Excluded)
            ) {
                [void]$eligibleRows.Add($row)
            }
        }

        return [pscustomobject]@{
            SummaryRows   = $summaryRows
            BreakdownRows = @($breakdownRows)
            EligibleRows  = @($eligibleRows)
        }
    }

    # Normalize auth-strength combinations into a canonical key so allow-lists remain stable
    # even if Microsoft changes the order of factors within the returned combination string.
    function Get-NormalizedAuthStrengthCombinationKey {
        param(
            [Parameter(Mandatory=$false)][string]$Combination
        )

        $normalizedFactors = @(
            "$Combination" -split "," |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
        )

        if ($normalizedFactors.Count -eq 0) {
            return ""
        }

        return ($normalizedFactors -join ",")
    }

    # Evaluate the inline authentication-strength object already returned with the Conditional
    # Access policy. This avoids relying on the separate auth-strength endpoint, which can expose
    # a broader combination set than the policy payload itself.
    function Get-CapAuthStrengthMetadata {
        param(
            [Parameter(Mandatory=$false)]$AuthenticationStrength
        )

        $metadata = [ordered]@{
            DisplayName                  = ""
            Id                           = ""
            Resolved                     = $false
            PhishingResistantOnly        = $false
            MfaCombinationsOnly          = $false
            ContainsSingleFactorElements = $false
            AllowedCombinations          = ""
        }

        if ($null -eq $AuthenticationStrength) {
            return [pscustomobject]$metadata
        }

        $phishingResistantFactors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($factor in @("windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor")) {
            $phishingResistantFactors.Add($factor) | Out-Null
        }

        $mfaEquivalentCombinationKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($combination in @(
            "windowsHelloForBusiness",
            "fido2",
            "x509CertificateMultiFactor",
            "deviceBasedPush",
            "temporaryAccessPassOneTime",
            "temporaryAccessPassMultiUse",
            "password,microsoftAuthenticatorPush",
            "password,softwareOath",
            "password,hardwareOath",
            "password,sms",
            "password,voice",
            "federatedMultiFactor",
            "microsoftAuthenticatorPush,federatedSingleFactor",
            "softwareOath,federatedSingleFactor",
            "hardwareOath,federatedSingleFactor",
            "sms,federatedSingleFactor",
            "voice,federatedSingleFactor"
        )) {
            $normalizedCombination = Get-NormalizedAuthStrengthCombinationKey -Combination $combination
            if (-not [string]::IsNullOrWhiteSpace($normalizedCombination)) {
                $mfaEquivalentCombinationKeys.Add($normalizedCombination) | Out-Null
            }
        }

        $singleFactorIndicators = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($factor in @("x509CertificateSingleFactor", "sms", "password", "federatedSingleFactor", "qrCodePin")) {
            $singleFactorIndicators.Add($factor) | Out-Null
        }

        if ($null -ne $AuthenticationStrength.DisplayName) {
            $metadata.DisplayName = [string]$AuthenticationStrength.DisplayName
        }
        if ($null -ne $AuthenticationStrength.Id) {
            $metadata.Id = [string]$AuthenticationStrength.Id
        }
        $requirementsSatisfied = ""
        if ($null -ne $AuthenticationStrength.requirementsSatisfied) {
            $requirementsSatisfied = "$($AuthenticationStrength.requirementsSatisfied)".Trim().ToLowerInvariant()
        }

        $combinationEntries = @()
        if ($null -ne $AuthenticationStrength.allowedCombinations) {
            if ($AuthenticationStrength.allowedCombinations -is [System.Collections.IEnumerable] -and -not ($AuthenticationStrength.allowedCombinations -is [string])) {
                $combinationEntries = @($AuthenticationStrength.allowedCombinations)
            } else {
                $combinationEntries = @($AuthenticationStrength.allowedCombinations)
            }
        }

        $allowedFactors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $normalizedCombinationKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($combination in $combinationEntries) {
            $normalizedCombination = Get-NormalizedAuthStrengthCombinationKey -Combination "$combination"
            if (-not [string]::IsNullOrWhiteSpace($normalizedCombination)) {
                $normalizedCombinationKeys.Add($normalizedCombination) | Out-Null
                foreach ($factor in ($normalizedCombination -split ",")) {
                    if (-not [string]::IsNullOrWhiteSpace($factor)) {
                        $allowedFactors.Add($factor) | Out-Null
                    }
                }
            }
        }

        $isPhishingResistant = ($allowedFactors.Count -gt 0)
        if ($isPhishingResistant) {
            foreach ($factor in $allowedFactors) {
                if (-not $phishingResistantFactors.Contains($factor)) {
                    $isPhishingResistant = $false
                    break
                }
            }
        }

        $isMfaEquivalent = ($normalizedCombinationKeys.Count -gt 0)
        if ($isMfaEquivalent) {
            foreach ($combinationKey in $normalizedCombinationKeys) {
                if (-not $mfaEquivalentCombinationKeys.Contains($combinationKey)) {
                    $isMfaEquivalent = $false
                    break
                }
            }
        }
        if (-not $isMfaEquivalent -and $requirementsSatisfied -eq "mfa") {
            $isMfaEquivalent = $true
        }

        $containsSingleFactorElements = $false
        foreach ($factor in $allowedFactors) {
            if ($singleFactorIndicators.Contains($factor)) {
                $containsSingleFactorElements = $true
                break
            }
        }

        $metadata.Resolved = (($normalizedCombinationKeys.Count -gt 0) -or -not [string]::IsNullOrWhiteSpace($requirementsSatisfied))
        $metadata.PhishingResistantOnly = $isPhishingResistant
        $metadata.MfaCombinationsOnly = $isMfaEquivalent
        $metadata.ContainsSingleFactorElements = $containsSingleFactorElements
        $metadata.AllowedCombinations = (@($combinationEntries) | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "; "

        return [pscustomobject]$metadata
    }

    # Evaluate grant controls from a security-semantics perspective instead of relying on the
    # flattened report string. This allows downstream checks to distinguish between MFA that is
    # truly mandatory and MFA that can be bypassed via an OR branch such as compliant devices.
    function Get-CapGrantAssuranceEvaluation {
        param(
            [Parameter(Mandatory=$false)][Object[]]$BuiltInControls,
            [Parameter(Mandatory=$false)][string]$Operator,
            [Parameter(Mandatory=$false)][bool]$HasAuthStrength = $false,
            [Parameter(Mandatory=$false)][bool]$AuthStrengthResolved = $false,
            [Parameter(Mandatory=$false)][bool]$AuthStrengthMfaCombinationsOnly = $false,
            [Parameter(Mandatory=$false)][bool]$AuthStrengthPhishingResistantOnly = $false
        )

        $normalizedOperator = "$Operator".Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($normalizedOperator)) {
            $normalizedOperator = "AND"
        }

        $normalizedBuiltInControls = @(
            @($BuiltInControls) |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )

        $grantAlternatives = [System.Collections.Generic.List[object]]::new()
        foreach ($control in $normalizedBuiltInControls) {
            if ($control -eq "block") { continue }
            $grantAlternatives.Add([pscustomobject]@{
                Label                  = $control
                Resolved               = $true
                MfaEquivalent          = ($control -eq "mfa")
                PhishingResistant      = $false
            })
        }

        if ($HasAuthStrength) {
            $grantAlternatives.Add([pscustomobject]@{
                Label                  = "authenticationStrength"
                Resolved               = $AuthStrengthResolved
                MfaEquivalent          = ($AuthStrengthResolved -and $AuthStrengthMfaCombinationsOnly)
                PhishingResistant      = ($AuthStrengthResolved -and $AuthStrengthPhishingResistantOnly)
            })
        }

        $hasMfaBaselineCandidate = (($normalizedBuiltInControls -contains "mfa") -or $HasAuthStrength)

        $mfaEquivalentEnforced = $false
        $phishingResistantEnforced = $false
        if ($hasMfaBaselineCandidate) {
            if ($normalizedOperator -eq "OR") {
                $mfaEquivalentEnforced = ($grantAlternatives.Count -gt 0)
                $phishingResistantEnforced = ($grantAlternatives.Count -gt 0)
                foreach ($grantAlternative in $grantAlternatives) {
                    if (-not [bool]$grantAlternative.MfaEquivalent) {
                        $mfaEquivalentEnforced = $false
                    }
                    if (-not [bool]$grantAlternative.PhishingResistant) {
                        $phishingResistantEnforced = $false
                    }
                }
            } else {
                foreach ($grantAlternative in $grantAlternatives) {
                    if ([bool]$grantAlternative.MfaEquivalent) {
                        $mfaEquivalentEnforced = $true
                    }
                    if ([bool]$grantAlternative.PhishingResistant) {
                        $phishingResistantEnforced = $true
                    }
                }
            }
        }

        $weakMfaAlternatives = @(
            foreach ($grantAlternative in $grantAlternatives) {
                if (-not [bool]$grantAlternative.MfaEquivalent) {
                    $grantAlternative.Label
                }
            }
        )
        $weakPhishingAlternatives = @(
            foreach ($grantAlternative in $grantAlternatives) {
                if (-not [bool]$grantAlternative.PhishingResistant) {
                    $grantAlternative.Label
                }
            }
        )
        $unresolvedAlternatives = @(
            foreach ($grantAlternative in $grantAlternatives) {
                if (-not [bool]$grantAlternative.Resolved) {
                    $grantAlternative.Label
                }
            }
        )
        $hasMultipleGrantAlternatives = ($grantAlternatives.Count -gt 1)

        $mfaWarningParts = @()
        if ($normalizedOperator -eq "OR" -and $hasMultipleGrantAlternatives -and $hasMfaBaselineCandidate -and $weakMfaAlternatives.Count -gt 0) {
            $mfaWarningParts += "uses OR with non-MFA grant alternative(s): " + (($weakMfaAlternatives | Sort-Object -Unique) -join ", ")
        }
        if ($unresolvedAlternatives.Count -gt 0) {
            $mfaWarningParts += "references authentication strength that could not be resolved"
        }
        if ($HasAuthStrength -and $grantAlternatives.Count -eq 1 -and $AuthStrengthResolved -and -not $AuthStrengthMfaCombinationsOnly) {
            $mfaWarningParts += "authentication strength is not MFA-equivalent"
        }

        $phishingWarningParts = @()
        if ($normalizedOperator -eq "OR" -and $hasMultipleGrantAlternatives -and $HasAuthStrength -and $weakPhishingAlternatives.Count -gt 0) {
            $phishingWarningParts += "uses OR with non-phishing-resistant alternative(s): " + (($weakPhishingAlternatives | Sort-Object -Unique) -join ", ")
        }
        if ($unresolvedAlternatives.Count -gt 0) {
            $phishingWarningParts += "references authentication strength that could not be resolved"
        }

        return [pscustomobject]@{
            Operator                    = $normalizedOperator
            HasMfaBaselineCandidate     = $hasMfaBaselineCandidate
            HasAuthStrengthCandidate    = $HasAuthStrength
            MfaEquivalentEnforced       = $mfaEquivalentEnforced
            PhishingResistantEnforced   = $phishingResistantEnforced
            Confidence                  = if ($unresolvedAlternatives.Count -gt 0) { "Requires Verification" } else { "High" }
            MfaWarning                  = ($mfaWarningParts -join "; ")
            PhishingResistantWarning    = ($phishingWarningParts -join "; ")
        }
    }

    # Add trimmed warning strings to a target collection without duplicating entries.
    function Add-UniqueStringItems {
        param(
            [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.IList]$Target,
            [Parameter(Mandatory=$false)][string[]]$Items
        )

        foreach ($item in @($Items)) {
            $normalizedItem = "$item".Trim()
            if ([string]::IsNullOrWhiteSpace($normalizedItem)) { continue }
            if (-not $Target.Contains($normalizedItem)) {
                $Target.Add($normalizedItem)
            }
        }
    }

    # Return a de-duplicated array of normalized warning strings for final rendering.
    function Get-DeduplicatedWarningItems {
        param(
            [Parameter(Mandatory=$false)][string[]]$Items
        )

        $uniqueItems = [System.Collections.Generic.List[string]]::new()
        foreach ($item in @($Items)) {
            $normalizedItem = "$item".Trim()
            if ([string]::IsNullOrWhiteSpace($normalizedItem)) { continue }
            if (-not $uniqueItems.Contains($normalizedItem)) {
                $uniqueItems.Add($normalizedItem)
            }
        }

        return @($uniqueItems)
    }

    # Merge MFA-equivalent and phishing-resistant issues into one table-facing assurance summary.
    function Get-CapCombinedAssuranceWarning {
        param(
            [Parameter(Mandatory=$false)][string[]]$MfaCommonIssues,
            [Parameter(Mandatory=$false)][string[]]$MfaIssues,
            [Parameter(Mandatory=$false)][string[]]$PhishingCommonIssues,
            [Parameter(Mandatory=$false)][string[]]$PhishingIssues,
            [Parameter(Mandatory=$false)][bool]$HasMfaContext = $false,
            [Parameter(Mandatory=$false)][bool]$HasPhishingContext = $false
        )

        $normalizedMfaCommonIssues = Get-DeduplicatedWarningItems -Items $MfaCommonIssues
        $normalizedMfaIssues = Get-DeduplicatedWarningItems -Items $MfaIssues
        $normalizedPhishingCommonIssues = Get-DeduplicatedWarningItems -Items $PhishingCommonIssues
        $normalizedPhishingIssues = Get-DeduplicatedWarningItems -Items $PhishingIssues

        if (-not $HasMfaContext -and -not $HasPhishingContext) {
            return ""
        }

        $mfaSummaryParts = [System.Collections.Generic.List[string]]::new()
        if ($normalizedMfaCommonIssues.Count -gt 0) {
            $mfaSummaryParts.Add(($normalizedMfaCommonIssues | Sort-Object) -join ", ")
        }
        if ($normalizedMfaIssues.Count -gt 0) {
            $mfaSummaryParts.Add(($normalizedMfaIssues | Sort-Object) -join ", ")
        }

        $phishingSummaryParts = [System.Collections.Generic.List[string]]::new()
        if ($normalizedPhishingCommonIssues.Count -gt 0) {
            $phishingSummaryParts.Add(($normalizedPhishingCommonIssues | Sort-Object) -join ", ")
        }
        if ($normalizedPhishingIssues.Count -gt 0) {
            $phishingSummaryParts.Add(($normalizedPhishingIssues | Sort-Object) -join ", ")
        }

        $hasMfaIssues = ($mfaSummaryParts.Count -gt 0)
        $hasPhishingIssues = ($phishingSummaryParts.Count -gt 0)

        if (-not $hasMfaIssues -and -not $hasPhishingIssues) {
            return ""
        }

        if ($HasMfaContext -and $HasPhishingContext) {
            $summaryParts = [System.Collections.Generic.List[string]]::new()
            if ($hasMfaIssues) {
                if ($normalizedMfaIssues.Count -gt 0) {
                    $summaryParts.Add("MFA issues: " + ($mfaSummaryParts -join ", "))
                } else {
                    $summaryParts.Add("MFA scope issues: " + ($mfaSummaryParts -join ", "))
                }
            }
            if ($hasPhishingIssues) {
                $summaryParts.Add("Phishing-resistant issues: " + ($phishingSummaryParts -join ", "))
            }
            return ($summaryParts -join "; ")
        }

        if ($HasPhishingContext) {
            if ($normalizedPhishingIssues.Count -gt 0) {
                return "Phishing-resistant MFA policy issues: " + ($phishingSummaryParts -join "; ")
            }
            return "Requiring phishing-resistant MFA but " + ($phishingSummaryParts -join "; ")
        }

        if ($normalizedMfaIssues.Count -gt 0) {
            return "MFA policy issues: " + ($mfaSummaryParts -join "; ")
        }

        return "Requiring MFA but " + ($mfaSummaryParts -join "; ")
    }

    # Function to look up GUIDs in hashtables
    function Resolve-Name {
        param (
            [string]$Guid,
            [string]$Report
        )

        #Note: Not ideal checking each object type. However, relatively cheap with HashTables
        if ($Users.ContainsKey($Guid)) {
            $ResolvedGUID = $($Users[$Guid].UPN)

            if ($Report -eq "HTML") {
                $ResolvedGUIDLink = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$Guid>$ResolvedGUID</a>"
                return $ResolvedGUIDLink
            } elseif ($Report -eq "TXT") {
                return $ResolvedGUID
            }
            
        }
        if ($AllGroupsDetails.ContainsKey($Guid)) {
            $ResolvedGUID = $($AllGroupsDetails[$Guid].DisplayName)

            if ($Report -eq "HTML") {
                $ResolvedGUIDLink = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$Guid>$ResolvedGUID</a>"
                return $ResolvedGUIDLink
            } elseif ($Report -eq "TXT") {
                return $ResolvedGUID
            }
        }

        if ($EnterpriseAppsHT.ContainsKey($Guid)) { 
            $ResolvedGUID = $($EnterpriseAppsHT[$Guid])
            return $ResolvedGUID
        }
        
        if ($NamedLocationsHT.ContainsKey($Guid)) { 
            $ResolvedGUID = $($NamedLocationsHT[$Guid].Name)

            if ($Report -eq "HTML") {
                $ResolvedGUIDLink = "<a href=#appendix:-network-location>$ResolvedGUID</a>"
                return $ResolvedGUIDLink
            } elseif ($Report -eq "TXT") {
                return $ResolvedGUID
            }
        }
        if ($RoleTemplatesHT.ContainsKey($Guid)) { 
            $ResolvedGUID = $($RoleTemplatesHT[$Guid])
            if ($Report -eq "HTML") {
                $ResolvedGUIDLink = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Role=$([System.Uri]::EscapeDataString("=$ResolvedGUID"))&AssignmentType=Active&PrincipalType=User%7C%7CGroup>$ResolvedGUID</a>"
                return $ResolvedGUIDLink
            } elseif ($Report -eq "TXT") {
                return $ResolvedGUID
            }
        }
        return $Guid  # Return original if not found
    }

    # Function to convert object to YAML and replacing GUIDs with names
    function ConvertTo-Yaml {
        param(
            [Parameter(Mandatory=$true)]
            [Object]$InputObject,
            [string]$Indent = "",
            [string]$Report
        )

        foreach ($property in $InputObject.PSObject.Properties) {
            $name = $property.Name
            $value = $property.Value
            $newIndent = "$Indent  "

            # Skip empty properties
            if (Is-Empty $value) { continue }

            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $isNestedObject = $false
                foreach ($item in $value) {
                    if ($item -is [PSCustomObject]) {
                        $isNestedObject = $true
                        break
                    }
                }

                if ($isNestedObject) {
                    Write-Output "${Indent}${name}:"
                    foreach ($item in $value) {
                        if (-not (Is-Empty $item)) {
                            Write-Output "${newIndent}-"
                            ConvertTo-Yaml -InputObject $item -Indent "$newIndent  " -Report $Report
                        }
                    }
                } else {
                    Write-Output "${Indent}${name}:"
                    foreach ($item in $value) {
                        # Call function only if $item is a valid GUID
                        if (Test-IsGuid -Value $item) {
                            #Resolve the GUID
                            $item = Resolve-Name -Guid $item -Report $Report
                        }
                        Write-Output "${newIndent}- $item"
                    }

                }
            }
            elseif ($value -is [PSCustomObject]) {
                Write-Output "${Indent}${name}:"
                ConvertTo-Yaml -InputObject $value -Indent $newIndent -Report $Report
            }
            else {
                # Resolve GUID if applicable
                if ($value -is [string]) {

                    # Call function only if $item is a valid GUID
                    if (Test-IsGuid -Value $value) {
                        #Resolve the GUID
                        $value = Resolve-Name -Guid $value -Report $Report
                    }
                    $formattedValue = "'$value'"
                }
                elseif ($value -is [datetime]) {
                    $formattedValue = "'$($value.ToString("yyyy-MM-dd HH:mm:ss"))'"
                }
                elseif ($value -is [boolean]) {
                    $formattedValue = $value.ToString().ToLower()
                }
                else {
                    $formattedValue = $value
                }

                Write-Output "${Indent}${name}: $formattedValue"
            }
        }
    }



    ############################## Script section ########################
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "ConditionalAccessPolicies"
    $ProgressCounter = 0
    $DetailOutputTxt = ""
    $MissingPolicies = @()
    $WarningReport = @()
    $PolicyDeviceCodeFlow = $false
    $PolicyLegacyAuth = $false
    $PolicyRiskySignIn = $false
    $PolicyUserRisk = $false
    $PolicyRegSecInfo = $false
    $PolicyMfaUser = $false
    $PolicyAuthStrength = $false
    $PolicyRegDevices = $false
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()


    ########################################## SECTION: DATACOLLECTION ##########################################

    write-host "[*] Get Conditional Access Policies"

    #Omit oData to avoid having odata in the sub-properties
    $headers = @{ 'Accept' = 'application/json; odata.metadata=none' }
    $AllPolicies = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/identity/conditionalAccess/policies" -BetaAPI -AdditionalHeaders $headers -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $AllPoliciesCount = @($AllPolicies).count
    write-host "[+] Got $AllPoliciesCount policies"

    #Check Named locations
    write-host "[*] Enumerate Named locations"
    $LocationsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/identity/conditionalAccess/namedLocations" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $NamedLocations = foreach($location in $LocationsRaw) {
        $NamedLocationType = "Unknown"
        $TargetedLocations = ""
        switch ($location."@odata.type") {
            "#microsoft.graph.countryNamedLocation" {
                $NamedLocationType = "Countries"
                $TargetedLocations = $location.countriesAndRegions | Sort-Object
                if ($TargetedLocations -is [array] -or ($TargetedLocations.GetType().Name -eq 'Object[]')) {
                    $TargetedLocations = $TargetedLocations -join ", "
                }
            }
        
            "#microsoft.graph.ipNamedLocation" {
                $NamedLocationType = "IP ranges"
                $TargetedLocations = $location.ipRanges.cidrAddress
                if ($TargetedLocations -is [array] -or ($TargetedLocations.GetType().Name -eq 'Object[]')) {
                    $TargetedLocations = $TargetedLocations -join ", "
                }
            }

            default {
                $NamedLocationType = [string]$location."@odata.type"
                $TargetedLocations = ""
            }
        }

        # Format Trusted property
        if ($null -eq $location.isTrusted) {
            $TrustedLocation = "-"
        } else {
            $TrustedLocation = $location.isTrusted
        }

        # Filter CAP policies where this location is included and excluded.
        $MatchingCAPsIncluded = $AllPolicies | Where-Object {
            ($_.Conditions.Locations.IncludeLocations -contains $location.Id) -or ( ($_.Conditions.Locations.IncludeLocations -contains "AllTrusted") -and $location.isTrusted )
        }
        
        $MatchingCAPsExcluded = $AllPolicies | Where-Object {
            ($_.Conditions.Locations.ExcludeLocations -contains $location.Id) -or ( ($_.Conditions.Locations.ExcludeLocations -contains "AllTrusted") -and $location.isTrusted )
        }
        
        # Create text values: a comma-separated list of policy display names (if any).
        $IncludedCAPsText = if ($MatchingCAPsIncluded) {
            ($MatchingCAPsIncluded | ForEach-Object { $_.DisplayName }) -join ", "
        } else {
            ""
        }
        $ExcludedCAPsText = if ($MatchingCAPsExcluded) {
            ($MatchingCAPsExcluded | ForEach-Object { $_.DisplayName }) -join ", "
        } else {
            ""
        }

        $IncludedCAPsTextLinks = if ($MatchingCAPsIncluded) {
            ( $MatchingCAPsIncluded | ForEach-Object { "<a href=#$($_.ID)>$($_.DisplayName)</a>" } ) -join ", "
        } else {
            ""
        }
        
        $ExcludedCAPsTextLinks = if ($MatchingCAPsExcluded) {
            ( $MatchingCAPsExcluded | ForEach-Object { "<a href=#$($_.ID)>$($_.DisplayName)</a>" } ) -join ", "
        } else {
            ""
        }
        
        [pscustomobject]@{
            "Id"                = $location.Id
            "Name"              = $location.DisplayName
            "Trusted"           = $TrustedLocation
            "Type"              = $NamedLocationType
            "TargetedLocations" = $TargetedLocations
            "IncludedCAPs"      = $IncludedCAPsText
            "ExcludedCAPs"      = $ExcludedCAPsText
            "IncludedCAPsLinks" = $IncludedCAPsTextLinks
            "ExcludedCAPsLinks" = $ExcludedCAPsTextLinks
        }
    }

    # Create a hashtable for fast lookup
    $NamedLocationsHT = @{}
    foreach ($location in $NamedLocations) {
        $NamedLocationsHT[$location.Id] = $location
    }
    write-host "[+] Got $($($NamedLocations | Measure-Object).count) named locations"

    # Cache supported external-user categories once so policies can reuse the same approximate user sets.
    $CapRelevantUsersLookup = @{}
    $CapRelevantUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($userEntry in $Users.GetEnumerator()) {
        $userObject = $userEntry.Value
        if ($null -eq $userObject) { continue }
        if ($userObject.PSObject.Properties.Name -contains 'Agent' -and [bool]$userObject.Agent) { continue }

        $userId = "$($userObject.Id)".Trim()
        if ([string]::IsNullOrWhiteSpace($userId)) {
            $userId = "$($userEntry.Key)".Trim()
        }
        if ([string]::IsNullOrWhiteSpace($userId)) { continue }

        $CapRelevantUsersLookup[$userId] = $userObject
        [void]$CapRelevantUserIds.Add($userId)
    }
    Write-Log -Level Debug -Message "Prepared CAP-relevant user lookup (excluding agents): $($CapRelevantUsersLookup.Count)"

    $ApproxExternalUserLookup = @{}
    $guestUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($userEntry in $CapRelevantUsersLookup.GetEnumerator()) {
        $userObject = $userEntry.Value
        if ($null -eq $userObject) { continue }

        $userType = "$($userObject.UserType)".Trim().ToLowerInvariant()
        if ($userType -ne "guest") { continue }

        $userId = "$($userObject.Id)".Trim()
        if ([string]::IsNullOrWhiteSpace($userId)) {
            $userId = "$($userEntry.Key)".Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($userId)) {
            [void]$guestUserIds.Add($userId)
        }
    }
    $ApproxExternalUserLookup["b2bcollaborationguest"] = [pscustomobject]@{
        UserIds     = $guestUserIds
        Count       = $guestUserIds.Count
        Approximate = $false
    }
    Write-Log -Level Debug -Message "Prepared external user lookup: b2bCollaborationGuest=$($guestUserIds.Count)"

    $EnabledUsersLookup = @{}
    $EnabledUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($userEntry in $CapRelevantUsersLookup.GetEnumerator()) {
        $userObject = $userEntry.Value
        if ($null -eq $userObject) { continue }

        $isEnabled = $false
        if ($userObject.PSObject.Properties.Name -contains 'Enabled') {
            $isEnabled = [bool]$userObject.Enabled
        } elseif ($userObject.PSObject.Properties.Name -contains 'AccountEnabled') {
            $isEnabled = [bool]$userObject.AccountEnabled
        }
        if (-not $isEnabled) { continue }

        $userId = "$($userObject.Id)".Trim()
        if ([string]::IsNullOrWhiteSpace($userId)) {
            $userId = "$($userEntry.Key)".Trim()
        }
        if ([string]::IsNullOrWhiteSpace($userId)) { continue }

        $EnabledUsersLookup[$userId] = $userObject
        [void]$EnabledUserIds.Add($userId)
    }
    Write-Log -Level Debug -Message "Prepared enabled user lookup for CAP exports: $($EnabledUsersLookup.Count)"

    $CapUncoveredUsersOutputFolder = $null
    if ($ExportCapUncoveredUsers) {
        $CapUncoveredUsersOutputFolder = Join-Path $OutputFolder "ConditionalAccessPolicies_UncoveredUsers"
        if (-not (Test-Path -LiteralPath $CapUncoveredUsersOutputFolder)) {
            $null = New-Item -Path $CapUncoveredUsersOutputFolder -ItemType Directory -Force
        }
    }

    # Build all three role-assignment lookups in a single pass over TenantRoleAssignments
    $HighTierAssignments           = [System.Collections.Generic.List[object]]::new()
    $ScopedAssignments             = @{}
    $ActiveRoleUsersImpactLookup   = @{}
    $EligibleRoleUsersImpactLookup = @{}

    foreach ($assignmentList in $TenantRoleAssignments.Values) {
        foreach ($assignment in $assignmentList) {
            $principalId      = [string]$assignment.PrincipalId
            $roleId           = [string]$assignment.RoleDefinitionId
            $isKnownPrincipal = $CapRelevantUsersLookup.ContainsKey($principalId) -or $AllGroupsDetails.ContainsKey($principalId)

            # HighTierAssignments: Tier 0/1 roles for known principals, excluding Directory Synchronization Accounts
            if ($assignment.RoleTier -in 0, 1 -and
                $roleId -ne "d29b2b05-8046-44ba-8758-1e26182fcf32" -and
                $isKnownPrincipal) {
                [void]$HighTierAssignments.Add($assignment)
            }

            # ScopedAssignments: any assignment type with a non-tenant scope
            if ($assignment.ScopeResolved.DisplayName -ne '/' -and $isKnownPrincipal) {
                if (-not $ScopedAssignments.ContainsKey($roleId)) {
                    $ScopedAssignments[$roleId] = @{
                        RoleName = $assignment.DisplayName
                        RoleTier = $assignment.RoleTier
                        Count    = 0
                    }
                }
                $ScopedAssignments[$roleId]['Count']++
            }

            if ([string]::IsNullOrWhiteSpace($roleId)) { continue }
            # Ignore scoped assignments because Conditional Access role targeting applies to tenant-wide assignments only.
            if ($assignment.ScopeResolved.DisplayName -ne '/') { continue }

            $targetRoleLookup = $null
            if ([string]$assignment.AssignmentType -eq "Active") {
                $targetRoleLookup = $ActiveRoleUsersImpactLookup
            } elseif ([string]$assignment.AssignmentType -eq "Eligible") {
                $targetRoleLookup = $EligibleRoleUsersImpactLookup
            } else {
                continue
            }

            if (-not $targetRoleLookup.ContainsKey($roleId)) {
                $targetRoleLookup[$roleId] = @{
                    UserIds         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    EligibleUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    FallbackGroups  = @{}
                }
            }

            if ($CapRelevantUsersLookup.ContainsKey($principalId)) {
                [void]$targetRoleLookup[$roleId].UserIds.Add($principalId)
            } elseif ($AllGroupsDetails.ContainsKey($principalId)) {
                # Reuse the same per-group cache so role expansion does not re-read large memberships.
                $groupMetrics = Get-GroupUsersMetricsCached -GroupId $principalId
                foreach ($userId in $groupMetrics.UserIds) {
                    [void]$targetRoleLookup[$roleId].UserIds.Add([string]$userId)
                }
                foreach ($userId in $groupMetrics.EligibleUserIds) {
                    [void]$targetRoleLookup[$roleId].EligibleUserIds.Add([string]$userId)
                }
                foreach ($fallbackEntry in $groupMetrics.FallbackGroups.GetEnumerator()) {
                    $targetRoleLookup[$roleId].FallbackGroups[$fallbackEntry.Key] = $fallbackEntry.Value
                }
            }
        }
    }
    Write-Log -Level Debug -Message "Prepared assignment lookups: HighTier=$($HighTierAssignments.Count) Scoped=$($ScopedAssignments.Count) ActiveRoleUsers=$($ActiveRoleUsersImpactLookup.Count) EligibleRoleUsers=$($EligibleRoleUsersImpactLookup.Count) GroupCache=$($GroupUsersMetricsCache.Count)"


    if ($AllPoliciesCount -gt 0) {
        #Get all Enterprise Apps to resolve GUIDs (fetching it again ensures MS apps are included)
        $QueryParameters = @{
            '$select' = "AppId,Displayname"
        }
        $EnterpriseApps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

        $EnterpriseAppsHT = @{}
        foreach ($app in $EnterpriseApps ) {
            $EnterpriseAppsHT[$app.AppId] = $app.DisplayName
        }

        Write-Log -Level Debug -Message "Prepared HT EnterpriseApps $($EnterpriseAppsHT.Count)"
        
        #Get all role templates to resolve GUIDs
        $QueryParameters = @{
            '$select' = "Id,Displayname"
        }
        $RoleTemplates = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directoryRoleTemplates" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        
        $RoleTemplatesHT = @{}
        foreach ($role in $RoleTemplates ) {
            $RoleTemplatesHT[$role.Id] = $role.DisplayName
        }

        Write-Log -Level Debug -Message "Prepared HT RoleTemplates $($RoleTemplates.Count)"
    }

    ########################################## SECTION: Processing ##########################################

    # Sort the policies based on custom order
    $sortOrder = @(
        "enabled",
        "enabledForReportingButNotEnforced",
        "disabled"
    )
    $AllPolicies = $AllPolicies | Sort-Object {
        [array]::IndexOf($sortOrder, $_.State)
    }, {
        $_.DisplayName
    }

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($AllPoliciesCount / 10), 1)
    if ($AllPoliciesCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing policy 1 of $AllPoliciesCount (updates every $StatusUpdateInterval policies)..."
    }

    # Create an list to store formatted policies
    $ConditionalAccessPolicies = [System.Collections.Generic.List[pscustomobject]]::new()

    $capUncoveredExportFilesWritten = 0
    $capUncoveredExportRows = 0
    $capUncoveredExportSkippedEmpty = 0
    $capUncoveredExportSkippedNoTargeting = 0

    #region Processing Loop
    #Main processing of the results
    foreach ($policy in $AllPolicies) {
        $ProgressCounter ++
        $PolicyWarningParts = [System.Collections.Generic.List[string]]::new()
        $MfaCommonIssues = [System.Collections.Generic.List[string]]::new()
        $MfaSpecificIssues = [System.Collections.Generic.List[string]]::new()
        $PhishingCommonIssues = [System.Collections.Generic.List[string]]::new()
        $PhishingSpecificIssues = [System.Collections.Generic.List[string]]::new()
        $HasMfaWarningContext = $false
        $HasPhishingWarningContext = $false
        $WarningPolicy = ""
        $ErrorMessages = @()
        $additionalConditionTypes = 0

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AllPoliciesCount) {
            Write-Host "[*] Status: Processing policy $ProgressCounter of $AllPoliciesCount..."
        }

        ###################### Handling special Values like "All" etc.
        if ($policy.State -eq "enabledForReportingButNotEnforced") {$policy.State = "report-only"}

        $NormalizedIncludeUsers = Remove-CapLegacyGuestsOrExternalUsersSelector -UserIds $policy.Conditions.Users.IncludeUsers
        $NormalizedExcludeUsers = Remove-CapLegacyGuestsOrExternalUsersSelector -UserIds $policy.Conditions.Users.ExcludeUsers
        $IncludedExternalSelector = Get-CapExternalSelector -StructuredSelector $policy.Conditions.Users.IncludeGuestsOrExternalUsers -UserIds $policy.Conditions.Users.IncludeUsers
        $ExcludedExternalSelector = Get-CapExternalSelector -StructuredSelector $policy.Conditions.Users.ExcludeGuestsOrExternalUsers -UserIds $policy.Conditions.Users.ExcludeUsers

        if ($NormalizedIncludeUsers -contains "All") {
            $IncludedUserCount = "All"
        } else {
            $IncludedUserCount = $NormalizedIncludeUsers.Count
        }
        if ($NormalizedIncludeUsers -contains "None") {
            $IncludedUserCount = 0
        }

        $IncludedDirectUserMetrics = Get-ExplicitUserMetrics -UserIds $NormalizedIncludeUsers
        $ExcludedDirectUserMetrics = Get-ExplicitUserMetrics -UserIds $NormalizedExcludeUsers
        $IncludedGroupUserMetrics = Get-UsersThroughGroupsMetrics -GroupIds $policy.Conditions.Users.IncludeGroups
        $ExcludedGroupUserMetrics = Get-UsersThroughGroupsMetrics -GroupIds $policy.Conditions.Users.ExcludeGroups
        $IncludedRoleUserMetrics = Get-UsersThroughRolesMetrics -RoleIds $policy.Conditions.Users.IncludeRoles -RoleUsersLookup $ActiveRoleUsersImpactLookup
        $ExcludedRoleUserMetrics = Get-UsersThroughRolesMetrics -RoleIds $policy.Conditions.Users.ExcludeRoles -RoleUsersLookup $ActiveRoleUsersImpactLookup
        $IncludedEligibleRoleUserMetrics = Get-UsersThroughRolesMetrics -RoleIds $policy.Conditions.Users.IncludeRoles -RoleUsersLookup $EligibleRoleUsersImpactLookup
        $ExcludedEligibleRoleUserMetrics = Get-UsersThroughRolesMetrics -RoleIds $policy.Conditions.Users.ExcludeRoles -RoleUsersLookup $EligibleRoleUsersImpactLookup

        # Include eligible group members that reach targeted roles through group principals in PotentialUsersViaGroups.
        $IncludedPotentialGroupUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($userId in $IncludedGroupUserMetrics.EligibleUserIds) {
            [void]$IncludedPotentialGroupUserIds.Add([string]$userId)
        }
        foreach ($userId in $IncludedRoleUserMetrics.EligibleUserIds) {
            [void]$IncludedPotentialGroupUserIds.Add([string]$userId)
        }
        foreach ($userId in $IncludedEligibleRoleUserMetrics.EligibleUserIds) {
            [void]$IncludedPotentialGroupUserIds.Add([string]$userId)
        }

        $ExcludedPotentialGroupUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($userId in $ExcludedGroupUserMetrics.EligibleUserIds) {
            [void]$ExcludedPotentialGroupUserIds.Add([string]$userId)
        }
        foreach ($userId in $ExcludedRoleUserMetrics.EligibleUserIds) {
            [void]$ExcludedPotentialGroupUserIds.Add([string]$userId)
        }
        foreach ($userId in $ExcludedEligibleRoleUserMetrics.EligibleUserIds) {
            [void]$ExcludedPotentialGroupUserIds.Add([string]$userId)
        }

        # External-user selectors are category-based. Only b2bCollaborationGuest is approximated
        # by matching already-loaded guest users in the tenant. Some external-user types and
        # tenant-specific selections cannot be resolved to concrete users and are only marked visually.
        $IncludedExternalTargetingResolution = Get-ExternalTargetingResolution -ExternalSelector $IncludedExternalSelector
        $ExcludedExternalTargetingResolution = Get-ExternalTargetingResolution -ExternalSelector $ExcludedExternalSelector

        $IncludedExternalUsers = $IncludedExternalTargetingResolution.GuestOrExternalUserTypes
        if ([string]::IsNullOrEmpty($IncludedExternalUsers)) {
            $IncludedExternalUsersCount = 0
        } else {
            $IncludedExternalUsersCount = ($IncludedExternalUsers -split ',').Count
        }
        $ExcludedExternalUsers = $ExcludedExternalTargetingResolution.GuestOrExternalUserTypes
        if ([string]::IsNullOrEmpty($ExcludedExternalUsers)) {
            $ExcludedExternalUsersCount = 0
        } else {
            $ExcludedExternalUsersCount = ($ExcludedExternalUsers -split ',').Count
        }

        $IncludedExternalUserMetrics = Get-ExternalUserMetricsApprox -GuestOrExternalUserTypes $IncludedExternalUsers -ExternalUserLookup $ApproxExternalUserLookup
        $ExcludedExternalUserMetrics = Get-ExternalUserMetricsApprox -GuestOrExternalUserTypes $ExcludedExternalUsers -ExternalUserLookup $ApproxExternalUserLookup

        $IncludedActualUserIds = Get-EffectiveTargetingUserIds -DirectMetrics $IncludedDirectUserMetrics -GroupMetrics $IncludedGroupUserMetrics -RoleMetrics $IncludedRoleUserMetrics -ExternalMetrics $IncludedExternalUserMetrics -AllUserIds $CapRelevantUserIds -HasAll $IncludedDirectUserMetrics.HasAll
        $ExcludedActualUserIds = Get-EffectiveTargetingUserIds -DirectMetrics $ExcludedDirectUserMetrics -GroupMetrics $ExcludedGroupUserMetrics -RoleMetrics $ExcludedRoleUserMetrics -ExternalMetrics $ExcludedExternalUserMetrics -AllUserIds $CapRelevantUserIds -HasAll $ExcludedDirectUserMetrics.HasAll

        $IncludedNetPotentialGroupUserIds = [System.Collections.Generic.HashSet[string]]::new($IncludedPotentialGroupUserIds, [System.StringComparer]::OrdinalIgnoreCase)
        $IncludedNetPotentialGroupUserIds.ExceptWith($IncludedActualUserIds)
        $ExcludedNetPotentialGroupUserIds = [System.Collections.Generic.HashSet[string]]::new($ExcludedPotentialGroupUserIds, [System.StringComparer]::OrdinalIgnoreCase)
        $ExcludedNetPotentialGroupUserIds.ExceptWith($ExcludedActualUserIds)

        $IncludedNetPotentialRoleUserIds = [System.Collections.Generic.HashSet[string]]::new($IncludedEligibleRoleUserMetrics.UserIds, [System.StringComparer]::OrdinalIgnoreCase)
        $IncludedNetPotentialRoleUserIds.ExceptWith($IncludedActualUserIds)
        $ExcludedNetPotentialRoleUserIds = [System.Collections.Generic.HashSet[string]]::new($ExcludedEligibleRoleUserMetrics.UserIds, [System.StringComparer]::OrdinalIgnoreCase)
        $ExcludedNetPotentialRoleUserIds.ExceptWith($ExcludedActualUserIds)

        $IncUsersViaGroups = $IncludedGroupUserMetrics.Count
        $ExcUsersViaGroups = $ExcludedGroupUserMetrics.Count
        $IncPotentialUsersViaGroups = $IncludedNetPotentialGroupUserIds.Count
        $ExcPotentialUsersViaGroups = $ExcludedNetPotentialGroupUserIds.Count
        $IncUsersViaRoles = $IncludedRoleUserMetrics.Count
        $ExcUsersViaRoles = $ExcludedRoleUserMetrics.Count
        $IncPotentialUsersViaRoles = $IncludedNetPotentialRoleUserIds.Count
        $ExcPotentialUsersViaRoles = $ExcludedNetPotentialRoleUserIds.Count
        $IncUsersViaExternalCategories = $IncludedExternalUserMetrics.Count
        $ExcUsersViaExternalCategories = $ExcludedExternalUserMetrics.Count
        $IncUsersViaGroupsDisplay = Format-ApproximateBreakdownDisplayValue -Value $IncUsersViaGroups -Approximate $IncludedGroupUserMetrics.Approximate
        $ExcUsersViaGroupsDisplay = Format-ApproximateBreakdownDisplayValue -Value $ExcUsersViaGroups -Approximate $ExcludedGroupUserMetrics.Approximate
        $IncUsersViaRolesDisplay = Format-ApproximateBreakdownDisplayValue -Value $IncUsersViaRoles -Approximate $IncludedRoleUserMetrics.Approximate
        $ExcUsersViaRolesDisplay = Format-ApproximateBreakdownDisplayValue -Value $ExcUsersViaRoles -Approximate $ExcludedRoleUserMetrics.Approximate
        $IncUsersViaExternalCategoriesDisplay = Format-ApproximateBreakdownDisplayValue -Value (Get-ExternalUsersBreakdownDisplayValue -ResolvedCount $IncUsersViaExternalCategories -TargetingResolution $IncludedExternalTargetingResolution) -Approximate $IncludedExternalTargetingResolution.RequiresVisualApproximation -AllowZeroApproximate $true
        $ExcUsersViaExternalCategoriesDisplay = Format-ApproximateBreakdownDisplayValue -Value (Get-ExternalUsersBreakdownDisplayValue -ResolvedCount $ExcUsersViaExternalCategories -TargetingResolution $ExcludedExternalTargetingResolution) -Approximate $ExcludedExternalTargetingResolution.RequiresVisualApproximation -AllowZeroApproximate $true
        $IncludedAllOverlapCount = [int]$IncludedDirectUserMetrics.Count + [int]$IncUsersViaGroups + [int]$IncUsersViaRoles + [int]$IncUsersViaExternalCategories
        $IncludedAllOverlapDisplay = Format-ApproximateBreakdownDisplayValue -Value $IncludedAllOverlapCount -Approximate ($IncludedGroupUserMetrics.Approximate -or $IncludedRoleUserMetrics.Approximate -or $IncludedExternalTargetingResolution.RequiresVisualApproximation)
        $IncludedDisplayApproximate = ($IncludedExternalTargetingResolution.RequiresVisualApproximation -and -not $IncludedDirectUserMetrics.HasAll)
        $ExcludedDisplayApproximate = $ExcludedExternalTargetingResolution.RequiresVisualApproximation
        $IncludedHasNoExactUserTargeting = ($IncludedDirectUserMetrics.HasNone -and $IncUsersViaGroups -eq 0 -and $IncUsersViaRoles -eq 0 -and $IncUsersViaExternalCategories -eq 0 -and -not $IncludedDisplayApproximate)
        $ExcludedHasNoExactUserTargeting = ($ExcludedDirectUserMetrics.HasNone -and $ExcUsersViaGroups -eq 0 -and $ExcUsersViaRoles -eq 0 -and $ExcUsersViaExternalCategories -eq 0 -and -not $ExcludedDisplayApproximate)
        $EffectiveTargetingNotesList = [System.Collections.Generic.List[string]]::new()
        if ($IncludedExternalTargetingResolution.HasUnknownTypes -or $ExcludedExternalTargetingResolution.HasUnknownTypes) {
            $unknownTypes = @(
                $IncludedExternalTargetingResolution.UnknownTypes +
                $ExcludedExternalTargetingResolution.UnknownTypes
            ) | Sort-Object -Unique
            [void]$EffectiveTargetingNotesList.Add("Approximate count: external user types other than b2bCollaborationGuest cannot be resolved to concrete users. Types: $($unknownTypes -join ', ').")
        }
        if ($IncludedExternalTargetingResolution.HasEnumeratedTenants -or $ExcludedExternalTargetingResolution.HasEnumeratedTenants) {
            [void]$EffectiveTargetingNotesList.Add("Approximate count: external-tenant selections with membershipKind 'enumerated' cannot be resolved to concrete guest users.")
        }
        if ($IncludedExternalTargetingResolution.IsLegacyGuestsOrExternalUsersSelector -or $ExcludedExternalTargetingResolution.IsLegacyGuestsOrExternalUsersSelector) {
            [void]$EffectiveTargetingNotesList.Add("Legacy selector GuestsOrExternalUsers was normalized to the structured external-user categories for coverage calculations.")
        }
        if ($IncPotentialUsersViaGroups -gt 0 -or $ExcPotentialUsersViaGroups -gt 0) {
            [void]$EffectiveTargetingNotesList.Add("PotentialUsersViaGroups are eligible users to targeted groups and are not included in EffectiveUsers or UserCoverage.")
        }
        if ($IncPotentialUsersViaRoles -gt 0 -or $ExcPotentialUsersViaRoles -gt 0) {
            [void]$EffectiveTargetingNotesList.Add("PotentialUsersViaRoles are eligible users to targeted roles and are not included in EffectiveUsers or UserCoverage.")
        }
        $NetEffectiveUsersRequiresApproximation = (
            $IncludedGroupUserMetrics.Approximate -or
            $ExcludedGroupUserMetrics.Approximate -or
            $IncludedRoleUserMetrics.Approximate -or
            $ExcludedRoleUserMetrics.Approximate
        )
        if ($NetEffectiveUsersRequiresApproximation) {
            [void]$EffectiveTargetingNotesList.Add("Approximate count: net effective users could not be deduplicated exactly because some targeted groups or roles only exposed aggregate user counts.")
        }
        $EffectiveTargetingNotes = ($EffectiveTargetingNotesList -join "`n")
        $TotalUsersCount = if ($null -ne $CapRelevantUsersLookup) { [int]$CapRelevantUsersLookup.Count } else { 0 }
        $ExcludedEffectiveMetrics = Merge-EffectiveTargetingMetrics -DirectMetrics $ExcludedDirectUserMetrics -GroupMetrics $ExcludedGroupUserMetrics -RoleMetrics $ExcludedRoleUserMetrics -ExternalMetrics $ExcludedExternalUserMetrics
        $ExcludedEffectiveUsersCount = if ($ExcludedHasNoExactUserTargeting) { 0 } else { [int]$ExcludedEffectiveMetrics.EffectiveCount }
        $ExcludedCoverage = if ($ExcludedHasNoExactUserTargeting) { "0.0%" } else { Format-UserCoverageValue -EffectiveUsers $ExcludedEffectiveUsersCount -TotalUsers $TotalUsersCount }
        $ExcludedUserCoverageDisplay = Format-ApproximateDisplayValue -Value $ExcludedCoverage -Approximate $ExcludedDisplayApproximate

        $ExcludedEffectiveTargetingRow = [pscustomobject]@{
            Scope             = "Excluded"
            DirectUsers       = if ($ExcludedHasNoExactUserTargeting) { "None" } else { $ExcludedDirectUserMetrics.Count }
            UsersViaGroups    = $ExcUsersViaGroupsDisplay
            UsersViaRoles     = $ExcUsersViaRolesDisplay
            UsersViaExternalCategories = $ExcUsersViaExternalCategoriesDisplay
            EffectiveUsers    = if ($ExcludedHasNoExactUserTargeting) { "None" } else { Format-ApproximateDisplayValue -Value $ExcludedEffectiveMetrics.EffectiveCount -Approximate $ExcludedDisplayApproximate }
            Overlap           = if ($ExcludedHasNoExactUserTargeting) { "-" } else { Format-ApproximateBreakdownDisplayValue -Value $ExcludedEffectiveMetrics.OverlapCount -Approximate $ExcludedEffectiveMetrics.IsApproximate }
            UserCoverage      = $ExcludedUserCoverageDisplay
            UncoveredUsers    = "-"
            PotentialUsersViaGroups = $ExcPotentialUsersViaGroups
            PotentialUsersViaRoles = $ExcPotentialUsersViaRoles
        }

        $IncludedEffectiveUsersCount = 0
        $IncludedCoverage = "0.0%"

        if ($IncludedDirectUserMetrics.HasAll) {
            $IncludedEffectiveUsersCount = $TotalUsersCount
            $IncludedCoverage = Format-UserCoverageValue -EffectiveUsers $IncludedEffectiveUsersCount -TotalUsers $TotalUsersCount
            $EffectiveTargeting = @(
                [pscustomobject]@{
                    Scope             = "Included"
                    DirectUsers       = "All"
                    UsersViaGroups    = $IncUsersViaGroupsDisplay
                    UsersViaRoles     = $IncUsersViaRolesDisplay
                    UsersViaExternalCategories = $IncUsersViaExternalCategoriesDisplay
                    EffectiveUsers    = Get-AllUsersEffectiveDisplay -Users $CapRelevantUsersLookup
                    Overlap           = $IncludedAllOverlapDisplay
                    UserCoverage      = $IncludedCoverage
                    UncoveredUsers    = "-"
                    PotentialUsersViaGroups = $IncPotentialUsersViaGroups
                    PotentialUsersViaRoles = $IncPotentialUsersViaRoles
                }
                $ExcludedEffectiveTargetingRow
            )
        } elseif ($IncludedHasNoExactUserTargeting) {
            $EffectiveTargeting = @(
                [pscustomobject]@{
                    Scope             = "Included"
                    DirectUsers       = "None"
                    UsersViaGroups    = $IncUsersViaGroupsDisplay
                    UsersViaRoles     = $IncUsersViaRolesDisplay
                    UsersViaExternalCategories = $IncUsersViaExternalCategoriesDisplay
                    EffectiveUsers    = "None"
                    Overlap           = "-"
                    UserCoverage      = $IncludedCoverage
                    UncoveredUsers    = "-"
                    PotentialUsersViaGroups = $IncPotentialUsersViaGroups
                    PotentialUsersViaRoles = $IncPotentialUsersViaRoles
                }
                $ExcludedEffectiveTargetingRow
            )
        } else {
            $IncludedEffectiveMetrics = Merge-EffectiveTargetingMetrics -DirectMetrics $IncludedDirectUserMetrics -GroupMetrics $IncludedGroupUserMetrics -RoleMetrics $IncludedRoleUserMetrics -ExternalMetrics $IncludedExternalUserMetrics
            $IncludedEffectiveUsersCount = [int]$IncludedEffectiveMetrics.EffectiveCount
            $IncludedCoverage = Format-UserCoverageValue -EffectiveUsers $IncludedEffectiveUsersCount -TotalUsers $TotalUsersCount
            $IncludedUserCoverageDisplay = Format-ApproximateDisplayValue -Value $IncludedCoverage -Approximate $IncludedDisplayApproximate
            $EffectiveTargeting = @(
                [pscustomobject]@{
                    Scope             = "Included"
                    DirectUsers       = $IncludedDirectUserMetrics.Count
                    UsersViaGroups    = $IncUsersViaGroupsDisplay
                    UsersViaRoles     = $IncUsersViaRolesDisplay
                    UsersViaExternalCategories = $IncUsersViaExternalCategoriesDisplay
                    EffectiveUsers    = Format-ApproximateDisplayValue -Value $IncludedEffectiveMetrics.EffectiveCount -Approximate $IncludedDisplayApproximate
                    Overlap           = Format-ApproximateBreakdownDisplayValue -Value $IncludedEffectiveMetrics.OverlapCount -Approximate $IncludedEffectiveMetrics.IsApproximate
                    UserCoverage      = $IncludedUserCoverageDisplay
                    UncoveredUsers    = "-"
                    PotentialUsersViaGroups = $IncPotentialUsersViaGroups
                    PotentialUsersViaRoles = $IncPotentialUsersViaRoles
                }
                $ExcludedEffectiveTargetingRow
            )
        }

        if ($NetEffectiveUsersRequiresApproximation) {
            $NetEffectiveUsers = [Math]::Max(($IncludedEffectiveUsersCount - $ExcludedEffectiveUsersCount), 0)
        } else {
            $NetEffectiveUserIds = [System.Collections.Generic.HashSet[string]]::new($IncludedActualUserIds, [System.StringComparer]::OrdinalIgnoreCase)
            $NetEffectiveUserIds.ExceptWith($ExcludedActualUserIds)
            $NetEffectiveUsers = $NetEffectiveUserIds.Count
        }
        $UserCoverage = Format-UserCoverageValue -EffectiveUsers $NetEffectiveUsers -TotalUsers $TotalUsersCount
        $UserCoverageValue = if ($TotalUsersCount -le 0) {
            0.0
        } else {
            $coveragePercent = ([double]$NetEffectiveUsers / [double]$TotalUsersCount) * 100
            $roundedCoverage = [Math]::Round($coveragePercent, 1)

            if ($coveragePercent -lt 100 -and $roundedCoverage -ge 100) {
                99.9
            } elseif ($coveragePercent -gt 0 -and $roundedCoverage -le 0) {
                0.1
            } else {
                $roundedCoverage
            }
        }
        $UncoveredUsers = [Math]::Max(($TotalUsersCount - $NetEffectiveUsers), 0)
        $TotalDisplayApproximate = ($IncludedDisplayApproximate -or $ExcludedDisplayApproximate -or $NetEffectiveUsersRequiresApproximation)
        $UserCoverageDisplay = Format-ApproximateDisplayValue -Value $UserCoverage -Approximate $TotalDisplayApproximate
        Write-Log -Level Debug -Message "CAP targeting summary for '$($policy.DisplayName)' [$($policy.Id)]: Included(direct=$IncludedUserCount, groups=$IncUsersViaGroups, roles=$IncUsersViaRoles, externalUsers=$IncUsersViaExternalCategories, effective=$IncludedEffectiveUsersCount) Excluded(direct=$($NormalizedExcludeUsers.Count), groups=$ExcUsersViaGroups, roles=$ExcUsersViaRoles, externalUsers=$ExcUsersViaExternalCategories, effective=$ExcludedEffectiveUsersCount) NetEffective=$NetEffectiveUsers Uncovered=$UncoveredUsers UserCoverage=$UserCoverageValue Potential(groups=$IncPotentialUsersViaGroups/$ExcPotentialUsersViaGroups, roles=$IncPotentialUsersViaRoles/$ExcPotentialUsersViaRoles)"
        $EffectiveTargeting += [pscustomobject]@{
            Scope             = "Total"
            DirectUsers       = "-"
            UsersViaGroups    = "-"
            UsersViaRoles     = "-"
            UsersViaExternalCategories = "-"
            EffectiveUsers    = Format-ApproximateDisplayValue -Value $NetEffectiveUsers -Approximate $TotalDisplayApproximate
            Overlap           = "-"
            UserCoverage      = $UserCoverageDisplay
            UncoveredUsers    = Format-ApproximateDisplayValue -Value $UncoveredUsers -Approximate $TotalDisplayApproximate
            PotentialUsersViaGroups = "-"
            PotentialUsersViaRoles = "-"
        }

        $hasUserTargetingForExport = (
            $IncludedDirectUserMetrics.HasAll -or
            $IncludedDirectUserMetrics.Count -gt 0 -or
            $IncUsersViaGroups -gt 0 -or
            $IncPotentialUsersViaGroups -gt 0 -or
            $IncUsersViaRoles -gt 0 -or
            $IncPotentialUsersViaRoles -gt 0 -or
            $IncUsersViaExternalCategories -gt 0
        )

        if ($ExportCapUncoveredUsers -and $policy.State -eq "enabled" -and $hasUserTargetingForExport) {
            $includedTargetUserIds = Get-EffectiveTargetingUserIds -DirectMetrics $IncludedDirectUserMetrics -GroupMetrics $IncludedGroupUserMetrics -RoleMetrics $IncludedRoleUserMetrics -ExternalMetrics $IncludedExternalUserMetrics -AllUserIds $EnabledUserIds -HasAll $IncludedDirectUserMetrics.HasAll
            $excludedTargetUserIds = Get-EffectiveTargetingUserIds -DirectMetrics $ExcludedDirectUserMetrics -GroupMetrics $ExcludedGroupUserMetrics -RoleMetrics $ExcludedRoleUserMetrics -ExternalMetrics $ExcludedExternalUserMetrics -AllUserIds $EnabledUserIds -HasAll $ExcludedDirectUserMetrics.HasAll
            $netTargetUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $includedPotentialPimUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($userId in $includedTargetUserIds) {
                if (-not $excludedTargetUserIds.Contains([string]$userId)) {
                    [void]$netTargetUserIds.Add([string]$userId)
                }
            }

            foreach ($userId in $IncludedNetPotentialGroupUserIds) {
                [void]$includedPotentialPimUserIds.Add([string]$userId)
            }
            foreach ($userId in $IncludedNetPotentialRoleUserIds) {
                [void]$includedPotentialPimUserIds.Add([string]$userId)
            }

            $capUncoveredUsersRows = [System.Collections.Generic.List[object]]::new()
            $excludedReasonCount = 0
            $potentialViaPimReasonCount = 0
            $notTargetedReasonCount = 0
            foreach ($enabledUserEntry in $EnabledUsersLookup.GetEnumerator()) {
                $userId = [string]$enabledUserEntry.Key
                if ($netTargetUserIds.Contains($userId)) { continue }

                $userObject = $enabledUserEntry.Value
                $reason = if ($excludedTargetUserIds.Contains($userId)) {
                    $excludedReasonCount++
                    "Excluded"
                } elseif ($includedPotentialPimUserIds.Contains($userId)) {
                    $potentialViaPimReasonCount++
                    "PotentialViaPIM"
                } else {
                    $notTargetedReasonCount++
                    "NotTargeted"
                }
                $capUncoveredUsersRows.Add([pscustomobject]@{
                    UPN          = $userObject.UPN
                    UserType     = $userObject.UserType
                    EntraMaxTier = $userObject.EntraMaxTier
                    AzureMaxTier = $userObject.AzureMaxTier
                    MfaCap       = $userObject.MfaCap
                    Impact       = $userObject.Impact
                    Reason       = $reason
                }) | Out-Null
            }

            $safePolicyName = Get-SafeFileName -Name $policy.DisplayName
            $shortPolicyId = if ([string]::IsNullOrWhiteSpace([string]$policy.Id)) { "unknown" } else { ([string]$policy.Id).Substring(0, [Math]::Min(8, ([string]$policy.Id).Length)) }
            $csvFilePath = Join-Path $CapUncoveredUsersOutputFolder "$safePolicyName`_$shortPolicyId.csv"
            Write-Log -Level Debug -Message "CAP uncovered-users export summary for '$($policy.DisplayName)' [$($policy.Id)]: includedTargeted=$($includedTargetUserIds.Count) excludedTargeted=$($excludedTargetUserIds.Count) netTargeted=$($netTargetUserIds.Count) potentialViaPim=$($includedPotentialPimUserIds.Count) uncovered=$($capUncoveredUsersRows.Count) reasons=(Excluded=$excludedReasonCount, PotentialViaPIM=$potentialViaPimReasonCount, NotTargeted=$notTargetedReasonCount)"
            if ($capUncoveredUsersRows.Count -gt 0) {
                $capUncoveredUsersRows | Sort-Object Reason,EntraMaxTier,UPN | Export-Csv -Path $csvFilePath -NoTypeInformation
                $capUncoveredExportFilesWritten++
                $capUncoveredExportRows += $capUncoveredUsersRows.Count
            } else {
                $capUncoveredExportSkippedEmpty++
                Write-Log -Level Debug -Message "CAP uncovered-users export skipped file write for '$($policy.DisplayName)' [$($policy.Id)]: no uncovered enabled users remained after effective targeting."
            }
        } elseif ($ExportCapUncoveredUsers -and $policy.State -eq "enabled" -and -not $hasUserTargetingForExport) {
            $capUncoveredExportSkippedNoTargeting++
            Write-Log -Level Debug -Message "CAP uncovered-users export skipped for '$($policy.DisplayName)' [$($policy.Id)]: no effective user targeting detected."
        }

        if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
            $IncludedResourcesCount = "All"
        } else {
            $IncludedResourcesCount = $policy.Conditions.Applications.IncludeApplications.count
        }

        if ($policy.Conditions.Applications.IncludeApplications -contains "None") {
            $IncludedResourcesCount = 0
        }
        
        if ($policy.Conditions.Locations.IncludeLocations -contains "AllTrusted") {
            $IncludedNwLocations = "AllTrusted"
            $IncludedNwLocationsCount = 1
        } elseif ($policy.Conditions.Locations.IncludeLocations -contains "AllCompliant") {
            $IncludedNwLocations = "AllCompliant"
            $IncludedNwLocationsCount = 1
        } elseif ($policy.Conditions.Locations.IncludeLocations -contains "All") {
            $IncludedNwLocations = "All"
            $IncludedNwLocationsCount = 0
        } else {
            $IncludedNwLocations = $policy.Conditions.Locations.IncludeLocations.count
            $IncludedNwLocationsCount = $IncludedNwLocations
        }

        if ($policy.Conditions.Locations.ExcludeLocations -contains "AllTrusted") {
            $ExcludedNwLocations = "AllTrusted"
            $ExcludedNwLocationsCount = 1
        } elseif ($policy.Conditions.Locations.ExcludeLocations -contains "AllCompliant") {
            $ExcludedNwLocations = "AllCompliant"
            $ExcludedNwLocationsCount = 1
        } elseif ($policy.Conditions.Locations.ExcludeLocations -contains "All") {
            $ExcludedNwLocations = "All"
            $ExcludedNwLocationsCount = 0
        } else {
            $ExcludedNwLocations = $policy.Conditions.Locations.ExcludeLocations.count
            $ExcludedNwLocationsCount = $ExcludedNwLocations
        }

        if ($policy.Conditions.Platforms.IncludePlatforms -contains "All") {
            $IncPlatforms = "All"
            # $IncPlatformsCount needed to check there are exceptions
            $IncPlatformsCount = 0
        } else {
            $IncPlatforms = $policy.Conditions.Platforms.IncludePlatforms.count
            $IncPlatformsCount = $IncPlatforms
        }

        if ($policy.Conditions.Platforms.ExcludePlatforms -contains "All") {
            $ExcPlatforms = "All"
        } else {
            $ExcPlatforms = $policy.Conditions.Platforms.ExcludePlatforms.count
        }

        if ($policy.Conditions.ClientAppTypes -contains "all") {
            $ClientAppTypesCount = 0
        } else {
            $ClientAppTypesCount = $policy.Conditions.ClientAppTypes.count
        }

        # Count Session Controls
        $SessionControls = 0
        foreach ($prop in $policy.sessionControls.PSObject.Properties) {
            if ($null -ne $prop.Value -and "$($prop.Value)" -ne '') {
                $SessionControls++
            }
        }

        $SignInFrequency = $false
        $SignInFrequencyInterval = ""
        if ($null -ne $policy.sessionControls) {
            $signInFreq = $policy.sessionControls.signInFrequency

            if ($null -ne $signInFreq -and $signInFreq.isEnabled -eq $true) {
                $SignInFrequency = $true
                if ($signInFreq.frequencyInterval -eq "everyTime") {
                    $SignInFrequencyInterval = "EveryTime"
                }
                elseif ($signInFreq.frequencyInterval -eq "timeBased" -and $null -ne $signInFreq.value -and $signInFreq.type) {
                    $SignInFrequencyInterval = "$($signInFreq.value) $($signInFreq.type)"
                }
            }
        }
        

        #Get Authcontext
        $AuthContextId = $policy.Conditions.Applications.IncludeAuthenticationContextClassReferences
        
        # Check if there are used Entra role assignments (Tier 0 & 1) which are no in the IncludeRoles
        $includedRoleIds = $policy.Conditions.Users.IncludeRoles
        $unmatchedRoleCounts = @{}

        # If 5 or more are targeted assuming all tier0 and tier1 roles should be included
        if (@($includedRoleIds).count -ge 5) {
            foreach ($assignment in $HighTierAssignments) {
                $roleId   = $assignment.RoleDefinitionId
                $roleName = $assignment.DisplayName
                $roleTier = $assignment.RoleTier
            
                # Unmatched high-tier roles
                if ($includedRoleIds -notcontains $roleId) {
                    if (-not $unmatchedRoleCounts.ContainsKey($roleName)) {
                        $unmatchedRoleCounts[$roleName] = @{
                            Count = 0
                            Tier  = $roleTier
                        }
                    }
                    $unmatchedRoleCounts[$roleName]["Count"]++
                }
            }
        }

        #Check if there are roles targetd which have a scoped assignment
        $ScopedRoles = @()
        $seenScopedRoleIds = @()        
        foreach ($roleId in $includedRoleIds) {
            if ($ScopedAssignments.ContainsKey($roleId) -and $seenScopedRoleIds -notcontains $roleId) {
                $seenScopedRoleIds += $roleId
        
                $info = $ScopedAssignments[$roleId]
                $ScopedRoles += [PSCustomObject]@{
                    RoleName              = $info.RoleName
                    RoleTier              = $info.RoleTier
                    Assignments           = $info.Count
                }
            }
        }
        $ScopedRolesCount = $ScopedRoles.count

        #Store missing roles in a var
        $MissingRolesTable = @()
        if ($unmatchedRoleCounts.Count -ne 0) {
            $MissingRolesTable = $unmatchedRoleCounts.GetEnumerator() |
                ForEach-Object {
                    [PSCustomObject]@{
                        RoleName    = $_.Key
                        RoleTier    = $_.Value.Tier
                        Assignments = $_.Value.Count
                    }
                } | Sort-Object RoleTier, RoleName

            $tier0Count = @($unmatchedRoleCounts.Values | Where-Object { $_.Tier -eq 0 }).Count
            $tier1Count = @($unmatchedRoleCounts.Values | Where-Object { $_.Tier -eq 1 }).Count
            
            $parts = @()
            if ($tier0Count -gt 0) { $parts += "Tier-0: $tier0Count" }
            if ($tier1Count -gt 0) { $parts += "Tier-1: $tier1Count" }
            
            if ($parts.Count -gt 0) {
                $MissingRolesWarning = "missing used roles (" + ($parts -join " / ") + ")"
            }
        }
        $MissingRolesCount = $MissingRolesTable.count

        # Build the warning text for missing privileged-role coverage.
        if ($ScopedRolesCount -gt 0) {
            $targetedCount = @($includedRoleIds).Count
            $scopedCount   = @($ScopedRoles).Count

            $roleWord = if ($targetedCount -eq 1) { "targeted role" } else { "targeted roles" }
            $assignmentWord = if ($scopedCount -eq 1) { "has scoped assignments" } else { "have scoped assignments" }

            $ScopedRolesWarning = "$scopedCount of the $targetedCount $roleWord $assignmentWord"
        }


        ###################### Analyzing policies

        $ExcludedUsersEffective = $ExcludedEffectiveUsersCount
        $ExcludedGuestUsersEffective = 0
        foreach ($excludedUserId in $ExcludedActualUserIds) {
            if (-not $CapRelevantUsersLookup.ContainsKey($excludedUserId)) { continue }
            $excludedUser = $CapRelevantUsersLookup[$excludedUserId]
            if ("$($excludedUser.UserType)".Trim().ToLowerInvariant() -eq "guest") {
                $ExcludedGuestUsersEffective++
            }
        }
        $ExcludedUsersWarningMessage = "has $ExcludedUsersEffective effectively excluded users"
        $ExcludedUsersEffectiveForCap002 = [Math]::Max(($ExcludedUsersEffective - $ExcludedGuestUsersEffective), 0)
        $ExcludedUsersWarningMessageForCap002 = "has $ExcludedUsersEffectiveForCap002 effectively excluded users"
        $ExcludedRolesCount = @($policy.Conditions.Users.ExcludeRoles).Count
        $ExcludedNonUserTargets = $ExcludedRolesCount + $ExcludedExternalUsersCount
        
        #Count condition types for policy complexity checks
        $SignInRiskCount = $policy.Conditions.SignInRiskLevels.count
        $UserRiskCount = $policy.Conditions.UserRiskLevels.count
        $AuthFlowCount = $policy.Conditions.AuthenticationFlows.TransferMethods.count

        $HasDeviceFilter = $false
        if ($policy.Conditions.Devices -and $policy.Conditions.Devices.DeviceFilter) {
            $rule = $policy.Conditions.Devices.DeviceFilter.Rule
            $HasDeviceFilter = $null -ne $rule -and @($rule).Count -gt 0
        }
        $HasPlatforms = ($IncPlatformsCount -gt 0 -or $ExcPlatforms -gt 0)
        $HasSignInRisk = ($SignInRiskCount -gt 0)
        $HasUserRisk = ($UserRiskCount -gt 0)
        $HasNetworkLocations = ($IncludedNwLocationsCount -gt 0 -or $ExcludedNwLocationsCount -gt 0)
        $HasClientApps = ($ClientAppTypesCount -gt 0)
        $HasAuthFlows = ($AuthFlowCount -gt 0)

        $ConditionTypeCount = 0
        if ($HasDeviceFilter) { $ConditionTypeCount++ }
        if ($HasPlatforms) { $ConditionTypeCount++ }
        if ($HasSignInRisk) { $ConditionTypeCount++ }
        if ($HasUserRisk) { $ConditionTypeCount++ }
        if ($HasNetworkLocations) { $ConditionTypeCount++ }
        if ($HasClientApps) { $ConditionTypeCount++ }
        if ($HasAuthFlows) { $ConditionTypeCount++ }

        if ($ConditionTypeCount -gt 1) {
            Write-Log -Level Debug -Message "Condition types for '$($policy.DisplayName)': total=$ConditionTypeCount (DeviceFilter=$HasDeviceFilter, Platforms=$HasPlatforms, SignInRisk=$HasSignInRisk, UserRisk=$HasUserRisk, NetworkLocations=$HasNetworkLocations, ClientApps=$HasClientApps, AuthFlows=$HasAuthFlows)"
        }

        #Check policy for DeviceCodeFlow
        if ($policy.Conditions.AuthenticationFlows.TransferMethods -match "deviceCodeFlow") {
            $PolicyDeviceCodeFlow = $true
            $DeviceCodeFlowWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $DeviceCodeFlowWarnings++
            }
            if ($policy.GrantControls.BuiltInControls -notcontains "block") {
                $ErrorMessages += "is not Grant: Block"
                $DeviceCodeFlowWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $DeviceCodeFlowWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $DeviceCodeFlowWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $DeviceCodeFlowWarnings++            
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $DeviceCodeFlowWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $DeviceCodeFlowWarnings++
            }
            $additionalConditionTypes = $ConditionTypeCount - 1 # DeviceCode Flow is a condition by itself
            if ($additionalConditionTypes -gt 0) {
                $ErrorMessages += "has ($additionalConditionTypes) additional condition types"
                $DeviceCodeFlowWarnings++
            }
            if ($DeviceCodeFlowWarnings -ge 1) {
                $warningMessage = "Targeting Device Code flow but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        #Check policy for blocking legacy authentication
        if ($policy.Conditions.ClientAppTypes -contains "exchangeActiveSync" -and $policy.Conditions.ClientAppTypes -contains "other" -and -not ($policy.Conditions.ClientAppTypes -contains "browser") -and -not ($policy.Conditions.ClientAppTypes -contains "mobileAppsAndDesktopClients")) {
            $PolicyLegacyAuth = $true
            $LegacyAuthWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $LegacyAuthWarnings++
            }
            if ($policy.GrantControls.BuiltInControls -notcontains "block") {
                $ErrorMessages += "is not Grant: Block"
                $LegacyAuthWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $LegacyAuthWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $LegacyAuthWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $LegacyAuthWarnings++           
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $LegacyAuthWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $LegacyAuthWarnings++
            }
            $additionalConditionTypes = $ConditionTypeCount - 1 # ClientAppTypes are a condition by themself
            if ($additionalConditionTypes -gt 0) {
                $ErrorMessages += "has ($additionalConditionTypes) additional condition types"
                $LegacyAuthWarnings++
            }
        
            if ($LegacyAuthWarnings -ge 1) {
                $warningMessage = "Targeting Legacy Auth but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        #Check policy for managing SignInRisk
        if ($policy.Conditions.SignInRiskLevels.count -ge 1 -and $policy.Conditions.UserRiskLevels.count -eq 0) {
            $PolicyRiskySignIn = $true
            $SignInRiskWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $SignInRiskWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $SignInRiskWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $SignInRiskWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $SignInRiskWarnings++            
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $SignInRiskWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $SignInRiskWarnings++
            }
            $additionalConditionTypes = $ConditionTypeCount - 1 # SignInRiskLevels is condition by itself
            if ($additionalConditionTypes -gt 0) {
                $ErrorMessages += "has additional ($additionalConditionTypes) condition types"
                $SignInRiskWarnings++
            }
        
            if ($SignInRiskWarnings -ge 1) {
                $warningMessage = "Targeting risky sign-ins but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        #Check policy for managing UserRisk
        if ($policy.Conditions.UserRiskLevels.count -ge 1 -and $policy.Conditions.SignInRiskLevels.count -eq 0) {
            $PolicyUserRisk = $true
            $UserRiskWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $UserRiskWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $UserRiskWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $UserRiskWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $UserRiskWarnings++          
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $UserRiskWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $UserRiskWarnings++
            }
            $additionalConditionTypes = $ConditionTypeCount - 1 # UserRiskLevels is condition by itself
            if ($additionalConditionTypes -gt 0) {
                $ErrorMessages += "has additional ($additionalConditionTypes) condition types"
                $UserRiskWarnings++
            }
        
            if ($UserRiskWarnings -ge 1) {
                $warningMessage = "Targeting user risk but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        #Check for the common case where user risk and sign-in risk are managed in the same policy
        if ($policy.Conditions.UserRiskLevels.count -ge 1 -and $policy.Conditions.SignInRiskLevels.count -ge 1) {
            $PolicyUserRisk = $true
            $PolicyRiskySignIn = $true
            $CombinedRiskWarnings = 0
            $ErrorMessages = @()
            $ErrorMessages += "includes both user risk and sign-in risk in the same policy"

            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $CombinedRiskWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $CombinedRiskWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $CombinedRiskWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $CombinedRiskWarnings++         
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $CombinedRiskWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $CombinedRiskWarnings++
            }
            $additionalConditionTypes = $ConditionTypeCount - 2 # UserRiskLevels and SignInRiskLevels are conditions by themself
            if ($additionalConditionTypes -gt 0) {
                $ErrorMessages += "has additional ($additionalConditionTypes) condition types"
                $CombinedRiskWarnings++
            }

            if ($ErrorMessages.Count -ge 1) {
                $warningMessage = "Targeting risks but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        #Check policy for registering security infos
        if ($policy.Conditions.Applications.IncludeUserActions -contains "urn:user:registersecurityinfo") {
            $PolicyRegSecInfo = $true
            $RegisterSecInfosWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $RegisterSecInfosWarnings++
            }
            if ($ExcludedUsersEffectiveForCap002 -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessageForCap002
                $RegisterSecInfosWarnings++
            }
            if ($ExcludedRolesCount -gt 0) {
                $ErrorMessages += "has $ExcludedRolesCount excluded roles"
                $RegisterSecInfosWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $RegisterSecInfosWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $RegisterSecInfosWarnings++          
            }
            if ($ConditionTypeCount -gt 2) {
                $ErrorMessages += "has multiple ($ConditionTypeCount) condition types"
                $RegisterSecInfosWarnings++
            }
        
            if ($RegisterSecInfosWarnings -ge 1) {
                $warningMessage = "Targeting registration of security infos but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }
  
        #Check policy for joining or registering devices
        if ($policy.Conditions.Applications.IncludeUserActions -contains "urn:user:registerdevice") {
            $PolicyRegDevices = $true
            $RegisterDevicesInfosWarnings = 0
            $ErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $RegisterDevicesInfosWarnings++
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += $ExcludedUsersWarningMessage
                $RegisterDevicesInfosWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $RegisterDevicesInfosWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $RegisterDevicesInfosWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $RegisterDevicesInfosWarnings++              
            }
            if ($ConditionTypeCount -gt 1) {
                $ErrorMessages += "has multiple ($ConditionTypeCount) condition types"
                $RegisterDevicesInfosWarnings++
            }
        
            if ($RegisterDevicesInfosWarnings -ge 1) {
                $warningMessage = "Targeting joining or registering devices but " + ($ErrorMessages -join ", ")
                Add-UniqueStringItems -Target $PolicyWarningParts -Items @($warningMessage)
            }
        }

        # Derive auth-strength semantics from the inline policy payload so the resulting CAP row
        # reflects the same object Conditional Access uses for this policy.
        $AuthStrengthMetadata = Get-CapAuthStrengthMetadata -AuthenticationStrength $policy.GrantControls.AuthenticationStrength
        $AuthStrength = [string]$AuthStrengthMetadata.DisplayName
        $AuthStrengthId = [string]$AuthStrengthMetadata.Id
        $AuthStrengthResolved = [bool]$AuthStrengthMetadata.Resolved
        $AuthStrengthPhishingResistantOnly = [bool]$AuthStrengthMetadata.PhishingResistantOnly
        $AuthStrengthMfaCombinationsOnly = [bool]$AuthStrengthMetadata.MfaCombinationsOnly
        $AuthStrengthContainsSingleFactorElements = [bool]$AuthStrengthMetadata.ContainsSingleFactorElements
        $AuthStrengthAllowedCombinations = [string]$AuthStrengthMetadata.AllowedCombinations

        $hasNoAuthFlow = $null -eq $policy.Conditions.AuthenticationFlows.TransferMethods -or $policy.Conditions.AuthenticationFlows.TransferMethods.Count -eq 0
        $hasNoUserActions = $null -eq $policy.Conditions.Applications.IncludeUserActions -or $policy.Conditions.Applications.IncludeUserActions.Count -eq 0
        $GrantAssuranceEvaluation = Get-CapGrantAssuranceEvaluation -BuiltInControls $policy.GrantControls.BuiltInControls -Operator $policy.GrantControls.Operator -HasAuthStrength (-not [string]::IsNullOrWhiteSpace($AuthStrengthId)) -AuthStrengthResolved $AuthStrengthResolved -AuthStrengthMfaCombinationsOnly $AuthStrengthMfaCombinationsOnly -AuthStrengthPhishingResistantOnly $AuthStrengthPhishingResistantOnly

        #Check policy for MFA
        if ($GrantAssuranceEvaluation.HasMfaBaselineCandidate -and $policy.Conditions.Applications.IncludeAuthenticationContextClassReferences.count -eq 0 -and $hasNoAuthFlow -and $policy.Conditions.SignInRiskLevels.count -eq 0 -and $policy.Conditions.UserRiskLevels.count -eq 0 -and $hasNoUserActions) {
            if ($GrantAssuranceEvaluation.MfaEquivalentEnforced) {
                $PolicyMfaUser = $true
            }
            $UserMfaWarnings = 0
            $CommonErrorMessages = @()
            $SpecificErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $CommonErrorMessages += "is not enabled"
                $UserMfaWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $CommonErrorMessages += "is not targeting all resources"
                $UserMfaWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $CommonErrorMessages += "is not targeting all users"
                $UserMfaWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $CommonErrorMessages += $MissingRolesWarning
                $UserMfaWarnings++
            }
            if ($ExcludedUsersEffective -ge 3) {
                $CommonErrorMessages += $ExcludedUsersWarningMessage
                $UserMfaWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $CommonErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $UserMfaWarnings++
            }
            if ($ConditionTypeCount -gt 0) {
                $CommonErrorMessages += "has ($ConditionTypeCount) condition types"
                $UserMfaWarnings++
            }
            if (-not $GrantAssuranceEvaluation.MfaEquivalentEnforced -and -not [string]::IsNullOrWhiteSpace($GrantAssuranceEvaluation.MfaWarning)) {
                $SpecificErrorMessages += $GrantAssuranceEvaluation.MfaWarning
                $UserMfaWarnings++
            }
        
            if ($UserMfaWarnings -ge 1) {
                $HasMfaWarningContext = $true
                Add-UniqueStringItems -Target $MfaCommonIssues -Items $CommonErrorMessages
                Add-UniqueStringItems -Target $MfaSpecificIssues -Items $SpecificErrorMessages
            }
        }

        #Check policy with Authentication strengths for enforcing phishing-resistant MFA
        $authStrengthIdCandidate = "$($policy.GrantControls.AuthenticationStrength.Id)".Trim()
        if ($policy.Conditions.Applications.IncludeAuthenticationContextClassReferences.count -eq 0 -and -not [string]::IsNullOrWhiteSpace($authStrengthIdCandidate) -and $policy.Conditions.SignInRiskLevels.count -eq 0 -and $policy.Conditions.UserRiskLevels.count -eq 0 -and $hasNoAuthFlow -and $hasNoUserActions) {
            if ($GrantAssuranceEvaluation.PhishingResistantEnforced) {
                $PolicyAuthStrength = $true
            }
            $AuthStrengthWarnings = 0
            $CommonErrorMessages = @()
            $SpecificErrorMessages = @()
        
            if ($policy.State -ne "enabled") {
                $CommonErrorMessages += "is not enabled"
                $AuthStrengthWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $CommonErrorMessages += "is not targeting all resources"
                $AuthStrengthWarnings++
            }
            if ($ExcludedUsersEffective -ge 3) {
                $CommonErrorMessages += $ExcludedUsersWarningMessage
                $AuthStrengthWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $CommonErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $AuthStrengthWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $CommonErrorMessages += $MissingRolesWarning
                $AuthStrengthWarnings++              
            }
            if ($ConditionTypeCount -gt 1) {
                $CommonErrorMessages += "has multiple ($ConditionTypeCount) condition types"
                $AuthStrengthWarnings++
            }
            if (-not $AuthStrengthResolved) {
                $SpecificErrorMessages += "references authentication strength without enough inline detail to validate it"
                $AuthStrengthWarnings++
            } elseif (-not $AuthStrengthPhishingResistantOnly) {
                $SpecificErrorMessages += "authentication strength is not phishing-resistant only"
                $AuthStrengthWarnings++
            }
            if (-not [string]::IsNullOrWhiteSpace($GrantAssuranceEvaluation.PhishingResistantWarning)) {
                $SpecificErrorMessages += $GrantAssuranceEvaluation.PhishingResistantWarning
                $AuthStrengthWarnings++
            }
        
            if ($AuthStrengthWarnings -ge 1) {
                $HasPhishingWarningContext = $true
                Add-UniqueStringItems -Target $PhishingCommonIssues -Items $CommonErrorMessages
                Add-UniqueStringItems -Target $PhishingSpecificIssues -Items $SpecificErrorMessages
            }
        }

        #General Policy checks
        
        #Check if the role includes roles but scope assignment exist for the role
        if ($ScopedRolesCount -gt 0) {
            Add-UniqueStringItems -Target $PolicyWarningParts -Items @($ScopedRolesWarning)
        }

        $combinedAssuranceWarning = Get-CapCombinedAssuranceWarning -MfaCommonIssues @($MfaCommonIssues) -MfaIssues @($MfaSpecificIssues) -PhishingCommonIssues @($PhishingCommonIssues) -PhishingIssues @($PhishingSpecificIssues) -HasMfaContext $HasMfaWarningContext -HasPhishingContext $HasPhishingWarningContext
        if ($HasMfaWarningContext -or $HasPhishingWarningContext) {
            Write-Log -Level Debug -Message "CAP assurance warning context for '$($policy.DisplayName)' [$($policy.Id)]: MfaContext=$HasMfaWarningContext MfaCommon=$($MfaCommonIssues.Count) MfaSpecific=$($MfaSpecificIssues.Count) PhishingContext=$HasPhishingWarningContext PhishingCommon=$($PhishingCommonIssues.Count) PhishingSpecific=$($PhishingSpecificIssues.Count) Combined='$combinedAssuranceWarning'"
        }
        if (-not [string]::IsNullOrWhiteSpace($combinedAssuranceWarning)) {
            Add-UniqueStringItems -Target $PolicyWarningParts -Items @($combinedAssuranceWarning)
        }
        $WarningPolicy = (Get-DeduplicatedWarningItems -Items @($PolicyWarningParts)) -join " / "
        $TargetType = Get-CapTargetType -Policy $policy


        $ConditionalAccessPolicies.Add([PSCustomObject]@{
            Id = $policy.Id
            DisplayName = $policy.DisplayName
            DisplayNameLink = "<a href=#$($policy.id)>$($policy.DisplayName)</a>"
            TargetType = $TargetType
            Description = $policy.Description
            CreatedDateTime = $policy.CreatedDateTime
            ModifiedDateTime = $policy.ModifiedDateTime
            State = $policy.State
            IncUsers = $IncludedUserCount
            IncUsersViaGroups = $IncUsersViaGroups
            IncPotentialUsersViaGroups = $IncPotentialUsersViaGroups
            IncGroups = $policy.Conditions.Users.IncludeGroups.count
            IncRoles = $policy.Conditions.Users.IncludeRoles.count
            IncUsersViaRoles = $IncUsersViaRoles
            IncPotentialUsersViaRoles = $IncPotentialUsersViaRoles
            IncUsersViaExternalCategories = $IncUsersViaExternalCategories
            IncExternals = $IncludedExternalUsersCount
            ExcUsers = $NormalizedExcludeUsers.Count
            ExcUsersViaGroups = $ExcUsersViaGroups
            ExcPotentialUsersViaGroups = $ExcPotentialUsersViaGroups
            ExcGroups = $policy.Conditions.Users.ExcludeGroups.count
            ExcRoles = $policy.Conditions.Users.ExcludeRoles.count
            ExcUsersViaRoles = $ExcUsersViaRoles
            ExcPotentialUsersViaRoles = $ExcPotentialUsersViaRoles
            ExcUsersViaExternalCategories = $ExcUsersViaExternalCategories
            ExcExternals = $ExcludedExternalUsersCount
            IncludedUsersEffective = $IncludedEffectiveUsersCount
            ExcludedUsersEffective = $ExcludedUsersEffective
            ExcludedGuestUsersEffective = $ExcludedGuestUsersEffective
            NetEffectiveUsers = $NetEffectiveUsers
            UserCoverage = $UserCoverageDisplay
            UserCoverageValue = $UserCoverageValue
            DeviceFilter = $policy.Conditions.Devices.DeviceFilter.rule.count
            SignInRisk = $policy.Conditions.SignInRiskLevels.count
            UserRisk = $policy.Conditions.UserRiskLevels.count
            AuthStrength = $AuthStrength
            AuthStrengthId = $AuthStrengthId
            AuthStrengthResolved = $AuthStrengthResolved
            AuthStrengthPhishingResistantOnly = $AuthStrengthPhishingResistantOnly
            AuthStrengthMfaCombinationsOnly = $AuthStrengthMfaCombinationsOnly
            AuthStrengthContainsSingleFactorElements = $AuthStrengthContainsSingleFactorElements
            AuthStrengthAllowedCombinations = $AuthStrengthAllowedCombinations
            GrantControlsOperator = $GrantAssuranceEvaluation.Operator
            MfaBaselineCandidate = $GrantAssuranceEvaluation.HasMfaBaselineCandidate
            MfaEquivalentEnforced = $GrantAssuranceEvaluation.MfaEquivalentEnforced
            PhishingResistantEnforced = $GrantAssuranceEvaluation.PhishingResistantEnforced
            GrantAssuranceConfidence = $GrantAssuranceEvaluation.Confidence
            MfaEvaluationWarning = $GrantAssuranceEvaluation.MfaWarning
            PhishingResistantEvaluationWarning = $GrantAssuranceEvaluation.PhishingResistantWarning
            AuthContext = $policy.Conditions.Applications.IncludeAuthenticationContextClassReferences.count
            IncResources = $IncludedResourcesCount
            ExcResources = $policy.Conditions.Applications.ExcludeApplications.count
            IncNw = $IncludedNwLocations
            ExcNw = $ExcludedNwLocations
            IncPlatforms = $IncPlatforms
            ExcPlatforms = $ExcPlatforms
            EffectiveTargeting = $EffectiveTargeting
            EffectiveTargetingNotes = $EffectiveTargetingNotes
            MissingRoles = $MissingRolesTable
            MissingRolesCount = $MissingRolesCount
            ScopedRoles = $ScopedRoles
            ScopedRolesCount = $ScopedRolesCount
            GrantControls = $policy.GrantControls.BuiltInControls -join " $($policy.GrantControls.Operator) "
            AuthFlow = (($policy.Conditions.AuthenticationFlows.TransferMethods -join ',') -replace '\s*,\s*', ', ')
            SessionControlsDetails = $policy.SessionControls
            SessionControls = $SessionControls
            SignInFrequency = $SignInFrequency
            SignInFrequencyInterval = $SignInFrequencyInterval
            AuthContextId = $AuthContextId
            AdditionalConditionTypes = $additionalConditionTypes
            UserActions = $policy.Conditions.Applications.IncludeUserActions -join ", "
            AppTypes = $policy.Conditions.ClientAppTypes -join ", "
            Warnings = $WarningPolicy
        })

        if (-not [string]::IsNullOrWhiteSpace($WarningPolicy)) {
            Write-Log -Level Trace -Message "Policy '$($policy.DisplayName)' warnings: $WarningPolicy"
        }
    }
    #endregion

    write-host "[*] Processing results"
    Write-Log -Level Debug -Message "Processed $($ConditionalAccessPolicies.Count) conditional access policies"
    $capEnabledPolicies = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'enabled' }).Count
    $capReportOnlyPolicies = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'report-only' }).Count
    $capDisabledPolicies = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'disabled' }).Count
    $capPoliciesWithEffectiveTargeting = @($ConditionalAccessPolicies | Where-Object { @($_.EffectiveTargeting).Count -gt 0 }).Count
    $capApproximateCoveragePolicies = @($ConditionalAccessPolicies | Where-Object { [string]$_.UserCoverage -like '~*' }).Count
    $capPotentialPimTargetingPolicies = @(
        $ConditionalAccessPolicies | Where-Object {
            [int]$_.IncPotentialUsersViaGroups -gt 0 -or
            [int]$_.ExcPotentialUsersViaGroups -gt 0 -or
            [int]$_.IncPotentialUsersViaRoles -gt 0 -or
            [int]$_.ExcPotentialUsersViaRoles -gt 0
        }
    ).Count
    $capEnabledPoliciesBelowFullCoverage = @(
        $ConditionalAccessPolicies | Where-Object {
            $_.State -eq 'enabled' -and
            $null -ne $_.UserCoverageValue -and
            [double]$_.UserCoverageValue -lt 100
        }
    ).Count
    Write-Log -Level Debug -Message "CAP effective targeting summary: Enabled=$capEnabledPolicies, ReportOnly=$capReportOnlyPolicies, Disabled=$capDisabledPolicies, WithEffectiveTargeting=$capPoliciesWithEffectiveTargeting, ApproximateCoverage=$capApproximateCoveragePolicies, PotentialViaPIM=$capPotentialPimTargetingPolicies, EnabledBelow100PercentCoverage=$capEnabledPoliciesBelowFullCoverage"

    $capAuthStrengthPolicies = @($ConditionalAccessPolicies | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.AuthStrength) -and [string]$_.AuthStrength -ne '-' }).Count
    $capMfaEquivalentPolicies = @($ConditionalAccessPolicies | Where-Object { [bool]$_.MfaEquivalentEnforced }).Count
    $capPhishingResistantPolicies = @($ConditionalAccessPolicies | Where-Object { [bool]$_.PhishingResistantEnforced }).Count
    $capAssuranceWarningPolicies = @(
        $ConditionalAccessPolicies | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.MfaEvaluationWarning) -or
            -not [string]::IsNullOrWhiteSpace([string]$_.PhishingResistantEvaluationWarning)
        }
    ).Count
    Write-Log -Level Debug -Message "CAP assurance summary: AuthStrengthPolicies=$capAuthStrengthPolicies, MfaEquivalentPolicies=$capMfaEquivalentPolicies, PhishingResistantPolicies=$capPhishingResistantPolicies, AssuranceWarningPolicies=$capAssuranceWarningPolicies"

    if ($ExportCapUncoveredUsers) {
        Write-Log -Level Debug -Message "CAP uncovered-users export total: FilesWritten=$capUncoveredExportFilesWritten, Rows=$capUncoveredExportRows, SkippedEmpty=$capUncoveredExportSkippedEmpty, SkippedNoTargeting=$capUncoveredExportSkippedNoTargeting, OutputFolder=$CapUncoveredUsersOutputFolder"
    }

    # Initialize an empty array to store warning messages
    $Warnings = @()
    $MissingPoliciesHTML = ""

    # Check each policy variable and add corresponding warning messages
    if (!$PolicyDeviceCodeFlow) {
        $Warnings += "No policy targeting the Device Code flow was found!"
    }
    if (!$PolicyLegacyAuth) {
        $Warnings += "No policy targeting legacy authentication was found!"
    }
    if (!$PolicyRiskySignIn) {
        $Warnings += "No policy targeting risky sign-ins was found!"
    }
    if (!$PolicyUserRisk) {
        $Warnings += "No policy targeting user risk was found!"
    }
    if (!$PolicyRegSecInfo) {
        $Warnings += "No policy limiting the registrations of security information was found!"
    }
    if (!$PolicyRegDevices) {
        $Warnings += "No policy Targeting joining or registering devices was found!"
    }
    if (!$PolicyMfaUser) {
        $Warnings += "No policy enforcing MFA was found!"
    }
    if (!$PolicyAuthStrength) {
        $Warnings += "No policy enforcing Authentication Strength (e.g., phishing-resistant MFA) for admins was found!"
    }
    
    if ($Warnings.count -ge 1) {
        # Correct way to format warnings into HTML list items
        $MissingPolicies = ($Warnings | ForEach-Object { "<li>$_</li>" }) -join "`n"

# Generate final HTML output
$MissingPoliciesHTML = @"
<h2>Missing Policies</h2>
<ul>
$MissingPolicies
</ul>
"@

        Write-Log -Level Debug -Message "Missing policy warnings: $($Warnings.Count)"
        Write-Log -Level Trace -Message ("Missing policies: " + ($Warnings -join " | "))
    }

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()
    $AppendixNetworkLocations = ""
    #Define output of the main table
    $tableOutput = $ConditionalAccessPolicies | select-object DisplayName,DisplayNameLink,TargetType,UserCoverage,State,IncResources,ExcResources,AuthContext,IncUsers,IncUsersViaGroups,ExcUsers,ExcUsersViaGroups,IncGroups,ExcGroups,IncRoles,IncUsersViaRoles,ExcRoles,ExcUsersViaRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings

    #Build the detail section of the report
    foreach ($item in $AllPolicies) {
        $ReportingCapInfo = @()
        $HtmlConditions = @()
        $HtmlSessionControls = @()
        $HtmlGrantControls = @()
        $EffectiveTargeting = @()
        $EffectiveTargetingNotes = ""
        $MissingRoles = @()
        $ScopedRoles = @()
 
        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        $policy = $ConditionalAccessPolicies | Where-Object { $item.Id -eq $_.Id }

        $ReportingCapInfo = [pscustomobject]@{
            "Policy Name" = $($item.DisplayName)
            "ID" = $($item.Id)
            "Target Type" = $($policy.TargetType)
            "State" = $($item.State)
        }
        
        #Sometimes even $item.CreatedDateTime is $null
        if ($null -ne $item.CreatedDateTime) {
            $ReportingCapInfo | Add-Member -NotePropertyName Created -NotePropertyValue $item.CreatedDateTime.ToString()
        }
        if ($null -ne $item.ModifiedDateTime) {
            $ReportingCapInfo | Add-Member -NotePropertyName Modified -NotePropertyValue $item.ModifiedDateTime.ToString()
        }
        if ($null -ne $item.Description) {
            $ReportingCapInfo | Add-Member -NotePropertyName Description -NotePropertyValue $item.Description
        }

        #Getting warning message to include in details
        $matchingWarnings = $ConditionalAccessPolicies | Where-Object { $_.Id -eq $item.Id } | Select-Object -ExpandProperty warnings
        if ($matchingWarnings -ne "") {
            $ReportingCapInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $matchingWarnings
        }
       
        [void]$DetailTxtBuilder.AppendLine(($ReportingCapInfo | Format-List | Out-String))


        if ($policy.TargetType -eq "Users" -and $policy.EffectiveTargeting.Count -ge 1) {
            $EffectiveTargeting = @($policy.EffectiveTargeting)
            $EffectiveTargetingNotes = $policy.EffectiveTargetingNotes
            $EffectiveTargetingLayout = Get-CapEffectiveTargetingDetailLayout -EffectiveTargeting $EffectiveTargeting
            [void]$DetailTxtBuilder.AppendLine("Effective Targeting (Users)")
            [void]$DetailTxtBuilder.AppendLine("--------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Summary")
            [void]$DetailTxtBuilder.AppendLine(($EffectiveTargetingLayout.SummaryRows | Format-Table -Property Metric,Value | Out-String))
            [void]$DetailTxtBuilder.AppendLine("Breakdown")
            [void]$DetailTxtBuilder.AppendLine(($EffectiveTargetingLayout.BreakdownRows | Format-Table -Property Metric,Included,Excluded | Out-String))
            if ($EffectiveTargetingLayout.EligibleRows.Count -gt 0) {
                [void]$DetailTxtBuilder.AppendLine("Eligible But Not Currently Effective")
                [void]$DetailTxtBuilder.AppendLine(($EffectiveTargetingLayout.EligibleRows | Format-Table -Property Metric,Included,Excluded | Out-String))
            }
            if (-not [string]::IsNullOrEmpty($EffectiveTargetingNotes)) {
                [void]$DetailTxtBuilder.AppendLine("Notes")
                foreach ($noteLine in ($EffectiveTargetingNotes -split "`r?`n")) {
                    if ([string]::IsNullOrWhiteSpace($noteLine)) { continue }
                    [void]$DetailTxtBuilder.AppendLine($noteLine.Trim())
                }
                [void]$DetailTxtBuilder.AppendLine("")
            }
        }

        ############### Missing Roles
        if ($policy.MissingRoles.count -ge 1) {

            $MissingRoles = foreach ($object in $($policy.MissingRoles)) {
                [pscustomobject]@{ 
                  "RoleName" = $($object.RoleName)
                  "RoleTier" = $($object.RoleTier)
                  "AssignmentsLink" = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Role=$([System.Uri]::EscapeDataString("=$($object.RoleName)"))>$($object.Assignments)</a>"
                  "Assignments" = $($object.Assignments)
              }
            }
            [void]$DetailTxtBuilder.AppendLine("Missing Roles With Assignments")
            [void]$DetailTxtBuilder.AppendLine("--------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($policy.MissingRoles  | format-table -Property RoleName,RoleTier,Assignments | Out-String))

            #Rebuild for HTML report
            $MissingRoles = foreach ($object in $MissingRoles) {
                [pscustomobject]@{
                    "RoleName" = $($object.RoleName)
                    "RoleTier" = $($object.RoleTier)
                    "Assignments" = $($object.AssignmentsLink)
                }
            }
            
        } 
        
        ############### Scoped Roles
        if ($policy.ScopedRoles.count -ge 1) {

            $ScopedRoles = foreach ($object in $($policy.ScopedRoles)) {
                [pscustomobject]@{ 
                  "RoleName" = $($object.RoleName)
                  "RoleTier" = $($object.RoleTier)
                  "AssignmentsScopedLink" = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html?Role=$([System.Uri]::EscapeDataString("=$($object.RoleName)"))&Scope=$([System.Uri]::EscapeDataString("!(Tenant)"))>$($object.Assignments)</a>"
                  "AssignmentsScoped" = $($object.Assignments)
              }
            }
            [void]$DetailTxtBuilder.AppendLine("Targeted Roles With Scoped Assignments")
            [void]$DetailTxtBuilder.AppendLine("------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($policy.ScopedRoles  | format-table -Property RoleName,RoleTier,AssignmentsScoped | Out-String))

            #Rebuild for HTML report
            $ScopedRoles = foreach ($object in $ScopedRoles) {
                [pscustomobject]@{
                    "RoleName" = $($object.RoleName)
                    "RoleTier" = $($object.RoleTier)
                    "AssignmentsScoped" = $($object.AssignmentsScopedLink)
                }
            }
        } 
        

        # Convert the raw CAP JSON to YAML, enriching it with HTTP links.
        if ($null -ne $item.Conditions) {
            $ConditionsHTML = ConvertTo-Yaml -InputObject $item.Conditions -Report "HTML"
            if ($null -ne $ConditionsHTML) {
                $HtmlConditions += $ConditionsHTML

                # Converting again the raw CAP YAML, enriching it with text only
                $ConditionsTXT = ConvertTo-Yaml -InputObject $item.Conditions -Report "TXT"
                [void]$DetailTxtBuilder.AppendLine("Conditions")
                [void]$DetailTxtBuilder.AppendLine("--------------------------------")
                [void]$DetailTxtBuilder.AppendLine(($ConditionsTXT | Out-String))
            }
        }

        # Convert the raw CAP JSON to YAML, enriching it with HTTP links.
        if ($null -ne $item.SessionControls) {
            $SessionControlsHTML = ConvertTo-Yaml -InputObject $item.SessionControls -Report "HTML"
            if ($null -ne $SessionControlsHTML) {
                $HtmlSessionControls += $SessionControlsHTML

                # Converting again the raw CAP YAML, enriching it with text only
                $SessionControlsTXT = ConvertTo-Yaml -InputObject $item.SessionControls -Report "TXT"
                [void]$DetailTxtBuilder.AppendLine("SessionControls")
                [void]$DetailTxtBuilder.AppendLine("--------------------------------")
                [void]$DetailTxtBuilder.AppendLine(($SessionControlsTXT | Out-String))
            }
        }

        # Convert the raw CAP JSON to YAML, enriching it with HTTP links.
        if ($null -ne $item.GrantControls) {
            $GrantControlsHTML = ConvertTo-Yaml -InputObject $item.GrantControls -Report "HTML"
            if ($null -ne $GrantControlsHTML) {
                $HtmlGrantControls += $GrantControlsHTML

                # Converting again the raw CAP YAML, enriching it with text only
                $GrantControlsTXT = ConvertTo-Yaml -InputObject $item.GrantControls -Report "TXT"
                [void]$DetailTxtBuilder.AppendLine("GrantControls")
                [void]$DetailTxtBuilder.AppendLine("--------------------------------")
                [void]$DetailTxtBuilder.AppendLine(($GrantControlsTXT | Out-String))
            }
        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"                               = $item.DisplayName
            "Object ID"                                 = $item.Id
            "General Information"                       = $ReportingCapInfo
            "Effective Targeting (Users)"               = $EffectiveTargeting
            "Effective Targeting (Users) Notes"         = $EffectiveTargetingNotes
            "Missing Roles With Assignments"            = $MissingRoles
            "Targeted Roles With Scoped Assignments"    = $ScopedRoles
            "Conditions"                                = $HtmlConditions
            "Session Controls"                          = $HtmlSessionControls
            "Grant Controls"                            = $HtmlGrantControls 
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)
    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()
    write-host "[*] Writing log files"
    write-host ""

    if ($AllPoliciesCount -gt 0) {
    $mainTable = $tableOutput | select-object -Property @{Label="DisplayName"; Expression={$_.DisplayNameLink}},TargetType,UserCoverage,State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,IncUsersViaGroups,ExcGroups,ExcUsersViaGroups,IncRoles,IncUsersViaRoles,ExcRoles,ExcUsersViaRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings
        $mainTableJson  = $mainTable | ConvertTo-Json -Depth 10 -Compress       
    } else {
        #Define an empty JSON object to make the HTML report loading
        $mainTableJson = "[{}]"
    }
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'


# Build Detail section as JSON for the HTML Report
if ($AllPoliciesCount -gt 0) {
    $AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 10 -Compress
    $ObjectsDetailsHEAD = @'
        <h2>CAPs Details</h2>
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
'@
    $AllObjectDetailsHTML = $ObjectsDetailsHEAD + "`n" + $AllObjectDetailsHTML + "`n" + '</script>'
} else {
    $AllObjectDetailsHTML = "`n"
}




#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"

#Define Appendix
$AppendixTitle = "

###############################################################################################################################################
Appendix: Network Location
###############################################################################################################################################
    "

    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'CAP' -CurrentReportName 'ConditionalAccessPolicies Enumeration' -Warnings $WarningReport


    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@
  
    #Write TXT and CSV files
    $headerTXT | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt"
    if ($AllPoliciesCount -gt 0 -and $Csv) { 
        $tableOutput | select-object DisplayName,TargetType,UserCoverage,State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,IncUsersViaGroups,ExcGroups,ExcUsersViaGroups,IncRoles,IncUsersViaRoles,ExcRoles,ExcUsersViaRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }
    $tableOutput | format-table -Property DisplayName,TargetType,UserCoverage,State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,IncUsersViaGroups,ExcGroups,ExcUsersViaGroups,IncRoles,IncUsersViaRoles,ExcRoles,ExcUsersViaRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Warnings.count -ge 1) {$Warnings | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append}
    $DetailOutputTxt | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append


    #Named location appendix
    If (($NamedLocations | Measure-Object).count -gt 0) {
        $AppendixTitle | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $NamedLocations | format-table Id,Name,Trusted,Type,TargetedLocations,IncludedCAPs,ExcludedCAPs | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixNetworkLocations += $NamedLocations | ConvertTo-Html Id,Name,Trusted,Type,TargetedLocations,@{Label="Included in CAPs"; Expression={$_.IncludedCAPsLinks}},@{Label="Excluded in CAPs"; Expression={$_.ExcludedCAPsLinks}} -Fragment -PreContent "<h2>Appendix: Network Location</h2>"
        #Remove the automated encoding
        $AppendixNetworkLocations  = $AppendixNetworkLocations -replace '&lt;', '<' -replace '&gt;', '>'
    }

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixNetworkLocations
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML $MissingPoliciesHTML" -Head ("<title>EF - Conditional Access</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $AllPoliciesCount policies stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    
    #Add information to the enumeration summary
    $GlobalAuditSummary.ConditionalAccess.Count = $AllPoliciesCount
    $EnabledCount = 0
    foreach ($cap in $tableOutput) {
        if ($cap.State -eq "enabled") {
            $EnabledCount ++
        }
    }
    $GlobalAuditSummary.ConditionalAccess.Enabled = $EnabledCount 

    #Convert to Hashtable for faster searches
    $AllCapsHT = @{}
    foreach ($item in $ConditionalAccessPolicies) {
        $AllCapsHT[$item.Id] = $item
    }
    Return $AllCapsHT
    
}
