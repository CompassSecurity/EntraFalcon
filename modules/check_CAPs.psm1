<#
.SYNOPSIS
   Enumerate CAPs

#>
function Invoke-CheckCaps {
    ############################## Parameter section ########################
    # AllGroupsDetails and Users are used by nested helper functions via parent scope
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'AllGroupsDetails')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Users')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )


    ############################## Function section ########################

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

    function Get-UsersThroughGroupsCount {
        param (
            [Parameter(Mandatory=$false)][Object[]]$GroupIds
        )

        $uniqueUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fallbackUsersCount = 0
        $usedFallback = $false

        foreach ($groupId in @($GroupIds)) {
            if ($null -eq $groupId) { continue }
            $groupIdString = [string]$groupId
            if ([string]::IsNullOrWhiteSpace($groupIdString)) { continue }

            if ($AllGroupsDetails.ContainsKey($groupIdString)) {
                $groupDetails = $AllGroupsDetails[$groupIdString]
                $groupUserIds = @($groupDetails.Userdetails | ForEach-Object { $_.Id })

                if (@($groupUserIds).Count -gt 0) {
                    foreach ($userId in $groupUserIds) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$userId)) {
                            [void]$uniqueUserIds.Add([string]$userId)
                        }
                    }
                } else {
                    $groupUsersRaw = $groupDetails.Users
                    $groupUsers = 0
                    if ($null -ne $groupUsersRaw -and [int]::TryParse([string]$groupUsersRaw, [ref]$groupUsers)) {
                        $fallbackUsersCount += $groupUsers
                        $usedFallback = $true
                    }
                }
            }
        }

        if ($usedFallback) {
            return ($uniqueUserIds.Count + $fallbackUsersCount)
        }

        return $uniqueUserIds.Count
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
                $ResolvedGUIDLink = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$Guid>$ResolvedGUID</a>"
                return $ResolvedGUIDLink
            } elseif ($Report -eq "TXT") {
                return $ResolvedGUID
            }

        }
        if ($AllGroupsDetails.ContainsKey($Guid)) {
            $ResolvedGUID = $($AllGroupsDetails[$Guid].DisplayName)

            if ($Report -eq "HTML") {
                $ResolvedGUIDLink = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$Guid>$ResolvedGUID</a>"
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
            return $ResolvedGUID
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

    # Pre-filter assignments with RoleTier 0 or 1
    # Used to identify missing targeted high-tier roles
    $HighTierAssignments = @()
    foreach ($assignmentList in $TenantRoleAssignments.Values) {
        foreach ($assignment in $assignmentList) {
            #Taking only Tier 0 and Tier 1 roles and hide the Directory Synchronization Accounts role
            if ($assignment.RoleTier -in 0, 1 -and $assignment.RoleDefinitionId -ne "d29b2b05-8046-44ba-8758-1e26182fcf32") {
                $HighTierAssignments += $assignment
            }
        }
    }
    Write-Log -Level Debug -Message "Prepared HT HighTierAssignments $($HighTierAssignments.Count)"

    # Hashtable to store scoped role info by RoleDefinitionId
    # Used to identify scoped assignments which are not working in CAPs targeting roles
    $ScopedAssignments = @{}
    foreach ($assignmentList in $TenantRoleAssignments.Values) {
        foreach ($assignment in $assignmentList) {
            $scopeDisplay = $assignment.ScopeResolved.DisplayName

            if ($scopeDisplay -ne '/') {
                $roleId   = $assignment.RoleDefinitionId
                $roleName = $assignment.DisplayName
                $roleTier = $assignment.RoleTier

                if (-not $ScopedAssignments.ContainsKey($roleId)) {
                    $ScopedAssignments[$roleId] = @{
                        RoleName = $roleName
                        RoleTier = $roleTier
                        Count    = 0
                    }
                }
                $ScopedAssignments[$roleId]['Count']++
            }
        }
    }
    Write-Log -Level Debug -Message "Prepared HT ScopedAssignments $($ScopedAssignments.Count)"


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


    #region Processing Loop
    #Main processing of the results
    foreach ($policy in $AllPolicies) {
        $ProgressCounter ++
        $WarningPolicy = ""
        $ErrorMessages = @()
        $additionalConditionTypes = 0

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AllPoliciesCount) {
            Write-Host "[*] Status: Processing policy $ProgressCounter of $AllPoliciesCount..."
        }

        ###################### Handling special Values like "All" etc.
        if ($policy.State -eq "enabledForReportingButNotEnforced") {$policy.State = "report-only"}

        if ($policy.Conditions.Users.IncludeUsers -contains "All") {
            $IncludedUserCount = "All"
        } else {
            $IncludedUserCount = $policy.Conditions.Users.IncludeUsers.count
        }
        if ($policy.Conditions.Users.IncludeUsers -contains "None") {
            $IncludedUserCount = 0
        }

        $IncUsersViaGroups = Get-UsersThroughGroupsCount -GroupIds $policy.Conditions.Users.IncludeGroups
        $ExcUsersViaGroups = Get-UsersThroughGroupsCount -GroupIds $policy.Conditions.Users.ExcludeGroups

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


        #Special handling for external identities, as they are stored in a CSV list
        $IncludedExternalUsers = $policy.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes
        if ([string]::IsNullOrEmpty($IncludedExternalUsers)) {
            $IncludedExternalUsersCount = 0
        } else {
            $IncludedExternalUsersCount = ($IncludedExternalUsers -split ',').Count
        }
        $ExcludedExternalUsers = $policy.Conditions.Users.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes
        if ([string]::IsNullOrEmpty($ExcludedExternalUsers)) {
            $ExcludedExternalUsersCount = 0
        } else {
            $ExcludedExternalUsersCount = ($ExcludedExternalUsers -split ',').Count
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

        #Generate error meassge
        if ($ScopedRolesCount -gt 0) {
            $targetedCount = @($includedRoleIds).Count
            $scopedCount   = @($ScopedRoles).Count

            $roleWord = if ($targetedCount -eq 1) { "targeted role" } else { "targeted roles" }
            $assignmentWord = if ($scopedCount -eq 1) { "has scoped assignments" } else { "have scoped assignments" }

            $ScopedRolesWarning = "$scopedCount of the $targetedCount $roleWord $assignmentWord"
        }


        ###################### Analyzing policies

        $ExcludedUsersEffective = $policy.Conditions.Users.ExcludeUsers.count + $ExcUsersViaGroups
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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
            }
        }

        #Check for the common case where user risk and sign-in risk are managed in the same policy
        if ($policy.Conditions.UserRiskLevels.count -ge 1 -and $policy.Conditions.SignInRiskLevels.count -ge 1) {
            $PolicyUserRisk = $true
            $PolicyRiskySignIn = $true
            $CombinedRiskWarnings = 0
            $ErrorMessages = @()
            $ErrorMessages += "targeting user risk AND sign-in risk in the same policy"

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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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

            if ($CombinedRiskWarnings -ge 1) {
                $warningMessage = "Targeting risks but " + ($ErrorMessages -join ", ")
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
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
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
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
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
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
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
            }
        }

        #Check policy for MFA
        if ($policy.GrantControls.BuiltInControls -contains "mfa" -and $policy.Conditions.AuthenticationFlows.TransferMethods.count -eq 0 -and $policy.Conditions.SignInRiskLevels.count -eq 0 -and $policy.Conditions.UserRiskLevels.count -eq 0 -and $policy.Conditions.Applications.IncludeUserActions.count -eq 0) {
            $PolicyMfaUser = $true
            $UserMfaWarnings = 0
            $ErrorMessages = @()

            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $UserMfaWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $UserMfaWarnings++
            }
            if ($null -eq $IncludedUserCount -or $IncludedUserCount -ne "All") {
                $ErrorMessages += "is not targeting all users"
                $UserMfaWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $UserMfaWarnings++
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
                $UserMfaWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $UserMfaWarnings++
            }
            if ($ConditionTypeCount -gt 0) {
                $ErrorMessages += "has ($ConditionTypeCount) condition types"
                $UserMfaWarnings++
            }

            if ($UserMfaWarnings -ge 1) {
                $warningMessage = "Requires MFA but " + ($ErrorMessages -join ", ")
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
            }
        }

        #Check policy with Authentication strengths for enforcing phishing-resistant MFA
        $authStrengthIdCandidate = "$($policy.GrantControls.AuthenticationStrength.Id)".Trim()
        $hasNoAuthFlow = $null -eq $policy.Conditions.AuthenticationFlows.TransferMethods -or $policy.Conditions.AuthenticationFlows.TransferMethods.Count -eq 0
        $hasNoUserActions = $null -eq $policy.Conditions.Applications.IncludeUserActions -or $policy.Conditions.Applications.IncludeUserActions.Count -eq 0
        if ($policy.Conditions.Applications.IncludeAuthenticationContextClassReferences.count -eq 0 -and -not [string]::IsNullOrWhiteSpace($authStrengthIdCandidate) -and $policy.Conditions.SignInRiskLevels.count -eq 0 -and $policy.Conditions.UserRiskLevels.count -eq 0 -and $hasNoAuthFlow -and $hasNoUserActions) {
            $PolicyAuthStrength = $true
            $AuthStrengthWarnings = 0
            $ErrorMessages = @()

            if ($policy.State -ne "enabled") {
                $ErrorMessages += "is not enabled"
                $AuthStrengthWarnings++
            }
            if ($null -eq $IncludedResourcesCount -or $IncludedResourcesCount -ne "All") {
                $ErrorMessages += "is not targeting all resources"
                $AuthStrengthWarnings++
            }
            if ($ExcludedUsersEffective -ge 3) {
                $ErrorMessages += "has $ExcludedUsersEffective excluded users (direct or through groups)"
                $AuthStrengthWarnings++
            }
            if ($ExcludedNonUserTargets -gt 0) {
                $ErrorMessages += "has $ExcludedNonUserTargets excluded roles or external user types"
                $AuthStrengthWarnings++
            }
            if ($unmatchedRoleCounts.Count -ne 0) {
                $ErrorMessages += $MissingRolesWarning
                $AuthStrengthWarnings++
            }
            if ($ConditionTypeCount -gt 1) {
                $ErrorMessages += "has multiple ($ConditionTypeCount) condition types"
                $AuthStrengthWarnings++
            }

            if ($AuthStrengthWarnings -ge 1) {
                $warningMessage = "Requires Authentication Strength (no Auth Context) but " + ($ErrorMessages -join ", ")
                if ([string]::IsNullOrWhiteSpace($WarningPolicy)) {
                    $WarningPolicy = $warningMessage
                } else {
                    $WarningPolicy += " / $warningMessage"
                }
            }
        }

        #General Policy checks

        #Check if the role includes roles but scope assignment exist for the role
        if ($ScopedRolesCount -gt 0) {
            if (-not [string]::IsNullOrWhiteSpace($WarningPolicy)) {
                $WarningPolicy += ", $ScopedRolesWarning"
            } else {
                $WarningPolicy = $ScopedRolesWarning
            }
        }


        #Avoid AuthStrength values to be null
        $AuthStrength = ""
        $AuthStrengthId = ""
        if ($null -ne $policy.GrantControls.AuthenticationStrength) {
            if ($null -ne $policy.GrantControls.AuthenticationStrength.DisplayName) {
                $AuthStrength = [string]$policy.GrantControls.AuthenticationStrength.DisplayName
            }
            if ($null -ne $policy.GrantControls.AuthenticationStrength.Id) {
                $AuthStrengthId = [string]$policy.GrantControls.AuthenticationStrength.Id
            }
        }


        $ConditionalAccessPolicies.Add([PSCustomObject]@{
            Id = $policy.Id
            DisplayName = $policy.DisplayName
            DisplayNameLink = "<a href=#$($policy.id)>$($policy.DisplayName)</a>"
            Description = $policy.Description
            CreatedDateTime = $policy.CreatedDateTime
            ModifiedDateTime = $policy.ModifiedDateTime
            State = $policy.State
            IncUsers = $IncludedUserCount
            IncUsersViaGroups = $IncUsersViaGroups
            IncGroups = $policy.Conditions.Users.IncludeGroups.count
            IncRoles = $policy.Conditions.Users.IncludeRoles.count
            IncExternals = $IncludedExternalUsersCount
            ExcUsers = $policy.Conditions.Users.ExcludeUsers.count
            ExcUsersViaGroups = $ExcUsersViaGroups
            ExcGroups = $policy.Conditions.Users.ExcludeGroups.count
            ExcRoles = $policy.Conditions.Users.ExcludeRoles.count
            ExcExternals = $ExcludedExternalUsersCount
            DeviceFilter = $policy.Conditions.Devices.DeviceFilter.rule.count
            SignInRisk = $policy.Conditions.SignInRiskLevels.count
            UserRisk = $policy.Conditions.UserRiskLevels.count
            AuthStrength = $AuthStrength
            AuthStrengthId = $AuthStrengthId
            AuthContext = $policy.Conditions.Applications.IncludeAuthenticationContextClassReferences.count
            IncResources = $IncludedResourcesCount
            ExcResources = $policy.Conditions.Applications.ExcludeApplications.count
            IncNw = $IncludedNwLocations
            ExcNw = $ExcludedNwLocations
            IncPlatforms = $IncPlatforms
            ExcPlatforms = $ExcPlatforms
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
    $tableOutput = $ConditionalAccessPolicies | select-object DisplayName,DisplayNameLink,State,IncResources,ExcResources,AuthContext,IncUsers,IncUsersViaGroups,ExcUsers,ExcUsersViaGroups,IncGroups,ExcGroups,IncRoles,ExcRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings

    #Build the detail section of the report
    foreach ($item in $AllPolicies) {
        $ReportingCapInfo = @()
        $HtmlConditions = @()
        $HtmlSessionControls = @()
        $HtmlGrantControls = @()
        $MissingRoles = @()
        $ScopedRoles = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        $ReportingCapInfo = [pscustomobject]@{
            "Policy Name" = $($item.DisplayName)
            "ID" = $($item.Id)
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


        ############### Missing Roles
        $policy = $ConditionalAccessPolicies | where-object { $item.Id -eq $_.id}
        if ($policy.MissingRoles.count -ge 1) {

            $MissingRoles = foreach ($object in $($policy.MissingRoles)) {
                [pscustomobject]@{
                  "RoleName" = $($object.RoleName)
                  "RoleTier" = $($object.RoleTier)
                  "AssignmentsLink" = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html?Role=$([System.Uri]::EscapeDataString("=$($object.RoleName)"))>$($object.Assignments)</a>"
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

        ############### Missing Roles
        if ($policy.ScopedRoles.count -ge 1) {

            $ScopedRoles = foreach ($object in $($policy.ScopedRoles)) {
                [pscustomobject]@{
                  "RoleName" = $($object.RoleName)
                  "RoleTier" = $($object.RoleTier)
                  "AssignmentsScopedLink" = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html?Role=$([System.Uri]::EscapeDataString("=$($object.RoleName)"))&Scope=$([System.Uri]::EscapeDataString("!(Tenant)"))>$($object.Assignments)</a>"
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
        $mainTable = $tableOutput | select-object -Property @{Label="DisplayName"; Expression={$_.DisplayNameLink}},State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,IncUsersViaGroups,ExcGroups,ExcUsersViaGroups,IncRoles,ExcRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings
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
    $headerTXT | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt"
    if ($AllPoliciesCount -gt 0 -and $Csv) {
        $tableOutput | select-object DisplayName,State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,ExcGroups,IncRoles,ExcRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    }
    $tableOutput | format-table -Property DisplayName,State,IncResources,ExcResources,AuthContext,IncUsers,ExcUsers,IncGroups,ExcGroups,IncRoles,ExcRoles,IncExternals,ExcExternals,DeviceFilter,IncPlatforms,ExcPlatforms,SignInRisk,UserRisk,IncNw,ExcNw,AppTypes,AuthFlow,UserActions,GrantControls,SessionControls,SignInFrequency,SignInFrequencyInterval,AuthStrength,Warnings | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    if ($Warnings.count -ge 1) {$Warnings | Out-File -Width 768 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append}
    $DetailOutputTxt | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append


    #Named location appendix
    If (($NamedLocations | Measure-Object).count -gt 0) {
        $AppendixTitle | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $NamedLocations | format-table Id,Name,Trusted,Type,TargetedLocations,IncludedCAPs,ExcludedCAPs | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixNetworkLocations += $NamedLocations | ConvertTo-Html Id,Name,Trusted,Type,TargetedLocations,@{Label="Included in CAPs"; Expression={$_.IncludedCAPsLinks}},@{Label="Excluded in CAPs"; Expression={$_.ExcludedCAPsLinks}} -Fragment -PreContent "<h2>Appendix: Network Location</h2>"
        #Remove the automated encoding
        $AppendixNetworkLocations  = $AppendixNetworkLocations -replace '&lt;', '<' -replace '&gt;', '>'
    }

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixNetworkLocations
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML $MissingPoliciesHTML" -Title "$Title enumeration" -Head ($global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $AllPoliciesCount policies stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

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

