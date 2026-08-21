<#
.SYNOPSIS
   Enumerate Agent Identity Blueprint Principals (including: API Permission, Source Tenant, Groups, Roles).

.DESCRIPTION
   This script will enumerate all Agent Identity Blueprint Principals (including: API Permission, Source Tenant, Groups, Roles).
   By default, MS applications are filtered out.

#>

function Invoke-AgentIdentityBlueprintsPrincipals {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][switch]$IncludeMsApps = $false,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory=$true)][hashtable]$AllUsersBasicHT,
        [Parameter(Mandatory=$false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$true)][hashtable]$ServicePrincipalSignInActivityLookup,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $ProgressCounter = 0
    $Inactive = $false
    $AppLastSignIns = $ServicePrincipalSignInActivityLookup
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    if ($null -eq $global:GLOBALUserAppRoles) { $global:GLOBALUserAppRoles = @{} }
    $SPImpactScore = @{
        "Base" = 1
    }

    $SPLikelihoodScore = @{
        "ForeignApp"                = 30
        "InternApp"                 = 5
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Agent Identity Blueprint Principals
    write-host "[*] Get Agent Identity Blueprint Principals"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'Application'"
        '$select' = "Id,DisplayName,PublisherName,appRoles,accountEnabled,AppId,servicePrincipalType,createdDateTime,signInAudience,AppOwnerOrganizationId,AppRoleAssignmentRequired"
        '$top' = $ApiTop
    }
    $AgentIdentityBlueprintPrincipals = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals/graph.agentIdentityBlueprintPrincipal' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)


    $AgentIdentityBlueprintPrincipalsCount = $($AgentIdentityBlueprintPrincipals.count)
    write-host "[+] Got $AgentIdentityBlueprintPrincipalsCount Agent Identity Blueprint Principals "

    #Abort if no apps are present
    if (@($AgentIdentityBlueprintPrincipals).count -eq 0) {
        $AllServicePrincipalHT = @{}
        Return $AllServicePrincipalHT
    }

    Write-Log -Level Debug -Message "Using $($AppLastSignIns.Count) cached app last sign-in dates"

    Write-Host "[*] Get all blueprint principal API permissions assignments"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/appRoleAssignments?`$select=AppRoleId,ResourceId,ResourceDisplayName"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppAssignmentsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppAssignmentsRaw[$item.id] = $item.response.value
        }
    }

    Write-Log -Level Debug -Message "Got $($AppAssignmentsRaw.Count) applications API permissions assignments"

    Write-Host "[*] Get all blueprint principal delegated API permissions"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/oauth2PermissionGrants?`$select=ResourceId,Scope,ConsentType,PrincipalId"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $DelegatedPermissionRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DelegatedPermissionRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($DelegatedPermissionRaw.Count) delegated API permissions assignments"

    Write-Host "[*] Get all blueprint principal group memberships"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/transitiveMemberOf/microsoft.graph.group?`$select=Id,displayName,visibility,securityEnabled,groupTypes,isAssignableToRole"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $GroupMemberRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $GroupMemberRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($GroupMemberRaw.Count) group memberships"

    Write-Host "[*] Get all blueprint principal object ownerships"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/ownedObjects"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $OwnedObjectsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $OwnedObjectsRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($OwnedObjectsRaw.Count) owned objects"

    Write-Host "[*] Get all owners"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/owners"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $OwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $OwnersRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($OwnersRaw.Count) owners"

    Write-Host "[*] Build linked agent identity lookup from passed AgentIdentities"
    $LinkedAgentIdentitiesByBlueprintId = @{}
    foreach ($AgentIdentity in $AgentIdentities.Values) {
        $AgentIdentityBlueprintId = "$($AgentIdentity.AgentIdentityBlueprintId)".Trim()
        if ([string]::IsNullOrWhiteSpace($AgentIdentityBlueprintId)) {
            continue
        }

        if (-not $LinkedAgentIdentitiesByBlueprintId.ContainsKey($AgentIdentityBlueprintId)) {
            $LinkedAgentIdentitiesByBlueprintId[$AgentIdentityBlueprintId] = [System.Collections.Generic.List[object]]::new()
        }

        [void]$LinkedAgentIdentitiesByBlueprintId[$AgentIdentityBlueprintId].Add($AgentIdentity)
    }
    Write-Log -Level Debug -Message "Built linked agent identity lookup for $($LinkedAgentIdentitiesByBlueprintId.Count) blueprint IDs from passed AgentIdentities"

    Write-Host "[*] Get all app role assignments"
    $Requests = @()
    $AgentIdentityBlueprintPrincipals | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/appRoleAssignedTo"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppRolesAssignedToRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppRolesAssignedToRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($AppRolesAssignedToRaw.Count) app role assignments"

    ########################################## SECTION: Agent Identity Blueprint Principal Processing ##########################################




    #Enumerate all AppRoles configured (only of the apps in scope)
    $AppRoles = [System.Collections.ArrayList]::new()

    foreach ($app in $AgentIdentityBlueprintPrincipals) {
        if (-not $AppRolesAssignedToRaw.ContainsKey($app.Id)) { continue }

        $userRoles = $app.AppRoles

        foreach ($assignment in $AppRolesAssignedToRaw[$app.Id]) {

            # Handle default access assignments
            if ($assignment.appRoleId -eq '00000000-0000-0000-0000-000000000000') {
                [void]$AppRoles.Add([PSCustomObject]@{
                    AppID                         = $app.Id
                    AppName                       = $app.DisplayName
                    AppRoleId                     = $assignment.appRoleId
                    AppRoleAssignmentDisplayName  = $assignment.PrincipalDisplayName
                    AppRoleAssignmentPrincipalId  = $assignment.PrincipalId
                    AppRoleAssignmentType         = $assignment.PrincipalType
                    AppRoleClaim                  = "-"
                    AppRoleDisplayName            = "Default Access"
                    AppRoleDescription            = "Default app role"
                    AppRoleEnabled                = $false
                })
                continue
            }

            # Handle explicitly assigned roles
            $matchedRole = $userRoles | Where-Object { $_.Id -eq $assignment.appRoleId }

            if ($matchedRole) {
                foreach ($role in $matchedRole) {
                    [void]$AppRoles.Add([PSCustomObject]@{
                        AppID                         = $app.Id
                        AppName                       = $app.DisplayName
                        AppRoleId                     = $role.Id
                        AppRoleAssignmentDisplayName  = $assignment.PrincipalDisplayName
                        AppRoleAssignmentPrincipalId  = $assignment.PrincipalId
                        AppRoleAssignmentType         = $assignment.PrincipalType
                        AppRoleClaim                  = $role.Value
                        AppRoleDisplayName            = $role.DisplayName
                        AppRoleDescription            = $role.Description
                        AppRoleEnabled                = $role.IsEnabled
                    })
                }
            } else {
                Write-Log -Level Debug -Message "No matching AppRole for ID $($assignment.appRoleId) in App $($app.DisplayName)"
            }
        }
    }

    # Add AppRoles assigned to users to a global var to use it in the check_user script
    $filteredAppRoles = $AppRoles | Where-Object { $_.AppRoleAssignmentType -eq "User" }

    # Loop through each filtered object
    foreach ($role in $filteredAppRoles) {
        $key = $role.AppRoleAssignmentPrincipalId
        $value = [PSCustomObject]@{
            AppRoleDisplayName  = $role.AppRoleDisplayName
            AppRoleDescription  = $role.AppRoleDescription
            AppRoleEnabled      = $role.AppRoleEnabled
            AppID               = $role.AppID
            AppName             = $role.AppName
        }

        # Check if the key already exists
        if ($GLOBALUserAppRoles.ContainsKey($key)) {
            # Append to the existing array
            $GLOBALUserAppRoles[$key] += $value
        } else {
            # Create a new array for this key
            $GLOBALUserAppRoles[$key] = @($value)
        }
    }

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($AgentIdentityBlueprintPrincipalsCount / 10), 1)
    if ($AgentIdentityBlueprintPrincipalsCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing agent identity blueprint principal 1 of $AgentIdentityBlueprintPrincipalsCount (updates every $StatusUpdateInterval objects)..."
    }

    #region Processing Loop
    #Loop through each agent identity blueprint principal, retrieve additional info, and store it in a custom object
    foreach ($item in $AgentIdentityBlueprintPrincipals) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = 0
        $OwnerUserDetails = @()
        $OwnerSPDetails = @()
        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AgentIdentityBlueprintPrincipalsCount) {
            Write-Host "[*] Status: Processing agent identity blueprint principal $ProgressCounter of $AgentIdentityBlueprintPrincipalsCount..."
        }

        #Process API permissions (AKA. RoleAssignments) for this app
        $AppAssignments = [System.Collections.ArrayList]::new()
        if ($AppAssignmentsRaw.ContainsKey($item.Id)) {
            foreach ($AppAssignmentsRole in $AppAssignmentsRaw[$item.Id]) {
                [void]$AppAssignments.Add(
                    [PSCustomObject]@{
                        AppRoleId = $AppAssignmentsRole.AppRoleId
                        ResourceId = $AppAssignmentsRole.ResourceId
                        ResourceDisplayName = $AppAssignmentsRole.ResourceDisplayName
                    }
                )
            }
        }

        #Get the application's API permission
        $AppApiPermission = [System.Collections.ArrayList]::new()
        foreach ($AppSinglePermission in $AppAssignments) {
            $ResolvedPermission = Resolve-AppRoleAssignmentRecord -AppRoleReferenceCache $AppRoleReferenceCache -PermissionId $AppSinglePermission.AppRoleId -ResourceId $AppSinglePermission.ResourceId -ApiNameOverride $AppSinglePermission.ResourceDisplayName
            if ($null -ne $ResolvedPermission) {
                [void]$AppApiPermission.Add($ResolvedPermission)
            }
        }

        # Define sort order. This is used for the appendix as well
        $categorizationOrder = @{
            'Dangerous'     = 1
            'High'          = 2
            'Medium'        = 3
            'Low'           = 4
            'Uncategorized' = 5
        }

        # Sort
        $AppApiPermission = $AppApiPermission | Sort-Object ApiName, @{ Expression = { $categorizationOrder[$_.ApiPermissionCategorization] }; Ascending = $true }

        # Group once by categorization
        $grouped = $AppApiPermission | Group-Object ApiPermissionCategorization

        # Build counts dictionary
        $counts = @{}
        foreach ($group in $grouped) {
            $counts[$group.Name] = $group.Count
        }

        # Count by category (fallback to 0 if null/missing)
        $AppApiPermissionDangerous     = if ($counts.ContainsKey('Dangerous'))     { $counts['Dangerous'] }     else { 0 }
        $AppApiPermissionHigh          = if ($counts.ContainsKey('High'))          { $counts['High'] }          else { 0 }
        $AppApiPermissionMedium        = if ($counts.ContainsKey('Medium'))        { $counts['Medium'] }        else { 0 }
        $AppApiPermissionLow           = if ($counts.ContainsKey('Low'))           { $counts['Low'] }           else { 0 }
        $AppApiPermissionUncategorized = if ($counts.ContainsKey('Uncategorized')) { $counts['Uncategorized'] } else { 0 }

        # For all sp check if there are Azure IAM assignments
        $AzureRoleDetails = @()
        if ($GLOBALAzurePsChecks) {
            #Use function to get the Azure Roles for each object
            $AzureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $item.Id
            # Update the Roles property only if there are matching roles
            $AzureRoleCount = ($AzureRoleDetails | Measure-Object).Count
        } else {
            $AzureRoleCount = "?"
        }

        $LinkedAgentIdentities = @()
        $BlueprintFilterId = if ([string]::IsNullOrWhiteSpace("$($item.AppId)")) { "$($item.Id)" } else { "$($item.AppId)" }
        if ($LinkedAgentIdentitiesByBlueprintId.ContainsKey($BlueprintFilterId)) {
            $LinkedAgentIdentities = foreach ($MatchingAgentIdentity in $LinkedAgentIdentitiesByBlueprintId[$BlueprintFilterId]) {
                [pscustomobject]@{
                    Id = $MatchingAgentIdentity.Id
                    DisplayName = if ([string]::IsNullOrWhiteSpace($MatchingAgentIdentity.DisplayName)) { "-" } else { $MatchingAgentIdentity.DisplayName }
                    Enabled = if ($null -eq $MatchingAgentIdentity.Enabled) { "-" } else { $MatchingAgentIdentity.Enabled }
                    Type = "AgentIdentity"
                    Impact = if ($null -ne $MatchingAgentIdentity.Impact) { [math]::Round([double]$MatchingAgentIdentity.Impact) } else { 0 }
                    Likelihood = if ($null -ne $MatchingAgentIdentity.Likelihood) { [math]::Round([double]$MatchingAgentIdentity.Likelihood, 1) } else { 0 }
                    Risk = if ($null -ne $MatchingAgentIdentity.Risk) { [math]::Round([double]$MatchingAgentIdentity.Risk) } else { 0 }
                    Warnings = if ([string]::IsNullOrWhiteSpace($MatchingAgentIdentity.Warnings)) { "-" } else { $MatchingAgentIdentity.Warnings }
                    AgentUsers = if ($null -ne $MatchingAgentIdentity.AgentUsers) { $MatchingAgentIdentity.AgentUsers } else { 0 }
                }
            }
        }

        #Check the assigned App roles for each app
        $MatchingAppRoles = @()
        # Loop through each role in $Approles and compare with $item.id
        foreach ($role in $Approles) {
            if ($role.AppID -eq $item.id) {

                #Shorten description if it is the same as the display name
                if ($role.AppRoleAssignmentDisplayName -eq $role.AppRoleDescription ) {
                    $description = "-"
                } else {
                    $description = $role.AppRoleDescription
                }

                # Create a new custom object with the relevant properties
                $newRole = [pscustomobject]@{
                    Type = "AppRole"
                    AppRoleName = $role.AppRoleDisplayName
                    AppRoleMember  = $role.AppRoleAssignmentDisplayName
                    AppRoleMemberId  = $role.AppRoleAssignmentPrincipalId
                    RoleEnabled   = $role.AppRoleEnabled
                    AppRoleClaim = $role.AppRoleClaim
                    AppRoleAssignmentType = $role.AppRoleAssignmentType
                    AppRoleDescription = $description
                }

                # Add the new object to the array
                $MatchingAppRoles += $newRole
            }
        }


        # Enumerate all roles including scope the app is assigned to (note: Get-MgBetaServicePrincipalMemberOf do not return custom roles or scoped roles)
        $MatchingRoles = $TenantRoleAssignments[$item.Id]

        $AppEntraRoles = @()
        $AppEntraRoles = foreach ($Role in $MatchingRoles) {
            [PSCustomObject]@{
                Type = "Roles"
                DisplayName = $Role.DisplayName
                Enabled = $Role.IsEnabled
                IsBuiltin = $Role.IsBuiltIn
                RoleTier  = $role.RoleTier
                IsPrivileged = $Role.IsPrivileged
                Scoped = $Role.DirectoryScopeId
                ScopeResolved = $Role.ScopeResolved
            }
        }

        $DirectAzureMaxTier = if ($GLOBALAzurePsChecks) { Get-HighestTierLabel -Assignments $AzureRoleDetails } else { "?" }
        $DirectEntraMaxTier = Get-HighestTierLabel -Assignments $AppEntraRoles

        $EntraMaxTierThroughGroupMembership = "-"
        $EntraMaxTierThroughGroupOwnership = "-"
        $AzureMaxTierThroughGroupMembership = "-"
        $AzureMaxTierThroughGroupOwnership = "-"

        $AzureMaxTier = $DirectAzureMaxTier
        $EntraMaxTier = $DirectEntraMaxTier

        # Calculate days since creation
        $CreationInDays = if ($item.createdDateTime) {
            $created = [datetime]::Parse($item.createdDateTime, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)

            (New-TimeSpan -Start $created -End (Get-Date).ToUniversalTime()).Days
        } else {
            "-"
        }


        #Get the Delegated permissions
        $DelegatedPermission = [System.Collections.ArrayList]::new()
        if ($DelegatedPermissionRaw.ContainsKey($item.Id)) {
            foreach ($DelegatedPermissionAssignment in $DelegatedPermissionRaw[$item.Id]) {
                [void]$DelegatedPermission.Add(
                    [PSCustomObject]@{
                        ResourceId = $DelegatedPermissionAssignment.ResourceId
                        Scope = $DelegatedPermissionAssignment.Scope
                        ConsentType = $DelegatedPermissionAssignment.ConsentType
                        PrincipalId = $DelegatedPermissionAssignment.PrincipalId
                    }
                )
            }
        }

        $DelegatedPermissionDetails = Resolve-DelegatedPermissionGrantDetails -AppRoleReferenceCache $AppRoleReferenceCache -DelegatedPermissions @($DelegatedPermission)


        #Store unique permission to show in table
        $DelegatedPermissionDetailsUnique = ($DelegatedPermissionDetails | Select-Object -ExpandProperty Scope | Sort-Object -Unique).count


        # Sort by Principal, then by custom Categorization order
        $DelegatedPermissionDetails = $DelegatedPermissionDetails | Sort-Object Principal, @{ Expression = { $categorizationOrder[$_.ApiPermissionCategorization] }; Ascending = $true }

        #Count by severity
        $ApiPermissionSeverity = @('Dangerous', 'High', 'Medium', 'Low', 'Uncategorized')
        $DelegateApiPermssionCount = @{}
        foreach ($severity in $ApiPermissionSeverity) {
            $count = ($DelegatedPermissionDetails | Where-Object { $_.ApiPermissionCategorization -eq $severity } | Measure-Object ).Count
            $DelegateApiPermssionCount[$severity] = $count
        }



        #Get all groups where the SP is member of
        $GroupMember = [System.Collections.ArrayList]::new()
        if ($GroupMemberRaw.ContainsKey($item.Id)) {
            foreach ($GroupMemberAssignment in $GroupMemberRaw[$item.Id]) {
                [void]$GroupMember.Add(
                    [PSCustomObject]@{
                        Id = $GroupMemberAssignment.Id
                        displayName = $GroupMemberAssignment.displayName
                        visibility = $GroupMemberAssignment.visibility
                        securityEnabled = $GroupMemberAssignment.securityEnabled
                        groupTypes = $GroupMemberAssignment.groupTypes
                        isAssignableToRole = $GroupMemberAssignment.isAssignableToRole
                    }
                )
            }
        }

        $GroupMember = foreach ($Group in $GroupMember) {
            Get-GroupDetails -Group $Group -AllGroupsDetails $AllGroupsDetails
        }


        #Get application owned objects (can own groups or applications)
        $OwnedApplications   = [System.Collections.ArrayList]::new()
        $OwnedGroups  	= [System.Collections.ArrayList]::new()
        $OwnedSP  	= [System.Collections.ArrayList]::new()
        if ($OwnedObjectsRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $OwnedObjectsRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.servicePrincipal' {
                        [void]$OwnedSP.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                                appId = $OwnedObject.appId
                            }
                        )
                    }

                    '#microsoft.graph.application' {
                        [void]$OwnedApplications.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                                appId = $OwnedObject.appId
                            }
                        )
                    }

                    '#microsoft.graph.group' {
                        [void]$OwnedGroups.Add(
                            [PSCustomObject]@{
                                Id  = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                            }
                        )
                    }

                }
            }
        }

        $OwnedGroups = foreach ($Group in $OwnedGroups) {
            Get-GroupDetails -Group $Group -AllGroupsDetails $AllGroupsDetails
        }

        # Group membership tier inheritance: active-only paths.
        foreach ($group in $GroupMember) {
            $entraMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Entra
            $EntraMaxTierThroughGroupMembership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierThroughGroupMembership -CandidateTier $entraMetrics.MaxTier

            if ($GLOBALAzurePsChecks) {
                $azureMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Azure
                $AzureMaxTierThroughGroupMembership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierThroughGroupMembership -CandidateTier $azureMetrics.MaxTier
            }
        }

        # Group ownership tier inheritance: active + eligible paths.
        foreach ($group in $OwnedGroups) {
            $entraMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Entra -IncludeEligible
            $EntraMaxTierThroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierThroughGroupOwnership -CandidateTier $entraMetrics.MaxTier

            if ($GLOBALAzurePsChecks) {
                $azureMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Azure -IncludeEligible
                $AzureMaxTierThroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierThroughGroupOwnership -CandidateTier $azureMetrics.MaxTier
            }
        }

        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $DirectEntraMaxTier -CandidateTier $EntraMaxTierThroughGroupMembership
        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $EntraMaxTier -CandidateTier $EntraMaxTierThroughGroupOwnership
        if ($GLOBALAzurePsChecks) {
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $DirectAzureMaxTier -CandidateTier $AzureMaxTierThroughGroupMembership
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $AzureMaxTier -CandidateTier $AzureMaxTierThroughGroupOwnership
        } else {
            $AzureMaxTier = "?"
        }

        if ($AzureRoleCount -is [int] -and $AzureRoleCount -gt 0 -and $AzureMaxTier -eq "-") {
            Write-Log -Level Debug -Message "AzureMaxTier '-' with AzureRoleCount $AzureRoleCount for app '$($item.DisplayName)' ($($item.Id))"
        }
        if ($AppEntraRoles -and $AppEntraRoles.Count -gt 0 -and $EntraMaxTier -eq "-") {
            Write-Log -Level Debug -Message "EntraMaxTier '-' with EntraRoleCount $($AppEntraRoles.Count) for app '$($item.DisplayName)' ($($item.Id))"
        }

        $OwnedApplicationsCount = $OwnedApplications.count
        $OwnedSPCount = $OwnedSP.count

        #Process Last sign-in date for each App
        if (-not [string]::IsNullOrWhiteSpace($item.AppId) -and $AppLastSignIns.ContainsKey($item.AppId)) {
            $AppsignInData = $AppLastSignIns[$item.AppId]
        } else {
            $AppsignInData = $Null
        }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################


        #Check if it is an SP of a foreign tenant
        if ($item.AppOwnerOrganizationId -eq $($CurrentTenant).id) {
            $ForeignTenant = $false

        } else {
            $ForeignTenant = $true
        }

        #Get owners of the sp
        $OwnerUserDetails  	= [System.Collections.ArrayList]::new()
        $OwnerSPDetails  	= [System.Collections.ArrayList]::new()
        if ($OwnersRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $OwnersRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.user' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$OwnerUserDetails.Add(
                            [PSCustomObject]@{
                                Id             = $OwnedObject.Id
                                UPN            = $OwnedObject.userPrincipalName
                                Enabled        = $OwnedObject.accountEnabled
                                Type           = $OwnedObject.userType
                                Department     = $OwnedObject.department
                                JobTitle       = $OwnedObject.jobTitle
                                OnPremSync     = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.agentUser' {
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$OwnerUserDetails.Add(
                            [PSCustomObject]@{
                                Id             = $OwnedObject.Id
                                UPN            = $OwnedObject.userPrincipalName
                                Enabled        = $OwnedObject.accountEnabled
                                Type           = $OwnedObject.userType
                                Department     = $OwnedObject.department
                                JobTitle       = $OwnedObject.jobTitle
                                OnPremSync     = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$OwnerSPDetails.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                displayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                appOwnerOrganizationId = $OwnedObject.appOwnerOrganizationId
                                publisherName          = $OwnedObject.publisherName
                                servicePrincipalType   = $OwnedObject.servicePrincipalType
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = 'ServicePrincipal'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        [void]$OwnerSPDetails.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                displayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                appOwnerOrganizationId = $OwnedObject.appOwnerOrganizationId
                                publisherName          = $OwnedObject.publisherName
                                servicePrincipalType   = if ($null -ne $OwnedObject.servicePrincipalType) { $OwnedObject.servicePrincipalType } else { 'Application' }
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = 'AgentIdentity'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        [void]$OwnerSPDetails.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                displayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                appOwnerOrganizationId = $OwnedObject.appOwnerOrganizationId
                                publisherName          = $OwnedObject.publisherName
                                servicePrincipalType   = if ($null -ne $OwnedObject.servicePrincipalType) { $OwnedObject.servicePrincipalType } else { 'Application' }
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = 'AgentIdentityBlueprintPrincipal'
                            }
                        )
                    }
                }
            }
        }

        $OwnersCount = $OwnerUserDetails.count + $OwnerSPDetails.count

        #Check if it is one of the MS default SPs
        if ($GLOBALMsTenantIds -contains $item.AppOwnerOrganizationId -or $item.DisplayName -eq "O365 LinkedIn Connection" -and $item.DisplayName -ne "P2P Server") {
            $DefaultMS = $true
        } else {
            $DefaultMS = $false
        }


        # Direct roles, ownerships, group paths, and configured API permissions are inventory-only for blueprint principals.

        $Inactive = Test-EntraFalconServicePrincipalInactive -SignInData $AppsignInData -CreationInDays $CreationInDays -ActivityAvailable ($global:GLOBALSpSignInActivityAvailable -ne $false)

        #Mark foreign non-default apps as risky
        if ($DefaultMS -eq $false -and $ForeignTenant -eq $true) {
            $LikelihoodScore += $SPLikelihoodScore["ForeignApp"]
        } elseif ($DefaultMS -eq $false -and $ForeignTenant -eq $false) {
            $LikelihoodScore += $SPLikelihoodScore["InternApp"]
        }

        $Warnings = if ($null -ne $AppsignInData -and "$($AppsignInData.lastSignInState)" -eq 'Malformed') {
            "Malformed service principal sign-in timestamp; inactivity not assessed"
        } else {
            ''
        }

        $LastSignInDays = "-"
        if ($null -ne $AppsignInData -and $null -ne $AppsignInData.lastSignInDays -and -not [string]::IsNullOrWhiteSpace("$($AppsignInData.lastSignInDays)")) {
            $LastSignInDays = $AppsignInData.lastSignInDays
        }

        #Write custom object
        $SPInfo = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            Enabled = $item.accountEnabled
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            PublisherName = $item.PublisherName
            AppId = $item.AppId
            ServicePrincipalType = $item.servicePrincipalType
            SignInAudience = $item.signInAudience
            GrpMem = ($GroupMember | Measure-Object).count
            EntraRoles = ($AppEntraRoles | Measure-Object).count
            EntraMaxTier = $EntraMaxTier
            PermissionCount = ($AppAssignments | Measure-Object).count
            GrpOwn = ($OwnedGroups | Measure-Object).count
            AppOwn = $OwnedApplicationsCount
            OwnedApplicationsDetails = $OwnedApplications
            SpOwn = $OwnedSPCount
            OwnedSPDetails = $OwnedSP
            GroupMember = $GroupMember
            AppOwnerOrganizationId = $item.AppOwnerOrganizationId
            EntraRoleDetails = $AppEntraRoles
            GroupOwner = $OwnedGroups
            AppPermission = $AppAssignments
            Foreign = $ForeignTenant
            DefaultMS = $DefaultMS
            AzureRoles = $AzureRoleCount
            AzureMaxTier = $AzureMaxTier
            Inactive = $Inactive
            LastSignInDays = $LastSignInDays
            CreationDate = $item.createdDateTime
            CreationInDays = $CreationInDays
            AppsignInData = $AppsignInData
            AzureRoleDetails = $AzureRoleDetails
            Owners = $OwnersCount
            OwnerUserDetails = $OwnerUserDetails
            OwnerSPDetails = $OwnerSPDetails
            LinkedAgentIdentities = ($LinkedAgentIdentities | Measure-Object).Count
            LinkedAgentIdentitiesDetails = $LinkedAgentIdentities
            AppRoleRequired = $item.AppRoleAssignmentRequired
            AppApiPermission = $AppApiPermission
            AppRoles = ($MatchingAppRoles | Measure-Object).count
            AppRolesDetails = $MatchingAppRoles
            ApiDelegated = $DelegatedPermissionDetailsUnique
            ApiDelegatedDetails  = $DelegatedPermissionDetails
            ApiDelegatedDangerous = $DelegateApiPermssionCount.Dangerous
            ApiDelegatedHigh = $DelegateApiPermssionCount.High
            ApiDelegatedMedium = $DelegateApiPermssionCount.Medium
            ApiDelegatedLow = $DelegateApiPermssionCount.Low
            ApiDelegatedMisc = $DelegateApiPermssionCount.Uncategorized
            ApiDangerous = $AppApiPermissionDangerous
            ApiHigh = $AppApiPermissionHigh
            ApiMedium = $AppApiPermissionMedium
            ApiLow = $AppApiPermissionLow
            ApiMisc = $AppApiPermissionUncategorized
            DirectImpact = $ImpactScore
            InheritedImpact = 0
            Impact = $ImpactScore
            Likelihood = $LikelihoodScore
            Risk = $ImpactScore * $LikelihoodScore
            Warnings = $Warnings
        }
        [void]$AllServicePrincipal.Add($SPInfo)
    }
    #endregion

    ########################################## SECTION: POST-PROCESSING ##########################################
    write-host "[*] Post-processing SP ownership relation with other apps"


    # Ownership relations are inventory-only for blueprint principals.
    $SPOwningApps = $AllServicePrincipal | Where-Object { $_.AppOwn -ge 1 }
    Write-Log -Level Debug -Message "Number of ownerships SP->AppReg: $($SPOwningApps.count)"

    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    $SPOwningSPs = $AllServicePrincipal | Where-Object { $_.SpOwn -ge 1 }
    Write-Log -Level Debug -Message "Number of ownerships SP->SP: $($SPOwningSPs.count)"
    foreach ($SpOwnerObject in $SPOwningSPs) {

        foreach ($OwnedSPObject in $SpOwnerObject.OwnedSPDetails) {

            $OwnedSPObjectDetails = $AllServicePrincipalHT[$OwnedSPObject.Id]
            if ($null -eq $OwnedSPObjectDetails) {
                continue
            }

            $OwnedSPObject | Add-Member -NotePropertyName Impact -NotePropertyValue $OwnedSPObjectDetails.Impact -Force
            $OwnedSPObject | Add-Member -NotePropertyName Foreign -NotePropertyValue $OwnedSPObjectDetails.Foreign -Force
        }
    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    return $AllServicePrincipalHT
}
