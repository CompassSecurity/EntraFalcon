<#
.SYNOPSIS
   Enumerate Agent Identities (including: API Permission, Source Tenant, Groups, Roles).

.DESCRIPTION
   This script will enumerate all Agent Identities (including: API Permission, Source Tenant, Groups, Roles).
   By default, MS applications are filtered out.

#>

function Invoke-AgentIdentities {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][switch]$IncludeMsApps = $false,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$AllUsersBasicHT,
        [Parameter(Mandatory=$false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$true)][hashtable]$ServicePrincipalSignInActivityLookup,
        [Parameter(Mandatory=$false)][hashtable]$CatalogRbacPrincipalIndex = @{},
        [Parameter(Mandatory=$false)][bool]$CatalogRbacAssessmentAvailable = $false,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $ProgressCounter = 0
    $Inactive = $false
    $SponsorResolutionCache = @{}
    $AppLastSignIns = $ServicePrincipalSignInActivityLookup
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    if ($null -eq $global:GLOBALUserAppRoles) { $global:GLOBALUserAppRoles = @{} }
    $SPImpactScore = @{
        "Base"                      = 1
        "APIDangerous"              = 800
        "APIHigh"                   = 400
        "APIMedium"                 = 100
        "APILow"                    = 50
        "ApiMisc"                   = 20
        "APIDelegatedDangerous"     = 200
        "APIDelegatedHigh"          = 100
        "APIDelegatedMedium"        = 60
        "APIDelegatedLow"           = 20
        "ApiDelegatedMisc"          = 20
        "AppRoleRequired"           = 10
        "AppRole"                   = 2
    }

    $SPLikelihoodScore = @{
        "ForeignApp"                = 30
    }

    # Resolve sponsor objects into a stable reporting shape.
    function Resolve-AgentIdentitySponsor {
        param(
            [Parameter(Mandatory = $true)]$SponsorObject
        )

        $sponsorId = "$($SponsorObject.id)".Trim()
        if ([string]::IsNullOrWhiteSpace($sponsorId)) {
            return [pscustomobject]@{
                Id            = "-"
                Type          = "Unknown"
                DisplayName   = "-"
                UPN           = "-"
                Foreign       = "-"
                PublisherName = "-"
            }
        }

        $sponsorType = switch ("$($SponsorObject.'@odata.type')".ToLowerInvariant()) {
            '#microsoft.graph.user'                           { 'user' }
            '#microsoft.graph.agentuser'                      { 'agentuser' }
            '#graph.agentuser'                                { 'agentuser' }
            '#microsoft.graph.group'                          { 'group' }
            '#microsoft.graph.serviceprincipal'               { 'serviceprincipal' }
            '#microsoft.graph.agentidentityblueprintprincipal' { 'agentidentityblueprintprincipal' }
            '#graph.agentidentityblueprintprincipal'          { 'agentidentityblueprintprincipal' }
            default                                           { 'unknown' }
        }

        $cacheKey = "$sponsorType|$sponsorId"
        if ($SponsorResolutionCache.ContainsKey($cacheKey)) {
            return $SponsorResolutionCache[$cacheKey]
        }

        $resolved = $null

        if ($sponsorType -eq 'user' -or $sponsorType -eq 'agentuser') {
            if ($AllUsersBasicHT.ContainsKey($sponsorId)) {
                $user = $AllUsersBasicHT[$sponsorId]
                $resolved = [pscustomobject]@{
                    Id            = $sponsorId
                    Type          = if ($sponsorType -eq 'agentuser') { "AgentUser" } else { "User" }
                    DisplayName   = if ([string]::IsNullOrWhiteSpace($user.DisplayName)) { "-" } else { $user.DisplayName }
                    UPN           = if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { "-" } else { $user.UserPrincipalName }
                    Foreign       = "-"
                    PublisherName = "-"
                }
            } else {
                $QueryParameters = @{
                    '$select' = "id,displayName,userPrincipalName"
                }
                $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$sponsorId" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
                if ($null -eq $user -and $sponsorType -eq 'agentuser') {
                    $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/microsoft.graph.agentUser/$sponsorId" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
                }
                if ($null -ne $user) {
                    $resolved = [pscustomobject]@{
                        Id            = $sponsorId
                        Type          = if ($sponsorType -eq 'agentuser') { "AgentUser" } else { "User" }
                        DisplayName   = if ([string]::IsNullOrWhiteSpace($user.displayName)) { "-" } else { $user.displayName }
                        UPN           = if ([string]::IsNullOrWhiteSpace($user.userPrincipalName)) { "-" } else { $user.userPrincipalName }
                        Foreign       = "-"
                        PublisherName = "-"
                    }
                }
            }
        } elseif ($sponsorType -eq 'group') {
            if ($AllGroupsDetails.ContainsKey($sponsorId)) {
                $group = $AllGroupsDetails[$sponsorId]
                $resolved = [pscustomobject]@{
                    Id            = $sponsorId
                    Type          = "Group"
                    DisplayName   = if ([string]::IsNullOrWhiteSpace($group.DisplayName)) { "-" } else { $group.DisplayName }
                    UPN           = "-"
                    Foreign       = "-"
                    PublisherName = "-"
                }
            } else {
                $QueryParameters = @{
                    '$select' = "id,displayName"
                }
                $group = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/groups/$sponsorId" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
                if ($null -ne $group) {
                    $resolved = [pscustomobject]@{
                        Id            = $sponsorId
                        Type          = "Group"
                        DisplayName   = if ([string]::IsNullOrWhiteSpace($group.displayName)) { "-" } else { $group.displayName }
                        UPN           = "-"
                        Foreign       = "-"
                        PublisherName = "-"
                    }
                }
            }
        } elseif ($sponsorType -eq 'serviceprincipal' -or $sponsorType -eq 'agentidentityblueprintprincipal') {
            $QueryParameters = @{
                '$select' = "id,displayName,publisherName,appOwnerOrganizationId"
            }
            $sp = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$sponsorId" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
            if ($null -ne $sp) {
                $foreign = "-"
                $ownerTenantId = "$($sp.appOwnerOrganizationId)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($ownerTenantId)) {
                    $foreign = ($ownerTenantId -ne "$($CurrentTenant.id)")
                }
                $resolved = [pscustomobject]@{
                    Id            = $sponsorId
                    Type          = if ($sponsorType -eq 'agentidentityblueprintprincipal') { "AgentIdentityBlueprintPrincipal" } else { "ServicePrincipal" }
                    DisplayName   = if ([string]::IsNullOrWhiteSpace($sp.displayName)) { "-" } else { $sp.displayName }
                    UPN           = "-"
                    Foreign       = $foreign
                    PublisherName = if ([string]::IsNullOrWhiteSpace($sp.publisherName)) { "-" } else { $sp.publisherName }
                }
            }
        }

        if ($null -eq $resolved) {
            $resolved = [pscustomobject]@{
                Id            = $sponsorId
                Type          = if ($sponsorType -eq 'unknown') { "Unknown" } else { $sponsorType }
                DisplayName   = "-"
                UPN           = "-"
                Foreign       = "-"
                PublisherName = "-"
            }
        }

        $SponsorResolutionCache[$cacheKey] = $resolved
        return $resolved
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Agent Identities
    write-host "[*] Get Agent Identities"
    $QueryParameters = @{
        '$select' = "Id,AppId,DisplayName,appRoles,accountEnabled,servicePrincipalType,createdDateTime,AppRoleAssignmentRequired,agentIdentityBlueprintId,createdByAppId,tags,AppOwnerOrganizationId"
        '$top' = $ApiTop
    }
    $AgentIdentities = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals/Microsoft.Graph.AgentIdentity' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $AgentIdentitiesCount = $($AgentIdentities.count)
    write-host "[+] Got $AgentIdentitiesCount Agent Identities "

    #Abort if no apps are present
    if (@($AgentIdentities).count -eq 0) {
        $AllServicePrincipalHT = @{}
        Return $AllServicePrincipalHT
    }

    Write-Log -Level Debug -Message "Using $($AppLastSignIns.Count) cached app last sign-in dates"

    Write-Host "[*] Get all agent identity API permissions assignments"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
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

    Write-Host "[*] Get all agent identity delegated API permissions"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
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

    Write-Host "[*] Get all agent identity group memberships"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
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

    Write-Host "[*] Get all agent identity object ownerships"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
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
    $AgentIdentities | ForEach-Object {
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

    Write-Host "[*] Get all sponsors"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/microsoft.graph.agentIdentity/sponsors"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $SponsorsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $SponsorsRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got $($SponsorsRaw.Count) sponsors"

    Write-Host "[*] Get assigned agent users"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/users/microsoft.graph.agentUser"
            "queryParameters" = @{
                '$filter' = "identityParentId eq '$($_.id)'"
                '$select' = "id,accountEnabled,userPrincipalName"
                '$top'    = "$ApiTop"
            }
        }
    }
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AgentUsersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AgentUsersRaw[$item.id] = $item.response.value
        }
    }
    Write-Log -Level Debug -Message "Got assigned agent users for $($AgentUsersRaw.Count) agent identities"

    Write-Host "[*] Get all app role assignments"
    $Requests = @()
    $AgentIdentities | ForEach-Object {
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

    ########################################## SECTION: Agent Identity Processing ##########################################




    #Enumerate all AppRoles configured (only of the apps in scope)
    $AppRoles = [System.Collections.ArrayList]::new()

    foreach ($app in $AgentIdentities) {
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
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($AgentIdentitiesCount / 10), 1)
    if ($AgentIdentitiesCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing agent identity 1 of $AgentIdentitiesCount (updates every $StatusUpdateInterval objects)..."
    }

    #region Processing Loop
    #Loop through each agent identity, retrieve additional info, and store it in a custom object
    foreach ($item in $AgentIdentities) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = 0
        $warnings = @()
        $OwnerUserDetails = @()
        $OwnerSPDetails = @()
        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AgentIdentitiesCount) {
            Write-Host "[*] Status: Processing agent identity $ProgressCounter of $AgentIdentitiesCount..."
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
        $AllAzureRoleDetails = @()
        $AzureRoleDetails = @()
        $EligibleAzureRoleDetails = @()
        if ($GLOBALAzurePsChecks) {
            #Use function to get the Azure Roles for each object
            $AllAzureRoleDetails = @(Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $item.Id)
            $AzureRoleDetails = @($AllAzureRoleDetails | Where-Object { "$($_.AssignmentType)".Trim() -eq "Active" })
            $EligibleAzureRoleDetails = @($AllAzureRoleDetails | Where-Object { "$($_.AssignmentType)".Trim() -eq "Eligible" })
            # Update the Roles property only if there are matching roles
            $AzureRoleCount = ($AzureRoleDetails | Measure-Object).Count
        } else {
            $AzureRoleCount = "?"
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

        $AllAppEntraRoles = @()
        $AllAppEntraRoles = foreach ($Role in $MatchingRoles) {
            [PSCustomObject]@{
                Type = "Roles"
                DisplayName = $Role.DisplayName
                Enabled = $Role.IsEnabled
                IsBuiltin = $Role.IsBuiltIn
                RoleTier  = $role.RoleTier
                IsPrivileged = $Role.IsPrivileged
                AssignmentType = $Role.AssignmentType
                Scoped = $Role.DirectoryScopeId
                ScopeResolved = $Role.ScopeResolved
            }
        }
        $AppEntraRoles = @($AllAppEntraRoles | Where-Object { "$($_.AssignmentType)".Trim() -eq "Active" })
        $EligibleAppEntraRoles = @($AllAppEntraRoles | Where-Object { "$($_.AssignmentType)".Trim() -eq "Eligible" })

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

        # Group ownership tier inheritance: active-only paths.
        foreach ($group in $OwnedGroups) {
            $entraMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Entra
            $EntraMaxTierThroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierThroughGroupOwnership -CandidateTier $entraMetrics.MaxTier

            if ($GLOBALAzurePsChecks) {
                $azureMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Azure
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

        # Prefer createdByAppId for agent identities; fallback to AppId when present.
        $appLookupId = "$($item.createdByAppId)".Trim()
        if ([string]::IsNullOrWhiteSpace($appLookupId)) {
            $appLookupId = "$($item.AppId)".Trim()
        }
        if ([string]::IsNullOrWhiteSpace($appLookupId)) {
            $appLookupId = $null
        }

        #Process Last sign-in date for each App
        if (-not [string]::IsNullOrWhiteSpace($appLookupId) -and $AppLastSignIns.ContainsKey($appLookupId)) {
            $AppsignInData = $AppLastSignIns[$appLookupId]
        } else {
            $AppsignInData = $Null
        }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################


        $appOwnerOrganizationId = "$($item.AppOwnerOrganizationId)".Trim()
        $ForeignTenant = ($appOwnerOrganizationId -ne "" -and $appOwnerOrganizationId -ne $CurrentTenant.id)

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
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
        $AppSponsorsDetails = @()
        if ($SponsorsRaw.ContainsKey($item.Id)) {
            $AppSponsorsDetails = foreach ($Sponsor in $SponsorsRaw[$item.Id]) {
                Resolve-AgentIdentitySponsor -SponsorObject $Sponsor
            }
        }
        $SponsorsCount = ($AppSponsorsDetails | Measure-Object).Count
        $AssignedAgentUsers = @()
        if ($AgentUsersRaw.ContainsKey($item.Id)) {
            $AssignedAgentUsers = foreach ($AgentUser in $AgentUsersRaw[$item.Id]) {
                [pscustomobject]@{
                    Id = $AgentUser.id
                    UPN = if ([string]::IsNullOrWhiteSpace($AgentUser.userPrincipalName)) { "-" } else { $AgentUser.userPrincipalName }
                    Enabled = if ($null -eq $AgentUser.accountEnabled) { "-" } else { $AgentUser.accountEnabled }
                }
            }
        }
        $AssignedAgentUsersCount = ($AssignedAgentUsers | Measure-Object).Count

        if ($DefaultMS -eq $false -and $ForeignTenant -eq $true) {
            $LikelihoodScore += $SPLikelihoodScore["ForeignApp"]
        }

        #Increase impact for each App role
        $AppRolesCount = ($MatchingAppRoles | Measure-Object).count
        if ($AppRolesCount -ge 1) {
            $ImpactScore += $AppRolesCount * $SPImpactScore["AppRole"]
        }

        #Increase impact if App Roles needs to be assigned
        if ($item.AppRoleAssignmentRequired) {
            $ImpactScore += $SPImpactScore["AppRoleRequired"]
        }

        #If SP owns App Registration
        if ($OwnedApplicationsCount -ge 1) {
            $Warnings += "SP owns $OwnedApplicationsCount App Registrations!"
        }

        #If SP owns another SP
        if ($OwnedSPCount -ge 1) {
            $Warnings += "Agent identity owns $OwnedSPCount service principals!"
        }


        #Check if it is one of the MS default SPs
        if (($appOwnerOrganizationId -and $GLOBALMsTenantIds -contains $appOwnerOrganizationId) -or $item.DisplayName -eq "O365 LinkedIn Connection" -and $item.DisplayName -ne "P2P Server") {
            $DefaultMS = $true
        } else {
            $DefaultMS = $false
        }


        #Process group memberships
        if (($GroupMember | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $TotalAzureRoles = 0

            #Check each group
            foreach ($Groups in $GroupMember) {
                # Inherit group impact excluding eligible/PIM role contribution.
                $groupInheritedImpact = 0
                [void][int]::TryParse([string]$Groups.ImpactOrgActiveOnly, [ref]$groupInheritedImpact)
                $ImpactScore += $groupInheritedImpact

                $entraMetrics = Get-GroupActiveRoleMetrics -Group $Groups -RoleSystem Entra
                $TotalAssignedRoleCount += $entraMetrics.RoleCount
                $TotalAssignedPrivilegedRoles += $entraMetrics.PrivilegedCount

                $groupAzureRoleCount = 0
                if ($GLOBALAzurePsChecks) {
                    $azureMetrics = Get-GroupActiveRoleMetrics -Group $Groups -RoleSystem Azure
                    $groupAzureRoleCount = $azureMetrics.RoleCount
                    $TotalAzureRoles += $groupAzureRoleCount
                }

                $groupCapCount = 0
                [void][int]::TryParse([string]$Groups.CAPs, [ref]$groupCapCount)
                if ($Groups.InheritedHighValue -ge 1 -and ($entraMetrics.RoleCount -ge 1 -or $groupAzureRoleCount -ge 1 -or $groupCapCount -ge 1)) {
                    $TotalInheritedHighValue += $Groups.InheritedHighValue
                }
            }

            #Check Entra role assignments
            if ($TotalAssignedRoleCount -ge 1) {
                if ($TotalAssignedPrivilegedRoles -ge 1) {
                    $privileged = "Privileged "
                } else {
                    $privileged = ""
                }
                $Warnings += "$($privileged)Entra role(s) through group membership"
            }

            #Check Azure role assignments
            if ($TotalAzureRoles -ge 1) {
                $Warnings += "$TotalAzureRoles Azure role(s) through group membership"
            }

            #Check membership of groups with inherited high value
            if ($TotalInheritedHighValue -ge 1) {
                $Warnings += "Member of $TotalInheritedHighValue groups with high value (active paths)"
            }
        }


        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if (($AppEntraRoles | Measure-Object).count -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $AppEntraRoles
            $Warnings += $EntraRolesProcessedDetails.Warning
            $ImpactScore += $EntraRolesProcessedDetails.ImpactScore
        }


        #If SP owns groups
        if (($OwnedGroups | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $TotalAzureRoles = 0
            $TotalCAPs = 0
            #Basic score for owning a group


                #Check each owned group
                foreach ($OwnedGroup in $OwnedGroups) {
                    # Ownership inherits only the group's active-path impact.
                    $groupInheritedImpact = 0
                    if (-not [int]::TryParse([string]$OwnedGroup.ImpactOrgActiveOnly, [ref]$groupInheritedImpact)) {
                        [void][int]::TryParse([string]$OwnedGroup.ImpactOrg, [ref]$groupInheritedImpact)
                    }
                    $ImpactScore += $groupInheritedImpact

                    $entraMetrics = Get-GroupActiveRoleMetrics -Group $OwnedGroup -RoleSystem Entra
                    $TotalAssignedRoleCount += $entraMetrics.RoleCount
                    $TotalAssignedPrivilegedRoles += $entraMetrics.PrivilegedCount

                    $groupAzureRoleCount = 0
                    if ($GLOBALAzurePsChecks) {
                        $azureMetrics = Get-GroupActiveRoleMetrics -Group $OwnedGroup -RoleSystem Azure
                        $groupAzureRoleCount = $azureMetrics.RoleCount
                        $TotalAzureRoles += $groupAzureRoleCount
                    }

                    $groupCapCount = 0
                    [void][int]::TryParse([string]$OwnedGroup.CAPs, [ref]$groupCapCount)
                    if ($OwnedGroup.InheritedHighValue -ge 1 -and ($entraMetrics.RoleCount -ge 1 -or $groupAzureRoleCount -ge 1 -or $groupCapCount -ge 1)) {
                        $TotalInheritedHighValue += $OwnedGroup.InheritedHighValue
                    }

                    $TotalCAPs += $OwnedGroup.CAPs
                }

                #Check Entra role assignments
                if ($TotalAssignedRoleCount -ge 1) {
                    if ($TotalAssignedPrivilegedRoles -ge 1) {
                        $privileged = "Privileged "
                    } else {
                        $privileged = ""
                    }
                    $Warnings += "$($privileged)Entra role(s) through group ownership"
                }

                #Check Azure role assignments
                if ($TotalAzureRoles -ge 1) {
                    $Warnings += "$TotalAzureRoles Azure role(s) through group ownership"
                }

                #Check CAP group ownership
                if ($TotalCAPs -ge 1) {
                    $Warnings += "Owns $TotalCAPs groups used in CAPs"
                }

                #Check ownership of groups with inherited high value
                if ($TotalInheritedHighValue -ge 1) {
                    $Warnings += "Owns $TotalInheritedHighValue groups with high value"
                }
        }

        #Process Application API permission
        if (($AppApiPermission | Measure-Object).Count -ge 1) {
            foreach ($object in $AppApiPermission) {
                switch($object.ApiPermissionCategorization) {
                    "Dangerous" {$ImpactScore += $SPImpactScore["APIDangerous"]; Break}
                    "High" {$ImpactScore += $SPImpactScore["APIHigh"]; Break}
                    "Medium" {$ImpactScore += $SPImpactScore["APIMedium"]; Break}
                    "Low" {$ImpactScore += $SPImpactScore["APILow"]; Break}
                    "Uncategorized" {$ImpactScore += $SPImpactScore["ApiMisc"]; Break}
                }
            }
        }

        #Check if agent is inactive
        $LastSignInDays = "-"
        if ($null -ne $AppsignInData -and $null -ne $AppsignInData.lastSignInDays -and -not [string]::IsNullOrWhiteSpace("$($AppsignInData.lastSignInDays)")) {
            $LastSignInDays = $AppsignInData.lastSignInDays
        }

        $lastSignInDaysText = "$LastSignInDays".Trim()
        $lastSignInDaysNumber = 0
        $hasLastSignInDays = [int]::TryParse($lastSignInDaysText, [ref]$lastSignInDaysNumber)
        $creationInDaysNumber = 0
        $hasCreationInDays = [int]::TryParse("$CreationInDays", [ref]$creationInDaysNumber)

        if (($hasLastSignInDays -and $lastSignInDaysNumber -ge 180) -or ($lastSignInDaysText -eq "-" -and $hasCreationInDays -and $creationInDaysNumber -gt 180)) {
            $Inactive = $true
        } else {
            $Inactive = $false
        }

        #Process Delegated API permission. Only increase the score once (independet of how many principal or how many of each category are assigned)
        if ($DelegatedPermissionDetailsUnique -ge 1) {

            if ($DelegateApiPermssionCount.Dangerous -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedDangerous"]
            }

            if ($DelegateApiPermssionCount.High -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedHigh"]
            }

            if ($DelegateApiPermssionCount.Medium -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedMedium"]
            }

            if ($DelegateApiPermssionCount.Low -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedLow"]
            }
            if ($DelegateApiPermssionCount.Uncategorized -ge 1) {
                $ImpactScore += $SPImpactScore["ApiDelegatedMisc"]
            }
        }

        $DirectCatalogRbacDetails = if ($CatalogRbacPrincipalIndex.ContainsKey([string]$item.Id)) { @($CatalogRbacPrincipalIndex[[string]$item.Id]) } else { @() }
        $CatalogRbacDetails = @(Merge-EntraFalconCatalogRbacAssignments -DirectAssignments $DirectCatalogRbacDetails -GroupMemberships $GroupMember)
        $CatalogRBAC = if ($CatalogRbacAssessmentAvailable) { $CatalogRbacDetails.Count } else { '-' }
        if (@($CatalogRbacDetails | Where-Object { [string]$_.Role -in @('Catalog Owner','Access Package Manager','Access Package Assignment Manager') }).Count -gt 0) {
            $Warnings += "Identity Governance management role assigned"
        }

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        #Write custom object
        $SPInfo = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            Enabled = $item.accountEnabled
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            PublisherName = $item.PublisherName
            AppId = $item.AppId
            AppLookupId = $appLookupId
            CreatedByAppId = $item.createdByAppId
            AgentIdentityBlueprintId = $item.agentIdentityBlueprintId
            Tags = if ($null -ne $item.tags) { @($item.tags) -join ", " } else { "" }
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
            CatalogRBAC = $CatalogRBAC
            CatalogRbacDetails = $CatalogRbacDetails
            OwnedSPDetails = $OwnedSP
            GroupMember = $GroupMember
            AppOwnerOrganizationId = $appOwnerOrganizationId
            EntraRoleDetails = $AppEntraRoles
            EligibleEntraRoleDetails = $EligibleAppEntraRoles
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
            EligibleAzureRoleDetails = $EligibleAzureRoleDetails
            Owners = $OwnersCount
            Sponsors = $SponsorsCount
            AgentUsers = $AssignedAgentUsersCount
            OwnerUserDetails = $OwnerUserDetails
            OwnerSPDetails = $OwnerSPDetails
            AppSponsorsDetails = $AppSponsorsDetails
            AgentUsersDetails = $AssignedAgentUsers
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


    #Process indirect App ownerships (SP->AppReg->SP) (take over Impact, inherit likelihood)
    $SPOwningApps = $AllServicePrincipal | Where-Object { $_.AppOwn -ge 1 }
    Write-Log -Level Debug -Message "Number of ownerships SP->AppReg: $($SPOwningApps.count)"

    # For each object which owns an App registration
    foreach ($SpObject in $SPOwningApps) {

        # For each owned App Registration
        foreach ($AppRegistration in $SpObject.OwnedApplicationsDetails) {

            #For each corresponding SP object of the App Registration
            foreach ($OwnedSP in $AllServicePrincipal | Where-Object { $_.AppId -eq $AppRegistration.AppId }) {

                # Increment/Recalculate RiskScore of the SP objects which is indirectly owned (SP->AppReg->SP*)
                $OwnedSP.Likelihood += [math]::Round($SpObject.Likelihood)
                $OwnedSP.Risk = [math]::Round(($OwnedSP.Impact * $OwnedSP.Likelihood))

                # Append the Message to Warnings of the SP objects which is indirectly owned (SP->AppReg->SP*)
                $warningMessage = "AppReg. owned by other SP"
                if ($OwnedSP.Warnings -and $OwnedSP.Warnings -notmatch $warningMessage) {
                    $OwnedSP.Warnings += " / $warningMessage"
                } else {
                    $OwnedSP.Warnings = $warningMessage
                }

                # Increment/Recalculate impact score of the SP which owns the other SP with it's impact score (SP*->AppReg->SP*)
                $SpObject.Impact += [math]::Round($OwnedSP.Impact)
                $SpObject.Risk = [math]::Round(($SpObject.Impact * $SpObject.Likelihood))

            }
        }
    }

    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    #Process direct App ownerships (SP->SP) (take over Impact, inherit likelihood)
    $SPOwningSPs = $AllServicePrincipal | Where-Object { $_.SpOwn -ge 1 }
    Write-Log -Level Debug -Message "Number of ownerships SP->SP: $($SPOwningSPs.count)"
    #For each object which owns an App registration
    foreach ($SpOwnerObject in $SPOwningSPs) {

        # For each owned App Registration
        foreach ($OwnedSPObject in $SpOwnerObject.OwnedSPDetails) {

            $OwnedSPObjectDetails = $AllServicePrincipalHT[$OwnedSPObject.Id]
            if ($null -eq $OwnedSPObjectDetails) {
                continue
            }

            # Increment/Recalculate RiskScore of the SP objects which is indirectly owned (SP->SP*)
            $OwnedSPObjectDetails.Likelihood += [math]::Round($SpOwnerObject.Likelihood)
            $OwnedSPObjectDetails.Risk = [math]::Round(($OwnedSPObjectDetails.Impact * $OwnedSPObjectDetails.Likelihood))

            # Append the Message to Warnings of the SP objects which is indirectly owned (SP->SP*)
            $warningMessage = "SP owned by another SP"
            if ($OwnedSPObjectDetails.Warnings -and $OwnedSPObjectDetails.Warnings -notmatch $warningMessage) {
                $OwnedSPObjectDetails.Warnings += " / $warningMessage"
            } else {
                $OwnedSPObjectDetails.Warnings = $warningMessage
            }

            # Increment/Recalculate Impactscore of the SP which owns the other SP with it's impact score (SP*->SP)
            $SpOwnerObject.Impact += [math]::Round($OwnedSPObjectDetails.Impact)
            $SpOwnerObject.Risk = [math]::Round(($SpOwnerObject.Impact * $SpOwnerObject.Likelihood))
            $OwnedSPObject | Add-Member -NotePropertyName Impact -NotePropertyValue $OwnedSPObjectDetails.Impact
            $OwnedSPObject | Add-Member -NotePropertyName Foreign -NotePropertyValue $OwnedSPObjectDetails.Foreign
        }
    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    return $AllServicePrincipalHT
}
