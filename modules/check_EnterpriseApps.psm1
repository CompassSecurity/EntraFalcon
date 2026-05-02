<#
.SYNOPSIS
   Enumerate Enterprise Applications (including: API Permission, Source Tenant, Groups, Roles).

.DESCRIPTION
   This script will enumerate all Enterprise Applications (including: API Permission, Source Tenant, Groups, Roles).
   By default, MS applications are filtered out.
   
#>

function Invoke-CheckEnterpriseApps {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][switch]$IncludeMsApps = $false,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$AllUsersBasicHT,
        [Parameter(Mandatory=$true)][hashtable]$AgentObjectBasics,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$true)][hashtable]$ServicePrincipalSignInActivityLookup,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][ref]$AppRoleReferenceCacheOut = $null,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "EnterpriseApps"
    $ProgressCounter = 0
    $Inactive = $false
    $EnterpriseAppsScriptWarningList = @()
    $AppRegistrations = @{}
    $AppLastSignIns = $ServicePrincipalSignInActivityLookup
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $global:GLOBALUserAppRoles = @{}
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
        "SpWithCredentials"         = 5
        "ForeignApp"                = 30
        "InternApp"                 = 5
        "Owners"          	        = 5
	    "UnknownAppLock"            = 1
        "NoAppLock"                 = 2
        "KnownMaliciousApp"         = 1000
    }

    function Resolve-EnterpriseAppOwner {
        param(
            [Parameter(Mandatory = $true)]$OwnerObject
        )

        # Keep Enterprise App owners on one path while resolving agent-backed owners through the shared typed lookup.
        switch ($OwnerObject.'@odata.type') {
            '#microsoft.graph.servicePrincipal' {
                $targetReport = if ($OwnerObject.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentities' } else { 'EnterpriseApps' }
                return [pscustomobject]@{
                    Id                   = $OwnerObject.Id
                    DisplayName          = $OwnerObject.displayName
                    Enabled              = $OwnerObject.accountEnabled
                    Foreign              = ($OwnerObject.servicePrincipalType -ne 'ManagedIdentity' -and $OwnerObject.appOwnerOrganizationId -ne $CurrentTenant.id)
                    PublisherName        = if ([string]::IsNullOrWhiteSpace($OwnerObject.publisherName)) { "-" } else { $OwnerObject.publisherName }
                    Type                 = if ($OwnerObject.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
                    TargetReport         = $targetReport
                    ServicePrincipalType = $OwnerObject.servicePrincipalType
                }
            }

            '#microsoft.graph.agentIdentity' {
                $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $OwnerObject.Id -RawType '#microsoft.graph.agentIdentity' -CurrentTenant $CurrentTenant -AllUsersBasicHT $AllUsersBasicHT -AllGroupsDetails @{} -ServicePrincipalBasics @{} -AgentObjectBasics $AgentObjectBasics
            }

            '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $OwnerObject.Id -RawType '#microsoft.graph.agentIdentityBlueprintPrincipal' -CurrentTenant $CurrentTenant -AllUsersBasicHT $AllUsersBasicHT -AllGroupsDetails @{} -ServicePrincipalBasics @{} -AgentObjectBasics $AgentObjectBasics
            }

            default {
                return $null
            }
        }

        if (-not $resolvedObject) { return $null }

        return [pscustomobject]@{
            Id                   = $resolvedObject.Id
            DisplayName          = $resolvedObject.DisplayName
            Enabled              = $resolvedObject.Enabled
            Foreign              = $resolvedObject.Foreign
            PublisherName        = $resolvedObject.PublisherName
            Type                 = $resolvedObject.ObjectKind
            TargetReport         = $resolvedObject.TargetReport
            ServicePrincipalType = $resolvedObject.ServicePrincipalType
        }
    }

    function Resolve-EnterpriseAppOwnedAgentObject {
        param(
            [Parameter(Mandatory = $true)]$OwnedObject
        )

        $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $OwnedObject.Id -RawType $OwnedObject.'@odata.type' -CurrentTenant $CurrentTenant -AllUsersBasicHT $AllUsersBasicHT -AllGroupsDetails @{} -ServicePrincipalBasics @{} -AgentObjectBasics $AgentObjectBasics
        if (-not $resolvedObject) { return $null }

        return [pscustomobject]@{
            Id                   = $resolvedObject.Id
            AppId                = if ($resolvedObject.PSObject.Properties.Name -contains 'AppId') { $resolvedObject.AppId } else { $null }
            DisplayName          = $resolvedObject.DisplayName
            Enabled              = $resolvedObject.Enabled
            PublisherName        = $resolvedObject.PublisherName
            Foreign              = $resolvedObject.Foreign
            Type                 = $resolvedObject.ObjectKind
            TargetReport         = $resolvedObject.TargetReport
            ServicePrincipalType = $resolvedObject.ServicePrincipalType
            CreationDate         = if ($resolvedObject.PSObject.Properties.Name -contains 'CreationDate') { $resolvedObject.CreationDate } else { $null }
        }
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Enterprise Apps
    write-host "[*] Get Enterprise Apps"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'Application'"
        '$select' = "Id,DisplayName,PublisherName,accountEnabled,AppRoles,AppId,servicePrincipalType,createdDateTime,signInAudience,AppOwnerOrganizationId,PasswordCredentials,KeyCredentials,AppRoleAssignmentRequired,preferredSingleSignOnMode"
        '$top' = $ApiTop
    }
    $EnterpriseApps = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))

    $EnterpriseAppsCount = $($EnterpriseApps.count)
    write-host "[+] Got $EnterpriseAppsCount Enterprise Applications "

    # Check if Azure IAM role were checked
    if (-not ($GLOBALAzurePsChecks)) {
        if ($GLOBALAzureIamWarningText) {
            $EnterpriseAppsScriptWarningList += $GLOBALAzureIamWarningText
        } else {
            $EnterpriseAppsScriptWarningList += "Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to EnterpriseApps are therefore missing from this report."
        }
    }

    write-host "[*] Build shared app role reference cache"
    $AppRoleReferenceCache = New-AppRoleReferenceCache -ServicePrincipals $EnterpriseApps
    if ($null -ne $AppRoleReferenceCacheOut) {
        $AppRoleReferenceCacheOut.Value = $AppRoleReferenceCache
    }

    # Filter out MS enterprise apps
    if (!$IncludeMsApps) {
        $EnterpriseApps = $EnterpriseApps | where-object {-not($GLOBALMsTenantIds -contains $_.AppOwnerOrganizationId) -and $_.DisplayName -ne "O365 LinkedIn Connection" -and $_.DisplayName -ne "P2P Server"} | select-object Id,'@odata.type',DisplayName,accountEnabled,PublisherName,AppRoles,AppId,servicePrincipalType,createdDateTime,signInAudience,AppOwnerOrganizationId,PasswordCredentials,KeyCredentials,AppRoleAssignmentRequired,preferredSingleSignOnMode
        $EnterpriseAppsCount = $($EnterpriseApps.count)
        write-host "[i] Filtered out Microsoft Applications. $EnterpriseAppsCount left (use -IncludeMsApps to include them)"
    } else {
        #Add information to the enumeration summary
        $GlobalAuditSummary.EnterpriseApps.IncludeMsApps = $true
    }

    # Filter out Agent Identity Blueprint Principals (Agent Identities are already excluded through the filter "ServicePrincipalType eq 'Application'")
    $EnterpriseApps = @($EnterpriseApps | Where-Object {$_.'@odata.type' -ne '#microsoft.graph.agentIdentityBlueprintPrincipal'})
    $FilteredAgentIdentityBlueprintPrincipalsCount = $EnterpriseAppsCount - $EnterpriseApps.count
        if ($FilteredAgentIdentityBlueprintPrincipalsCount -gt 0) {
        $EnterpriseAppsCount = $($EnterpriseApps.count)
        Write-Log -Level Verbose -Message "Filtered out $FilteredAgentIdentityBlueprintPrincipalsCount agent identity blueprint principals from Enterprise Apps."
    }

    #Abort if no apps are present
    if (@($EnterpriseApps).count -eq 0) {
        $AllServicePrincipalHT = @{}
        Return $AllServicePrincipalHT
    }

    write-host "[*] Get App Registrations for lookups"
    $QueryParameters = @{
        '$select' = "id,AppId,ServicePrincipalLockConfiguration"
    }
    $AllAppRegistrations = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($app in $AllAppRegistrations) {
        $AppRegistrations[$app.AppId] = @{
            id = $app.id
            ServicePrincipalLockConfiguration = $app.ServicePrincipalLockConfiguration
        }
    }
    Write-Log -Level Debug -Message "Got $($AppRegistrations.Count) app registrations"

    Write-Log -Level Debug -Message "Using $($AppLastSignIns.Count) cached app last sign-in dates"

    Write-Host "[*] Get all applications API permissions assignments"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
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

    Write-Host "[*] Get all delegated API permissions"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
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

    Write-Host "[*] Get all applications group memberships"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
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

    Write-Host "[*] Get all application object ownerships"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
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
    $EnterpriseApps | ForEach-Object {
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

    Write-Host "[*] Get all app role assignments"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
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

    ########################################## SECTION: Enterprise App Processing ##########################################




    #Enumerate all AppRoles configured (only of the apps in scope)
    $AppRoles = [System.Collections.ArrayList]::new()
    
    foreach ($app in $EnterpriseApps) {
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
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($EnterpriseAppsCount / 10), 1)
    if ($EnterpriseAppsCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing app 1 of $EnterpriseAppsCount (updates every $StatusUpdateInterval apps)..."
    }

    #region Processing Loop
    #Loop through each enterprise app, retrieve additional info, and store it in a custom object
    foreach ($item in $EnterpriseApps) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = 0
        $warnings = @()
        $WarningsHighPermission = $null
        $WarningsDangerousPermission = $null
        $WarningsMediumPermission = $null
        $KnownMaliciousApp = $null
        $AppCredentials = @()
        $OwnerUserDetails = @()
        $OwnerSPDetails = @()
        $AppRegObjectId = ""
        

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $EnterpriseAppsCount) {
            Write-Host "[*] Status: Processing app $ProgressCounter of $EnterpriseAppsCount..."
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
        $EntraRolesDirect = @($AppEntraRoles).Count
        $AzureRolesDirect = 0
        [void][int]::TryParse([string]$AzureRoleCount, [ref]$AzureRolesDirect)
        $EntraRolesThroughGroupMembership = 0
        $EntraRolesThroughGroupOwnership = 0
        $AzureRolesThroughGroupMembership = 0
        $AzureRolesThroughGroupOwnership = 0

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
        $OwnedBlueprints = [System.Collections.ArrayList]::new()
        $OwnedBlueprintPrincipals = [System.Collections.ArrayList]::new()
        $OwnedAgentIdentities = [System.Collections.ArrayList]::new()
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

                    '#microsoft.graph.agentIdentityBlueprint' {
                        $resolvedOwnedObject = Resolve-EnterpriseAppOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedBlueprints.Add($resolvedOwnedObject)
                        }
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        $resolvedOwnedObject = Resolve-EnterpriseAppOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedBlueprintPrincipals.Add($resolvedOwnedObject)
                        }
                    }

                    '#microsoft.graph.agentIdentity' {
                        $resolvedOwnedObject = Resolve-EnterpriseAppOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedAgentIdentities.Add($resolvedOwnedObject)
                        }
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
        $OwnedBlueprintsCount = $OwnedBlueprints.count
        $OwnedSPCount = $OwnedSP.count
    

        #Check if sp has configured credentials
        $AppCredentialsSecrets = foreach ($creds in $item.PasswordCredentials) {
            [pscustomobject]@{
                Type = "Secret"
                DisplayName = if ([string]::IsNullOrWhiteSpace($creds.DisplayName)) { "-" } else { $creds.DisplayName }
                Id = $creds.KeyId
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
            }
        }
        $AppCredentialsCertificates = foreach ($creds in $item.KeyCredentials) {
            [pscustomobject]@{
                Type = "Certificate"
                DisplayName = if ([string]::IsNullOrWhiteSpace($creds.DisplayName)) { "-" } else { $creds.DisplayName }
                Id = $creds.KeyId
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
            }
        }
        $AppCredentials += $AppCredentialsSecrets
        $AppCredentials += $AppCredentialsCertificates

        #Process Last sign-in date for each App
        if ($AppLastSignIns.ContainsKey($item.AppId)) {
            $AppsignInData = $AppLastSignIns[$item.AppId]
        } else {
            $AppsignInData = $Null
        }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
    
    
        # Check if it the Entra Connect Sync App
        if ($item.DisplayName -match "ConnectSyncProvisioning_") {
            $Warnings += "Entra Connect Sync Application!"
        }

        # Check if the SP has credentials defined
        $AppCredentialsCount = ($AppCredentials | Measure-Object).count
        if ($AppCredentialsCount -ge 1) {
            $Warnings += "SP with credentials!"
            $LikelihoodScore += $SPLikelihoodScore["SpWithCredentials"]
        }

        #Check if it is an SP of a foreign tenant
        if ($item.AppOwnerOrganizationId -eq $($CurrentTenant).id) {
            $ForeignTenant = $false

            #If not set corresponding SP object ID
            $AppRegObjectId = $AppRegistrations[$($item.AppId)].id
            
        } else {
            $ForeignTenant = $true
        }

        $KnownMaliciousApp = Get-KnownMaliciousEnterpriseApp -AppId $item.AppId
        if ($null -ne $KnownMaliciousApp) {
            $Warnings += "Known malicious application!"
            $LikelihoodScore += $SPLikelihoodScore["KnownMaliciousApp"]
        }

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
                        $resolvedOwner = Resolve-EnterpriseAppOwner -OwnerObject $OwnedObject
                        if ($resolvedOwner) {
                            [void]$OwnerSPDetails.Add($resolvedOwner)
                        }
                    }

                    '#microsoft.graph.agentIdentity' {
                        $resolvedOwner = Resolve-EnterpriseAppOwner -OwnerObject $OwnedObject
                        if ($resolvedOwner) {
                            [void]$OwnerSPDetails.Add($resolvedOwner)
                        }
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        $resolvedOwner = Resolve-EnterpriseAppOwner -OwnerObject $OwnedObject
                        if ($resolvedOwner) {
                            [void]$OwnerSPDetails.Add($resolvedOwner)
                        }
                    }
                }
            }
        }
        
        $OwnersCount = $OwnerUserDetails.count + $OwnerSPDetails.count
        #Check owners of the SP.
        if ($OwnersCount -ge 1) {

            #Check if SP is protected by app instance locking
            #Cannot be checked for foreign apps
            if ($ForeignTenant) {
                $LikelihoodScore += $SPLikelihoodScore["UnknownAppLock"]
                $Warnings += "SP with owner (unknown AppLock)!"
            } else {
                $AppLockConfiguration = $AppRegistrations[$($item.AppId)].ServicePrincipalLockConfiguration
                
                #App instance property lock can be completely disabled or more granular
                if ($AppLockConfiguration.IsEnabled -ne $true -or ($AppLockConfiguration.AllProperties -ne $true -and $AppLockConfiguration.credentialsWithUsageVerify -ne $true)) {
                    $LikelihoodScore += $SPLikelihoodScore["NoAppLock"]
                    $Warnings += "SP with owner and no AppLock!"
                } else {
                    $Warnings += "SP with owner but app protected by AppLock!"
                }
            }
        }

        if (($OwnerSPDetails | Measure-Object).count -ge 1) {
            if ($OwnerSPDetails.Foreign -contains $true) {
                $Warnings += "Foreign non-user owner!"
            } elseif ($OwnerSPDetails.Foreign -contains $false) {
                $Warnings += "Internal non-user owner"
            }
        }
            
        #Increase likelihood for each owner (user) SP ownership is calculated in the post-processing part
        $LikelihoodScore += $OwnerUserDetails.count * $SPLikelihoodScore["Owners"] 

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

        #If SP owns Agent Identity Blueprint
        if ($OwnedBlueprintsCount -ge 1) {
            $Warnings += "SP owns $OwnedBlueprintsCount Agent Identity Blueprint(s)!"
        }

        #If SP owns another SP
        if ($OwnedSPCount -ge 1) {
            $Warnings += "SP owns $OwnedSPCount Enterprise Applications!" 
        }
        

        #Check if it is one of the MS default SPs
        if ($GLOBALMsTenantIds -contains $item.AppOwnerOrganizationId -or $item.DisplayName -eq "O365 LinkedIn Connection" -and $item.DisplayName -ne "P2P Server") {  
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
            $EntraRolesThroughGroupMembership = $TotalAssignedRoleCount
            if ($GLOBALAzurePsChecks) {
                $AzureRolesThroughGroupMembership = $TotalAzureRoles
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
                    # Ownership inherits the group's full impact (active + eligible role paths).
                    $groupInheritedImpact = 0
                    if (-not [int]::TryParse([string]$OwnedGroup.Impact, [ref]$groupInheritedImpact)) {
                        [void][int]::TryParse([string]$OwnedGroup.ImpactOrg, [ref]$groupInheritedImpact)
                    }
                    $ImpactScore += $groupInheritedImpact

                    $entraMetrics = Get-GroupActiveRoleMetrics -Group $OwnedGroup -RoleSystem Entra -IncludeEligible
                    $TotalAssignedRoleCount += $entraMetrics.RoleCount
                    $TotalAssignedPrivilegedRoles += $entraMetrics.PrivilegedCount

                    $groupAzureRoleCount = 0
                    if ($GLOBALAzurePsChecks) {
                        $azureMetrics = Get-GroupActiveRoleMetrics -Group $OwnedGroup -RoleSystem Azure -IncludeEligible
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
                $EntraRolesThroughGroupOwnership = $TotalAssignedRoleCount
                if ($GLOBALAzurePsChecks) {
                    $AzureRolesThroughGroupOwnership = $TotalAzureRoles
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
                    "Dangerous" {$ImpactScore += $SPImpactScore["APIDangerous"]; $WarningsDangerousPermission = $true ; Break}
                    "High" {$ImpactScore += $SPImpactScore["APIHigh"]; $WarningsHighPermission = $true; Break}
                    "Medium" {$ImpactScore += $SPImpactScore["APIMedium"]; if ($ForeignTenant) { $WarningsMediumPermission = $true }; Break}
                    "Low" {$ImpactScore += $SPImpactScore["APILow"]; Break}
                    "Uncategorized" {$ImpactScore += $SPImpactScore["ApiMisc"]; Break}
                }
            }
        }

        # Build the warning parts dynamically
        [string[]]$severities = @()
        if ($WarningsDangerousPermission) { $severities += "dangerous" }
        if ($WarningsHighPermission)      { $severities += "high" }
        if ($WarningsMediumPermission)    { $severities += "medium" }

        $severities = $severities | Select-Object -Unique

        # Generate joined warning
        if ($severities.Count -gt 0) {
            $lastIndex = $severities.Count - 1
            $last = $severities[$lastIndex]
            
            if ($severities.Count -gt 1) {
                $first = $severities[0..($lastIndex - 1)] -join ", "
                $joined = "$first and $last"
            } else {
                $joined = "$last"
            }

            $plural = ""
            if ($severities.Count -gt 1) { $plural = "s" }

            $Warnings += "Known $joined API permission$plural!"
        }

        #Check if app is inactive
        if ($AppsignInData.lastSignInDays -ge 180 -or $AppsignInData.lastSignInDays -eq "-" -or $Null -eq $AppsignInData) {
            $Inactive = $true
        } else {
            $Inactive = $false
        }

        #Process Delegated API permission. Only increase the score once (independet of how many principal or how many of each category are assigned)
        if ($DelegatedPermissionDetailsUnique -ge 1) {

            if ($DelegateApiPermssionCount.Dangerous -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedDangerous"]
                $WarningsDangerousDelegatedPermission = $true
            } else {
                $WarningsDangerousDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.High -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedHigh"]
                $WarningsHighDelegatedPermission = $true
            } else {
                $WarningsHighDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.Medium -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedMedium"]
                #Show warnings only for foreign apps
                if ($ForeignTenant) {
                    $WarningsMediumDelegatedPermission = $true
                }
            } else {
                $WarningsMediumDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.Low -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedLow"]
            }
            if ($DelegateApiPermssionCount.Uncategorized -ge 1) {
                $ImpactScore += $SPImpactScore["ApiDelegatedMisc"]
            }

            # Build the warning parts dynamically
            [string[]]$severities = @()
            if ($WarningsDangerousDelegatedPermission) { $severities += "dangerous" }
            if ($WarningsHighDelegatedPermission)      { $severities += "high" }
            if ($WarningsMediumDelegatedPermission)    { $severities += "medium" }
            $severities = $severities | Select-Object -Unique

            # Generate joined warning for delegate permissions
            if ($severities.Count -gt 0) {
                $lastIndex = $severities.Count - 1
                $last = $severities[$lastIndex]
                
                if ($severities.Count -gt 1) {
                    $first = $severities[0..($lastIndex - 1)] -join ", "
                    $joined = "$first and $last"
                } else {
                    $joined = "$last"
                }
                $plural = ""
                if ($severities.Count -gt 1) { $plural = "s" }
                $Warnings += "Known $joined delegated API permission$plural!"
            }
        }

        #Mark foreign non-default apps as risky
        if ($DefaultMS -eq $false -and $ForeignTenant -eq $true) {
            $LikelihoodScore += $SPLikelihoodScore["ForeignApp"]
        } elseif ($DefaultMS -eq $false -and $ForeignTenant -eq $false) {
            $LikelihoodScore += $SPLikelihoodScore["InternApp"]
        }


        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        if ($AppsignInData.lastSignInDays) {
            $LastSignInDays = $AppsignInData.lastSignInDays
        } else {
            $LastSignInDays = "-"
        }
        $EntraRolesEffective = $EntraRolesDirect + $EntraRolesThroughGroupMembership + $EntraRolesThroughGroupOwnership
        $AzureRolesEffective = $AzureRolesDirect + $AzureRolesThroughGroupMembership + $AzureRolesThroughGroupOwnership

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
            EntraRolesDirect = $EntraRolesDirect
            EntraRolesEffective = $EntraRolesEffective
            EntraRoles = $EntraRolesEffective
            EntraMaxTier = $EntraMaxTier
            PermissionCount = ($AppAssignments | Measure-Object).count
            GrpOwn = ($OwnedGroups | Measure-Object).count
            AppOwn = $OwnedApplicationsCount
            BlueprintOwn = $OwnedBlueprintsCount
            OwnedApplicationsDetails = $OwnedApplications
            OwnedBlueprintsDetails = $OwnedBlueprints
            OwnedBlueprintPrincipalsDetails = $OwnedBlueprintPrincipals
            OwnedAgentIdentitiesDetails = $OwnedAgentIdentities
            SpOwn = $OwnedSPCount
            OwnedSPDetails = $OwnedSP
            GroupMember = $GroupMember
            AppOwnerOrganizationId = $item.AppOwnerOrganizationId
            EntraRoleDetails = $AppEntraRoles
            GroupOwner = $OwnedGroups
            AppPermission = $AppAssignments
            Foreign = $ForeignTenant
            DefaultMS = $DefaultMS
            AzureRolesDirect = $AzureRolesDirect
            AzureRolesEffective = $AzureRolesEffective
            AzureRoles = $AzureRolesEffective
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
            AppRegObjectId = $AppRegObjectId
            AppRoleRequired = $item.AppRoleAssignmentRequired
            SAML = ($item.preferredSingleSignOnMode -eq "saml")
            Credentials = $AppCredentialsCount
            AppCredentialsDetails = $AppCredentials
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
            KnownMaliciousApplication = ($null -ne $KnownMaliciousApp)
            KnownMaliciousSourceUrl = $KnownMaliciousApp
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

    #Process direct App ownerships (SP->SP) (take over Impact, inherit likelihood)
    $SPOwningSPs = $AllServicePrincipal | Where-Object { $_.SpOwn -ge 1 }
    Write-Log -Level Debug -Message "Number of ownerships SP->SP: $($SPOwningSPs.count)"
    #For each object which owns an App registration
    foreach ($SpOwnerObject in $SPOwningSPs) {
        
        # For each owned App Registration
        foreach ($OwnedSPObject in $SpOwnerObject.OwnedSPDetails) {

            # Get the details of the owned SP by looping over matching objects
            foreach ($OwnedSPObjectDetails in $AllServicePrincipal | Where-Object { $_.id -eq $OwnedSPObject.id }) {

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
    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"

    #Define output of the main table
    $tableOutput = $AllServicePrincipal | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,SAML,LastSignInDays,CreationInDays,AppRoles,GrpMem,GrpOwn,AppOwn,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,Owners,Credentials,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,Impact,Likelihood,Risk,Warnings
    
    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllServicePrincipal | Sort-Object Risk -Descending

    #Convert to Hashtable for faster searches and use for lookups in the details section
    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    #Enum the details for the apps in scope
    foreach ($item in $details) {

        $ReportingEntAppInfo = @()
        $ReportingRoles = @()
        $ReportingAzureRoles = @()
        $ReportingGroupOwner = @()
        $ReportingAppOwner = @()
        $ReportingBlueprintOwner = @()
        $ReportingBlueprintPrincipalOwner = @()
        $ReportingAgentIdentityOwner = @()
        $ReportingSPOwner = @()
        $ReportingGroupMember = @()
        $ReportingCredentials = @()
        $ReportingAppRoles = @()
        $ReportingAppOwnersUser = @()
        $ReportingAppOwnersSP = @()
        $ReportingAPIPermission = @()
        $ReportingDelegatedApiPermission = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        ############### HEADER
        $ReportingEntAppInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "Publisher Name" = $($item.PublisherName)
            "Publisher TenantId" = $($item.AppOwnerOrganizationId)
            "Enabled" = $($item.Enabled)
            "CreationDate" = $($item.CreationDate)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "MS Default" = $($item.DefaultMS)
            "Foreign" = $($item.Foreign)
            "Require AppRole" = $($item.AppRoleRequired)
            "SAML" = $($item.SAML)
            "RiskScore" = $($item.Risk)
        }
        #If it is not a foreign app, add the link to the appreg
        if (-not $item.Foreign) {
            $ReportingEntAppInfo | Add-Member -NotePropertyName AppRegistration -NotePropertyValue "<a href=AppRegistration_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($item.AppRegObjectId)>$($item.DisplayName)</a>"
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","Publisher Name","Publisher TenantId","Enabled", "App Client-ID","App Object-ID","MS Default","Foreign","Require AppRole","SAML","RiskScore")

        if ($item.KnownMaliciousApplication) {
            $ReportingEntAppInfo | Add-Member -NotePropertyName "Known Malicious Application" -NotePropertyValue $true
            if (-not [string]::IsNullOrWhiteSpace($item.KnownMaliciousSourceUrl)) {
                $ReportingEntAppInfo | Add-Member -NotePropertyName "Malicious App Source" -NotePropertyValue "<a href=`"$($item.KnownMaliciousSourceUrl)`" target=`"_blank`">$($item.KnownMaliciousSourceUrl)</a>"
            }
            $TxtReportProps += "Known Malicious Application"
            if ($ReportingEntAppInfo.PSObject.Properties.Name -contains "Malicious App Source") {
                $TxtReportProps += "Malicious App Source"
            }
        }

        if ($item.Warnings -ne '') {
            $ReportingEntAppInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingEntAppInfo| Select-Object $TxtReportProps | Out-String))
       
        ############### Last Sing-Ins
        $lastSignIn = if ($($item.AppsignInData.lastSignIn) -and $($item.AppsignInData.lastSignIn) -ne "-") {"$($item.AppsignInData.lastSignIn) ($($item.AppsignInData.lastSignInDays) days ago)"} else {"-"}
        $lastSignInAppAsClient = if ($($item.AppsignInData.lastSignInAppAsClient) -and $($item.AppsignInData.lastSignInAppAsClient) -ne "-") {"$($item.AppsignInData.lastSignInAppAsClient) ($($item.AppsignInData.lastSignInAppAsClientDays) days ago)"} else {"-"}
        $lastSignInAppAsResource = if ($($item.AppsignInData.lastSignInAppAsResource) -and $($item.AppsignInData.lastSignInAppAsResource) -ne "-") {"$($item.AppsignInData.lastSignInAppAsResource) ($($item.AppsignInData.lastSignInAppAsResourceDays) days ago)"} else {"-"}
        $lastSignInDelegatedAsClient = if ($($item.AppsignInData.lastSignInDelegatedAsClient) -and $($item.AppsignInData.lastSignInDelegatedAsClient) -ne "-") {"$($item.AppsignInData.lastSignInDelegatedAsClient) ($($item.AppsignInData.lastSignInDelegatedAsClientDays) days ago)"} else {"-"}
        $lastSignInDelegatedAsResource = if ($($item.AppsignInData.lastSignInDelegatedAsResource) -and $($item.AppsignInData.lastSignInDelegatedAsResource) -ne "-") {"$($item.AppsignInData.lastSignInDelegatedAsResource) ($($item.AppsignInData.lastSignInDelegatedAsResourceDays) days ago)"} else {"-"}
        $ReportingLastSignIns = [pscustomobject]@{
            "Last sign-in overall" = $lastSignIn
            "Last sign-in as application (client)" = $lastSignInAppAsClient
            "Last sign-in as application (resource)" = $lastSignInAppAsResource
            "Last sign-in delegated (client)" = $lastSignInDelegatedAsClient
            "Last sign-in delegated (resource)" = $lastSignInDelegatedAsResource 
        }           
        [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
        [void]$DetailTxtBuilder.AppendLine("Last Sign-Ins Details")
        [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in overall: $lastSignIn")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in as application (client): $lastSignInAppAsClient")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in as application (resource): $lastSignInAppAsResource")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in delegated (client): $lastSignInDelegatedAsClient")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in delegated (resource): $lastSignInDelegatedAsResource ")
        [void]$DetailTxtBuilder.AppendLine("")


        ############### Entra Roles
        if ($($item.EntraRoleDetails | Measure-Object).count -ge 1) {
            $ReportingRoles = foreach ($object in $($item.EntraRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($object.DisplayName)
                    "Tier Level" = $($object.RoleTier)
                    "Privileged" = $($object.isPrivileged)
                    "IsBuiltin" = $($object.IsBuiltin)
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Active Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | format-table | Out-String))
        }
    

        ############### Azure Roles
        if ($($item.AzureRoleDetails | Measure-Object).count -ge 1) {
            $ReportingAzureRoles = foreach ($object in $($item.AzureRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($object.RoleName)
                    "RoleType" = $($object.RoleType)
                    "Tier Level" = $($object.RoleTier)
                    "Conditions" = $($object.Conditions)
                    "Scoped to" = $($object.Scope)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | format-table | Out-String))
        }


        ############### Group Owner
        if ($($item.GroupOwner | Measure-Object).count -ge 1) {
            $ReportingGroupOwner = foreach ($object in $($item.GroupOwner)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "RoleAssignable" = $($object.RoleAssignable)
                    "EntraRoles" = $($object.AssignedRoleCount)
                    "AzureRoles" = $($object.AzureRoles)
                    "CAPs" = $($object.CAPs)
                    "ImpactOrg" = $($object.ImpactOrg)
                    "Warnings" = $($object.Warnings)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owner of Groups")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupOwner | Format-Table DisplayName,SecurityEnabled,RoleAssignable,EntraRoles,AzureRoles,CAPs,ImpactOrg,Warnings -AutoSize | Out-String -Width 200))
            $ReportingGroupOwner  = foreach ($obj in $ReportingGroupOwner) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SecurityEnabled         = $obj.SecurityEnabled
                    RoleAssignable          = $obj.RoleAssignable
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    CAPs                    = $obj.CAPs
                    ImpactOrg               = $obj.ImpactOrg
                    Warnings                = $obj.Warnings
                }
            }
        } 

        ############### App owner
        if ($($item.OwnedApplicationsDetails | Measure-Object).count -ge 1) {
            $ReportingAppOwner = foreach ($object in $($item.OwnedApplicationsDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=AppRegistration_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned App Registrations")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwner | Format-Table DisplayName | Out-String))
            $ReportingAppOwner = foreach ($obj in $ReportingAppOwner) {
                [pscustomobject]@{
                    DisplayName        = $obj.DisplayNameLink
                }
            }
        }

        if ($($item.OwnedBlueprintsDetails | Measure-Object).count -ge 1) {
            $ReportingBlueprintOwner = foreach ($object in $($item.OwnedBlueprintsDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=AgentIdentityBlueprints_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    "Enabled" = $(if ($null -eq $object.Enabled) { "-" } else { $object.Enabled })
                    "Created" = $(if ($null -ne $object.CreationDate) { $object.CreationDate.ToString() } else { "-" })
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Blueprints")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingBlueprintOwner | Format-Table DisplayName,Enabled,Created | Out-String))
            $ReportingBlueprintOwner = foreach ($obj in $ReportingBlueprintOwner) {
                [pscustomobject]@{
                    DisplayName = $obj.DisplayNameLink
                    Enabled     = $obj.Enabled
                    Created     = $obj.Created
                }
            }
        }

        if ($($item.OwnedBlueprintPrincipalsDetails | Measure-Object).count -ge 1) {
            $ReportingBlueprintPrincipalOwner = foreach ($object in $($item.OwnedBlueprintPrincipalsDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    "Enabled" = $($object.Enabled)
                    "PublisherName" = $($object.PublisherName)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Blueprint Principals")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingBlueprintPrincipalOwner | Format-Table DisplayName,Enabled,PublisherName | Out-String))
            $ReportingBlueprintPrincipalOwner = foreach ($obj in $ReportingBlueprintPrincipalOwner) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Enabled       = $obj.Enabled
                    PublisherName = $obj.PublisherName
                }
            }
        }

        if ($($item.OwnedAgentIdentitiesDetails | Measure-Object).count -ge 1) {
            $ReportingAgentIdentityOwner = foreach ($object in $($item.OwnedAgentIdentitiesDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    "Enabled" = $($object.Enabled)
                    "PublisherName" = $($object.PublisherName)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Agent Identities")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAgentIdentityOwner | Format-Table DisplayName,Enabled,PublisherName | Out-String))
            $ReportingAgentIdentityOwner = foreach ($obj in $ReportingAgentIdentityOwner) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Enabled       = $obj.Enabled
                    PublisherName = $obj.PublisherName
                }
            }
        }

        ############### SP owner
        if ($($item.OwnedSPDetails | Measure-Object).count -ge 1) {
            $ReportingSPOwner = foreach ($object in $($item.OwnedSPDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($object.DisplayName)</a>"
                    "Foreign" = $($object.Foreign)                    
                    "Impact" = $($object.Impact)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Enterprise Applications")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingSPOwner | Format-Table DisplayName,Foreign,Impact | Out-String))
            $ReportingSPOwner = foreach ($obj in $ReportingSPOwner) {
                [pscustomobject]@{
                    DisplayName     = $obj.DisplayNameLink
                    Foreign          =$obj.Foreign
                    Impact          = $obj.Impact
                }
            }
        }
        
        ############### Group Member
        if ($($item.GroupMember | Measure-Object).count -ge 1) {
            $ReportingGroupMember = foreach ($object in $($item.GroupMember)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "RoleAssignable" = $($object.RoleAssignable)
                    "EntraRoles" = $($object.AssignedRoleCount)
                    "AzureRoles" = $($object.AzureRoles)
                    "CAPs" = $($object.CAPs)
                    "ImpactOrgActiveOnly" = $($object.ImpactOrgActiveOnly)
                    "Warnings" = $($object.Warnings)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Member in Groups (transitive)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupMember | Format-Table DisplayName,SecurityEnabled,RoleAssignable,EntraRoles,AzureRoles,CAPs,ImpactOrgActiveOnly,Warnings | Out-String))
            $ReportingGroupMember  = foreach ($obj in $ReportingGroupMember) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SecurityEnabled         = $obj.SecurityEnabled
                    RoleAssignable          = $obj.RoleAssignable
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    CAPs                    = $obj.CAPs
                    "Impact (No Eligible)"  = $obj.ImpactOrgActiveOnly
                    Warnings                = $obj.Warnings
                }
            }
        } 

        ############### Enterprise Application Credentials
        if ($($item.AppCredentialsDetails | Measure-Object).count -ge 1) {
            $ReportingCredentials = foreach ($object in $($item.AppCredentialsDetails)) {
                [pscustomobject]@{ 
                    "Type" = $($object.Type)
                    "DisplayName" = $($object.DisplayName)
                    "StartDateTime" = $(if ($null -ne $object.StartDateTime) { $object.StartDateTime.ToString() } else { "-" })
                    "EndDateTime" = $(if ($null -ne $object.EndDateTime) { $object.EndDateTime.ToString() } else { "-" })
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Enterprise Application Credentials")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String))
        } 

        ############### App Roles
        if ($($item.AppRolesDetails | Measure-Object).count -ge 1) {
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                # Build link for HTML report based on the object type
                switch ($object.AppRoleAssignmentType) {
                    'User' {
                        $AppRoleMemberLink = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.AppRoleMemberId)>$($object.AppRoleMember)</a>"
                        break
                    }
                    'Group' {
                        $AppRoleMemberLink = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.AppRoleMemberId)>$($object.AppRoleMember)</a>"
                        break
                    }
                    'ServicePrincipal' {
                        #Only add the link if the SP exist in this report
                        if ($AllServicePrincipalHT.ContainsKey($object.AppRoleMemberId)) {
                            $AppRoleMemberLink = "<a href=#$($object.AppRoleMemberId)>$($object.AppRoleMember)</a>"
                        } else {
                            $AppRoleMemberLink = $object.AppRoleMember
                        }
                        break
                    }
                    Default {
                        $AppRoleMemberLink = $object.AppRoleMember
                        Write-Log -Level Debug -Message "Unknown AppRoleAssignmentType: $($object.AppRoleAssignmentType) / object: $($object.AppRoleMemberId)"
                    }
                }
                [pscustomobject]@{ 
                    "AppRoleClaim" = $($object.AppRoleClaim)
                    "AppRoleName" = $($object.AppRoleName)
                    "RoleEnabled" = $($object.RoleEnabled)
                    "AppRoleAssignmentType" = $($object.AppRoleAssignmentType)
                    "AppRoleMember" = $($object.AppRoleMember)
                    "AppRoleMemberLink" = $AppRoleMemberLink
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Assigned App Roles")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | format-table -Property AppRoleName,RoleEnabled,AppRoleAssignmentType,AppRoleMember | Out-String))
            
            #Rebuild for HTML report
            $ReportingAppRoles = foreach ($obj in $ReportingAppRoles) {
                [pscustomobject]@{
                    Claim            = $obj.AppRoleClaim
                    Name             = $obj.AppRoleName
                    RoleEnabled      = $obj.RoleEnabled
                    AssignmentType   = $obj.AppRoleAssignmentType
                    Member           = $obj.AppRoleMemberLink
                }
            }
        }

        ############### Owners of the SP Object
        if ($($item.OwnerUserDetails | Measure-Object).count -ge 1 -or $($item.OwnerSPDetails | Measure-Object).count -ge 1) {
            if ($($item.OwnerUserDetails | Measure-Object).count -ge 1) {
                $ReportingAppOwnersUser = foreach ($object in $($item.OwnerUserDetails)) {
                    [pscustomobject]@{ 
                        "UPN" = $($object.UPN)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.UPN)</a>"
                        "Enabled" = $($object.Enabled)
                        "Type" = $($object.Type)
                        "OnPremSync" = $($object.OnPremSync)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.JobTitle)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Users)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersUser | format-table -Property UPN,Enabled,Type,OnPremSync,Department,JobTitle | Out-String))
                
                #Rebuild for HTML report
                $ReportingAppOwnersUser = foreach ($obj in $ReportingAppOwnersUser) {
                    [pscustomobject]@{
                        UserName        = $obj.UPNLink
                        Enabled         = $obj.Enabled
                        Type            = $obj.Type
                        OnPremSync      = $obj.OnPremSync
                        Department      = $obj.Department
                        JobTitle        = $obj.JobTitle
                    }
                }
            }

            if ($($item.OwnerSPDetails | Measure-Object).count -ge 1) {
                $ReportingAppOwnersSP = foreach ($object in $($item.OwnerSPDetails)) {
                    # Route mixed non-user owners to the correct report based on the normalized target report.
                    $displayNameLink = switch ($object.TargetReport) {
                        'AgentIdentities' { "<a href=AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                        'AgentIdentityBlueprintsPrincipals' { "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                        'ManagedIdentities' { "<a href=ManagedIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                        default { "<a href=#$($object.id)>$($object.DisplayName)</a>" }
                    }
                    [pscustomobject]@{ 
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = $displayNameLink
                        "Enabled" = $($object.Enabled)
                        "PublisherName" = $($object.PublisherName)
                        "ServicePrincipalType" = $(if ($object.Type -eq 'ServicePrincipal' -or $object.Type -eq 'ManagedIdentity') { $object.ServicePrincipalType } else { $object.Type })
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Service Principals / Agent Objects)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersSP | format-table -Property DisplayName,Enabled,PublisherName,ServicePrincipalType | Out-String))
                $ReportingAppOwnersSP = foreach ($obj in $ReportingAppOwnersSP) {
                    [pscustomobject]@{
                        DisplayName             = $obj.DisplayNameLink
                        Enabled                 = $obj.Enabled
                        PublisherName           = $obj.PublisherName
                        ServicePrincipalType    = $obj.ServicePrincipalType
                    }
                }
            }
        }   

        ############### API permission
        if ($($item.AppApiPermission | Measure-Object).count -ge 1) {
            $ReportingAPIPermission = foreach ($object in $($item.AppApiPermission)) {
                [pscustomobject]@{ 
                    "API" = $($object.ApiName)
                    "Category" = $($object.ApiPermissionCategorization)
                    "Permission" = $($object.ApiPermission)
                    "Short Description" = $($object.ApiPermissionDisplayname)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Application)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAPIPermission | Out-String))
        } 


        ############### API Delegated Permissions
        if ($($item.ApiDelegatedDetails | Measure-Object).count -ge 1) {

            $ReportingDelegatedApiPermission = foreach ($object in $($item.ApiDelegatedDetails)) {
                
                $userDetails = $AllUsersBasicHT[$object.Principal]
                
                # Check if a matching user was found
                if ($userDetails) {
                    $PrincipalUpn = $userDetails.UserPrincipalName
                    $PrincipalUpnLink = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Principal)>$($PrincipalUpn)</a>"
                } else {
                    # Handle the case where no match was found
                    $PrincipalUpn = $object.Principal
                    $PrincipalUpnLink = $object.Principal
                }

                [pscustomobject]@{ 
                    "APIName" = $object.APIName
                    "Permission" = $object.Scope
                    "Categorization" = $object.ApiPermissionCategorization
                    "ConsentType" = $object.ConsentType
                    "Principal" = $PrincipalUpn
                    "PrincipalLink" = $PrincipalUpnLink
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Delegated)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingDelegatedApiPermission | format-table APIName,Permission,Categorization,ConsentType,Principal | Out-String))

            $ReportingDelegatedApiPermission = foreach ($obj in $ReportingDelegatedApiPermission) {
              [pscustomobject]@{ 
                    "APIName" = $obj.APIName
                    "Permission" = $obj.Permission
                    "Categorization" = $obj.Categorization
                    "ConsentType" = $obj.ConsentType
                    "Principal" = $obj.PrincipalLink
                }
            }

        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information" = $ReportingEntAppInfo
            "Last Sign-Ins Details" = $ReportingLastSignIns
            "Active Entra Role Assignments" = $ReportingRoles
            "Azure IAM assignments" = $ReportingAzureRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owned App Registrations" = $ReportingAppOwner
            "Owned Blueprints" = $ReportingBlueprintOwner
            "Owned Blueprint Principals" = $ReportingBlueprintPrincipalOwner
            "Owned Agent Identities" = $ReportingAgentIdentityOwner
            "Owned Enterprise Applications" = $ReportingSPOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Enterprise Application Credentials" = $ReportingCredentials
            "Assigned App Roles" = $ReportingAppRoles
            "Owners (Users)" = $ReportingAppOwnersUser
            "Owners (Service Principals)" = $ReportingAppOwnersSP
            "API Permission (Application)" = $ReportingAPIPermission
            "API Permission (Delegated)" = $ReportingDelegatedApiPermission
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()
    
    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,SAML,LastSignInDays,CreationInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Enterprise Applications Details</h2>
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

#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($EnterpriseAppsScriptWarningList -join ' / ')
************************************************************************************************************************
"

#Define Appendix
$AppendixHeaderTXT = "

=======================================================================================================================
Appendix: Used API Permission Reference
=======================================================================================================================
"

    # Create and sort the permission appendix
    $ApiPermissionReference =
        $details |
        Select-Object -ExpandProperty AppApiPermission |
        Select-Object ApiName,
                    @{Name='Category'; Expression = { $_.ApiPermissionCategorization }},
                    ApiPermission,
                    ApiPermissionDescription,
                    @{Name='CategorySort'; Expression = {
                        if ($categorizationOrder.ContainsKey($_.ApiPermissionCategorization)) {
                            $categorizationOrder[$_.ApiPermissionCategorization]
                        } else {
                            99
                        }
                    }} |
        Sort-Object ApiName, CategorySort, ApiPermission, ApiPermissionDescription -Unique |
        Select-Object ApiName, Category, ApiPermission, ApiPermissionDescription


    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'EA' -CurrentReportName 'EnterpriseApps Enumeration' -Warnings $EnterpriseAppsScriptWarningList

    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $tableOutput | format-table DisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,SAML,LastSignInDays,CreationInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Csv) {
        $tableOutput | select-object DisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,SAML,LastSignInDays,CreationInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,ApiDelegatedDangerous,ApiDelegatedHigh,ApiDelegatedMedium,ApiDelegatedLow,ApiDelegatedMisc,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $AppendixHeaderTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $ApiPermissionReference | Format-Table -AutoSize | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
   
    #Write HTML
    $ApiPermissionReferenceHTML += $ApiPermissionReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
    $PostContentCombined = $GLOBALJavaScript + "`n" + $ApiPermissionReferenceHTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - Enterprise Apps</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"
   
    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $EnterpriseAppsCount Enterprise Applications stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
   
    #Add information to the enumeration summary
    $ForeignCount = 0
    $CredentialCount = 0
    $AppApiDangerous = 0
    $AppApiHigh = 0
    $AppApiMedium = 0
    $AppApiLow = 0
    $AppApiMisc = 0
    $signInBuckets = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $tableOutput) {
        if ($app.Foreign) {
            $ForeignCount++
        }
        if ($app.Credentials) {
            $CredentialCount++
        }
        if ($app.ApiDangerous) {$AppApiDangerous++}
        if ($app.ApiHigh) {$AppApiHigh++}
        if ($app.ApiMedium) {$AppApiMedium++}
        if ($app.ApiLow) {$AppApiLow++}
        if ($app.ApiMisc) {$AppApiMisc++}

        $lastSignIn = $app.LastSignInDays
        if ($lastSignIn -eq "-" -or [string]::IsNullOrWhiteSpace($lastSignIn)) {
            $signInBuckets.Add("Never")
        } else {
            try {
                $bucket = if ($lastSignIn -le 30) { "0-1 month" }
                        elseif ($lastSignIn -le 60) { "1-2 months" }
                        elseif ($lastSignIn -le 90) { "2-3 months" }
                        elseif ($lastSignIn -le 120) { "3-4 months" }
                        elseif ($lastSignIn -le 150) { "4-5 months" }
                        elseif ($lastSignIn -le 180) { "5-6 months" }
                        else { "6+ months" }
                $signInBuckets.Add($bucket)
            } catch {
                $signInBuckets.Add("Never")
            }
        }
    }

    # Store in global var
    $GlobalAuditSummary.EnterpriseApps.Count = $EnterpriseAppsCount
    $GlobalAuditSummary.EnterpriseApps.Foreign = $ForeignCount
    $GlobalAuditSummary.EnterpriseApps.Credentials = $CredentialCount

    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Dangerous = $AppApiDangerous
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.High = $AppApiHigh
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Medium = $AppApiMedium
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Low = $AppApiLow
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Misc = $AppApiMisc

    $signInBuckets | Group-Object | ForEach-Object {
        $GlobalAuditSummary.EnterpriseApps.SignInActivity[$_.Name] = $_.Count
    }

    if ($null -ne $AppRoleReferenceCacheOut) {
        $AppRoleReferenceCacheOut.Value = $AppRoleReferenceCache
    }

    Return $AllServicePrincipalHT

}
