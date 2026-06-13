<#
	.SYNOPSIS
	   Enumerates and analyzes all users in the current tenant, including access, ownerships, roles, and risk posture.

#>
function Invoke-CheckUsers {
    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][switch]$SkipAutoRefresh = $false,
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$false)][int]$LimitResults,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][Object[]]$ConditionalAccessPolicies,
        [Parameter(Mandatory=$false)][switch]$QAMode = $false,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$Devices,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$false)][hashtable]$UserAuthMethodsTable,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments,
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentities = @{},
        [Parameter(Mandatory=$false)][hashtable]$AgentIdentityBlueprintsPrincipals = @{},
        [Parameter(Mandatory=$false)][switch]$Csv = $false,
        [Parameter(Mandatory=$true)][ref]$ReportStateOut
    )

    ############################## Function section ########################


    ############################## Script section ########################
    $PmScript = [System.Diagnostics.Stopwatch]::StartNew()
    $PmInitTasks = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Log -Level Verbose -Message "Start user script"
    if ($null -eq $ReportStateOut) {
        throw "Invoke-CheckUsers requires -ReportStateOut."
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "Users"
    $ProgressCounter = 0
    $TokenCheckLimit = 5000  # Define recheck limit for token lifetime. In large environments the access token might expire during the test.
    $PermissionUserSignInActivity = $true
    $global:GLOBALUserSignInActivityAvailable = $true
    $AllUsersDetails = [System.Collections.ArrayList]::new()
    $WarningReport = [System.Collections.Generic.List[string]]::new()
    $EscapedTenantName = $CurrentTenant.FileSafeDisplayNameEncoded
    if (-not $GLOBALGraphExtendedChecks) {$WarningReport.Add("Coverage gap: eligible role assignments not assessed; only active assignments are included.")}
    if (-not ($GLOBALPimForGroupsChecked)) {$WarningReport.Add("Coverage gap: PIM for Groups not assessed; eligible group owners/members may be missing.")}
    if (-not ($GLOBALAzurePsChecks)) {
        if ($GLOBALAzureIamWarningText) {
            $WarningReport.Add($GLOBALAzureIamWarningText)
        } else {
            $WarningReport.Add("Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to users are therefore missing from this report.")
        }
    }
    $UserImpact = @{
    "Base"                      = 1
    "DirectAppRoleNormal"       = 10
    "DirectAppRoleSensitive"    = 50
    "SpOwnAppLock"              = 20
    }
	
    $UserLikelihood = @{
	"Base"                      = 5
	"SyncedFromOnPrem"          = 3
    "Protected"                 = -4
    "NoMFA"                     = 10
    "ForeignAgentBlueprintPrincipal" = 20
    }

    # Build the agent-parent context once so Agent Users can be enriched before the user report is written.
    $PrincipalLookupByBlueprintId = @{}
    foreach ($principal in $AgentIdentityBlueprintsPrincipals.Values) {
        foreach ($lookupKey in @("$($principal.AppId)".Trim(), "$($principal.Id)".Trim())) {
            if ([string]::IsNullOrWhiteSpace($lookupKey)) {
                continue
            }
            if (-not $PrincipalLookupByBlueprintId.ContainsKey($lookupKey)) {
                $PrincipalLookupByBlueprintId[$lookupKey] = $principal
            }
        }
    }

    $AgentUserParentContext = @{}
    foreach ($agentIdentity in $AgentIdentities.Values) {
        $parentPrincipal = $null
        $parentKey = "$($agentIdentity.AgentIdentityBlueprintId)".Trim()
        if (-not [string]::IsNullOrWhiteSpace($parentKey) -and $PrincipalLookupByBlueprintId.ContainsKey($parentKey)) {
            $parentPrincipal = $PrincipalLookupByBlueprintId[$parentKey]
        }

        foreach ($agentUser in @($agentIdentity.AgentUsersDetails)) {
            $userId = "$($agentUser.Id)".Trim()
            if ([string]::IsNullOrWhiteSpace($userId)) {
                continue
            }

            if ($AgentUserParentContext.ContainsKey($userId) -and $AgentUserParentContext[$userId].ParentAgentIdentityId -ne $agentIdentity.Id) {
                Write-Log -Level Debug -Message "Agent user $userId is linked to multiple agent identities in source data. Keeping the first parent reference."
                continue
            }

            $AgentUserParentContext[$userId] = [pscustomobject]@{
                ParentAgentIdentityId = $agentIdentity.Id
                ParentAgentIdentityDisplayName = $agentIdentity.DisplayName
                ParentBlueprintPrincipalId = if ($parentPrincipal) { $parentPrincipal.Id } else { $null }
                ParentBlueprintPrincipalDisplayName = if ($parentPrincipal) { $parentPrincipal.DisplayName } else { $null }
                ForeignBlueprintPrincipal = if ($parentPrincipal) { [bool]$parentPrincipal.Foreign } else { $false }
            }
        }
    }

    # List of roles which members are not protected against the password reset of other low-tier admin roles.
    # Reference: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions?tabs=admin-center#who-can-reset-passwords
    $UnprotectedRoles = @(
        'Auth Admin',
        'Directory Readers',
        'Groups Admin',
        'Guest Inviter',
        'Helpdesk Admin',
        'Message Center Reader',
        'Password Admin',
        'Reports Reader',
        'User Admin',
        'User Experience Success Manager',
        'Usage Summary Reports Reader'
    )

    if ($TenantPimForGroupsAssignments) {

        # Initialize an empty hashtable
        $UserGroupMapping = @{}

        # Iterate through each object in the list
        $TenantPimForGroupsAssignments | Where-Object { $_.Type -eq "User" } | ForEach-Object {
            $principalId = $_.principalId
            $groupId = $_.groupId
            $accessId = $_.accessId

            # Create an object with groupId and accessId
            $entry = [PSCustomObject]@{
                groupId  = $groupId
                accessId = $accessId
            }

            # If the principalId already exists in the hashtable, append to the array
            if ($UserGroupMapping.ContainsKey($principalId)) {
                $UserGroupMapping[$principalId] += $entry
            } else {
                # Otherwise, create a new array with the first object
                $UserGroupMapping[$principalId] = @($entry)
            }
        }

    }

    Write-Log -Level Debug -Message "Create AU mapping"

    # Create a hashtable: UserId -> List of Admin Units
    $UserToAUMap = @{}

    foreach ($au in $AdminUnitWithMembers) {
        $members = $au.MembersUser
    
        if ($members -is [System.Collections.IDictionary]) {
            $members = @($members)
        }
    
        foreach ($member in $members) {
            $id = $member.id
            if ($null -ne $id) {
                if (-not $UserToAUMap.ContainsKey($id)) {
                    $UserToAUMap[$id] = [System.Collections.Generic.List[object]]::new()
                }
    
                # Store only required properties
                $auLite = [pscustomobject]@{
                    DisplayName                  = $au.DisplayName
                    IsMemberManagementRestricted = $au.IsMemberManagementRestricted
                }
    
                $UserToAUMap[$id].Add($auLite)
            }
        }
    }

    $PmInitTasks.Stop()
    ########################################## SECTION: DATACOLLECTION ##########################################
    $PmDataCollection = [System.Diagnostics.Stopwatch]::StartNew()


    # Checking if users SignInActivity property can be retrieved. Requires Premium otherwise HTTP 403:Tenant is not a B2C tenant and doesn't have premium license
    write-host "[*] Check if SignInActivity can be retrieved"
    $QueryParameters = @{
        '$select' = "id,SignInActivity"
        '$top' = "1"
    }
    try {
        Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop -DisablePagination | Out-Null
    } catch {
        if ($($_.Exception.Message) -match "Status: 403") {
            write-host "[!] HTTP 403 Error: Most likely due to missing Entra ID premium licence. Can't retrieve SignInActivity."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Can't retrieve SignInActivity."
        }
        $WarningReport.Add("No permissions to retrieve users SignInActivity properties. Inactive users are not marked.")
        $PermissionUserSignInActivity = $false
        $global:GLOBALUserSignInActivityAvailable = $false
    }


    #Perform collection
    write-host "[*] Get all users"
    if ($PermissionUserSignInActivity) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,AssignedLicenses,OtherMails,OnPremisesSyncEnabled,SignInActivity,CreatedDateTime,JobTitle,Department,perUserMfaState"
            '$top' = $ApiTop
        }
    } else {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,AssignedLicenses,OtherMails,OnPremisesSyncEnabled,CreatedDateTime,JobTitle,Department,perUserMfaState"
            '$top' = $ApiTop
        } 
    }
    $AllUsers = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $UsersTotalCount = @($AllUsers).count
    write-host "[+] Got $($UsersTotalCount) users"

    # Get all transitive memberships (expensive!)
    Write-Host "[*] Collecting user memberships"

    $UserMemberOfRaw = @{}
    $BatchSize = 10000     
    $ChunkCount = [math]::Ceiling($AllUsers.Count / $BatchSize)

    for ($chunkIndex = 0; $chunkIndex -lt $ChunkCount; $chunkIndex++) {
        Write-Log -Level Verbose -Message "Processing user batch $($chunkIndex + 1) of $ChunkCount..." 

        $StartIndex = $chunkIndex * $BatchSize
        $EndIndex = [math]::Min($StartIndex + $BatchSize - 1, $AllUsers.Count - 1)
        $UserBatch = $AllUsers[$StartIndex..$EndIndex]

        $Requests = New-Object System.Collections.Generic.List[Hashtable]
        foreach ($user in $UserBatch) {
            $req = @{
                "id"     = $user.id
                "method" = "GET"
                "url"    = "/users/$($user.id)/transitiveMemberOf"
            }
            $Requests.Add($req)
        }

        # Send batched request
        $Response = Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id'; '$top'= $ApiTop}

        # Parse and store results
        foreach ($item in $Response) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $groupIds = [System.Collections.Generic.List[string]]::new()

                foreach ($entry in $item.response.value) {
                    if ($entry.'@odata.type' -eq '#microsoft.graph.group') {
                        $groupIds.Add($entry.id)
                    }
                }

                if ($groupIds.Count -gt 0) {
                    $UserMemberOfRaw[$item.id] = $groupIds
                }
            }
        }
    }
    

    # Count transitive memberships
    $TotalTransitiveMemberRelations = 0
    foreach ($members in $UserMemberOfRaw.Values) {
        $TotalTransitiveMemberRelations += $members.Count
    }

    #Show warning in large tenants
    if (-not $LimitResults) {
        if ($TotalTransitiveMemberRelations -ge 1500000 -or $UsersTotalCount -ge 100000) {
            Write-Warning "In large tenants, consider using -LimitResults (e.g., 30000) to reduce report size and improve performance."
        }
    }


    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Collecting user ownerships"
    #Get all users ownerships for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllUsers) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    = "/users/$($item.id)/ownedObjects"
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id' ;'$top'=$ApiTop})
    $UserOwnedObjectsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $UserOwnedObjectsRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Collecting user device ownership"
    #Get all users device ownerships for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllUsers) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    = "/users/$($item.id)/ownedDevices"
            "headers" = @{"Accept"= "application/json;odata.metadata=none"} 
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id'; '$top'=$ApiTop})
    $DeviceOwnerRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DeviceOwnerRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Collecting user device registrations"
    #Get all users device registrations for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllUsers) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    = "/users/$($item.id)/registeredDevices"
            "headers" = @{"Accept"= "application/json;odata.metadata=none"} 
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id'; '$top'=$ApiTop})
    $DeviceRegisteredRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DeviceRegisteredRaw[$item.id] = $item.response.value
        }
    }    

    $PmDataCollection.Stop()
    ########################################## SECTION: User Processing ##########################################
    $PmDataProcessing = [System.Diagnostics.Stopwatch]::StartNew()

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($UsersTotalCount / 10), 1)
    Write-Host "[*] Status: Processing user 1 of $UsersTotalCount (updates every $StatusUpdateInterval users)..."

    #region Processing Loop
    #Loop through all users and get additional info and store it in a custom object
    foreach ($item in $AllUsers) {

        # Clean vars
        $Warnings = [System.Collections.Generic.HashSet[string]]::new()
        $Protected = $false
        $ProgressCounter ++
        $Impact = $UserImpact["Base"]
        $Likelihood = $UserLikelihood["Base"]
        $LastInteractiveSignIn = $item.SignInActivity.LastSignInDateTime
        $LastNonInteractiveSignIn = $item.SignInActivity.LastNonInteractiveSignInDateTime
        $LastSuccessfulSignInTime = $item.SignInActivity.lastSuccessfulSignInDateTime
        #Null check in case CreatedDateTime is $null
        if ($item.CreatedDateTime) {
            $CreatedDays = (New-TimeSpan -Start $item.CreatedDateTime).Days
        } else {
            $CreatedDays = $null
        }
        $EntraRolesTroughGroupOwnership = 0
        $EntraRolesTroughGroupMembership = 0
        $AzureRolesTroughGroupOwnership = 0
        $AzureRolesTroughGroupMembership = 0
        $EntraMaxTierTroughGroupOwnership = "-"
        $EntraMaxTierTroughGroupMembership = "-"
        $AzureMaxTierTroughGroupOwnership = "-"
        $AzureMaxTierTroughGroupMembership = "-"
        $Inactive = $false
        $UserEntraRoles = @()
        $Agent = $item.'@odata.type' -eq '#microsoft.graph.agentUser'
        $ParentAgentIdentityId = $null
        $ParentAgentIdentityDisplayName = $null
        $ParentBlueprintPrincipalId = $null
        $ParentBlueprintPrincipalDisplayName = $null
        $ForeignBlueprintPrincipal = $false

        # Enrich Agent Users with their parent Agent Identity and foreign blueprint principal state.
        if ($Agent -and $AgentUserParentContext.ContainsKey($item.Id)) {
            $agentParentContext = $AgentUserParentContext[$item.Id]
            $ParentAgentIdentityId = $agentParentContext.ParentAgentIdentityId
            $ParentAgentIdentityDisplayName = $agentParentContext.ParentAgentIdentityDisplayName
            $ParentBlueprintPrincipalId = $agentParentContext.ParentBlueprintPrincipalId
            $ParentBlueprintPrincipalDisplayName = $agentParentContext.ParentBlueprintPrincipalDisplayName
            $ForeignBlueprintPrincipal = [bool]$agentParentContext.ForeignBlueprintPrincipal
        }
        
        # Check the token lifetime after a specific amount of objects
        if (($ProgressCounter % $TokenCheckLimit) -eq 0 -and $SkipAutoRefresh -eq $false) {
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
        }

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $UsersTotalCount) {
            Write-Host "[*] Status: Processing user $ProgressCounter of $UsersTotalCount..."
        }

        if(($item.AssignedLicenses).Count -ne 0) {
            $LicenseStatus = "Licensed"
        }
        else {
            $LicenseStatus = "Unlicensed"
        }

        if ($item.OnPremisesSyncEnabled) {
            $OnPrem = $true
            $Likelihood += $UserLikelihood["SyncedFromOnPrem"]
        } else {
            $OnPrem = $false
        }


        #Process users memberships
        $UserMemberGroups = [System.Collections.Generic.List[object]]::new()
        if ($UserMemberOfRaw.ContainsKey($item.Id)) {
            foreach ($groupId in $UserMemberOfRaw[$item.Id]) {
                [void]$UserMemberGroups.Add(
                    [PSCustomObject]@{
                        Id             = $groupId
                        AssignmentType = 'Active'
                    }
                )
            }
        }

        #Check AU assignment
        $AUMember = [System.Collections.Generic.List[object]]::new()
        if ($UserToAUMap.ContainsKey($item.Id)) {
            $AUMember = $UserToAUMap[$item.Id]
        }

        #Get users owned objects (do not contain devices)
        $UserOwnedSP                                = [System.Collections.Generic.List[object]]::new()
		$UserOwnedAppRegs                           = [System.Collections.Generic.List[object]]::new()
        $UserOwnedGroups  	                        = [System.Collections.Generic.List[object]]::new()
        $UserOwnedAgentIdentitys  	                = [System.Collections.Generic.List[object]]::new()
        $UserOwnedAgentIdentityBlueprint 	        = [System.Collections.Generic.List[object]]::new()
        $UserOwnedAgentIdentityBlueprintPrincipal 	= [System.Collections.Generic.List[object]]::new()
        
        if ($UserOwnedObjectsRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $UserOwnedObjectsRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {
        
                    '#microsoft.graph.servicePrincipal' {
                        [void]$UserOwnedSP.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
        
                    '#microsoft.graph.application' {
                        [void]$UserOwnedAppRegs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        Write-Log -Level Trace -Message "The user $($item.Id) owns the AgentIdentity $($OwnedObject.Id)"
                        [void]$UserOwnedAgentIdentitys.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        Write-Log -Level Trace -Message "The user $($item.Id) owns the AgentIdentityBlueprintPrincipal $($OwnedObject.Id)"
                        [void]$UserOwnedAgentIdentityBlueprintPrincipal.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
                    '#microsoft.graph.agentIdentityBlueprint' {
                        Write-Log -Level Trace -Message "The user $($item.Id) owns the AgentIdentityBlueprint $($OwnedObject.Id)"
                        [void]$UserOwnedAgentIdentityBlueprint.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
                    '#microsoft.graph.group' {
                        [void]$UserOwnedGroups.Add(
                            [PSCustomObject]@{
                                Id             = $OwnedObject.Id
                                AssignmentType = 'Active'
                            }
                        )
                    }
        
                    default {
                        Write-Log -Level Debug -Message "Unknown owned object type: $($OwnedObject.'@odata.type') for user $($item.Id)"
                    }
                }
            }
        }

        #Get users owned devices
        $DeviceOwner = [System.Collections.Generic.List[object]]::new()
        if ($DeviceOwnerRaw.ContainsKey($item.Id)) {
            foreach ($Device in $DeviceOwnerRaw[$item.Id]) {
                [void]$DeviceOwner.Add(
                    [PSCustomObject]@{
                        id = $Device.id
                    }
                )
            }
        } 

        #Get users registered devices
        $DeviceRegistered = [System.Collections.Generic.List[object]]::new()
        if ($DeviceRegisteredRaw.ContainsKey($item.Id)) {
            foreach ($Device in $DeviceRegisteredRaw[$item.Id]) {
                [void]$DeviceRegistered.Add(
                    [PSCustomObject]@{
                        id = $Device.id
                    }
                )
            }
        } 

        if ($TenantPimForGroupsAssignments) {
            if ($UserGroupMapping.ContainsKey($item.Id)) {
                # Filter to retrieve only groupId values where accessId is "member"
                $memberGroups = $UserGroupMapping[$item.Id] | Where-Object { $_.accessId -eq "member" } | Select-Object @{Name="id"; Expression={$_.groupId}},@{Label='AssignmentType'; Expression={'Eligible'}}
                $ownerGroups = $UserGroupMapping[$item.Id] | Where-Object { $_.accessId -eq "owner" } | Select-Object @{Name="id"; Expression={$_.groupId}},@{Label='AssignmentType'; Expression={'Eligible'}}
                # Ensure $memberGroups contains values before merging
                if ($memberGroups -and @($memberGroups).Count -gt 0) {
                    # Rebuild $UserMemberGroups as an array of objects with the new IDs
                    [void]$UserMemberGroups.AddRange(@($memberGroups))
                }

                # Ensure $ownerGroups contains values before merging
                if ($ownerGroups -and @($ownerGroups).Count -gt 0) {
                    # Rebuild $UserOwnedGroups as an array of objects with the new IDs
                    [void]$UserOwnedGroups.AddRange(@($ownerGroups))

                }
            }
        }

        #Get details for each SP
        $SPOwnerDetails = foreach ($object in $UserOwnedSP) {
            $MatchingEnterpriseApp = $EnterpriseApps[$($Object.id)]

            if ($MatchingEnterpriseApp.Foreign) {
                $AppLock = "Unknown (Foreign App)"
            } else {
                $MatchingAppReg = $AppRegistrations.Values | Where-Object { $_.AppId -eq $MatchingEnterpriseApp.AppId }
                $AppLock = $MatchingAppReg.AppLock
            }

            if (@($MatchingEnterpriseApp).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingEnterpriseApp.Id
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    AppLock = $AppLock
                    GroupMembership = $MatchingEnterpriseApp.GrpMem
                    GroupOwnership = $MatchingEnterpriseApp.GrpOwn
                    AppOwnership = $MatchingEnterpriseApp.AppOwn
                    EntraRoles = $MatchingEnterpriseApp.EntraRoles
                    AzureRoles = $MatchingEnterpriseApp.AzureRoles
                    ApiDangerous = $MatchingEnterpriseApp.ApiDangerous
                    ApiHigh = $MatchingEnterpriseApp.ApiHigh
                    ApiMedium = $MatchingEnterpriseApp.ApiMedium
                    ApiLow = $MatchingEnterpriseApp.ApiLow
                    ApiMisc = $MatchingEnterpriseApp.ApiMisc
                    Warnings = $MatchingEnterpriseApp.Warnings
                    Impact = $MatchingEnterpriseApp.Impact
                }
            }
        }

        #Get details for each AppRegistration
        $AppRegOwnerDetails = foreach ($object in $UserOwnedAppRegs) {
            $MatchingAppReg = $AppRegistrations[$($Object.id)]
            if (@($MatchingAppReg).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingAppReg.Id
                    DisplayName = $MatchingAppReg.DisplayName
                    SignInAudience = $MatchingAppReg.SignInAudience
                    AppRoles = $MatchingAppReg.AppRoles
                    Impact = $MatchingAppReg.Impact
                }
            }
        }

        # Blueprint owner impact is applied after agent finalization so it uses finalized inherited impact.
        $BlueprintOwnerDetails = @()

        # Resolve owned agent objects into detail rows without feeding them into user scoring.
        $AgentIdentityOwnerDetails = @(foreach ($object in $UserOwnedAgentIdentitys) {
            $MatchingAgentIdentity = $AgentIdentities[$object.Id]
            if ($MatchingAgentIdentity) {
                [PSCustomObject]@{
                    Id          = $MatchingAgentIdentity.Id
                    DisplayName = $MatchingAgentIdentity.DisplayName
                    Warnings    = $MatchingAgentIdentity.Warnings
                }
            }
        }) | Where-Object { $null -ne $_ }

        $BlueprintPrincipalOwnerDetails = @(foreach ($object in $UserOwnedAgentIdentityBlueprintPrincipal) {
            $MatchingBlueprintPrincipal = $AgentIdentityBlueprintsPrincipals[$object.Id]
            if ($MatchingBlueprintPrincipal) {
                [PSCustomObject]@{
                    Id          = $MatchingBlueprintPrincipal.Id
                    DisplayName = $MatchingBlueprintPrincipal.DisplayName
                    Warnings    = $MatchingBlueprintPrincipal.Warnings
                }
            }
        }) | Where-Object { $null -ne $_ }

        #Get details for each Group
        $GroupOwnerDetails = [System.Collections.Generic.List[psobject]]::new()
        foreach ($object in $UserOwnedGroups) {
            $MatchingGroup = $AllGroupsDetails[$($Object.id)]
            if ($MatchingGroup) {
                [void]$GroupOwnerDetails.Add([PSCustomObject]@{ 
                    Id = $object.Id
                    AssignmentType = $object.AssignmentType
                    RoleAssignable = $MatchingGroup.RoleAssignable
                    EntraRoles = $MatchingGroup.EntraRoles
                    EntraMaxTier = $MatchingGroup.EntraMaxTier
                    CAPs = $MatchingGroup.CAPs
                    AzureRoles = $MatchingGroup.AzureRoles
                    AzureMaxTier = $MatchingGroup.AzureMaxTier
                    AppRoles = $MatchingGroup.AppRoles
                    Impact = $MatchingGroup.Impact
                })
            }
        }

        #Sort by impact
        $GroupOwnerDetails = $GroupOwnerDetails | Sort-Object -Property Impact -Descending

        #Get details for each Group
        $GroupMemberDetails    = [System.Collections.Generic.List[psobject]]::new()
        foreach ($object in $UserMemberGroups) {
            $MatchingGroup = $AllGroupsDetails[$($Object.id)]

            if ($MatchingGroup) {
                [void]$GroupMemberDetails.Add([PSCustomObject]@{ 
                    Id = $object.Id
                    AssignmentType = $object.AssignmentType
                    RoleAssignable = $MatchingGroup.RoleAssignable
                    EntraRoles = $MatchingGroup.EntraRoles
                    EntraMaxTier = $MatchingGroup.EntraMaxTier
                    CAPs = $MatchingGroup.CAPs
                    AzureRoles = $MatchingGroup.AzureRoles
                    AzureMaxTier = $MatchingGroup.AzureMaxTier
                    AppRoles = $MatchingGroup.AppRoles
                    Impact = $MatchingGroup.Impact
                })
            }
        } 
        #Sort by impact
        $GroupMemberDetails = $GroupMemberDetails | Sort-Object -Property Impact -Descending


        $UserDirectAppRoles = $GLOBALUserAppRoles[$item.Id]
        if ($null -eq $UserDirectAppRoles) {
            $UserDirectAppRolesCount = 0
        } else { 
            $UserDirectAppRolesCount = @($UserDirectAppRoles).Count 
        }


        # For all users check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            #Use function to get the Azure Roles for each object
            $AzureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $item.Id
            # Update the Roles property only if there are matching roles
            if ($null -eq $AzureRoleDetails) {$AzureRoleCount = 0} else { $AzureRoleCount = @($AzureRoleDetails).Count }
        } else {
            $AzureRoleCount = "?"
        }

        #Check if the user is MFA-capable
        $IsMfaCapable = $UserAuthMethodsTable[$item.Id]

        #Default value if not checked
        if ($null -eq $IsMfaCapable) {
            $IsMfaCapable = "?"
        }

        # Per-user MFA state from /users endpoint
        $PerUserMfa = if ([string]::IsNullOrWhiteSpace([string]$item.perUserMfaState)) { "-" } else { [string]$item.perUserMfaState }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################   

        #Increase the risk score if user is not MFA capable and is not the sync account and not an AgentUser
        if ($IsMfaCapable -ne "?" -and $IsMfaCapable -ne $true -and $item.DisplayName -ne "On-Premises Directory Synchronization Service Account" -and -not $Agent) {
            $Likelihood += $UserLikelihood["NoMFA"]
        }
        
        #Process owned SP
        if ($SPOwnerDetails) {
            #Add the impact score of the owned SP
            $AddImpact = 0
            $SpCount = 0
            $SpCountAppLock = 0
            $SpCountAppLockUnknown = 0
            $SpCountAppLockNo = 0
            foreach ($object in $SPOwnerDetails) {
                $SpCount ++
                if ($object.AppLock -eq $false) {
                    #takeover impact from SP
                    $AddImpact += $object.Impact
                    $SpCountAppLockNo ++
                } elseif ($object.AppLock -eq $true) {
                    $SpCountAppLock ++
                    #Otherwise, add SP impact or a base value (the lower one)
                    if ($object.Impact -le $UserImpact["SpOwnAppLock"]) {
                        $AddImpact += $object.Impact
                    } else {
                        $AddImpact += $UserImpact["SpOwnAppLock"]
                    }
                } else {
                    $SpCountAppLockUnknown ++
                    #takeover impact from SP
                    $AddImpact += $object.Impact
                }
            }
            [void]$Warnings.Add("User is owner of $SpCount SP (AppLock:$SpCountAppLock/$SpCount, Unknown:$SpCountAppLockUnknown)")
            $Impact += $AddImpact
        }

        #Process owned AppRegistrations
        if ($AppRegOwnerDetails) {
            $AppRegCount = 0
            $AddImpact = 0
            foreach ($object in $AppRegOwnerDetails) {
                $AppRegCount++
                #Apply impact score from App Registration
                $AddImpact += $object.Impact
            }
            $Impact += $AddImpact
            [void]$Warnings.Add("User is owner of $AppRegCount App Registrations")
        }


        #Process owned groups
        if ($GroupOwnerDetails) {
            $GroupCount = 0
            $AddImpact = 0
            $EntraRolesCount = 0
            $CAPs = 0
            $AzureRolesCount = 0
            $AppRolesCount = 0
            $Message = ""
            $MessageParts = @()

            foreach ($object in $GroupOwnerDetails) {
                $GroupCount++

                #Take over Impact from Group
                $AddImpact += $object.Impact
                $EntraRolesCount += $object.EntraRoles
                #Only process Caps if user has permission to them
                if ($GLOBALPermissionForCaps) {
                    $CAPs += $object.CAPs
                }
                if ($object.AzureRoles -is [int]) {$AzureRolesCount += $object.AzureRoles} else {$AzureRolesCount += 0}
                $EntraMaxTierTroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierTroughGroupOwnership -CandidateTier $object.EntraMaxTier
                $AzureMaxTierTroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierTroughGroupOwnership -CandidateTier $object.AzureMaxTier
                
                $AppRolesCount += $object.AppRoles
            }
            $Impact += $AddImpact

            #If any user is owner of a role assignable group the likelihood score has to be lowered
            if ($GroupOwnerDetails.RoleAssignable -contains $true) {
                $protected = $true
            }

            if (($EntraRolesCount + $CAPs + $AzureRolesCount + $AppRolesCount) -ge 1) {
                if ($EntraRolesCount -ge 1) {
                    $MessageParts += "EntraRoles:$EntraRolesCount"
                }
                if ($AzureRolesCount -ge 1) {
                    $MessageParts += "AzureRoles:$AzureRolesCount"
                }
                if ($AppRolesCount -ge 1) {
                    $MessageParts += "AppRoles:$AppRolesCount"
                }
                if ($CAPs -ge 1) {
                    $MessageParts += "CAPs:$CAPs"
                }
                $Message = $MessageParts -join ' / '
                [void]$Warnings.Add("Owns privileged group ($Message)")
            }
            $EntraRolesTroughGroupOwnership = $EntraRolesCount
            $AzureRolesTroughGroupOwnership = $AzureRolesCount
        }

        #Process member groups
        if ($GroupMemberDetails) {
            $GroupCount = 0
            $AddImpact = 0
            $EntraRolesCount = 0
            $ObjectsWithCaps = 0
            $AzureRolesCount = 0
            $AppRolesCount = 0
            $Message = ""
            $MessageParts = @()

            foreach ($object in $GroupMemberDetails) {
                $GroupCount++

                #Take over Impact from Group
                $AddImpact += $object.Impact
                $EntraRolesCount += $object.EntraRoles

                #Only process Caps if user had permission to enumerate them
                if ($GLOBALPermissionForCaps -and $object.CAPs -ge 1) {
                    $ObjectsWithCaps++
                }
                
                if ($object.AzureRoles -is [int]) {$AzureRolesCount += $object.AzureRoles} else {$AzureRolesCount += 0}
                $EntraMaxTierTroughGroupMembership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierTroughGroupMembership -CandidateTier $object.EntraMaxTier
                $AzureMaxTierTroughGroupMembership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierTroughGroupMembership -CandidateTier $object.AzureMaxTier
                $AppRolesCount += $object.AppRoles
            }

            #Removing the impact of CAPs if the user just is a member of a group in a CAP. Must match the value from the group script $GroupImpactScore
            $AddImpact -= ($ObjectsWithCaps * 50)

            $Impact += $AddImpact

            #If any user is member of a role assignable group the likelihood score has to be lowered
            if ($GroupMemberDetails.RoleAssignable -contains $true) {
                $protected = $true
            }

            if (($EntraRolesCount + $AzureRolesCount) -ge 1) {
                if ($EntraRolesCount -ge 1) {
                    $MessageParts += "EntraRoles:$EntraRolesCount"
                }
                if ($AzureRolesCount -ge 1) {
                    $MessageParts += "AzureRoles:$AzureRolesCount"
                }
                $Message = $MessageParts -join ' / '
                [void]$Warnings.Add("Member of privileged group ($Message)")
            }
            $EntraRolesTroughGroupMembership = $EntraRolesCount
            $AzureRolesTroughGroupMembership = $AzureRolesCount
        }

        #If any user is member of a AU which is management restricted the likelihood score has to be lowered
        if ($AUMember.isMemberManagementRestricted -contains $true) {
            $protected = $true
        }

        if ($item.DisplayName -eq "On-Premises Directory Synchronization Service Account") {
            $SyncAcc = $true

            if ($item.UserPrincipalName.StartsWith("Sync_")){
                $SyncAccType = "Connect Sync"
            } elseif ($item.UserPrincipalName.StartsWith("ADToAADSyncServiceAccount@")) {
                $SyncAccType = "Cloud Sync"
                #Mark cloud sync account to skip inactivity check
                $CloudSyncAccount = $true
            }
            [void]$Warnings.Add("Entra $SyncAccType account")
        } else {
            $SyncAcc = $false
            $CloudSyncAccount = $false
        }
        
        # Find matching roles in Entra role assignments where the PrincipalId matches the user's Id
        $MatchingEntraRoles = $TenantRoleAssignments[$item.Id]
        foreach ($Role in $MatchingEntraRoles) { 

            $Roleinfo = [PSCustomObject]@{
                DisplayName       = $role.DisplayName
                AssignmentType    = $role.AssignmentType
                IsPrivileged      = $role.IsPrivileged
                IsEnabled         = $role.IsEnabled
                IsBuiltIn         = $role.IsBuiltIn
                RoleTier          = $role.RoleTier
                DirectoryScopeId  = $role.DirectoryScopeId
                ScopeResolved     = $role.ScopeResolved
            }
            $UserEntraRoles += $Roleinfo

            #Set user to protected if not marked as protected already and if is not and unprotected role
            if (-not $protected -and ($UnprotectedRoles -notcontains $role.DisplayName)) {
                $Protected = $true
            }
        }

        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if (($UserEntraRoles | Measure-Object).count -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $UserEntraRoles
            [void]$Warnings.Add($EntraRolesProcessedDetails.Warning)
            $Impact += $EntraRolesProcessedDetails.ImpactScore

            #Check if the sync account has more than one role or an unexpected role
            if ($SyncAcc -and (@($UserEntraRoles).count -gt 1 -or $UserEntraRoles.DisplayName -notcontains "Directory Synchronization Accounts")) {
                [void]$Warnings.Add("Sync account with extensive privileges")
            }
            #Check if another user has the Directory Sync role
            if (!$SyncAcc -and $UserEntraRoles.DisplayName -contains "Directory Synchronization Accounts") {
                [void]$Warnings.Add("Directory Synchronization Role on non-sync user!")
            }
        }
       
        # Check app roles for sensitive keywords
        if ($UserDirectAppRolesCount -ge 1) {
            $keywords = @("admin", "critical")
            $SensitiveCounter = 0

            foreach ($appRole in $UserDirectAppRoles) {
                if ($appRole.AppRoleEnabled -eq $true) {
                    $matchFound = $false

                    foreach ($keyword in $keywords) {
                        if ($appRole.AppRoleDisplayName -like "*$keyword*" -or $appRole.AppRoleDescription -like "*$keyword*") {
                            $matchFound = $true
                            break
                        }
                    }

                    if ($matchFound) {
                        $Impact += $UserImpact["DirectAppRoleSensitive"]
                        $SensitiveCounter++
                    } else {
                        $Impact += $UserImpact["DirectAppRoleNormal"]
                    }
                }
            }

            if ($SensitiveCounter -ge 1) {
                [void]$Warnings.Add("Potentially sensitive AppRole directly assigned")
            }
        }



        #Check last sign-in dates
        if ($PermissionUserSignInActivity) {
            #Calculate number of inactive days
            if($null -eq $LastInteractiveSignIn) {
                $LastInteractiveSignIn = "Never logged in"
                $InactiveDays_InteractiveSignIn = "-"
            }
            else {
                $InactiveDays_InteractiveSignIn = (New-TimeSpan -Start $LastInteractiveSignIn).Days
            }
            if($null -eq $LastNonInteractiveSignIn) {
                $LastNonInteractiveSignIn = "Never Logged In"
                $InactiveDays_NonInteractiveSignIn = "-"
            }
            else {
                $InactiveDays_NonInteractiveSignIn = (New-TimeSpan -Start $LastNonInteractiveSignIn).Days
            }
            if($null -eq $LastSuccessfulSignInTime) {
                #Property exist since 12.2023
                $LastSuccessfulSignInTime = "Never or before 2024"
                $InactiveDays_lastsuccessfulSignin = "-"
            }
            else {
                $InactiveDays_lastsuccessfulSignin = (New-TimeSpan -Start $LastSuccessfulSignInTime).Days
            }


            if ($InactiveDays_lastsuccessfulSignin -ge 180 -or ($InactiveDays_lastsuccessfulSignin -eq "-" -and $CreatedDays -gt 180 -and -not $CloudSyncAccount)) {
                $Inactive = $true
            }
        } else {
            $InactiveDays_lastsuccessfulSignin = "?"
            $Inactive = "?"
        }


        if ($Protected) {
            $Likelihood += $UserLikelihood["Protected"]
        }

        if ($ForeignBlueprintPrincipal) {
            $Likelihood += $UserLikelihood["ForeignAgentBlueprintPrincipal"]
            [void]$Warnings.Add("Child of foreign blueprint principal")
        }

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            [void]$Warnings.Add($AzureRolesProcessedDetails.Warning)
            $Impact += $AzureRolesProcessedDetails.ImpactScore
        }

        # Determine direct + inherited max tier labels
        $DirectEntraMaxTier = Get-HighestTierLabel -Assignments $UserEntraRoles
        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $DirectEntraMaxTier -CandidateTier $EntraMaxTierTroughGroupOwnership
        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $EntraMaxTier -CandidateTier $EntraMaxTierTroughGroupMembership

        if ($GLOBALAzurePsChecks) {
            $DirectAzureMaxTier = Get-HighestTierLabel -Assignments $AzureRoleDetails
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $DirectAzureMaxTier -CandidateTier $AzureMaxTierTroughGroupOwnership
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $AzureMaxTier -CandidateTier $AzureMaxTierTroughGroupMembership
        } else {
            $AzureMaxTier = "?"
        }

    #Format warning messages
    $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }
        
        #Combine Direct assigned Entra roles + roles trough group
        $TotalEntraRoles = $EntraRolesTroughGroupOwnership + $EntraRolesTroughGroupMembership + @($UserEntraRoles).count

        if ($GLOBALAzurePsChecks) {
            $TotalAzureRoles = $AzureRolesTroughGroupOwnership + $AzureRolesTroughGroupMembership + $AzureRoleCount
        } else {
            $TotalAzureRoles = $AzureRoleCount
        }
        
        
        #Calc risk
        $Risk = [math]::Round(($Impact * $Likelihood))

        #Create custom object
        $UserDetails = [PSCustomObject]@{ 
            Id = $item.Id 
            DisplayName = $item.DisplayName
            UPNlink = "<a href=#$($item.id)>$($item.UserPrincipalName)</a>"
            UPN = $item.UserPrincipalName
            Enabled = $item.AccountEnabled
            UserType = $item.UserType
            Agent = $Agent
            Licenses = $($item.AssignedLicenses).count
            LicenseStatus = $LicenseStatus
            OnPrem = $OnPrem
            Department = $item.Department
            JobTitle = $item.JobTitle
            OtherMails = $item.OtherMails
            ParentAgentIdentityId = $ParentAgentIdentityId
            ParentAgentIdentityDisplayName = $ParentAgentIdentityDisplayName
            ParentBlueprintPrincipalId = $ParentBlueprintPrincipalId
            ParentBlueprintPrincipalDisplayName = $ParentBlueprintPrincipalDisplayName
            ForeignBlueprintPrincipal = $ForeignBlueprintPrincipal
            ForeignAgent = if ($Agent) { [bool]$ForeignBlueprintPrincipal } else { "-" }
            CreatedDateTime = $item.CreatedDateTime
            CreatedDays = $CreatedDays
            LastInteractiveSignInDateTime = $LastInteractiveSignIn
            InactiveDays_InteractiveSignIn = $InactiveDays_InteractiveSignIn
            LastNonInteractiveSignInDateTime = $LastNonInteractiveSignIn
            InactiveDays_NonInteractiveSignIn = $InactiveDays_NonInteractiveSignIn
            lastSuccessfulSignInDateTime = $LastSuccessfulSignInTime
            LastSignInDays = $InactiveDays_lastsuccessfulSignin
            Inactive = $Inactive
            AzureRoles = $TotalAzureRoles
            AzureMaxTier = $AzureMaxTier
            AzureRoleDetails = $AzureRoleDetails
            GrpMem = @($GroupMemberDetails).count
            GrpOwn = @($GroupOwnerDetails).count
            AuUnits = $AUMember.count
            EntraRoles = $TotalEntraRoles
            EntraMaxTier = $EntraMaxTier
            AppRegOwn = @($AppRegOwnerDetails).count
            BlueprintOwn = @($BlueprintOwnerDetails).count
            SPOwn = @($SPOwnerDetails).count
            DeviceOwn = @($DeviceOwner).count
            UserMemberGroups = $GroupMemberDetails
            AUMemberDetails = $AUMember
            Protected = $protected
            AppRoles = $UserDirectAppRolesCount
            AppRolesDetails = $UserDirectAppRoles
            GroupOwnerDetails = $GroupOwnerDetails
            AppRegOwnerDetails = $AppRegOwnerDetails
            BlueprintOwnerDetails = $BlueprintOwnerDetails
            AgentIdentityOwnerDetails = $AgentIdentityOwnerDetails
            BlueprintPrincipalOwnerDetails = $BlueprintPrincipalOwnerDetails
            SPOwnerDetails = $SPOwnerDetails
            DeviceOwnerDetails = $DeviceOwner
            DeviceRegisteredDetails = $DeviceRegistered
            MfaCap = $IsMfaCapable
            PerUserMfa = $PerUserMfa
            DeviceReg = @($DeviceRegistered).count
            RolesDetails = $UserEntraRoles
            BaselineImpact = [math]::Round($Impact)
            BaselineRisk = $Risk
            BaselineWarnings = $Warnings
            BlueprintOwnerImpact = 0
            Impact = [math]::Round($Impact)
            Likelihood = [math]::Round($Likelihood,1)
            Risk = $Risk
            Warnings = $Warnings
        } 

        
        [void]$AllUsersDetails.Add($UserDetails)


    }
    #endregion

    $PmDataProcessing.Stop()

    $UsersHT = @{}
    foreach ($user in $AllUsersDetails) {
        $UsersHT[$user.Id] = $user
    }

    $UserReportState = [PSCustomObject]@{
        AllUsersDetails              = $AllUsersDetails
        AllGroupsDetails             = $AllGroupsDetails
        Devices                      = $Devices
        CurrentTenant                = $CurrentTenant
        StartTimestamp               = $StartTimestamp
        OutputFolder                 = $OutputFolder
        Csv                          = $Csv
        QAMode                       = $QAMode
        LimitResults                 = $LimitResults
        WarningReport                = $WarningReport
        PermissionUserSignInActivity = $PermissionUserSignInActivity
        UsersTotalCount              = $UsersTotalCount
        EscapedTenantName            = $EscapedTenantName
        Title                        = $Title
        Timers                       = [PSCustomObject]@{
            Script         = $PmScript
            InitTasks      = $PmInitTasks
            DataCollection = $PmDataCollection
            DataProcessing = $PmDataProcessing
        }
    }
    $ReportStateOut.Value = $UserReportState

    if ($PmScript.IsRunning) {
        $PmScript.Stop()
    }
    Write-Log -Level Debug -Message "=== Performance Summary ==="
    Write-Log -Level Debug -Message ("Init Tasks:           {0:N2} s" -f $PmInitTasks.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Data Collection:      {0:N2} s" -f $PmDataCollection.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Data Processing:      {0:N2} s" -f $PmDataProcessing.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Report Writing:       deferred")
    Write-Log -Level Debug -Message ("-------------------------------")
    Write-Log -Level Debug -Message ("Total Script Time:    {0:N2} s" -f $PmScript.Elapsed.TotalSeconds)

    Return $UsersHT

}

function Add-EntraFalconUserWarningText {
    param(
        [Parameter(Mandatory = $false)][string]$ExistingWarnings,
        [Parameter(Mandatory = $true)][string]$NewWarning
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

function Update-EntraFalconUserBlueprintOwnershipImpact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Users,
        [Parameter(Mandatory = $true)][hashtable]$AgentIdentityBlueprints
    )

    if ($null -eq $Users -or $Users.Count -eq 0) {
        return
    }
    if ($null -eq $AgentIdentityBlueprints) {
        $AgentIdentityBlueprints = @{}
    }

    $BlueprintDetailsByUserId = @{}
    $blueprintsScanned = 0
    $ownerLinksFound = 0
    $skippedOwnersNotInUsers = 0
    foreach ($blueprint in @($AgentIdentityBlueprints.Values)) {
        if ($null -eq $blueprint) {
            continue
        }
        $blueprintsScanned++

        $blueprintId = "$($blueprint.Id)".Trim()
        if ([string]::IsNullOrWhiteSpace($blueprintId)) {
            continue
        }

        foreach ($owner in @($blueprint.AppOwnerUsers)) {
            $userId = "$($owner.Id)".Trim()
            if ([string]::IsNullOrWhiteSpace($userId)) {
                continue
            }
            $ownerLinksFound++
            if (-not $Users.ContainsKey($userId)) {
                $skippedOwnersNotInUsers++
                continue
            }

            if (-not $BlueprintDetailsByUserId.ContainsKey($userId)) {
                $BlueprintDetailsByUserId[$userId] = @{}
            }

            if ($BlueprintDetailsByUserId[$userId].ContainsKey($blueprintId)) {
                continue
            }

            $agentIdentities = if ($null -ne $blueprint.LinkedAgentIdentities) { [int]$blueprint.LinkedAgentIdentities } else { 0 }
            $agentUsers = if ($null -ne $blueprint.AgentUsers) { [int]$blueprint.AgentUsers } else { 0 }
            $directImpact = if ($null -ne $blueprint.DirectImpact) { [double]$blueprint.DirectImpact } else { 0 }
            $inheritedImpact = if ($null -ne $blueprint.InheritedImpact) { [double]$blueprint.InheritedImpact } else { 0 }
            $impact = if ($null -ne $blueprint.Impact) { [double]$blueprint.Impact } else { 0 }

            $BlueprintDetailsByUserId[$userId][$blueprintId] = [PSCustomObject]@{
                Id                    = $blueprint.Id
                DisplayName           = $blueprint.DisplayName
                BlueprintPrincipals   = if ($null -ne $blueprint.BlueprintPrincipals) { [int]$blueprint.BlueprintPrincipals } else { 0 }
                AgentIdentities       = $agentIdentities
                AgentUsers            = $agentUsers
                LinkedAgentIdentities = $agentIdentities
                LinkedAgentUsers      = $agentUsers
                DirectImpact          = [math]::Round($directImpact)
                InheritedImpact       = [math]::Round($inheritedImpact)
                Impact                = [math]::Round($impact)
            }
        }
    }

    $uniqueOwnerLinks = 0
    foreach ($blueprintDetailsByUser in $BlueprintDetailsByUserId.Values) {
        $uniqueOwnerLinks += $blueprintDetailsByUser.Count
    }
    $usersUpdated = 0
    $totalBlueprintOwnerImpact = 0
    foreach ($entry in $Users.GetEnumerator()) {
        $user = $entry.Value
        if ($null -eq $user) {
            continue
        }

        $baselineImpact = if ($user.PSObject.Properties.Name -contains 'BaselineImpact') { [double]$user.BaselineImpact } elseif ($user.PSObject.Properties.Name -contains 'Impact') { [double]$user.Impact } else { 0 }
        $baselineRisk = if ($user.PSObject.Properties.Name -contains 'BaselineRisk') { [double]$user.BaselineRisk } elseif ($user.PSObject.Properties.Name -contains 'Risk') { [double]$user.Risk } else { 0 }
        $baselineWarnings = if ($user.PSObject.Properties.Name -contains 'BaselineWarnings') { [string]$user.BaselineWarnings } else { [string]$user.Warnings }

        $user | Add-Member -NotePropertyName BaselineImpact -NotePropertyValue ([math]::Round($baselineImpact)) -Force
        $user | Add-Member -NotePropertyName BaselineRisk -NotePropertyValue ([math]::Round($baselineRisk)) -Force
        $user | Add-Member -NotePropertyName BaselineWarnings -NotePropertyValue $baselineWarnings -Force
        $user | Add-Member -NotePropertyName BlueprintOwnerImpact -NotePropertyValue 0 -Force
        $user | Add-Member -NotePropertyName BlueprintOwnerDetails -NotePropertyValue @() -Force
        $user | Add-Member -NotePropertyName BlueprintOwn -NotePropertyValue 0 -Force
        $user | Add-Member -NotePropertyName Impact -NotePropertyValue ([math]::Round($baselineImpact)) -Force
        $user | Add-Member -NotePropertyName Risk -NotePropertyValue ([math]::Round($baselineRisk)) -Force
        $user | Add-Member -NotePropertyName Warnings -NotePropertyValue $baselineWarnings -Force

        if (-not $BlueprintDetailsByUserId.ContainsKey($entry.Key)) {
            continue
        }

        $details = @($BlueprintDetailsByUserId[$entry.Key].Values | Sort-Object -Property @(@{ Expression = 'Impact'; Descending = $true }, 'DisplayName'))
        $blueprintOwnerImpact = [double](($details | Measure-Object -Property Impact -Sum).Sum)
        $likelihood = if ($user.PSObject.Properties.Name -contains 'Likelihood' -and $null -ne $user.Likelihood) {
            [double]$user.Likelihood
        } elseif ($baselineImpact -ne 0) {
            [double]$baselineRisk / [double]$baselineImpact
        } else {
            0
        }

        $user.BlueprintOwnerDetails = $details
        $user.BlueprintOwn = @($details).Count
        $user.BlueprintOwnerImpact = [math]::Round($blueprintOwnerImpact)
        $finalImpact = [math]::Round($baselineImpact + $blueprintOwnerImpact)
        $user | Add-Member -NotePropertyName Impact -NotePropertyValue $finalImpact -Force
        $user | Add-Member -NotePropertyName Risk -NotePropertyValue ([math]::Round($finalImpact * $likelihood)) -Force
        $user | Add-Member -NotePropertyName Warnings -NotePropertyValue (Add-EntraFalconUserWarningText -ExistingWarnings $baselineWarnings -NewWarning "User is owner of $($user.BlueprintOwn) Agent Identity Blueprint(s)") -Force
        $usersUpdated++
        $totalBlueprintOwnerImpact += [double]$user.BlueprintOwnerImpact
    }

    Write-Log -Level Debug -Message "User blueprint ownership impact: BlueprintsScanned=$blueprintsScanned, OwnerLinks=$ownerLinksFound, UniqueOwnerLinks=$uniqueOwnerLinks, UsersUpdated=$usersUpdated, SkippedOwnersNotInUsers=$skippedOwnersNotInUsers, TotalBlueprintOwnerImpact=$([math]::Round($totalBlueprintOwnerImpact))"
}

function Write-EntraFalconUsersReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$UserReportState,
        [Parameter(Mandatory = $true)][hashtable]$Users
    )

    if ($null -eq $UserReportState) {
        throw "Users report state is missing."
    }
    if ($null -eq $Users) {
        throw "Users are required to write the Users report."
    }

    $requiredProperties = @(
        'AllUsersDetails',
        'AllGroupsDetails',
        'Devices',
        'CurrentTenant',
        'StartTimestamp',
        'OutputFolder',
        'WarningReport',
        'PermissionUserSignInActivity',
        'UsersTotalCount',
        'EscapedTenantName',
        'Title',
        'Timers'
    )
    foreach ($propertyName in $requiredProperties) {
        if ($UserReportState.PSObject.Properties.Name -notcontains $propertyName -or $null -eq $UserReportState.$propertyName) {
            throw "Users report state is missing required property '$propertyName'."
        }
    }

    if ($null -ne $UserReportState.AllUsersDetails) {
        for ($i = 0; $i -lt $UserReportState.AllUsersDetails.Count; $i++) {
            $userId = "$($UserReportState.AllUsersDetails[$i].Id)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($userId) -and $Users.ContainsKey($userId)) {
                $UserReportState.AllUsersDetails[$i] = $Users[$userId]
            }
        }
    }

    $AllUsersDetails = $UserReportState.AllUsersDetails
    $AllGroupsDetails = $UserReportState.AllGroupsDetails
    $Devices = $UserReportState.Devices
    $CurrentTenant = $UserReportState.CurrentTenant
    $StartTimestamp = $UserReportState.StartTimestamp
    $outputFolder = $UserReportState.OutputFolder
    $Csv = [bool]$UserReportState.Csv
    $QAMode = [bool]$UserReportState.QAMode
    $LimitResults = $UserReportState.LimitResults
    $WarningReport = $UserReportState.WarningReport
    $PermissionUserSignInActivity = [bool]$UserReportState.PermissionUserSignInActivity
    $UsersTotalCount = $UserReportState.UsersTotalCount
    $EscapedTenantName = $UserReportState.EscapedTenantName
    $Title = $UserReportState.Title
    $PmScript = $UserReportState.Timers.Script
    $PmInitTasks = $UserReportState.Timers.InitTasks
    $PmDataCollection = $UserReportState.Timers.DataCollection
    $PmDataProcessing = $UserReportState.Timers.DataProcessing
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $UserCounter = 0

    $PmDataPostProcessing = [System.Diagnostics.Stopwatch]::StartNew()

    $blueprintOwnerUserCount = @($Users.Values | Where-Object { $_.PSObject.Properties.Name -contains 'BlueprintOwn' -and $null -ne $_.BlueprintOwn -and [double]$_.BlueprintOwn -gt 0 }).Count
    $totalBlueprintOwnerImpact = ($Users.Values | Measure-Object -Property BlueprintOwnerImpact -Sum).Sum
    if ($null -eq $totalBlueprintOwnerImpact) { $totalBlueprintOwnerImpact = 0 }
    Write-Log -Level Debug -Message "Users report final state: Users=$($Users.Count), BlueprintOwners=$blueprintOwnerUserCount, TotalBlueprintOwnerImpact=$([math]::Round([double]$totalBlueprintOwnerImpact))"

    write-host "[*] Processing results"

    #Define output of the main table
    $tableOutput = $AllUsersDetails | Sort-Object Risk -Descending | select-object UPN,UPNlink,Enabled,UserType,Agent,ForeignAgent,OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AppRoles,AppRegOwn,BlueprintOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,PerUserMfa,Impact,Likelihood,Risk,Warnings
    
    # Apply result limit for the main table
    if ($LimitResults -and $LimitResults -gt 0) {
        $tableOutput = $tableOutput | Select-Object -First $LimitResults
    }


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllUsersDetails | Sort-Object Risk -Descending

    # Apply limit for details
    if ($LimitResults -and $LimitResults -gt 0) {
        $details = $details | Select-Object -First $LimitResults
    }

    # Get the total count of group memberships. If this is to high the amount groups in the HTML report will be limited
    $TotalMemberGroups = $($AllUsersDetails.UserMemberGroups).count
    Write-Log -Level Debug -Message "Total transitive group memberships across all users: $TotalMemberGroups"
    if ($TotalMemberGroups -ge 50000) {
        $LimitGroupMembers = $true
        $WarningReport.Add("GroupMembership: Only 10 groups are displayed to ensure HTML performance.")
    } else {
        $LimitGroupMembers = $false
    }

    $PmDataPostProcessing.Stop()
    $PmGeneratingDetails = [System.Diagnostics.Stopwatch]::StartNew()

    # Initialize StringBuilders
    $DetailTxtBuilder  = [System.Text.StringBuilder]::new()

    # Progress status in verbose mode
    $detailsCount = $details.count
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($detailsCount / 10), 1)
    Write-Log -Level Verbose -Message "Status: Processing user 1 of $detailsCount (updates every $StatusUpdateInterval users)..."
    $ProgressCounter = 0    

    #Enum the details
    foreach ($item in $details) {

        # Progress status in verbose mode
        $ProgressCounter++
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $detailsCount) {
            Write-Log -Level Verbose -Message "Status: Processing user $ProgressCounter of $detailsCount ..."
        }

        $ReportingUserInfo = @()
        $ReportingLoginDetails = @()
        $ReportingRoles = @()
        $ReportingGroupOwner = @()
        $ReportingOwnerAppRegistration = @()
        $ReportingOwnerBlueprint = @()
        $ReportingOwnerAgentIdentity = @()
        $ReportingOwnerBlueprintPrincipal = @()
        $ReportingOwnerSP = @()
        $ReportingOwnerDevice = @()
        $ReportingRegisteredDevice = @()
        $ReportingAdminUnits = @()
        $ReportingAppRoles = @()
        $ReportingMemberGroup = [System.Collections.Generic.List[object]]::new()
        $ReportingAzureRoles = @()

        $UserCounter ++
        [void]$DetailTxtBuilder.AppendLine("##############################################################################################################################################################################################################")

        $ReportingUserInfo = [pscustomobject]@{
            "Display Name" = $item.DisplayName
            "User UPN" = $item.Upn
            "User ObjectID" = $item.Id
            "Enabled" = $item.Enabled
            "PerUserMfa" = $item.PerUserMfa
            "Protected" = $item.Protected
            "Entra Max Tier" = $item.EntraMaxTier
            "Azure Max Tier" = $item.AzureMaxTier
            "RiskScore" = $item.Risk
            "UserType" = $item.UserType
            "Agent" = $item.Agent
            "Created" = "{0} ({1} days ago)" -f $item.CreatedDateTime, $item.CreatedDays
        }
        if (-not [string]::IsNullOrWhiteSpace($item.ParentAgentIdentityDisplayName)) {
            $ReportingUserInfo | Add-Member -NotePropertyName "Parent Agent Identity" -NotePropertyValue $item.ParentAgentIdentityDisplayName
        }
        if ("$($item.ForeignAgent)" -ne "-") {
            $ReportingUserInfo | Add-Member -NotePropertyName "Foreign Agent" -NotePropertyValue $item.ForeignAgent
        }
        #Add sign-in info to the list if it's not shown in a dedicated table
        if ($null -ne $item.Department) {
            $ReportingUserInfo | Add-Member -NotePropertyName Department -NotePropertyValue $item.Department
        }
        if ($null -ne $item.JobTitle) {
            $ReportingUserInfo | Add-Member -NotePropertyName JobTitle -NotePropertyValue $item.JobTitle
        }
        if ($item.OtherMails -ne '') {
            $ReportingUserInfo | Add-Member -NotePropertyName OtherMails -NotePropertyValue ($item.OtherMails | Out-String)
        }

        if ($item.Warnings -ne '') {
            $ReportingUserInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        foreach ($prop in $ReportingUserInfo.PSObject.Properties) {
            $name = if ($null -ne $prop.Name) { $prop.Name } else { "Unknown" }

            # Safely convert any value type to string
            if ($null -eq $prop.Value) {
                $value = ""
            } elseif ($prop.Value -is [System.Array]) {
                $value = ($prop.Value -join ', ')
            } else {
                $value = $prop.Value.ToString()
            }

            [void]$DetailTxtBuilder.AppendLine("$name : $value")
        }
        [void]$DetailTxtBuilder.AppendLine("")

        if (-not [string]::IsNullOrWhiteSpace($item.ParentAgentIdentityId) -and $ReportingUserInfo.PSObject.Properties.Name -contains "Parent Agent Identity") {
            $ReportingUserInfo."Parent Agent Identity" = "<a href=AgentIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($item.ParentAgentIdentityId)>$($item.ParentAgentIdentityDisplayName)</a>"
        }

        #Hide Login details section if user had not enough permissions to read the attributes
        if ($PermissionUserSignInActivity) {
            $lastSuccessful     = "{0} ({1} days ago)" -f $item.lastSuccessfulSignInDateTime, $item.LastSignInDays
            $lastInteractive    = "{0} ({1} days ago)" -f $item.LastInteractiveSignInDateTime, $item.InactiveDays_InteractiveSignIn
            $lastNonInteractive = "{0} ({1} days ago)" -f $item.LastNonInteractiveSignInDateTime, $item.InactiveDays_NonInteractiveSignIn

            $ReportingLoginDetails = [pscustomobject]@{
                "Last successful log-in"         = $lastSuccessful
                "Last interactive log-in attempt" = $lastInteractive
                "Last non-interactive log-in"    = $lastNonInteractive
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Login Details")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Last successful log-in: $lastSuccessful")
            [void]$DetailTxtBuilder.AppendLine("Last interactive log-in attempt: $lastInteractive")
            [void]$DetailTxtBuilder.AppendLine("Last non-interactive log-in: $lastNonInteractive")
            [void]$DetailTxtBuilder.AppendLine()
        }

        
        if (@($item.RolesDetails).count -ge 1) {
            $ReportingRoles = foreach ($role in $($item.RolesDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $role.DisplayName
                    "AssignmentType" = $role.AssignmentType
                    "Tier Level" = $role.RoleTier
                    "Privileged" = $role.isPrivileged
                    "Builtin" = $role.IsBuiltin
                    "Scoped to" = "$($role.ScopeResolved.DisplayName) ($($role.ScopeResolved.Type))"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles| format-table | Out-String))
        }

        if (@($item.GroupOwnerDetails).count -ge 1) {

            #Set lenght to 0
            $maxDisplayNameLength = 0
            $maxWarningsLength = 0

            $ReportingGroupOwner = foreach ($object in $($item.GroupOwnerDetails)) {
                $MatchingGroup = $AllGroupsDetails[$($Object.id)]

                #Calculate field size for displayname and warnings. This allow the reduce of whitespaces in combination with Format-ReportSection
                $displayName = $MatchingGroup.DisplayName
                $warnings = $MatchingGroup.Warnings
                if ($null -ne $displayName -and $displayName.Length -gt $maxDisplayNameLength) {
                    $maxDisplayNameLength = $displayName.Length
                }
                if ($null -ne $warnings -and $warnings.Length -gt $maxWarningsLength) {
                    $maxWarningsLength = $warnings.Length
                }

                [pscustomobject]@{ 
                    "AssignmentType" = $object.AssignmentType
                    "DisplayName" = $displayName
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($displayName)</a>"
                    "Type" = $MatchingGroup.Type
                    "OnPrem" = $MatchingGroup.OnPrem
                    "EntraRoles" = $object.EntraRoles
                    "EntraMaxTier" = $object.EntraMaxTier
                    "AzureRoles" = $object.AzureRoles
                    "AzureMaxTier" = $object.AzureMaxTier
                    "AppRoles" = $object.AppRoles
                    "CAPs" = $object.CAPs
                    "Users" = $MatchingGroup.Users
                    "Impact" = $object.Impact
                    "Warnings" = $warnings
                }
            }

            $formattedText = Format-ReportSection -Title "Owner of Groups" `
            -Objects $ReportingGroupOwner `
            -Properties @("AssignmentType", "Displayname", "Type", "OnPrem", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "AppRoles", "CAPs", "Users", "Impact", "Warnings") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = [Math]::Min($maxDisplayNameLength, 60); Type = 15; OnPrem = 7; EntraRoles = 10; EntraMaxTier = 11; AzureRoles = 10; AzureMaxTier = 11; AppRoles = 8; CAPs = 4; Users = 5; Impact = 6; Warnings = [Math]::Min($maxWarningsLength, 60) }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
                    
            
            $ReportingGroupOwner  = foreach ($obj in $ReportingGroupOwner) {
                [pscustomobject]@{
                    AssignmentType          = $obj.AssignmentType
                    DisplayName             = $obj.DisplayNameLink
                    Type                    = $obj.Type
                    OnPrem                  = $obj.OnPrem
                    EntraRoles              = $obj.EntraRoles
                    EntraMaxTier            = $obj.EntraMaxTier
                    AzureRoles              = $obj.AzureRoles
                    AzureMaxTier            = $obj.AzureMaxTier
                    AppRoles                = $obj.AppRoles
                    CAPs                    = $obj.CAPs
                    Users                   = $obj.Users
                    Impact                  = $obj.Impact
                    Warnings                = $obj.Warnings
                }
            }
        }

        if (@($item.AppRegOwnerDetails).count -ge 1) {
            $ReportingOwnerAppRegistration = foreach ($app in $($item.AppRegOwnerDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $app.DisplayName
                    "DisplayNameLink" = "<a href=AppRegistration_$($StartTimestamp)_$($EscapedTenantName).html#$($app.Id)>$($app.DisplayName)</a>"
                    "SignInAudience" = $app.SignInAudience
                    "AppRoles" = $app.AppRoles
                    "Impact" = $app.Impact
                }            
            }
            #Sort based on the impact
            $ReportingOwnerAppRegistration = $ReportingOwnerAppRegistration | Sort-Object -Property Impact -Descending

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of App Registration")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerAppRegistration | format-table -Property DisplayName,SignInAudience,AppRoles,Impact | Out-String))
            $ReportingOwnerAppRegistration = foreach ($obj in $ReportingOwnerAppRegistration) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SignInAudience          = $obj.SignInAudience
                    AppRoles                = $obj.AppRoles
                    Impact                  = $obj.Impact
                }
            }
        }


        if (@($item.BlueprintOwnerDetails).count -ge 1) {
            $ReportingOwnerBlueprint = foreach ($bp in $item.BlueprintOwnerDetails) {
                [pscustomobject]@{
                    DisplayName           = $bp.DisplayName
                    DisplayNameLink       = "<a href=AgentIdentityBlueprints_$($StartTimestamp)_$($EscapedTenantName).html#$($bp.Id)>$($bp.DisplayName)</a>"
                    BlueprintPrincipals   = $bp.BlueprintPrincipals
                    AgentIdentities       = $bp.AgentIdentities
                    AgentUsers            = $bp.AgentUsers
                    DirectImpact          = $bp.DirectImpact
                    InheritedImpact       = $bp.InheritedImpact
                    Impact                = $bp.Impact
                }
            }
            $ReportingOwnerBlueprint = $ReportingOwnerBlueprint | Sort-Object -Property Impact -Descending

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Agent Identity Blueprint")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerBlueprint | format-table -Property DisplayName,BlueprintPrincipals,AgentIdentities,AgentUsers,DirectImpact,InheritedImpact,Impact | Out-String))

            $ReportingOwnerBlueprint = foreach ($obj in $ReportingOwnerBlueprint) {
                [pscustomobject]@{
                    DisplayName           = $obj.DisplayNameLink
                    BlueprintPrincipals   = $obj.BlueprintPrincipals
                    AgentIdentities       = $obj.AgentIdentities
                    AgentUsers            = $obj.AgentUsers
                    DirectImpact          = $obj.DirectImpact
                    InheritedImpact       = $obj.InheritedImpact
                    Impact                = $obj.Impact
                }
            }
        }

        # Render owned agent objects as detail-only sections to make ownership visible without changing user scoring.
        if (@($item.AgentIdentityOwnerDetails).count -ge 1) {
            $ReportingOwnerAgentIdentity = foreach ($agentIdentity in $item.AgentIdentityOwnerDetails) {
                [pscustomobject]@{
                    DisplayName     = $agentIdentity.DisplayName
                    DisplayNameLink = "<a href=AgentIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($agentIdentity.Id)>$($agentIdentity.DisplayName)</a>"
                }
            }
            $ReportingOwnerAgentIdentity = $ReportingOwnerAgentIdentity | Sort-Object -Property DisplayName

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Agent Identities")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerAgentIdentity | Format-Table -Property DisplayName | Out-String -Width 512))

            $ReportingOwnerAgentIdentity = foreach ($obj in $ReportingOwnerAgentIdentity) {
                [pscustomobject]@{
                    DisplayName = $obj.DisplayNameLink
                }
            }
        }

        if (@($item.BlueprintPrincipalOwnerDetails).count -ge 1) {
            $ReportingOwnerBlueprintPrincipal = foreach ($principal in $item.BlueprintPrincipalOwnerDetails) {
                [pscustomobject]@{
                    DisplayName     = $principal.DisplayName
                    DisplayNameLink = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($EscapedTenantName).html#$($principal.Id)>$($principal.DisplayName)</a>"
                }
            }
            $ReportingOwnerBlueprintPrincipal = $ReportingOwnerBlueprintPrincipal | Sort-Object -Property DisplayName

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Agent Identity Blueprint Principals")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerBlueprintPrincipal | Format-Table -Property DisplayName | Out-String -Width 512))

            $ReportingOwnerBlueprintPrincipal = foreach ($obj in $ReportingOwnerBlueprintPrincipal) {
                [pscustomobject]@{
                    DisplayName = $obj.DisplayNameLink
                }
            }
        }

        if (@($item.SPOwnerDetails).count -ge 1) {
            $ReportingOwnerSP  = foreach ($app in $($item.SPOwnerDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $app.DisplayName
                    "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$($EscapedTenantName).html#$($app.Id)>$($app.DisplayName)</a>"
                    "AppLock" = $app.AppLock
                    "GroupMembership" = $app.GroupMembership
                    "GroupOwnership" = $app.GroupOwnership
                    "AppOwnership" = $app.AppOwnership
                    "EntraRoles" = $app.EntraRoles
                    "AzureRoles" = $app.AzureRoles
                    "APIPermission" = "D:$($app.ApiDangerous) / H:$($app.ApiHigh) / M:$($app.ApiMedium) / L:$($app.ApiLow) / U:$($app.ApiMisc)"
                    "Warnings" = $app.Warnings
                }
            }
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Service Principal")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerSP | format-table -Property DisplayName,AppLock,GroupMembership,GroupOwnership,AppOwnership,EntraRoles,AzureRoles,APIPermission,Warnings | Out-String -Width 512))
            $ReportingOwnerSP  = foreach ($obj in $ReportingOwnerSP) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    AppLock                 = $obj.AppLock
                    GroupMembership         = $obj.GroupMembership
                    AppOwnership            = $obj.AppOwnership
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    APIPermission           = $obj.APIPermission
                    Warnings                = $obj.Warnings
                }
            }
        }


        if (@($item.DeviceOwnerDetails).count -ge 1) {

            $DiplayNameLength = 0
            $OsLength = 0

            $ReportingOwnerDevice = foreach ($object in $($item.DeviceOwnerDetails)) {
                $DeviceDetails = $Devices[$object.id]

                # Calc Max Length
                $DiplayName = $DeviceDetails.displayName
                if ($null -ne $DisplayName -and $DisplayName.Length -gt $DiplayNameLength) {
                    $DiplayNameLength = $DisplayName.Length
                }
                $Os = $DeviceDetails.operatingSystem + " / " + $DeviceDetails.operatingSystemVersion
                if ($null -ne $Os -and $Os.Length -gt $OsLength) {
                    $OsLength = $Os.Length
                }

                [pscustomobject]@{ 
                    "Displayname" = $DiplayName
                    "Type" = $DeviceDetails.trustType
                    "OS" = $Os
                }
            }
            
            # Build TXT
            $formattedText = Format-ReportSection -Title "Owner of Devices" `
            -Objects $ReportingOwnerDevice `
            -Properties @("Displayname", "Type", "OS") `
            -ColumnWidths @{ Displayname = [Math]::Min($DiplayNameLength, 50); Type = 15; OS = [Math]::Min($OsLength, 40) }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        }

        #Registered devices
        if (@($item.DeviceRegisteredDetails).count -ge 1) {

            $DiplayNameLength = 0
            $OsLength = 0

            $ReportingRegisteredDevice = foreach ($object in $($item.DeviceRegisteredDetails)) {
                $DeviceDetails = $Devices[$object.id]

                # Calc Max Length
                $DiplayName = $DeviceDetails.displayName
                if ($null -ne $DisplayName -and $DisplayName.Length -gt $DiplayNameLength) {
                    $DiplayNameLength = $DisplayName.Length
                }
                $Os = $DeviceDetails.operatingSystem + " / " + $DeviceDetails.operatingSystemVersion
                if ($null -ne $Os -and $Os.Length -gt $OsLength) {
                    $OsLength = $Os.Length
                }

                [pscustomobject]@{ 
                    "Displayname" = $DiplayName
                    "Type" = $DeviceDetails.trustType
                    "OS" = $Os
                }
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Registered Devices" `
            -Objects $ReportingRegisteredDevice `
            -Properties @("Displayname", "Type", "OS") `
            -ColumnWidths @{ Displayname = [Math]::Min($DiplayNameLength, 30); Type = 15; OS = [Math]::Min($OsLength, 40) }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        }   

        #AU Devices
        if (@($item.AUMemberDetails).count -ge 1) {       
            $ReportingAdminUnits = foreach ($Au in $($item.AUMemberDetails)) {
                [pscustomobject]@{ 
                    "AU Name" = $Au.DisplayName
                    "isMemberManagementRestricted" = $Au.isMemberManagementRestricted
                    
                }
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Administrative Units")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAdminUnits | format-table))
        }

        #Directly assigned AppRoles
        if ($item.AppRoles -ge 1) {

            #Set lenght to 0
            $maxAppRoleNameLength = 0
            $maxDescriptionLength = 0
            $maxAppNameLength = 0
           
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {

                $AppRoleName = $object.AppRoleDisplayName
                $Description = $object.AppRoleDescriptions
                $AppName = $object.AppName
                if ($null -ne $AppRoleName -and $AppRoleName.Length -gt $maxAppRoleNameLength) {
                    $maxAppRoleNameLength = $AppRoleName.Length
                }
                if ($null -ne $Description -and $Description.Length -gt $maxDescriptionLength) {
                    $maxDescriptionLength = $Description.Length
                }
                if ($null -ne $AppName -and $AppName.Length -gt $maxAppNameLength) {
                    $maxAppNameLength = $AppName.Length
                }
                [pscustomobject]@{ 
                    "AppRoleName" = $AppRoleName
                    "Enabled" = $object.AppRoleEnabled
                    "Description" = $Description
                    "AssignedtoApp" = "<a href=EnterpriseApps_$($StartTimestamp)_$($EscapedTenantName).html#$($object.AppID)>$($AppName)</a>"
                    "App" = $AppName
                }
            }
            
            $formattedText = Format-ReportSection -Title "Directly Assigned AppRoles" `
            -Objects $ReportingAppRoles `
            -Properties @("AppRoleName", "Enabled", "Description", "App") `
            -ColumnWidths @{ AppRoleName = [Math]::Min($maxAppRoleNameLength, 40); Enabled = 7; Description = [Math]::Min($maxDescriptionLength, 40); App = [Math]::Min($maxAppNameLength, 40)}
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            $ReportingAppRoles  = foreach ($obj in $ReportingAppRoles) {
                [pscustomobject]@{
                    AppRoleName     = $obj.AppRoleName
                    Enabled         = $obj.Enabled
                    Description     = $obj.Description
                    AssignedtoApp   = $obj.AssignedtoApp
                }
            }
        }

        #Group Memberships
        if (@($item.UserMemberGroups).count -ge 1) {
            $MatchingGroupRaw = [System.Collections.Generic.List[object]]::new()
            #Limit the number of groups if needed
            if ($LimitGroupMembers) {
                $item.UserMemberGroups = $item.UserMemberGroups | select-object -First 10
            }

            #Set lenght to 0
            $maxDisplayNameLength = 0
            $maxWarningsLength = 0

            foreach ($object in $($item.UserMemberGroups)) {
                $MatchingGroup = $AllGroupsDetails[$($Object.id)]
                
                #Calculate field size for displayname and warnings. This allow the reduce of whitespaces in combination with Format-ReportSection
                $displayName = $MatchingGroup.DisplayName
                $warnings = $MatchingGroup.Warnings
                if ($null -ne $displayName -and $displayName.Length -gt $maxDisplayNameLength) {
                    $maxDisplayNameLength = $displayName.Length
                }
                if ($null -ne $warnings -and $warnings.Length -gt $maxWarningsLength) {
                    $maxWarningsLength = $warnings.Length
                }

                $obj = [pscustomobject]@{
                    "AssignmentType" = $object.AssignmentType
                    "DisplayName" = $displayName
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($displayName)</a>"
                    "Type" = $MatchingGroup.Type
                    "OnPrem" = $MatchingGroup.OnPrem
                    "EntraRoles" = $object.EntraRoles
                    "EntraMaxTier" = $object.EntraMaxTier
                    "AzureRoles" = $object.AzureRoles
                    "AzureMaxTier" = $object.AzureMaxTier
                    "AppRoles" = $object.AppRoles
                    "CAPs" = $object.CAPs
                    "Users" = $MatchingGroup.Users
                    "Impact" = $object.Impact
                    "Warnings" = $warnings
                }
                [void]$MatchingGroupRaw.Add($obj)
            }

            $formattedText = Format-ReportSection -Title "Member of Groups" `
            -Objects $MatchingGroupRaw `
            -Properties @("AssignmentType", "Displayname", "Type", "OnPrem", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "AppRoles", "CAPs", "Users", "Impact", "Warnings") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = [Math]::Min($maxDisplayNameLength, 60); Type = 15; OnPrem = 7; EntraRoles = 10; EntraMaxTier = 11; AzureRoles = 10; AzureMaxTier = 11; AppRoles = 8; CAPs = 4; Users = 5; Impact = 6; Warnings = [Math]::Min($maxWarningsLength, 60) }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        
            foreach ($obj in $MatchingGroupRaw) {
                $ReportingMemberGroup.Add([pscustomobject]@{
                    AssignmentType          = $obj.AssignmentType
                    DisplayName             = $obj.DisplayNameLink
                    Type                    = $obj.Type
                    OnPrem                  = $obj.OnPrem
                    EntraRoles              = $obj.EntraRoles
                    EntraMaxTier            = $obj.EntraMaxTier
                    AzureRoles              = $obj.AzureRoles
                    AzureMaxTier            = $obj.AzureMaxTier
                    AppRoles                = $obj.AppRoles
                    CAPs                    = $obj.CAPs
                    Users                   = $obj.Users
                    Impact                  = $obj.Impact
                    Warnings                = $obj.Warnings
                })

            }
        }

        ############### Azure Roles
        if (@($item.AzureRoleDetails).Count -ge 1 ) {
            $ReportingAzureRoles = foreach ($object in $($item.AzureRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $object.RoleName
                    "Assignment" = $object.AssignmentType
                    "RoleType" = $object.RoleType
                    "Tier Level" = $object.RoleTier
                    "Conditions" = $object.Conditions
                    "Scoped to" = $object.Scope
                }
            }
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | format-table | Out-String -Width 512))
        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.Upn
            "Object ID"       = $item.Id
            "General Information" = $ReportingUserInfo
            "Sign-In Details" = $ReportingLoginDetails
            "Entra Role Assignments" = $ReportingRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owner of App Registration" = $ReportingOwnerAppRegistration
            "Owner of Agent Identity Blueprint" = $ReportingOwnerBlueprint
            "Owner of Agent Identities" = $ReportingOwnerAgentIdentity
            "Owner of Agent Identity Blueprint Principals" = $ReportingOwnerBlueprintPrincipal
            "Owner of Service Principal" = $ReportingOwnerSP
            "Owner of Devices" = $ReportingOwnerDevice
            "Registered Devices" = $ReportingRegisteredDevice
            "Administrative Units" = $ReportingAdminUnits
            "Directly Assigned AppRoles" = $ReportingAppRoles
            "Member of Groups (Transitive)" = $ReportingMemberGroup
            "Azure IAM assignments" = $ReportingAzureRoles
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)
    }

    $DetailOutputTxt  = $DetailTxtBuilder.ToString()

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Users Details</h2>
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
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"

    $PmGeneratingDetails.Stop()
    $PmWritingReports = [System.Diagnostics.Stopwatch]::StartNew()
    write-host "[+] Writing log files"
    write-host ""

    $mainTable = $tableOutput | select-object -Property @{Name = "UPN"; Expression = { $_.UPNlink}},Enabled,UserType,Agent,@{Name = "ForeignAgent"; Expression = { if ($null -eq $_.ForeignAgent -or [string]::IsNullOrWhiteSpace([string]$_.ForeignAgent)) { "-" } else { $_.ForeignAgent } }},OnPrem,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AppRoles,AppRegOwn,BlueprintOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,PerUserMfa,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'Users' -CurrentReportName 'Users Enumeration' -Warnings $WarningReport

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
    if ($Csv) {
        $tableOutput | select-object UPN,Enabled,UserType,Agent,@{Name = "ForeignAgent"; Expression = { if ($null -eq $_.ForeignAgent -or [string]::IsNullOrWhiteSpace([string]$_.ForeignAgent)) { "-" } else { $_.ForeignAgent } }},OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AppRoles,AppRegOwn,BlueprintOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,PerUserMfa,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }
    $tableOutput | select-object UPN,Enabled,UserType,Agent,@{Name = "ForeignAgent"; Expression = { if ($null -eq $_.ForeignAgent -or [string]::IsNullOrWhiteSpace([string]$_.ForeignAgent)) { "-" } else { $_.ForeignAgent } }},OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,PerUserMfa,Impact,Likelihood,Risk,Warnings | format-table | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $DetailOutputTxt | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append

    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $($tableOutput.count) users stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - Users</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $PmWritingReports.Stop()
    $PmEndTasks = [System.Diagnostics.Stopwatch]::StartNew()

    #Add information to the enumeration summary
    $GuestCount = 0
    $InactiveCount = 0
    $EnabledCount = 0
    $MfaCapCount = 0
    $OnPremCount = 0
    $buckets = New-Object 'System.Collections.Generic.List[string]'

    foreach ($user in $AllUsersDetails) {
        if ($user.UserType -eq "Guest") {
            $GuestCount++
        }
        if ($user.Inactive) {
            $InactiveCount++
        }
        if ($user.Enabled) {
            $EnabledCount++
        }
        if ($user.MfaCap) {
            $MfaCapCount++
        }
        if ($user.OnPrem) {
            $OnPremCount++
        }

        # Group sign-in activity
        $lastSignIn = $user.LastSignInDays
        if ($lastSignIn -eq "-" -or [string]::IsNullOrWhiteSpace($lastSignIn)) {
            $buckets.Add("Never")
        } else {
            try {
                $bucket = if ($lastSignIn -le 30) { "0-1 month" }
                        elseif ($lastSignIn -le 60) { "1-2 months" }
                        elseif ($lastSignIn -le 90) { "2-3 months" }
                        elseif ($lastSignIn -le 120) { "3-4 months" }
                        elseif ($lastSignIn -le 150) { "4-5 months" }
                        elseif ($lastSignIn -le 180) { "5-6 months" }
                        else { "6+ months" }

                $buckets.Add($bucket)
            } catch {
                $buckets.Add("?")
            }
        }

    }
    # Store in global var
    $GlobalAuditSummary.Users.Count = $UsersTotalCount
    $GlobalAuditSummary.Users.Guests = $GuestCount
    $GlobalAuditSummary.Users.Inactive = $InactiveCount
    $GlobalAuditSummary.Users.Enabled = $EnabledCount
    $GlobalAuditSummary.Users.MfaCapable = $MfaCapCount
    $GlobalAuditSummary.Users.OnPrem = $OnPremCount

    # Group and summarize
    $buckets | Group-Object | ForEach-Object {
        $GlobalAuditSummary.Users.SignInActivity[$_.Name] = $_.Count
    }

    #Dump data for QA checks
    if ($QAMode) {
        $AllUsersDetails | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputFolder\QA_AllUsersDetails.json" -Encoding utf8
    }

    $PmEndTasks.Stop()
    if ($PmScript.IsRunning) {
        $PmScript.Stop()
    }
    Write-Log -Level Debug -Message "=== Performance Summary ==="
    Write-Log -Level Debug -Message ("Init Tasks:           {0:N2} s" -f $PmInitTasks.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Data Collection:      {0:N2} s" -f $PmDataCollection.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Data Processing:      {0:N2} s" -f $PmDataProcessing.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Post-Processing:      {0:N2} s" -f $PmDataPostProcessing.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Generating Details:   {0:N2} s" -f $PmGeneratingDetails.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("Writing Reports:      {0:N2} s" -f $PmWritingReports.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("EndTasks:             {0:N2} s" -f $PmEndTasks.Elapsed.TotalSeconds)
    Write-Log -Level Debug -Message ("-------------------------------")
    Write-Log -Level Debug -Message ("Total Script Time:    {0:N2} s" -f $PmScript.Elapsed.TotalSeconds)

}
