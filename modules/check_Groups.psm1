<#
	.SYNOPSIS
	   Enumerates groups and evaluates their configurations, ownership, roles, and risk posture.
#>

function Invoke-CheckGroups {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][int]$HTMLMemberLimit = 20,
        [Parameter(Mandatory=$false)][int]$LimitResults,
        [Parameter(Mandatory=$false)][int]$HTMLNestedGroupsLimit = 40,
        [Parameter(Mandatory=$false)][switch]$SkipAutoRefresh = $false,
        [Parameter(Mandatory=$false)][switch]$QAMode = $false,
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][Object[]]$ConditionalAccessPolicies,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][hashtable]$Devices,
        [Parameter(Mandatory=$true)][hashtable]$AllUsersBasicHT,
        [Parameter(Mandatory=$true)][hashtable]$AgentObjectBasics,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Function section ########################

    # Normalize non-user owners/members so agent-backed service principals can share the same flow.
    function CheckSP {
        param($Object)

        # Resolve mixed directory objects through the shared typed lookup instead of assuming every non-user object is a generic service principal.
        $rawType = if ($Object.PSObject.Properties['RawType']) { $Object.RawType } else { '#microsoft.graph.servicePrincipal' }
        $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $Object.Id -RawType $rawType -CurrentTenant $CurrentTenant -AllUsersBasicHT $AllUsersBasicHT -AllGroupsDetails @{} -ServicePrincipalBasics $AllSPBasicHT -AgentObjectBasics $AgentObjectBasics
        if (-not $resolvedObject) { return }

        [PSCustomObject]@{
            Id            = $resolvedObject.Id
            DisplayName   = $resolvedObject.DisplayName
            Foreign       = $resolvedObject.Foreign
            PublisherName = $resolvedObject.PublisherName
            OwnerKind     = $resolvedObject.ObjectKind
            TargetReport  = $resolvedObject.TargetReport
            SPType        = $resolvedObject.ServicePrincipalType
            DefaultMS     = $resolvedObject.DefaultMS
        }
    }   

    #Function to create transitive members
    function Get-TransitiveMembers {
        param (
            [string]$GroupId,
            [hashtable]$AdjList,
            [hashtable]$VisitedGlobal
        )

        $Transitive = [System.Collections.Generic.List[object]]::new()
        $Stack = [System.Collections.Stack]::new()
        $VisitedLocal = @{}

        $Stack.Push($GroupId)
        while ($Stack.Count -gt 0) {
            $Current = $Stack.Pop()
            if (-not $VisitedLocal.ContainsKey($Current)) {
                $VisitedLocal[$Current] = $true
                if ($AdjList.ContainsKey($Current)) {
                    foreach ($memberObj in $AdjList[$Current]) {
                        $memberId = $memberObj.id
                        $memberType = $memberObj.'@odata.type'

                        if ($VisitedGlobal.ContainsKey($memberId)) { continue }
                        $VisitedGlobal[$memberId] = $true

                        if ($memberType -eq "#microsoft.graph.group") {
                            $Stack.Push($memberId)
                            $Transitive.Add($memberObj)
                        } else {
                            $Transitive.Add($memberObj)
                        }
                    }
                }
            }
        }
        return $Transitive
    }

    #Function to create transitive parents
    $TransitiveParentCache = @{}

    function Get-TransitiveParentsCached {
        param (
            [string]$GroupId,
            [hashtable]$ReverseAdjList,
            [hashtable]$AllGroupsHT
        )
    
        if ($TransitiveParentCache.ContainsKey($GroupId)) {
            return $TransitiveParentCache[$GroupId]
        }
    
        $Visited = @{}
        $Stack = New-Object System.Collections.Stack
        $ResultHT = @{}
    
        $Stack.Push($GroupId)
        while ($Stack.Count -gt 0) {
            $Current = $Stack.Pop()
    
            if (-not $Visited.ContainsKey($Current)) {
                $Visited[$Current] = $true
    
                if ($ReverseAdjList.ContainsKey($Current)) {
                    foreach ($parent in $ReverseAdjList[$Current]) {
                        $parentId = $parent.id
    
                        if ($AllGroupsHT.ContainsKey($parentId)) {
                            # Only add to result if not already added
                            if (-not $ResultHT.ContainsKey($parentId)) {
                                $ResultHT[$parentId] = $AllGroupsHT[$parentId]
                            }
    
                            # Continue walking up only if we haven’t seen this parent
                            if (-not $Visited.ContainsKey($parentId)) {
                                $Stack.Push($parentId)
                            }
                        }
                    }
                }
            }
        }
    
        # Cache the result
        $TransitiveParentCache[$GroupId] = $ResultHT.Values
        return $ResultHT.Values
    }


    $NestedGroupCache = @{}
    function Expand-NestedGroups-Cached {
        param (
            [Parameter(Mandatory = $true)]
            [object]$StartGroup,
    
            [Parameter(Mandatory = $true)]
            [hashtable]$GroupLookup,
    
            [Parameter(Mandatory = $true)]
            [System.Management.Automation.PSCmdlet]$CallerPSCmdlet
        )
    
        # Return cached if available
        if ($NestedGroupCache.ContainsKey($StartGroup.Id)) {
            return $NestedGroupCache[$StartGroup.Id]
        }
    
        $allNestedGroups = [System.Collections.Generic.List[object]]::new()
        $toProcess = [System.Collections.Queue]::new()
        $visited = [System.Collections.Generic.HashSet[string]]::new()
    
        $null = $toProcess.Enqueue($StartGroup)
        $null = $visited.Add($StartGroup.Id)
    
        while ($toProcess.Count -gt 0) {
            $current = $toProcess.Dequeue()
    
            $nestedGroups = $current.NestedGroupsDetails
            if ($null -eq $nestedGroups -or $nestedGroups.Count -eq 0) { continue }
    
            foreach ($nested in $nestedGroups) {
                $nestedId = $nested.Id
                if (-not $nestedId) { continue }
    
                if ($visited.Add($nestedId)) {
                    $resolvedGroup = $GroupLookup[$nestedId]
                    if ($resolvedGroup) {
                        $allNestedGroups.Add($resolvedGroup)
                        $toProcess.Enqueue($resolvedGroup)
                    }
                }
            }
        }
    
        $NestedGroupCache[$StartGroup.Id] = $allNestedGroups
        return $allNestedGroups
    }

    ############################## Script section ########################
    $PmScript = [System.Diagnostics.Stopwatch]::StartNew()
    $PmInitTasks = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Log -Level Verbose -Message "Start group script"

    # Check token and trigger refresh if required
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    # Define basic variables
    $Title = "Groups"
    $ProgressCounter = 0
    $TokenCheckLimit = 5000  # Define recheck limit for token lifetime. In large environments the access token might expire during the test.
    $GroupScriptWarningList = [System.Collections.Generic.List[string]]::new()
    $NestedGroupsHighvalue = [System.Collections.Generic.List[object]]::new()
	$AllGroupsDetails = [System.Collections.Generic.List[object]]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $EscapedTenantName = $CurrentTenant.FileSafeDisplayNameEncoded

    if (-not $GLOBALGraphExtendedChecks) {$GroupScriptWarningList.Add("Coverage gap: eligible role assignments not assessed; only active assignments are included.")}

    $GroupImpactScore = @{
        "M365Group"                 = 1
        "HiddenGAL"                 = 1 
        "Distribution"              = 0.5
        "SecurityEnabled"           = 2
        "AzureRole"                 = 100
        "AppRole"                   = 10
        "CAP"                       = 50
    }
    $GroupLikelihoodScore = @{
        "PublicM365Group"           = 100
        "Member"                    = 0.1
        "DirectOwnerCloud"          = 1
        "DirectOwnerOnprem"         = 2
        "PIMforGroupsOwnersGroup"   = 3
        "NestedGroup"               = 2
        "DynamicGroup"              = 5
        "DynamicGroupDangerous"     = 20
        "ExternalSPMemberOwner"     = 50
        "InternalSPMemberOwner"     = 5
        "BaseNotProtected"          = 5
        "GuestMemberOwner"          = 5
    }

    
    if ($TenantPimForGroupsAssignments) {
        Write-Log -Level Verbose -Message "Processing $($TenantPimForGroupsAssignments.Count) PIM for Groups Assignments"
        # Hashtable for all owners for faster lookup in each group
        $PimForGroupsEligibleOwnersHT = @{}
        $PimForGroupsEligibleOwnerParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "owner") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleOwnersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleOwnersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }
        
                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        UserType         =      $assignment.UserType
                        type                  = $assignment.Type
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        type               = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }

                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }
                    
                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group has ownership of
                    if (-not $PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] += $ParentInfo

                } else {
                    #This should never be triggered
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }
        
                # Add the object to the array for that groupId
                $PimForGroupsEligibleOwnersHT[$assignment.groupId] += $OwnerInfo
            }
        }

        # Hashtable for all members for faster lookup in each group
        $PimForGroupsEligibleMembersHT = @{}
        $PimForGroupsEligibleMemberParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "member") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleMembersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleMembersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }
                
                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        UserType         =      $assignment.UserType
                        type                  = $assignment.Type
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                    
                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }

                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group is nested in
                    if (-not $PimForGroupsEligibleMemberParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] += $ParentInfo

                } else {
                    #Fallback: This should never be triggered
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }
        
                # Add the object to the array for that groupId
                $PimForGroupsEligibleMembersHT[$assignment.groupId] += $MemberInfo
 
            }
        }

    }

    # Build the lookup for AU Units
    $GroupToAUMap = @{}

    foreach ($au in $AdminUnitWithMembers) {
        $members = $au.MembersGroup

        if ($members -is [System.Collections.IDictionary]) {
            $members = @($members)
        }

        foreach ($member in $members) {
            $id = $member.id
            if ($null -ne $id) {
                if (-not $GroupToAUMap.ContainsKey($id)) {
                    $GroupToAUMap[$id] = [System.Collections.Generic.List[object]]::new()
                }

                $auLite = [pscustomobject]@{
                    DisplayName                  = $au.DisplayName
                    IsMemberManagementRestricted = $au.IsMemberManagementRestricted
                }

                $GroupToAUMap[$id].Add($auLite)
            }
        }
    }

    $PmInitTasks.Stop()
    ########################################## SECTION: DATACOLLECTION ##########################################
    $PmDataCollection = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "[*] Get Groups"
    $QueryParameters = @{ 
        '$select' = 'Id,DisplayName,Visibility,GroupTypes,SecurityEnabled,IsAssignableToRole,OnPremisesSyncEnabled,MailEnabled,Description,MembershipRule'
        '$top' = $ApiTop
    }
    $AllGroups = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/groups' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $GroupsTotalCount = @($AllGroups).Count
    Write-Host "[+] Got $($GroupsTotalCount) groups"

    #Abort if no groups are present
    if (@($AllGroups).count -eq 0) {
        $AllGroupsDetailsHT = @{}
        Return $AllGroupsDetailsHT
    }
    


    #Build Hashtable with basic group info. Needed in nesting scenarios to git information about parent / child group
    $AllGroupsHT = @{}
    foreach ($group in $AllGroups) {
        $id = $group.id
        $DisplayName = $group.DisplayName
        $securityEnabled = $group.securityEnabled
        $isAssignableToRole = if ($null -eq $group.isAssignableToRole) { $false } else { $group.isAssignableToRole }

        $AllGroupsHT[$id] = [PSCustomObject]@{
            id           = $id
            DisplayName    = $DisplayName
            securityEnabled     = $securityEnabled
            isAssignableToRole  = $isAssignableToRole
        }
    }

    # Check if Azure IAM roles were checked
    if (-not ($GLOBALAzurePsChecks)) {
        if ($GLOBALAzureIamWarningText) {
            $GroupScriptWarningList.Add($GLOBALAzureIamWarningText)
        } else {
            $GroupScriptWarningList.Add("Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to groups are therefore missing from this report.")
        }
    }

    #Check if CAP have been assessed
    if (-not ($GLOBALPermissionForCaps)) {
        $GroupScriptWarningList.Add("Coverage gap: Conditional Access group assignments not assessed; CAP relations may be missing.")
    }

    #Check if PIM for groups was checked
    if (-not ($GLOBALPimForGroupsChecked)) {
        $GroupScriptWarningList.Add("Coverage gap: PIM for Groups not assessed; eligible group owners/members are therefore missing from this report.")
    }

    Write-Host "[*] Getting all group memberships"
    $GroupMembers = @{}
    $DirectActiveMemberCountById = @{}
    $BatchSize = 10000
    $ChunkCount = [math]::Ceiling($GroupsTotalCount / $BatchSize)
    
    for ($chunkIndex = 0; $chunkIndex -lt $ChunkCount; $chunkIndex++) {
        Write-Log -Level Verbose -Message "Processing batch $($chunkIndex + 1) of $ChunkCount..."                  
    
        $StartIndex = $chunkIndex * $BatchSize
        $EndIndex = [math]::Min($StartIndex + $BatchSize - 1, $GroupsTotalCount - 1)
        $GroupBatch = $AllGroups[$StartIndex..$EndIndex]
        $Requests = New-Object System.Collections.Generic.List[Hashtable]
        foreach ($group in $GroupBatch) {
            $req = @{
                "id"     = $group.id
                "method" = "GET"
                "url"    = "/groups/$($group.id)/members"
            }
            $Requests.Add($req)
        }
    
        # Send the batch
        $Response = Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id,userType,onPremisesSyncEnabled' ;'$top'= $ApiTop}

        # Store results
        foreach ($item in $Response) {
            $groupResponseId = [string]$item.id
            $directMembers = @($item.response.value)
            $DirectActiveMemberCountById[$groupResponseId] = $directMembers.Count
            if ($directMembers.Count -gt 0) {
                $GroupMembers[$groupResponseId] = $directMembers
            }
        }
    }


    foreach ($group in $GroupMembers.Values) {
        $TotalGroupMembers += $group.Count
    }
    Write-Log -Level Verbose -Message "Got $TotalGroupMembers direct member relationships"
    Write-Log -Level Verbose -Message "Build transitive member relationships"

    # Build transitive members for each group
    $TransitiveMembersRaw = @{}
    foreach ($groupId in $GroupMembers.Keys) {
        $Visited = @{}
        $TransitiveMembersRaw[$groupId] = Get-TransitiveMembers -GroupId $groupId -AdjList $GroupMembers -VisitedGlobal $Visited
    }

    $TotalTransitiveMemberRelations = 0
    foreach ($members in $TransitiveMembersRaw.Values) {
        $TotalTransitiveMemberRelations += $members.Count
    }

    Write-Log -Level Verbose -Message "Calculated $TotalTransitiveMemberRelations transitive member relationships"
    #Show warning in large tenants
    if (-not $LimitResults) {
        if ($TotalTransitiveMemberRelations -ge 1500000 -or $GroupsTotalCount -ge 100000) {
            Write-Warning "In large tenants, consider using -LimitResults (e.g., 30000) to reduce report size and improve report building performance."
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group ownerships"
    #Get owners of all groups for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllGroups) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    =   "/groups/$($item.id)/owners"
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id,userType,onPremisesSyncEnabled'})
    $GroupOwnersRaw = @{}
    $DirectActiveOwnerCountById = @{}
    foreach ($item in $RawResponse) {
        $groupResponseId = [string]$item.id
        $directOwners = @($item.response.value)
        $DirectActiveOwnerCountById[$groupResponseId] = $directOwners.Count
        if ($directOwners.Count -gt 0) {
            $GroupOwnersRaw[$groupResponseId] = $directOwners
        }
    }

    Write-Log -Level Debug -Message "Got $($GroupOwnersRaw.Count) group ownerships"

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group app role assignments"
    #Get group AppRole Assignments of all groups for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllGroups) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    =   "/groups/$($item.id)/appRoleAssignments"
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'ResourceDisplayName,ResourceId,AppRoleId' ;'$top'= $ApiTop})
    $AppRoleAssignmentsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppRoleAssignmentsRaw[$item.id] = $item.response.value
        }
    }

    Write-Log -Level Debug -Message "Got $($AppRoleAssignmentsRaw.Count) app group role assignments"

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
    
    Write-Host "[*] Calculate all group-to-parent-group relationships"
    
    # Build reverse group membership map: child -> parent
    $ReverseGroupMembershipMap = @{}
    foreach ($parentGroupId in $GroupMembers.Keys) {
        foreach ($member in $GroupMembers[$parentGroupId]) {
            if ($member.'@odata.type' -eq '#microsoft.graph.group') {
                $childGroupId = $member.id

                if (-not $ReverseGroupMembershipMap.ContainsKey($childGroupId)) {
                    $ReverseGroupMembershipMap[$childGroupId] = [System.Collections.Generic.List[object]]::new()
                }

                if ($AllGroupsHT.ContainsKey($parentGroupId)) {
                    $ReverseGroupMembershipMap[$childGroupId].Add($AllGroupsHT[$parentGroupId])
                }
            }
        }
    }   

    $GroupNestedInRaw = @{}
    foreach ($group in $AllGroups) {
        $parents = Get-TransitiveParentsCached -GroupId $group.id -ReverseAdjList $ReverseGroupMembershipMap -AllGroupsHT $AllGroupsHT
        if (@($parents).Count -gt 0) {
            $GroupNestedInRaw[$group.id] = $parents
        }
    }

    Write-Log -Level Debug -Message "Got $($GroupNestedInRaw.Count) groups with parent group relationship"


    #Basic ServicePrincipal Info to avoid storing the information in a large object
    $QueryParameters = @{
        '$select' = "id,displayName,accountEnabled,appOwnerOrganizationId,publisherName,servicePrincipalType"
        '$top' = $ApiTop
    }
    $RawResponse = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $AllSPBasicHT = @{}
    foreach ($app in $RawResponse) {
        $AllSPBasicHT[$app.id] = $app
    }
    

    #Remove Variables
    remove-variable parents -ErrorAction SilentlyContinue
    remove-variable RawResponse -ErrorAction SilentlyContinue
    remove-variable Requests -ErrorAction SilentlyContinue
    remove-variable GroupMembers -ErrorAction SilentlyContinue
    
    $PmDataCollection.Stop()
    ########################################## SECTION: Group Processing ##########################################
    $PmDataProcessing = [System.Diagnostics.Stopwatch]::StartNew()

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($GroupsTotalCount / 10), 1)
    Write-Host "[*] Status: Processing group 1 of $GroupsTotalCount (updates every $StatusUpdateInterval groups)..."

    #region Processing Loop
    # Loop through each group and get additional info
    foreach ($group in $AllGroups) {     

        #Loop init section
        $ProgressCounter++
        $ImpactScore = 0
        $EligibleRoleImpactContribution = 0 # Downstream objects should inherit group impact without eligible/PIM role impact.
        $LikelihoodScore = 0
        $Warnings = [System.Collections.Generic.HashSet[string]]::new()
        $ownerGroup = @()
        $PfGOwnedGroups = @()
        $GroupNestedIn = [System.Collections.Generic.List[psobject]]::new()
        $AppRoleAssignments = [System.Collections.Generic.List[object]]::new()
		$AzureRoleDetails = @()
        $RoleCount = 0
        $RolePrivilegedCount = 0
        $roleDetails = [System.Collections.Generic.List[object]]::new()

        # Check the token lifetime after a specific amount of objects
        if (($ProgressCounter % $TokenCheckLimit) -eq 0 -and $SkipAutoRefresh -eq $false) {
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
        }

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $GroupsTotalCount) {
            Write-Host "[*] Status: Processing group $ProgressCounter of $GroupsTotalCount..."
        }

        #Find parent groups if actual group
        if ($GroupNestedInRaw.ContainsKey($group.Id)) {
            foreach ($member in $GroupNestedInRaw[$group.Id]) {
                $GroupNestedIn.Add([PSCustomObject]@{
                    Id              = $member.id
                    AssignmentType  = 'Active'
                    EntraRoles = 0 #Might be changed in post processing
                    AzureRoles = 0 #Might be changed in post processing
                    CAPs = 0 #Might be changed in post processing
                })
            }
        }

        
        #Check if group has an app role
        if ($AppRoleAssignmentsRaw.ContainsKey($group.Id)) {
            foreach ($AppRole in $AppRoleAssignmentsRaw[$group.Id]) {
                $AppRoleAssignments.Add([PSCustomObject]@{
                    ResourceDisplayName = $AppRole.ResourceDisplayName
                    ResourceId     = $AppRole.ResourceId
                    AppRoleId = $AppRole.AppRoleId
                })
            }
        }
        
		# Initialize ArrayLists
        $memberUser    = [System.Collections.Generic.List[psobject]]::new()
        $memberGroup   = [System.Collections.Generic.List[psobject]]::new()
        $memberSP      = [System.Collections.Generic.List[psobject]]::new()
        $memberDevices = [System.Collections.Generic.List[psobject]]::new()
        $owneruser     = [System.Collections.Generic.List[psobject]]::new()
        $ownersp       = [System.Collections.Generic.List[psobject]]::new()
        $baseOwnerUserDetails = [System.Collections.Generic.List[psobject]]::new()
        $groupIdKey = [string]$group.Id
        $DirectActiveMemberCount = if ($null -ne $DirectActiveMemberCountById -and $DirectActiveMemberCountById.ContainsKey($groupIdKey)) { [int]$DirectActiveMemberCountById[$groupIdKey] } else { 0 }
        $DirectActiveOwnerCount = if ($null -ne $DirectActiveOwnerCountById -and $DirectActiveOwnerCountById.ContainsKey($groupIdKey)) { [int]$DirectActiveOwnerCountById[$groupIdKey] } else { 0 }

        # Process group members
        if ($TransitiveMembersRaw.ContainsKey($group.Id)) {
            foreach ($member in $TransitiveMembersRaw[$group.Id]) {
                switch ($member.'@odata.type') {
        
                    '#microsoft.graph.user' {
                        [void]$memberUser.Add(
                            [PSCustomObject]@{
                                Id                    = $member.Id
                                userType              = $member.userType
                                onPremisesSyncEnabled = $member.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.agentUser' {
                        [void]$memberUser.Add(
                            [PSCustomObject]@{
                                Id                    = $member.Id
                                userType              = $member.userType
                                onPremisesSyncEnabled = $member.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.group' {

                        [void]$memberGroup.Add(
                            [PSCustomObject]@{
                                Id             = $member.Id
                                AssignmentType = 'Active'
                            }
                        )
                    }
        
                    '#microsoft.graph.servicePrincipal' {
                        [void]$memberSP.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                                RawType = $member.'@odata.type'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        [void]$memberSP.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                                RawType = $member.'@odata.type'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        [void]$memberSP.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                                RawType = $member.'@odata.type'
                            }
                        )
                    }
        
                    '#microsoft.graph.device' {
                        [void]$memberDevices.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                            }
                        )
                    }
                }
            }
        }

        #Process group owners
        if ($GroupOwnersRaw.ContainsKey($group.Id)) {
            foreach ($Owner in $GroupOwnersRaw[$group.Id]) {
                switch ($Owner.'@odata.type') {
        
                    '#microsoft.graph.user' {
                        $ownerUserEntry = [PSCustomObject]@{
                            Id                    = $Owner.Id
                            userType              = $Owner.userType
                            onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                            AssignmentType        = 'Active'
                        }

                        [void]$owneruser.Add($ownerUserEntry)
                        [void]$baseOwnerUserDetails.Add(
                            [PSCustomObject]@{
                                Id                    = $Owner.Id
                                onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.agentUser' {
                        $ownerUserEntry = [PSCustomObject]@{
                            Id                    = $Owner.Id
                            userType              = $Owner.userType
                            onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                            AssignmentType        = 'Active'
                        }

                        [void]$owneruser.Add($ownerUserEntry)
                        [void]$baseOwnerUserDetails.Add(
                            [PSCustomObject]@{
                                Id                    = $Owner.Id
                                onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$ownersp.Add(
                            [PSCustomObject]@{
                                Id = $Owner.Id
                                RawType = $Owner.'@odata.type'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        [void]$ownersp.Add(
                            [PSCustomObject]@{
                                Id = $Owner.Id
                                RawType = $Owner.'@odata.type'
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        [void]$ownersp.Add(
                            [PSCustomObject]@{
                                Id = $Owner.Id
                                RawType = $Owner.'@odata.type'
                            }
                        )
                    }
        
                    default {
                        # Optional: log or handle unexpected owner types
                        Write-host "Unknown owner type: $($Owner.'@odata.type') for group $($group.Id)"
                    }
                }
            }
        }

       #Process pim for groups. Assignments will be added to the normal $memberGroup, $memberUser, $owneruser array and proccessed like active assignments
        if ($TenantPimForGroupsAssignments) {

            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleOwnersHT.ContainsKey($group.Id)) {
                # Retrieve all owners for this group
                $PfGownersGroup = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "group" })
                $PfGownersUser = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "user" })
                
                # Merge with normal owner list
                foreach ($user in $PfGownersUser) {
                    [void]$owneruser.Add($user)
                }
                $ownerGroup = $PfGownersGroup
            }

            #Find groups where this group is an eligible owner
            if ($PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($group.Id)) {
                $PfGOwnedGroupsRaw = @($PimForGroupsEligibleOwnerParentGroupHT[$group.Id])
                $PfGOwnedGroups = foreach ($OwnedGroup in $PfGOwnedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($OwnedGroup.Id)) {
                        $info = $AllGroupsHT[$OwnedGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $OwnedGroup.Id
                            DisplayName         = $OwnedGroup.DisplayName
                            AssignmentType      = $OwnedGroup.AssignmentType
                            SecurityEnabled     = $info.SecurityEnabled
                            isAssignableToRole  = $info.isAssignableToRole
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }
             }

            
            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleMembersHT.ContainsKey($group.Id)) {
                # Retrieve all members of the groups for this group
				 foreach ($pimMember in $PimForGroupsEligibleMembersHT[$group.Id]) {
					if ($pimMember.type -eq "group") { [void]$memberGroup.Add($pimMember) }
					elseif ($pimMember.type -eq "user") { [void]$memberUser.Add($pimMember) }
				}
            }

            #Find groups where this group is an eligible member
            if ($PimForGroupsEligibleMemberParentGroupHT.ContainsKey($group.Id)) {
                $PfGnestedGroupsRaw = @($PimForGroupsEligibleMemberParentGroupHT[$group.Id])
                $PfGnestedGroups = foreach ($ParentGroup in $PfGnestedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($ParentGroup.Id)) {
                        $info = $AllGroupsHT[$ParentGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $ParentGroup.Id
                            AssignmentType      = $ParentGroup.AssignmentType
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }
                
                # Merge with normal nested list
                foreach ($item in $PfGnestedGroups) {
                    $GroupNestedIn.Add($item)
                }
            }       
        }

        # If PIM for Group has been evaluated: Check if group is onboarded in PIM for Groups
        $PIM = if (-not $GLOBALPimForGroupsChecked) {
            "?"
        } elseif ($GLOBALPimForGroupsHT -and $GLOBALPimForGroupsHT.ContainsKey($group.Id)) {
            $true
        } else {
            $false
        }
   

        #Count the owners to show in table
        $ownersynced = 0
        foreach ($user in $owneruser) {
            if ($user.onPremisesSyncEnabled -eq $true) {
                $ownersynced++
            }
        }

        #check guest counts
        $GuestsCount = 0
        foreach ($user in $memberUser) {
            if ($user.userType -eq 'Guest') {
                $GuestsCount++
            }
        }

        #Get details for service principals
        $memberSpDetails = foreach ($object in $memberSP) {
            CheckSP $object
        }
        $ownerSpDetails = foreach ($object in $ownersp) {
            CheckSP $object
        }

        # Determine group type
        if ($group.GroupTypes -eq "Unified") {
            $groupType = "M365 Group"
            $ImpactScore += $GroupImpactScore["M365Group"]
        } elseif ($group.SecurityEnabled -eq $false -and $group.MailEnabled -eq $true) {
            $groupType = "Distribution"
            $ImpactScore += $GroupImpactScore["Distribution"]
        } else {
            $groupType = "Security Group"
        }

        # Check if dynamic
        if ($group.GroupTypes -eq "DynamicMembership") {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $true
        } else {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $false
        }

        # Add visibility default value if empty
        If ($null -eq $group.Visibility) {
            $group.Visibility = "Private"
        }

        # Add sync default value if empty
        If ($null -eq $group.OnPremisesSyncEnabled) {
            $group.OnPremisesSyncEnabled = $false
        }

        # For all security enabled groups check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            if ($group.SecurityEnabled -eq $true) {
                
                    #Use function to get the Azure Roles for each object
                    $azureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $group.Id

                    # Update the Roles property only if there are matching roles
                    $AzureRoleCount = @($azureRoleDetails).Count
                } else {
                $AzureRoleCount = 0
            }
        } else {
            $AzureRoleCount = "?"
        }



        # Check if the group is assignable to a role
        if ($group.IsAssignableToRole -eq $true) {

            # Find matching roles in $TenantRoleAssignments where the PrincipalId matches the group's Id
            $MatchingRoles = $TenantRoleAssignments[$group.Id]
            
            # Array to hold the role information for this group
            $roleDetails = [System.Collections.Generic.List[object]]::new()

            foreach ($role in $MatchingRoles) {
                $roleInfo = [PSCustomObject]@{
                    DisplayName       = $role.DisplayName
                    Id                = $role.Id
                    AssignmentType    = $role.AssignmentType
                    IsPrivileged      = $role.IsPrivileged
                    RoleTier          = $role.RoleTier
                    IsEnabled         = $role.IsEnabled
                    IsBuiltIn         = $role.IsBuiltIn
                    DirectoryScopeId  = $role.DirectoryScopeId
                    ScopeResolved     = $role.ScopeResolved
                }
                # Add the role information to the RoleDetails array
                $roleDetails.Add($roleInfo)
            }

            # Update the Roles property only if there are matching roles
            if ($roleDetails.Count -gt 0) {
                $RoleCount = $roleDetails.Count
                $RolePrivilegedCount = @($roleDetails | Where-Object { $_.IsPrivileged -eq $true }).Count
            }

        } else {
            $RoleCount = 0
            $RolePrivilegedCount  = 0
            $roleDetails = [System.Collections.Generic.List[object]]::new()
            $group.IsAssignableToRole = $false
        }

        # Determine highest assigned role tier labels for Entra and Azure
        $EntraMaxTier = Get-HighestTierLabel -Assignments $roleDetails
        $AzureMaxTier = if ($GLOBALAzurePsChecks) { Get-HighestTierLabel -Assignments $AzureRoleDetails } else { "?" }

        #Check AU assignment
        $GroupAdminUnits = [System.Collections.Generic.List[object]]::new()
        if ($GroupToAUMap.ContainsKey($group.Id)) {
            $GroupAdminUnits = $GroupToAUMap[$group.Id]
            if ($GroupAdminUnits | Where-Object { $_.IsMemberManagementRestricted }) {
                [void]$Warnings.Add("Group protected by restricted AU")
            }
        }

        # Check if the script has permission to enumerate CAPs
        if ($GLOBALPermissionForCaps) {

            # Initialize a list to store CAP information for this group
            $groupCAPs = [System.Collections.Generic.List[object]]::new()

            # Loop through each conditional access policy in $CapGroups
            foreach ($cap in $ConditionalAccessPolicies) {
                # Check if the group ID is in the ExcludedGroup or IncludedGroup of the CAP
                $isExcluded = $cap.ExcludedGroup -contains $group.Id
                $isIncluded = $cap.IncludedGroup -contains $group.Id

                if ($isExcluded -or $isIncluded) {

                    # Determine if the group is "Included" or "Excluded"
                    $groupUsage = if ($isExcluded) { "Excluded" } elseif ($isIncluded) { "Included" }

                    # Add CAP information to the list for this group
                    $groupCAPs.Add([PSCustomObject]@{
                        Id         = $cap.Id
                        CAPName    = $cap.CAPName
                        CAPExOrIn  = $groupUsage
                        CAPStatus  = $cap.CAPStatus
                    })
                }
            }

            # Add the CAP information to the group properties if any CAPs were found
            if ($groupCAPs.Count -ge 1) {
                $CAPCount = $groupCAPs.Count
            } else {
                $CAPCount = 0
                $groupCAPs = $null

            }
        } else {
            # If no permission for CAPs, set CAPCount to "?"
            $CAPCount = "?"
        }



    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
        if ($GLOBALAzurePsChecks -and $AzureRoleCount -ge 1) {

            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            [void]$Warnings.Add($AzureRolesProcessedDetails.Warning)
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
            $AzureRoleScore = $AzureRolesProcessedDetails.ImpactScore

            # Remove eligible Azure role contribution from inherited group impact only.
            $EligibleRoleImpactContribution += $AzureRolesProcessedDetails.EligibleImpactScore

            #Add group to list for re-processing
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with AzureRole"
	                "AzureRoles" = $AzureRoleCount
                    "Score" = $AzureRoleScore
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of with AzureRole"
                    "AzureRoles" = $AzureRoleCount
	                "Score" = $AzureRoleScore
	                "TargetGroups" = $ownerGroup.Id
	            })
            }
        }


        #Direct owner
        if ($owneruser.count -ge 1) {

            #Check if there is an owner synced from on-prem
            if ($owneruser.onPremisesSyncEnabled -contains $true) {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerOnprem"]
            } else {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerCloud"]
            }
        }

        #PimForGroupsOwners
        if (@($ownerGroup).count -ge 1) {
            $LikelihoodScore += $GroupLikelihoodScore["PIMforGroupsOwnersGroup"]
        }

        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if ($RoleCount -ge 1) {
            Write-Log -Level Trace -Message "Processing group $($group.DisplayName) with $RoleCount role assignments"
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $RoleDetails
            [void]$Warnings.Add($EntraRolesProcessedDetails.Warning)
            $ImpactScore += $EntraRolesProcessedDetails.ImpactScore
            $RoleScore = $EntraRolesProcessedDetails.ImpactScore

            # Remove eligible Entra role contribution from inherited group impact only.
            $EligibleRoleImpactContribution += $EntraRolesProcessedDetails.EligibleImpactScore
        }

        if ($RoleCount -ge 1) {
            #Add group to list for re-processing 
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $ownerGroup.Id
	            })
            }
        }


        #Check if groups can be modified by low-tier admins or SPs
        if ($group.OnPremisesSyncEnabled -or $group.IsAssignableToRole -or $GroupAdminUnits.IsMemberManagementRestricted -contains $true) {
            $Protected = $true
        } else {
            $Protected = $false
            $LikelihoodScore += $GroupLikelihoodScore["BaseNotProtected"] #Group base score if not protected
        }


        #Check if assigned to Caps
        if ($CAPCount -ge 1) {
            $ImpactScore += $GroupImpactScore["CAP"]
            if ($group.IsAssignableToRole -eq $true) {
                [void]$Warnings.Add("Group is used in CAP")
            } elseif ($group.Dynamic -eq $true) {
                [void]$Warnings.Add("Group is used in CAP and is dynamic")
            } elseif ($group.OnPremisesSyncEnabled -eq $true) {
                [void]$Warnings.Add("Group is used in CAP and from on-prem")
            } elseif ($group.Visibility -eq "Public" -and $group.Dynamic -eq $false -and $grouptype -contains "M365 Group") {
                [void]$Warnings.Add("Public M365 group in CAP")
            } elseif (-not $Protected) {
                [void]$Warnings.Add("Group is used in CAP and is not protected")
            }

            #Add group to list for re-processing
            $score = $GroupImpactScore["CAP"]
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $ownerGroup.Id
	            })
            }
            
        }

        #Check if M365 group is public
        if ($group.visibility -eq "Public" -and $grouptype -eq "M365 Group" -and $group.Dynamic -eq $false) {
            If ($group.SecurityEnabled) {
                [void]$Warnings.Add("Public security enabled M365 group")
            } else {
                [void]$Warnings.Add("Public M365 group")
            }

            $LikelihoodScore += $GroupLikelihoodScore["PublicM365Group"]

            if ($AppRoleAssignments.count -ge 1) { 
                [void]$Warnings.Add("Used for AppRoles")
            }       
        }

        #Check for guests as owner
        if ($owneruser.userType -contains "Guest") {
            [void]$Warnings.Add("Guest as owner")
            $LikelihoodScore += $GroupLikelihoodScore["GuestMemberOwner"]
        }

        #Check if group is dynamic
        if ($group.Dynamic -eq $true) {
            if ($AppRoleAssignments.count -ge 1) { 
                $ForAppRoles = " used for AppRoles"
            } else {
                $ForAppRoles = ""
            }

            #Search for potential dangerous queries
            if ($group.MembershipRule -match "user.userPrincipalName " -or $group.MembershipRule -match "user.otherMail " -or $group.MembershipRule -match "user.mail" -or $group.MembershipRule -match "user.PreferredLanguage" -or $group.MembershipRule -match "user.MobilePhone" -or $group.MembershipRule -match "user.BusinessPhones") {
                $DangerousQuery = "with potentially dangerous query"
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroupDangerous"]
            } else {
                $DangerousQuery = ""
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroup"]
            }
            [void]$Warnings.Add("Dynamic group $DangerousQuery $ForAppRoles")
        }

        #Check app roles
        if ($AppRoleAssignments.count -ge 1) {
            $ImpactScore += $GroupImpactScore["AppRole"]
        }

        #SP as member
        if ($memberSP.count -ge 1) {
            if ($memberSpDetails.Foreign -contains $true -and $memberSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("External (non-MS) SP as member")
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($memberSpDetails.Foreign -contains $false -and $memberSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("Internal SP as member")
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            } else {
                $LikelihoodScore += 1
            }
        }

        #SP as owner
        if (@($ownersp).count -ge 1) {
            if ($ownerSpDetails.Foreign -contains $true -and $ownerSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("External (non-MS) SP as owner")
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($ownerSpDetails.Foreign -contains $false -and $ownerSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("Internal SP as owner")
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            }
        }

        #Has members
		$MemberUserCount = $memberuser.count
        if ($MemberUserCount -ge 1) {
            # Use Square Root Scaling to avoid likelihood inflation in large tenants
            $LikelihoodScore += [math]::Sqrt($MemberUserCount) * $GroupLikelihoodScore["Member"]
        }

        #Is security enabled and has any members/owners, is dynamic etc
        if ($group.SecurityEnabled) {
            $ImpactScore += $GroupImpactScore["SecurityEnabled"]
        }
        
        
        #Format warning messages
        $Warnings = ($Warnings -join ' / ')

        #Creating HT to speed-up the post-processing part
        $PfGOwnedGroupsById = @{}
        $NestedInGroupsById = @{}
        foreach ($owned in $PfGOwnedGroups) {
            $PfGOwnedGroupsById[$owned.Id] = $owned
        }
        foreach ($nestedIn in $GroupNestedIn) {
            $NestedInGroupsById[$nestedIn.Id] = $nestedIn
        }

        #Remove properties to save some RAM
        foreach ($user in $memberUser) {
            if ($user -is [PSObject]) {
                $user.PSObject.Properties.Remove('userType')
                $user.PSObject.Properties.Remove('onPremisesSyncEnabled')
            }
        }
        foreach ($user in $owneruser) {
            if ($user -is [PSObject]) {
                $user.PSObject.Properties.Remove('userType')
                $user.PSObject.Properties.Remove('onPremisesSyncEnabled')
            }
        }


        # Keep full Impact/ImpactOrg for group reporting, and expose active-only inheritance score.
        $ImpactOrgActiveOnly = [math]::Round([math]::Max(0, $ImpactScore - $EligibleRoleImpactContribution))

        # Create custom object
        $groupDetails = [PSCustomObject]@{ 
            Id = $group.Id 
            DisplayName = $group.DisplayName
            DisplayNameLink = "<a href=#$($group.id)>$($group.DisplayName)</a>"
            Type = $groupType
            Visibility = $group.Visibility
            RoleAssignable = $group.IsAssignableToRole
            SecurityEnabled = $group.SecurityEnabled
            OnPrem = $group.OnPremisesSyncEnabled
            Description = $group.Description
            Dynamic = $group.dynamic
            MembershipRule = $group.MembershipRule
            EntraRoles  = $RoleCount
            EntraMaxTier = $EntraMaxTier
            EntraRolePrivilegedCount = $RolePrivilegedCount
            EntraRoleDetails = $roleDetails
            GroupCAPsDetails = $groupCAPs
            CAPs = $CAPCount
            AzureRoles = $AzureRoleCount
            AzureMaxTier = $AzureMaxTier
            AzureRoleDetails = $azureRoleDetails
            AppRoles = $AppRoleAssignments.count
            AppRolesDetails = $AppRoleAssignments
            Users = $MemberUserCount
            Userdetails = $memberuser
            Guests = $GuestsCount
            PIM = $PIM
            NestedGroups = $membergroup.count
            NestedGroupsDetails = $membergroup
            NestedInGroups = $GroupNestedIn.count
            NestedInGroupsDetails = $GroupNestedIn
            NestedInGroupsById = $NestedInGroupsById
            PfGOwnedGroupsDetails = $PfGOwnedGroups
            PfGOwnedGroupsById = $PfGOwnedGroupsById
            AuUnits = $GroupAdminUnits.count
            AuUnitsDetails = $GroupAdminUnits
            SPCount = $memberSP.count
            MemberSpDetails = $memberSpDetails
            Devices = $memberdevices.count
            DevicesDetails = $memberdevices
            DirectActiveMembers = $DirectActiveMemberCount
            DirectActiveOwners = $DirectActiveOwnerCount
            DirectOwners = @($owneruser).count + @($ownersp).count + @($OwnerGroup).count
            NestedOwners = 0 #Will be adjusted in port-processing
            OwnerUserDetails = $owneruser
            OwnerGroupDetails = $OwnerGroup
            OwnersSynced = $ownersynced
            ownerSpDetails = $ownerSpDetails
            BaseOwnerUserDetails = $baseOwnerUserDetails #Used for nesting calculations
            BaseOwnerSpDetails   = $ownerSpDetails  #Used for nesting calculations
            InheritedHighValue = 0
            Protected = $Protected
            NestedOwnerUserDetails = [System.Collections.Generic.List[object]]::new()
            NestedOwnerSPDetails = @()
            UsedNestedGroupIds = @()
            Risk = [math]::Ceiling($ImpactScore * $LikelihoodScore)
            Impact = [math]::Round($ImpactScore,1)
            ImpactOrg = [math]::Round($ImpactScore) #Will be required in the user script
            ImpactOrgActiveOnly = $ImpactOrgActiveOnly
            Likelihood = [math]::Round($LikelihoodScore,1)
            BaseLikelihood = [math]::Round($LikelihoodScore,1) #Used for nesting calculations
            Warnings = $Warnings
        }
		[void]$AllGroupsDetails.Add($groupDetails)


    }
    #endregion

    $PmDataProcessing.Stop()
    ########################################## SECTION: POST-PROCESSING ##########################################
    $PmDataPostProcessing = [System.Diagnostics.Stopwatch]::StartNew()
    write-host "[*] Post-processing group nesting"

    # Create a hashtable for faster group lookup by ID (used throughout post-processing)
    $GroupLookup = @{}
    foreach ($group in $AllGroupsDetails) {
        $GroupLookup[$group.Id] = $group
    }

    #Additional helper HT for faster post-processing
    $GroupLookup2 = @{}
    foreach ($group in $AllGroupsDetails) {
        $GroupLookup2[$group.Id] = [PSCustomObject]@{
            Id                 = $group.Id
            Protected        = $group.Protected
            Warnings = $group.Warnings
            NestedOwnerUserDetails = $group.NestedOwnerUserDetails
            NestedOwners = $group.NestedOwners
            OwnersSynced = $group.OwnersSynced
            NestedOwnerSPDetails = $group.NestedOwnerSPDetails
            Likelihood = $group.Likelihood
            Risk = $group.Risk
            Impact = $group.Impact
        }
    }

    # Pre-initialize the property once for all parent groups
    foreach ($g in $GroupLookup.Values) {
        if (-not $g.PSObject.Properties.Match('UsedNestedGroupIdsSet')) {
            $g.UsedNestedGroupIdsSet = [System.Collections.Generic.HashSet[string]]::new()
        }
    }

    # Reprocessing nested groups in groups which give access to potential critical ressources -> Nested group is adjusted
    # Note: Nested groups do not inherit AppRoles
    Write-Log -Level Debug -Message "Processing $($NestedGroupsHighvalue.Count) high value groups with nestings"
    # Tracks already processed groupID->targetID combinations
    $processedGroupHighValuePairs = New-Object System.Collections.Generic.HashSet[string]

    foreach ($highValueGroup in $NestedGroupsHighvalue) {

        $targetIds = $highValueGroup.TargetGroups -split ','
    
        foreach ($targetIdRaw in $targetIds) {
            $targetId = $targetIdRaw.Trim()
    
            # Skip self-nesting
            if ($highValueGroup.GroupID -eq $targetId) { continue }
    
            # Deduplicate highValueGroup -> targetId
            $pairKey = "$($highValueGroup.GroupID)|$targetId"
            if ($processedGroupHighValuePairs.Contains($pairKey)) { continue }
            $null = $processedGroupHighValuePairs.Add($pairKey)
    
            $group = $GroupLookup[$targetId]
            if (-not $group) { continue }

            $sourceGroup = $GroupLookup[$highValueGroup.GroupID]
            if ($sourceGroup) {
                $group.EntraMaxTier = Merge-HigherTierLabel -CurrentTier $group.EntraMaxTier -CandidateTier $sourceGroup.EntraMaxTier
                $group.AzureMaxTier = Merge-HigherTierLabel -CurrentTier $group.AzureMaxTier -CandidateTier $sourceGroup.AzureMaxTier
            }
    
            # Adjust impact + risk
            $group.Impact += [math]::Round($highValueGroup.Score, 1)
            $group.Risk = [math]::Ceiling($group.Impact * $group.Likelihood)
    
            # Add role/CAP counts
            if ($highValueGroup.CAPs)       { $group.CAPs       += $highValueGroup.CAPs }
            if ($highValueGroup.EntraRoles) { $group.EntraRoles += $highValueGroup.EntraRoles }
            if ($highValueGroup.AzureRoles) { $group.AzureRoles += $highValueGroup.AzureRoles }
    
            # Update owned group (fast lookup through)
            if ($group.PfGOwnedGroupsById.ContainsKey($highValueGroup.GroupID)) {
                $ownedGroup = $group.PfGOwnedGroupsById[$highValueGroup.GroupID]
                if ($highValueGroup.CAPs)       { $ownedGroup.CAPs       += $highValueGroup.CAPs }
                if ($highValueGroup.EntraRoles) { $ownedGroup.EntraRoles += $highValueGroup.EntraRoles }
                if ($highValueGroup.AzureRoles) { $ownedGroup.AzureRoles += $highValueGroup.AzureRoles }
            }
    
            # Update parent group (fast lookup through HT)
            if ($group.NestedInGroupsById.ContainsKey($highValueGroup.GroupID)) {
                $parentGroup = $group.NestedInGroupsById[$highValueGroup.GroupID]
                if ($highValueGroup.CAPs)       { $parentGroup.CAPs       += $highValueGroup.CAPs }
                if ($highValueGroup.EntraRoles) { $parentGroup.EntraRoles += $highValueGroup.EntraRoles }
                if ($highValueGroup.AzureRoles) { $parentGroup.AzureRoles += $highValueGroup.AzureRoles }
            }
    
            # Append warning
            $message = $highValueGroup.Message
            if ([string]::IsNullOrWhiteSpace($group.Warnings)) {
                $group.Warnings = $message
            } elseif ($group.Warnings -notmatch [regex]::Escape($message)) {
                $group.Warnings += " / $message"
            }
    
            $group.InheritedHighValue += 1
        }
    }


    $GroupsWithNestings = $AllGroupsDetails | Where-Object { $_.NestedGroups -ge 1 }

    $GroupsWithNestingsCount = $($GroupsWithNestings.Count)
    Write-Log -Level Debug -Message "Processing $GroupsWithNestingsCount groups with nesting"
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($GroupsWithNestingsCount / 10), 1)
    Write-Log -Level Debug -Message "Status: Processing group 1 of $GroupsWithNestingsCount (updates every $StatusUpdateInterval groups)..."
    $ProgressCounter = 0
        

    #Reprocessing groups which have a nested group to include their owners  -> Parent group is adjusted
   # Pre-create hash sets for faster containment checks
   foreach ($Group in $GroupsWithNestings) {
        $ProgressCounter++

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $GroupsWithNestingsCount) {
            Write-Log -Level Debug -Message "[*] Status: Processing group $ProgressCounter of $GroupsWithNestingsCount ..."
        }


        # Step 1: Expand nested groups
        $allNestedGroups = Expand-NestedGroups-Cached -StartGroup $Group -GroupLookup $GroupLookup2 -CallerPSCmdlet $PSCmdlet
        $targetGroup = $GroupLookup[$Group.Id]


        # Step 2: Aggregate owners from nested groups
        
        foreach ($match in $allNestedGroups) {
            $matchingGroup = $GroupLookup[$match.Id]
            if (-not $matchingGroup) { continue }
            # Risky nesting warning
            if ($targetGroup.Protected -and -not $matchingGroup.Protected) {
                if ($targetGroup.Warnings -notcontains "Protected group is owned by or contains unprotected groups") {
                    $targetGroup.Warnings += " / Protected group is owned by or contains unprotected groups"
                }
            }

            # Owner aggregation
            if ($matchingGroup.DirectOwners -ge 1) {
                $userOwners = $matchingGroup.BaseOwnerUserDetails
                $spOwners   = $matchingGroup.BaseOwnerSpDetails

                if ($userOwners.Count -ge 1) {
                    $targetGroup.NestedOwnerUserDetails.AddRange($userOwners)

                    # Count on-prem owners only once
                    $onPremCount = 0
                    foreach ($u in $userOwners) {
                        if ($u.onPremisesSyncEnabled) { $onPremCount++ }
                    }
                    $targetGroup.NestedOwners += $userOwners.Count
                    $targetGroup.OwnersSynced += $onPremCount
                }

                if ($spOwners.Count -ge 1) {
                    $targetGroup.NestedOwnerSPDetails += $spOwners
                    $targetGroup.NestedOwners += $spOwners.Count
                }
            }

            # Accumulate likelihood score
            $baseLikelihood = $matchingGroup.BaseLikelihood
            if ($null -ne $baseLikelihood) {
                $targetGroup.Likelihood += [math]::Round($baseLikelihood, 1)
            }
        }

        # Finalize scores: round once and recalculate risk
        $targetGroup.Likelihood = [math]::Round($targetGroup.Likelihood, 1)
        $targetGroup.Risk = [math]::Ceiling($targetGroup.Likelihood * $targetGroup.Impact)
    }


    Write-Log -Level Debug -Message "Processed all groups with nestings"

    $PmDataPostProcessing.Stop()
    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    $PmGeneratingDetails = [System.Diagnostics.Stopwatch]::StartNew()

    write-host "[*] Generating Details Section"

    #Define output of the main table
    $tableOutput = $AllGroupsDetails | Sort-Object Risk -Descending | select-object DisplayName,DisplayNameLink,Type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,Impact,Likelihood,Risk,Warnings
    
    # Apply result limit for the main table
    if ($LimitResults -and $LimitResults -gt 0) {
        $tableOutput = $tableOutput | Select-Object -First $LimitResults
    }

    #Generate Appendix with Dynamic Groups
    $AppendixDynamic = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $AllGroupsDetails) {
        if ($group.Dynamic -eq $true) {
            $AppendixDynamic.Add([PSCustomObject]@{
                DisplayName     = $group.DisplayName
                Description     = $group.Description
                type            = $group.type
                SecurityEnabled = $group.SecurityEnabled
                AzureRoles      = $group.AzureRoles
                AzureMaxTier    = $group.AzureMaxTier
                CAPs            = $group.CAPs
                AppRoles        = $group.AppRoles
                EntraMaxTier    = $group.EntraMaxTier
                MembershipRule  = $group.MembershipRule
                Warnings        = $group.Warnings
            })
        }
    }
    $DynamicGroupsCount = $AppendixDynamic.count

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllGroupsDetails | Sort-Object Risk -Descending
    
    # Apply limit for details
    if ($LimitResults -and $LimitResults -gt 0) {
        $details = $details | Select-Object -First $LimitResults
    }

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    # Progress status in verbose mode
    $detailsCount = $details.count
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($detailsCount / 10), 1)
    Write-Log -Level Debug -Message "Status: Processing group 1 of $detailsCount (updates every $StatusUpdateInterval groups)..."
    $ProgressCounter = 0

    $DetailTxtBuffer = [System.Text.StringBuilder]::new()
    $BufferThreshold = 5000
    $BufferedCount = 0
    $DetailReportPath = "$OutputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt"

#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($GroupScriptWarningList  -join ' / ')
************************************************************************************************************************
"

$tableOutput | Format-table DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append


    foreach ($item in $details) {

        # Progress status in verbose mode
        $ProgressCounter++
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $detailsCount) {
            Write-Log -Level Debug -Message "[*] Status: Processing group $ProgressCounter of $detailsCount ..."
        }

        $ReportingAU = [System.Collections.Generic.List[object]]::new()
        $ReportingRoles = [System.Collections.Generic.List[object]]::new()
        $ReportingAzureRoles = [System.Collections.Generic.List[object]]::new()
        $ReportingCAPs = [System.Collections.Generic.List[object]]::new()
        $AppRoles = [System.Collections.Generic.List[object]]::new()
        $OwnerUser = [System.Collections.Generic.List[object]]::new()
        $OwnerGroups = [System.Collections.Generic.List[object]]::new()
        $OwnerSP = [System.Collections.Generic.List[object]]::new()
        $NestedOwnerUser = [System.Collections.Generic.List[object]]::new()
        $NestedOwnerSP = [System.Collections.Generic.List[object]]::new()
        $NestedGroups = [System.Collections.Generic.List[object]]::new()
        $NestedUsers = [System.Collections.Generic.List[object]]::new()
        $NestedSP = [System.Collections.Generic.List[object]]::new()
        $NestedDevices = [System.Collections.Generic.List[object]]::new()
        $NestedInGroups = [System.Collections.Generic.List[object]]::new()
        $OwnedGroups = [System.Collections.Generic.List[object]]::new()

        [void]$DetailTxtBuilder.AppendLine("#" * 120)

        ############### HEADER
        $ReportingGroupInfo = [pscustomobject]@{
            "Group Name" = $item.DisplayName
            "Group ObjectID" = $item.Id
            "Type" = $item.Type
            "SecurityEnabled" = $item.SecurityEnabled
            "Protected" = $item.Protected
            "Synced from on-prem" = $item.OnPrem
            "Entra Max Tier" = $item.EntraMaxTier
            "Azure Max Tier" = $item.AzureMaxTier
            "RiskScore" = $item.Risk
        }
        if ($item.Dynamic) {
            $ReportingGroupInfo | Add-Member -NotePropertyName DynamicRule -NotePropertyValue $item.MembershipRule
        }
        
        if ($item.Warnings -ne '') {
            $ReportingGroupInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        foreach ($prop in $ReportingGroupInfo.PSObject.Properties) {
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
        
        ############### Administrative Units
        if (@($item.AuUnitsDetails).Count -ge 1) {
            foreach ($object in $item.AuUnitsDetails) {
                [void]$ReportingAU.Add([pscustomobject]@{ 
                    "Administrative Unit"         = $object.Displayname
                    "IsMemberManagementRestricted" = $object.IsMemberManagementRestricted
                })
            }
        
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Administrative Units")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAU | Out-String))
        }

        ############### Entra Roles
        if (@($item.EntraRoleDetails).count -ge 1) {
            foreach ($object in $item.EntraRoleDetails) {
                [void]$ReportingRoles.Add([pscustomobject]@{ 
                    "Role name"   = $object.DisplayName
                    "Assignment"  = $object.AssignmentType
                    "Tier Level"  = $object.RoleTier
                    "Privileged"  = $object.isPrivileged
                    "Builtin"     = $object.IsBuiltin
                    "Scoped to"   = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                })
            }
        
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | format-table | Out-String))
        }

        ############### Azure Roles
        if (@($item.AzureRoleDetails).Count -ge 1) {
            foreach ($role in $item.AzureRoleDetails) {
                [void]$ReportingAzureRoles.Add([pscustomobject]@{ 
                    "Role name"   = $role.RoleName
                    "Assignment"  = $role.AssignmentType
                    "RoleType"    = $role.RoleType
                    "Tier Level"  = $role.RoleTier
                    "Conditions"  = $role.Conditions
                    "Scoped to"   = $role.Scope
                })
            }
        
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | format-table | Out-String))
        }        

        ############### CAPs
        if ($item.GroupCAPsDetails.Count -ge 1) {

            $ReportingCAPsRaw = [System.Collections.Generic.List[object]]::new()
            
            $CapNameLength = 0
            foreach ($object in $item.GroupCAPsDetails) {
                # Calc Max Length
                $CapName = $object.CAPName
                if ($null -ne $CapName -and $CapName.Length -gt $CapNameLength) {
                    $CapNameLength = $CapName.Length
                }

                $txtObj = [pscustomobject]@{
                    CAPName     = $CapName
                    Usage       = $object.CAPExOrIn
                    Status      = $object.CAPStatus
                }
        
                [void]$ReportingCAPsRaw.Add($txtObj)
        
                [void]$ReportingCAPs.Add([pscustomobject]@{
                    CAPName = "<a href=ConditionalAccessPolicies_$($StartTimestamp)_$($EscapedTenantName).html#$($object.Id)>$($CapName)</a>"
                    Usage   = $object.CAPExOrIn
                    Status  = $object.CAPStatus
                })
            }
        
            $formattedText = Format-ReportSection -Title "Linked Conditional Access Policies" `
            -Objects $ReportingCAPsRaw `
            -Properties @("CAPName", "Usage", "Status") `
            -ColumnWidths @{ CAPName = [Math]::Min($CapNameLength, 120); Usage = 9; Status = 8}
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        }

        ############### App Roles
        if (@($item.AppRolesDetails).Count -ge 1) {
            $AppRolesRaw = [System.Collections.Generic.List[object]]::new()

            $ResourceDisplayNameLength = 0
            foreach ($object in $item.AppRolesDetails) {

                # Calc Max Length
                $ResourceDisplayName = $object.ResourceDisplayName
                if ($null -ne $ResourceDisplayName -and $ResourceDisplayName.Length -gt $ResourceDisplayNameLength) {
                    $ResourceDisplayNameLength = $ResourceDisplayName.Length
                }

                $appObj = [pscustomobject]@{ 
                    UsedIn     = $ResourceDisplayName
                    UsedInLink = "<a href=EnterpriseApps_$($StartTimestamp)_$($EscapedTenantName).html#$($object.ResourceId)>$($ResourceDisplayName)</a>"
                    AppRoleId  = $object.AppRoleId
                }
                [void]$AppRolesRaw.Add($appObj)
            }
        
            # Output for TXT report
            $formattedText = Format-ReportSection -Title "App Roles" `
            -Objects $AppRolesRaw `
            -Properties @("UsedIn", "AppRoleId") `
            -ColumnWidths @{ UsedIn = [Math]::Min($ResourceDisplayNameLength, 50); AppRoleId = 40 }
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        
            # Rebuild for HTML report
            foreach ($obj in $AppRolesRaw) {
                [void]$AppRoles.Add([pscustomobject]@{
                    UsedInApp = $obj.UsedInLink
                    AppRoleId = $obj.AppRoleId
                })
            }
        }

        ############### Owners (Users)
        if (@($item.OwnerUserDetails).Count -ge 1) {
            # Initialize list for raw user data
            $OwnerUserRaw = [System.Collections.Generic.List[object]]::new()

            $UsernameLength = 0
        
            foreach ($object in $item.OwnerUserDetails) {
                $userDetails = $AllUsersBasicHT[$object.id]
                if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                # Calc Max Length
                $Username = $userDetails.userPrincipalName
                if ($null -ne $Username -and $Username.Length -gt $UsernameLength) {
                    $UsernameLength = $Username.Length
                }

                # Add raw user data to the list
                $userObj = [pscustomobject]@{ 
                    "AssignmentType" = $object.AssignmentType
                    "Username" = $Username
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$($EscapedTenantName).html#$($userDetails.id)>$($Username)</a>"
                    "Enabled" = $userDetails.accountEnabled
                    "Type" = $userDetails.userType
                    "Synced" = $userDetails.onPremisesSyncEnabled
                }

                [void]$OwnerUserRaw.Add($userObj)
            }

            # Output for TXT report
            $formattedText = Format-ReportSection -Title "Owners (User)" `
            -Objects $OwnerUserRaw `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = [Math]::Min($UsernameLength, 60); Enabled = 7; Type = 7; Synced = 6}
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Rebuild for HTML report
            $OwnerUserHtml = [System.Collections.Generic.List[object]]::new()

            foreach ($obj in $OwnerUserRaw) {
                # Add only the necessary HTML fields
                [void]$OwnerUserHtml.Add([pscustomobject]@{
                    AssignmentType  = $obj.AssignmentType
                    Username        = $obj.UsernameLink
                    Enabled         = $obj.Enabled
                    Type            = $obj.Type
                    Synced          = $obj.Synced
                })
            }

            # Final assignment for HTML report
            $OwnerUser = $OwnerUserHtml
        }

        ############### Owners (Groups) (only possible with PIM for Groups)
        if (@($item.OwnerGroupDetails).count -ge 1) {
            $OwnerGroupsRaw = [System.Collections.Generic.List[object]]::new()

            $GroupNameLength = 0

            foreach ($object in $item.OwnerGroupDetails) {
                $groupDetails = $GroupLookup[$object.id]
                if (-not $groupDetails) { $groupDetails = $AllGroupsHT[$object.id] }

                # Calc Max Length
                $GroupName = if ($null -ne $groupDetails.DisplayName) { $groupDetails.DisplayName } else { $groupDetails.displayName }
                if ($null -ne $GroupName -and $GroupName.Length -gt $GroupNameLength) {
                    $GroupNameLength = $GroupName.Length
                }
                $entraMaxTier = if ($null -ne $groupDetails.EntraMaxTier) { $groupDetails.EntraMaxTier } else { "-" }
                $azureMaxTier = if ($null -ne $groupDetails.AzureMaxTier) { $groupDetails.AzureMaxTier } else { if ($GLOBALAzurePsChecks) { "-" } else { "?" } }
                $roleAssignable = if ($null -ne $groupDetails.RoleAssignable) { $groupDetails.RoleAssignable } else { $groupDetails.IsAssignableToRole }

                $groupObj = [pscustomobject]@{ 
                    "AssignmentType" = $object.AssignmentType
                    "Displayname" = $GroupName
                    "DisplayNameLink" = "<a href=#$($object.id)>$($GroupName)</a>"
                    "SecurityEnabled" = $groupDetails.SecurityEnabled
                    "IsAssignableToRole" = $roleAssignable
                    "EntraMaxTier" = $entraMaxTier
                    "AzureMaxTier" = $azureMaxTier
                }
                [void]$OwnerGroupsRaw.Add($groupObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Eligible Owners (Groups)" `
            -Objects $OwnerGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole", "EntraMaxTier", "AzureMaxTier") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = [Math]::Min($GroupNameLength, 60); SecurityEnabled = 16; IsAssignableToRole = 19; EntraMaxTier = 11; AzureMaxTier = 11 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            #Rebuild for HTML report
            foreach ($obj in $OwnerGroupsRaw) {
                [void]$OwnerGroups.Add([pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                    EntraMaxTier        = $obj.EntraMaxTier
                    AzureMaxTier        = $obj.AzureMaxTier
                })
            }
        }

        ############### Owners (SP)
        if (@($item.ownerSpDetails).Count -ge 1) {
            $OwnerSPRaw = [System.Collections.Generic.List[object]]::new()

            $DisplayNameLength = 0
        
            foreach ($object in $item.ownerSpDetails) {

                # Calc Max Length
                $DisplayName = $object.displayName
                if ($null -ne $DisplayName -and $DisplayName.Length -gt $DisplayNameLength) {
                    $DisplayNameLength = $DisplayName.Length
                }                

                if ($object.TargetReport -eq 'AgentIdentities') {
                    $DisplayNameLink = "<a href=AgentIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                } elseif ($object.TargetReport -eq 'AgentIdentityBlueprintsPrincipals') {
                    $DisplayNameLink = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                } elseif ($object.TargetReport -eq 'ManagedIdentities') {
                    $DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                } else {
                    $DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                }

                $displayType = if ($object.OwnerKind -eq 'ServicePrincipal') { $object.SPType } else { $object.OwnerKind }

                $ownerObj = [pscustomobject]@{ 
                    DisplayName     = $DisplayName
                    DisplayNameLink = $DisplayNameLink
                    Type            = $displayType
                    Org             = $object.publisherName
                    Foreign         = $object.Foreign
                    DefaultMS       = $object.DefaultMS
                }
                [void]$OwnerSPRaw.Add($ownerObj)
            }
        
            # Build TXT
            $formattedText = Format-ReportSection -Title "Owners (Service Principals / Agent Objects)" `
            -Objects $OwnerSPRaw `
            -Properties @("DisplayName", "Type", "Org", "Foreign", "DefaultMS") `
            -ColumnWidths @{ DisplayName = [Math]::Min($DisplayNameLength, 45); Type = 20; Org = 45; Foreign = 8; DefaultMS = 10 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        
            # Rebuild for HTML report
            foreach ($obj in $OwnerSPRaw) {
                [void]$OwnerSP.Add([pscustomobject]@{
                    DisplayName  = $obj.DisplayNameLink
                    Type         = $obj.Type
                    Organization = $obj.Org
                    Foreign      = $obj.Foreign
                    DefaultMS    = $obj.DefaultMS
                })
            }
        }

        ############### Nested Owners (Users)
        if (@($item.NestedOwnerUserDetails).count -ge 1) {
            $NestedOwnerUserHtml = [System.Collections.Generic.List[object]]::new()

            $UsernameLength = 0

            foreach ($object in $($item.NestedOwnerUserDetails)) {
                $userDetails = $AllUsersBasicHT[$object.id]
                if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                # Calc Max Length
                $Username = $userDetails.userPrincipalName
                if ($null -ne $Username -and $Username.Length -gt $UsernameLength) {
                    $UsernameLength = $Username.Length
                }

                $userObj = [pscustomobject]@{ 
                    "AssignmentType" = $object.AssignmentType
                    "Username" = $Username
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$($EscapedTenantName).html#$($userDetails.id)>$($Username)</a>"
                    "Enabled" = $userDetails.accountEnabled
                    "Type" = $userDetails.userType
                    "Synced" = $userDetails.onPremisesSyncEnabled
                }

                [void]$NestedOwnerUser.Add($userObj)

                [void]$NestedOwnerUserHtml.Add([pscustomobject]@{
                    AssignmentType  = $userObj.AssignmentType
                    Username        = $userObj.UsernameLink
                    Enabled         = $userObj.Enabled
                    Type            = $userObj.Type
                    Synced          = $userObj.Synced
                })

            }

            # Build TXT report
            $formattedText = Format-ReportSection -Title "Nested Owners (Users)" `
            -Objects $NestedOwnerUser `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = [Math]::Min($UsernameLength, 60); Enabled = 7; Type = 7; Synced = 6}
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            #Rebuild for HTML report
            $NestedOwnerUser = $NestedOwnerUserHtml
        }

        ############### Nested Owners (SP)
        if (@($item.NestedOwnerSPDetails).Count -ge 1) {

            foreach ($object in $item.NestedOwnerSPDetails) {
                $displayType = if ($object.OwnerKind -eq 'ServicePrincipal') { $object.SPType } else { $object.OwnerKind }
                $spObj = [pscustomobject]@{
                    "DisplayName"  = $object.DisplayName
                    "Type"         = $displayType
                    "Org"          = $object.PublisherName
                    "Foreign"      = $object.Foreign
                    "DefaultMS"    = $object.DefaultMS
                }
                [void]$NestedOwnerSP.Add($spObj)
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Owners (Service Principals / Agent Objects)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedOwnerSP | Format-Table | Out-String))
        }

        ############### Nested Groups
        if (@($item.NestedGroupsDetails).Count -ge 1) {
            $NestedGroupsRaw = [System.Collections.Generic.List[object]]::new()
        
            foreach ($object in $item.NestedGroupsDetails) {
                $groupDetails = $GroupLookup[$object.id]
                if (-not $groupDetails) { $groupDetails = $AllGroupsHT[$object.id] }
                $groupName = if ($null -ne $groupDetails.DisplayName) { $groupDetails.DisplayName } else { $groupDetails.displayName }
                $roleAssignable = if ($null -ne $groupDetails.RoleAssignable) { $groupDetails.RoleAssignable } else { $groupDetails.IsAssignableToRole }
        
                $rawObj = [pscustomobject]@{
                    AssignmentType     = $object.AssignmentType
                    DisplayName        = $groupName
                    DisplayNameLink    = "<a href=#$($object.id)>$($groupName)</a>"
                    SecurityEnabled    = $groupDetails.SecurityEnabled
                    IsAssignableToRole = $roleAssignable
                }
        
                [void]$NestedGroupsRaw.Add($rawObj)
            }
        
            # Sort by role assignability & security for both TXT and HTML
            $SortedNestedGroups = $NestedGroupsRaw | Sort-Object {
                $priority = 0
                if (-not $_.IsAssignableToRole) { $priority += 1 }
                if (-not $_.SecurityEnabled)   { $priority += 1 }
                return $priority
            }
        
            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Nested Groups" `
            -Objects $SortedNestedGroups `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = 60; SecurityEnabled = 16; IsAssignableToRole = 19 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        
            # Limit for HTML
            $ExceedsLimit = $SortedNestedGroups.Count -gt $HTMLNestedGroupsLimit
            $GroupsToShow = if ($ExceedsLimit) { $SortedNestedGroups[0..($HTMLNestedGroupsLimit - 1)] } else { $SortedNestedGroups }
        
            foreach ($obj in $GroupsToShow) {
                [void]$NestedGroups.Add([pscustomobject]@{
                    AssignmentType     = $obj.AssignmentType
                    DisplayName        = $obj.DisplayNameLink
                    SecurityEnabled    = $obj.SecurityEnabled
                    IsAssignableToRole = $obj.IsAssignableToRole
                })
            }
        
            if ($ExceedsLimit) {
                [void]$NestedGroups.Add([pscustomobject]@{
                    AssignmentType     = "-"
                    DisplayName        = "Showing first $HTMLNestedGroupsLimit of $($SortedNestedGroups.Count) groups (see TXT for full list)"
                    SecurityEnabled    = "-"
                    IsAssignableToRole = "-"
                })
            }
        }
        
        


        ############### Nested Users
        if (@($item.UserDetails).Count -ge 1) {
            $ObjectCounter = 0
            $NestedUsersTXT = [System.Collections.Generic.List[object]]::new()

            #Set lenght to 0
            $UsernameLength = 0
        
            foreach ($object in $item.UserDetails) {
                $userDetails = $AllUsersBasicHT[$object.id]
        
                if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                # Calc Max Length
                $Username = $userDetails.userPrincipalName
                if ($null -ne $Username -and $Username.Length -gt $UsernameLength) {
                    $UsernameLength = $Username.Length
                }

                $linkedUsername = "<a href=Users_$($StartTimestamp)_$($EscapedTenantName).html#$($userDetails.id)>$($Username)</a>"
        
                # Plain for TXT
                $txtObj = [pscustomobject]@{ 
                    AssignmentType  = $object.AssignmentType
                    Username        = $Username
                    Enabled         = $userDetails.accountEnabled
                    Type            = $userDetails.userType
                    Synced          = $userDetails.onPremisesSyncEnabled
                }
        
                # Linked for HTML
                $htmlObj = [pscustomobject]@{ 
                    AssignmentType  = $object.AssignmentType
                    Username        = $linkedUsername
                    Enabled         = $userDetails.accountEnabled
                    Type            = $userDetails.userType
                    Synced          = $userDetails.onPremisesSyncEnabled
                }
        
                if ($ObjectCounter -lt $HTMLMemberLimit) {
                    [void]$NestedUsers.Add($htmlObj)
                } elseif ($ObjectCounter -eq $HTMLMemberLimit) {
                    [void]$NestedUsers.Add([pscustomobject]@{
                        AssignmentType = "-"
                        Username       = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                        Enabled        = "-"
                        Type           = "-"
                        Synced         = "-"
                    })
                }
        
                [void]$NestedUsersTXT.Add($txtObj)
                $ObjectCounter++
            }
        
            $formattedText = Format-ReportSection -Title "Nested Members: Users" `
            -Objects $NestedUsersTXT `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = [Math]::Min($UsernameLength, 60); Enabled = 7; Type = 7; Synced = 6}
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)
            
        }

        ############### Nested SP
        if (@($item.MemberSpDetails).Count -ge 1) {
            $NestedSPRaw = [System.Collections.Generic.List[object]]::new()

            $DisplayNameLength = 0
        
            foreach ($object in $item.MemberSpDetails) {

                # Calc Max Length
                $DisplayName = $object.displayName
                if ($null -ne $DisplayName -and $DisplayName.Length -gt $DisplayNameLength) {
                    $DisplayNameLength = $DisplayName.Length
                }

                if ($object.TargetReport -eq 'AgentIdentities') {
                    $DisplayNameLink = "<a href=AgentIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                    $org = $object.publisherName
                } elseif ($object.TargetReport -eq 'AgentIdentityBlueprintsPrincipals') {
                    $DisplayNameLink = "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                    $org = $object.publisherName
                } elseif ($object.SPType -eq "Application") {
                    $DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                    $org = $object.publisherName
                } else {
                    $DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$($EscapedTenantName).html#$($object.id)>$($DisplayName)</a>"
                    $org = "-"
                }

                $displayType = if ($object.OwnerKind -eq 'ServicePrincipal') { $object.SPType } else { $object.OwnerKind }
        
                $rawObj = [pscustomobject]@{
                    DisplayName     = $DisplayName
                    DisplayNameLink = $DisplayNameLink
                    Type            = $displayType
                    Org             = $org
                    Foreign         = $object.Foreign
                    DefaultMS       = $object.DefaultMS
                }
        
                [void]$NestedSPRaw.Add($rawObj)
            }
        
            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Service Principals / Agent Objects" `
            -Objects $NestedSPRaw `
            -Properties @("DisplayName", "Type", "Org", "Foreign", "DefaultMS") `
            -ColumnWidths @{ DisplayName = [Math]::Min($DisplayNameLength, 55); Type = 20; Org = 45; Foreign = 8; DefaultMS = 10 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

        
            foreach ($obj in $NestedSPRaw) {
                [void]$NestedSP.Add([pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Type          = $obj.Type
                    Organization  = $obj.Org
                    Foreign       = $obj.Foreign
                    DefaultMS     = $obj.DefaultMS
                })
            }
        }

        ############### Nested Devices
        if (@($item.DevicesDetails).count -ge 1) {
            $NestedDevicesRaw = [System.Collections.Generic.List[object]]::new()

            $DiplayNameLength = 0
            $OsLength = 0

            foreach ($object in $item.DevicesDetails) {
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
                
                $rawObj = [pscustomobject]@{
                    Displayname   = $DiplayName
                    Type          = $DeviceDetails.trustType
                    OS            = $Os
                }
        
                [void]$NestedDevicesRaw.Add($rawObj)
            }
        
            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Devices" `
            -Objects $NestedDevicesRaw `
            -Properties @("Displayname", "Type", "OS") `
            -ColumnWidths @{ Displayname = [Math]::Min($DiplayNameLength, 30); Enabled = 8; Type = 15; OS = [Math]::Min($OsLength, 40) }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
            
            # Limit HTML output
            $ExceedsLimit = $NestedDevicesRaw.Count -gt $HTMLMemberLimit
            if ($ExceedsLimit -and $HTMLMemberLimit -gt 0) {
                $DevicesToShow = $NestedDevicesRaw[0..($HTMLMemberLimit - 1)]
            } else {
                $DevicesToShow = $NestedDevicesRaw
            }

            foreach ($obj in $DevicesToShow) {
                [void]$NestedDevices.Add([pscustomobject]@{
                    Displayname   = $obj.Displayname
                    Type          = $obj.Type
                    OS            = $obj.OS
                })
            }

            if ($ExceedsLimit) {
                [void]$NestedDevices.Add([pscustomobject]@{
                    Displayname   = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                    Type          = "-"
                    OS            = "-"
                })
            }
        }

        ############### Nested in Groups
        if (@($item.NestedInGroupsDetails).count -ge 1) {
            $NestedInGroupsRaw = [System.Collections.Generic.List[object]]::new()

            $GroupNameLength = 0

            foreach ($object in $item.NestedInGroupsDetails) {
                $groupDetails = $GroupLookup[$object.id]
                if (-not $groupDetails) { $groupDetails = $AllGroupsHT[$object.id] }

                # Calc Max Length
                $GroupName = if ($null -ne $groupDetails.DisplayName) { $groupDetails.DisplayName } else { $groupDetails.displayName }
                if ($null -ne $GroupName -and $GroupName.Length -gt $GroupNameLength) {
                    $GroupNameLength = $GroupName.Length
                }
                $roleAssignable = if ($null -ne $groupDetails.RoleAssignable) { $groupDetails.RoleAssignable } else { $groupDetails.IsAssignableToRole }
                $entraMaxTier = if ($null -ne $groupDetails.EntraMaxTier) { $groupDetails.EntraMaxTier } else { "-" }
                $azureMaxTier = if ($null -ne $groupDetails.AzureMaxTier) { $groupDetails.AzureMaxTier } else { if ($GLOBALAzurePsChecks) { "-" } else { "?" } }
        
                $rawObj = [pscustomobject]@{
                    AssignmentType     = $object.AssignmentType
                    Displayname        = $GroupName
                    DisplayNameLink    = "<a href=#$($object.id)>$($GroupName)</a>"
                    SecurityEnabled    = $groupDetails.SecurityEnabled
                    IsAssignableToRole = $roleAssignable
                    EntraRoles         = $object.EntraRoles
                    EntraMaxTier       = $entraMaxTier
                    AzureRoles         = $object.AzureRoles
                    AzureMaxTier       = $azureMaxTier
                    CAPs               = $object.CAPs
                }
        
                [void]$NestedInGroupsRaw.Add($rawObj)
            }
        
            # Build TXT
            $formattedText = Format-ReportSection -Title "Member Of: Nested in Groups (Transitive)" `
            -Objects $NestedInGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "CAPs") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = [Math]::Min($GroupNameLength, 60); SecurityEnabled = 16; IsAssignableToRole = 19; EntraRoles = 11; EntraMaxTier = 11; AzureRoles = 11; AzureMaxTier = 11; CAPs = 4 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)
        
            # Sort only for HTML
            $SortedNestedGroups = $NestedInGroupsRaw | Sort-Object {
                if ($_.EntraRoles -or $_.AzureRoles -or $_.CAPs) { 0 } else { 1 }
            }
        
            # Apply HTML limit
            $ExceedsLimit = $SortedNestedGroups.Count -gt $HTMLNestedGroupsLimit
            if ($ExceedsLimit -and $HTMLNestedGroupsLimit -gt 0) {
                $GroupsToShow = $SortedNestedGroups[0..($HTMLNestedGroupsLimit - 1)]
            } else {
                $GroupsToShow = $SortedNestedGroups
            }
        
            foreach ($obj in $GroupsToShow) {
                [void]$NestedInGroups.Add([pscustomobject]@{
                    AssignmentType     = $obj.AssignmentType
                    DisplayName        = $obj.DisplayNameLink
                    SecurityEnabled    = $obj.SecurityEnabled
                    IsAssignableToRole = $obj.IsAssignableToRole
                    EntraRoles         = $obj.EntraRoles
                    EntraMaxTier       = $obj.EntraMaxTier
                    AzureRoles         = $obj.AzureRoles
                    AzureMaxTier       = $obj.AzureMaxTier
                    CAPs               = $obj.CAPs
                })
            }
        
            if ($ExceedsLimit) {
                [void]$NestedInGroups.Add([pscustomobject]@{
                    AssignmentType     = "-"
                    DisplayName        = "Showing first $HTMLNestedGroupsLimit of $($SortedNestedGroups.Count) groups (see TXT for full list)"
                    SecurityEnabled    = "-"
                    IsAssignableToRole = "-"
                    EntraRoles         = "-"
                    EntraMaxTier       = "-"
                    AzureRoles         = "-"
                    AzureMaxTier       = $(if ($GLOBALAzurePsChecks) { "-" } else { "?" })
                    CAPs               = "-"
                })
            }
        }


        ############### Owns another Group (Pim for Groups)
        if (@($item.PfGOwnedGroupsDetails).Count -ge 1) {
            $OwnedGroupsRaw = [System.Collections.Generic.List[object]]::new()

            $GroupNameLength = 0

            foreach ($object in $item.PfGOwnedGroupsDetails) {
                $groupDetails = $GroupLookup[$object.id]
                $entraMaxTier = if ($null -ne $groupDetails -and $null -ne $groupDetails.EntraMaxTier) { $groupDetails.EntraMaxTier } else { "-" }
                $azureMaxTier = if ($null -ne $groupDetails -and $null -ne $groupDetails.AzureMaxTier) { $groupDetails.AzureMaxTier } else { if ($GLOBALAzurePsChecks) { "-" } else { "?" } }

                $GroupName = $object.displayName
                if ($null -ne $GroupName -and $GroupName.Length -gt $GroupNameLength) {
                    $GroupNameLength = $GroupName.Length
                }

                [void]$OwnedGroupsRaw.Add([pscustomobject]@{ 
                    AssignmentType      = $object.AssignmentType
                    Displayname         = $GroupName
                    DisplayNameLink     = "<a href=#$($object.id)>$($GroupName)</a>"
                    SecurityEnabled     = $object.SecurityEnabled
                    IsAssignableToRole  = $object.IsAssignableToRole
                    EntraRoles          = $object.EntraRoles
                    EntraMaxTier        = $entraMaxTier
                    AzureRoles          = $object.AzureRoles
                    AzureMaxTier        = $azureMaxTier
                    CAPs                = $object.CAPs
                })
            }
        
            $formattedText = Format-ReportSection -Title "Owned Groups (PIM for Groups)" `
            -Objects $OwnedGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "CAPs") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = [Math]::Min($GroupNameLength, 60); SecurityEnabled = 16; IsAssignableToRole = 19; EntraRoles = 11; EntraMaxTier = 11; AzureRoles = 11; AzureMaxTier = 11; CAPs = 4 }
        
            [void]$DetailTxtBuilder.AppendLine($formattedText)
            
        
            # Rebuild for HTML report
            foreach ($obj in $OwnedGroupsRaw) {
                [void]$OwnedGroups.Add([pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                    EntraRoles          = $obj.EntraRoles
                    EntraMaxTier        = $obj.EntraMaxTier
                    AzureRoles          = $obj.AzureRoles
                    AzureMaxTier        = $obj.AzureMaxTier
                    CAPs                = $obj.CAPs
                })
            }
        }
        
        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information"    = $ReportingGroupInfo
            "Administrative Units" = $ReportingAU
            "Entra ID Roles" = $ReportingRoles
            "Azure Roles" = $ReportingAzureRoles
            "Conditional Access Policies" = $ReportingCAPs
            "Application Roles" = $AppRoles
            "Owners (User)" = $OwnerUser
            "Owners (Groups)" = $OwnerGroups
            "Owners (Service Principals / Agent Objects)" = $OwnerSP
            "Nested owners (User)" = $NestedOwnerUser
            "Nested Owners (Service Principals / Agent Objects)" = $NestedOwnerSP
            "Nested Groups" = $NestedGroups
            "Nested Users" = $NestedUsers
            "Nested SP" = $NestedSP 
            "Nested Devices " = $NestedDevices 
            "Nested in Groups " = $NestedInGroups
            "Owned Groups (PIM for Groups)" = $OwnedGroups
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

        #Write TXT report chunk
        if (-not $SkipTxtReport) {
            [void]$DetailTxtBuffer.AppendLine($DetailTxtBuilder.ToString())
            $DetailTxtBuilder.Clear() > $null
            $BufferedCount++

            if ($BufferedCount -ge $BufferThreshold) {
                $DetailTxtBuffer.ToString() | Out-File -Width 512 -Append -FilePath $DetailReportPath
                $DetailTxtBuffer.Clear() > $null
                $BufferedCount = 0
            }
        }

    }

    # Flush remaining buffered content after loop
    if (-not $SkipTxtReport -and $BufferedCount -gt 0) {
        $DetailTxtBuffer.ToString() | Out-File -Width 512 -Append -FilePath $DetailReportPath
    }

    write-host "[*] Writing Reports"
    write-host ""

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Groups Details</h2>
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


    #Define Appendix
$AppendixTitle = "

###############################################################################################################################################
Appendix: Dynamic Groups
###############################################################################################################################################
    "
    
    $PmGeneratingDetails.Stop()
    $PmWritingReports = [System.Diagnostics.Stopwatch]::StartNew()

    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'Groups' -CurrentReportName 'Groups Enumeration' -Warnings $GroupScriptWarningList


    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@



    ########################################## SECTION: OUTPUT WRITING ##########################################

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Csv) {
        $tableOutput | select-object DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }

    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $($tableOutput.count) groups stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    If ($DynamicGroupsCount -gt 0) {
        $AppendixTitle | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixDynamic | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixDynamicHTML = $AppendixDynamic | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Dynamic Groups</h2>"
    }

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixDynamicHTML
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - Groups</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $PmWritingReports.Stop()
    $PmEndTasks = [System.Diagnostics.Stopwatch]::StartNew()

    #Add information to the enumeration summary
    $M365Count = 0
    $OnPremCount = 0
    $PublicM365 = 0
    $PimOnboarded = 0

    foreach ($group in $AllGroupsDetails) {
        if ($group.Type -eq "M365 Group") {
            $M365Count++
            if ($group.Visibility -eq "Public") {
                $PublicM365++
            }
        }
        if ($group.OnPrem) {
            $OnPremCount++
        }
        if ($group.PIM -eq $true) {
            $PimOnboarded++
        }       
    }

    # Store in global var
    $GlobalAuditSummary.Groups.Count = $GroupsTotalCount
    $GlobalAuditSummary.Groups.M365 = $M365Count
    $GlobalAuditSummary.Groups.PublicM365 = $PublicM365
    $GlobalAuditSummary.Groups.OnPrem = $OnPremCount
    $GlobalAuditSummary.Groups.PimOnboarded = $PimOnboarded

    #Dump data for QA checks
    if ($QAMode) {
        $AllGroupsDetails | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputFolder\QA_AllGroupsDetails.json" -Encoding utf8
    }

    #Convert to Hashtable for faster searches
    $AllGroupsDetailsHT = @{}

    foreach ($group in $AllGroupsDetails) {
        $AllGroupsDetailsHT[$group.Id] = [PSCustomObject]@{
            DisplayName   = $group.DisplayName
            Type = $group.Type
            Visibility = $group.Visibility
            RoleAssignable = $group.RoleAssignable
            SecurityEnabled = $group.SecurityEnabled
            OnPrem = $group.OnPrem
            Dynamic = $group.dynamic
            EntraRoles  = $group.EntraRoles
            EntraMaxTier = $group.EntraMaxTier
            EntraRoleDetails = $group.EntraRoleDetails
            CAPs = $group.CAPs
            AzureRoles = $group.AzureRoles
            AzureMaxTier = $group.AzureMaxTier
            AzureRoleDetails = $group.AzureRoleDetails
            AppRoles = $group.AppRoles
            Users = $group.Users
            MembershipRule = $group.MembershipRule
            Userdetails = $group.Userdetails
            Guests = $group.Guests
            NestedGroups = $group.NestedGroups
            SPCount = $group.SPCount
            Protected = $group.Protected
            PIM = $group.PIM
            Impact = $group.Impact
            ImpactOrg = $group.ImpactOrg
            ImpactOrgActiveOnly = $group.ImpactOrgActiveOnly
            Likelihood = $group.Likelihood
            Warnings = $group.Warnings
            EntraRolePrivilegedCount = $group.EntraRolePrivilegedCount
            InheritedHighValue = $group.InheritedHighValue
            DirectActiveMembers = $group.DirectActiveMembers
            DirectActiveOwners = $group.DirectActiveOwners
            DirectOwners = $group.DirectOwners
            NestedOwners = $group.NestedOwners
        }
    }
       
    Remove-Variable Report
    Remove-Variable tableOutput
    Remove-Variable AllGroupsDetails
    Remove-Variable details

    $PmEndTasks.Stop()
    $PmScript.Stop()

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

    return $AllGroupsDetailsHT
}
