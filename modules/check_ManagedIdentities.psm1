<#
.SYNOPSIS
   Enumerate Managed Identities (including: API Permission, Source Tenant, Groups, Roles).
#>

function Invoke-CheckManagedIdentities {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$AgentObjectBasics,
        [Parameter(Mandatory=$false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory = $true)][int]$ApiTop,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "ManagedIdentities"
    $ProgressCounter = 0
    $ManagedIdentitiesScriptWarningList = @()
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $SPImpactScore = @{
        "Base"                     = 1
        "CAPGroupOwner"             = 100
        "InheritedHighValue"        = 200
        "APIDangerous"              = 800
        "APIHigh"                   = 400
        "APIMedium"                 = 100
        "APILow"                    = 50
        "ApiMisc"                   = 20
	    "GroupMember"               = 5
	    "GroupOwner"                = 5
        "AppRole"                   = 2
    }

    $SPLikelihoodScore = @{
        "Base"          	        = 1
    }

    function Resolve-ManagedIdentityOwnedAgentObject {
        param(
            [Parameter(Mandatory = $true)]$OwnedObject
        )

        $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $OwnedObject.Id -RawType $OwnedObject.'@odata.type' -CurrentTenant $CurrentTenant -AllUsersBasicHT @{} -AllGroupsDetails @{} -ServicePrincipalBasics @{} -AgentObjectBasics $AgentObjectBasics
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
    # Get Managed Identity
    write-host "[*] Get Managed Identities"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'ManagedIdentity'"
        '$select' = "Id,DisplayName,AppId,AppRoles,servicePrincipalType,createdDateTime,PasswordCredentials,KeyCredentials,AlternativeNames"
        '$top' = $ApiTop
    }
    $ManagedIdentities = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))

    
    $ManagedIdentitiesCount = $($ManagedIdentities.count)
    write-host "[+] Got $ManagedIdentitiesCount Managed Identities"

    # Check if Azure IAM role were checked
    if (-not ($GLOBALAzurePsChecks)) {
        if ($GLOBALAzureIamWarningText) {
            $ManagedIdentitiesScriptWarningList += $GLOBALAzureIamWarningText
        } else {
            $ManagedIdentitiesScriptWarningList += "Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to MI are therefore missing from this report."
        }
    }

    if ($ManagedIdentitiesCount -ge 1) {
        Write-Host "[*] Get all applications API permissions assignments"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
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
        Write-Log -Level Debug -Message "Got $($AppAssignmentsRaw.count) assignments"



        Write-Host "[*] Get all applications group memberships"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
            $Requests += @{
                "id"     = $($_.id)
                "method" = "GET"
                "url"    =   "/servicePrincipals/$($_.id)/transitiveMemberOf/microsoft.graph.group?`$select=Id,displayName,visibility,securityEnabled,groupTypes,isAssignableToRole"
                "$top" = $ApiTop
            }
        }
        # Send Batch request and create a hashtable
        $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        $GroupMemberRaw = @{}
        foreach ($item in $RawResponse) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $GroupMemberRaw[$item.id] = $item.response.value
            }
        }
        Write-Log -Level Debug -Message "Got $($GroupMemberRaw.count) memberships"

        Write-Host "[*] Get all application object ownerships"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
            $Requests += @{
                "id"     = $($_.id)
                "method" = "GET"
                "url"    =   "/servicePrincipals/$($_.id)/ownedObjects"
            }
        }
        # Send Batch request and create a hashtable
        $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        $OwnedObjectsRaw = @{}
        foreach ($item in $RawResponse) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $OwnedObjectsRaw[$item.id] = $item.response.value
            }
        }
        Write-Log -Level Debug -Message "Got $($OwnedObjectsRaw.count) ownerships"
    }


    ########################################## SECTION: Managed Identity Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($ManagedIdentitiesCount / 10), 1)
    if ($ManagedIdentitiesCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing managed identity 1 of $ManagedIdentitiesCount (updates every $StatusUpdateInterval managed identities)..."
    }
    
    #region Processing Loop
    #Loop through each Managed Identity and get additional info and store it in a custom object
    foreach ($item in $ManagedIdentities) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = $SPLikelihoodScore["Base"] 
        $warnings = @()
        $WarningsHighPermission = $null
        $WarningsDangerousPermission = $null
        $AppCredentials = @()
        

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $ManagedIdentitiesCount) {
            Write-Host "[*] Status: Processing managed identity $ProgressCounter of $ManagedIdentitiesCount..."
        }

        # Check AlternativeNames in a safe way
        $IsExplicit = $false
        $MiPath = "Unknown"
        $explicitEntry = $null
        if ($item.AlternativeNames -and $item.AlternativeNames.Count -gt 0) {
            $explicitEntry = $item.AlternativeNames | Where-Object { $_ -like 'isExplicit=*' } | Select-Object -First 1
            if ($explicitEntry -and $explicitEntry -match '^isExplicit=(?<val>true|false)$') {
                $IsExplicit = [bool]::Parse($Matches['val'])
            }

            $pathEntry = $item.AlternativeNames | Where-Object { $_ -and $_ -notlike 'isExplicit=*' } | Select-Object -First 1
            if (-not [string]::IsNullOrWhiteSpace($pathEntry)) {
                $MiPath = $pathEntry.Trim()
            }

            # Substitute subscription ID with display name when available
            if ($global:GLOBALAzureSubscriptionScopeMap -and $MiPath -imatch '^/subscriptions/([^/]+)(/.*)$') {
                $subName = $global:GLOBALAzureSubscriptionScopeMap[$Matches[1].ToLowerInvariant()]
                if (-not [string]::IsNullOrWhiteSpace($subName)) {
                    $MiPath = "/subscriptions/$subName$($Matches[2])"
                }
            }
        }

        if (-not $item.AlternativeNames) {
            Write-Log -Level Trace -Message "Managed Identity '$($item.DisplayName)' ($($item.Id)) has no AlternativeNames"
        } elseif (-not $explicitEntry) {
            Write-Log -Level Trace -Message "Managed Identity '$($item.DisplayName)' ($($item.Id)) AlternativeNames missing isExplicit=..."
        } elseif ($MiPath -eq 'Unknown') {
            Write-Log -Level Trace -Message "Managed Identity '$($item.DisplayName)' ($($item.Id)) AlternativeNames missing resource path"
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
        
        #Get the applications API permission
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
                        $resolvedOwnedObject = Resolve-ManagedIdentityOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedBlueprints.Add($resolvedOwnedObject)
                        }
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        $resolvedOwnedObject = Resolve-ManagedIdentityOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedBlueprintPrincipals.Add($resolvedOwnedObject)
                        }
                    }

                    '#microsoft.graph.agentIdentity' {
                        $resolvedOwnedObject = Resolve-ManagedIdentityOwnedAgentObject -OwnedObject $OwnedObject
                        if ($resolvedOwnedObject) {
                            [void]$OwnedAgentIdentities.Add($resolvedOwnedObject)
                        }
                    }

                }
            }
        }

        #Process owned groups
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
            Write-Log -Level Debug -Message "AzureMaxTier '-' with AzureRoleCount $AzureRoleCount for managed identity '$($item.DisplayName)' ($($item.Id))"
        }
        if ($AppEntraRoles -and $AppEntraRoles.Count -gt 0 -and $EntraMaxTier -eq "-") {
            Write-Log -Level Debug -Message "EntraMaxTier '-' with EntraRoleCount $($AppEntraRoles.Count) for managed identity '$($item.DisplayName)' ($($item.Id))"
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


    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################        
        $AppCredentialsCount = ($AppCredentials | Measure-Object).count

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
        }

        #If SP owns App Registration
        if ($OwnedApplicationsCount -ge 1) {
            $Warnings += "SP owns $OwnedApplicationsCount App Registrations!" 
        }

        #If SP owns Agent Identity Blueprint
        if ($OwnedBlueprintsCount -ge 1) {
            $Warnings += "SP owns $OwnedBlueprintsCount Agent Identity Blueprint(s)!"
        }

        #If SP owns App Registration
        if ($OwnedSPCount -ge 1) {
            $Warnings += "SP owns $OwnedSPCount Enterprise Applications!" 
        }

        #Process group memberships
        if (($GroupMember | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $TotalAzureRoles = 0

            #Basic score for being member of a group
            $ImpactScore += $SPImpactScore["GroupMember"]

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


        if (($AppApiPermission | Measure-Object).Count -ge 1) {
            foreach ($object in $AppApiPermission) {
                switch($object.ApiPermissionCategorization) {
                    "Dangerous" {$ImpactScore += $SPImpactScore["APIDangerous"]; $WarningsDangerousPermission = $true ; Break}
                    "High" {$ImpactScore += $SPImpactScore["APIHigh"]; $WarningsHighPermission = $true; Break}
                    "Medium" {$ImpactScore += $SPImpactScore["APIMedium"]; Break}
                    "Low" {$ImpactScore += $SPImpactScore["APILow"]; Break}
                    "Uncategorized" {$ImpactScore += $SPImpactScore["ApiMisc"]; Break}
                }
            }
        }

        # Calculate days since creation
        $CreationInDays = if ($item.createdDateTime) {
            $created = [datetime]::Parse($item.createdDateTime, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)

            (New-TimeSpan -Start $created -End (Get-Date).ToUniversalTime()).Days
        } else {
            "-"
        }

        # Build the warning parts dynamically
        [string[]]$severities = @()
        if ($WarningsDangerousPermission) { $severities += "dangerous" }
        if ($WarningsHighPermission)      { $severities += "high" }

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
        $EntraRolesEffective = $EntraRolesDirect + $EntraRolesThroughGroupMembership + $EntraRolesThroughGroupOwnership
        $AzureRolesEffective = $AzureRolesDirect + $AzureRolesThroughGroupMembership + $AzureRolesThroughGroupOwnership
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
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            AppId = $item.AppId
            ServicePrincipalType = $item.servicePrincipalType
            GroupMembership = ($GroupMember | Measure-Object).count
            EntraRolesDirect = $EntraRolesDirect
            EntraRolesEffective = $EntraRolesEffective
            EntraRoles = $EntraRolesEffective
            EntraMaxTier = $EntraMaxTier
            PermissionCount = ($AppAssignments | Measure-Object).count
            GroupOwnership = ($OwnedGroups | Measure-Object).count
            AppOwnership = $OwnedApplicationsCount
            BlueprintOwn = $OwnedBlueprintsCount
            OwnedApplicationsDetails = $OwnedApplications
            OwnedBlueprintsDetails = $OwnedBlueprints
            OwnedBlueprintPrincipalsDetails = $OwnedBlueprintPrincipals
            OwnedAgentIdentitiesDetails = $OwnedAgentIdentities
            SpOwn = $OwnedSPCount
            GroupMember = $GroupMember
            EntraRoleDetails = $AppEntraRoles
            GroupOwner = $OwnedGroups
            AppPermission = $AppAssignments
            IsExplicit = $IsExplicit
            MiPath = $MiPath
            CreationDate = $item.createdDateTime
            CreationInDays = $CreationInDays
            AzureRolesDirect = $AzureRolesDirect
            AzureRolesEffective = $AzureRolesEffective
            AzureRoles = $AzureRolesEffective
            AzureMaxTier = $AzureMaxTier
            AzureRoleDetails = $AzureRoleDetails
            AppCredentials = $AppCredentialsCount
            AppCredentialsDetails = $AppCredentials
            AppApiPermission = $AppApiPermission
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

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"

    #Define output of the main table
    $tableOutput = $AllServicePrincipal | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,IsExplicit,CreationInDays,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AppCredentials,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings
    
    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllServicePrincipal | Sort-Object Risk -Descending

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    #Enum the details for the apps in scope
    foreach ($item in $details) {
        $ReportingMIInfo = @()
        $ReportingRoles = @()
        $ReportingAzureRoles = @()
        $ReportingAPIPermission = @()
        $ReportingAppOwner = @()
        $ReportingBlueprintOwner = @()
        $ReportingBlueprintPrincipalOwner = @()
        $ReportingAgentIdentityOwner = @()
        $ReportingGroupMember = @()
        $ReportingGroupOwner = @()
        $ReportingCredentials = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################`n")

        ############### HEADER
        $ReportingMIInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "CreationDate" = $($item.CreationDate)
            "Custom Identity" = $($item.IsExplicit)
            "Object Path" = $($item.MiPath)
            "RiskScore" = $($item.Risk)
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","App Client-ID","App Object-ID","CreationDate","Custom Identity","Object Path","RiskScore")

        if ($item.Warnings -ne '') {
            $ReportingMIInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingMIInfo | Select-Object $TxtReportProps | Out-String))
        
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Active Entra Role Assignments`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | Out-String))
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | Out-String))
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owner of Groups`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupOwner | Format-Table DisplayName,SecurityEnabled,RoleAssignable,EntraRoles,AzureRoles,CAPs,ImpactOrg,Warnings | Out-String))
            
            $ReportingGroupOwner = foreach ($obj in $ReportingGroupOwner) {
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owned App Registrations`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owned Blueprints`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owned Blueprint Principals`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owned Agent Identities`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAgentIdentityOwner | Format-Table DisplayName,Enabled,PublisherName | Out-String))
            $ReportingAgentIdentityOwner = foreach ($obj in $ReportingAgentIdentityOwner) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Enabled       = $obj.Enabled
                    PublisherName = $obj.PublisherName
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Member in Groups (transitive)`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
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

        ############### Managed Identity Credentials
        if ($($item.AppCredentialsDetails | Measure-Object).count -ge 1) {
            $ReportingCredentials = foreach ($object in $($item.AppCredentialsDetails)) {
                [pscustomobject]@{ 
                    "Type" = $($object.Type)
                    "DisplayName" = $($object.DisplayName)
                    "StartDateTime" = $(if ($null -ne $object.StartDateTime) { $object.StartDateTime.ToString() } else { "-" })
                    "EndDateTime" = $(if ($null -ne $object.EndDateTime) { $object.EndDateTime.ToString() } else { "-" })
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Managed Identity Credentials`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String -Width 512))
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Application)`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAPIPermission | Out-String))
        }


        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information" = $ReportingMIInfo
            "Active Entra Role Assignments" = $ReportingRoles
            "Azure IAM assignment" = $ReportingAzureRoles
            "API Permission (Application)" = $ReportingAPIPermission
            "Owned App Registrations" = $ReportingAppOwner
            "Owned Blueprints" = $ReportingBlueprintOwner
            "Owned Blueprint Principals" = $ReportingBlueprintPrincipalOwner
            "Owned Agent Identities" = $ReportingAgentIdentityOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Owner of Groups" = $ReportingGroupOwner
            "Credentials" = $ReportingCredentials
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)


    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()
    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},IsExplicit,CreationInDays,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Managed Identities Details</h2>
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
Execution Warnings = $($ManagedIdentitiesScriptWarningList -join ' / ')
************************************************************************************************************************
"

#Define Appendix
$AppendixHeaderTXT = "

=======================================================================================================================
Appendix: Used API permission reference
=======================================================================================================================
"

    #It could be that the tenant does not contain managed identities.
    if ($ManagedIdentitiesCount -ge 1) {

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
        Set-GlobalReportManifest -CurrentReportKey 'MI' -CurrentReportName 'ManagedIdentities Enumeration' -Warnings $ManagedIdentitiesScriptWarningList

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
        $tableOutput | format-table DisplayName,IsExplicit,CreationInDays,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        if ($Csv) {
            $tableOutput | select-object DisplayName,IsExplicit,CreationInDays,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
        }
        $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixHeaderTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $ApiPermissionReference | Format-Table -AutoSize | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append

        #Write HTML
        $ApiPermissionReferenceHTML += $ApiPermissionReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
        $PostContentCombined = $GLOBALJavaScript + "`n" + $ApiPermissionReferenceHTML
        $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - Managed Identities</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
        $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"
        $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
        write-host "[+] Details of $ManagedIdentitiesCount Managed Identities stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
    } else {
        write-host "[-] No managed Identities exist."
        write-host "[-] No logs have been written."
    }

    #Add information to the enumeration summary
    $IsExplicit = 0
    $AppApiDangerous = 0
    $AppApiHigh = 0
    $AppApiMedium = 0
    $AppApiLow = 0
    $AppApiMisc = 0

    foreach ($app in $AllServicePrincipal) {
        if ($app.IsExplicit) {
            $IsExplicit++
        }

        if ($app.ApiDangerous) {$AppApiDangerous++}
        if ($app.ApiHigh) {$AppApiHigh++}
        if ($app.ApiMedium) {$AppApiMedium++}
        if ($app.ApiLow) {$AppApiLow++}
        if ($app.ApiMisc) {$AppApiMisc++}
    }

    # Store in global var
    $GlobalAuditSummary.ManagedIdentities.Count = $ManagedIdentitiesCount
    $GlobalAuditSummary.ManagedIdentities.IsExplicit = $IsExplicit  
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Dangerous = $AppApiDangerous
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.High = $AppApiHigh
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Medium = $AppApiMedium
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Low = $AppApiLow
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Misc = $AppApiMisc


    #Convert to Hashtable for faster searches
    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    Return $AllServicePrincipalHT

}
