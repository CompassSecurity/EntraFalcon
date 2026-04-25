<#
.SYNOPSIS
   Enumerate Agent Identity Blueprints (including: API Permission (Application), Owner, Secrets, Certificates, Access through App Roles etc.).

.DESCRIPTION
   This script will enumerate all Agent Identity Blueprints (including: API Permission (Application), Owner, Secrets, Certificates, Active access through App Roles, blueprint property lock).

#>
function Invoke-AgentIdentityBlueprints {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AppRoleReferenceCache = @{},
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AgentIdentityBlueprintsPrincipals
    )

    ############################## Function section ########################
    #Function to deliver detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
    #The type can be specified to save some GraphAPI calls
    function GetObjectInfo($Object,$type="unknown"){
        if ($type -eq "unknown" -or $type -eq "user" -or $type -eq "agentUser") {
            $QueryParameters = @{
                '$select' = "DisplayName,UserPrincipalName,UserType,OnPremisesSyncEnabled,AccountEnabled,jobTitle,Department"
            }
            $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$Object" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)

            if ($user) {
                If ($Null -eq $User.OnPremisesSyncEnabled) {
                    $onprem = $False
                } else {
                    $onprem = $True
                }
                If ($Null -eq $User.JobTitle) {
                    $JobTitle = "-"
                } else {
                    $JobTitle = $User.JobTitle
                }

                If ($Null -eq $User.Department) {
                    $Department = "-"
                } else {
                    $Department = $User.Department
                }
                [PSCustomObject]@{
                    Type = "User"
                    DisplayName = $User.DisplayName
                    UPN= $User.UserPrincipalName
                    UserType = $User.UserType
                    Enabled = $User.AccountEnabled
                    Onprem = $onprem
                    JobTitle = $JobTitle
                    Department = $Department
                }
            }
        }

        if ($type -eq "unknown" -or $type -eq "group" ) {
            #Takes information about the groups from $AllGroupsDetails parameter
            $MatchingGroup = $AllGroupsDetails[$($Object)]

            if (($MatchingGroup | Measure-Object).count -ge 1) {
                [PSCustomObject]@{
                    Type = "Group"
                    Id = $MatchingGroup.Id
                    DisplayName = $MatchingGroup.DisplayName
                    InheritedHighValue  = $MatchingGroup.InheritedHighValue
                    OnPrem  = $MatchingGroup.OnPrem
                    Users  = $MatchingGroup.Users
                    Guests  = $MatchingGroup.Guests
                    Owners  = $MatchingGroup.DirectOwners + $MatchingGroup.NestedOwners
                    LikelihoodScore  = $MatchingGroup.Likelihood
                }
            }
        }

        if ($type -eq "unknown" -or $type -eq "ServicePrincipal" ) {
            $MatchingEnterpriseApp = $EnterpriseApps[$($Object)]

            if (($MatchingEnterpriseApp | Measure-Object).count -ge 1) {
                [PSCustomObject]@{
                    Type = "ServicePrincipal"
                    Id = $MatchingEnterpriseApp.Id
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    Foreign = $MatchingEnterpriseApp.Foreign
                    PublisherName = $MatchingEnterpriseApp.PublisherName
                    OwnersCount = $MatchingEnterpriseApp.Owners
                }
            }
        }

        if ($type -eq "unknown" -or $type -eq "agentIdentityBlueprintPrincipal") {
            $MatchingBlueprintPrincipal = $AgentIdentityBlueprintsPrincipals[$($Object)]

            if (($MatchingBlueprintPrincipal | Measure-Object).Count -ge 1) {
                [PSCustomObject]@{
                    Type = "AgentIdentityBlueprintPrincipal"
                    Id = $MatchingBlueprintPrincipal.Id
                    DisplayName = $MatchingBlueprintPrincipal.DisplayName
                    Foreign = $MatchingBlueprintPrincipal.Foreign
                    PublisherName = $MatchingBlueprintPrincipal.PublisherName
                    OwnersCount = $MatchingBlueprintPrincipal.Owners
                    Enabled = $MatchingBlueprintPrincipal.Enabled
                }
            }
        }

        if ($type -eq "Secret" ) {
            if ($null -ne $Object.EndDateTime) {
                if (($Object.EndDateTime - (Get-Date).Date).TotalDays -le 0) {
                    $Expired = $True
                } else {
                    $Expired = $False
                }
            }
            [PSCustomObject]@{
                Type = "Secret"
                DisplayName = $Object.DisplayName
                EndDateTime = $Object.EndDateTime
                Expired = $Expired
                Hint = $Object.Hint
            }

        }

        if ($type -eq "Cert" ) {

            if ($null -ne $Object.EndDateTime) {
                if (($Object.EndDateTime - (Get-Date).Date).TotalDays -le 0) {
                    $Expired = $True
                } else {
                    $Expired = $False
                }
            }
            [PSCustomObject]@{
                Type = "Cert"
                DisplayName = $Object.DisplayName
                EndDateTime = $Object.EndDateTime
                Expired = $Expired
            }
        }
    }

    function Resolve-InheritablePermissionApiName {
        param(
            [Parameter(Mandatory = $true)][string]$ResourceAppId,
            [Parameter(Mandatory = $true)][hashtable]$ResourceApiDisplayNameCache
        )

        if ([string]::IsNullOrWhiteSpace($ResourceAppId) -or $ResourceAppId -eq "-") {
            return "-"
        }

        if ($ResourceApiDisplayNameCache.ContainsKey($ResourceAppId)) {
            return $ResourceApiDisplayNameCache[$ResourceAppId]
        }

        $CachedApiName = Get-AppRoleReferenceApiName -AppRoleReferenceCache $AppRoleReferenceCache -ResourceAppId $ResourceAppId
        if (-not [string]::IsNullOrWhiteSpace($CachedApiName) -and $CachedApiName -ne "-") {
            $ResourceApiDisplayNameCache[$ResourceAppId] = $CachedApiName
            return $CachedApiName
        }

        $QueryParameters = @{
            '$filter' = "appId eq '$ResourceAppId'"
            '$select' = "displayName,appId"
            '$top' = "1"
        }

        $MatchingServicePrincipal = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        if (($MatchingServicePrincipal | Measure-Object).Count -ge 1) {
            $ApiDisplayName = if ([string]::IsNullOrWhiteSpace($MatchingServicePrincipal[0].displayName)) { "-" } else { $MatchingServicePrincipal[0].displayName }
            $ResourceApiDisplayNameCache[$ResourceAppId] = $ApiDisplayName
            return $ApiDisplayName
        }

        $ResourceApiDisplayNameCache[$ResourceAppId] = "-"
        return "-"
    }

    function Resolve-InheritablePermissionRoleValues {
        param(
            [Parameter(Mandatory = $true)][string]$ResourceAppId,
            [AllowNull()][object[]]$RoleIds = @()
        )

        $ResolvedRoleValues = foreach ($RoleId in @($RoleIds)) {
            if ([string]::IsNullOrWhiteSpace("$RoleId".Trim())) {
                continue
            }

            $ResolvedRole = Resolve-AppRoleReference -AppRoleReferenceCache $AppRoleReferenceCache -PermissionId "$RoleId".Trim() -ResourceAppId $ResourceAppId
            if ($ResolvedRole) {
                $ResolvedRole.ApiPermission
            } else {
                "$RoleId".Trim()
            }
        }

        if (($ResolvedRoleValues | Measure-Object).Count -ge 1) {
            return ($ResolvedRoleValues -join ", ")
        }

        return "-"
    }


    ############################## Script section ########################

    # Check token and trigger refresh if required
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $ProgressCounter = 0
    $AllAgentIdentityBlueprints = [System.Collections.ArrayList]::new()
    $AppLikelihoodScore = @{
        "AppBase"                   = 1
        "AppSecret"                 = 5
        "EntraConnectIoC"           = 200
        "AppCertificate"            = 2
        "AppOwner"          	    = 20
	    "InternalSPOwner"		    = 5
	    "ExternalSPOwner"		    = 50
	    "GuestAsOwner"		        = 50
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Agent Identity Blueprint Definitions
    write-host "[*] Get Agent Identity Blueprint Definitions"
    $QueryParameters = @{
        '$select' = "Id,AppID,DisplayName,SignInAudience,isDisabled,RequiredResourceAccess,web,createdDateTime,KeyCredentials,PasswordCredentials,AppRoles,api"
    }
    $BlueprintDefinitions = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications/microsoft.graph.agentIdentityBlueprint' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $BlueprintCount = $($BlueprintDefinitions.count)
    write-host "[+] Got $BlueprintCount Agent Identity Blueprints"

    #Abort if no blueprints are present
    if (@($BlueprintDefinitions).count -eq 0) {
        $AllAgentIdentityBlueprintsHT = @{}
        Return $AllAgentIdentityBlueprintsHT
    }
    Write-Host "[*] Get all owners"
    $Requests = @()
    $BlueprintDefinitions | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/applications/$($_.id)/owners"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppOwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppOwnersRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all sponsors"
    $Requests = @()
    $BlueprintDefinitions | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/applications/$($_.id)/microsoft.graph.agentIdentityBlueprint/sponsors"
        }
    }
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppSponsorsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppSponsorsRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all inheritable permissions"
    $Requests = @()
    $BlueprintDefinitions | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/applications/$($_.id)/microsoft.graph.agentIdentityBlueprint/inheritablePermissions"
        }
    }
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppInheritablePermissionsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppInheritablePermissionsRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all federated identity credentials"
    $Requests = @()
    $BlueprintDefinitions | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/applications/$($_.id)/microsoft.graph.agentIdentityBlueprint/federatedIdentityCredentials"
        }
    }
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppFederatedIdentityCredentialsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppFederatedIdentityCredentialsRaw[$item.id] = $item.response.value
        }
    }

    # Cache API display names by appId to enrich inheritable-permission output
    $ResourceApiDisplayNameCache = @{}
    if ($AppRoleReferenceCache.ContainsKey('ApiNamesByAppId')) {
        foreach ($entry in $AppRoleReferenceCache.ApiNamesByAppId.GetEnumerator()) {
            if (-not [string]::IsNullOrWhiteSpace($entry.Key) -and -not [string]::IsNullOrWhiteSpace($entry.Value) -and -not $ResourceApiDisplayNameCache.ContainsKey($entry.Key)) {
                $ResourceApiDisplayNameCache[$entry.Key] = $entry.Value
            }
        }
    }
    foreach ($EnterpriseApp in $EnterpriseApps.Values) {
        if (-not [string]::IsNullOrWhiteSpace($EnterpriseApp.AppId) -and -not $ResourceApiDisplayNameCache.ContainsKey($EnterpriseApp.AppId)) {
            $ResourceApiDisplayNameCache[$EnterpriseApp.AppId] = if ([string]::IsNullOrWhiteSpace($EnterpriseApp.DisplayName)) { "-" } else { $EnterpriseApp.DisplayName }
        }
    }


    ########################################## SECTION: Data Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($BlueprintCount / 10), 1)
    if ($BlueprintCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing blueprint 1 of $BlueprintCount (updates every $StatusUpdateInterval objects)..."
    }

    #region Processing Loop
    #Loop through each app and get additional info and store it in a custom object
    foreach ($item in $BlueprintDefinitions) {
        $ImpactScore = 0
        $LikelihoodScore = $AppLikelihoodScore["AppBase"]
        $warnings = @()
        $AppRolesDetails = @()
        $Oauth2PermissionScopesDetails = @()
        $AppCredentials = @()
        $SPObjectID = @()
        $DirectImpactScore = 0
        $InheritedImpactScore = 0
        $AppHomePage = $null
        $BlueprintEnabled = -not ($item.isDisabled -eq $true)

        $ProgressCounter ++

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $BlueprintCount) {
            Write-Host "[*] Status: Processing blueprint $ProgressCounter of $BlueprintCount..."
        }

        # Check if it the Entra Connect Sync App
        if ($item.DisplayName -match "ConnectSyncProvisioning_") {
            $EntraConnectApp = $true
            $Warnings += "Entra Connect Application!"
        } else {
            $EntraConnectApp = $false
        }

        #Process app credentials
        $AppCredentialsSecrets = foreach ($creds in $item.PasswordCredentials) {
            $Expired = $null

            if ($null -ne $creds.EndDateTime) {
                try {
                    $endDate = [datetime]$creds.EndDateTime
                    $Expired = ($endDate - (Get-Date)).TotalDays -le 0
                } catch {
                    $Expired = "?"
                }
            }
            #The object for apps with secrets require the appname for seperate output file
            [pscustomobject]@{
                Type = "Secret"
                DisplayName = if ([string]::IsNullOrWhiteSpace($creds.DisplayName)) { "-" } else { $creds.DisplayName }
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
                Expired = $Expired
                AppName = $item.DisplayName
            }
        }

        $AppRolesDetails = foreach ($roles in $item.AppRoles) {
            [pscustomobject]@{
                DisplayName = if ([string]::IsNullOrWhiteSpace($roles.DisplayName)) { "-" } else { $roles.DisplayName }
                Enabled = $roles.IsEnabled
                Claim = $roles.Value
                Description = $roles.Description
                MemberTypes = ($roles.AllowedMemberTypes -join ' / ')
            }
        }

        $Oauth2PermissionScopesDetails = foreach ($scope in @($item.api.oauth2PermissionScopes)) {
            [pscustomobject]@{
                Value = if ([string]::IsNullOrWhiteSpace($scope.value)) { "-" } else { $scope.value }
                IsEnabled = [bool]$scope.isEnabled
                Type = if ([string]::IsNullOrWhiteSpace($scope.type)) { "-" } else { $scope.type }
                IsPrivate = [bool]$scope.isPrivate
            }
        }

        $AppCredentialsCertificates = foreach ($creds in $item.KeyCredentials) {
            $Expired = $null

            if ($null -ne $creds.EndDateTime) {
                try {
                    $endDate = [datetime]$creds.EndDateTime
                    $Expired = ($endDate - (Get-Date)).TotalDays -le 0
                } catch {
                    $Expired = "?"
                }
            }
            [pscustomobject]@{
                Type = "Certificate"
                DisplayName = if ([string]::IsNullOrWhiteSpace($creds.DisplayName)) { "-" } else { $creds.DisplayName }
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
                Expired = $Expired
            }
        }
        $AppCredentials += $AppCredentialsSecrets
        $AppCredentials += $AppCredentialsCertificates

        #Get application home page
        if ($null -ne $item.web.HomePageUrl) {
            $AppHomePage = $item.web.HomePageUrl
        }

        #Get owners of the sp
        $AppOwnerUsers  	= [System.Collections.ArrayList]::new()
        $AppOwnerSPs  	= [System.Collections.ArrayList]::new()
        if ($AppOwnersRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $AppOwnersRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.user' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$AppOwnerUsers.Add(
                            [PSCustomObject]@{
                                Id                      = $OwnedObject.Id
                                displayName             = $OwnedObject.displayName
                                userPrincipalName       = $OwnedObject.userPrincipalName
                                accountEnabled          = $OwnedObject.accountEnabled
                                userType                = $OwnedObject.userType
                                Department              = $OwnedObject.department
                                JobTitle                = $OwnedObject.jobTitle
                                onPremisesSyncEnabled   = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType          = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.agentUser' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$AppOwnerUsers.Add(
                            [PSCustomObject]@{
                                Id                      = $OwnedObject.Id
                                displayName             = $OwnedObject.displayName
                                userPrincipalName       = $OwnedObject.userPrincipalName
                                accountEnabled          = $OwnedObject.accountEnabled
                                userType                = $OwnedObject.userType
                                Department              = $OwnedObject.department
                                JobTitle                = $OwnedObject.jobTitle
                                onPremisesSyncEnabled   = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType          = 'Active'
                            }
                        )
                    }

                    '#graph.agentUser' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$AppOwnerUsers.Add(
                            [PSCustomObject]@{
                                Id                      = $OwnedObject.Id
                                displayName             = $OwnedObject.displayName
                                userPrincipalName       = $OwnedObject.userPrincipalName
                                accountEnabled          = $OwnedObject.accountEnabled
                                userType                = $OwnedObject.userType
                                Department              = $OwnedObject.department
                                JobTitle                = $OwnedObject.jobTitle
                                onPremisesSyncEnabled   = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType          = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                DisplayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                PublisherName          = $OwnedObject.publisherName
                                Foreign                = ($OwnedObject.appOwnerOrganizationId -ne $CurrentTenant.id)
                                OwnersCount            = $null
                                ServicePrincipalType   = $OwnedObject.servicePrincipalType
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = "ServicePrincipal"
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                DisplayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                PublisherName          = if ([string]::IsNullOrWhiteSpace($OwnedObject.publisherName)) { "-" } else { $OwnedObject.publisherName }
                                Foreign                = (-not [string]::IsNullOrWhiteSpace("$($OwnedObject.appOwnerOrganizationId)".Trim()) -and "$($OwnedObject.appOwnerOrganizationId)".Trim() -ne $CurrentTenant.id)
                                OwnersCount            = $null
                                ServicePrincipalType   = if ($null -ne $OwnedObject.servicePrincipalType) { $OwnedObject.servicePrincipalType } else { 'Application' }
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = "AgentIdentity"
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                DisplayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                PublisherName          = if ([string]::IsNullOrWhiteSpace($OwnedObject.publisherName)) { "-" } else { $OwnedObject.publisherName }
                                Foreign                = ("$($OwnedObject.appOwnerOrganizationId)".Trim() -ne $CurrentTenant.id)
                                OwnersCount            = $null
                                ServicePrincipalType   = if ($null -ne $OwnedObject.servicePrincipalType) { $OwnedObject.servicePrincipalType } else { 'Application' }
                                RawType                = $OwnedObject.'@odata.type'
                                Type                   = "AgentIdentityBlueprintPrincipal"
                            }
                        )
                    }
                }
            }
        }

        $AppOwnersCount = $AppOwnerUsers.Count + $AppOwnerSPs.count

        # Resolve sponsors for this blueprint
        $BlueprintSponsors = @()
        if ($AppSponsorsRaw.ContainsKey($item.Id)) {
            $BlueprintSponsors = foreach ($Sponsor in $AppSponsorsRaw[$item.Id]) {
                $SponsorType = switch ($Sponsor.'@odata.type') {
                    '#microsoft.graph.user' { 'user' }
                    '#microsoft.graph.agentUser' { 'agentUser' }
                    '#graph.agentUser' { 'agentUser' }
                    '#microsoft.graph.group' { 'group' }
                    '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
                    '#microsoft.graph.agentIdentityBlueprintPrincipal' { 'agentIdentityBlueprintPrincipal' }
                    '#graph.agentIdentityBlueprintPrincipal' { 'agentIdentityBlueprintPrincipal' }
                    default { 'unknown' }
                }

                $SponsorDetails = GetObjectInfo $Sponsor.Id -type $SponsorType
                if ($null -eq $SponsorDetails) {
                    [pscustomobject]@{
                        Id            = $Sponsor.Id
                        Type          = if ($SponsorType -eq 'unknown') { '-' } else { $SponsorType }
                        DisplayName   = "-"
                        UPN           = "-"
                        Foreign       = "-"
                        PublisherName = "-"
                    }
                } else {
                    [pscustomobject]@{
                        Id            = $Sponsor.Id
                        Type          = $SponsorDetails.Type
                        DisplayName   = if ([string]::IsNullOrWhiteSpace($SponsorDetails.DisplayName)) { "-" } else { $SponsorDetails.DisplayName }
                        UPN           = if ([string]::IsNullOrWhiteSpace($SponsorDetails.UPN)) { "-" } else { $SponsorDetails.UPN }
                        Foreign       = if ($null -eq $SponsorDetails.Foreign) { "-" } else { $SponsorDetails.Foreign }
                        PublisherName = if ([string]::IsNullOrWhiteSpace($SponsorDetails.PublisherName)) { "-" } else { $SponsorDetails.PublisherName }
                    }
                }
            }
        }

        # Normalize inheritable permissions for this blueprint
        $BlueprintInheritablePermissions = @()
        if ($AppInheritablePermissionsRaw.ContainsKey($item.Id)) {
            $BlueprintInheritablePermissions = foreach ($Permission in $AppInheritablePermissionsRaw[$item.Id]) {
                $ResourceAppId = if ([string]::IsNullOrWhiteSpace($Permission.resourceAppId)) { "-" } else { $Permission.resourceAppId }
                $ResourceApiName = Resolve-InheritablePermissionApiName -ResourceAppId $ResourceAppId -ResourceApiDisplayNameCache $ResourceApiDisplayNameCache
                $ScopeKind = if ([string]::IsNullOrWhiteSpace($Permission.inheritableScopes.kind)) { "-" } else { $Permission.inheritableScopes.kind }
                $RoleKind = if ([string]::IsNullOrWhiteSpace($Permission.inheritableRoles.kind)) { "-" } else { $Permission.inheritableRoles.kind }
                $RoleIds = @(@($Permission.inheritableRoles.appRoleIds) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                if ($RoleIds.Count -eq 0) {
                    $RoleIds = @(@($Permission.inheritableRoles.roles) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                }
                $HasScopeRow = $null -ne $Permission.inheritableScopes -and (
                    -not [string]::IsNullOrWhiteSpace($Permission.inheritableScopes.kind) -or
                    @($Permission.inheritableScopes.scopes).Count -gt 0 -or
                    -not [string]::IsNullOrWhiteSpace($Permission.inheritableScopes.'@odata.type')
                )
                $HasRoleRow = $null -ne $Permission.inheritableRoles -and (
                    -not [string]::IsNullOrWhiteSpace($Permission.inheritableRoles.kind) -or
                    $RoleIds.Count -gt 0 -or
                    -not [string]::IsNullOrWhiteSpace($Permission.inheritableRoles.'@odata.type')
                )

                if ($HasScopeRow) {
                    $scopeValues = @($Permission.inheritableScopes.scopes | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                    [pscustomobject]@{
                        ResourceApiName = $ResourceApiName
                        ResourceAppId   = $ResourceAppId
                        PermissionType  = "Delegated"
                        Kind            = $ScopeKind
                        PermissionValues = $scopeValues
                        Permissions     = if ($scopeValues.Count -gt 0) { ($scopeValues -join ", ") } else { "-" }
                    }
                }

                if ($HasRoleRow) {
                    $resolvedRoleDisplay = if ($RoleIds.Count -gt 0) { Resolve-InheritablePermissionRoleValues -ResourceAppId $ResourceAppId -RoleIds $RoleIds } else { "-" }
                    [pscustomobject]@{
                        ResourceApiName = $ResourceApiName
                        ResourceAppId   = $ResourceAppId
                        PermissionType  = "Application"
                        Kind            = $RoleKind
                        PermissionValues = @($RoleIds)
                        Permissions     = $resolvedRoleDisplay
                    }
                }
            }
        }

        # Normalize federated identity credentials for this blueprint
        $BlueprintFederatedIdentityCredentials = @()
        if ($AppFederatedIdentityCredentialsRaw.ContainsKey($item.Id)) {
            $BlueprintFederatedIdentityCredentials = foreach ($Credential in $AppFederatedIdentityCredentialsRaw[$item.Id]) {
                [pscustomobject]@{
                    Name        = if ([string]::IsNullOrWhiteSpace($Credential.name)) { "-" } else { $Credential.name }
                    Issuer      = if ([string]::IsNullOrWhiteSpace($Credential.issuer)) { "-" } else { $Credential.issuer }
                    Subject     = if ([string]::IsNullOrWhiteSpace($Credential.subject)) { "-" } else { $Credential.subject }
                    Description = if ([string]::IsNullOrWhiteSpace($Credential.description)) { "-" } else { $Credential.description }
                    Audiences   = if ($Credential.audiences) { ($Credential.audiences -join ", ") } else { "-" }
                }
            }
        }
        #Calculate likelihood for client credentials
        $SecretsCount = ($AppCredentialsSecrets | Measure-Object).Count
        $LikelihoodScore += $SecretsCount * $AppLikelihoodScore["AppSecret"]

        $CertificateCount = ($AppCredentialsCertificates | Measure-Object).Count
        $LikelihoodScore += $CertificateCount * $AppLikelihoodScore["AppCertificate"]

        # Warning if Entra Connect App has client secret
        if ($EntraConnectApp -and $SecretsCount -gt 0) {
            $LikelihoodScore += $AppLikelihoodScore["EntraConnectIoC"]
            $Warnings += "IoC: Entra Connect App with secrets!"
        }

        # Warning if Entra Connect App has mutiple certificates
        if ($EntraConnectApp -and $CertificateCount -gt 1) {
            $LikelihoodScore += $AppLikelihoodScore["EntraConnectIoC"]
            $Warnings += "IoC: Entra Connect App multiple certificates!"
        }

        #Check if there are owners
        if ($AppOwnersCount -ge 1) {
            $LikelihoodScore += $AppOwnersCount * $AppLikelihoodScore["AppOwner"]
            if ($EntraConnectApp) {
                $Warnings += "Entra Connect App with owner!"
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

        #SP as owner
        if (($AppOwnerSPs | Measure-Object).count -ge 1) {
            if ($AppOwnerSPs.Foreign -contains $true) {
                $Warnings += "Foreign SP as owner!"
                $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
            } elseif ($AppOwnerSPs.Foreign -contains $false) {
                $Warnings += "Internal SP as owner"
                $LikelihoodScore += $AppLikelihoodScore["InternalSPOwner"]
            }
        }


        if (($AppOwnerUsers | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as Owner!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }

        $BlueprintPrincipals = @($AgentIdentityBlueprintsPrincipals.Values | Where-Object { $_.AppId -eq $item.AppId } | Sort-Object Risk -Descending)
        $BlueprintLinkedAgentIdentities = @()

        if (($BlueprintPrincipals | Measure-Object).Count -ge 1) {
            $SPObjectID = @($BlueprintPrincipals | Select-Object -ExpandProperty Id)
            $InheritedImpactScore = [double](($BlueprintPrincipals | Measure-Object -Property Impact -Sum).Sum)

            foreach ($BlueprintPrincipal in $BlueprintPrincipals) {
                foreach ($LinkedAgentIdentity in @($BlueprintPrincipal.LinkedAgentIdentitiesDetails)) {
                    $BlueprintLinkedAgentIdentities += [pscustomobject]@{
                        Id = $LinkedAgentIdentity.Id
                        DisplayName = $LinkedAgentIdentity.DisplayName
                        Enabled = $LinkedAgentIdentity.Enabled
                        Type = $LinkedAgentIdentity.Type
                        Impact = if ($null -ne $LinkedAgentIdentity.Impact) { [math]::Round([double]$LinkedAgentIdentity.Impact) } else { 0 }
                        Risk = if ($null -ne $LinkedAgentIdentity.Risk) { [math]::Round([double]$LinkedAgentIdentity.Risk) } else { 0 }
                        ParentPrincipalId = $BlueprintPrincipal.Id
                        ParentPrincipalDisplayName = $BlueprintPrincipal.DisplayName
                    }
                }
            }
        } else {
            # Fallback if no processed blueprint principal object was passed in.
            $EnterpriseApps.GetEnumerator() | Where-Object { $_.Value.AppId -eq $item.AppId } | Select-Object -First 1 | ForEach-Object {
                $InheritedImpactScore += [double]$_.Value.Impact
                $SPObjectID = $_.Name
            }
        }

        $ImpactScore = $DirectImpactScore + $InheritedImpactScore

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        #Write custom object
        $BlueprintDetails = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            AppId = $item.AppId
            Enabled = $BlueprintEnabled
            SignInAudience = $item.signInAudience
            BlueprintPrincipals = ($BlueprintPrincipals | Measure-Object).Count
            BlueprintPrincipalsDetails = $BlueprintPrincipals
            LinkedAgentIdentities = ($BlueprintLinkedAgentIdentities | Measure-Object).Count
            LinkedAgentIdentitiesDetails = $BlueprintLinkedAgentIdentities
            Owners = ($AppOwnerUsers | Measure-Object).Count + ($AppOwnerSPs | Measure-Object).Count
            Sponsors = ($BlueprintSponsors | Measure-Object).Count
            InheritablePermissions = @($BlueprintInheritablePermissions | Where-Object { $_.Kind -ne "-" -and $_.Kind -ne "none" }).Count
            InhScopes = @($BlueprintInheritablePermissions | Where-Object { $_.PermissionType -eq "Delegated" -and $_.Kind -ne "-" -and $_.Kind -ne "none" }).Count
            InhRoles = @($BlueprintInheritablePermissions | Where-Object { $_.PermissionType -eq "Application" -and $_.Kind -ne "-" -and $_.Kind -ne "none" }).Count
            FederatedCreds = ($BlueprintFederatedIdentityCredentials | Measure-Object).Count
            SecretsCount = $SecretsCount
            CertsCount = $CertificateCount
            AppCredentialsDetails = $AppCredentials
            AppOwnerUsers = $AppOwnerUsers
            AppOwnerSPs = $AppOwnerSPs
            AppSponsorsDetails = $BlueprintSponsors
            InheritablePermissionsDetails = $BlueprintInheritablePermissions
            FederatedIdentityCredentialsDetails = $BlueprintFederatedIdentityCredentials
            CreationDate = $item.createdDateTime
            CreationInDays = $CreationInDays
            SPObjectId = if ($SPObjectID -is [System.Array]) { $SPObjectID[0] } else { $SPObjectID }
            SPObjectIds = @($SPObjectID)
            AppRolesDetails = $AppRolesDetails
            AppRoles = ($AppRolesDetails | Measure-Object).Count
            Oauth2PermissionScopesDetails = $Oauth2PermissionScopesDetails
            Oauth2PermissionScopes = ($Oauth2PermissionScopesDetails | Measure-Object).Count
            DistinctAPIs = $($item.RequiredResourceAccess).Count
            DirectImpact = [math]::Round($DirectImpactScore)
            InheritedImpact = [math]::Round($InheritedImpactScore)
            Risk = [math]::Round(($ImpactScore * $LikelihoodScore))
            Impact = [math]::Round($ImpactScore)
            Likelihood = [math]::Round($LikelihoodScore,1)
            AppHomePage = $AppHomePage
            Warnings = $Warnings
        }
        [void]$AllAgentIdentityBlueprints.Add($BlueprintDetails)

    }
    #endregion

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    $AllAgentIdentityBlueprintsHT = @{}
    foreach ($item in $AllAgentIdentityBlueprints) {
        $AllAgentIdentityBlueprintsHT[$item.Id] = $item
    }
    return $AllAgentIdentityBlueprintsHT
}
