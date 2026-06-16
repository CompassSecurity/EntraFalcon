<#
.SYNOPSIS
   Enumerate App Registrations (including: API Permission (Application), Owner, Secrets, Certificates, 	Access through App Roles etc.).

.DESCRIPTION
   This script will enumerate all App Registrations (including: API Permission (Application), Owner, Secrets, Certificates, Active access through App Roles, App instance property lock).

#>
function Invoke-CheckAppRegistrations {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$AgentObjectBasics,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Function section ########################
    #Function to deliver detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
    #The type can be specified to save some GraphAPI calls
    function GetObjectInfo($Object,$type="unknown"){
        if ($type -eq "unknown" -or $type -eq "user" ) {
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
                    OwnersCount = $MatchingEnterpriseApp.OwnersCount
                    TargetReport = 'EnterpriseApps'
                    ServicePrincipalType = $MatchingEnterpriseApp.ServicePrincipalType
                }
            }
        }

        if ($type -eq "agentIdentity" -or $type -eq "agentIdentityBlueprintPrincipal") {
            # Resolve AgentObjects through the shared typed lookup.
            $rawType = if ($type -eq "agentIdentity") { '#microsoft.graph.agentIdentity' } else { '#microsoft.graph.agentIdentityBlueprintPrincipal' }
            $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $Object -RawType $rawType -CurrentTenant $CurrentTenant -AllUsersBasicHT @{} -AllGroupsDetails @{} -ServicePrincipalBasics $EnterpriseApps -AgentObjectBasics $AgentObjectBasics
            if ($resolvedObject) {
                [PSCustomObject]@{
                    Type                 = $resolvedObject.ObjectKind
                    Id                   = $resolvedObject.Id
                    DisplayName          = $resolvedObject.DisplayName
                    Foreign              = $resolvedObject.Foreign
                    PublisherName        = $resolvedObject.PublisherName
                    OwnersCount          = "-"
                    TargetReport         = $resolvedObject.TargetReport
                    ServicePrincipalType = $resolvedObject.ServicePrincipalType
                }
            }
        }

        if ($type -eq "Secret" ) {
            $Expired = $null
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
            $Expired = $null
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


    ############################## Script section ########################

    # Check token and trigger refresh if required
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "AppRegistration"
    $ScriptWarningList = @()
    $AppsWithSecrets = @()
    $AppAuthentication = @()
    $ProgressCounter = 0
    $AllAppRegistrations = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $AppLikelihoodScore = @{
        "AppBase"                   = 1
        "AppSecret"                 = 5
        "EntraConnectIoC"           = 200
        "AppCertificate"            = 2
        "AppOwner"          	    = 20
        "AppAdmins"          	    = 10
	    "InternalSPOwner"		    = 5
	    "ExternalSPOwner"		    = 50
	    "GuestAsOwner"		        = 50
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Enterprise Apps (to check the permissions)
    write-host "[*] Get App Registrations"
    $QueryParameters = @{
        '$select' = "Id,AppID,DisplayName,isDisabled,SignInAudience,RequiredResourceAccess,ServicePrincipalLockConfiguration,web,createdDateTime,KeyCredentials,PasswordCredentials,AppRoles,Spa,Windows,PublicClient,DefaultRedirectUri,isFallbackPublicClient"
    }
    $AppRegistrations = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppsTotalCount = $($AppRegistrations.count)

    # Filter out Agent Identity Blueprints
    $AppRegistrations = @($AppRegistrations | Where-Object {$_.'@odata.type' -ne '#microsoft.graph.agentIdentityBlueprint'})
    $AgentIdentityBlueprintCount = $AppsTotalCount - $($AppRegistrations).count
    if ($AgentIdentityBlueprintCount -gt 0) {
        $AppsTotalCount = $($AppRegistrations.count)
        Write-Log -Level Verbose -Message "Filtered out $AgentIdentityBlueprintCount agent identity blueprints from App Registrations."
    }
    
    write-host "[+] Got $AppsTotalCount App registrations"

    #Abort if no apps are present
    if (@($AppRegistrations).count -eq 0) {
        $AllAppRegistrationsHT = @{}
        Return $AllAppRegistrationsHT
    }

    # Build lookups once to avoid repeated full scans in the per-app loop.
    $EnterpriseAppsByAppId = @{}
    foreach ($entry in $EnterpriseApps.GetEnumerator()) {
        if ($null -eq $entry.Value) { continue }
        if ([string]::IsNullOrWhiteSpace($entry.Value.AppId)) { continue }
        if (-not $EnterpriseAppsByAppId.ContainsKey($entry.Value.AppId)) {
            $EnterpriseAppsByAppId[$entry.Value.AppId] = [PSCustomObject]@{
                ObjectId = $entry.Name
                Data     = $entry.Value
            }
        }
    }

    $CloudAppAdminAssignmentsByScope = @{}
    $AppAdminAssignmentsByScope = @{}
    foreach ($assignmentSet in $TenantRoleAssignments.Values) {
        foreach ($assignment in @($assignmentSet)) {
            if ([string]::IsNullOrWhiteSpace([string]$assignment.DirectoryScopeId)) { continue }
            switch ($assignment.RoleDefinitionId) {
                "158c047a-c907-4556-b7ef-446551a6b5f7" {
                    if (-not $CloudAppAdminAssignmentsByScope.ContainsKey($assignment.DirectoryScopeId)) {
                        $CloudAppAdminAssignmentsByScope[$assignment.DirectoryScopeId] = @()
                    }
                    $CloudAppAdminAssignmentsByScope[$assignment.DirectoryScopeId] += [PSCustomObject]@{
                        PrincipalId     = $assignment.PrincipalId
                        AssignmentType  = $assignment.AssignmentType
                    }
                    break
                }
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" {
                    if (-not $AppAdminAssignmentsByScope.ContainsKey($assignment.DirectoryScopeId)) {
                        $AppAdminAssignmentsByScope[$assignment.DirectoryScopeId] = @()
                    }
                    $AppAdminAssignmentsByScope[$assignment.DirectoryScopeId] += [PSCustomObject]@{
                        PrincipalId     = $assignment.PrincipalId
                        AssignmentType  = $assignment.AssignmentType
                    }
                    break
                }
            }
        }
    }

    #Get members of Cloud Application Administrator (158c047a-c907-4556-b7ef-446551a6b5f7) with the scope for the Tenant
    $CloudAppAdminTenant = if ($CloudAppAdminAssignmentsByScope.ContainsKey("/")) {
        @($CloudAppAdminAssignmentsByScope["/"])
    } else {
        @()
    }
    $CloudAppAdminTenantDetails = foreach ($Object in $CloudAppAdminTenant) {
        # Get the object details
        $ObjectDetails = GetObjectInfo $Object.PrincipalId
        # Add the 'Role' property and use passthru to give back the object
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'CloudApplicationAdministrator'
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'Tenant' -PassThru
    }
    
    #Get members of Application Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3) with the scope for current the Tenant
    $AppAdminTenant = if ($AppAdminAssignmentsByScope.ContainsKey("/")) {
        @($AppAdminAssignmentsByScope["/"])
    } else {
        @()
    }
    $AppAdminTenantDetails = foreach ($Object in $AppAdminTenant) {
        # Get the object details
        $ObjectDetails = GetObjectInfo $Object.PrincipalId
        # Add the 'Role' property and use passthru to give back the object
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'ApplicationAdministrator'
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'Tenant' -PassThru
    }

    #Count Admins
    $CloudAppAdminTenantCount = ($CloudAppAdminTenant | Measure-Object).Count
    $AppAdminTenantCount = ($AppAdminTenant | Measure-Object).Count


    Write-Host "[*] Get all owners"
    $Requests = @()
    $AppRegistrations | ForEach-Object {
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

    Write-Host "[*] Get all federated identity credentials"
    $Requests = @()
    $AppRegistrations | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/applications/$($_.id)/federatedIdentityCredentials"
        }
    }
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppFederatedCredsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppFederatedCredsRaw[$item.id] = $item.response.value
        }
    }


    ########################################## SECTION: Data Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($AppsTotalCount / 10), 1)
    if ($AppsTotalCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing app 1 of $AppsTotalCount (updates every $StatusUpdateInterval apps)..."
    }
    
    #region Processing Loop
    #Loop through each app and get additional info and store it in a custom object
    foreach ($item in $AppRegistrations) {
        $ImpactScore = 0
        $LikelihoodScore = $AppLikelihoodScore["AppBase"]
        $warnings = @()
        $AppRolesDetails = @()
        $AppCredentials = @()
        $SPObjectID = @()
        $RelatedEnterpriseApplicationDetails = @()
        $RelatedEnterpriseApplicationDisplayName = $null
        $ApiDelegatedCount = 0
        $AppHomePage = $null
        $Listfindings = ""
        $DefaultRedirectUri = $item.DefaultRedirectUri
        $IsFallbackPublicClient = $item.isFallbackPublicClient
        $AllowPublicClientflows = $item.web.implicitGrantSettings.enableAccessTokenIssuance
        $WebImplicitAccessTokenIssuance = $item.Web.implicitGrantSettings.enableAccessTokenIssuance
        $WebImplicitIdTokenIssuance = $item.Web.implicitGrantSettings.enableIdTokenIssuance
        $SpaRedirectUris = $item.Spa.RedirectUris -join ", "
        $WebRedirectUris = $item.Web.RedirectUris -join ", "
        $WindowsRedirectUris = $item.Windows.RedirectUris -join ", "
        $PublicClientRedirectUris = $item.PublicClient.RedirectUris -join ", "
        $AppEnabled = -not ($item.isDisabled -eq $true)

        $ProgressCounter ++

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AppsTotalCount) {
            Write-Host "[*] Status: Processing app $ProgressCounter of $AppsTotalCount..."
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
                DisplayName = $roles.DisplayName
                Enabled = $roles.IsEnabled
                Claim = $roles.Value
                Description = $roles.Description
                MemberTypes = ($roles.AllowedMemberTypes -join ' / ')
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

        $AppFederatedCreds = @()
        if ($AppFederatedCredsRaw.ContainsKey($item.Id)) {
            $AppFederatedCreds = foreach ($credential in $AppFederatedCredsRaw[$item.Id]) {
                [pscustomobject]@{
                    Name        = if ([string]::IsNullOrWhiteSpace($credential.name)) { "-" } else { $credential.name }
                    Issuer      = if ([string]::IsNullOrWhiteSpace($credential.issuer)) { "-" } else { $credential.issuer }
                    Subject     = if ([string]::IsNullOrWhiteSpace($credential.subject)) { "-" } else { $credential.subject }
                    Description = if ([string]::IsNullOrWhiteSpace($credential.description)) { "-" } else { $credential.description }
                    Audiences   = if ($credential.audiences) { ($credential.audiences -join ", ") } else { "-" }
                }
            }
        }

        # Combine arrays into a hashtable for easy identification
        $AppRedirectURL = @{
            SpaRedirectUris = $item.Spa.RedirectUris
            WebRedirectUris = $item.Web.RedirectUris
            WindowsRedirectUris = $item.Windows.RedirectUris
            PublicClientRedirectUris = $item.PublicClient.RedirectUris
        }
        
        # Define patterns with severity levels
        $RedirectPatterns = @(
            [PSCustomObject]@{ Pattern = "*.azurewebsites.net"; Severity = "High" },
            [PSCustomObject]@{ Pattern = "*.logic.azure.com"; Severity = "High" },
            [PSCustomObject]@{ Pattern = "*.github.com"; Severity = "High" },
            [PSCustomObject]@{ Pattern = ".logic.azure.com"; Severity = "Medium" },
            [PSCustomObject]@{ Pattern = ".azurewebsites.net"; Severity = "Medium" }
        )

        # Prepare a result object
        $FindingsRedirectUrls = @()

        # Iterate through arrays and check for matches
        foreach ($key in $AppRedirectURL.Keys) {
            foreach ($RedirectURL in $AppRedirectURL[$key]) {
                if ([string]::IsNullOrWhiteSpace($RedirectURL)) { continue }
                foreach ($pattern in $RedirectPatterns) {
                    # Use wildcard matching so patterns with '*' work as intended.
                    if ($RedirectURL -like $pattern.Pattern) {
                        $FindingsRedirectUrls += [PSCustomObject]@{
                            Match      = $RedirectURL
                            Pattern    = $pattern.Pattern
                            Severity   = $pattern.Severity
                            ArrayName  = $key
                        }
                    }
                }
            }
        }

        foreach ($Finding in $FindingsRedirectUrls) {
            $Listfindings += "$($Finding.Severity): $($Finding.Match)"
        }

        #Get application lock config
        $AppLockConfiguration = $item | Select-Object -ExpandProperty ServicePrincipalLockConfiguration


        # Ensure it's not null and is an object with properties
        if ($null -eq $AppLockConfiguration -or $AppLockConfiguration.PSObject.Properties.Count -eq 0) {
            # Initialize with default values if it's null or has no properties
            $AppLockConfiguration = [PSCustomObject]@{
                IsEnabled = $false
                AllProperties = $false
                credentialsWithUsageVerify = $false
            }
        } else {
            # Set to false if any expected property is null or missing
            if (-not $AppLockConfiguration.PSObject.Properties.Match('IsEnabled') -or $null -eq $AppLockConfiguration.IsEnabled) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name IsEnabled -Value $false -Force
            }
            if (-not $AppLockConfiguration.PSObject.Properties.Match('AllProperties') -or $null -eq $AppLockConfiguration.AllProperties) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name AllProperties -Value $false -Force
            }
            if (-not $AppLockConfiguration.PSObject.Properties.Match('credentialsWithUsageVerify') -or $null -eq $AppLockConfiguration.credentialsWithUsageVerify) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name credentialsWithUsageVerify -Value $false -Force
            }
        }

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

                    '#microsoft.graph.servicePrincipal' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                Type = "ServicePrincipal"
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentity' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                Type = "agentIdentity"
                            }
                        )
                    }

                    '#microsoft.graph.agentIdentityBlueprintPrincipal' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                Type = "agentIdentityBlueprintPrincipal"
                            }
                        )
                    }
                }
            }
        }

        $AppOwnersCount = $AppOwnerUsers.Count + $AppOwnerSPs.count
        # Keep non-user app owners on one path while letting the shared resolver supply the correct target report and ownership metadata.
        $AppOwnerSPs = foreach ($Object in $AppOwnerSPs) {
            GetObjectInfo $Object.Id -type $Object.Type
        }


        #Get members of Cloud Application Administrator (158c047a-c907-4556-b7ef-446551a6b5f7) with the scope for current App Registrations
        $scopeKey = "/$($item.Id)"
        $CloudAppAdminCurrentApp = if ($CloudAppAdminAssignmentsByScope.ContainsKey($scopeKey)) {
            @($CloudAppAdminAssignmentsByScope[$scopeKey])
        } else {
            @()
        }
        
        $CloudAppAdminCurrentAppDetails = foreach ($Object in $CloudAppAdminCurrentApp) {
            # Get the object details
            $ObjectDetails = GetObjectInfo $Object.PrincipalId
            # Add the 'Role' property and use passthru to give back the object
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'CloudApplicationAdministrator'
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'ThisApplication' -PassThru
        }
        
        #Get members of Application Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3) with the scope for current App Registrations
        $AppAdminCurrentApp = if ($AppAdminAssignmentsByScope.ContainsKey($scopeKey)) {
            @($AppAdminAssignmentsByScope[$scopeKey])
        } else {
            @()
        }
        $AppAdminCurrentAppDetails = foreach ($Object in $AppAdminCurrentApp) {
            # Get the object details
            $ObjectDetails = GetObjectInfo $Object.PrincipalId
            # Add the 'Role' property and use passthru to give back the object
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'ApplicationAdministrator'
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'ThisApplication' -PassThru
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

        #Count App Admins and increase risk score
        $CloudAppAdminCurrentAppCount = ($CloudAppAdminCurrentApp | Measure-Object).Count
        $AppAdminCurrentAppCount = ($AppAdminCurrentApp | Measure-Object).Count
        $AppAdminsCount = $CloudAppAdminCurrentAppCount + $AppAdminCurrentAppCount + $CloudAppAdminTenantCount + $AppAdminTenantCount
        if ($AppAdminsCount -ge 1) {
            $LikelihoodScore += $AppAdminsCount * $AppLikelihoodScore["AppAdmins"]
        }


        #Check if there are owners
        if ($AppOwnersCount -ge 1) {
            $LikelihoodScore += $AppOwnersCount * $AppLikelihoodScore["AppOwner"]
            if ($EntraConnectApp) {
                $Warnings += "Entra Connect App with owner!"
            }
        }

        #Check application lock config
        if ($AppLockConfiguration.IsEnabled -ne $true -or ($AppLockConfiguration.AllProperties -ne $true -and $AppLockConfiguration.credentialsWithUsageVerify -ne $true)) {
            $AppLock = $false
        } else {
            $AppLock = $true
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
                $Warnings += "Foreign non-user owner!"
                $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
            } elseif ($AppOwnerSPs.Foreign -contains $false) {
                $Warnings += "Internal non-user owner"
                $LikelihoodScore += $AppLikelihoodScore["InternalSPOwner"]
            }
        }


        if (($AppOwnerUsers | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as Owner!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($CloudAppAdminCurrentAppDetails | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as scoped CloudAppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($AppAdminCurrentAppDetails | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as scoped AppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($CloudAppAdminCurrentAppDetails | Where-Object { $_.Foreign -eq "True" } | Measure-Object).Count -ge 1) {
            $Warnings += "Foreign SP as scoped CloudAppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
        }
        if (($AppAdminCurrentAppDetails | Where-Object { $_.Foreign -eq "True" } | Measure-Object).Count -ge 1) {
            $Warnings += "Foreign SP scoped AppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
        }

        #Take ImpactScore and ObjectId from SP
        if ($EnterpriseAppsByAppId.ContainsKey($item.AppId)) {
            $MatchingEnterpriseApp = $EnterpriseAppsByAppId[$item.AppId]
            $ImpactScore += $MatchingEnterpriseApp.Data.Impact
            $SPObjectID = $MatchingEnterpriseApp.ObjectId
            $ApiDelegatedCount = $MatchingEnterpriseApp.Data.ApiDelegated
            $RelatedEnterpriseApplicationDisplayName = $MatchingEnterpriseApp.Data.DisplayName
            $RelatedEnterpriseApplicationDetails = [pscustomobject]@{
                DisplayName = "<a href=EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($SPObjectID)>$($MatchingEnterpriseApp.Data.DisplayName)</a>"
                Impact = [math]::Round($MatchingEnterpriseApp.Data.Impact)
                Warnings = if ([string]::IsNullOrWhiteSpace($MatchingEnterpriseApp.Data.Warnings)) { "-" } else { $MatchingEnterpriseApp.Data.Warnings }
            }
        }

        # Experimental collect app authentication properties after delegated API lookup
        $AppAuthentication += [pscustomobject]@{
            AppName = $item.DisplayName
            ApiDelegated = $ApiDelegatedCount
            IsFallbackPublicClient = $IsFallbackPublicClient
            AllowPublicClientflows = $AllowPublicClientflows
            WebImplicitAccessTokenIssuance = $WebImplicitAccessTokenIssuance
            WebImplicitIdTokenIssuance = $WebImplicitIdTokenIssuance
            DefaultRedirectUri = $DefaultRedirectUri
            PublicClientRedirectUris = $PublicClientRedirectUris
            SpaRedirectUris = $SpaRedirectUris
            WebRedirectUris = $WebRedirectUris
            WindowsRedirectUris = $WindowsRedirectUris
            Warning = $Listfindings
        }

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        #Appendix of Applications with Secrets
        if ($SecretsCount -ge 1){
            $AppsWithSecrets += $AppCredentialsSecrets
        }
        
        #Write custom object
        $AppRegDetails = [PSCustomObject]@{ 
            Id = $item.Id
            DisplayName = $item.DisplayName
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            AppId = $item.AppId
            Enabled = $AppEnabled
            SignInAudience = $item.signInAudience
            Owners = ($AppOwnerUsers | Measure-Object).Count + ($AppOwnerSPs | Measure-Object).Count
            FederatedCreds = ($AppFederatedCreds | Measure-Object).Count
            SecretsCount = $SecretsCount
            CertsCount = $CertificateCount
            AppCredentialsDetails = $AppCredentials
            FederatedCredsDetails = $AppFederatedCreds
            AppOwnerUsers = $AppOwnerUsers
            AppOwnerSPs = $AppOwnerSPs
            CreationDate = $item.createdDateTime
            CreationInDays = $CreationInDays
            SPObjectId = $SPObjectID
            RelatedEnterpriseApplicationDetails = $RelatedEnterpriseApplicationDetails
            RelatedEnterpriseApplicationDisplayName = $RelatedEnterpriseApplicationDisplayName
            AppRolesDetails = $AppRolesDetails
            AppRoles = ($AppRolesDetails | Measure-Object).Count
            CloudAppAdmins = ($CloudAppAdminCurrentApp | Measure-Object).Count + ($CloudAppAdminTenantDetails | Measure-Object).Count
            AppAdmins = ($AppAdminCurrentApp | Measure-Object).Count + ($AppAdminTenantDetails | Measure-Object).Count
            CloudAppAdminCurrentAppDetails = $CloudAppAdminCurrentAppDetails
            AppAdminCurrentAppDetails = $AppAdminCurrentAppDetails
            DistinctAPIs = $($item.RequiredResourceAccess).Count
            Risk = [math]::Round(($ImpactScore * $LikelihoodScore))
            Impact = [math]::Round($ImpactScore)
            Likelihood = [math]::Round($LikelihoodScore,1)
            AppLock = $AppLock
            AppLockConfiguration = $AppLockConfiguration
            AppHomePage = $AppHomePage
            Warnings = $Warnings
        }
        [void]$AllAppRegistrations.Add($AppRegDetails)
        
    }
    #endregion
    
    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"


    #Define Table for output
    $tableOutput = $AllAppRegistrations | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,Enabled,CreationInDays,SignInAudience,AppRoles,AppLock,Owners,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,FederatedCreds,Impact,Likelihood,Risk,Warnings
    

    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllAppRegistrations | Sort-Object Risk -Descending


    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()
    
    foreach ($item in $details) {
        $ReportingAppRegInfo = @()
        $ReportingCredentials = @()
        $ReportingFederatedCreds = @()
        $ReportingAppLock = @()
        $ReportingAppRoles = @()
        $ReportingAppOwnersUser = @()
        $ReportingAppOwnersSP = @()
        $ScopedAdminUser = @()
        $ScopedAdminGroup = @()
        $ScopedAdminSP = @()
        

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        ############### HEADER
        $ReportingAppRegInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "CreationDate" = $($item.CreationDate)
            "Enabled" = $($item.Enabled)
            "SignInAudience" = $($item.SignInAudience)
            "RiskScore" = $($item.Risk)
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","App Client-ID","App Object-ID","CreationDate","Enabled","SignInAudience","RiskScore")

        if ($null -ne $item.AppHomePage) {
            $ReportingAppRegInfo | Add-Member -NotePropertyName URL -NotePropertyValue $item.AppHomePage
            $TxtReportProps += "URL"
        }

        if ($item.Warnings -ne '') {
            $ReportingAppRegInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingAppRegInfo | select-object $TxtReportProps | Out-String))

        ############### Related Enterprise Application
        if (($item.RelatedEnterpriseApplicationDetails | Measure-Object).Count -ge 1) {
            $ReportingRelatedEnterpriseApplication = [pscustomobject]@{
                DisplayName = $item.RelatedEnterpriseApplicationDisplayName
                Impact = $item.RelatedEnterpriseApplicationDetails.Impact
                Warnings = $item.RelatedEnterpriseApplicationDetails.Warnings
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Related Enterprise Application")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRelatedEnterpriseApplication | Format-Table DisplayName,Impact,Warnings | Out-String))
        }

        ############### App Registration Credentials
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
            [void]$DetailTxtBuilder.AppendLine("App Registration Credentials")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String))
        }

        ############### Federated Identity Credentials
        if (($item.FederatedCredsDetails | Measure-Object).count -ge 1) {
            $ReportingFederatedCreds = foreach ($object in $item.FederatedCredsDetails) {
                [pscustomobject]@{
                    "Name" = $object.Name
                    "Issuer" = $object.Issuer
                    "Subject" = $object.Subject
                    "Description" = $object.Description
                    "Audiences" = $object.Audiences
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Federated Identity Credentials")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingFederatedCreds | Format-Table -Property Name,Issuer,Subject,Description,Audiences | Out-String -Width 350))
        }

        ############### AppLock
        if ($($item.AppLockConfiguration | Measure-Object).count -ge 1) {
            $ReportingAppLock = foreach ($object in $($item.AppLockConfiguration)) {
                [pscustomobject]@{
                    "Enabled" = $($object.IsEnabled)
                    "All properties" = $($object.AllProperties)
                    "Credentials used for verification" = $($object.credentialsWithUsageVerify)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("App Instance Property Lock (AppLock)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppLock | Out-String))
        }

       ############### Owners of the App Registration
        if ($($item.AppOwnerUsers | Measure-Object).count -ge 1 -or $($item.AppOwnerSPs | Measure-Object).count -ge 1) {

            if ($($item.AppOwnerUsers | Measure-Object).count -ge 1) {
                $ReportingAppOwnersUser = foreach ($object in $($item.AppOwnerUsers)) {
                    [pscustomobject]@{ 
                        "UPN" = $($object.userPrincipalName)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.userPrincipalName)</a>"
                        "Enabled" = $($object.accountEnabled)
                        "Type" = $($object.userType)
                        "OnPremSync" = $($object.onPremisesSyncEnabled)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.jobTitle)
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

            if ($($item.AppOwnerSPs | Measure-Object).count -ge 1) {
                $ReportingAppOwnersSP = foreach ($object in $($item.AppOwnerSPs)) {
                    $ownerLink = switch ($object.TargetReport) {
                        'AgentIdentities' { "<a href=AgentIdentities_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                        'AgentIdentityBlueprintsPrincipals' { "<a href=AgentIdentityBlueprintsPrincipals_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                        default { "<a href=EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>" }
                    }
                    [pscustomobject]@{ 
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = $ownerLink
                        "Foreign" = $($object.Foreign)
                        "PublisherName" = $($object.publisherName)
                        "OwnersCount" = $($object.OwnersCount)
                    }
                }

                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Service Principals / Agent Objects)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersSP | format-table -Property DisplayName,Foreign,PublisherName,OwnersCount | Out-String))
                $ReportingAppOwnersSP = foreach ($obj in $ReportingAppOwnersSP) {
                    [pscustomobject]@{
                        DisplayName     = $obj.DisplayNameLink
                        Foreign         = $obj.Foreign
                        PublisherName   = $obj.PublisherName
                        OwnersCount     = $obj.OwnersCount
                    }
                }
            }
        }

        ############### Scoped Admins
       
        #Wrap to Array and merge
        $CloudAppAdminCurrentAppDetails = @($item.CloudAppAdminCurrentAppDetails)
        $AppAdminCurrentAppDetails = @($item.AppAdminCurrentAppDetails)
        $MergedAdmins = $CloudAppAdminCurrentAppDetails + $AppAdminCurrentAppDetails + $CloudAppAdminTenantDetails + $AppAdminTenantDetails

        if ($($MergedAdmins | Measure-Object).count -ge 1) {

            #Split by object type
            $EntityDetails = @{
                Users  = @($MergedAdmins | Where-Object { $_.Type -eq 'User' })
                Groups = @($MergedAdmins | Where-Object { $_.Type -eq 'Group' })
                SP = @($MergedAdmins | Where-Object { $_.Type -eq 'ServicePrincipal' })
            }

            if ($($EntityDetails.Users | Measure-Object).count -ge 1) {
                $ScopedAdminUser = foreach ($object in $($EntityDetails.Users)) {
                    [pscustomobject]@{ 
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "UPN" = $($object.UPN)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.PrincipalId)>$($object.UPN)</a>"
                        "Enabled" = $($object.Enabled)
                        "Type" = $($object.userType)
                        "OnPremSync" = $($object.Onprem)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.JobTitle)
                    }
                }

                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("App Admins (Users)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminUser | format-table -Property Role,Scope,AssignmentType,UPN,Enabled,Type,OnPremSync,Department,JobTitle | Out-String -Width 200))
                $ScopedAdminUser  = foreach ($obj in $ScopedAdminUser ) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        UserName        = $obj.UPNLink
                        Enabled         = $obj.Enabled
                        Type            = $obj.Type
                        OnPremSync      = $obj.OnPremSync
                        Department      = $obj.Department
                        JobTitle        = $obj.JobTitle
                    }
                }
            }

            if ($($EntityDetails.Groups | Measure-Object).count -ge 1) {
                $ScopedAdminGroup = foreach ($object in $($EntityDetails.Groups)) {
                    [pscustomobject]@{ 
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "Name" = $($object.DisplayName)
                        "NameLink" = "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.PrincipalId)>$($object.DisplayName)</a>"
                        "OnPremSync" = $($object.OnPrem)
                        "Users" = $($object.Users)
                        "Guests" = $($object.Guests)
                        "Owners" = $($object.Owners)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Admins (Groups)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminGroup | format-table -Property Role,Scope,AssignmentType,Name,OnPremSync,Users,Guests,Owners | Out-String))
                $ScopedAdminGroup  = foreach ($obj in $ScopedAdminGroup) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        DisplayName     = $obj.NameLink
                        OnPremSync      = $obj.OnPremSync
                        Users           = $obj.Users
                        Guests          = $obj.Guests
                        Owners          = $obj.Owners
                    }
                }
            }

            if ($($EntityDetails.SP | Measure-Object).count -ge 1) {
                $ScopedAdminSP = foreach ($object in $($EntityDetails.SP)) {
                    [pscustomobject]@{ 
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                        "PublisherName" = $($object.publisherName)
                        "Foreign" = $($object.Foreign)
                        "Owners" = $($object.OwnersCount)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Admins (SPs)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminSP | format-table -Property Role,Scope,AssignmentType,DisplayName,PublisherName,Foreign,Owners | Out-String))
                $ScopedAdminSP = foreach ($obj in $ScopedAdminSP) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        DisplayName     = $obj.DisplayNameLink
                        Foreign         = $obj.Foreign
                        PublisherName   = $obj.PublisherName
                        Owners          = $obj.Owners
                    }
                }
            }
        }

        ############### AppRoles
        if ($($item.AppRolesDetails | Measure-Object).count -ge 1) {
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "Enabled" = $($object.Enabled)
                    "Claim" = $($object.Claim)
                    "MemberTypes" = $($object.MemberTypes)
                    "Description" = $($object.Description)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("App Roles")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | format-table | Out-String))
        }

        
        $ObjectDetails=[pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information"    = $ReportingAppRegInfo
            "Related Enterprise Application" = $item.RelatedEnterpriseApplicationDetails
            "App Credentials"    = $ReportingCredentials
            "Federated Identity Credentials" = $ReportingFederatedCreds
            "App Instance Property Lock (AppLock)"    = $ReportingAppLock
            "Application Roles"    = $ReportingAppRoles
            "Owners (Users)"    = $ReportingAppOwnersUser
            "Owners (ServicePrincipals)"    = $ReportingAppOwnersSP
            "Admins (Users)"    = $ScopedAdminUser
            "Admins (Groups)"    = $ScopedAdminGroup
            "Admins (ServicePrincipals)"    = $ScopedAdminSP
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()

    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},SignInAudience,Enabled,AppLock,CreationInDays,AppRoles,Owners,FederatedCreds,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'



# Build Detail section as JSON for the HTML Report
    $AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>App Registrations Details</h2>
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
Execution Warnings = $($ScriptWarningList  -join ' / ')
************************************************************************************************************************
"

$headerHTML = [pscustomobject]@{ 
    "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
    "Executed at" = "$StartTimestamp "
    "Execution Warnings" = $ScriptWarningList -join ' / '
}

    
#Define Appendix

$AppendixClientSecrets = "

===============================================================================================================================================
Appendix: App Registrations with Client Secrets
===============================================================================================================================================
"

$AppendixAppAuthSettings = "

===============================================================================================================================================
Appendix: Experimental App Authentication Settings
===============================================================================================================================================
"

    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'AR' -CurrentReportName 'App Registrations Enumeration' -Warnings $ScriptWarningList

    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

    #Write TXT and CSV files
    $headerTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $tableOutput | format-table DisplayName,SignInAudience,Enabled,CreationInDays,AppLock,AppRoles,Owners,FederatedCreds,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Csv) {
        $tableOutput | select-object DisplayName,SignInAudience,Enabled,CreationInDays,AppLock,AppRoles,Owners,FederatedCreds,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $AppendixSecretsHTML = ""
    $AppsWithSecrets = $AppsWithSecrets | sort-object DisplayName | select-object AppName,Displayname,StartDateTime,EndDateTime,Expired
    if (($AppsWithSecrets | Measure-Object).count -ge 1) {
        $AppendixClientSecrets  | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppsWithSecrets | Format-Table | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixSecretsHTML += $AppsWithSecrets | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Apps With Secrets</h2>"
    }

    if (($AppAuthentication | Measure-Object).count -ge 1) {
        $AppendixAppAuthSettings  | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppAuthentication | Format-Table | Out-File -Width 800 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        $AppendixSecretsHTML += $AppAuthentication | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Application Authentication Configuration</h2>"
    }


    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixSecretsHTML

    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - App Registrations</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $($AllAppRegistrations.count) App Registrations stored in output files ($OutputFormats): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName)"
   
    #Add information to the enumeration summary
    $AppLock = 0
    $AzureADMyOrg = 0
    $AzureADMultipleOrgs = 0
    $AzureADandPersonalMicrosoftAccount = 0
    $AppsSecrets = 0
    $AppsCertificates = 0
    $AppsFederatedCredentials = 0
    $AppsNoCredentials = 0

    foreach ($app in $AllAppRegistrations) {
        if ($app.AppLock) {
            $AppLock++
        }
        if ($app.SecretsCount -ge 1) {
            $AppsSecrets++
        }
        if ($app.CertsCount -ge 1) {
            $AppsCertificates++
        }
        if ($app.FederatedCreds -ge 1) {
            $AppsFederatedCredentials++
        }
        if ($app.SecretsCount -eq 0 -and $app.CertsCount -eq 0 -and $app.FederatedCreds -eq 0){
            $AppsNoCredentials++
        }

        switch ($app.signInAudience) {
            "AzureADMyOrg" {
                $AzureADMyOrg++
                break
            }
            "AzureADMultipleOrgs" {
                $AzureADMultipleOrgs++
                break
            }
            "AzureADandPersonalMicrosoftAccount" {
                $AzureADandPersonalMicrosoftAccount++
                break
            }
        }
    }

    # Store in global var
    $GlobalAuditSummary.AppRegistrations.Count = $AppsTotalCount
    $GlobalAuditSummary.AppRegistrations.AppLock = $AppLock
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsSecrets = $AppsSecrets
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsCerts = $AppsCertificates
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsFederatedCreds = $AppsFederatedCredentials
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsNoCreds = $AppsNoCredentials
    $GlobalAuditSummary.AppRegistrations.Audience.SingleTenant = $AzureADMyOrg
    $GlobalAuditSummary.AppRegistrations.Audience.MultiTenant = $AzureADMultipleOrgs
    $GlobalAuditSummary.AppRegistrations.Audience.MultiTenantPersonal = $AzureADandPersonalMicrosoftAccount

    #Convert to Hashtable for faster searches
    $AllAppRegistrationsHT = @{}
    foreach ($item in $AllAppRegistrations) {
        $AllAppRegistrationsHT[$item.Id] = $item
    }
    Return $AllAppRegistrationsHT
}
