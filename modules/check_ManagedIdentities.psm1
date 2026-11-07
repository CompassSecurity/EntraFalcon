<#
.SYNOPSIS
   Enumerate Managed Identities (including: API Permission, Source Tenant, Groups, Roles).
#>

$script:ManagedIdentityFederationGuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$script:ManagedIdentityFederationRegexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
$script:ManagedIdentityFederationIssuerPatterns = @(
    '\Ahttps://login\.microsoftonline\.com/(?<tid>{0})/v2\.0/?\z',
    '\Ahttps://sts\.windows\.net/(?<tid>{0})/?\z',
    '\Ahttps://[a-z0-9-]+\.oic\.prod-aks\.azure\.com/(?<tid>{0})/{0}/?\z',
    '\Ahttps://[a-z0-9-]+\.oic\.prod-arc\.azure\.com/(?<tid>{0})/{0}/?\z'
) | ForEach-Object {
    [regex]::new(($_ -f $script:ManagedIdentityFederationGuidPattern), $script:ManagedIdentityFederationRegexOptions)
}

function Get-ManagedIdentityFederationTrust {
    param([string]$Issuer, [string]$TenantId)

    $trust = [pscustomobject]@{ TenantBoundary='Unknown'; IssuerTenantId=$null }
    $issuerUri = $null
    if (-not [uri]::TryCreate($Issuer, [UriKind]::Absolute, [ref]$issuerUri) -or
        $issuerUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($issuerUri.Host)) {
        return $trust
    }

    # Match the original issuer: URI path normalization differs between supported runtimes.
    foreach ($pattern in $script:ManagedIdentityFederationIssuerPatterns) {
        $issuerMatch = $pattern.Match($Issuer)
        if (-not $issuerMatch.Success) { continue }
        $sourceTenant = [guid]::Empty
        $assessedTenant = [guid]::Empty
        if ([guid]::TryParse($issuerMatch.Groups['tid'].Value, [ref]$sourceTenant)) {
            $trust.IssuerTenantId = $sourceTenant.ToString('D')
            if ([guid]::TryParse($TenantId, [ref]$assessedTenant)) {
                $trust.TenantBoundary = if ($sourceTenant -eq $assessedTenant) { 'SameTenant' } else { 'OutsideTenant' }
            }
        }
        return $trust
    }

    $issuerHost = $issuerUri.Host.ToLowerInvariant()
    $unresolvedAzureHosts = @('login.microsoftonline.com', 'sts.windows.net', 'oidc.prod-aks.azure.com',
        'vstoken.dev.azure.com', 'app.vstoken.visualstudio.com')
    if ($issuerHost -notin $unresolvedAzureHosts -and
        -not $issuerHost.EndsWith('.oic.prod-aks.azure.com', [StringComparison]::OrdinalIgnoreCase) -and
        -not $issuerHost.EndsWith('.oic.prod-arc.azure.com', [StringComparison]::OrdinalIgnoreCase)) {
        $trust.TenantBoundary = 'OutsideTenant'
    }
    return $trust
}

function ConvertTo-ManagedIdentityResourceRecord {
    param([string]$ResourceId, [string]$Name, [string]$SubscriptionName)

    $resourceMatch = [regex]::Match($ResourceId, '^/subscriptions/(?<subscription>[0-9a-f-]{36})(?:/resourceGroups/(?<group>[^/?#]+))?/providers/(?<provider>[^/?#]+)/(?<path>[^?#]+?)/?$', 'IgnoreCase')
    if (-not $resourceMatch.Success) {
        $resourceMatch = [regex]::Match($ResourceId, '^/providers/(?<provider>[^/?#]+)/(?<path>[^?#]+?)/?$', 'IgnoreCase')
    }
    $subscriptionId = [guid]::Empty
    if (-not $resourceMatch.Success) { return $null }
    $subscriptionText = $null
    if ($resourceMatch.Groups['subscription'].Success) {
        if (-not [guid]::TryParse($resourceMatch.Groups['subscription'].Value, [ref]$subscriptionId)) { return $null }
        $subscriptionText = $subscriptionId.ToString()
    }
    $parts = $resourceMatch.Groups['path'].Value -split '/'
    if ($parts.Count -lt 2 -or $parts.Count % 2 -ne 0 -or @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.','..') }).Count -gt 0) { return $null }
    $provider = $resourceMatch.Groups['provider'].Value
    $types = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $parts.Count; $index += 2) {
        if ($parts[$index] -eq 'providers') {
            if ($index + 3 -ge $parts.Count) { return $null }
            $provider = $parts[$index + 1]
            $types.Clear()
        } else {
            $types.Add($parts[$index])
        }
    }
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = $parts[-1] }
    if ([string]::IsNullOrWhiteSpace($SubscriptionName) -and $subscriptionText -and $global:GLOBALAzureSubscriptionScopeMap) {
        $SubscriptionName = [string]$global:GLOBALAzureSubscriptionScopeMap[$subscriptionText]
    }
    if ([string]::IsNullOrWhiteSpace($SubscriptionName)) { $SubscriptionName = if ($subscriptionText) { $subscriptionText } else { '-' } }
    [pscustomobject]@{
        Id = $ResourceId.TrimEnd('/')
        Name = $Name
        Type = $provider + '/' + ($types -join '/')
        ResourceGroup = if ($resourceMatch.Groups['group'].Success) { $resourceMatch.Groups['group'].Value } else { '-' }
        SubscriptionId = $subscriptionText
        SubscriptionName = $SubscriptionName
    }
}

function Get-ManagedIdentityResourceBinding {
    param($Identity)

    $records = @{}
    $explicitValues = @()
    $invalidMetadata = $false
    foreach ($alternativeName in @($Identity.alternativeNames)) {
        if ($alternativeName -like 'isExplicit=*') {
            if ($alternativeName -match '^isExplicit=(true|false)$') { $explicitValues += $Matches[1].ToLowerInvariant() } else { $invalidMetadata = $true }
        } elseif ($alternativeName -like '/subscriptions/*' -or $alternativeName -like '/providers/*') {
            $record = ConvertTo-ManagedIdentityResourceRecord -ResourceId $alternativeName
            if ($null -eq $record) { $invalidMetadata = $true } else { $records[$record.Id] = $record }
        }
    }
    $explicitValues = @($explicitValues | Select-Object -Unique)
    $userRecords = @($records.Values | Where-Object { $_.Type -eq 'Microsoft.ManagedIdentity/userAssignedIdentities' })
    $isUserAssigned = ($explicitValues -contains 'true' -or $userRecords.Count -gt 0)
    $kind = 'Unknown'
    $resource = $null
    if (-not $invalidMetadata -and $explicitValues.Count -le 1 -and $records.Count -eq 1) {
        $candidate = @($records.Values)[0]
        $pathIsUserAssigned = ($userRecords.Count -eq 1)
        $validUserResource = ($candidate.ResourceGroup -ne '-' -and -not [string]::IsNullOrWhiteSpace($candidate.SubscriptionId))
        if (($pathIsUserAssigned -and $validUserResource -and $explicitValues -notcontains 'false') -or (-not $pathIsUserAssigned -and $explicitValues -notcontains 'true')) {
            $kind = if ($pathIsUserAssigned) { 'UserAssigned' } else { 'SystemAssigned' }
            $resource = $candidate
        }
    }
    $identityType = $kind
    if (-not $invalidMetadata -and $records.Count -eq 0 -and $explicitValues.Count -eq 1) {
        $identityType = if ($explicitValues[0] -eq 'true') { 'UserAssigned' } else { 'SystemAssigned' }
    }
    [pscustomobject]@{ IdentityType=$identityType; Kind=$kind; IsUserAssigned=$isUserAssigned; Resource=$resource }
}

function Invoke-ManagedIdentityAssociationRequest {
    param([string]$Uri, [int]$Skip, [hashtable]$State)

    $renewed = $false
    while ($true) {
        $token = $global:GLOBALArmAccessToken
        $expiration = $token.Expiration_time -as [datetime]
        if ($null -eq $token -or [string]::IsNullOrWhiteSpace([string]$token.access_token) -or $null -eq $expiration) {
            $State.Unavailable = $true
            throw [System.Security.Authentication.AuthenticationException]::new('ARM authentication is unavailable.')
        }
        if ($expiration.ToUniversalTime() -le [datetime]::UtcNow) {
            if ($renewed) {
                $State.Unavailable = $true
                throw [System.Security.Authentication.AuthenticationException]::new('ARM authentication could not be renewed.')
            }
            $renewed = $true
            try { $authenticated = EnsureAuthAzurePsNative } catch { $authenticated = $false }
            if (-not $authenticated) {
                $State.Unavailable = $true
                throw [System.Security.Authentication.AuthenticationException]::new('ARM authentication could not be renewed.')
            }
            continue
        }

        # Automatic pagination changes POST to GET; collect each page explicitly instead.
        if ($null -ne $State.LastRequestFinished) {
            $delay = 1100 - ([datetime]::UtcNow - $State.LastRequestFinished).TotalMilliseconds
            if ($delay -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling($delay)) }
        }
        try {
            Send-ApiRequest -Method POST -Uri $Uri -AccessToken $token.access_token -QueryParameters @{
                'api-version' = '2021-09-30-preview'
                '$top' = 100
                '$skip' = $Skip
                '$orderby' = 'name asc'
            } -DisablePagination -MaxRetries 2 -Silent -UserAgent $GlobalAuditSummary.UserAgent.Name -ErrorAction Stop
            return
        } catch {
            $authenticationError = ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::AuthenticationError)
            if (-not $authenticationError) { throw }
            if ($renewed) {
                $State.Unavailable = $true
                throw
            }
            $renewed = $true
            try { $authenticated = EnsureAuthAzurePsNative } catch { $authenticated = $false }
            if (-not $authenticated) {
                $State.Unavailable = $true
                throw [System.Security.Authentication.AuthenticationException]::new('ARM authentication could not be renewed.')
            }
        } finally {
            $State.LastRequestFinished = [datetime]::UtcNow
        }
    }
}

function Get-ManagedIdentityAssociatedResources {
    param([string]$ResourceId, [hashtable]$State)

    $resources = @{}
    $status = 'Complete'
    $skip = 0
    $requestPath = ($ResourceId -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    try {
        while ($true) {
            $page = @(Invoke-ManagedIdentityAssociationRequest -Uri ('https://management.azure.com' + $requestPath + '/listAssociatedResources') -Skip $skip -State $State)
            if ($page.Count -eq 1 -and $null -ne $page[0] -and $null -ne $page[0].PSObject.Properties['value']) { $page = @($page[0].value) }
            $newResources = 0
            foreach ($entry in $page) {
                $record = ConvertTo-ManagedIdentityResourceRecord -ResourceId $entry.id -Name $entry.name -SubscriptionName $entry.subscriptionDisplayName
                if ($null -eq $record) { $status = 'Partial'; continue }
                if ($resources.ContainsKey($record.Id)) { $status = 'Partial'; continue }
                $resources[$record.Id] = $record
                $newResources++
            }
            if ($page.Count -gt 0 -and $newResources -eq 0) { $status = 'Partial'; break }
            if ($page.Count -lt 100) { break }
            $skip += $page.Count
        }
    } catch {
        Write-Log -Level Verbose -Message "Managed identity resource association collection failed for '$ResourceId': $($_.Exception.Message)"
        $status = if ($resources.Count -gt 0) { 'Partial' } elseif ($State.Unavailable) { 'Unavailable' } else { 'Failed' }
    }
    $count = if ($status -eq 'Complete') { $resources.Count } else { '?' }
    [pscustomobject]@{ MiResourceId=$ResourceId; AssociatedResources=$count; AssociatedResourcesStatus=$status; AssociatedResourcesDetails=@($resources.Values | Sort-Object Name,Id) }
}

function Get-ManagedIdentityResourceAssociationIndex {
    param([AllowEmptyCollection()][array]$Identities)

    $bindings = @{}
    $userAssignedCount = 0
    $eligibleCount = 0
    $associationLookupLimit = 1000
    $collectionAvailable = ($global:GLOBALAzureSubscriptionDiscoveryComplete -and -not [string]::IsNullOrWhiteSpace([string]$global:GLOBALArmAccessToken.access_token))
    foreach ($identity in $Identities) {
        $binding = Get-ManagedIdentityResourceBinding -Identity $identity
        $bindings[[string]$identity.id] = $binding
        if ($binding.IsUserAssigned) { $userAssignedCount++ }
        if ($binding.Kind -eq 'UserAssigned' -and $collectionAvailable -and $global:GLOBALAzureVisibleSubscriptionIds -and $global:GLOBALAzureVisibleSubscriptionIds.ContainsKey($binding.Resource.SubscriptionId)) {
            $eligibleCount++
        }
    }
    if ($eligibleCount -ge $associationLookupLimit) {
        Write-Host "[i] EntraFalcon collection safeguard: skipping $eligibleCount eligible user-assigned identities (limit: fewer than $associationLookupLimit; $userAssignedCount identified in total)."
    } elseif ($eligibleCount -gt 0) {
        Write-Host "[*] Collect associated resources for $eligibleCount of $userAssignedCount user-assigned managed identities (one request per 1.1 seconds)."
    } elseif ($userAssignedCount -gt 0) {
        Write-Host "[i] Skipping associated resource collection: no eligible user-assigned managed identities ($userAssignedCount identified in total)."
    }
    $state = @{ Unavailable=$false; LastRequestFinished=$null }
    $queriedCount = 0
    $statusCounts = @{ Complete=0; Partial=0; Failed=0; SkippedLimit=0; SkippedSubscription=0; Unavailable=0; Unknown=0; FromMetadata=0 }
    $results = @{}
    foreach ($identity in $Identities) {
        $id = [string]$identity.id
        $binding = $bindings[$id]
        $resourceId = if ($null -ne $binding.Resource) { $binding.Resource.Id } else { $null }
        $result = [pscustomobject]@{ MiResourceId=$resourceId; AssociatedResources='?'; AssociatedResourcesStatus='Unknown'; AssociatedResourcesDetails=@() }
        if ($binding.Kind -eq 'SystemAssigned') {
            $result.AssociatedResources = 1
            $result.AssociatedResourcesStatus = 'FromMetadata'
            $result.AssociatedResourcesDetails = @($binding.Resource)
        } elseif ($binding.Kind -eq 'UserAssigned') {
            if (-not $global:GLOBALAzureSubscriptionDiscoveryComplete -or $state.Unavailable -or [string]::IsNullOrWhiteSpace([string]$global:GLOBALArmAccessToken.access_token)) {
                $result.AssociatedResources = '?'
                $result.AssociatedResourcesStatus = 'Unavailable'
            } elseif (-not $global:GLOBALAzureVisibleSubscriptionIds -or -not $global:GLOBALAzureVisibleSubscriptionIds.ContainsKey($binding.Resource.SubscriptionId)) {
                $result.AssociatedResources = '?'
                $result.AssociatedResourcesStatus = 'SkippedSubscription'
            } elseif ($eligibleCount -ge $associationLookupLimit) {
                $result.AssociatedResources = '-'
                $result.AssociatedResourcesStatus = 'SkippedLimit'
            } else {
                $result = Get-ManagedIdentityAssociatedResources -ResourceId $resourceId -State $state
                $queriedCount++
                if ($queriedCount % 50 -eq 0) {
                    Write-Host "[*] Associated resources: processed $queriedCount of $eligibleCount identities..."
                }
            }
        }
        $result | Add-Member -NotePropertyName IdentityType -NotePropertyValue $binding.IdentityType
        $results[$id] = $result
        $statusCounts[$result.AssociatedResourcesStatus]++
        Write-Log -Level Debug -Message "Associated resources for '$($identity.displayName)' ($id): status=$($result.AssociatedResourcesStatus); retrieved=$($result.AssociatedResourcesDetails.Count)."
    }
    if ($queriedCount -gt 0) {
        if ($state.Unavailable) {
            Write-Host "[i] Associated resource collection stopped after $queriedCount of $eligibleCount identities: ARM authentication is unavailable."
        } else {
            Write-Host "[+] Associated resource collection completed for $queriedCount of $eligibleCount identities."
        }
    }
    Write-Log -Level Verbose -Message ("Associated resource summary: complete=$($statusCounts.Complete), partial=$($statusCounts.Partial), failed=$($statusCounts.Failed), " +
        "skipped=$($statusCounts.SkippedLimit + $statusCounts.SkippedSubscription), unavailable=$($statusCounts.Unavailable), unknown=$($statusCounts.Unknown), from metadata=$($statusCounts.FromMetadata).")
    return $results
}

function ConvertTo-ManagedIdentityUtcDisplayDate {
    param([object]$Value)

    if ($Value -is [datetime]) {
        $date = $Value
        if ($date.Kind -eq [DateTimeKind]::Unspecified) {
            $date = [datetime]::SpecifyKind($date, [DateTimeKind]::Utc)
        }
        $utcDate = $date.ToUniversalTime()
    } elseif ($Value -is [datetimeoffset]) {
        $utcDate = $Value.UtcDateTime
    } else {
        $date = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$date)) {
            return '?'
        }
        $utcDate = $date.UtcDateTime
    }
    return $utcDate.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", [Globalization.CultureInfo]::InvariantCulture)
}

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
        [Parameter(Mandatory=$false)][hashtable]$CatalogRbacPrincipalIndex = @{},
        [Parameter(Mandatory=$false)][bool]$CatalogRbacAssessmentAvailable = $false,
        [Parameter(Mandatory=$false)][switch]$Csv = $false,
        [Parameter(Mandatory=$false)][switch]$ExportDataJson = $false,
        [Parameter(Mandatory=$false)][hashtable]$ServicePrincipalSignInActivityLookup = @{}
    )

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    $GraphTokenProvider = New-EntraFalconGraphTokenProvider -Purpose MainAuth

    #Define basic variables
    $Title = "ManagedIdentities"
    $ProgressCounter = 0
    $ManagedIdentitiesScriptWarningList = @()
    # Declared here so the processing loop can consult them even when no managed identities exist.
    $AppAssignmentsCoverage = @{}
    $GroupMemberCoverage = @{}
    $OwnedObjectsCoverage = @{}
    $FederatedCredsCoverage = @{}
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $SPImpactScore = @{
        "Base"                     = 1
        "APIDangerous"              = 800
        "APIHigh"                   = 400
        "APIMedium"                 = 100
        "APILow"                    = 50
        "ApiMisc"                   = 20
	    "GroupMember"               = 5
    }

    $SPLikelihoodScore = @{
        "Base"          	        = 1
        "AdditionalResource"         = 1
        "FederatedCredential"        = 1
        "OutsideTenantFederation"    = 1
        "Maximum"                    = 5
    }

    function Resolve-ManagedIdentityOwnedAgentObject {
        param(
            [Parameter(Mandatory = $true)]$OwnedObject
        )

        $resolvedObject = Resolve-DirectoryObjectReference -ObjectId $OwnedObject.Id -RawType $OwnedObject.'@odata.type' -CurrentTenant $CurrentTenant -AllUsersBasicHT @{} -AllGroupsDetails @{} -ServicePrincipalBasics @{} -AgentObjectBasics $AgentObjectBasics
        if (-not $resolvedObject) { return $null }

        return [pscustomobject]@{
            Id                   = $resolvedObject.Id
            AppId                = if ($null -ne $resolvedObject.PSObject.Properties['AppId']) { $resolvedObject.AppId } else { $null }
            DisplayName          = $resolvedObject.DisplayName
            Enabled              = $resolvedObject.Enabled
            PublisherName        = $resolvedObject.PublisherName
            Foreign              = $resolvedObject.Foreign
            Type                 = $resolvedObject.ObjectKind
            TargetReport         = $resolvedObject.TargetReport
            ServicePrincipalType = $resolvedObject.ServicePrincipalType
            CreationDate         = if ($null -ne $resolvedObject.PSObject.Properties['CreationDate']) { $resolvedObject.CreationDate } else { $null }
        }
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Managed Identity
    write-host "[*] Get Managed Identities"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'ManagedIdentity'"
        '$select' = "Id,DisplayName,AppId,servicePrincipalType,createdDateTime,PasswordCredentials,KeyCredentials,AlternativeNames"
        '$top' = $ApiTop
    }
    # A partial list cannot be told apart from a complete one, so fail instead of reporting an
    # empty tenant.
    try {
        $ManagedIdentities = @(Send-GraphRequest -AccessTokenProvider $GraphTokenProvider -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)
    } catch {
        throw "Managed identity enumeration failed and the report cannot be produced from a partial list: $($_.Exception.Message)"
    }

    
    $ManagedIdentitiesCount = $($ManagedIdentities.count)
    write-host "[+] Got $ManagedIdentitiesCount Managed Identities"
    $ResourceAssociationIndex = Get-ManagedIdentityResourceAssociationIndex -Identities $ManagedIdentities

    # Check if Azure IAM role were checked
    if (-not ($GLOBALAzurePsChecks)) {
        if ($GLOBALAzureIamWarningText) {
            $ManagedIdentitiesScriptWarningList += $GLOBALAzureIamWarningText
        } else {
            $ManagedIdentitiesScriptWarningList += "Coverage gap: Azure IAM role assignments were not assessed; Azure role assignments to MI are therefore missing from this report."
        }
    }

    if ($ManagedIdentitiesCount -ge 1) {
        $RelationshipBatchSize = 10000

        Write-Host "[*] Get all applications API permissions assignments"
        $AppAssignmentsResult = Get-EntraFalconObjectRelationshipChunked -Objects $ManagedIdentities -UrlTemplate "/servicePrincipals/{0}/appRoleAssignments?`$select=AppRoleId,ResourceId,ResourceDisplayName" -Provider $GraphTokenProvider -BatchSize $RelationshipBatchSize -QueryParameters @{} -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        $AppAssignmentsRaw = $AppAssignmentsResult.Values
        $AppAssignmentsCoverage = $AppAssignmentsResult.Coverage
        Write-Log -Level Debug -Message "Got $($AppAssignmentsRaw.count) assignments"

        Write-Host "[*] Get all applications group memberships"
        $GroupMemberResult = Get-EntraFalconObjectRelationshipChunked -Objects $ManagedIdentities -UrlTemplate "/servicePrincipals/{0}/transitiveMemberOf/microsoft.graph.group?`$select=Id,displayName,visibility,securityEnabled,groupTypes,isAssignableToRole" -Provider $GraphTokenProvider -BatchSize $RelationshipBatchSize -QueryParameters @{} -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        $GroupMemberRaw = $GroupMemberResult.Values
        $GroupMemberCoverage = $GroupMemberResult.Coverage
        Write-Log -Level Debug -Message "Got $($GroupMemberRaw.count) memberships"

        Write-Host "[*] Get all application object ownerships"
        $OwnedObjectsResult = Get-EntraFalconObjectRelationshipChunked -Objects $ManagedIdentities -UrlTemplate "/servicePrincipals/{0}/ownedObjects" -Provider $GraphTokenProvider -BatchSize $RelationshipBatchSize -QueryParameters @{} -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        $OwnedObjectsRaw = $OwnedObjectsResult.Values
        $OwnedObjectsCoverage = $OwnedObjectsResult.Coverage
        Write-Log -Level Debug -Message "Got $($OwnedObjectsRaw.count) ownerships"

        Write-Host "[*] Get all federated identity credentials"
        $FederatedCredsResult = Get-EntraFalconObjectRelationshipChunked -Objects $ManagedIdentities -UrlTemplate "/servicePrincipals/{0}/federatedIdentityCredentials" -Provider $GraphTokenProvider -BatchSize $RelationshipBatchSize -QueryParameters @{} -UserAgent $($GlobalAuditSummary.UserAgent.Name) -BetaAPI:$false
        $FederatedCredsRaw = $FederatedCredsResult.Values
        $FederatedCredsCoverage = $FederatedCredsResult.Coverage

        $RelationshipCoverageTotal = $AppAssignmentsCoverage.Count + $GroupMemberCoverage.Count + $OwnedObjectsCoverage.Count
        if ($RelationshipCoverageTotal -gt 0) {
            $ManagedIdentitiesScriptWarningList += "Coverage gap: one or more managed identity relationships (API permissions, group memberships, owned objects) could not be fully enumerated. Affected identities are marked in the Warnings column; an absence of permissions must not be read as no access."
        }
    }


    ########################################## SECTION: Managed Identity Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = if ($ManagedIdentitiesCount -ge 200) {
        [Math]::Floor($ManagedIdentitiesCount / 4)
    } else {
        [Math]::Max([Math]::Floor($ManagedIdentitiesCount / 10), 1)
    }
    $IsSmallCollection = ($ManagedIdentitiesCount -gt 0 -and $ManagedIdentitiesCount -lt 200)
    if ($IsSmallCollection) {
        $ProcessingObjectLabel = if ($ManagedIdentitiesCount -eq 1) { 'managed identity' } else { 'managed identities' }
        Write-Host "[*] Processing $ManagedIdentitiesCount $ProcessingObjectLabel..."
    } elseif ($ManagedIdentitiesCount -ge 200) {
        Write-Host "[*] Status: Processing managed identity 1 of $ManagedIdentitiesCount (updates every $StatusUpdateInterval managed identities)..."
    }
    
    #region Processing Loop
    #Loop through each Managed Identity and get additional info and store it in a custom object
    $signInLookupAvailable = ($PSBoundParameters.ContainsKey('ServicePrincipalSignInActivityLookup') -and $global:GLOBALSpSignInActivityAvailable -eq $true)
    foreach ($item in $ManagedIdentities) {
        $ProgressCounter++
        $LastSignIn = '?'
        $LastSignInDays = '?'
        if ($signInLookupAvailable -and -not [string]::IsNullOrWhiteSpace([string]$item.AppId)) {
            if (-not $ServicePrincipalSignInActivityLookup.ContainsKey([string]$item.AppId)) {
                $LastSignIn = '-'
                $LastSignInDays = '-'
            } else {
                $activity = $ServicePrincipalSignInActivityLookup[[string]$item.AppId]
                if ($activity.lastSignInAppAsClientState -eq 'Missing') {
                    $LastSignIn = '-'
                    $LastSignInDays = '-'
                } elseif ($activity.lastSignInAppAsClientState -eq 'Valid') {
                    $clientDate = [datetime]::MinValue
                    $clientDays = 0
                    if ([datetime]::TryParseExact([string]$activity.lastSignInAppAsClient, "yyyy-MM-dd HH:mm:ss 'UTC'",
                            [Globalization.CultureInfo]::InvariantCulture,
                            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$clientDate) -and
                        [int]::TryParse([string]$activity.lastSignInAppAsClientDays, [ref]$clientDays) -and $clientDays -ge 0) {
                        $LastSignIn = $activity.lastSignInAppAsClient
                        $LastSignInDays = $clientDays
                    }
                }
            }
        }
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = $SPLikelihoodScore["Base"] 
        $warnings = @()

        $miIdKey = [string]$item.Id
        $ResourceAssociation = $ResourceAssociationIndex[$miIdKey]
        if ($AppAssignmentsCoverage.ContainsKey($miIdKey)) {
            $warnings += "API permissions incomplete: application permission data could not be fully retrieved"
        }
        if ($GroupMemberCoverage.ContainsKey($miIdKey)) {
            $warnings += "Group membership incomplete: inherited roles and impact are understated"
        }
        if ($OwnedObjectsCoverage.ContainsKey($miIdKey)) {
            $warnings += "Owned objects incomplete: owned object data could not be fully retrieved"
        }
        $FederatedCredsDetails = @(
            if ($FederatedCredsRaw.ContainsKey($miIdKey)) {
                foreach ($credential in $FederatedCredsRaw[$miIdKey]) {
                    $trust = Get-ManagedIdentityFederationTrust -Issuer $credential.issuer -TenantId ([string]$CurrentTenant.Id)
                    [pscustomobject]@{
                        Id          = $credential.id
                        Name        = $credential.name
                        TenantBoundary = $trust.TenantBoundary
                        IssuerTenantId = $trust.IssuerTenantId
                        Issuer      = $credential.issuer
                        Subject     = $credential.subject
                        Audiences   = @($credential.audiences)
                        Description = $credential.description
                    }
                }
            }
        )
        $FederatedCredsCount = if ($FederatedCredsCoverage.ContainsKey($miIdKey)) { '?' } else { $FederatedCredsDetails.Count }

        $WarningsHighPermission = $null
        $WarningsDangerousPermission = $null
        $AppCredentials = @()
        

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $ManagedIdentitiesCount) {
            if ($IsSmallCollection) {
                Write-Log -Level Verbose -Message "Status: Processing managed identity $ProgressCounter of $ManagedIdentitiesCount..."
            } else {
                Write-Host "[*] Status: Processing managed identity $ProgressCounter of $ManagedIdentitiesCount..."
            }
        }

        # Check AlternativeNames in a safe way
        $MiPath = "Unknown"
        $explicitEntry = $null
        if ($item.AlternativeNames -and $item.AlternativeNames.Count -gt 0) {
            $explicitEntry = $item.AlternativeNames | Where-Object { $_ -like 'isExplicit=*' } | Select-Object -First 1
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
        $AzureMaxImpactThroughGroupMembership = 0
        $AzureMaxImpactThroughGroupOwnership = 0

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
                $azureMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Azure -TenantId ([string]$CurrentTenant.Id)
                $AzureMaxTierThroughGroupMembership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierThroughGroupMembership -CandidateTier $azureMetrics.MaxTier
                $candidateAzureExposureImpact = $group.AzureExposureImpact
                if ($candidateAzureExposureImpact -isnot [int]) {
                    if ($null -eq $candidateAzureExposureImpact -or $candidateAzureExposureImpact -eq '?' -or $candidateAzureExposureImpact -eq '-') {
                        $candidateAzureExposureImpact = 0
                    } else {
                        $candidateAzureExposureImpact = $candidateAzureExposureImpact -as [int]
                        if ($null -eq $candidateAzureExposureImpact) { $candidateAzureExposureImpact = 0 }
                    }
                }
                if ($candidateAzureExposureImpact -gt $AzureMaxImpactThroughGroupMembership) {
                    $AzureMaxImpactThroughGroupMembership = $candidateAzureExposureImpact
                }
            }
        }

        # Group ownership tier inheritance: active + eligible paths.
        foreach ($group in $OwnedGroups) {
            $entraMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Entra -IncludeEligible
            $EntraMaxTierThroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $EntraMaxTierThroughGroupOwnership -CandidateTier $entraMetrics.MaxTier

            if ($GLOBALAzurePsChecks) {
                $azureMetrics = Get-GroupActiveRoleMetrics -Group $group -RoleSystem Azure -TenantId ([string]$CurrentTenant.Id) -IncludeEligible
                $AzureMaxTierThroughGroupOwnership = Merge-HigherTierLabel -CurrentTier $AzureMaxTierThroughGroupOwnership -CandidateTier $azureMetrics.MaxTier
                $candidateAzureExposureImpact = $group.AzureExposureImpact
                if ($candidateAzureExposureImpact -isnot [int]) {
                    if ($null -eq $candidateAzureExposureImpact -or $candidateAzureExposureImpact -eq '?' -or $candidateAzureExposureImpact -eq '-') {
                        $candidateAzureExposureImpact = 0
                    } else {
                        $candidateAzureExposureImpact = $candidateAzureExposureImpact -as [int]
                        if ($null -eq $candidateAzureExposureImpact) { $candidateAzureExposureImpact = 0 }
                    }
                }
                if ($candidateAzureExposureImpact -gt $AzureMaxImpactThroughGroupOwnership) {
                    $AzureMaxImpactThroughGroupOwnership = $candidateAzureExposureImpact
                }
            }
        }

        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $DirectEntraMaxTier -CandidateTier $EntraMaxTierThroughGroupMembership
        $EntraMaxTier = Merge-HigherTierLabel -CurrentTier $EntraMaxTier -CandidateTier $EntraMaxTierThroughGroupOwnership
        if ($GLOBALAzurePsChecks) {
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $DirectAzureMaxTier -CandidateTier $AzureMaxTierThroughGroupMembership
            $AzureMaxTier = Merge-HigherTierLabel -CurrentTier $AzureMaxTier -CandidateTier $AzureMaxTierThroughGroupOwnership

            $DirectAzureMaxImpact = Get-AzureRoleExposureImpact -RoleDetails $AzureRoleDetails -TenantId ([string]$CurrentTenant.Id)
            $AzureMaxImpact = [int]$DirectAzureMaxImpact
            if ($AzureMaxImpactThroughGroupMembership -gt $AzureMaxImpact) {
                $AzureMaxImpact = $AzureMaxImpactThroughGroupMembership
            }
            if ($AzureMaxImpactThroughGroupOwnership -gt $AzureMaxImpact) {
                $AzureMaxImpact = $AzureMaxImpactThroughGroupOwnership
            }
        } else {
            $AzureMaxTier = "?"
            $AzureMaxImpact = "?"
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
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails -TenantId ([string]$CurrentTenant.Id)
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
            $AzureWarningMaxImpactMembership = 0

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
                        $azureMetrics = Get-GroupActiveRoleMetrics -Group $Groups -RoleSystem Azure -TenantId ([string]$CurrentTenant.Id)
                        $groupAzureRoleCount = $azureMetrics.RoleCount
                        $TotalAzureRoles += $groupAzureRoleCount
                        $candidateAzureWarningImpact = [int]$azureMetrics.MaxImpact
                        if ($candidateAzureWarningImpact -gt $AzureWarningMaxImpactMembership) {
                            $AzureWarningMaxImpactMembership = $candidateAzureWarningImpact
                        }
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
                    $Warnings += Get-AzureInheritedRoleWarningText -RoleCount $TotalAzureRoles -MaxImpact $AzureWarningMaxImpactMembership -Relationship membership
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
            $AzureWarningMaxImpactOwnership = 0
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
                        $azureMetrics = Get-GroupActiveRoleMetrics -Group $OwnedGroup -RoleSystem Azure -TenantId ([string]$CurrentTenant.Id) -IncludeEligible
                        $groupAzureRoleCount = $azureMetrics.RoleCount
                        $TotalAzureRoles += $groupAzureRoleCount
                        $candidateAzureWarningImpact = [int]$azureMetrics.MaxImpact
                        if ($candidateAzureWarningImpact -gt $AzureWarningMaxImpactOwnership) {
                            $AzureWarningMaxImpactOwnership = $candidateAzureWarningImpact
                        }
                    }

                    $groupCapCount = 0
                    [void][int]::TryParse([string]$OwnedGroup.CAPs, [ref]$groupCapCount)
                    if ($OwnedGroup.InheritedHighValue -ge 1 -and ($entraMetrics.RoleCount -ge 1 -or $groupAzureRoleCount -ge 1 -or $groupCapCount -ge 1)) {
                        $TotalInheritedHighValue += $OwnedGroup.InheritedHighValue
                    }

                    # Use the parsed count: CAPs is "?" when Conditional Access was not enumerated.
                    $TotalCAPs += $groupCapCount
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
                    $Warnings += Get-AzureInheritedRoleWarningText -RoleCount $TotalAzureRoles -MaxImpact $AzureWarningMaxImpactOwnership -Relationship ownership
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

        # Retrieved authentication paths provide a minimum exposure estimate when collection is incomplete.
        $associatedResourceCount = @($ResourceAssociation.AssociatedResourcesDetails | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) } | ForEach-Object { $_.Id } | Sort-Object -Unique).Count
        $federatedCredentialCount = @($FederatedCredsDetails | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) } | ForEach-Object { $_.Id } | Sort-Object -Unique).Count
        $LikelihoodScore += [math]::Max(0, $associatedResourceCount - 1) * $SPLikelihoodScore["AdditionalResource"]
        $LikelihoodScore += $federatedCredentialCount * $SPLikelihoodScore["FederatedCredential"]
        if (@($FederatedCredsDetails | Where-Object TenantBoundary -eq 'OutsideTenant').Count -gt 0) {
            $LikelihoodScore += $SPLikelihoodScore["OutsideTenantFederation"]
            $Warnings += "External federation configured."
        }
        $LikelihoodScore = [math]::Min($SPLikelihoodScore["Maximum"], $LikelihoodScore)

        # Calculate days since creation
        $CreationInDays = if ($item.createdDateTime) {
            $created = [datetime]::Parse($item.createdDateTime, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)

            (New-TimeSpan -Start $created -End (Get-Date).ToUniversalTime()).Days
        } else {
            "-"
        }

        $Inactive = Test-EntraFalconServicePrincipalInactive -SignInData @{ lastSignInDays = $LastSignInDays } `
            -CreationInDays $CreationInDays -ActivityAvailable ($LastSignInDays -ne '?')

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
        $AzureRolesEffective = if ($GLOBALAzurePsChecks) {
            $AzureRolesDirect + $AzureRolesThroughGroupMembership + $AzureRolesThroughGroupOwnership
        } else {
            "?"
        }
        $DirectCatalogRbacDetails = if ($CatalogRbacPrincipalIndex.ContainsKey([string]$item.Id)) { @($CatalogRbacPrincipalIndex[[string]$item.Id]) } else { @() }
        $CatalogRbacDetails = @(Merge-EntraFalconCatalogRbacAssignments -DirectAssignments $DirectCatalogRbacDetails -GroupMemberships $GroupMember)
        if (@($CatalogRbacDetails | Where-Object { [string]$_.Role -in @('Catalog Owner','Access Package Manager','Access Package Assignment Manager') }).Count -gt 0) {
            $Warnings += "Identity Governance management role assigned"
        }
        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }
        $CatalogRBAC = if ($CatalogRbacAssessmentAvailable) { $CatalogRbacDetails.Count } else { '-' }
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
            CatalogRBAC = $CatalogRBAC
            CatalogRbacDetails = $CatalogRbacDetails
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
            IdentityType = $ResourceAssociation.IdentityType
            MiPath = $MiPath
            MiResourceId = $ResourceAssociation.MiResourceId
            AssociatedResources = $ResourceAssociation.AssociatedResources
            AssociatedResourcesStatus = $ResourceAssociation.AssociatedResourcesStatus
            AssociatedResourcesDetails = $ResourceAssociation.AssociatedResourcesDetails
            CreationDate = $item.createdDateTime
            CreationInDays = $CreationInDays
            Inactive = $Inactive
            LastSignIn = $LastSignIn
            LastSignInDays = $LastSignInDays
            FederatedCreds = $FederatedCredsCount
            FederatedCredsDetails = $FederatedCredsDetails
            AzureRolesDirect = $AzureRolesDirect
            AzureRolesEffective = $AzureRolesEffective
            AzureRoles = $AzureRolesEffective
            AzureMaxTier = $AzureMaxTier
            AzureMaxLevel = Get-AzureImpactLevel -Impact $AzureMaxImpact
            AzureMaxImpact = $AzureMaxImpact
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
    if ($IsSmallCollection) {
        Write-Host "[+] Processed $ManagedIdentitiesCount $ProcessingObjectLabel."
    }
    #endregion

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"

    # Sort once and reuse the same risk ordering for the overview and details.
    $SortedManagedIdentitiesByRisk = $AllServicePrincipal | Sort-Object Risk -Descending

    #Define output of the main table
    $tableOutput = $SortedManagedIdentitiesByRisk | select-object DisplayName,DisplayNameLink,IdentityType,Inactive,CreationInDays,LastSignInDays,FederatedCreds,AssociatedResources,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AppCredentials,AzureRoles,AzureMaxTier,AzureMaxLevel,AzureMaxImpact,CatalogRBAC,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings
    
    #Define the managed identities to be displayed in detail
    $details = $SortedManagedIdentitiesByRisk

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
        $ReportingCatalogRbac = @($item.CatalogRbacDetails | ForEach-Object { [pscustomobject]@{ Role=$_.Role; Catalog="<a href=Catalogs_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($_.CatalogId)>$(ConvertTo-EntraFalconHtmlText $_.Catalog -DefaultValue '-')</a>"; AssignedVia=$_.AssignedVia; CatalogEnabled=$_.CatalogEnabled } })

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################`n")

        ############### HEADER
        $ReportingMIInfo = [pscustomobject]@{
            "Identity name" = $($item.DisplayName)
            "Client ID" = $($item.AppId)
            "Object ID" = $($item.Id)
            "CreationDate" = ConvertTo-ManagedIdentityUtcDisplayDate -Value $item.CreationDate
            "Last sign-in" = $item.LastSignIn
            "Inactive" = $item.Inactive
            "IdentityType" = $($item.IdentityType)
            "Object Path" = $($item.MiPath)
            "RiskScore" = $($item.Risk)
        }
        $ReportingAssociatedResources = @($item.AssociatedResourcesDetails | ForEach-Object {
            [pscustomobject]@{
                'Resource name' = ConvertTo-EntraFalconHtmlText $_.Name
                'Resource type' = ConvertTo-EntraFalconHtmlText $_.Type
                'Subscription' = ConvertTo-EntraFalconHtmlText $_.SubscriptionName
                'Resource group' = ConvertTo-EntraFalconHtmlText $_.ResourceGroup
            }
        })

        #Build dynamic TXT report property list
        $TxtReportProps = @("Identity name","Client ID","Object ID","CreationDate","Last sign-in","Inactive","IdentityType","Object Path","RiskScore")

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
            $ReportingAzureRoles = foreach ($object in ($item.AzureRoleDetails | Sort-Object -Property @{
                Expression = { [int]$_.AssignmentImpact }
                Descending = $true
            }, 'RoleName')) {
                [pscustomobject]@{ 
                    "Role name" = $($object.RoleName)
                    "RoleType" = $($object.RoleType)
                    "Level" = $object.Level
                    "Impact" = $($object.AssignmentImpact)
                    "Scope type" = $($object.ScopeType)
                    "Environment" = $($object.Environment)
                    "Resources" = $($object.ObservedResources)
                    "Conditions" = $($object.Conditions)
                    "Scoped to" = $($object.Scope)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignment`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | Out-String))
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

        if ($item.AssociatedResourcesDetails.Count -gt 0) {
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Associated Azure Resources`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($item.AssociatedResourcesDetails | Select-Object @{Name='Resource name';Expression={$_.Name}},@{Name='Resource type';Expression={$_.Type}},@{Name='Subscription';Expression={$_.SubscriptionName}},@{Name='Resource group';Expression={$_.ResourceGroup}} | Format-Table -AutoSize -Wrap | Out-String -Width 512))
        }

        $ReportingFederatedCredsTxt = @(
            foreach ($credential in $item.FederatedCredsDetails) {
                [pscustomobject]@{
                    Name        = $credential.Name
                    'Federation boundary' = switch ($credential.TenantBoundary) {
                        'SameTenant' { 'This tenant' }
                        'OutsideTenant' { 'External' }
                        default { 'Unknown' }
                    }
                    Issuer      = $credential.Issuer
                    Subject     = $credential.Subject
                    Audiences   = $credential.Audiences -join ', '
                    Description = if ([string]::IsNullOrWhiteSpace($credential.Description)) { '-' } else { $credential.Description }
                }
            }
        )
        $ReportingFederatedCreds = @(
            foreach ($credential in $ReportingFederatedCredsTxt) {
                $HtmlCredential = [ordered]@{}
                foreach ($property in $credential.PSObject.Properties) {
                    $HtmlCredential[$property.Name] = ConvertTo-EntraFalconHtmlText -Value $property.Value -DefaultValue '-'
                }
                [pscustomobject]$HtmlCredential
            }
        )
        if ($ReportingFederatedCredsTxt.Count -gt 0) {
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Federated Identity Credentials`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingFederatedCredsTxt | Format-List -Property Name,'Federation boundary',Issuer,Subject,Audiences,Description | Out-String -Width 512))
        }

        if (($item.CatalogRbacDetails | Measure-Object).Count -ge 1) {
            $ReportingCatalogRbacTxt = @($item.CatalogRbacDetails | Select-Object Catalog,Role,AssignedVia,CatalogEnabled)
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Identity Governance RBAC Assignments`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCatalogRbacTxt | Format-Table Catalog,Role,AssignedVia,CatalogEnabled | Out-String))
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
            [void]$DetailTxtBuilder.AppendLine("Credentials`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String -Width 512))
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
            "Associated Azure Resources" = $ReportingAssociatedResources
            "Federated Identity Credentials" = $ReportingFederatedCreds
            "Identity Governance RBAC Assignments" = $ReportingCatalogRbac
            "Credentials" = $ReportingCredentials
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)


    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()
    write-host "[*] Writing report files..."
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},IdentityType,Inactive,CreationInDays,LastSignInDays,FederatedCreds,AssociatedResources,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AzureMaxLevel,AzureMaxImpact,CatalogRBAC,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings
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
                        <li><code>term</code> &mdash; substring match anywhere in object</li>
                        <li><code>!term</code> &mdash; exclude objects containing term</li>
                        <li><code>=value</code> &mdash; exact field value match</li>
                        <li><code>^prefix</code> &mdash; field value starts with</li>
                        <li><code>$suffix</code> &mdash; field value ends with</li>
                        <li><code>a && b</code> &mdash; both must match</li>
                        <li><code>a || b</code> &mdash; either must match</li>
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

    if ($ExportDataJson) {
        Export-EntraFalconDataJson -OutputFolder $outputFolder -DatasetName "ManagedIdentities" -Data $AllServicePrincipal | Out-Null
    }

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
        $tableOutput | format-table DisplayName,IdentityType,Inactive,CreationInDays,LastSignInDays,FederatedCreds,AssociatedResources,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AzureMaxLevel,AzureMaxImpact,CatalogRBAC,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
        if ($Csv) {
            $tableOutput | select-object DisplayName,IdentityType,Inactive,CreationInDays,LastSignInDays,FederatedCreds,AssociatedResources,GroupMembership,GroupOwnership,AppOwnership,BlueprintOwn,SpOwn,EntraRoles,EntraMaxTier,AzureRoles,AzureMaxTier,AzureMaxLevel,AzureMaxImpact,CatalogRBAC,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation -Encoding UTF8
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
    $IdentityTypeCounts = @{ UserAssigned=0; SystemAssigned=0; Unknown=0 }
    $AppApiDangerous = 0
    $AppApiHigh = 0
    $AppApiMedium = 0
    $AppApiLow = 0
    $AppApiMisc = 0

    foreach ($app in $AllServicePrincipal) {
        $IdentityTypeCounts[$app.IdentityType]++

        if ($app.ApiDangerous) {$AppApiDangerous++}
        if ($app.ApiHigh) {$AppApiHigh++}
        if ($app.ApiMedium) {$AppApiMedium++}
        if ($app.ApiLow) {$AppApiLow++}
        if ($app.ApiMisc) {$AppApiMisc++}
    }

    # Store in global var
    $GlobalAuditSummary.ManagedIdentities.Count = $ManagedIdentitiesCount
    $GlobalAuditSummary.ManagedIdentities.IdentityTypes = $IdentityTypeCounts
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Dangerous = $AppApiDangerous
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.High = $AppApiHigh
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Medium = $AppApiMedium
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Low = $AppApiLow
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Misc = $AppApiMisc

    $managedIdentityAzureRoleDetails = @($AllServicePrincipal | ForEach-Object { @($_.AzureRoleDetails) })
    $GlobalAuditSummary.ManagedIdentities.AzureScopeType = Get-AzureRoleScopeTypeCounts -Assignments $managedIdentityAzureRoleDetails

    $azureImpactLevelCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Unknown = 0 }
    foreach ($assignment in $managedIdentityAzureRoleDetails) {
        switch ($assignment.Level) {
            "Critical" { $azureImpactLevelCounts.Critical++; break }
            "High" { $azureImpactLevelCounts.High++; break }
            "Medium" { $azureImpactLevelCounts.Medium++; break }
            "Low" { $azureImpactLevelCounts.Low++; break }
            default { $azureImpactLevelCounts.Unknown++ }
        }
    }
    $GlobalAuditSummary.ManagedIdentities.AzureImpactLevel = $azureImpactLevelCounts


    #Convert to Hashtable for faster searches
    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    Return $AllServicePrincipalHT

}

Export-ModuleMember -Function Invoke-CheckManagedIdentities
