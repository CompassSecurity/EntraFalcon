<#
.SYNOPSIS
   Collects and enriches Entra ID and Azure IAM role assignments, producing output in HTML, TXT, and CSV formats.
#>

function Invoke-CheckRoles {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$ManagedIdentities,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Function section ########################

    $ObjectDetailsCache = @{}

    #Function to get details about specific objects
    function Get-ObjectDetails($ObjectID, $type = "unknown") {
        $normalizedType = $type.ToString().ToLowerInvariant()
        $cacheKey = "$normalizedType|$ObjectID"

        if ($ObjectDetailsCache.ContainsKey($cacheKey)) {

            return $ObjectDetailsCache[$cacheKey]
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "user") {
            $MatchingUser = $Users[$($ObjectID)]
            if ($MatchingUser) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingUser.UPN
                    DisplayNameLink = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingUser.UPN)</a>"
                    Type = "User"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "group" ) {
            $MatchingGroup = $AllGroupsDetails[$($ObjectID)]
            if ($MatchingGroup) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingGroup.DisplayName
                    DisplayNameLink = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingGroup.DisplayName)</a>"
                    Type = "Group"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal") {
            $MatchingEnterpriseApp = $EnterpriseApps[$($ObjectID)]
            if ($MatchingEnterpriseApp) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingEnterpriseApp.DisplayName)</a>"
                    Type = "Enterprise Application"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "managedidentity" -or $normalizedType -eq "serviceprincipal") {
            $MatchingManagedIdentity = $ManagedIdentities[$($ObjectID)]
            if ($MatchingManagedIdentity) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingManagedIdentity.DisplayName
                    DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingManagedIdentity.DisplayName)</a>"
                    Type = "Managed Identity"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "AppRegistration" ) {
            $MatchingAppRegistration = $AppRegistrations[$($ObjectID)]
            if ($MatchingAppRegistration) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingAppRegistration.DisplayName
                    DisplayNameLink = "<a href=AppRegistration_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingAppRegistration.DisplayName)</a>"
                    Type = "App Registration"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }

        if ($normalizedType -eq "unknown" -or $normalizedType -eq "administrativeunit") {
            $MatchingAdministrativeUnit = $AdminUnitWithMembers | Where-Object { $_.AuId -eq $ObjectID }
            if ($MatchingAdministrativeUnit) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingAdministrativeUnit.DisplayName
                    DisplayNameLink = $MatchingAdministrativeUnit.DisplayName
                    Type = "Administrative Unit"
                }
                $ObjectDetailsCache[$cacheKey] = $object
                Return $object
            }
        }


        # Fallback: resolve unknown objects via directoryObjects/getByIds (expensive but should be OK with caching)
        if ($normalizedType -eq "unknown" -or $normalizedType -like "*foreign*") {


            Write-Log -Level Trace -Message "Manually resolve $ObjectID"
            # Not sure if device make sense, but the Azure Portal use it as well
            $Body = @{
                ids   = @($ObjectID)
                types = @(
                    "user",
                    "group",
                    "servicePrincipal",
                    "device",
                    "directoryObjectPartnerReference"
                )
            }

            $ResolvedDirectoryObject = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method POST -Uri "/directoryObjects/getByIds" -Body $Body -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)

            if ($ResolvedDirectoryObject) {

                if ($ResolvedDirectoryObject -is [System.Array]) {
                    $ResolvedDirectoryObject = $ResolvedDirectoryObject | Select-Object -First 1
                }

                $odataType = $ResolvedDirectoryObject.'@odata.type'
                $resolvedType = "Unknown Object"

                #Special handling for foreign partner objects
                if ($odataType -eq "#microsoft.graph.directoryObjectPartnerReference") {
                    switch ($ResolvedDirectoryObject.objectType) {
                        "User" { $resolvedType = "User" }
                        "Group" { $resolvedType = "Group" }
                        "ServicePrincipal" { $resolvedType = "Enterprise Application" }
                        "Device" { $resolvedType = "Device" }
                        default { $resolvedType = "Unknown Object" }
                    }
                } else {
                    switch ($odataType) {
                        "#microsoft.graph.user" { $resolvedType = "User" }
                        "#microsoft.graph.group" { $resolvedType = "Group" }
                        "#microsoft.graph.servicePrincipal" { $resolvedType = "Service Principal" }
                        "#microsoft.graph.application" { $resolvedType = "App Registration" }
                        "#microsoft.graph.device" { $resolvedType = "Device" }
                        default { $resolvedType = "Unknown Object" }
                    }
                }

                # Check what kind of SP
                if ($odataType -eq "#microsoft.graph.servicePrincipal") {
                    switch ($ResolvedDirectoryObject.servicePrincipalType) {
                        "Application" { $resolvedType = "Enterprise Application" }
                        "ManagedIdentity" { $resolvedType = "Managed Identity" }
                        "ServiceIdentity" { $resolvedType = "Service Identity" }
                        default { $resolvedType = "Service Principal" }
                    }
                }

                $resolvedName = $null
                if ($ResolvedDirectoryObject.PSObject.Properties.Match('userPrincipalName').Count -gt 0 -and $ResolvedDirectoryObject.userPrincipalName) {
                    $resolvedName = [string]$ResolvedDirectoryObject.userPrincipalName
                } elseif ($ResolvedDirectoryObject.PSObject.Properties.Match('displayName').Count -gt 0 -and $ResolvedDirectoryObject.displayName) {
                    $resolvedName = [string]$ResolvedDirectoryObject.displayName
                }

                if (-not $resolvedName) {
                    $resolvedName = $ObjectID
                }

                if ($normalizedType -like "*foreign*") {
                    $resolvedName = "$resolvedName (Foreign)"
                }

                # Define returned objects. Since the object have not been found in the internal lists they are not linked.
                switch ($resolvedType) {
                    "User" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "User"
                        }
                    }
                    "Group" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Group"
                        }
                    }
                    "Enterprise Application" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Enterprise Application"
                        }
                    }
                    "Managed Identity" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Managed Identity"
                        }
                    }
                    "Service Identity" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Service Identity"
                        }
                    }

                    "Service Principal" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Service Principal"
                        }
                    }

                    "App Registration" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "App Registration"
                        }
                    }
                    "Device" {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Device"
                        }
                    }

                    default {
                        $object = [PSCustomObject]@{
                            DisplayName     = $resolvedName
                            DisplayNameLink = $resolvedName
                            Type            = "Unknown Object"
                        }
                    }
                }

                $ObjectDetailsCache[$cacheKey] = $object
                return $object
            }
        }

        #Unknown Object
        if ($normalizedType -eq "unknown") {

            $object = [PSCustomObject]@{
                DisplayName = $ObjectID
                DisplayNameLink = $ObjectID
                Type = "Unknown Object"
            }
            Write-Log -Level Debug -Message "Unknown Object: $ObjectID"
            $ObjectDetailsCache[$cacheKey] = $object
            Return $object
        }
    }

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "Role_Assignments"
    $WarningReport = @()
    if (-not $GLOBALGraphExtendedChecks) {$WarningReport += "Coverage gap: eligible role assignments not assessed; only active assignments are included."}

    ########################################## SECTION: DATACOLLECTION ##########################################

    write-host "[*] Process Entra role assignments"

    # Flatten the merged hash table into a single array
    $FlattenedAssignments = foreach ($entry in $TenantRoleAssignments.GetEnumerator()) {
        foreach ($a in @($entry.Value)) { $a }
    }

    $EntraRoles = foreach ($item in $FlattenedAssignments) {
        $PrincipalDetails = Get-ObjectDetails -ObjectID $item.PrincipalId

        $ScopeDetails = if ($item.DirectoryScopeId -eq "/") {
            [PSCustomObject]@{
                DisplayName = "/"
                DisplayNameLink = "/"
                Type        = "Tenant"
            }
        } elseif ($($item.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $($item.DirectoryScopeId).Replace("/administrativeUnits/", "")
            Get-ObjectDetails -ObjectID $ObjectID -type AdministrativeUnit
        }else {
            $ObjectID = $item.DirectoryScopeId.Replace("/", "")
            Get-ObjectDetails -ObjectID $ObjectID
        }
        #Convert Tier-Level to text
        switch ($item.RoleTier) {
            0 {$RoleTier = "Tier-0"; break}
            1 {$RoleTier = "Tier-1"; break}
            2 {$RoleTier = "Tier-2"; break}
            3 {$RoleTier = "Tier-3"; break}
            "?" {$RoleTier = "Uncategorized"}
        }
        [pscustomobject]@{
            "Role" = $($item.DisplayName)
            "PrincipalId" = $($item.PrincipalId)
            "PrincipalDisplayName" = $($PrincipalDetails.DisplayName)
            "PrincipalDisplayNameLink" = $($PrincipalDetails.DisplayNameLink)
            "PrincipalType" = $($PrincipalDetails.Type)
            "RoleTier" = $RoleTier
            "AssignmentType" = $($item.AssignmentType)
            "DirectoryScopeId" = $($item.DirectoryScopeId)
            "IsPrivileged" = $($item.IsPrivileged)
            "IsBuiltIn" = $($item.IsBuiltIn)
            "ScopeResolved" = "$($ScopeDetails.DisplayName) ($($ScopeDetails.Type))"
            "ScopeResolvedLink" = "$($ScopeDetails.DisplayNameLink) ($($ScopeDetails.Type))"
        }
    }

    # Custom sort order
    $SortedEntraRoles = $EntraRoles | Sort-Object @{
        Expression = { $_.Role -eq "Global Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Privileged Role Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Privileged Authentication Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Application Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-0" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "User Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.Role -eq "Groups Administrator" }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-1" }
        Descending = $true
    }, @{
        Expression = { $_.IsPrivileged }
        Descending = $true
    }, @{
        Expression = { $_.RoleTier -eq "Tier-2" }
        Descending = $true
    }, @{
        Expression = { $_.Role }
        Descending = $false
    }


    write-host "[*] Process Azure role assignments"
    # Convert hashtable to normal objects
    $SortedAzureRolesList = [System.Collections.Generic.List[object]]::new()

    $AzureIAMAssignments.GetEnumerator() | ForEach-Object {
        $PrincipalId = $_.Key
        $Assignments = @($_.Value)

        $PrincipalType = $null
        if ($Assignments.Count -gt 0) {
            $PrincipalType = $Assignments[0].PrincipalType
        }

        if ($PrincipalType -and $PrincipalType -notlike "Foreign*") {
            $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId -type $PrincipalType

            # Fallback
            if (-not $PrincipalDetails -or $PrincipalDetails.Type -eq "Unknown Object") {
                $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId
            }

            if (-not $PrincipalDetails -or $PrincipalDetails.Type -eq "Unknown Object") {
                $PrincipalDisplayName = "$PrincipalId (Unknown)"
                $PrincipalDisplayNameLink = "$PrincipalId (Unknown)"
            } else {
                $PrincipalDisplayName = $PrincipalDetails.DisplayName
                $PrincipalDisplayNameLink = $PrincipalDetails.DisplayNameLink
            }

            foreach ($Assignment in $Assignments) {
                switch ($Assignment.RoleTier) {
                    0 { $RoleTier = "Tier-0"; break }
                    1 { $RoleTier = "Tier-1"; break }
                    2 { $RoleTier = "Tier-2"; break }
                    3 { $RoleTier = "Tier-3"; break }
                    default { $RoleTier = "Uncategorized" }
                }
                $SortedAzureRolesList.Add([PSCustomObject]@{
                    PrincipalId               = $PrincipalId
                    PrincipalDisplayName      = $PrincipalDisplayName
                    PrincipalDisplayNameLink  = $PrincipalDisplayNameLink
                    PrincipalType             = $Assignment.PrincipalType
                    RoleType                  = $Assignment.RoleType
                    Conditions                = $Assignment.Conditions
                    Role                      = $Assignment.RoleDefinitionName
                    Scope                     = $Assignment.Scope
                    RoleTier                  = $RoleTier
                    AssignmentType            = $Assignment.AssignmentType
                })
            }
        } else {
            $PrincipalDetails = Get-ObjectDetails -ObjectID $PrincipalId

            foreach ($Assignment in $Assignments) {
                switch ($Assignment.RoleTier) {
                    0 { $RoleTier = "Tier-0"; break }
                    1 { $RoleTier = "Tier-1"; break }
                    2 { $RoleTier = "Tier-2"; break }
                    3 { $RoleTier = "Tier-3"; break }
                    default { $RoleTier = "Uncategorized" }
                }
                $SortedAzureRolesList.Add([PSCustomObject]@{
                    PrincipalId               = $PrincipalId
                    PrincipalDisplayName      = $PrincipalDetails.DisplayName
                    PrincipalDisplayNameLink  = $PrincipalDetails.DisplayNameLink
                    PrincipalType             = $PrincipalDetails.Type
                    RoleType                  = $Assignment.RoleType
                    Conditions                = $Assignment.Conditions
                    Role                      = $Assignment.RoleDefinitionName
                    Scope                     = $Assignment.Scope
                    RoleTier                  = $RoleTier
                    AssignmentType            = $Assignment.AssignmentType
                })
            }
        }
    }

    $SortedAzureRoles = $SortedAzureRolesList


    # Define custom sorting logic for Scope
    $SortedAzureRoles = $SortedAzureRoles | Sort-Object -Property @{
        # Primary sorting: Scope depth and specific path rules
        Expression = {
            if ($_.Scope -eq '/') {
                0  # Root path should come first
            } elseif ($_.Scope -like '/providers/Microsoft.Management/managementGroups/*') {
                1  # Management group paths come second
            } else {
                2 + ($_.Scope -split '/').Count  # Subscription paths sorted by depth
            }
        }
    }, @{
        # Secondary sorting: Scope alphabetically (to maintain proper order within same depth)
        Expression = {$_.Scope}
    }, @{
        # Tertiary sorting: RoleDefinitionName priority (within same Scope)
        Expression = {
            switch ($_.Role) {
                "Owner" { 0 }                      # Owner comes first
                "User Access Administrator" { 1 }
                "Contributor" { 2 }
                "Role Based Access Control Administrator" { 3 }
                "Reservations Administrator" { 4 }
                default { 5 + [string]::Compare($_.Role, '') } # Alphabetical for others
            }
        }
    }



    write-host "[*] Writing log files"

    $mainEntraTable = $SortedEntraRoles | select-object -Property Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}},PrincipalType,@{Name = "Scope"; Expression = { $_.ScopeResolvedLink}}
    $mainEntraTableJson  = $mainEntraTable | ConvertTo-Json -Depth 5 -Compress

    $mainEntraTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainEntraTableJson + "`n" + '</script>'


    $mainAzureTable = $SortedAzureRoles | select-object -Property Scope,Role,RoleTier,RoleType,Conditions,AssignmentType,PrincipalType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}}
    $mainAzureTableJson  = $mainAzureTable | ConvertTo-Json -Depth 5 -Compress

    $mainAzureTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainAzureTableJson + "`n" + '</script>'



#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"
#Headers for the TXT output
$headerTXTEntraRoles = "
Entra Roles
****************************
"
$headerTXTAzureRoles = "
Azure Roles
****************************
"
    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

    #Generate and write HTML Entra role report
    Set-GlobalReportManifest -CurrentReportKey 'RoleEntra' -CurrentReportName 'Role Assignments Entra ID' -Warnings $WarningReport
    $Report = ConvertTo-HTML -Body "$headerHtml $mainEntraTableHTML" -Title "$Title Enumeration" -Head ($global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript
    $Report | Out-File "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $headerTXTEntraRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $SortedEntraRoles | format-table Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType, PrincipalDisplayName, PrincipalType,ScopeResolved | Out-File -Width 512 "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    if ($Csv) {
        $SortedEntraRoles | select-object Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType, PrincipalDisplayName, PrincipalType,ScopeResolved | Export-Csv -Path "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    }
    $OutputFormats = if ($Csv) { "CSV,TXT,HTML" } else { "TXT,HTML" }
    write-host "[+] Details of $($SortedEntraRoles.count) Entra ID role assignments stored in output files ($OutputFormats): $outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

    #Add information to the enumeration summary
    $EntraEligibleCount = 0
    $Tier0Count = 0
    $Tier1Count = 0
    $Tier2Count = 0
    $TierUncatCount = 0
    $AssignmentsBuiltInRoles = 0
    $AssignmentPrincipalTypUsers = 0
    $AssignmentPrincipalTypGroups = 0
    $AssignmentPrincipalTypApps = 0
    $AssignmentPrincipalTypMIs = 0
    $AssignmentPrincipalTypUnknown = 0

    foreach ($assignment in $SortedEntraRoles) {
        if ($assignment.AssignmentType -eq "eligible") {
            $EntraEligibleCount++
        }

        switch ($assignment.RoleTier) {
            "Tier-0" {$Tier0Count++; break}
            "Tier-1" {$Tier1Count++; break}
            "Tier-2" {$Tier2Count++; break}
            "Uncategorized" {$TierUncatCount++}
        }

        if ($Assignment.IsBuiltIn) {
            $AssignmentsBuiltInRoles++
        }

        switch ($assignment.PrincipalType) {
            "User" {$AssignmentPrincipalTypUsers++; break}
            "Group" {$AssignmentPrincipalTypGroups++; break}
            "Enterprise Application" {$AssignmentPrincipalTypApps++; break}
            "Managed Identity" {$AssignmentPrincipalTypMIs++; break}
            "Unknown Object" {$AssignmentPrincipalTypUnknown++}
        }
    }

    # Store in global var
    $GlobalAuditSummary.EntraRoleAssignments.Count = @($SortedEntraRoles).count
    $GlobalAuditSummary.EntraRoleAssignments.Eligible = $EntraEligibleCount
    $GlobalAuditSummary.EntraRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles

    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.App = $AssignmentPrincipalTypApps
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.MI = $AssignmentPrincipalTypMIs
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown

    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-0" = $Tier0Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-1" = $Tier1Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-2" = $Tier2Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers.Uncategorized = $TierUncatCount



    if ($SortedAzureRoles.count -ge 1) {
        Set-GlobalReportManifest -CurrentReportKey 'RoleAz' -CurrentReportName 'Role Assignments Azure IAM'
        $Report = ConvertTo-HTML -Body "$headerHtml $mainAzureTableHTML" -Title "$Title Enumeration" -Head ($global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $GLOBALJavaScript
        $Report | Out-File "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"
        $headerTXTAzureRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $SortedAzureRoles | format-table Scope,Role,RoleTier,RoleType,Conditions,AssignmentType,PrincipalDisplayName,PrincipalType | Out-File -Width 512 "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        if ($Csv) {
            $SortedAzureRoles | select-object Scope,Role,RoleTier,RoleType,Conditions,AssignmentType,PrincipalDisplayName,PrincipalType | Export-Csv -Path "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
        }
        write-host "[+] Details of $($SortedAzureRoles.count) Azure role assignments stored in output files ($OutputFormats): $outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

        #Add information to the enumeration summary
        $AzureEligibleCount = 0
        $AzureTier0Count = 0
        $AzureTier1Count = 0
        $AzureTier2Count = 0
        $AzureTier3Count = 0
        $AzureTierUncatCount = 0
        $AssignmentsBuiltInRoles = 0
        $AssignmentPrincipalTypUsers = 0
        $AssignmentPrincipalTypGroups = 0
        $AssignmentPrincipalTypSPs = 0
        $AssignmentPrincipalTypUnknown = 0

        foreach ($assignment in $SortedAzureRoles) {
            if ($assignment.AssignmentType -eq "eligible") {
                $AzureEligibleCount++
            }
            if ($Assignment.RoleType -match "BuiltInRole") {
                $AssignmentsBuiltInRoles++
            }

            switch ($assignment.RoleTier) {
                "Tier-0" { $AzureTier0Count++; break }
                "Tier-1" { $AzureTier1Count++; break }
                "Tier-2" { $AzureTier2Count++; break }
                "Tier-3" { $AzureTier3Count++; break }
                "Uncategorized" { $AzureTierUncatCount++ }
            }

            switch ($assignment.PrincipalType) {
                "User" {$AssignmentPrincipalTypUsers++; break}
                "Group" {$AssignmentPrincipalTypGroups++; break}
                "ServicePrincipal" {$AssignmentPrincipalTypSPs++; break}
                "Unknown Object" {$AssignmentPrincipalTypUnknown++}
            }
        }

        #Add information to the enumeration summary
        $GlobalAuditSummary.AzureRoleAssignments.Count = $SortedAzureRoles.count
        $GlobalAuditSummary.AzureRoleAssignments.Eligible = $AzureEligibleCount
        $GlobalAuditSummary.AzureRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.SP = $AssignmentPrincipalTypSPs
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-0" = $AzureTier0Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-1" = $AzureTier1Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-2" = $AzureTier2Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-3" = $AzureTier3Count
        $GlobalAuditSummary.AzureRoleAssignments.Tiers.Uncategorized = $AzureTierUncatCount



    }

}

