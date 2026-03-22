<#
	.SYNOPSIS
	   Enumerates PIM role configuration.
#>

function Invoke-CheckPIM {

    ############################## Parameter section ########################
    # Users is passed by the shared calling interface but not consumed by this module
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Users')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$Users,
        [Parameter(Mandatory=$true)][hashtable]$AllCaps,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][switch]$Csv = $false
    )

    ############################## Function section ########################

    #Function to parse ISO8601 used in PIM
    function Parse-ISO8601Duration {
        param (
            [string]$DurationString,

            [ValidateSet('Hours','Days')]
            [string]$ReturnUnit = 'Hours'
        )

        $result = [PSCustomObject]@{
            Value = $null
            Unit  = $null
        }

        if ([string]::IsNullOrWhiteSpace($DurationString)) {
            return $result
        }

        $pattern = '^P(?:(?<Days>\d+)D)?(?:T(?:(?<Hours>\d+)H)?(?:(?<Minutes>\d+)M)?(?:(?<Seconds>\d+)S)?)?$'
        $match = [regex]::Match($DurationString.Trim(), $pattern)

        if (-not $match.Success) {
            $result.Unit = 'Unknown'
            return $result
        }

        $days    = if ($match.Groups['Days'].Success)    { [int]$match.Groups['Days'].Value }    else { 0 }
        $hours   = if ($match.Groups['Hours'].Success)   { [int]$match.Groups['Hours'].Value }   else { 0 }
        $minutes = if ($match.Groups['Minutes'].Success) { [int]$match.Groups['Minutes'].Value } else { 0 }
        $seconds = if ($match.Groups['Seconds'].Success) { [int]$match.Groups['Seconds'].Value } else { 0 }

        if (($days + $hours + $minutes + $seconds) -eq 0) {
            $result.Unit = 'Unknown'
            return $result
        }

        $timeSpan = New-TimeSpan -Days $days -Hours $hours -Minutes $minutes -Seconds $seconds

        switch ($ReturnUnit) {
            'Days' {
                $result.Value = [math]::Round($timeSpan.TotalDays, 2)
                $result.Unit  = 'Days'
            }
            'Hours' {
                $result.Value = [math]::Round($timeSpan.TotalHours, 2)
                $result.Unit  = 'Hours'
            }
        }

        return $result
    }





    ########################################## SECTION: DATACOLLECTION ##########################################

    # Check if access token for PIM is still valid. Refresh if required
    if (-not (Invoke-CheckTokenExpiration $GLOBALPIMsGraphAccessToken)) {Invoke-MsGraphRefreshPIM | Out-Null}

    $AllPIMDetails = [System.Collections.Generic.List[object]]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $Title = "PIM"

    write-host "[*] Get PIM settings"
    # Get all Entra Roles PIM Policies
    $QueryParameters = @{
        '$filter' = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
        '$expand' = 'rules'
        '$select' = "Id,scopeId,scopeType,rules"
    }
    $AllPimEntraPolicies = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri '/policies/roleManagementPolicies' -QueryParameters $QueryParameters -BetaAPI

    $PimPoliciesCount = $($AllPimEntraPolicies.count)
    write-host "[+] Got $PimPoliciesCount PIM settings"

    # Get all Entra Roles PIM Role/Policie relations
    $QueryParameters = @{
        '$filter' = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
        '$select' = "policyId,scopeId,scopeType,roleDefinitionId"
    }
    $AllPimEntraPoliciesAssignments = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri '/policies/roleManagementPolicyAssignments' -QueryParameters $QueryParameters -BetaAPI

    Write-Log -Level Verbose -Message "Got $($AllPimEntraPoliciesAssignments.count) PIM settings relations"

    # Get all role names
    $QueryParameters = @{
        '$select' = "id,displayName"
    }
    $EntraRolesDefinition = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri '/roleManagement/directory/roleDefinitions' -QueryParameters $QueryParameters -BetaAPI

    Write-Log -Level Verbose -Message "Got $($EntraRolesDefinition.count) Entra role definitions"

    # Create a lookup for role display names
    $RoleIdToNameMap = @{}
    foreach ($role in $EntraRolesDefinition) {
        $RoleIdToNameMap[$role.id] = $role.displayName
    }

    # Flatten the role assignments
    $FlattenedAssignments = @()
    foreach ($entry in $TenantRoleAssignments.Values) {
        foreach ($assignment in $entry) {
            $FlattenedAssignments += $assignment
        }
    }

    # Count Active/Eligible assignments per RoleDefinitionId
    $AssignmentCounts = $FlattenedAssignments | Group-Object -Property RoleDefinitionId | ForEach-Object {
        $roleId = $_.Name
        $activeAssignments = @($_.Group | Where-Object { $_.AssignmentType -eq "Active" })
        $eligibleAssignments = @($_.Group | Where-Object { $_.AssignmentType -eq "Eligible" })

        [PSCustomObject]@{
            RoleDefinitionId    = $roleId
            ActiveAssignments   = $activeAssignments.Count
            EligibleAssignments = $eligibleAssignments.Count
        }
    }


    # Build a lookup for PolicyId -> Rules
    $PolicyRulesMap = @{}
    foreach ($policy in $AllPimEntraPolicies) {
        $PolicyRulesMap[$policy.id] = $policy.rules
    }

    # Build final output objects with all role settings
    $FinalRoleData = @()

    foreach ($roleDef in $EntraRolesDefinition) {
        $roleId = $roleDef.id
        $roleName = $roleDef.displayName

        # Get counts
        $counts = $AssignmentCounts | Where-Object { $_.RoleDefinitionId -eq $roleId }
        $activeCount = if ($counts) { $counts.ActiveAssignments } else { 0 }
        $eligibleCount = if ($counts) { $counts.EligibleAssignments } else { 0 }

        # Find related policy assignment(s)
        $policyAssignments = $AllPimEntraPoliciesAssignments | Where-Object { $_.roleDefinitionId -eq $roleId }

        # Aggregate rules (there may be multiple policy IDs)
        $allRules = @()
        foreach ($pa in $policyAssignments) {
            $policyId = $pa.policyId
            if ($PolicyRulesMap.ContainsKey($policyId)) {
                $allRules += $PolicyRulesMap[$policyId]
            }
        }

        $FinalRoleData += [PSCustomObject]@{
            Id                  = $roleId
            RoleName            = $roleName
            ActiveAssignments   = $activeCount
            EligibleAssignments = $eligibleCount
            PolicyRules         = $allRules
        }
    }



    ########################################## SECTION: Start Processing ##########################################

    #region Processing Loop
    # Loop through each role setting and get additional info
    foreach ($item in $FinalRoleData) {
        $warningMessages = @()
        $Warnings = @()
        $LinkedCaps = @()
        $CapIssues = $false

        if ($GLOBALEntraRoleRating.ContainsKey($item.Id)) {
            # If the RoleDefinition ID is found, return its Tier-Level
            $RoleTier = switch ($GLOBALEntraRoleRating[$item.Id]) {
                0   {"Tier-0"}
                1   {"Tier-1"}
                2   {"Tier-2"}
                3   {"Tier-3"}
            }
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }

        # Create rule lookup
        $ruleMap = @{}
        foreach ($rule in $item.PolicyRules) {
            $ruleMap[$rule.id] = $rule
        }

        # Extract Enablement_EndUser_Assignment
        $enabledRules = $null
        if ($ruleMap.ContainsKey("Enablement_EndUser_Assignment")) {
            $enabledRules = $ruleMap["Enablement_EndUser_Assignment"].enabledRules
        }

        $mfaEnabled = $enabledRules -contains "MultiFactorAuthentication"
        $justificationEnabled = $enabledRules -contains "Justification"
        $TicketingEnabled = $enabledRules -contains "Ticketing"

        # Extract AuthenticationContext_EndUser_Assignment
        $authCtxEnabled = $false
        $claimValue = $null
        if ($ruleMap.ContainsKey("AuthenticationContext_EndUser_Assignment")) {
            $authCtxEnabled = $ruleMap["AuthenticationContext_EndUser_Assignment"].isEnabled -eq $true
            $claimValue = $ruleMap["AuthenticationContext_EndUser_Assignment"].claimValue
        }

        # Extract Expiration_EndUser_Assignment aka Activation maximum duration (hours)
        $durationRaw = $null
        if ($ruleMap.ContainsKey("Expiration_EndUser_Assignment")) {
            $expirationRule = $ruleMap["Expiration_EndUser_Assignment"]
            $durationRaw = $expirationRule.maximumDuration
            $parsedActivationDuration = Parse-ISO8601Duration -DurationString $durationRaw -ReturnUnit 'Hours'
        }

        # Extract Expiration_Admin_Eligibility
        $adminEligibilityEnabled = $false
        $adminEligibilityDurationRaw = $null
        if ($ruleMap.ContainsKey("Expiration_Admin_Eligibility")) {
            $adminEligibilityRule = $ruleMap["Expiration_Admin_Eligibility"]
            $adminEligibilityEnabled = $adminEligibilityRule.isExpirationRequired -eq $true
            $adminEligibilityDurationRaw = $adminEligibilityRule.maximumDuration
        }

        # Display the value even if it's set, as it doesn't affect the outcome
        if ($adminEligibilityEnabled) {
            $parsedAdminEligibilityDuration = Parse-ISO8601Duration -DurationString $adminEligibilityDurationRaw -ReturnUnit 'Days'
            $parsedAdminEligibilityDurationValue = $parsedAdminEligibilityDuration.Value
            $parsedAdminEligibilityDurationUnit = $parsedAdminEligibilityDuration.Unit
        } else {
            $parsedAdminEligibilityDurationValue = "-"
            $parsedAdminEligibilityDurationUnit = ""
        }


        # Extract Expiration_Admin_Assignment
        $adminAssignmentEnabled = $false
        $adminAssignmentDurationRaw = $null
        if ($ruleMap.ContainsKey("Expiration_Admin_Assignment")) {
            $adminAssignmentRule = $ruleMap["Expiration_Admin_Assignment"]
            $adminAssignmentEnabled = $adminAssignmentRule.isExpirationRequired -eq $true
            $adminAssignmentDurationRaw = $adminAssignmentRule.maximumDuration
        }

        # Even if a value is set display - because it does not matter
        if ($adminAssignmentEnabled) {
            $parsedAdminAssignmentDuration = Parse-ISO8601Duration -DurationString $adminAssignmentDurationRaw -ReturnUnit 'Days'
            $parsedAdminAssignmentDurationValue = $parsedAdminAssignmentDuration.Value
            $parsedAdminAssignmentDurationUnit = $parsedAdminAssignmentDuration.Unit
        } else {
            $parsedAdminAssignmentDurationValue = "-"
            $parsedAdminAssignmentDurationUnit = ""
        }


        # Extract Enablement_Admin_Assignment
        $adminAssignmentEnabledRules = @()
        if ($ruleMap.ContainsKey("Enablement_Admin_Assignment")) {
            $adminAssignmentEnabledRules = $ruleMap["Enablement_Admin_Assignment"].enabledRules
        }

        $adminMFAEnabled = $adminAssignmentEnabledRules -contains "MultiFactorAuthentication"
        $adminJustificationEnabled = $adminAssignmentEnabledRules -contains "Justification"


        # Extract Approval_EndUser_Assignment
        $approvalRequired = $false
        $approverObjects = @()

        if ($ruleMap.ContainsKey("Approval_EndUser_Assignment")) {
            $approvalRule = $ruleMap["Approval_EndUser_Assignment"]
            $approvalSetting = $approvalRule.setting
            $approvalRequired = $approvalSetting.isApprovalRequired -eq $true

            if ($approvalRequired -and $approvalSetting.approvalStages) {
                foreach ($stage in $approvalSetting.approvalStages) {
                    foreach ($approver in $stage.primaryApprovers) {
                        $type = 'Unknown'
                        $MemberCount = "-"

                        if ($approver.'@odata.type' -match 'groupMembers') {
                            $type = 'Group'
                            if ($AllGroupsDetails.ContainsKey($approver.id)) {
                                $MemberCount = $AllGroupsDetails[$approver.id].Users
                            }
                        } elseif ($approver.'@odata.type' -match 'singleUser') {
                            $type = 'User'
                        }

                        $approverObj = [PSCustomObject]@{
                            Type        = $type
                            Id          = $approver.id
                            Description = $approver.description
                            Members     = $MemberCount
                        }

                        $approverObjects += $approverObj
                    }
                }
            }
        }


        # Extract Notification_Admin_Admin_Eligibility (eligible assignments)
        $notifEligibilityDefaultEnabled = $false
        $notifEligibilityRecipients = @()
        $notifEligibilityRecipientCount = 0
        $NotifyAssignmentEligible = $false

        if ($ruleMap.ContainsKey("Notification_Admin_Admin_Eligibility")) {
            $notifRule = $ruleMap["Notification_Admin_Admin_Eligibility"]
            $notifEligibilityDefaultEnabled = $notifRule.isDefaultRecipientsEnabled -eq $true

            if ($notifRule.notificationRecipients) {
                $notifEligibilityRecipients = $notifRule.notificationRecipients
                $notifEligibilityRecipientCount = @($notifEligibilityRecipients).Count
            }

            if ($notifEligibilityDefaultEnabled -or $notifEligibilityRecipientCount -gt 0) {
                $NotifyAssignmentEligible = $true
            }
        }


        # Extract Notification_Admin_Admin_Assignment (active assignment)
        $notifAssignmentDefaultEnabled = $false
        $notifAssignmentRecipients = @()
        $notifAssignmentRecipientCount = 0
        $NotifyAssignmentActive = $false

        if ($ruleMap.ContainsKey("Notification_Admin_Admin_Assignment")) {
            $notifRule = $ruleMap["Notification_Admin_Admin_Assignment"]
            $notifAssignmentDefaultEnabled = $notifRule.isDefaultRecipientsEnabled -eq $true

            if ($notifRule.notificationRecipients) {
                $notifAssignmentRecipients = $notifRule.notificationRecipients
                $notifAssignmentRecipientCount = @($notifAssignmentRecipients).Count
            }

            if ($notifAssignmentDefaultEnabled -or $notifAssignmentRecipientCount -gt 0) {
                $NotifyAssignmentActive = $true
            }
        }

        # Extract Notification_Admin_EndUser_Assignment
        $notifyActivationDefaultEnabled = $false
        $notifyActivationRecipients = @()
        $notifyActivationRecipientCount = 0
        $NotifyActivation = $false

        if ($ruleMap.ContainsKey("Notification_Admin_EndUser_Assignment")) {
            $notifRule = $ruleMap["Notification_Admin_EndUser_Assignment"]
            $notifyActivationDefaultEnabled = $notifRule.isDefaultRecipientsEnabled -eq $true

            if ($notifRule.notificationRecipients) {
                $notifyActivationRecipients = $notifRule.notificationRecipients
                $notifyActivationRecipientCount = @($notifyActivationRecipients).Count
            }

            if ($notifyActivationDefaultEnabled -or $notifyActivationRecipientCount -gt 0) {
                $NotifyActivation = $true
            }
        }



        #Check auth context related Caps
        if ($authCtxEnabled) {
            $AuthContextIssues = ""
            $AuthContextIssueSummary = [System.Collections.Generic.List[string]]::new()

            # Process each matching policy
            $LinkedCaps = @(
                $AllCaps.values | Where-Object { $_.AuthContextId -contains $claimValue } | ForEach-Object {
                    $policy = $_
                    $Issues = [System.Collections.Generic.List[string]]::new()

                    # Check if sign-in frequency is not set to everyTime
                    if ($policy.SignInFrequencyInterval -ne 'EveryTime' -or -not $policy.SignInFrequency) {
                        $Issues.Add("sign-in frequency is not 'EveryTime'")
                    }

                    # Check if policy is not enabled
                    if ($policy.State -ne 'enabled') {
                        $Issues.Add("policy is not enabled")
                    }

                    # Check if policy targets all users
                    if ($policy.IncUsers -ne 'All') {
                        $Issues.Add("not target all users")
                    }

                    # Check if policy excludes users
                    if ($policy.ExcUsers -gt 0) {
                        $Issues.Add("excludes users")
                    }

                    # Check if policy excludes groups
                    if ($policy.ExcGroups -gt 0) {
                        $Issues.Add("excludes groups")
                    }

                    # Check if policy excludes roles
                    if ($policy.ExcRoles -gt 0) {
                        $Issues.Add("excludes roles")
                    }

                    # Check if policy targets sign-in risks
                    if ($policy.SignInRisk -gt 0) {
                        $Issues.Add("targets SinginRisk")
                    }

                    # Check if policy targets user risks
                    if ($policy.UserRisk -gt 0) {
                        $Issues.Add("targets UserRisk")
                    }

                    # Check if policy exclude platforms
                    if ($policy.ExcPlatforms -gt 0) {
                        $Issues.Add("excludes platforms")
                    }

                    # Check if policy includes specific platforms
                    if ($policy.IncPlatforms -gt 0 -and $policy.IncPlatforms -lt 6) {
                        $Issues.Add("includes specific platforms")
                    }

                    # Check if policy exclude networks
                    if ($policy.ExcNw -gt 1) {
                        $Issues.Add("exclude networks")
                    }

                    # Check if policy targets specific networks
                    if ($policy.IncNw -gt 0 -and -not ($policy.IncNw -eq "All")) {
                        $Issues.Add("targets specific networks")
                    }

                    # Check if policy targets specific AuthFlow
                    if (-not ($policy.AuthFlow -eq "")) {
                        $Issues.Add("targets AuthFlow")
                    }

                    # Check if policy targets specific App types
                    if ($policy.AppTypes -ne 'all') {
                        $appTypeCount = ($policy.AppTypes -split ',' | ForEach-Object { $_.Trim() }).Count
                        if ($appTypeCount -lt 4) {
                            $Issues.Add("targets specific app types")
                        }
                    }

                    # Check GrantControls and AuthStrength
                    $grantControlsStr = ($policy.GrantControls -join ' ')  # Convert to string for easier search
                    $hasMfa = $grantControlsStr -match '\bmfa\b'
                    $hasAuthStrength = -not [string]::IsNullOrWhiteSpace($policy.AuthStrength)

                    if (-not $hasMfa -and -not $hasAuthStrength) {
                        $Issues.Add("Neither MFA in GrantControls nor AuthStrength is configured")
                    }

                    if ($Issues.Count -gt 0) {
                        $AuthContextIssueSummary.Add("CAP '$($policy.DisplayName)' (AuthContext:$($policy.AuthContextId -join ', ')): $($Issues -join ' / ')")
                    }

                    [pscustomobject]@{
                        Id            = $policy.Id
                        DisplayName   = $policy.DisplayName
                        AuthContextId = $policy.AuthContextId
                        Issues        = if ($Issues.Count -gt 0) { @($Issues) } else { "-" }
                    }
                }
            )

            #Check if the role has an AuthContext which is not linked to a CAP
            if (@($LinkedCaps).Count -eq 0) {
                $warningMessages += "AuthContext ($claimValue) not linked to a CAP"
            } elseif ($AuthContextIssueSummary.Count -gt 0) {
                $AuthContextIssues = $AuthContextIssueSummary -join ', '
            }
        }

        # Role activation time
        if ($parsedActivationDuration.Unit -eq 'Hours') {
            if ($RoleTier -eq 'Tier-0') {
                if ($parsedActivationDuration.Value -gt 4) {
                    $warningMessages += 'long activation time (>4h)'
                }
            } else {
                if ($parsedActivationDuration.Value -gt 12) {
                    $warningMessages += 'long activation time (>12h)'
                }
            }
        }

        # Unexpected active assignment expiration (except Global Admin)
        if (-not $adminAssignmentEnabled -and $item.RoleName -ne "Global Administrator") {
            $warningMessages += "allows perm. active assignments"
        }

        # Missing AuthContext or Approval
        if (-not $authCtxEnabled -and -not $approvalRequired) {
            $warningMessages += "missing AuthContext or Approval"
        } elseif ($authCtxEnabled -and $CapIssues) {
            $warningMessages += $AuthContextIssues
        }

        #Customize message
        if ($RoleTier -eq "Tier-2" -or $RoleTier -eq "?") {
            $RoleTierReporting = ""
        } else {
            $RoleTierReporting = "$RoleTier but "
        }

        # Set property if any issues found
        $Warnings = if ($warningMessages.Count -gt 0) {
            $RoleTierReporting + ($warningMessages -join ", ")
        } else {
            ""
        }

        # Create output object
        $PIMRuleDetails = [PSCustomObject]@{
            Id                        = $item.id
            RoleLink                  = "<a href=#$($item.id)>$($item.RoleName)</a>"
            Role                      = $item.RoleName
            Tier                      = $RoleTier
            Eligible                  = $item.EligibleAssignments
            Active                    = $item.ActiveAssignments

            ActivationMFA             = $mfaEnabled
            ActivationJustification   = $justificationEnabled
            ActivationTicketing       = $TicketingEnabled
            ActivationAuthContext     = $authCtxEnabled
            ActivationDuration        = $parsedActivationDuration.Value
            ActivationDurationUnit    = $parsedActivationDuration.Unit
            ActivationApproval        = $approvalRequired
            ActivationApprovers       = $approverObjects

            EligibleExpiration        = $adminEligibilityEnabled
            EligibleExpirationTime    = $parsedAdminEligibilityDurationValue
            EligibleExpirationUnit    = $parsedAdminEligibilityDurationUnit

            ActiveExpiration          = $adminAssignmentEnabled
            ActiveExpirationTime      = $parsedAdminAssignmentDurationValue
            ActiveExpirationUnit      = $parsedAdminAssignmentDurationUnit

            ActiveAssignMFA           = $adminMFAEnabled
            ActiveAssignJustification = $adminJustificationEnabled

            AlertAssignEligible       = $NotifyAssignmentEligible
            AlertAssignActive         = $NotifyAssignmentActive
            AlertActivation           = $NotifyActivation

            LinkedCaps                = @($LinkedCaps).Count
            LinkedCapsDetails         = $LinkedCaps
            Warnings                  = $Warnings
        }

        [void]$AllPIMDetails.Add($PIMRuleDetails)
    }
    #endregion

    ########################################## SECTION: Generating Details ##########################################

    write-host "[*] Generating Details Section"

    #Sort roles based on tier level
    $order = @{
        'Tier-0' = 0
        'Tier-1' = 1
        'Tier-2' = 2
        'Tier-3' = 3
        '?'      = 4
    }

    $AllPIMDetails = $AllPIMDetails | Sort-Object {
        $tierKey = $_.Tier
        if ($order.ContainsKey($tierKey)) {
            $order[$tierKey]
        } else {
            5
        }
    }, Role


    #Define output of the main table
    $tableOutput = $AllPIMDetails | select-object Role,RoleLink,Tier,Eligible,Active,ActivationAuthContext,ActivationMFA,ActivationJustification,ActivationTicketing,ActivationDuration,ActivationApproval,EligibleExpiration,EligibleExpirationTime,ActiveExpiration,ActiveExpirationTime,ActiveAssignMFA,ActiveAssignJustification,AlertAssignEligible,AlertAssignActive,AlertActivation,Warnings

    #Create HTML main table
    $mainTable = $tableOutput | select-object -Property @{Name = "Role"; Expression = { $_.RoleLink}},Tier,Eligible,Active,ActivationAuthContext,ActivationMFA,ActivationJustification,ActivationTicketing,ActivationDuration,ActivationApproval,EligibleExpiration,EligibleExpirationTime,ActiveExpiration,ActiveExpirationTime,ActiveAssignMFA,ActiveAssignJustification,AlertAssignEligible,AlertAssignActive,AlertActivation,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    #Generate details section for each role
    foreach ($item in $AllPIMDetails) {

        $PimRoleSettingInfo = @()
        $ActivationSettings = @()
        $Approvers = @()
        $AssignmentSettings = @()
        $NotificationSettings = @()
        $LinkedCaps = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        ############### HEADER
        $PimRoleSettingInfo= [pscustomobject]@{
            "RoleName" = $($item.Role)
            "Role Tier" = $($item.Tier)
            "Eligible Assignments"  = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html?Role=$([System.Uri]::EscapeDataString($item.Role))&AssignmentType=Eligible>$($item.Eligible)</a>"
            "Active Assignments"     = "<a href=Role_Assignments_Entra_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html?Role=$([System.Uri]::EscapeDataString($item.Role))&AssignmentType=Active>$($item.Active)</a>"
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("RoleName","Role Tier")

        if ($item.Warnings -ne '') {
            $PimRoleSettingInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($PimRoleSettingInfo| Format-List $TxtReportProps | Out-String))


        ############### Activation Settings
        $ActivationSettings = [pscustomobject]@{
                    "Activation Max Duration" = "$($item.ActivationDuration) $($item.ActivationDurationUnit)"
                    "Justification Required" = $item.ActivationJustification
                    "Ticket Info Required" = $item.ActivationTicketing
                    "MFA Claim Required" = $item.ActivationMFA
                    "Auth Context Required" = $item.ActivationAuthContext
                    "Approver Required" = $item.ActivationApproval
             }

        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Activation Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($ActivationSettings | format-table | Out-String))



        ############## Approvers
        if ($item.ActivationApproval) {
            if ($($item.ActivationApprovers | Measure-Object).count -ge 1 -and $null -ne $item.ActivationApprovers) {
                $ApproversRaw = foreach ($object in $($item.ActivationApprovers)) {
                    #Check type and link the right file
                    $DisplayNameLink = switch ($object.Type) {
                        "Group"     { "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.Description)</a>" }
                        "User"      { "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.Description)</a>" }
                        default     { $($object.Description) }
                    }

                    [pscustomobject]@{
                        "Type" = $object.Type
                        "DisplayNameLink" = $DisplayNameLink
                        "DisplayName" = $object.Description
                        "Members" = $object.Members
                    }
                }


            } else {
                #If approvals are required but none are configured
                $ApproversRaw = [pscustomobject]@{
                        "Type" = "-"
                        "DisplayNameLink" = "No approvers configured. Defaulting to Privileged Role Administrators or Global Administrators."
                        "DisplayName" = "No approvers configured. Defaulting to Privileged Role Administrators or Global Administrators."
                        "Members" = "-"
                    }
            }

            [void]$DetailTxtBuilder.AppendLine("Activation Approvers")
            [void]$DetailTxtBuilder.AppendLine("------------------")
            [void]$DetailTxtBuilder.AppendLine(($ApproversRaw | format-table -Property Type,DisplayName,Members | Out-String))
            $Approvers = foreach ($obj in $ApproversRaw) {
                [pscustomobject]@{
                    Type            = $obj.Type
                    DisplayName     = $obj.DisplayNameLink
                    Members         = $obj.Members
                }
            }
        }

        ############## Linked CAPs (AuthContext)
        if ($item.LinkedCaps -ge 1) {

            $LinkedCapsRaw = foreach ($object in $($item.LinkedCapsDetails)) {
                [pscustomobject]@{
                    "DisplayNameLink" = "<a href=ConditionalAccessPolicies_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                    "DisplayName" = $object.DisplayName
                    "AuthContextId" = ($object.AuthContextId -join ', ')
                    "Issues" = ($object.Issues -join ', ')
                }
            }

            [void]$DetailTxtBuilder.AppendLine("Linked CAPs (Auth Context)")
            [void]$DetailTxtBuilder.AppendLine("------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($LinkedCapsRaw | format-table -Property DisplayName,AuthContextId,Issues | Out-String))
            $LinkedCaps = foreach ($obj in $LinkedCapsRaw) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    AuthContextId = $obj.AuthContextId
                    Issues        = $obj.Issues
                }
            }
        }


        ############### Assignment Settings
        if ($item.EligibleExpiration) {
            $MaxEligibleAssignment = "$($item.EligibleExpirationTime) $($item.EligibleExpirationUnit)"
        } else {
            $MaxEligibleAssignment = "-"
        }

        if ($item.ActiveExpiration) {
            $MaxActiveAssignment = "$($item.ActiveExpirationTime) $($item.ActiveExpirationUnit)"
        } else {
            $MaxActiveAssignment = "-"
        }

        # $item.EligibleExpiration and $item.ActiveExpiration are inverted due to the wording used in the portal.
        $AssignmentSettings = [pscustomobject]@{
                    "Allow Permanent Eligible Assignment" = !$item.EligibleExpiration
                    "Expire Eligible Assignments After" = $MaxEligibleAssignment
                    "Allow Permanent Active Assignment" = !$item.ActiveExpiration
                    "Expire Active Assignments After" = $MaxActiveAssignment
                    "MFA Claim Required" = $item.ActiveAssignMFA
                    "Justification Required" = $item.ActiveAssignJustification
        }

        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Assignment Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($AssignmentSettings | format-table | Out-String))


        $NotificationSettings = [pscustomobject]@{
                    "Alert On Eligible Assignment" = $item.AlertAssignEligible
                    "Alert On Permanent Assignments" = $item.AlertAssignActive
                    "Alert On Role Activation" = $item.AlertActivation
        }

        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Notification Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($NotificationSettings | format-table | Out-String))

        #Build final object
        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.Role
            "Object ID"       = $item.id
            "General Information" = $PimRoleSettingInfo
            "Activation Settings" = $ActivationSettings
            "Activation Approvers" = $Approvers
            "Linked CAPs (AuthContext)" = $LinkedCaps
            "Assignment Settings" = $AssignmentSettings
            "Notification Settings" = $NotificationSettings
        }

        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()


    ########################################## SECTION: OUTPUT WRITING ##########################################

    write-host "[*] Writing Reports"
    write-host ""

#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = This report includes only PIM settings for Entra ID roles.
************************************************************************************************************************
"

    # Build Detail section as JSON for the HTML Report
    $AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress

$ObjectsDetailsHEAD = @'
    <h2>PIM Policies Details</h2>
    <div class="details-toolbar">
        <button id="toggle-expand">Expand All</button>
        <div id="details-info" class="details-info">Showing 0-0 of 0 entries</div>
    </div>
    <div id="object-container"></div>
    <script id="object-data" type="application/json">
'@
    $AllObjectDetailsHTML = $ObjectsDetailsHEAD + "`n" + $AllObjectDetailsHTML + "`n" + '</script>'

    #Write TXT and CSV files
    $headerTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | format-table Role,Tier,Eligible,Active,ActivationAuthContext,ActivationMFA,ActivationJustification,ActivationTicketing,ActivationDuration,ActivationApproval,EligibleExpiration,EligibleExpirationTime,ActiveExpiration,ActiveExpirationTime,ActiveAssignMFA,ActiveAssignJustification,AlertAssignEligible,AlertAssignActive,AlertActivation,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    if ($Csv) {
        $tableOutput | select-object Role,Tier,Eligible,Active,ActivationAuthContext,ActivationMFA,ActivationJustification,ActivationTicketing,ActivationDuration,ActivationApproval,EligibleExpiration,EligibleExpirationTime,ActiveExpiration,ActiveExpirationTime,ActiveAssignMFA,ActiveAssignJustification,AlertAssignEligible,AlertAssignActive,AlertActivation,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    }
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

    # Set generic information which get injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'PIM' -CurrentReportName 'PIM Enumeration'


    # HTML header below the navbar
$headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>$Title Overview</h2>
"@

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixDynamicHTML
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title enumeration" -Head ($global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    # Store in global var
    $GlobalAuditSummary.PimSettings.Count = $PimPoliciesCount

    #Convert to Hashtable for faster searches
    $PimHT = @{}
    foreach ($PimRole in $AllPIMDetails) {
        $PimHT[$PimRole.Id] = $PimRole
    }

    Return $PimHT

}
