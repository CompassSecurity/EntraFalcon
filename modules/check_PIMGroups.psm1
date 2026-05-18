<#
    .SYNOPSIS
       Enumerates PIM for Groups configuration.
#>

function Invoke-CheckPIMGroups {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][string]$OutputFolder = ".",
        [Parameter(Mandatory = $true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory = $true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory = $true)][hashtable]$AllCaps,
        [Parameter(Mandatory = $true)][String[]]$StartTimestamp,
        [Parameter(Mandatory = $false)][switch]$Csv = $false
    )

    function Parse-ISO8601Duration {
        param (
            [string]$DurationString,
            [ValidateSet('Hours', 'Days')]
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

        $days = if ($match.Groups['Days'].Success) { [int]$match.Groups['Days'].Value } else { 0 }
        $hours = if ($match.Groups['Hours'].Success) { [int]$match.Groups['Hours'].Value } else { 0 }
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
                $result.Unit = 'Days'
            }
            'Hours' {
                $result.Value = [math]::Round($timeSpan.TotalHours, 2)
                $result.Unit = 'Hours'
            }
        }

        return $result
    }

    function Get-PolicyAssignmentCountMap {
        param(
            [array]$EligibleAssignments
        )

        $countMap = @{}

        foreach ($assignment in @($EligibleAssignments)) {
            if (-not $assignment) { continue }
            $groupId = [string]$assignment.groupId
            $accessId = [string]$assignment.accessId
            if ([string]::IsNullOrWhiteSpace($groupId) -or [string]::IsNullOrWhiteSpace($accessId)) { continue }
            $lookupKey = "$groupId|$($accessId.ToLowerInvariant())"
            if (-not $countMap.ContainsKey($lookupKey)) {
                $countMap[$lookupKey] = [ordered]@{
                    Eligible = 0
                }
            }
            $countMap[$lookupKey].Eligible++
        }

        return $countMap
    }

    function Get-ObjectIntPropertyValue {
        param(
            $Object,
            [string]$PropertyName
        )

        if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) {
            return 0
        }

        $property = $Object.PSObject.Properties[$PropertyName]
        if ($null -eq $property -or $null -eq $property.Value) {
            return 0
        }

        return [int]$property.Value
    }

    function Test-ObjectPropertyExists {
        param(
            $Object,
            [string]$PropertyName
        )

        if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) {
            return $false
        }

        return $null -ne $Object.PSObject.Properties[$PropertyName]
    }

    function Test-DictionaryContainsKey {
        param(
            [System.Collections.IDictionary]$Dictionary,
            $Key
        )

        if ($null -eq $Dictionary -or $null -eq $Key) {
            return $false
        }

        if ($Key -is [string] -and [string]::IsNullOrWhiteSpace($Key)) {
            return $false
        }

        return $Dictionary.Contains($Key)
    }

    function Get-ActiveAssignmentCount {
        param(
            $GroupDetails,
            [string]$RoleDefinitionId
        )

        if ($null -eq $GroupDetails -or [string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
            return 0
        }

        switch ($RoleDefinitionId.ToLowerInvariant()) {
            'owner' {
                if (Test-ObjectPropertyExists -Object $GroupDetails -PropertyName 'DirectActiveOwners') {
                    return (Get-ObjectIntPropertyValue -Object $GroupDetails -PropertyName 'DirectActiveOwners')
                }

                return 0
            }
            'member' {
                return (Get-ObjectIntPropertyValue -Object $GroupDetails -PropertyName 'DirectActiveMembers')
            }
            default {
                return 0
            }
        }
    }

    function Get-ContainerValue {
        param(
            $Container,
            [string]$Name
        )

        if ($null -eq $Container -or [string]::IsNullOrWhiteSpace($Name)) {
            return $null
        }

        if ($Container -is [System.Collections.IDictionary]) {
            if ($Container.Contains($Name)) {
                return $Container[$Name]
            }
            return $null
        }

        $property = $Container.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return $property.Value
        }

        return $null
    }

    function Get-TierSortRank {
        param(
            [string]$Tier
        )

        $normalizedTier = [string]$Tier
        if ([string]::IsNullOrWhiteSpace($normalizedTier)) {
            return 9
        }

        switch ($normalizedTier.Trim()) {
            'Tier-0' { return 0 }
            'Tier-1' { return 1 }
            'Tier-2' { return 2 }
            'Tier-3' { return 3 }
            '?'      { return 8 }
            default  { return 9 }
        }
    }

    function Get-RoleSortRank {
        param(
            [string]$Role
        )

        switch ([string]$Role) {
            'Owner'  { return 0 }
            'Member' { return 1 }
            default  { return 9 }
        }
    }

    function Get-WarningTierLabel {
        param(
            [string]$Tier
        )

        $normalizedTier = [string]$Tier
        if ([string]::IsNullOrWhiteSpace($normalizedTier)) {
            return ""
        }

        switch ($normalizedTier.Trim()) {
            'Tier-0' { return 'Tier-0' }
            'Tier-1' { return 'Tier-1' }
            'Tier-2' { return 'Tier-2' }
            'Tier-3' { return 'Tier-3' }
            '?'      { return '?' }
            default  { return '' }
        }
    }

    function Get-EffectiveWarningTier {
        param(
            [string]$EntraTier,
            [string]$AzureTier
        )

        $candidateTiers = @($EntraTier, $AzureTier) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        if (@($candidateTiers).Count -eq 0) {
            return ''
        }

        return ($candidateTiers | Sort-Object { Get-TierSortRank -Tier $_ } | Select-Object -First 1)
    }

    if (-not $GLOBALPimForGroupsChecked) {
        return @{}
    }

    $PimEnabledGroups = @($global:GLOBALPimForGroupsResources)
    if ($PimEnabledGroups.Count -eq 0) {
        return @{}
    }

    $EligibleAssignments = @()
    if ($global:GLOBALPimForGroupsAssignmentObjects) {
        $EligibleAssignments = @($global:GLOBALPimForGroupsAssignmentObjects)
    }

    $AllPIMGroupDetails = [System.Collections.Generic.List[object]]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $Title = "PIM_Groups"

    $BatchMaxSize = 8
    $BatchDelaySeconds = 1

    Write-Host "[*] Get PIM for Groups settings"
    Write-Host "[i] This step can be slow in larger tenants because these policy queries are sent more slowly to avoid throttling."
    Write-Log -Level Verbose -Message "Enumerating settings for $($PimEnabledGroups.Count) PIM-enabled groups"
    Write-Log -Level Debug -Message "Found $($EligibleAssignments.Count) eligible assignments for count enrichment"

    $Requests = [System.Collections.Generic.List[hashtable]]::new()
    $RequestContext = @{}
    $RequestId = 0
    foreach ($group in $PimEnabledGroups) {
        foreach ($roleDefinitionId in @('member', 'owner')) {
            $RequestId++
            $requestKey = [string]$RequestId
            $Requests.Add(@{
                id = $requestKey
                method = 'GET'
                url = '/policies/roleManagementPolicyAssignments'
                queryParameters = @{
                    '$filter' = "scopeId eq '$($group.Id)' and scopeType eq 'Group' and roleDefinitionId eq '$roleDefinitionId'"
                    '$expand' = 'policy($expand=rules)'
                }
            })
            $RequestContext[$requestKey] = [pscustomobject]@{
                GroupId = [string]$group.Id
                GroupDisplayName = [string]$group.displayName
                RoleDefinitionId = [string]$roleDefinitionId
            }
        }
    }

    Write-Host "[*] Query PIM for Groups policy assignments for $($PimEnabledGroups.Count) groups ($($Requests.Count) role requests)"
    Write-Log -Level Verbose -Message "Sending $($Requests.Count) role policy requests via Graph batch (MaxBatchSize=$BatchMaxSize, BatchDelay=${BatchDelaySeconds}s)"
    $PolicyQueryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $PolicyAssignmentsRaw = @(Send-GraphBatchRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Requests $Requests -MaxBatchSize $BatchMaxSize -BatchDelay $BatchDelaySeconds -UserAgent $($GlobalAuditSummary.UserAgent.Name) -DisablePagination)
    $PolicyQueryStopwatch.Stop()
    Write-Log -Level Verbose -Message "Got $($PolicyAssignmentsRaw.Count) policy assignment responses in $([math]::Round($PolicyQueryStopwatch.Elapsed.TotalSeconds, 2))s"

    $AssignmentCounts = Get-PolicyAssignmentCountMap -EligibleAssignments $EligibleAssignments
    Write-Log -Level Debug -Message "Built assignment count map for $($AssignmentCounts.Count) group/role combinations"

    $PolicyQueryErrorCount = 0
    $MissingPolicyAssignmentCount = 0
    $MultiPolicyAssignmentCount = 0

    foreach ($response in $PolicyAssignmentsRaw) {
        $responseId = [string](Get-ContainerValue -Container $response -Name 'id')
        $context = $RequestContext[$responseId]
        if (-not $context) { continue }

        $warningMessages = [System.Collections.Generic.List[string]]::new()
        $groupId = $context.GroupId
        $groupDisplayName = $context.GroupDisplayName
        $groupDetails = if (Test-DictionaryContainsKey -Dictionary $AllGroupsDetails -Key $groupId) { $AllGroupsDetails[$groupId] } else { $null }
        $roleDefinitionId = $context.RoleDefinitionId
        $roleLabel = (Get-Culture).TextInfo.ToTitleCase($roleDefinitionId)
        $entraMaxTier = if ($groupDetails) { [string]$groupDetails.EntraMaxTier } else { '' }
        $azureMaxTier = if ($groupDetails) { [string]$groupDetails.AzureMaxTier } else { '' }
        $effectiveWarningTier = Get-EffectiveWarningTier -EntraTier $entraMaxTier -AzureTier $azureMaxTier
        $warningTier = Get-WarningTierLabel -Tier $effectiveWarningTier
        $countKey = "$groupId|$roleDefinitionId"
        $countEntry = if (Test-DictionaryContainsKey -Dictionary $AssignmentCounts -Key $countKey) { $AssignmentCounts[$countKey] } else { $null }

        $eligibleCount = if ($countEntry) { [int]$countEntry.Eligible } else { 0 }
        $activeCount = Get-ActiveAssignmentCount -GroupDetails $groupDetails -RoleDefinitionId $roleDefinitionId

        $policyAssignments = @()
        $responseBody = Get-ContainerValue -Container $response -Name 'response'
        $responseValue = Get-ContainerValue -Container $responseBody -Name 'value'
        if ($null -ne $responseValue) {
            $policyAssignments = @($responseValue)
        }

        $responseStatus = Get-ContainerValue -Container $response -Name 'status'
        $responseErrorCode = Get-ContainerValue -Container $response -Name 'errorCode'
        $responseErrorMessage = Get-ContainerValue -Container $response -Name 'errorMessage'
        if ($null -ne $responseStatus -and [int]$responseStatus -ne 200) {
            $PolicyQueryErrorCount++
            $warningMessages.Add(("Policy query failed with status {0}: {1} {2}" -f $responseStatus, $responseErrorCode, $responseErrorMessage).Trim())
        }

        if ($policyAssignments.Count -eq 0) {
            $MissingPolicyAssignmentCount++
            $warningMessages.Add("No policy assignment returned for role '$roleDefinitionId'")
        } elseif ($policyAssignments.Count -gt 1) {
            $MultiPolicyAssignmentCount++
            $warningMessages.Add("Multiple policy assignments returned for role '$roleDefinitionId'")
        }

        $policyAssignment = if ($policyAssignments.Count -ge 1) { $policyAssignments[0] } else { $null }
        $policyId = if ($policyAssignment) { [string]$policyAssignment.policyId } else { $null }
        $policyLastModifiedDateTime = if ($policyAssignment -and $policyAssignment.policy) { [string]$policyAssignment.policy.lastModifiedDateTime } else { $null }
        $policyLastModifiedBy = if ($policyAssignment -and $policyAssignment.policy -and $policyAssignment.policy.lastModifiedBy) { [string]$policyAssignment.policy.lastModifiedBy.displayName } else { $null }
        $policyRules = if ($policyAssignment -and $policyAssignment.policy -and $policyAssignment.policy.rules) { @($policyAssignment.policy.rules) } else { @() }

        $ruleMap = @{}
        foreach ($rule in $policyRules) {
            if ($null -ne $rule.id) {
                $ruleMap[[string]$rule.id] = $rule
            }
        }

        $hasEndUserEnablementRule = $ruleMap.ContainsKey('Enablement_EndUser_Assignment')
        $enabledRules = if ($hasEndUserEnablementRule) { @($ruleMap['Enablement_EndUser_Assignment'].enabledRules) } else { @() }
        $mfaEnabled = if ($hasEndUserEnablementRule) { $enabledRules -contains 'MultiFactorAuthentication' } else { $null }
        $justificationEnabled = if ($hasEndUserEnablementRule) { $enabledRules -contains 'Justification' } else { $null }
        $ticketingEnabled = if ($hasEndUserEnablementRule) { $enabledRules -contains 'Ticketing' } else { $null }

        $authCtxEnabled = $null
        $authCtxUsable = $false
        $claimValue = $null
        if ($ruleMap.ContainsKey('AuthenticationContext_EndUser_Assignment')) {
            $authCtxEnabled = $ruleMap['AuthenticationContext_EndUser_Assignment'].isEnabled -eq $true
            $claimValue = $ruleMap['AuthenticationContext_EndUser_Assignment'].claimValue
            $authCtxUsable = ($authCtxEnabled -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$claimValue))
        }

        $parsedActivationDuration = [PSCustomObject]@{ Value = $null; Unit = $null }
        if ($ruleMap.ContainsKey('Expiration_EndUser_Assignment')) {
            $parsedActivationDuration = Parse-ISO8601Duration -DurationString $ruleMap['Expiration_EndUser_Assignment'].maximumDuration -ReturnUnit 'Hours'
        }

        $adminEligibilityEnabled = $null
        $parsedAdminEligibilityDurationValue = $null
        $parsedAdminEligibilityDurationUnit = $null
        if ($ruleMap.ContainsKey('Expiration_Admin_Eligibility')) {
            $adminEligibilityRule = $ruleMap['Expiration_Admin_Eligibility']
            $adminEligibilityEnabled = $adminEligibilityRule.isExpirationRequired -eq $true
            if ($adminEligibilityEnabled) {
                $parsedAdminEligibilityDuration = Parse-ISO8601Duration -DurationString $adminEligibilityRule.maximumDuration -ReturnUnit 'Days'
                $parsedAdminEligibilityDurationValue = $parsedAdminEligibilityDuration.Value
                $parsedAdminEligibilityDurationUnit = $parsedAdminEligibilityDuration.Unit
            }
        }

        $adminAssignmentEnabled = $null
        $parsedAdminAssignmentDurationValue = $null
        $parsedAdminAssignmentDurationUnit = $null
        if ($ruleMap.ContainsKey('Expiration_Admin_Assignment')) {
            $adminAssignmentRule = $ruleMap['Expiration_Admin_Assignment']
            $adminAssignmentEnabled = $adminAssignmentRule.isExpirationRequired -eq $true
            if ($adminAssignmentEnabled) {
                $parsedAdminAssignmentDuration = Parse-ISO8601Duration -DurationString $adminAssignmentRule.maximumDuration -ReturnUnit 'Days'
                $parsedAdminAssignmentDurationValue = $parsedAdminAssignmentDuration.Value
                $parsedAdminAssignmentDurationUnit = $parsedAdminAssignmentDuration.Unit
            }
        }

        $adminAssignmentEnabledRules = if ($ruleMap.ContainsKey('Enablement_Admin_Assignment')) { @($ruleMap['Enablement_Admin_Assignment'].enabledRules) } else { @() }
        $adminMfaEnabled = if ($ruleMap.ContainsKey('Enablement_Admin_Assignment')) { $adminAssignmentEnabledRules -contains 'MultiFactorAuthentication' } else { $null }
        $adminJustificationEnabled = if ($ruleMap.ContainsKey('Enablement_Admin_Assignment')) { $adminAssignmentEnabledRules -contains 'Justification' } else { $null }

        $approvalRequired = $null
        $approverObjects = @()
        if ($ruleMap.ContainsKey('Approval_EndUser_Assignment')) {
            $approvalRule = $ruleMap['Approval_EndUser_Assignment']
            $approvalSetting = $approvalRule.setting
            $approvalRequired = $approvalSetting.isApprovalRequired -eq $true

            if ($approvalRequired -and $approvalSetting.approvalStages) {
                foreach ($stage in $approvalSetting.approvalStages) {
                    foreach ($approver in @($stage.primaryApprovers)) {
                        $type = 'Unknown'
                        $memberCount = '-'
                        $approverId = $null

                        if ($approver.'@odata.type' -match 'groupMembers') {
                            $type = 'Group'
                            $approverId = [string]$approver.groupId
                            if (Test-DictionaryContainsKey -Dictionary $AllGroupsDetails -Key $approverId) {
                                $memberCount = $AllGroupsDetails[$approverId].Users
                            }
                        } elseif ($approver.'@odata.type' -match 'singleUser') {
                            $type = 'User'
                            $approverId = [string]$approver.userId
                        }

                        $approverObjects += [PSCustomObject]@{
                            Type = $type
                            Id = $approverId
                            Description = $approver.description
                            Members = $memberCount
                        }
                    }
                }
            }
        }

        $notifyAssignmentEligible = $null
        if ($ruleMap.ContainsKey('Notification_Admin_Admin_Eligibility')) {
            $notifRule = $ruleMap['Notification_Admin_Admin_Eligibility']
            $notifyAssignmentEligible = (($notifRule.isDefaultRecipientsEnabled -eq $true) -or @($notifRule.notificationRecipients).Count -gt 0)
        }

        $notifyAssignmentActive = $null
        if ($ruleMap.ContainsKey('Notification_Admin_Admin_Assignment')) {
            $notifRule = $ruleMap['Notification_Admin_Admin_Assignment']
            $notifyAssignmentActive = (($notifRule.isDefaultRecipientsEnabled -eq $true) -or @($notifRule.notificationRecipients).Count -gt 0)
        }

        $notifyActivation = $null
        if ($ruleMap.ContainsKey('Notification_Admin_EndUser_Assignment')) {
            $notifRule = $ruleMap['Notification_Admin_EndUser_Assignment']
            $notifyActivation = (($notifRule.isDefaultRecipientsEnabled -eq $true) -or @($notifRule.notificationRecipients).Count -gt 0)
        }

        $linkedCaps = @()
        $authContextIssues = [System.Collections.Generic.List[string]]::new()
        if ($authCtxEnabled -eq $true -and -not $authCtxUsable) {
            $warningMessages.Add('AuthContext enabled but claimValue missing')
        }
        if ($authCtxUsable) {
            $linkedCaps = @(
                $AllCaps.values | Where-Object { $_.AuthContextId -contains $claimValue } | ForEach-Object {
                    $policy = $_
                    $issues = [System.Collections.Generic.List[string]]::new()

                    if ($policy.SignInFrequencyInterval -ne 'EveryTime' -or -not $policy.SignInFrequency) { $issues.Add("sign-in frequency is not 'EveryTime'") }
                    if ($policy.State -ne 'enabled') { $issues.Add('policy is not enabled') }
                    if ($policy.IncUsers -ne 'All') { $issues.Add('does not target all users') }
                    if ($policy.ExcUsers -gt 0) { $issues.Add('excludes users') }
                    if ($policy.ExcGroups -gt 0) { $issues.Add('excludes groups') }
                    if ($policy.ExcRoles -gt 0) { $issues.Add('excludes roles') }
                    if ($policy.AppTypes -ne 'all') {
                        $appTypeCount = ($policy.AppTypes -split ',' | ForEach-Object { $_.Trim() }).Count
                        if ($appTypeCount -lt 4) {
                            $issues.Add('targets specific app types')
                        }
                    }

                    $grantControlsStr = ($policy.GrantControls -join ' ')
                    $hasMfa = $grantControlsStr -match '\bmfa\b'
                    $hasAuthStrength = -not [string]::IsNullOrWhiteSpace([string]$policy.AuthStrength)
                    if (-not $hasMfa -and -not $hasAuthStrength) {
                        $issues.Add('Neither MFA in GrantControls nor AuthStrength is configured')
                    }

                    if ($issues.Count -gt 0) {
                        $authContextIssues.Add("CAP '$($policy.DisplayName)' (AuthContext:$($policy.AuthContextId -join ', ')): $($issues -join ' / ')")
                    }

                    [pscustomobject]@{
                        Id = $policy.Id
                        DisplayName = $policy.DisplayName
                        AuthContextId = $policy.AuthContextId
                        Issues = if ($issues.Count -gt 0) { @($issues) } else { '-' }
                    }
                }
            )

            if (@($linkedCaps).Count -eq 0) {
                $warningMessages.Add("AuthContext ($claimValue) not linked to a CAP")
            }
        }

        if ($parsedActivationDuration.Unit -eq 'Hours') {
            if ($warningTier -eq 'Tier-0') {
                if ($parsedActivationDuration.Value -gt 4) {
                    $warningMessages.Add('long activation time (>4h)')
                }
            } else {
                if ($parsedActivationDuration.Value -gt 12) {
                    $warningMessages.Add('long activation time (>12h)')
                }
            }
        }
        $isHighImpactWarningTier = $warningTier -in @('Tier-0', 'Tier-1')

        if ($isHighImpactWarningTier -and $adminAssignmentEnabled -eq $false) {
            $warningMessages.Add('allows perm. active assignments')
        }
        if ($isHighImpactWarningTier -and -not $authCtxUsable -and $approvalRequired -ne $true -and $policyAssignment) {
            $warningMessages.Add('missing AuthContext or Approval')
        } elseif ($authCtxUsable -and $authContextIssues.Count -gt 0) {
            $warningMessages.AddRange($authContextIssues)
        }

        $warningTierReporting = if ($warningTier -eq 'Tier-0' -or $warningTier -eq 'Tier-1') {
            "$warningTier but "
        } else {
            ""
        }

        $warningsText = if ($warningMessages.Count -gt 0) {
            $warningTierReporting + (($warningMessages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ', ')
        } else {
            ""
        }
        $detailId = if ($policyId) { $policyId } else { "Group_$groupId`_$roleDefinitionId" }
        $groupLink = "<a href=#$detailId>$groupDisplayName</a>"
        $groupReportLink = "<a href=`"Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$groupId`">$groupDisplayName</a>"

        $PIMGroupRuleDetails = [PSCustomObject]@{
            Id                        = $detailId
            GroupId                   = $groupId
            Group                     = $groupDisplayName
            GroupLink                 = $groupLink
            GroupReportLink           = $groupReportLink
            Role                      = $roleLabel
            EntraMaxTier              = $entraMaxTier
            AzureMaxTier              = $azureMaxTier
            RoleDefinitionId          = $roleDefinitionId
            PolicyId                  = $policyId
            PolicyLastModifiedDateTime = $policyLastModifiedDateTime
            PolicyLastModifiedBy      = $policyLastModifiedBy
            Eligible                  = $eligibleCount
            Active                    = $activeCount
            ActivationMFA             = $mfaEnabled
            ActivationJustification   = $justificationEnabled
            ActivationTicketing       = $ticketingEnabled
            ActivationAuthContext     = $authCtxEnabled
            ActivationAuthContextId   = $claimValue
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
            ActiveAssignMFA           = $adminMfaEnabled
            ActiveAssignJustification = $adminJustificationEnabled
            AlertAssignEligible       = $notifyAssignmentEligible
            AlertAssignActive         = $notifyAssignmentActive
            AlertActivation           = $notifyActivation
            LinkedCaps                = @($linkedCaps).Count
            LinkedCapsDetails         = $linkedCaps
            Warnings                  = $warningsText
        }

        [void]$AllPIMGroupDetails.Add($PIMGroupRuleDetails)
    }

    Write-Log -Level Debug -Message "Built $($AllPIMGroupDetails.Count) report rows"
    Write-Log -Level Debug -Message "Policy query issues - non-200 responses=$PolicyQueryErrorCount, missing policy assignments=$MissingPolicyAssignmentCount, multiple policy assignments=$MultiPolicyAssignmentCount"

    $AllPIMGroupDetails = $AllPIMGroupDetails | Sort-Object `
        @{ Expression = { Get-TierSortRank -Tier $_.EntraMaxTier } ; Ascending = $true }, `
        @{ Expression = { Get-TierSortRank -Tier $_.AzureMaxTier } ; Ascending = $true }, `
        Group, `
        @{ Expression = { Get-RoleSortRank -Role $_.Role } ; Ascending = $true }, `
        Role

    $tableOutput = $AllPIMGroupDetails | Select-Object Group, GroupLink, EntraMaxTier, AzureMaxTier, Role, Eligible, Active, ActivationAuthContext, ActivationMFA, ActivationJustification, ActivationTicketing, ActivationDuration, ActivationApproval, EligibleExpiration, EligibleExpirationTime, ActiveExpiration, ActiveExpirationTime, ActiveAssignMFA, ActiveAssignJustification, AlertAssignEligible, AlertAssignActive, AlertActivation, Warnings
    $mainTable = $tableOutput | Select-Object -Property @{Name = 'Group'; Expression = { $_.GroupLink } }, Role, EntraMaxTier, AzureMaxTier, Eligible, Active, ActivationAuthContext, ActivationMFA, ActivationJustification, ActivationTicketing, ActivationDuration, ActivationApproval, EligibleExpiration, EligibleExpirationTime, ActiveExpiration, ActiveExpirationTime, ActiveAssignMFA, ActiveAssignJustification, AlertAssignEligible, AlertAssignActive, AlertActivation, Warnings
    $mainTableJson = $mainTable | ConvertTo-Json -Depth 5 -Compress
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'

    $DetailTxtBuilder = [System.Text.StringBuilder]::new()
    foreach ($item in $AllPIMGroupDetails) {
        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        $headerInfo = [pscustomobject]@{
            "Group" = $item.Group
            "Entra Max Tier" = $item.EntraMaxTier
            "Azure Max Tier" = $item.AzureMaxTier
            "Role" = $item.Role
            "Eligible Assignments" = $item.Eligible
            "Active Assignments" = $item.Active
        }
        if (-not [string]::IsNullOrWhiteSpace($item.Warnings)) {
            $headerInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }
        [void]$DetailTxtBuilder.AppendLine(($headerInfo | Format-List | Out-String))

        $activationSettings = [pscustomobject]@{
            "Activation Max Duration" = if ($null -ne $item.ActivationDuration) { "$($item.ActivationDuration) $($item.ActivationDurationUnit)" } else { '' }
            "Justification Required" = $item.ActivationJustification
            "Ticket Info Required" = $item.ActivationTicketing
            "MFA Claim Required" = $item.ActivationMFA
            "Auth Context Required" = $item.ActivationAuthContext
            "Auth Context ID" = $item.ActivationAuthContextId
            "Approver Required" = $item.ActivationApproval
        }
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Activation Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($activationSettings | Format-Table | Out-String))

        $approvers = @()
        if ($item.ActivationApproval -eq $true) {
            if (@($item.ActivationApprovers).Count -ge 1) {
                $approversRaw = foreach ($object in @($item.ActivationApprovers)) {
                    $displayNameLink = switch ($object.Type) {
                        'Group' {
                            if ([string]::IsNullOrWhiteSpace([string]$object.Id)) { $object.Description } else { "<a href=Groups_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)>$($object.Description)</a>" }
                        }
                        'User' {
                            if ([string]::IsNullOrWhiteSpace([string]$object.Id)) { $object.Description } else { "<a href=Users_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.Id)>$($object.Description)</a>" }
                        }
                        default { $object.Description }
                    }
                    [pscustomobject]@{
                        Type = $object.Type
                        DisplayNameLink = $displayNameLink
                        DisplayName = $object.Description
                        Members = $object.Members
                    }
                }
            } else {
                $approversRaw = [pscustomobject]@{
                    Type = '-'
                    DisplayNameLink = 'No approvers configured. Defaulting to Privileged Role Administrators or Global Administrators.'
                    DisplayName = 'No approvers configured. Defaulting to Privileged Role Administrators or Global Administrators.'
                    Members = '-'
                }
            }

            [void]$DetailTxtBuilder.AppendLine("Activation Approvers")
            [void]$DetailTxtBuilder.AppendLine("--------------------")
            [void]$DetailTxtBuilder.AppendLine(($approversRaw | Format-Table -Property Type, DisplayName, Members | Out-String))
            $approvers = foreach ($obj in @($approversRaw)) {
                [pscustomobject]@{
                    Type = $obj.Type
                    DisplayName = $obj.DisplayNameLink
                    Members = $obj.Members
                }
            }
        }

        $linkedCaps = @()
        if ($item.LinkedCaps -ge 1) {
            $linkedCapsRaw = foreach ($object in @($item.LinkedCapsDetails)) {
                [pscustomobject]@{
                    DisplayNameLink = "<a href=ConditionalAccessPolicies_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayNameEncoded).html#$($object.id)>$($object.DisplayName)</a>"
                    DisplayName = $object.DisplayName
                    AuthContextId = ($object.AuthContextId -join ', ')
                    Issues = ($object.Issues -join ', ')
                }
            }
            [void]$DetailTxtBuilder.AppendLine("Linked CAPs (Auth Context)")
            [void]$DetailTxtBuilder.AppendLine("--------------------------")
            [void]$DetailTxtBuilder.AppendLine(($linkedCapsRaw | Format-Table -Property DisplayName, AuthContextId, Issues | Out-String))
            $linkedCaps = foreach ($obj in $linkedCapsRaw) {
                [pscustomobject]@{
                    DisplayName = $obj.DisplayNameLink
                    AuthContextId = $obj.AuthContextId
                    Issues = $obj.Issues
                }
            }
        }

        $assignmentSettings = [pscustomobject]@{
            "Allow Permanent Eligible Assignment" = if ($null -ne $item.EligibleExpiration) { -not $item.EligibleExpiration } else { $null }
            "Expire Eligible Assignments After" = if ($item.EligibleExpiration -and $null -ne $item.EligibleExpirationTime -and -not [string]::IsNullOrWhiteSpace([string]$item.EligibleExpirationUnit)) { "$($item.EligibleExpirationTime) $($item.EligibleExpirationUnit)" } else { '-' }
            "Allow Permanent Active Assignment" = if ($null -ne $item.ActiveExpiration) { -not $item.ActiveExpiration } else { $null }
            "Expire Active Assignments After" = if ($item.ActiveExpiration -and $null -ne $item.ActiveExpirationTime -and -not [string]::IsNullOrWhiteSpace([string]$item.ActiveExpirationUnit)) { "$($item.ActiveExpirationTime) $($item.ActiveExpirationUnit)" } else { '-' }
            "MFA Claim Required" = $item.ActiveAssignMFA
            "Justification Required" = $item.ActiveAssignJustification
        }
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Assignment Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($assignmentSettings | Format-Table | Out-String))

        $notificationSettings = [pscustomobject]@{
            "Alert On Eligible Assignment" = $item.AlertAssignEligible
            "Alert On Permanent Assignments" = $item.AlertAssignActive
            "Alert On Role Activation" = $item.AlertActivation
        }
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine("Notification Settings")
        [void]$DetailTxtBuilder.AppendLine("================================================================================================")
        [void]$DetailTxtBuilder.AppendLine(($notificationSettings | Format-Table | Out-String))

        $generalInformation = [pscustomobject]@{
            Group = $item.GroupReportLink
            "Entra Max Tier" = $item.EntraMaxTier
            "Azure Max Tier" = $item.AzureMaxTier
            Role = $item.Role
            "Last Modified" = if ([string]::IsNullOrWhiteSpace([string]$item.PolicyLastModifiedDateTime)) { '-' } else { $item.PolicyLastModifiedDateTime }
            "Last Modified By" = if ([string]::IsNullOrWhiteSpace([string]$item.PolicyLastModifiedBy)) { '-' } else { $item.PolicyLastModifiedBy }
            "Eligible Assignments" = $item.Eligible
            "Active Assignments" = $item.Active
        }
        if (-not [string]::IsNullOrWhiteSpace($item.Warnings)) {
            $generalInformation | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        [void]$AllObjectDetailsHTML.Add([pscustomobject]@{
            "Object Name" = "$($item.Group) ($($item.Role))"
            "Object ID" = $item.Id
            "General Information" = $generalInformation
            "Activation Settings" = $activationSettings
            "Activation Approvers" = $approvers
            "Linked CAPs (AuthContext)" = $linkedCaps
            "Assignment Settings" = $assignmentSettings
            "Notification Settings" = $notificationSettings
        })
    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()

    Write-Host "[*] Writing Reports"
    Write-Host ""

    $headerTXT = "************************************************************************************************************************
$($Title -replace '_', ' ') Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = This report includes only PIM settings for PIM-enabled groups.
************************************************************************************************************************
"

    $AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 6 -Compress

    $ObjectsDetailsHEAD = @'
    <h2>PIM Policies Details</h2>
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

    $headerTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    $tableOutput | Format-Table Group, EntraMaxTier, AzureMaxTier, Role, Eligible, Active, ActivationAuthContext, ActivationMFA, ActivationJustification, ActivationTicketing, ActivationDuration, ActivationApproval, EligibleExpiration, EligibleExpirationTime, ActiveExpiration, ActiveExpirationTime, ActiveAssignMFA, ActiveAssignJustification, AlertAssignEligible, AlertAssignActive, AlertActivation, Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append
    if ($Csv) {
        $tableOutput | Select-Object Group, EntraMaxTier, AzureMaxTier, Role, Eligible, Active, ActivationAuthContext, ActivationMFA, ActivationJustification, ActivationTicketing, ActivationDuration, ActivationApproval, EligibleExpiration, EligibleExpirationTime, ActiveExpiration, ActiveExpirationTime, ActiveAssignMFA, ActiveAssignJustification, AlertAssignEligible, AlertAssignActive, AlertActivation, Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).csv" -NoTypeInformation
    }
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).txt" -Append

    Set-GlobalReportManifest -CurrentReportKey 'PIMGroups' -CurrentReportName 'PIM (Groups) Enumeration (BETA)'

    $headerHtml = @"
<div id="loadingOverlay">
  <div class="spinner"></div>
  <div class="loading-text">Loading data...</div>
</div>
<h2>PIM (Groups) Overview</h2>
"@

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixDynamicHTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Head ("<title>EF - PIM (Groups)</title>`n" + $global:GLOBALReportManifestScript + $global:GLOBALCss) -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.FileSafeDisplayName).html"

    $PimGroupsHT = @{}
    foreach ($PimGroup in $AllPIMGroupDetails) {
        $PimGroupsHT["$($PimGroup.GroupId)|$($PimGroup.RoleDefinitionId)"] = $PimGroup
    }

    return $PimGroupsHT
}
