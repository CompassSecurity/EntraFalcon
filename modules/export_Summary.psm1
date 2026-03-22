<#
.SYNOPSIS
   Generate a summary about the enumerated objects in the tenant.

#>
function Export-Summary {
    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Function section ########################
    function New-ChartSection {
        param (
            [string]$Title,
            [string]$Prefix,
            [int]$ChartCount
        )
        $charts = ""
        for ($i = 1; $i -le $ChartCount; $i++) {
            $charts += "<div class='chart-box'><canvas id='${Prefix}_chart$i'></canvas></div>`n"
        }

return @"
<section class='summary-chart-panel'>
    <div class='summary-chart-panel-header'>
        <h2>$Title</h2>
        <div class='summary-chart-panel-meta'>$ChartCount charts</div>
    </div>
    <div class='chart-grid'>
        $charts
    </div>
</section>
"@
    }

    function New-KpiSection {
        param (
            $Items
        )

        $cards = ""
        foreach ($entry in $Items.GetEnumerator()) {
            $cards += @"
<div class='summary-kpi-card'>
    <div class='summary-kpi-label'>$($entry.Key)</div>
    <div class='summary-kpi-value'>$($entry.Value)</div>
</div>
"@
        }

return @"
<section class='summary-kpi-panel'>
    <div class='summary-kpi-panel-header'>
        <h2>Enumeration Summary</h2>
        <div class='summary-chart-panel-meta'>$($Items.Count) categories</div>
    </div>
    <div class='summary-kpi-grid'>
        $cards
    </div>
</section>
"@
    }

    function ConvertTo-SummaryHtmlText {
        param($Value)
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    function New-GeneralField {
        param(
            [string]$Label,
            [string]$ValueHtml
        )

return @"
<div class='summary-info-row'>
    <div class='summary-info-label'>$(ConvertTo-SummaryHtmlText $Label)</div>
    <div class='summary-info-value'>$ValueHtml</div>
</div>
"@
    }

    function New-GeneralStatusBadge {
        param(
            [string]$Text,
            [string]$Tone = "neutral"
        )

        $safeText = ConvertTo-SummaryHtmlText $Text
        return "<span class='summary-status-badge tone-$Tone'>$safeText</span>"
    }

    function New-GeneralCard {
        param(
            [string]$Title,
            [string[]]$Rows
        )

        $rowsHtml = @($Rows) -join "`n"
return @"
<section class='summary-info-card'>
    <h3>$(ConvertTo-SummaryHtmlText $Title)</h3>
    <div class='summary-info-list'>
        $rowsHtml
    </div>
</section>
"@
    }

    function Get-DurationDisplay {
        param(
            [string]$Start,
            [string]$End
        )

        if ([string]::IsNullOrWhiteSpace($Start) -or [string]::IsNullOrWhiteSpace($End)) { return "Unknown" }

        try {
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            $styles = [System.Globalization.DateTimeStyles]::AssumeLocal
            $startTime = [datetime]::ParseExact($Start, "yyyyMMdd HH:mm", $culture, $styles)
            $endTime = [datetime]::ParseExact($End, "yyyyMMdd HH:mm", $culture, $styles)
            $duration = $endTime - $startTime
            if ($duration.TotalMinutes -lt 0) { return "Unknown" }

            if ($duration.TotalMinutes -lt 60) {
                return "{0} min" -f [int][math]::Round($duration.TotalMinutes)
            }

            $parts = @()
            if ($duration.Days -gt 0) { $parts += "{0}d" -f $duration.Days }
            if ($duration.Hours -gt 0) { $parts += "{0}h" -f $duration.Hours }
            if ($duration.Minutes -gt 0 -or $parts.Count -eq 0) { $parts += "{0}m" -f $duration.Minutes }
            return ($parts -join " ")
        } catch {
            return "Unknown"
        }
    }

    function New-GeneralSection {
        param(
            [string]$TenantName,
            [string]$TenantId,
            [string]$TenantLicense,
            [string]$Subscriptions,
            [string]$StartTime,
            [string]$EndTime,
            [string]$Duration,
            [string]$EntraFalconVersion,
            [string]$PowerShellVersion,
            [string]$UserAgent,
            [string]$AzureIamBadge,
            [string]$PimRolesBadge,
            [string]$PimGroupsBadge,
            [string]$DefaultMsSpBadge
        )

        $tenantRows = @(
            (New-GeneralField -Label "Tenant Name" -ValueHtml (ConvertTo-SummaryHtmlText $TenantName)),
            (New-GeneralField -Label "Tenant ID" -ValueHtml (ConvertTo-SummaryHtmlText $TenantId)),
            (New-GeneralField -Label "License" -ValueHtml (ConvertTo-SummaryHtmlText $TenantLicense)),
            (New-GeneralField -Label "Subscriptions" -ValueHtml (ConvertTo-SummaryHtmlText $Subscriptions))
        )

        $executionRows = @(
            (New-GeneralField -Label "Start Time" -ValueHtml (ConvertTo-SummaryHtmlText $StartTime)),
            (New-GeneralField -Label "End Time" -ValueHtml (ConvertTo-SummaryHtmlText $EndTime)),
            (New-GeneralField -Label "Duration" -ValueHtml (ConvertTo-SummaryHtmlText $Duration)),
            (New-GeneralField -Label "EntraFalcon Version" -ValueHtml (ConvertTo-SummaryHtmlText $EntraFalconVersion)),
            (New-GeneralField -Label "PowerShell Version" -ValueHtml (ConvertTo-SummaryHtmlText $PowerShellVersion)),
            (New-GeneralField -Label "UserAgent" -ValueHtml (ConvertTo-SummaryHtmlText $UserAgent))
        )

        $scopeRows = @(
            (New-GeneralField -Label "Azure IAM Data" -ValueHtml $AzureIamBadge),
            (New-GeneralField -Label "PIM Role Data" -ValueHtml $PimRolesBadge),
            (New-GeneralField -Label "PIM Group Data" -ValueHtml $PimGroupsBadge),
            (New-GeneralField -Label "Default Microsoft SP Data" -ValueHtml $DefaultMsSpBadge)
        )

return @"
<section class='summary-panel summary-general-panel'>
    <div class='summary-general-header'>
        <h2>General</h2>
    </div>
    <div class='summary-general-grid'>
        $(New-GeneralCard -Title "Tenant" -Rows $tenantRows)
        $(New-GeneralCard -Title "Execution" -Rows $executionRows)
        $(New-GeneralCard -Title "Coverage" -Rows $scopeRows)
    </div>
</section>
"@
    }

    ############################## Script section ########################

    #Define basic variables
    $Title = "EntraFalcon Enumeration Summary"

    $chartJsEmbedded = $global:GLOBALJavaScript_Chart

    write-host "[*] Writing log files"

    $GlobalAuditSummary.Time.End = Get-Date -Format "yyyyMMdd HH:mm"

    $MsAppsEnumerated = if ([bool]$GlobalAuditSummary.EnterpriseApps.IncludeMsApps) {
        "True"
    } else {
        "False (default)"
    }

    #Check whether there are subscriptions
    if ($($GlobalAuditSummary.Subscriptions.Count) -eq 0) {
        if ($($GlobalAuditSummary.ManagedIdentities.Count) -ge 1) {
            $SubscriptionCount = "? (no access - but there are managed identities!)"
        } else {
            $SubscriptionCount = "0 (no subscriptions or no access)"
        }
    } else {
        $SubscriptionCount = $($GlobalAuditSummary.Subscriptions.Count)
    }

    $securityFindingsSummary = $GlobalAuditSummary.SecurityFindings
    if ($null -eq $securityFindingsSummary) {
        $securityFindingsSummary = @{ Vulnerable = 0; NotVulnerable = 0; Skipped = 0; Total = 0 }
    }
    $findingsStatusLine = "{0} Vulnerable / {1} Not Vulnerable / {2} Skipped" -f `
        $securityFindingsSummary.Vulnerable, $securityFindingsSummary.NotVulnerable, $securityFindingsSummary.Skipped
    $hostOs = Get-EntraFalconHostOs
    $powerShellDisplay = "V$($PSVersionTable.PSVersion.ToString()) ($hostOs)"
    $durationDisplay = Get-DurationDisplay -Start $GlobalAuditSummary.Time.Start -End $GlobalAuditSummary.Time.End

    $azureIamBadge = if ([bool]$GLOBALAzurePsChecks) {
        New-GeneralStatusBadge -Text "Collected" -Tone "success"
    } else {
        New-GeneralStatusBadge -Text "Not Collected" -Tone "neutral"
    }
    $pimRolesBadge = if ([bool]$GLOBALGraphExtendedChecks) {
        New-GeneralStatusBadge -Text "Collected" -Tone "success"
    } else {
        New-GeneralStatusBadge -Text "Not Collected" -Tone "neutral"
    }
    $pimGroupsBadge = if ([bool]$GLOBALPimForGroupsChecked) {
        New-GeneralStatusBadge -Text "Collected" -Tone "success"
    } else {
        New-GeneralStatusBadge -Text "Not Collected" -Tone "neutral"
    }
    $defaultMsSpBadge = if ([bool]$GlobalAuditSummary.EnterpriseApps.IncludeMsApps) {
        New-GeneralStatusBadge -Text "Collected" -Tone "success"
    } else {
        New-GeneralStatusBadge -Text "Not Collected (default)" -Tone "muted"
    }

    $generalSectionHtml = New-GeneralSection `
        -TenantName $GlobalAuditSummary.Tenant.Name `
        -TenantId $GlobalAuditSummary.Tenant.ID `
        -TenantLicense $GlobalAuditSummary.TenantLicense.Name `
        -Subscriptions $SubscriptionCount `
        -StartTime $GlobalAuditSummary.Time.Start `
        -EndTime $GlobalAuditSummary.Time.End `
        -Duration $durationDisplay `
        -EntraFalconVersion $GlobalAuditSummary.EntraFalcon.Version `
        -PowerShellVersion $powerShellDisplay `
        -UserAgent $GlobalAuditSummary.UserAgent.Name `
        -AzureIamBadge $azureIamBadge `
        -PimRolesBadge $pimRolesBadge `
        -PimGroupsBadge $pimGroupsBadge `
        -DefaultMsSpBadge $defaultMsSpBadge

    $mainTable = [ordered]@{
            "Users"                       = $($GlobalAuditSummary.Users.Count)
            "Groups"                      = $($GlobalAuditSummary.Groups.Count)
            "Entra Role Assignments"      = $($GlobalAuditSummary.EntraRoleAssignments.Count)
            "Azure Role Assignments"      = $($GlobalAuditSummary.AzureRoleAssignments.Count)
            "App Registrations"           = $($GlobalAuditSummary.AppRegistrations.Count)
            "Enterprise Applications"     = $($GlobalAuditSummary.EnterpriseApps.Count)
            "Managed Identities"          = $($GlobalAuditSummary.ManagedIdentities.Count)
            "Administrative Units"        = $($GlobalAuditSummary.AdministrativeUnits.Count)
            "Conditional Access Policies" = $($GlobalAuditSummary.ConditionalAccess.Count)
            "PIM Settings"                = $($GlobalAuditSummary.PimSettings.Count)
            "Findings"                    = $securityFindingsSummary.Vulnerable
        }
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 10 -Compress


    # Generate chart sections
    $Chartsection += New-ChartSection -Title "Users" -Prefix "user" -ChartCount 6
    # Only include PIM chart if it's checked
    if ($GLOBALPimForGroupsChecked) { $ChartsectionGroups += New-ChartSection -Title "Groups" -Prefix "group" -ChartCount 4} else {$ChartsectionGroups += New-ChartSection -Title "Groups" -Prefix "group" -ChartCount 3}
    $ChartsectionEnterpriseApps += New-ChartSection -Title "Enterprise Applications" -Prefix "enterpriseapps" -ChartCount 3
    $ChartsectionAppRegistrations += New-ChartSection -Title "App Registrations" -Prefix "appregistrations" -ChartCount 3
    $ChartsectionManagedIdentities += New-ChartSection -Title "Managed Identities" -Prefix "managedidentities" -ChartCount 2
    $ChartsectionEntraRoles += New-ChartSection -Title "Entra ID Role Assignments" -Prefix "entraroles" -ChartCount 4
    $ChartsectionAzureRoles += New-ChartSection -Title "Azure Role Assignments" -Prefix "azureroles" -ChartCount 4


    #Dynamically generate sections
    if ($($GlobalAuditSummary.Groups.Count) -ge 1) {
        $Chartsection += $ChartsectionGroups
    }
    if ($($GlobalAuditSummary.EnterpriseApps.Count) -ge 1) {
        $Chartsection += $ChartsectionEnterpriseApps
    }
    if ($($GlobalAuditSummary.AppRegistrations.Count) -ge 1) {
        $Chartsection += $ChartsectionAppRegistrations
    }
    if ($($GlobalAuditSummary.ManagedIdentities.Count) -ge 1) {
        $Chartsection += $ChartsectionManagedIdentities
    }
    if ($($GlobalAuditSummary.EntraRoleAssignments.Count) -ge 1) {
        $Chartsection += $ChartsectionEntraRoles
    }
    if ($($GlobalAuditSummary.AzureRoleAssignments.Count) -ge 1) {
        $Chartsection += $ChartsectionAzureRoles
    }

    $kpiSectionHtml = New-KpiSection -Items $mainTable
    $mainTableRuntimeHtml = @"
<div class='summary-hidden-runtime' aria-hidden='true'>
$GLOBALMainTableDetailsHEAD
$mainTableJson
</script>
<div id='object-container'></div>
</div>
"@

    $Chartsection += "<script type='text/javascript'>`n$chartJsEmbedded`n</script>"

    # Chart script
    $Chartsection += @"
<script>
document.addEventListener('DOMContentLoaded', function () {
    // === 1. Your data source(s) ===
    const dataSources = {
        // ============ USERS ============
        users_general: {
            internal: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Guests)),
            guests: $($GlobalAuditSummary.Users.Guests),
            total: $($GlobalAuditSummary.Users.Count)
        },
        users_enabled: {
            enabled: $($GlobalAuditSummary.Users.Enabled),
            disabled: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Enabled))
        },
        users_onprem: {
            onprem: $($GlobalAuditSummary.Users.OnPrem),
            cloudOnly: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.OnPrem))
        },
        users_mfacap: {
            mfacap: $($GlobalAuditSummary.Users.MfaCapable),
            notmfacap: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.MfaCapable))
        },
        users_inactive: {
            inactive: $($GlobalAuditSummary.Users.Inactive),
            active: $($($GlobalAuditSummary.Users.Count) - $($GlobalAuditSummary.Users.Inactive))
        },
        users_lastsignin: {
            '0-1 month': $($GlobalAuditSummary.Users.SignInActivity."0-1 month"),
            '1-2 months': $($GlobalAuditSummary.Users.SignInActivity."1-2 months"),
            '2-3 months': $($GlobalAuditSummary.Users.SignInActivity."2-3 months"),
            '3-4 months': $($GlobalAuditSummary.Users.SignInActivity."3-4 months"),
            '4-5 months': $($GlobalAuditSummary.Users.SignInActivity."4-5 months"),
            '5-6 months': $($GlobalAuditSummary.Users.SignInActivity."5-6 months"),
            '6+ months': $($GlobalAuditSummary.Users.SignInActivity."6+ months"),
            'Never': $($GlobalAuditSummary.Users.SignInActivity."Never")
        },

        // ============ GROUPS ============
        groups_general: {
            security: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.M365)),
            m365: $($GlobalAuditSummary.Groups.M365),
            total: $($GlobalAuditSummary.Groups.Count)
        },
        groups_onprem: {
            onprem: $($GlobalAuditSummary.Groups.OnPrem),
            cloudonly: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.OnPrem))
        },
        groups_public: {
            public: $($GlobalAuditSummary.Groups.PublicM365),
            notpublic: $($($GlobalAuditSummary.Groups.M365) - $($GlobalAuditSummary.Groups.PublicM365))
        },
        groups_pimonboarded: {
            onboarded: $($GlobalAuditSummary.Groups.PimOnboarded),
            notonboarded: $($($GlobalAuditSummary.Groups.Count) - $($GlobalAuditSummary.Groups.PimOnboarded))
        },

        // ============ Enterprise Apps ============
        enterpriseapps_general: {
            internal: $($($GlobalAuditSummary.EnterpriseApps.Count) - $($GlobalAuditSummary.EnterpriseApps.Foreign)),
            foreign: $($GlobalAuditSummary.EnterpriseApps.Foreign),
            total: $($GlobalAuditSummary.EnterpriseApps.Count)
        },
        enterpriseapps_credentials: {
            credentials: $($GlobalAuditSummary.EnterpriseApps.Credentials),
            nocredentials: $($($GlobalAuditSummary.EnterpriseApps.Count) - $($GlobalAuditSummary.EnterpriseApps.Credentials))
        },
            enterpriseapps_apicategorization: {
            'Dangerous': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Dangerous),
            'High': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.High),
            'Medium': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Medium),
            'Low': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Low),
            'Uncategorized': $($GlobalAuditSummary.EnterpriseApps.ApiCategorization.Misc)
        },

        // ============ App Registrations ============
        appregistrations_general: {
            singletenant: $($GlobalAuditSummary.AppRegistrations.Audience.SingleTenant),
            multitenant: $($GlobalAuditSummary.AppRegistrations.Audience.MultiTenant),
            multitenantpersonal: $($GlobalAuditSummary.AppRegistrations.Audience.MultiTenantPersonal),
            total: $($GlobalAuditSummary.AppRegistrations.Count)
        },
        appregistrations_applock: {
            applock: $($GlobalAuditSummary.AppRegistrations.AppLock),
            noapplock: $($($GlobalAuditSummary.AppRegistrations.Count) - $($GlobalAuditSummary.AppRegistrations.AppLock))
        },
        appregistrations_credentials: {
            'Secrets': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsSecrets),
            'Certificates': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsCerts),
            'Federated Credentials': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsFederatedCreds),
            'None': $($GlobalAuditSummary.AppRegistrations.Credentials.AppsNoCreds)
        },

        // ============ Managed Identities ============
        managedidentities_general: {
            systemassigned: $($($GlobalAuditSummary.ManagedIdentities.Count) - $($GlobalAuditSummary.ManagedIdentities.IsExplicit)),
            userassigned: $($GlobalAuditSummary.ManagedIdentities.IsExplicit),
            total: $($GlobalAuditSummary.ManagedIdentities.Count)
        },
            managedidentities_apicategorization: {
            'Dangerous': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Dangerous),
            'High': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.High),
            'Medium': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Medium),
            'Low': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Low),
            'Uncategorized': $($GlobalAuditSummary.ManagedIdentities.ApiCategorization.Misc)
        },

        // ============ Entra Roles ============
        entraroles_general: {
            active: $($($GlobalAuditSummary.EntraRoleAssignments.Count) - $($GlobalAuditSummary.EntraRoleAssignments.Eligible)),
            eligible: $($GlobalAuditSummary.EntraRoleAssignments.Eligible),
            total: $($GlobalAuditSummary.EntraRoleAssignments.Count)
        },
        entraroles_builtin: {
            builtin: $($GlobalAuditSummary.EntraRoleAssignments.BuiltIn),
            custom: $($($GlobalAuditSummary.EntraRoleAssignments.Count) - $($GlobalAuditSummary.EntraRoleAssignments.BuiltIn))
        },
        entraroles_tiers: {
            'Tier-0': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-0"),
            'Tier-1': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-1"),
            'Tier-2': $($GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-2"),
            'Uncategorized': $($GlobalAuditSummary.EntraRoleAssignments.Tiers.Uncategorized)
        },
        entraroles_principaltypes: {
            'User': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.User),
            'Group': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Group),
            'App': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.App),
            'Managed Identity': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.MI),
            'Unknown': $($GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Unknown)
        },

        // ============ Azure Roles ============
        azureroles_general: {
            active: $($($GlobalAuditSummary.AzureRoleAssignments.Count) - $($GlobalAuditSummary.AzureRoleAssignments.Eligible)),
            eligible: $($GlobalAuditSummary.AzureRoleAssignments.Eligible),
            total: $($GlobalAuditSummary.AzureRoleAssignments.Count)
        },
        azureroles_builtin: {
            builtin: $($GlobalAuditSummary.AzureRoleAssignments.BuiltIn),
            custom: $($($GlobalAuditSummary.AzureRoleAssignments.Count) - $($GlobalAuditSummary.AzureRoleAssignments.BuiltIn))
        },
        azureroles_tiers: {
            'Tier-0': $($GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-0"),
            'Tier-1': $($GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-1"),
            'Tier-2': $($GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-2"),
            'Tier-3': $($GlobalAuditSummary.AzureRoleAssignments.Tiers."Tier-3"),
            'Uncategorized': $($GlobalAuditSummary.AzureRoleAssignments.Tiers.Uncategorized)
        },
        azureroles_principaltypes: {
            'User': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.User),
            'Group': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Group),
            'ServicePrincipal': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.SP),
            'Unknown': $($GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Unknown)
        }
    };

    // === 2. Shared chart config ===
    const chartColorPalette = ['#4CAF50', '#FF7043', '#29B6F6', '#FFCA28', '#AB47BC', '#26A69A', '#EC407A'];
    const chartInstances = [];

    function getDatasetColors(datasetKey, labels) {
        const labelList = Array.isArray(labels) ? labels : [];
        return labelList.map(function (_, idx) {
            return chartColorPalette[idx % chartColorPalette.length];
        });
    }

    function getDatasetTotal(chartData) {
        if (!chartData || !Array.isArray(chartData.datasets)) {
            return 0;
        }

        return chartData.datasets.reduce(function (datasetSum, dataset) {
            const values = Array.isArray(dataset.data) ? dataset.data : [];
            const numericValues = values.map(function (value) {
                return Number(value) || 0;
            });
            return datasetSum + numericValues.reduce(function (sum, value) {
                return sum + value;
            }, 0);
        }, 0);
    }

    function hasRenderableChartData(chartData) {
        return getDatasetTotal(chartData) > 0;
    }

    function getChartData(datasetKey) {

        // ============ USERS ============

        if (datasetKey === 'users_general') {
            return {
                labels: ['Internal Users', 'Guest Users'],
                datasets: [{
                    data: [dataSources.users_general.internal, dataSources.users_general.guests],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_enabled') {
            return {
                labels: ['Enabled Users', 'Disabled Users'],
                datasets: [{
                    data: [dataSources.users_enabled.enabled, dataSources.users_enabled.disabled],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_onprem') {
            return {
                labels: ['Cloud-Only Users', 'Synced Users'],
                datasets: [{
                    data: [dataSources.users_onprem.cloudOnly, dataSources.users_onprem.onprem],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_mfacap') {
            return {
                labels: ['MFA Capable', 'Not MFA Capable'],
                datasets: [{
                    data: [dataSources.users_mfacap.mfacap, dataSources.users_mfacap.notmfacap],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_inactive') {
            return {
                labels: ['Active Users', 'Inactive Users'],
                datasets: [{
                    data: [dataSources.users_inactive.active, dataSources.users_inactive.inactive],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'users_lastsignin') {
            const entries = Object.entries(dataSources.users_lastsignin);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Users',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ Groups ============

        if (datasetKey === 'groups_general') {
            return {
                labels: ['Security Groups', 'M365 Groups'],
                datasets: [{
                    data: [dataSources.groups_general.security, dataSources.groups_general.m365],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_onprem') {
            return {
                labels: ['Cloud-Only Groups', 'Synced Groups'],
                datasets: [{
                    data: [dataSources.groups_onprem.cloudonly, dataSources.groups_onprem.onprem],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_public') {
            return {
                labels: ['Private M365 Group', 'Public M365 Groups'],
                datasets: [{
                    data: [dataSources.groups_public.notpublic, dataSources.groups_public.public],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'groups_pimonboarded') {
            return {
                labels: ['Not PIM Onboarded', 'PIM Onboarded'],
                datasets: [{
                    data: [dataSources.groups_pimonboarded.notonboarded, dataSources.groups_pimonboarded.onboarded],
                    backgroundColor: chartColorPalette
                }]
            };
        }

        // ============ Enterprise Apps ============
        if (datasetKey === 'enterpriseapps_general') {
            return {
                labels: ['Internal Apps', 'Foreign Apps'],
                datasets: [{
                    data: [dataSources.enterpriseapps_general.internal, dataSources.enterpriseapps_general.foreign],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'enterpriseapps_credentials') {
            return {
                labels: ['Apps without Credentials', 'Apps with Credentials'],
                datasets: [{
                    data: [dataSources.enterpriseapps_credentials.nocredentials, dataSources.enterpriseapps_credentials.credentials],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'enterpriseapps_apicategorization') {
            const entries = Object.entries(dataSources.enterpriseapps_apicategorization);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ App Registrations ============
        if (datasetKey === 'appregistrations_general') {
            return {
                labels: ['Single Tenant', 'Multitenant', 'Multitenant and Personal'],
                datasets: [{
                    data: [dataSources.appregistrations_general.singletenant, dataSources.appregistrations_general.multitenant, dataSources.appregistrations_general.multitenantpersonal],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'appregistrations_applock') {
            return {
                labels: ['Apps with AppLock', 'Apps without AppLock'],
                datasets: [{
                    data: [dataSources.appregistrations_applock.applock, dataSources.appregistrations_applock.noapplock],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'appregistrations_credentials') {
            const entries = Object.entries(dataSources.appregistrations_credentials);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ Managed Identities ============
        if (datasetKey === 'managedidentities_general') {
            return {
                labels: ['System Assigned', 'User Assigned'],
                datasets: [{
                    data: [dataSources.managedidentities_general.systemassigned, dataSources.managedidentities_general.userassigned],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'managedidentities_apicategorization') {
            const entries = Object.entries(dataSources.managedidentities_apicategorization);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Apps',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        // ============ Entra Roles ============
        if (datasetKey === 'entraroles_general') {
            return {
                labels: ['Eligible Assignments', 'Active Assignments'],
                datasets: [{
                    data: [dataSources.entraroles_general.eligible, dataSources.entraroles_general.active],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'entraroles_builtin') {
            return {
                labels: ['Built-In Roles', 'Custom Roles'],
                datasets: [{
                    data: [dataSources.entraroles_builtin.builtin, dataSources.entraroles_builtin.custom],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'entraroles_tiers') {
            const entries = Object.entries(dataSources.entraroles_tiers);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Roles',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }
        if (datasetKey === 'entraroles_principaltypes') {
            const entries = Object.entries(dataSources.entraroles_principaltypes);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Principals',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }


        // ============ Azure Roles ============
        if (datasetKey === 'azureroles_general') {
            return {
                labels: ['Eligible Assignments', 'Active Assignments'],
                datasets: [{
                    data: [dataSources.azureroles_general.eligible, dataSources.azureroles_general.active],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'azureroles_builtin') {
            return {
                labels: ['Built-In Roles', 'Custom Roles'],
                datasets: [{
                    data: [dataSources.azureroles_builtin.builtin, dataSources.azureroles_builtin.custom],
                    backgroundColor: chartColorPalette
                }]
            };
        }
        if (datasetKey === 'azureroles_tiers') {
            const entries = Object.entries(dataSources.azureroles_tiers);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Assignments',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }
        if (datasetKey === 'azureroles_principaltypes') {
            const entries = Object.entries(dataSources.azureroles_principaltypes);
            return {
                labels: entries.map(e => e[0]),
                datasets: [{
                    label: 'Principals',
                    data: entries.map(e => e[1]),
                    backgroundColor: chartColorPalette
                }],
            };
        }

        return null;
    }

    function getChartOptions(titleText, type, datasetKey, indexAxis = 'x', showLegend = true) {
        const isDarkMode = document.body.classList.contains('dark-mode');
        const axisColor = isDarkMode ? '#ccc' : '#333';
        const gridColor = isDarkMode ? '#444' : '#ccc';
        const titleColor = isDarkMode ? '#ccc' : '#222';
        const labelColor = isDarkMode ? '#eee' : '#111';
        const chartData = getChartData(datasetKey);
        const hasData = hasRenderableChartData(chartData);

        if (chartData && Array.isArray(chartData.datasets)) {
            chartData.datasets.forEach(function (dataset) {
                dataset.backgroundColor = getDatasetColors(datasetKey, chartData.labels);
                if (!hasData) {
                    dataset.backgroundColor = 'rgba(0,0,0,0)';
                    dataset.borderColor = 'rgba(0,0,0,0)';
                    dataset.hoverBackgroundColor = 'rgba(0,0,0,0)';
                    dataset.hoverBorderColor = 'rgba(0,0,0,0)';
                    dataset.borderWidth = 0;
                }
            });
        }

        const plugins = [{
            id: 'emptyState',
            afterDraw: (chart) => {
                if (hasData) {
                    return;
                }

                const { ctx, chartArea } = chart;
                if (!chartArea) {
                    return;
                }

                ctx.save();
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = isDarkMode ? '#bbbbbb' : '#666666';
                ctx.font = '600 14px Arial';
                ctx.fillText('No data available', (chartArea.left + chartArea.right) / 2, (chartArea.top + chartArea.bottom) / 2);
                ctx.restore();
            }
        }];

        if (type === 'bar') {
            plugins.push({
                id: 'barValueLabels',
                afterDatasetsDraw: (chart) => {
                    if (!hasData) {
                        return;
                    }

                    const { ctx, chartArea } = chart;
                    const isHorizontal = chart.options.indexAxis === 'y';

                    ctx.save();
                    ctx.fillStyle = labelColor;
                    ctx.font = '600 11px Arial';

                    chart.data.datasets.forEach((dataset, datasetIndex) => {
                        const meta = chart.getDatasetMeta(datasetIndex);
                        if (meta.hidden) {
                            return;
                        }

                        meta.data.forEach((element, index) => {
                            const value = Number(dataset.data[index]) || 0;
                            if (value <= 0) {
                                return;
                            }

                            const position = element.tooltipPosition();
                            let x;
                            let y;

                            if (isHorizontal) {
                                x = Math.min(position.x + 8, chartArea.right - 4);
                                y = position.y;
                                ctx.textAlign = x >= chartArea.right - 10 ? 'right' : 'left';
                            } else {
                                x = position.x;
                                y = Math.max(position.y - 10, chartArea.top + 12);
                                ctx.textAlign = 'center';
                            }

                            ctx.textBaseline = 'middle';
                            ctx.fillText(String(value), x, y);
                        });
                    });

                    ctx.restore();
                }
            });
        }

        if (type === 'doughnut' && hasData) {
            plugins.push({
                id: 'centerText',
                beforeDraw: (chart) => {
                    const { width, height, ctx } = chart;
                    const total = dataSources[datasetKey].total;

                    ctx.save();
                    ctx.font = 'bold 14px Arial';
                    ctx.fillStyle = labelColor;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(total + ' Total', width / 2, height / 2 + 37);
                    ctx.restore();
                }
            });
        }

        return {
            type,
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: type === 'doughnut' ? '70%' : undefined,
                indexAxis: indexAxis,
                plugins: {
                    legend: {
                        display: hasData && showLegend,
                        position: 'top',
                        labels: { color: axisColor }
                    },
                    title: {
                        display: true,
                        text: titleText,
                        color: titleColor,
                        font: { size: 16 },
                        padding: { bottom: 14 }
                    }
                },
                scales: type === 'bar' ? {
                    x: {
                        display: hasData,
                        ticks: { color: axisColor },
                        grid: { color: gridColor }
                    },
                    y: {
                        display: hasData,
                        ticks: { color: axisColor },
                        grid: { color: gridColor }
                    }
                } : {}
            },
            plugins
        };
    }

    // === 3. Chart layout/config ===
    const chartConfigs = [
        // ============ Users ============
        { id: 'user_chart1', title: 'Internal vs Guest Users', type: 'doughnut', dataset: 'users_general' },
        { id: 'user_chart2', title: 'Enabled vs Disabled', type: 'bar', dataset: 'users_enabled', showLegend: false },
        { id: 'user_chart3', title: 'MFA Capability', type: 'bar', dataset: 'users_mfacap', showLegend: false },
        { id: 'user_chart4', title: 'Cloud-Only vs Synced', type: 'bar', dataset: 'users_onprem', showLegend: false },
        { id: 'user_chart5', title: 'Active vs Inactive', type: 'bar', dataset: 'users_inactive', showLegend: false },
        { id: 'user_chart6', title: 'Last Successful Sign-In', type: 'bar', dataset: 'users_lastsignin', indexAxis: 'y', showLegend: false },

        // ============ Groups ============
        { id: 'group_chart1', title: 'Security vs M365', type: 'doughnut', dataset: 'groups_general' },
        { id: 'group_chart2', title: 'Cloud-Only vs Synced', type: 'bar', dataset: 'groups_onprem', showLegend: false },
        { id: 'group_chart3', title: 'Private vs Public M365', type: 'bar', dataset: 'groups_public', showLegend: false },
        { id: 'group_chart4', title: 'PIM Onboarding', type: 'bar', dataset: 'groups_pimonboarded', showLegend: false },

        // ============ Enterprise Apps ============
        { id: 'enterpriseapps_chart1', title: 'Internal vs Foreign', type: 'doughnut', dataset: 'enterpriseapps_general' },
        { id: 'enterpriseapps_chart2', title: 'Credential Presence', type: 'bar', dataset: 'enterpriseapps_credentials', showLegend: false },
        { id: 'enterpriseapps_chart3', title: 'API Permission Severity', type: 'bar', dataset: 'enterpriseapps_apicategorization', indexAxis: 'y', showLegend: false },

        // ============ App Registrations ============
        { id: 'appregistrations_chart1', title: 'Tenant Audience', type: 'doughnut', dataset: 'appregistrations_general' },
        { id: 'appregistrations_chart2', title: 'AppLock Coverage', type: 'bar', dataset: 'appregistrations_applock', showLegend: false },
        { id: 'appregistrations_chart3', title: 'Credential Types', type: 'bar', dataset: 'appregistrations_credentials', indexAxis: 'y', showLegend: false },

        // ============ Managed Identities  ============
        { id: 'managedidentities_chart1', title: 'System vs User Assigned', type: 'doughnut', dataset: 'managedidentities_general' },
        { id: 'managedidentities_chart2', title: 'API Permission Severity', type: 'bar', dataset: 'managedidentities_apicategorization', indexAxis: 'y', showLegend: false },

        // ============ Entra Roles ============
        { id: 'entraroles_chart1', title: 'Eligible vs Active', type: 'doughnut', dataset: 'entraroles_general' },
        { id: 'entraroles_chart2', title: 'Built-In vs Custom', type: 'bar', dataset: 'entraroles_builtin', showLegend: false },
        { id: 'entraroles_chart3', title: 'Role Tier Distribution', type: 'bar', dataset: 'entraroles_tiers', indexAxis: 'y', showLegend: false },
        { id: 'entraroles_chart4', title: 'Principal Types', type: 'bar', dataset: 'entraroles_principaltypes', indexAxis: 'y', showLegend: false },

        // ============ Azure Roles ============
        { id: 'azureroles_chart1', title: 'Eligible vs Active', type: 'doughnut', dataset: 'azureroles_general' },
        { id: 'azureroles_chart2', title: 'Built-In vs Custom', type: 'bar', dataset: 'azureroles_builtin', showLegend: false },
        { id: 'azureroles_chart3', title: 'Role Tier Distribution', type: 'bar', dataset: 'azureroles_tiers', indexAxis: 'y', showLegend: false },
        { id: 'azureroles_chart4', title: 'Principal Types', type: 'bar', dataset: 'azureroles_principaltypes', indexAxis: 'y', showLegend: false }
    ];

    // === 4. Render all charts ===
    function renderCharts() {
        chartInstances.forEach(chart => chart.destroy());
        chartInstances.length = 0;

        chartConfigs.forEach(config => {
            const ctx = document.getElementById(config.id);
            if (ctx) {
                const chart = new Chart(
                    ctx,
                    getChartOptions(config.title, config.type, config.dataset, config.indexAxis || 'x', config.showLegend !== false)
                );
                chartInstances.push(chart);
            }
        });
    }

    renderCharts(); // Initial load

    // === 5. Re-render on theme change ===
    const observer = new MutationObserver(() => renderCharts());
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
});
</script>

"@
$CustomCss = @"
<style>
.chart-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    max-width: none;
    margin-bottom: 0;
}
.chart-box {
    width: 100%;
    max-width: none;
    height: 270px;
    padding: 10px;
    border-radius: 14px;
    border: 1px solid rgba(0,0,0,0.08);
    background: rgba(255,255,255,0.56);
}
body.dark-mode .chart-box {
    border-color: rgba(255,255,255,0.10);
    background: rgba(255,255,255,0.03);
}
.summary-panel,
.summary-kpi-panel,
.summary-chart-panel {
    padding: 16px;
    margin-bottom: 18px;
    border-radius: 16px;
    border: 1px solid rgba(0,0,0,0.10);
    background: rgba(255,255,255,0.78);
    box-shadow: 0 8px 20px rgba(17, 26, 43, 0.06);
}
body.dark-mode .summary-panel,
body.dark-mode .summary-kpi-panel,
body.dark-mode .summary-chart-panel {
    border-color: rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.04);
    box-shadow: 0 10px 22px rgba(0, 0, 0, 0.18);
}
.summary-panel h2,
.summary-kpi-panel h2,
.summary-chart-panel h2 {
    margin-top: 0;
}
.summary-general-header {
    display: flex;
    align-items: baseline;
    margin-bottom: 16px;
}
.summary-general-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 14px;
}
.summary-info-card {
    padding: 14px;
    border-radius: 14px;
    border: 1px solid rgba(0,0,0,0.10);
    background: rgba(255,255,255,0.78);
}
body.dark-mode .summary-info-card {
    border-color: rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.04);
}
.summary-info-card h3 {
    margin: 0 0 12px 0;
    font-size: 15px;
}
.summary-info-list {
    display: grid;
    gap: 10px;
}
.summary-info-row {
    display: grid;
    grid-template-columns: minmax(120px, 0.9fr) minmax(0, 1.2fr);
    gap: 10px;
    align-items: start;
}
.summary-info-label {
    font-size: 12px;
    opacity: 0.72;
}
.summary-info-value {
    font-size: 13px;
    line-height: 1.45;
    word-break: break-word;
}
.summary-status-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid rgba(0,0,0,0.10);
    font-size: 12px;
    line-height: 1.2;
}
.summary-status-badge.tone-success {
    background: rgba(91, 140, 90, 0.16);
    color: #2f6a34;
    border-color: rgba(47, 106, 52, 0.20);
}
.summary-status-badge.tone-neutral {
    background: rgba(79, 129, 189, 0.12);
    color: #2e567f;
    border-color: rgba(46, 86, 127, 0.18);
}
.summary-status-badge.tone-muted {
    background: rgba(120,120,120,0.12);
    color: #5f5f5f;
    border-color: rgba(95,95,95,0.18);
}
body.dark-mode .summary-status-badge {
    border-color: rgba(255,255,255,0.12);
}
body.dark-mode .summary-status-badge.tone-success {
    background: rgba(110, 168, 110, 0.16);
    color: #cfe8cf;
    border-color: rgba(180, 220, 180, 0.18);
}
body.dark-mode .summary-status-badge.tone-neutral {
    background: rgba(120, 165, 214, 0.16);
    color: #d6e7f8;
    border-color: rgba(173, 205, 238, 0.18);
}
body.dark-mode .summary-status-badge.tone-muted {
    background: rgba(170,170,170,0.10);
    color: #dddddd;
    border-color: rgba(210,210,210,0.16);
}
.summary-chart-panel-header,
.summary-kpi-panel-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 12px;
}
.summary-chart-panel-meta {
    font-size: 12px;
    opacity: 0.72;
}
.summary-kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
}
.summary-kpi-card {
    display: grid;
    grid-template-rows: minmax(32px, auto) auto;
    gap: 8px;
    padding: 14px;
    border-radius: 14px;
    border: 1px solid rgba(0,0,0,0.10);
    background: rgba(255,255,255,0.78);
}
body.dark-mode .summary-kpi-card {
    border-color: rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.04);
}
.summary-kpi-label {
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    opacity: 0.72;
    line-height: 1.4;
    min-height: 32px;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
    overflow: hidden;
}
.summary-kpi-value {
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
}
.summary-hidden-runtime {
    display: none !important;
}
@media (max-width: 720px) {
    .chart-grid {
        grid-template-columns: 1fr;
    }
    .summary-chart-panel-header,
    .summary-kpi-panel-header {
        flex-direction: column;
        align-items: flex-start;
    }
    .summary-info-row {
        grid-template-columns: 1fr;
        gap: 4px;
    }
}
</style>
"@


$OutputCLI = @"
Execution Information:
    - Tenant Name:    $($GlobalAuditSummary.Tenant.Name)
    - Tenant ID:      $($GlobalAuditSummary.Tenant.ID)
    - Tenant License: $($GlobalAuditSummary.TenantLicense.Name)
    - Subscriptions:  $SubscriptionCount
    - Start:          $($GlobalAuditSummary.Time.Start)
    - End:            $($GlobalAuditSummary.Time.End)
    - EntraFalcon:    $($GlobalAuditSummary.EntraFalcon.Version)
    - PowerShell:     $powerShellDisplay
    - UserAgent:      $($GlobalAuditSummary.UserAgent.Name)

Enhanced Checks:
    - Enumerate Azure IAM:                  $GLOBALAzurePsChecks
    - Enumerate PIM for Entra/Azure Roles:  $GLOBALGraphExtendedChecks
    - Enumerate PIM for Groups:             $GLOBALPimForGroupsChecked
    - Enumerate Default Microsoft SP:       $MsAppsEnumerated

Enumeration Results:
    - Users:                       $($GlobalAuditSummary.Users.Count) ($($GlobalAuditSummary.Users.Guests) Guests)
    - Groups:                      $($GlobalAuditSummary.Groups.Count)
    - App Registrations:           $($GlobalAuditSummary.AppRegistrations.Count)
    - Enterprise Applications:     $($GlobalAuditSummary.EnterpriseApps.Count) ($($GlobalAuditSummary.EnterpriseApps.Foreign) Foreign)
    - Managed Identities:          $($GlobalAuditSummary.ManagedIdentities.Count)
    - Administrative Units:        $($GlobalAuditSummary.AdministrativeUnits.Count)
    - Conditional Access Policies: $($GlobalAuditSummary.ConditionalAccess.Count) ($($GlobalAuditSummary.ConditionalAccess.Enabled) Enabled)
    - Entra Role Assignments:      $($GlobalAuditSummary.EntraRoleAssignments.Count) ($($GlobalAuditSummary.EntraRoleAssignments.Eligible) Eligible)
    - Azure Role Assignments:      $($GlobalAuditSummary.AzureRoleAssignments.Count) ($($GlobalAuditSummary.AzureRoleAssignments.Eligible) Eligible)
    - PIM Settings:                $($GlobalAuditSummary.PimSettings.Count)
    - Findings:                    $findingsStatusLine
"@

    # Set generic information hich gets injected into the HTML
    Set-GlobalReportManifest -CurrentReportKey 'Summary' -CurrentReportName 'EntraFalcon Enumeration Summary'

    # Build header section
    $headerHTML = "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div>$generalSectionHtml"

    #Write HTML
    $PostContentCombined =  $Chartsection + "`n" + $GLOBALJavaScript
    $CssCombined = $GLOBALcss + $CustomCss + $global:GLOBALReportManifestScript
    $Report = ConvertTo-HTML -Body "$headerHTML $kpiSectionHtml $mainTableRuntimeHtml" -Title "$Title" -Head $CssCombined -PostContent $PostContentCombined
    $summaryHtmlPath = "$outputFolder\_EntraFalconEnumerationSummary_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"
    $summaryTxtPath = "$outputFolder\_EntraFalconEnumerationSummary_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt"
    $Report | Out-File $summaryHtmlPath
    $OutputCLI | Out-File -Width 512 -FilePath $summaryTxtPath

    # Print to console
    Write-Host "`n`n========================================= Summary =========================================" -ForegroundColor Cyan
    Write-Host $OutputCLI
    Write-Host "===========================================================================================" -ForegroundColor Cyan
    write-host "[+] Enumeration summary stored at: $summaryHtmlPath"
    write-host "[+] Enumeration summary (txt) stored at: $summaryTxtPath"
    write-host "[+] Run completed successfully"
}

