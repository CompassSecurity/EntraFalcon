<#
    .Synopsis
    PowerShell-based security assessment tool for Microsoft Entra ID environments.

    .Description
    EntraFalcon is a PowerShell-based assessment tool for pentesters, security analysts, and system administrators to evaluate the security posture of a Microsoft Entra ID environment.
    The tool identifies potential privilege escalation paths, excessive permissions, inactive accounts, and Conditional Access misconfigurations across users, groups, applications, roles, and policies. Findings are compiled into interactive HTML reports with a simple risk scoring.
    Designed with a focus on ease of use, EntraFalcon runs on PowerShell 5.1 and 7, supports Windows, Linux, and macOS, and requires no external dependencies or Microsoft Graph API consent.

    .PARAMETER Tenant
    Specifies the Entra ID tenant to authenticate against.
    Use this to target a specific tenant ID or domain, especially when enumerating tenants other than the account’s home tenant.
    - `organizations` (for multi-tenant apps)
    - A specific tenant ID
    Default: `organizations`

    .PARAMETER UserAgent
    Specifies the user agent string to be used in the HTTP requests to the token endpoint and APIs
    Default: `EntraFalcon`

    .PARAMETER ApiTop
    Specifies the Graph API page size (number of objects per response). Use a lower value if you encounter HTTP 504 errors (this will result in more API requests).
    The default value used by Microsoft Graph API is 100. Valid range: 5–999.
    Default: `999`

    .PARAMETER DisableCAE
    Disables Continuous Access Evaluation (CAE), resulting in shorter-lived access tokens.
    Useful when CAE breaks the script.

    .PARAMETER LimitResults
    Limits the number of groups or users included in the report.
    The limit is applied *after* sorting by risk score, ensuring only the highest-risk groups and users are processed and reported. This helps improve performance and keep the reports usable in large environments.

    .PARAMETER AuthFlow
    Preferred authentication flow selector.
    Supported values:
    - `BroCi` (default): BroCi flow
    - `AuthCode`: Auth Code flow (non-BroCi)
    - `DeviceCode`: Device Code flow
    - `ManualCode`: Auth Code + Manual Code flow (non-BroCi)
    - `BroCiManualCode`: BroCi + Manual Code flow
    - `BroCiToken`: BroCi flow using a supplied refresh token (`-BroCiToken`)

    .PARAMETER BroCiToken
    Optional Bring Your Own BroCi refresh token.
    Required when using `-AuthFlow BroCiToken`.
    The provided token must be a valid refresh token for the Azure Portal client (c44b4083-3bb0-49c1-b47d-974e53cbdf3c).
    Treat this value as sensitive secret material.

    .PARAMETER SkipPimForGroups
    Skips the enumeration of PIM for Groups, avoiding the need for a secondary authentication flow.

    .PARAMETER IncludeMsApps
    Includes Microsoft-owned enterprise applications in the enumeration and analysis.
    By default, these are excluded to reduce noise.

    .PARAMETER LogLevel
    Controls runtime status output.
    - `Off` (default): No additional status output
    - `Verbose`: High-level status messages
    - `Debug`: Includes Verbose plus additional details useful for debugging
    - `Trace`: Includes Debug plus very detailed output (may be noisy)

    .PARAMETER QAMode
    Dumps the AllGroups and AllUsers objects as JSON for internal QA tests.

    .PARAMETER Csv
    Enables CSV report generation for enumeration modules.
    By default, reports are written as HTML and TXT only.

    .NOTES
    Author: Christian Feuchter, Compass Security Switzerland AG, https://www.compass-security.com/
    Source: https://github.com/CompassSecurity/EntraFalcon

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("BroCi", "AuthCode", "DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken")]
    [string]$AuthFlow = "BroCi",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Off", "Verbose", "Debug", "Trace")]
    [string]$LogLevel = "Off",

    [Parameter(Mandatory = $false)]
    [string]$UserAgent = "EntraFalcon",

    [Parameter(Mandatory = $false)]
    [switch]$SkipPimForGroups = $false,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeMsApps = $false,

    [Parameter(Mandatory=$false)]
    [switch]$DisableCAE = $false,

    [Parameter(Mandatory=$false)]
    [string]$Tenant,

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder,

    [Parameter(Mandatory = $false)]
    [int]$LimitResults,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 999)]
    [int]$ApiTop = 999,

    [Parameter(Mandatory=$false)]
    [switch]$QAMode = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Csv = $false,

    [Parameter(Mandatory = $false)]
    [string]$BroCiToken
)

#Constants
$EntraFalconVersion = "V20260321"

# Import shared functions
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
Import-Module (Join-Path $ScriptRoot 'modules\EntraTokenAid.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\Send-ApiRequest.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\shared_Functions.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_Groups.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_EnterpriseApps.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_AppRegistrations.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_Users.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_ManagedIdentities.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_Roles.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_CAPs.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\Send-GraphBatchRequest.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\Send-GraphRequest.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\export_Summary.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_PIM.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_Tenant.psm1') -Force

if ($AuthFlow -ne "BroCiToken" -and -not [string]::IsNullOrWhiteSpace($BroCiToken)) {
    Write-Error "Invalid parameter combination: -BroCiToken can only be used with -AuthFlow BroCiToken." -ErrorAction Stop
}

if ($AuthFlow -eq "BroCiToken" -and [string]::IsNullOrWhiteSpace($BroCiToken)) {
    Write-Error "Invalid parameter combination: -AuthFlow BroCiToken requires -BroCiToken." -ErrorAction Stop
}

# Check non-Windows auth flow compatibility (Linux/macOS)
if (-not (Test-NonWindowsAuthFlowCompatibility -AuthFlow $AuthFlow -ReadmePath (Join-Path $ScriptRoot 'README.md'))) {
    return
}

#Splat AuthMethods
$Global:GLOBALAuthMethods = @{
    AuthFlow = $AuthFlow
 }

if (-not [string]::IsNullOrWhiteSpace($BroCiToken)) {

    # Access tokens (JWT) typically start with 'ey'
    if ($BroCiToken.StartsWith("ey")) {
        Write-Error "Invalid -BroCiToken: access token (JWT) detected. A refresh token is required." -ErrorAction Stop
    }

    # Must look like a refresh token (Azure refresh tokens usually start with "1.")
    if (-not $BroCiToken.StartsWith("1.")) {
        Write-Error "Invalid -BroCiToken: expected a refresh token starting with '1.'." -ErrorAction Stop
    }
    $GLOBALAuthMethods.BroCiToken = $BroCiToken
}


#Define additional authentication parameters
$Global:GLOBALEntraFalconLogLevel = $LogLevel
$Global:GLOBALAuthParameters = @{}
$GLOBALAuthParameters['UserAgent'] = $UserAgent
if ($DisableCAE) {
    $GLOBALAuthParameters['DisableCAE'] = $true
}
if ($null -ne $Tenant -and "" -ne $Tenant) {
    $GLOBALAuthParameters['Tenant'] = $Tenant
}

# Optional parameters for the sub-modules
$optionalParamsET = @{}
if ($IncludeMsApps) {
    $optionalParamsET['IncludeMsApps'] = $true
}

$optionalParamsUserandGroup = @{}
if ($LimitResults) {
    $optionalParamsUserandGroup['LimitResults'] = $LimitResults
}
if ($QAMode) {
    $optionalParamsUserandGroup['QAMode'] = $QAMode
}

$optionalParamsOutput = @{}
if ($Csv) {
    $optionalParamsOutput['Csv'] = $true
}

#Define summary array and show banner
Start-InitTasks -EntraFalconVersion $EntraFalconVersion -UserAgent $UserAgent
Show-EntraFalconBanner -EntraFalconVersion $EntraFalconVersion


write-host ""
write-host "********************************** Main Authentication **********************************"
# Perform authentication check and authenticate if required
if (-Not(EnsureAuthMsGraph)) {
    Return
}


if (-not($SkipPimForGroups)) {
write-host ""
write-host "********************************** PIM for Groups: Pre-Collection Phase **********************************"
    $TenantPimForGroupsAssignments = Get-PimforGroupsAssignments
} else {
    $global:GLOBALPimForGroupsChecked = $false
}


write-host ""
write-host "********************************** Gather Basic Data **********************************"
# Gather basic data
$CurrentTenant = Get-OrgInfo
$StartTimestamp = Get-Date -Format "yyyyMMdd_HHmm"
$GlobalAuditSummary.Tenant.Name = $CurrentTenant.DisplayName
$GlobalAuditSummary.Tenant.Id = $CurrentTenant.Id

$licenseResult = Get-EffectiveEntraLicense
$GlobalAuditSummary.TenantLicense.Name  = $licenseResult.EntraIDLicencesString
$GlobalAuditSummary.TenantLicense.Level = $licenseResult.EntraIDLicencesInt

#Define output folder if not defined
if ($null -eq $OutputFolder -or "" -eq $OutputFolder) {
    $OutputFolder = "Results_$($CurrentTenant.DisplayName)_$($StartTimestamp)"
}
# Create report directory
if (-not (Test-Path -Path $OutputFolder)) {
    try {
        New-Item -ItemType Directory -Path $OutputFolder -ErrorAction Stop | out-null
    } catch {
        Write-Host "[!] Failed to create folder '$OutputFolder': $($_.Exception.Message)"
        Write-Host "[!] Aborting..."
        Start-CleanUp
        exit 1
    }
}

$AdminUnitWithMembers = Get-AdministrativeUnitsWithMembers
$Caps = Get-ConditionalAccessPolicies
# Get PIM eligible role assignments
if (Invoke-MsGraphAuthPIM) {
    $TenantPimRoleAssignments = Get-EntraPIMRoleAssignments
}
#Get active role assignments and merge eligible
$TenantRoleAssignments = Get-EntraRoleAssignments -TenantPimRoleAssignments $TenantPimRoleAssignments

# Check if authentication to Azure ARM API works and if the user has access to a subscription
if ((EnsureAuthAzurePsNative) -and (checkSubscriptionNative)){
    $global:GLOBALAzurePsChecks = $true
    $AzureIAMAssignments = Get-AllAzureIAMAssignmentsNative
} else {
    $global:GLOBALAzurePsChecks = $false
    Write-Host "[!] No AzurePS session: No Azure IAM assignments will be checked"
    $AzureIAMAssignments = @{}
}


if ($TenantPimForGroupsAssignments) {
    Write-Host "[*] Post processing PIM for Groups results..."
    $TenantPimForGroupsAssignments = Get-PIMForGroupsAssignmentsDetails -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments
}

# Prepare authentication context for Security Findings extra API calls.
$global:GLOBALSecurityFindingsAccessContext = @{
    TokenSource = "MainGraph"
    IsAvailable = $true
    Reason      = ""
}

# Authentication for Security Findings
$isBroCiFlow = @("BroCi", "BroCiManualCode", "BroCiToken") -contains $AuthFlow
if ($isBroCiFlow) {
    Write-Log -Level Verbose -Message "[SecurityFindings] BroCi flow detected. Reusing existing Graph token for special policy endpoints."
} elseif ($AuthFlow -eq "DeviceCode") {
    $global:GLOBALSecurityFindingsAccessContext.TokenSource = "Unavailable"
    $global:GLOBALSecurityFindingsAccessContext.IsAvailable = $false
    $global:GLOBALSecurityFindingsAccessContext.Reason = "DeviceCodeNotSupported"
    Write-Log -Level Verbose -Message "[SecurityFindings] DeviceCode flow detected. Special policy endpoints are skipped for this flow."
} else {
    if (EnsureAuthSecurityFindingsMsGraph) {
        $global:GLOBALSecurityFindingsAccessContext.TokenSource = "SecurityFindingsSpecial"
        Write-Log -Level Verbose -Message "[SecurityFindings] Special Graph token acquired."
    } else {
        $global:GLOBALSecurityFindingsAccessContext.TokenSource = "Unavailable"
        $global:GLOBALSecurityFindingsAccessContext.IsAvailable = $false
        $global:GLOBALSecurityFindingsAccessContext.Reason = "AuthenticationFailed"
        Write-Log -Level Verbose -Message "[SecurityFindings] Special policy endpoints will be skipped because special authentication failed."
    }
}

# Get user's MFA status
$UserAuthMethodsTable = Get-RegisterAuthMethodsUsers

# Get Devices
$Devices = Get-Devices -ApiTop $ApiTop

# Get Basic User info
$AllUsersBasicHT = Get-UsersBasic -ApiTop $ApiTop


# Determine which reports will be generated
$TenantReports = [pscustomobject]@{
    Users                     = $true
    Groups                    = $false
    EnterpriseApps            = $true
    ManagedIdentities         = $false
    AppRegistrations          = $false
    ConditionalAccessPolicies = $false
    Agents                    = $false
    EntraRoles                = $true
    AzureRoles                = $false
    PimForEntra               = $false
    SecurityFindings          = $true
    Summary                   = $true
}
$ReportsBasedOnObjects = Get-TenantReportAvailability -IncludeMsApps:$IncludeMsApps
$global:GLOBALAzureIamWarningText = $null
if (-not $GLOBALAzurePsChecks) {
    if ($ReportsBasedOnObjects.ManagedIdentities) {
        $global:GLOBALAzureIamWarningText = "Coverage gap: Azure IAM not assessed (no subscription visible or accessible, but managed identities exist). Azure role assignments are therefore missing from this report."
    } else {
        $global:GLOBALAzureIamWarningText = "Coverage gap: Azure IAM not assessed (no subscriptions exist or no access). Azure role assignments are therefore missing from this report."
    }
}
$TenantReports.ConditionalAccessPolicies = ($null -ne $Caps -and $Caps.Count -gt 0)
$TenantReports.PimForEntra               = ($null -ne $TenantPimRoleAssignments -and $TenantPimRoleAssignments.Count -gt 0)
$TenantReports.AzureRoles                = ($null -ne $AzureIAMAssignments -and $AzureIAMAssignments.Count -gt 0)
$TenantReports.Groups           = $ReportsBasedOnObjects.Groups
$TenantReports.AppRegistrations = $ReportsBasedOnObjects.AppRegistrations
$TenantReports.ManagedIdentities = $ReportsBasedOnObjects.ManagedIdentities
#$TenantReports.EnterpriseApps   = $ReportsBasedOnObjects.EnterpriseApps
#$TenantReports.Agents   = $ReportsBasedOnObjects.Agents
$global:ReportContext = [pscustomobject]@{
    TenantName     = $CurrentTenant.DisplayName
    TenantId       = $CurrentTenant.Id
    StartTimestamp = $StartTimestamp
}
Initialize-TenantReportTabs -StartTimestamp $global:ReportContext.StartTimestamp -CurrentTenant $CurrentTenant -TenantReports $TenantReports
$TenantReportsText = ($TenantReports.PSObject.Properties | Sort-Object Name | ForEach-Object { "{0} = {1}" -f $_.Name, $_.Value }) -join " | "
Write-Log -Level Debug -Message ("Reports:{0}" -f $TenantReportsText)

# Main enumeration
write-host "`n********************************** [1/10] Enumerating Groups **********************************"
$AllGroupsDetails = Invoke-CheckGroups -AdminUnitWithMembers $AdminUnitWithMembers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -OutputFolder $OutputFolder -Devices $Devices -AllUsersBasicHT $AllUsersBasicHT -ApiTop $ApiTop @optionalParamsUserandGroup @optionalParamsOutput

write-host "`n********************************** [2/10] Enumerating Enterprise Apps **********************************"
$EnterpriseApps = Invoke-CheckEnterpriseApps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -AllUsersBasicHT $AllUsersBasicHT -ApiTop $ApiTop @optionalParamsET @optionalParamsOutput

write-host "`n********************************** [3/10] Enumerating Managed Identities **********************************"
$ManagedIdentities = Invoke-CheckManagedIdentities -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -ApiTop $ApiTop @optionalParamsOutput

write-host "`n********************************** [4/10] Enumerating App Registrations **********************************"
$AppRegistrations = Invoke-CheckAppRegistrations -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -TenantRoleAssignments $TenantRoleAssignments -OutputFolder $OutputFolder @optionalParamsOutput

write-host "`n********************************** [5/10] Enumerating Users **********************************"
$Users = Invoke-CheckUsers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -UserAuthMethodsTable $UserAuthMethodsTable -Devices $Devices -OutputFolder $OutputFolder -ApiTop $ApiTop @optionalParamsUserandGroup @optionalParamsOutput

write-host "`n********************************** [6/10] Generating Role Assignments **********************************"
Invoke-CheckRoles -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -Users $Users -ManagedIdentities $ManagedIdentities -OutputFolder $OutputFolder @optionalParamsOutput

write-host "`n********************************** [7/10] Enumerating Conditional Access Policies **********************************"
$AllCaps = Invoke-CheckCaps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AllGroupsDetails $AllGroupsDetails -Users $Users -OutputFolder $OutputFolder -TenantRoleAssignments $TenantRoleAssignments @optionalParamsOutput

write-host "`n********************************** [8/10] Enumerating PIM Role Settings **********************************"
if ($GLOBALPIMForEntraRolesChecked) {
    $PimforEntraRoles = Invoke-CheckPIM -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -AllGroupsDetails $AllGroupsDetails -Users $Users -TenantRoleAssignments $TenantRoleAssignments -AllCaps $AllCaps @optionalParamsOutput
} else {
    write-host "[!] Tenant is not licensed to use PIM. Skipping role settings checks..."
    $PimforEntraRoles = @{}
}

write-host "`n********************************** [9/10] Enumerating Security Findings **********************************"
Invoke-CheckTenant -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -EnterpriseApps $EnterpriseApps -AppRegistrations $AppRegistrations -ManagedIdentities $ManagedIdentities -AllCaps $AllCaps -PimforEntraRoles $PimforEntraRoles -AllGroupsDetails $AllGroupsDetails -Users $Users -Devices $Devices

write-host "`n********************************** [10/10] Generating Summary Report **********************************"
# Show assessment summary and generate summary HTML report
Export-Summary -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder

# Remove global variables
Start-CleanUp
