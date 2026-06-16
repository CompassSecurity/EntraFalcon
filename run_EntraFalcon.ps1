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
    - `ServicePrincipal`: Client Credentials flow using a custom app registration (`-SPClientId` + secret or certificate)

    .PARAMETER BroCiToken
    Optional Bring Your Own BroCi refresh token.
    Required when using `-AuthFlow BroCiToken`.
    The provided token must be a valid refresh token for the Azure Portal client (c44b4083-3bb0-49c1-b47d-974e53cbdf3c).
    Treat this value as sensitive secret material.

    .PARAMETER SPClientId
    Client ID of the app registration to use with `-AuthFlow ServicePrincipal`.

    .PARAMETER SPClientSecret
    Client secret for the app registration. Used with `-AuthFlow ServicePrincipal`.

    .PARAMETER SPCertificatePath
    Path to a PFX/P12 certificate file for client assertion. Used with `-AuthFlow ServicePrincipal`.

    .PARAMETER SPCertificatePassword
    Optional password (`SecureString`) for the PFX certificate specified by `-SPCertificatePath`. Use `Read-Host -AsSecureString` to create the value.

    .PARAMETER SPCertificatePemPath
    Path to a PEM certificate file. Used together with `-SPPrivateKeyPemPath` for `-AuthFlow ServicePrincipal`. Requires PowerShell 7+.

    .PARAMETER SPPrivateKeyPemPath
    Path to a PEM private key file. Used together with `-SPCertificatePemPath` for `-AuthFlow ServicePrincipal`. Requires PowerShell 7+.

    .PARAMETER SPPrivateKeyPemPassword
    Optional password (`SecureString`) for the encrypted PEM private key specified by `-SPPrivateKeyPemPath`. Use `Read-Host -AsSecureString` to create the value. Requires PowerShell 7+.

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

    .PARAMETER DebugObjectDump
    Exports a CLIXML debug snapshot of final in-memory report objects to Debug_ObjectDump under the output folder.

    .PARAMETER Csv
    Enables CSV report generation for enumeration modules.
    By default, reports are written as HTML and TXT only.

    .PARAMETER ExportFindingsJson
    Exports the complete Security Findings report as JSON at the end of the run.
    The output matches the JSON (All) export from the interactive Security Findings report.

    .NOTES
    Author: Christian Feuchter, Compass Security Switzerland AG, https://www.compass-security.com/
    Source: https://github.com/CompassSecurity/EntraFalcon 

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("BroCi", "AuthCode", "DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken", "ServicePrincipal")]
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
    [switch]$DebugObjectDump = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Csv = $false,

    [Parameter(Mandatory=$false)]
    [switch]$ExportCapUncoveredUsers = $false,

    [Parameter(Mandatory=$false)]
    [switch]$ExportFindingsJson = $false,

    [Parameter(Mandatory = $false)]
    [string]$BroCiToken,

    # ServicePrincipal credential params
    [Parameter(Mandatory = $false)]
    [string]$SPClientId,

    [Parameter(Mandatory = $false)]
    [string]$SPClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$SPCertificatePath,

    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$SPCertificatePassword,

    [Parameter(Mandatory = $false)]
    [string]$SPCertificatePemPath,

    [Parameter(Mandatory = $false)]
    [string]$SPPrivateKeyPemPath,

    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$SPPrivateKeyPemPassword
)

#Constants
$EntraFalconVersion = "V20260616"

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
Import-Module (Join-Path $ScriptRoot 'modules\check_PIMGroups.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_Tenant.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_AgentIdentityBlueprints.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_AgentIdentityBlueprintsPrincipals.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_AgentIdentities.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules\check_AgentsFinalize.psm1') -Force

if ($AuthFlow -ne "BroCiToken" -and -not [string]::IsNullOrWhiteSpace($BroCiToken)) {
    Write-Error "Invalid parameter combination: -BroCiToken can only be used with -AuthFlow BroCiToken." -ErrorAction Stop
}

if ($AuthFlow -eq "BroCiToken" -and [string]::IsNullOrWhiteSpace($BroCiToken)) {
    Write-Error "Invalid parameter combination: -AuthFlow BroCiToken requires -BroCiToken." -ErrorAction Stop
}

if ($AuthFlow -eq "ServicePrincipal" -and [string]::IsNullOrWhiteSpace($SPClientId)) {
    Write-Error "Invalid parameter combination: -AuthFlow ServicePrincipal requires -SPClientId." -ErrorAction Stop
}

if ($AuthFlow -eq "ServicePrincipal" -and [string]::IsNullOrWhiteSpace($Tenant)) {
    Write-Error "ServicePrincipal flow requires a tenant. Use -Tenant." -ErrorAction Stop
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

if ($AuthFlow -eq "ServicePrincipal") {
    $GLOBALAuthMethods.SPClientId = $SPClientId
    if (-not [string]::IsNullOrWhiteSpace($SPClientSecret))    { $GLOBALAuthMethods.SPClientSecret        = $SPClientSecret }
    if (-not [string]::IsNullOrWhiteSpace($SPCertificatePath)) { $GLOBALAuthMethods.SPCertificatePath     = $SPCertificatePath }
    if ($SPCertificatePassword)                                 { $GLOBALAuthMethods.SPCertificatePassword = $SPCertificatePassword }
    if (-not [string]::IsNullOrWhiteSpace($SPCertificatePemPath)) {
        $GLOBALAuthMethods.SPCertificatePemPath = $SPCertificatePemPath
        $GLOBALAuthMethods.SPPrivateKeyPemPath  = $SPPrivateKeyPemPath
    }
    if ($SPPrivateKeyPemPassword) { $GLOBALAuthMethods.SPPrivateKeyPemPassword = $SPPrivateKeyPemPassword }
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
$optionalParamsCap = @{}
if ($ExportCapUncoveredUsers) {
    $optionalParamsCap['ExportCapUncoveredUsers'] = $true
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
    $global:GLOBALPimForGroupsHT = @{}
    $global:GLOBALPimForGroupsResources = @()
    $global:GLOBALPimForGroupsAssignmentObjects = @()
    $global:GLOBALPimForGroupsPolicySettingsSupported = $false
    $global:GLOBALPimForGroupsPolicySettingsSkipReason = "PIM for Groups assessment skipped by parameter."
}


write-host ""
write-host "********************************** Gather Basic Data **********************************"
# Gather basic data
$CurrentTenant = Get-OrgInfo
$StartTimestamp = Get-Date -Format "yyyyMMdd_HHmm"
$GlobalAuditSummary.Tenant.Name = $CurrentTenant.DisplayName
$GlobalAuditSummary.Tenant.Id = $CurrentTenant.Id
$GlobalAuditSummary.Tenant.OnPremisesSyncEnabled = $CurrentTenant.OnPremisesSyncEnabled
$GlobalAuditSummary.Tenant.OnPremisesLastSyncDateTime = $CurrentTenant.OnPremisesLastSyncDateTime

$licenseResult = Get-EffectiveEntraLicense
$GlobalAuditSummary.TenantLicense.Name  = $licenseResult.EntraIDLicencesString
$GlobalAuditSummary.TenantLicense.Level = $licenseResult.EntraIDLicencesInt

$TenantDomains = Get-TenantDomains

#Define output folder if not defined
if ($null -eq $OutputFolder -or "" -eq $OutputFolder) {
    $OutputFolder = "Results_$($CurrentTenant.FileSafeDisplayName)_$($StartTimestamp)"
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
if ($isBroCiFlow -or $AuthFlow -eq "ServicePrincipal") {
    Write-Log -Level Verbose -Message "[SecurityFindings] BroCi/ServicePrincipal flow detected. Reusing existing Graph token for special policy endpoints."
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

# Preload agent-specific basics so early reports can resolve mixed owner/member objects correctly.
$AgentObjectBasics = Get-AgentObjectBasics -CurrentTenant $CurrentTenant -ApiTop $ApiTop


# Determine which reports will be generated
$TenantReports = [pscustomobject]@{
    Users                     = $true
    Groups                    = $false
    EnterpriseApps            = $true
    ManagedIdentities         = $false
    AppRegistrations          = $false
    AgentIdentities           = $false
    AgentIdentityBlueprintsPrincipals = $false
    AgentIdentityBlueprints   = $false
    ConditionalAccessPolicies = $false
    EntraRoles                = $true
    AzureRoles                = $false
    PimForEntra               = $false
    PimForGroups              = $false
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
$TenantReports.PimForGroups              = ($GLOBALPimForGroupsChecked -and $GLOBALPimForGroupsPolicySettingsSupported -and $null -ne $GLOBALPimForGroupsResources -and @($GLOBALPimForGroupsResources).Count -gt 0)
$TenantReports.AzureRoles                = ($null -ne $AzureIAMAssignments -and $AzureIAMAssignments.Count -gt 0)
$TenantReports.Groups           = $ReportsBasedOnObjects.Groups
$TenantReports.AppRegistrations = $ReportsBasedOnObjects.AppRegistrations
$TenantReports.ManagedIdentities = $ReportsBasedOnObjects.ManagedIdentities
$TenantReports.AgentIdentities = $ReportsBasedOnObjects.AgentIdentities
$TenantReports.AgentIdentityBlueprintsPrincipals = $ReportsBasedOnObjects.AgentIdentityBlueprintsPrincipals
$TenantReports.AgentIdentityBlueprints = $ReportsBasedOnObjects.AgentIdentityBlueprints
#$TenantReports.EnterpriseApps   = $ReportsBasedOnObjects.EnterpriseApps
$global:ReportContext = [pscustomobject]@{
    TenantName     = $CurrentTenant.DisplayName
    TenantId       = $CurrentTenant.Id
    StartTimestamp = $StartTimestamp
}
Initialize-TenantReportTabs -StartTimestamp $global:ReportContext.StartTimestamp -CurrentTenant $CurrentTenant -TenantReports $TenantReports
$TenantReportsText = ($TenantReports.PSObject.Properties | Sort-Object Name | ForEach-Object { "{0} = {1}" -f $_.Name, $_.Value }) -join " | "
Write-Log -Level Debug -Message ("Reports:{0}" -f $TenantReportsText)

$ServicePrincipalSignInActivityLookup = Get-ServicePrincipalSignInActivityLookup -ApiTop $ApiTop

# Main enumeration
write-host "`n********************************** [1/15] Enumerating Groups **********************************"
$AllGroupsDetails = Invoke-CheckGroups -AdminUnitWithMembers $AdminUnitWithMembers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -OutputFolder $OutputFolder -Devices $Devices -AllUsersBasicHT $AllUsersBasicHT -AgentObjectBasics $AgentObjectBasics -ApiTop $ApiTop @optionalParamsUserandGroup @optionalParamsOutput

write-host "`n********************************** [2/15] Enumerating Enterprise Apps **********************************"
$AppRoleReferenceCache = @{}
$EnterpriseApps = Invoke-CheckEnterpriseApps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -AllUsersBasicHT $AllUsersBasicHT -AgentObjectBasics $AgentObjectBasics -ApiTop $ApiTop -ServicePrincipalSignInActivityLookup $ServicePrincipalSignInActivityLookup -AppRoleReferenceCacheOut ([ref]$AppRoleReferenceCache) @optionalParamsET @optionalParamsOutput

write-host "`n********************************** [3/15] Enumerating Managed Identities **********************************"
$ManagedIdentities = Invoke-CheckManagedIdentities -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -AgentObjectBasics $AgentObjectBasics -AppRoleReferenceCache $AppRoleReferenceCache -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -ApiTop $ApiTop @optionalParamsOutput

write-host "`n********************************** [4/15] Enumerating App Registrations **********************************"
$AppRegistrations = Invoke-CheckAppRegistrations -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -AgentObjectBasics $AgentObjectBasics -TenantRoleAssignments $TenantRoleAssignments -OutputFolder $OutputFolder @optionalParamsOutput

write-host "`n********************************** [5/15] Enumerating Agent Identities **********************************"
$AgentIdentities = Invoke-AgentIdentities -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -AppRoleReferenceCache $AppRoleReferenceCache -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -AllUsersBasicHT $AllUsersBasicHT -ApiTop $ApiTop -ServicePrincipalSignInActivityLookup $ServicePrincipalSignInActivityLookup @optionalParamsET

write-host "`n********************************** [6/15] Enumerating Agent Identity Blueprint Principals **********************************"
$AgentIdentityBlueprintsPrincipals = Invoke-AgentIdentityBlueprintsPrincipals -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -AppRoleReferenceCache $AppRoleReferenceCache -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -AgentIdentities $AgentIdentities -AllUsersBasicHT $AllUsersBasicHT -ApiTop $ApiTop -ServicePrincipalSignInActivityLookup $ServicePrincipalSignInActivityLookup @optionalParamsET

write-host "`n********************************** [7/15] Enumerating Agent Identity Blueprints **********************************"
$AgentIdentityBlueprints = Invoke-AgentIdentityBlueprints -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AppRoleReferenceCache $AppRoleReferenceCache -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals

write-host "`n********************************** [8/15] Enumerating Users **********************************"
$UserReportState = $null
$Users = Invoke-CheckUsers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -UserAuthMethodsTable $UserAuthMethodsTable -Devices $Devices -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals -OutputFolder $OutputFolder -ApiTop $ApiTop -ReportStateOut ([ref]$UserReportState) @optionalParamsUserandGroup @optionalParamsOutput

write-host "`n********************************** [9/15] Finalizing Agent Objects **********************************"
Invoke-CheckAgentsFinalize -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -AllUsersBasicHT $AllUsersBasicHT -Users $Users -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals -AgentIdentityBlueprints $AgentIdentityBlueprints @optionalParamsOutput

write-host "`n********************************** [10/15] Finalizing Users Report **********************************"
Write-Host "[*] Applying finalized Agent Identity Blueprint ownership impact to Users"
Update-EntraFalconUserBlueprintOwnershipImpact -Users $Users -AgentIdentityBlueprints $AgentIdentityBlueprints
Write-EntraFalconUsersReport -UserReportState $UserReportState -Users $Users

write-host "`n********************************** [11/15] Generating Role Assignments **********************************"
Invoke-CheckRoles -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -Users $Users -ManagedIdentities $ManagedIdentities -AgentIdentities $AgentIdentities -AgentIdentityBlueprintsPrincipals $AgentIdentityBlueprintsPrincipals -OutputFolder $OutputFolder @optionalParamsOutput

write-host "`n********************************** [12/15] Enumerating Conditional Access Policies **********************************"
$AllCaps = Invoke-CheckCaps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AllGroupsDetails $AllGroupsDetails -Users $Users -OutputFolder $OutputFolder -TenantRoleAssignments $TenantRoleAssignments @optionalParamsOutput @optionalParamsCap

write-host "`n********************************** [13/16] Enumerating PIM Role Settings **********************************"
if ($GLOBALPIMForEntraRolesChecked) {
    $PimforEntraRoles = Invoke-CheckPIM -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -AllGroupsDetails $AllGroupsDetails -Users $Users -TenantRoleAssignments $TenantRoleAssignments -AllCaps $AllCaps @optionalParamsOutput
} else {
    write-host "[!] Tenant is not licensed to use PIM. Skipping role settings checks..."
    $PimforEntraRoles = @{}
}

write-host "`n********************************** [14/16] Enumerating PIM for Groups Settings **********************************"
if ($TenantReports.PimForGroups) {
    $PimforGroups = Invoke-CheckPIMGroups -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -AllGroupsDetails $AllGroupsDetails -AllCaps $AllCaps @optionalParamsOutput
} else {
    if (-not $GLOBALPimForGroupsChecked) {
        if (-not [string]::IsNullOrWhiteSpace([string]$GLOBALPimForGroupsPolicySettingsSkipReason)) {
            Write-Host "[!] $GLOBALPimForGroupsPolicySettingsSkipReason Skipping PIM for Groups settings report..."
        } else {
            Write-Host "[!] PIM for Groups was not assessed. Skipping PIM for Groups settings report..."
        }
    } elseif (-not $GLOBALPimForGroupsPolicySettingsSupported) {
        Write-Host "[!] $GLOBALPimForGroupsPolicySettingsSkipReason Skipping PIM for Groups settings report..."
    } elseif ($null -eq $GLOBALPimForGroupsResources -or @($GLOBALPimForGroupsResources).Count -eq 0) {
        Write-Host "[!] No PIM-enabled groups found. Skipping PIM for Groups settings report..."
    } else {
        Write-Host "[!] PIM for Groups settings report is not available. Skipping..."
    }
    $PimforGroups = @{}
}

write-host "`n********************************** [15/16] Enumerating Security Findings **********************************"
$SecurityFindings = Invoke-CheckTenant -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -EnterpriseApps $EnterpriseApps -AppRegistrations $AppRegistrations -ManagedIdentities $ManagedIdentities -AllCaps $AllCaps -PimforEntraRoles $PimforEntraRoles -AllGroupsDetails $AllGroupsDetails -Users $Users -Devices $Devices -TenantRoleAssignments $TenantRoleAssignments -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -AgentIdentityBlueprints $AgentIdentityBlueprints -AgentIdentities $AgentIdentities

write-host "`n********************************** [16/16] Generating Summary Report **********************************"
# Show assessment summary and generate summary HTML report
Export-Summary -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -TenantDomains $TenantDomains -Users $Users

if ($DebugObjectDump) {
    $debugContext = @{
        OutputFolder                           = $OutputFolder
        StartTimestamp                        = $StartTimestamp
        CurrentTenant                         = $CurrentTenant
        EntraFalconVersion                    = $EntraFalconVersion
        TenantDomains                         = $TenantDomains
        GlobalAuditSummary                    = $GlobalAuditSummary
        AllUsersBasicHT                       = $AllUsersBasicHT
        UserReportState                       = $UserReportState
        Users                                 = $Users
        AllGroupsDetails                      = $AllGroupsDetails
        AgentObjectBasics                     = $AgentObjectBasics
        ServicePrincipalSignInActivityLookup = $ServicePrincipalSignInActivityLookup
        AppRoleReferenceCache                 = $AppRoleReferenceCache
        TenantPimForGroupsAssignments         = $TenantPimForGroupsAssignments
        TenantPimRoleAssignments              = $TenantPimRoleAssignments
        TenantRoleAssignments                 = $TenantRoleAssignments
        AzureIAMAssignments                   = $AzureIAMAssignments
        AllCaps                               = $AllCaps
        Devices                               = $Devices
        AdminUnitWithMembers                  = $AdminUnitWithMembers
        PimforEntraRoles                      = $PimforEntraRoles
        PimforGroups                          = $PimforGroups
        EnterpriseApps                        = $EnterpriseApps
        AppRegistrations                      = $AppRegistrations
        ManagedIdentities                     = $ManagedIdentities
        AgentIdentities                       = $AgentIdentities
        AgentIdentityBlueprintsPrincipals     = $AgentIdentityBlueprintsPrincipals
        AgentIdentityBlueprints               = $AgentIdentityBlueprints
        SecurityFindings                      = $SecurityFindings
    }

    Export-EntraFalconDebugObjectDump @debugContext
}

if ($ExportFindingsJson) {
    $findingsJsonPath = Export-EntraFalconSecurityFindingsJson -OutputFolder $OutputFolder -StartTimestamp $StartTimestamp -CurrentTenant $CurrentTenant -SecurityFindings $SecurityFindings
    if (-not [string]::IsNullOrWhiteSpace($findingsJsonPath)) {
        Write-Host "[+] Security findings JSON exported to $findingsJsonPath"
    }
}

# Remove global variables
Start-CleanUp
write-host "[+] Run completed"
