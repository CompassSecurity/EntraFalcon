<#
    .SYNOPSIS
    Helper functions used by the main flow or by the different sub-modules
#>

############################## Static variables ########################

# Reference list for known malicious Enterprise Application client IDs.
$global:GLOBALKnownMaliciousEnterpriseApps = @{
    'fc5d3843-d0e8-4c3f-b0ee-6d407f667751' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '5037c1a6-7cfc-48b5-b887-f2a045937081' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '58427324-4e5d-4441-b029-cd2d532b47d7' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '706e0542-2dfb-4e7f-98f0-1e17eab6d5b8' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'b0d8ea55-bc29-436c-9f8b-f8829030261d' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'c4d0b015-689a-4bcf-b69b-3ed5005fddb6' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'c52517b0-46eb-4d61-975a-771d9978dac0' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'f927b0f3-6fce-4d59-a246-904fa7317969' = 'https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs'
    '355d1228-1537-4e90-80a6-dae111bb4d70' = 'https://rhisac.org/threat-intelligence/microsoft-oauth-app-impersonation-leads-to-mfa-phishing/'
    '14b2864e-3cff-4d33-b5cd-7f14ca272ea4' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '85da47ec-2977-40ab-af03-f3d45aaab169' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'fc45d3d0-d870-4c83-b3f7-08ebca61d3a0' = 'https://raw.githubusercontent.com/anak0ndah/EntraHunt/main/data/threats.json'
    '6a77659d-dd6f-4c73-a555-aed25926a05f' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '6628b5b8-55af-42b4-9797-5cd5c148313c' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '599fc26c-5a11-432e-a1b1-f441314ab378' = 'https://www.proofpoint.com/us/blog/cloud-security/dangerous-consequences-threat-actors-abusing-microsofts-verified-publisher'
    '2e024fe5-fe68-4b4f-893a-53630a97b0ae' = 'https://www.proofpoint.com/us/blog/cloud-security/dangerous-consequences-threat-actors-abusing-microsofts-verified-publisher'
    '8bf3e5b9-2888-4cf3-b82f-9ba6e8a1a8b9' = 'https://www.proofpoint.com/us/blog/cloud-security/dangerous-consequences-threat-actors-abusing-microsofts-verified-publisher'
    'a3903ccd-ec81-4264-8f6a-a7d4cd395fd5' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'db2eb385-c02f-44fc-b204-ade7d9f418b1' = 'https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs'
    'fdcf7337-92bf-4c70-9888-ea234b6ffb0d' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'f99a0806-7650-4d78-acef-71e445dfc844' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'f66985e0-7bb1-4cc5-a871-1cea533665d9' = 'https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs'
    '854189f9-4c71-44bb-9880-dd0c2f75922a' = 'https://raw.githubusercontent.com/anak0ndah/EntraHunt/main/data/threats.json'
    '2ef68ccc-8a4d-42ff-ae88-2d7bb89ad139' = 'https://raw.githubusercontent.com/anak0ndah/EntraHunt/main/data/threats.json'
    'b7cb9a9b-ddc9-4444-935b-1122733c97c4' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '57b8c81f-1d9a-42fe-8ba5-2262822d7291' = 'https://www.joesandbox.com/joereverser/analysis/download/8d0148db-3ef0-401f-ab09-60523df1531f'
    '31c6b531-dd95-4361-93df-f5a9c906da39' = 'https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs'
    'c7121e86-fe4d-4dbd-b5f3-e61a62ee533a' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'a69a0f78-a77c-451c-b090-b766425caee2' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'ff8d92dc-3d82-41d6-bcbd-b9174d163620' = 'https://raw.githubusercontent.com/anak0ndah/EntraHunt/main/data/threats.json'
    'bbc79423-4b95-4ab5-814f-5437a954126c' = 'https://www.joesandbox.com/analysis/1887080/0/html'
    '1e69a9f6-bb18-452a-baba-b4650ff21882' = 'https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs'
    '48cb1fac-7195-47b3-98b2-fe3562bee75c' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '482fb03a-5218-43c2-8ce6-61956c7ca99b' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '4e4d64ac-4a2a-432c-b79e-65ca8213ede5' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '768a57a0-1c5e-477a-939a-63aebf2e5ecf' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'a43a3d51-c821-4b86-9a63-fbc775120fc2' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '0bd8e698-4298-405a-bc6b-da5647a4616b' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    'a8ca8dad-f6e6-4b01-9d6b-02e1da6c9d7f' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '055399fa-29b9-46ab-994d-4ae06f40bada' = 'https://rhisac.org/threat-intelligence/microsoft-oauth-app-impersonation-leads-to-mfa-phishing/'
    '22c606e8-7d68-4a09-89d9-c3c563a453a0' = 'https://rhisac.org/threat-intelligence/microsoft-oauth-app-impersonation-leads-to-mfa-phishing/'
    '987c259f-da29-4575-8072-96c610204830' = 'https://rhisac.org/threat-intelligence/microsoft-oauth-app-impersonation-leads-to-mfa-phishing/'
    'fe0e32ca-d09e-4f80-af3c-5b086d4b8e66' = 'https://rhisac.org/threat-intelligence/microsoft-oauth-app-impersonation-leads-to-mfa-phishing/'
    '00afba72-9008-454f-bbe6-d24e743fbe73' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '1b6f59dd-45da-4ff7-9b70-36fb780f855b' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '3cc07cb4-dba8-4051-82cd-93250a43b53b' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '440f4886-2c3a-4269-a78c-088b3b521e02' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '6755c710-194d-464f-9365-7d89d773b443' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '6efe57d9-b00a-4091-b861-a16b7368ab11' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '6fae87b3-3a0f-4519-8b56-006ba50f62c4' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '89430f84-6c29-43f8-9b23-62871a314417' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '8c659c19-8a90-49b0-a9f1-15aeba3bb449' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '9a36eaa2-cf9d-4e50-ad3e-58c9b5c04255' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    'a68c61ee-6185-4b36-bc59-1dca946d95cb' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    'bc618bf4-c6d1-4653-8c4d-c6036001b226' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    'c752e1ef-e475-43c0-9b97-9c9832dd3755' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    'f73c6332-4618-4b9d-bcd4-c77726581acd' = 'https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md'
    '21f81c9e-475d-4c26-9308-1de74a286f73' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '626b6813-13dc-45d7-abfe-a7fe09fd5276' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '443efa1c-8a0a-47a0-bd31-7c30fe32dee4' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
    '3280b1dc-4b64-4f90-a16a-b0804e6ec4ca' = 'https://www.wiz.io/blog/detecting-malicious-oauth-applications'
}

function Get-KnownMaliciousEnterpriseApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$AppId
    )

    if ([string]::IsNullOrWhiteSpace($AppId)) {
        return $null
    }

    $normalizedAppId = $AppId.Trim().ToLowerInvariant()
    if ($global:GLOBALKnownMaliciousEnterpriseApps.ContainsKey($normalizedAppId)) {
        return [string]$global:GLOBALKnownMaliciousEnterpriseApps[$normalizedAppId]
    }

    return $null
}

$global:GLOBALMainTableDetailsHEAD = @'
<div id="mainTableContainer">
  <div class="page-size-wrapper">
    <span class="page-size-icon">&#x2630;</span>
    <select id="pageSize">
      <option value="1000">1000 rows</option>
      <option value="5000">5000 rows</option>
      <option value="10000">10000 rows</option>
    </select>
  </div>
  <div id="tableWrapper"></div>
  <div id="paginationControls"></div>
</div>
<script id="mainTableData" type="application/json">
'@

# JavaScript for improved HTML table output
$global:GLOBALJavaScript_Table = @'
    <script>
        // Predefined Views
        const predefinedViews = {
            "User": [
                {
                    id: "PVU-001",
                    group: "Privileges",
                    description: "Users with Tier-0 roles in Entra ID or Azure",
                    label: "Tier-0 Users",
                    filters: {
                        EntraMaxTier: "or_Tier-0",
                        AzureMaxTier: "or_Tier-0",
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "Protected", "OnPrem", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-002",
                    group: "Privileges",
                    description: "Users with Tier-0 roles in Entra ID",
                    label: "Tier-0 Users (Entra Only)",
                    filters: {
                        EntraMaxTier: "=Tier-0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "Protected", "OnPrem", "EntraRoles", "EntraMaxTier", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-003",
                    group: "Privileges",
                    description: "Any user holding at least one role assignment",
                    label: "Users with Roles (Entra / Azure)",
                    filters: {
                        AzureRoles: "or_>0",
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles||AzureRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "Protected", "OnPrem", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-004",
                    group: "Privileges",
                    description: "Users with at least one Entra ID role",
                    label: "Users with Roles (Entra Only)",
                    filters: {
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "Protected", "OnPrem", "EntraRoles", "EntraMaxTier", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-005",
                    group: "Privileges",
                    description: "Users with app registration or service principal ownership",
                    label: "Users Owning Applications",
                    filters: {
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "Protected", "AppRegOwn", "SpOwn", "Inactive", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-014",
                    group: "Privileges",
                    description: "Licensed Tier-0 users without admin-naming convention",
                    label: "Users Tier-0 None-Admin",
                    filters: {
                        EntraMaxTier: "or_Tier-0",
                        AzureMaxTier: "or_Tier-0",
                        Enabled: "=true",
                        Agent: "=false",
                        LicenseStatus: "=Licensed",
                        UPN: "!adm_ && !_adm && !adm- && !-adm && !svc_ && !svc. && !admin && !srv- && !SYNC && !emergency && !breakglass"
                    },
                    columns: ["UPN", "Enabled", "LicenseStatus", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-006",
                    group: "Security",
                    description: "Role holders and app owners which can be influenced by low-tier admins",
                    label: "Privileged Unprotected Users",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0",
                        Agent: "=false"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "AppRegOwn", "SPOwn", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-007",
                    group: "Security",
                    description: "User accounts with no MFA method registered",
                    label: "Users Without MFA Methods",
                    filters: {
                        MfaCap: "=false",
                        Agent: "=false",
                        UPN: "!^Sync_&&!^ADToAADSyncServiceAccount"
                    },
                    columns: ["UPN", "Enabled", "UserType", "GrpMem", "GrpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "AppRegOwn", "SPOwn", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-008",
                    group: "Security",
                    description: "Accounts with per-user MFA explicitly disabled",
                    label: "Users Disabled Per-User MFA",
                    filters: {
                        PerUserMfa: "=disabled",
                        Agent: "=false"
                    },
                    columns: ["UPN", "Enabled", "UserType","LastSignInDays","Inactive", "Impact", "MfaCap", "PerUserMfa", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-009",
                    group: "Lifecycle",
                    description: "Enabled accounts with no sign-in activity in the last 180 days",
                    label: "Inactive Users",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Agent", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "LastSignInDays", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    id: "PVU-010",
                    group: "Lifecycle",
                    description: "Accounts created within the last 90 days",
                    label: "New Users",
                    filters: { CreatedDays: "<91"},
                    columns: ["UPN", "Enabled", "UserType", "Agent", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "CreatedDays", direction: "asc" }
                },
                {
                    id: "PVU-015",
                    group: "Lifecycle",
                    description: "Enabled synced user older than 90 days with no sign-in",
                    label: "Unnecessary Synced Users",
                    filters: {
                        Enabled: "=true",
                        OnPrem: "=true",
                        LastSignInDays: "=-",
                        CreatedDays: ">90"
                    },
                    columns: ["UPN", "Enabled", "OnPrem", "LicenseStatus", "GrpMem", "GrpOwn", "AuUnits", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "AppRoles", "AppRegOwn", "SPOwn", "Inactive", "LastSignInDays", "CreatedDays", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Impact", direction: "desc" }
                },
                {
                    id: "PVU-011",
                    group: "Identity Type",
                    description: "Accounts flagged as agent/workload identities",
                    label: "Agent Users",
                    filters: {
                        Agent: "=True"
                    },
                    columns: ["UPN", "Enabled", "Agent", "ForeignAgent", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-012",
                    group: "Identity Type",
                    description: "External B2B guest accounts",
                    label: "Guest Users",
                    filters: {
                        UserType: "=Guest"
                    },
                    columns: ["UPN", "Enabled", "UserType", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVU-013",
                    group: "Identity Type",
                    description: "Entra Connect service accounts",
                    label: "Entra Connect Accounts",
                    filters: {
                        UPN: "^Sync_||^ADToAADSyncServiceAccount"
                    },
                    columns: ["UPN", "Enabled", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Groups": [
                {
                    id: "PVG-001",
                    group: "Privileges",
                    description: "Groups with Tier-0 roles in Entra or Azure",
                    label: "Tier-0 Groups",
                    filters: { EntraMaxTier: "or_Tier-0", AzureMaxTier: "or_Tier-0", },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "AuUnits", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-002",
                    group: "Privileges",
                    description: "Groups with Tier-0 Entra ID roles",
                    label: "Tier-0 Groups (Entra Only)",
                    filters: { EntraMaxTier: "Tier-0"},
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "AuUnits", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-003",
                    group: "Privileges",
                    description: "Groups referenced in Conditional Access Policies",
                    label: "Groups Used in CAPs",
                    filters: {
                        CAPs: "or_>0",
                        Warnings: "or_used in CAP"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Visibility", "Users", "Devices", "NestedGroups", "NestedInGroups", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-004",
                    group: "Security",
                    description: "Privileged groups which can be influenced by low-tier admins",
                    label: "Privileged Unprotected Groups",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        CAPs: "or_>0",
                        Warnings: "or_Eligible"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "Protected", "SecurityEnabled", "Visibility", "Users", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Impact", direction: "desc" }
                },
                {
                    id: "PVG-005",
                    group: "Security",
                    description: "Groups with a guest user as an owner",
                    label: "Groups Owned by Guests",
                    filters: {
                        Warnings: "Guest as owner"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Users", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-006",
                    group: "Security",
                    description: "Protected PIM groups containing unprotected nested groups",
                    label: "PIM for Groups PrivEsc",
                    filters: {
                        PIM: "=true",
                        Protected: "=true",
                        Warnings: "contains unprotected groups"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "AuUnits", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-007",
                    group: "Security",
                    description: "Publicly joinable M365 groups",
                    label: "Public M365 Groups",
                    filters: { Visibility: "=Public", Type: "=M365 Group", Dynamic: "=false" },
                    columns: ["DisplayName", "Type", "SecurityEnabled", "Visibility", "Users", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-008",
                    group: "Configuration",
                    description: "Groups with dynamic membership rules",
                    label: "Dynamic Groups",
                    filters: { Dynamic: "=true"},
                    columns: ["DisplayName", "Type", "Dynamic", "SecurityEnabled", "Visibility", "Users", "Devices",  "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-009",
                    group: "Configuration",
                    description: "Groups enrolled in Privileged Identity Management",
                    label: "Groups Onboarded to PIM",
                    filters: { PIM: "=true" },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVG-010",
                    group: "Special",
                    description: "Groups with security-relevant keywords in the name",
                    label: "Interesting Groups by Keywords",
                    filters: {
                        DisplayName: "admin||subscription||owner||contributor||secret||geheim||keyvault||passwor"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "DirectOwners", "PIM", "NestedOwners", "Protected", "SecurityEnabled", "Visibility", "Users", "Guests", "SPCount", "Devices", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                }

            ],
            "Enterprise Apps": [
                {
                    id: "PVE-001",
                    group: "Foreign Apps",
                    description: "Third-party apps with significant privileges",
                    label: "Foreign Apps: Privileged",
                    filters: {
                        Foreign: "=True",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        BlueprintOwn: "or_>0",
                        SpOwn: "or_>0",
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0",
                        ApiDelegatedMedium: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_through group"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "Inactive", "Foreign", "GrpMem", "GrpOwn", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-002",
                    group: "Foreign Apps",
                    description: "Third-party apps with high application-level API permissions",
                    label: "Foreign Apps: Extensive API Privs (Application)",
                    filters: {
                        Foreign: "=True",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-003",
                    group: "Foreign Apps",
                    description: "Third-party apps with high delegated API permissions",
                    label: "Foreign Apps: Extensive API Privs (Delegated)",
                    filters: {
                        Foreign: "=True",
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0",
                        ApiDelegatedMedium: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "ApiDelegatedDangerous", "ApiDelegatedHigh", "ApiDelegatedMedium","ApiDelegatedLow", "ApiDelegatedMisc", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-004",
                    group: "Foreign Apps",
                    description: "Third-party apps with Entra or Azure role assignments",
                    label: "Foreign Apps: With Roles",
                    filters: {
                        Foreign: "=True",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-005",
                    group: "Internal Apps",
                    description: "Internal apps with significant privileges",
                    label: "Internal Apps: Privileged",
                    filters: {
                        Foreign: "=False",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0",
                        AppOwn: "or_>0",
                        BlueprintOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraMaxTier: "or_Tier-0||Tier-1",
                        AzureMaxTier: "or_Tier-0||Tier-1",
                        Warnings: "or_through group"
                    },
                    columns: ["DisplayName", "Foreign", "Enabled", "Inactive", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegatedDangerous", "ApiDelegatedHigh", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-006",
                    group: "Configuration",
                    description: "Non-SAML apps with active secret or certificate credentials",
                    label: "Apps with Credentials (Excludes SAML)",
                    filters: {
                        Credentials: ">0",
                        SAML: "=false",
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "SAML", "Credentials", "GrpMem", "GrpOwn", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-007",
                    group: "Configuration",
                    description: "Apps that have at least one owner assigned",
                    label: "Apps with Owners",
                    filters: {
                        Owners: ">0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Owners", "GrpMem", "GrpOwn", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVE-008",
                    group: "Lifecycle",
                    description: "Enabled apps with no recent sign-in activity",
                    label: "Inactive Apps",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "Owners", "GrpMem", "GrpOwn", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    id: "PVE-009",
                    group: "Special",
                    description: "Microsoft Entra Connect sync app",
                    label: "Entra Connect Application",
                    filters: {
                        DisplayName: "^ConnectSyncProvisioning_"
                    },
                    columns: ["DisplayName", "Enabled", "Inactive", "Owners", "Credentials", "GrpMem", "GrpOwn", "AppOwn", "BlueprintOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Managed Identities": [
                {
                    id: "PVM-001",
                    group: "Privileges",
                    description: "Managed identities with significant role or API privileges",
                    label: "Privileged Managed Identities",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        BlueprintOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraMaxTier: "or_Tier-0||Tier-1",
                        AzureMaxTier: "or_Tier-0||Tier-1",
                        Warnings: "or_through group"
                    },
                    columns: ["DisplayName", "IsExplicit", "GroupMembership", "GroupOwnership", "AppOwnership", "BlueprintOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVM-002",
                    group: "Privileges",
                    description: "Managed identities with medium-to-dangerous API permissions",
                    label: "Managed Identities: Extensive API Privs",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    },
                    columns: ["DisplayName", "IsExplicit", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVM-003",
                    group: "Privileges",
                    description: "Managed identities with Entra or Azure role assignments",
                    label: "Managed Identities: With Roles",
                    filters: {
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    },
                    columns: ["DisplayName", "IsExplicit", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                }
            ],
            "App Registrations": [
                {
                    id: "PVA-001",
                    group: "Access",
                    description: "App registrations with at least one owner",
                    label: "Apps with Owners",
                    filters: {
                        Owners: ">0"
                    }
                },
                {
                    id: "PVA-002",
                    group: "Access",
                    description: "Apps controlled by Cloud App or App Administrator role holders",
                    label: "Apps Controlled by App Admins",
                    filters: {
                        CloudAppAdmins: "or_>0",
                        AppAdmins: "or_>0"
                    },
                    sort: { column: "Impact", direction: "desc" }
                },
                {
                    id: "PVA-003",
                    group: "Configuration",
                    description: "App registrations with secret credentials",
                    label: "Apps with Secrets",
                    filters: {
                        SecretsCount: ">0"
                    }
                },
                {
                    id: "PVA-004",
                    group: "Configuration",
                    description: "App registrations without AppLock enabled",
                    label: "Apps Not Protected by AppLock",
                    filters: {
                        AppLock: "=false"
                    }
                },
                {
                    id: "PVA-005",
                    group: "Configuration",
                    description: "Apps accepting sign-ins from multiple tenants or personal accounts",
                    label: "Multitenant Apps",
                    filters: {
                        SignInAudience: "AzureADandPersonalMicrosoftAccount||AzureADMultipleOrgs"
                    }
                },
                {
                    id: "PVA-006",
                    group: "Special",
                    description: "Microsoft Entra Connect sync app registration",
                    label: "Entra Connect Application",
                    filters: {
                        DisplayName: "^ConnectSyncProvisioning_"
                    }
                }

            ],
            "Conditional Access Policies": [
                {
                    id: "PVC-001",
                    group: "Status",
                    description: "Policies currently in enabled state",
                    label: "Enabled Policies",
                    filters: {
                        State: "=enabled"
                    }
                },
                {
                    id: "PVC-002",
                    group: "Status",
                    description: "Policies that block access as the grant control",
                    label: "Blocking Policies",
                    filters: {
                        GrantControls: "=block"
                    }
                },
                {
                    id: "PVC-003",
                    group: "Authentication",
                    description: "Policies requiring multi-factor authentication",
                    label: "MFA Policies",
                    filters: {
                        GrantControls: "mfa"
                    }
                },
                {
                    id: "PVC-004",
                    group: "Authentication",
                    description: "Policies enforcing a specific authentication strength",
                    label: "Authentication Strength Policies",
                    filters: {
                        AuthStrength: "!=empty"
                    }
                },
                {
                    id: "PVC-005",
                    group: "Authentication",
                    description: "Policies targeting legacy and Exchange ActiveSync clients",
                    label: "Legacy Authentication Policies",
                    filters: {
                        AppTypes: "exchangeActiveSync||other"
                    }
                },
                {
                    id: "PVC-006",
                    group: "Authentication",
                    description: "Policies targeting device code flow sign-in",
                    label: "Device Code Flow Policies",
                    filters: {
                        AuthFlow: "deviceCodeFlow"
                    }
                },
                {
                    id: "PVC-007",
                    group: "Registration",
                    description: "Policies scoped to the device registration user action",
                    label: "Device Registration Policies",
                    filters: {
                        UserActions: "urn:user:registerdevice"
                    }
                },
                {
                    id: "PVC-008",
                    group: "Registration",
                    description: "Policies scoped to the security info registration user action",
                    label: "Security Info Registration Policies",
                    filters: {
                        UserActions: "urn:user:registersecurityinfo"
                    }
                },
                {
                    id: "PVC-009",
                    group: "Conditions",
                    description: "Policies with named network location conditions",
                    label: "Network Location Policies",
                    filters: {
                        IncNw: "or_!=0",
                        ExcNw: "or_!=0"
                    }
                },
                {
                    id: "PVC-010",
                    group: "Controls",
                    description: "Policies with session control settings configured",
                    label: "Session Control Policies",
                    filters: {
                        SessionControls: ">0"
                    }
                }
            ],
            "Role Assignments Entra ID": [
                {
                    id: "PVRE-001",
                    group: "Assignment Type",
                    description: "PIM-eligible role assignments",
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    id: "PVRE-002",
                    group: "Assignment Type",
                    description: "Active role assignments (permanent or activated)",
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    id: "PVRE-002A",
                    group: "Assignment Type",
                    description: "Active assignments currently activated through PIM",
                    label: "Activated via PIM",
                    filters: {
                        AssignmentType: "=Active",
                        ActivatedViaPIM: "=true"
                    }
                },
                {
                    id: "PVRE-003",
                    group: "Scope",
                    description: "Assignments to Tier-0 classified roles",
                    label: "Tier-0 Assignments",
                    filters: {
                        RoleTier: "=Tier-0"
                    }
                },
                {
                    id: "PVRE-004",
                    group: "Scope",
                    description: "Assignments scoped to a specific object",
                    label: "Scoped Assignments",
                    filters: {
                        Scope: "!=/ (Tenant)"
                    }
                },
                {
                    id: "PVRE-005",
                    group: "Principal Type",
                    description: "Role assignments held by managed identities or enterprise apps",
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "Managed Identity||Enterprise Application"
                    }
                },
                {
                    id: "PVRE-006",
                    group: "Role Type",
                    description: "Assignments using custom-defined roles",
                    label: "Custom Roles",
                    filters: {
                        IsBuiltIn: "=false"
                    }
                }
            ],
            "Role Assignments Azure IAM": [
                {
                    id: "PVRA-001",
                    group: "Assignment Type",
                    description: "PIM-eligible role assignments",
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    id: "PVRA-002",
                    group: "Assignment Type",
                    description: "Active role assignments (permanent or activated)",
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    id: "PVRA-003",
                    group: "Principal Type",
                    description: "Azure role assignments held by service principals",
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "ServicePrincipal||Enterprise Application||Agent Identity||Agent Identity Blueprint Principal||Managed Identity"
                    }
                },
                {
                    id: "PVRA-004",
                    group: "Configuration",
                    description: "Assignments with attribute-based conditions",
                    label: "Additional Conditions",
                    filters: {
                        Conditions: "=true"
                    }
                },
                {
                    id: "PVRA-005",
                    group: "Role Type",
                    description: "Assignments using custom-defined Azure roles",
                    label: "Custom Roles",
                    filters: {
                        RoleType: "=CustomRole"
                    }
                }
            ],
            "PIM": [
                {
                    id: "PVP-001",
                    group: "Tier-0",
                    description: "Tier-0 roles with active security warnings",
                    label: "Tier-0 Roles: With Warnings",
                    filters: {
                        Tier: "=Tier-0",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    id: "PVP-002",
                    group: "Tier-0",
                    description: "Tier-0 roles missing activation authentication context",
                    label: "Tier-0 Roles: No Auth Context",
                    filters: {
                        Tier: "=Tier-0",
                        ActivationAuthContext: "=false"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "Warnings"]
                },
                {
                    id: "PVP-003",
                    group: "Tier-0",
                    description: "Tier-0 roles with maximum activation time over 4 hours",
                    label: "Tier-0 Roles: Activation Duration >4 Hours",
                    filters: {
                        Tier: "=Tier-0",
                        ActivationDuration	: ">4"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationDuration", "Warnings"]
                },
                {
                    id: "PVP-004",
                    group: "Tier-0",
                    description: "Tier-0 roles with direct but no eligible assignments",
                    label: "Tier-0 Roles: Only Direct Assignments",
                    filters: {
                        Tier: "Tier-0",
                        Eligible: "=0",
                        Direct: ">0"
                    },
                    columns: ["Role", "Tier", "Eligible", "Direct", "Activated"]
                },
                {
                    id: "PVP-005",
                    group: "Tier-0/1",
                    description: "Tier-0 and Tier-1 roles with active security warnings",
                    label: "Tier-0/1 Roles: With Warnings",
                    filters: {
                        Tier: "Tier-0 || Tier-1",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    id: "PVP-006",
                    group: "Tier-0/1",
                    description: "In-use eligible Tier-0/1 roles with security warnings",
                    label: "Tier-0/1 Roles (Used): With Warnings",
                    filters: {
                        Eligible: ">0",
                        Tier: "Tier-0 || Tier-1",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    id: "PVP-007",
                    group: "Tier-0/1",
                    description: "Tier-0/1 roles with direct but no eligible assignments",
                    label: "Tier-0/1 Roles: Only Direct Assignments",
                    filters: {
                        Tier: "Tier-0 || Tier-1",
                        Eligible: "=0",
                        Direct: ">0"
                    },
                    columns: ["Role", "Tier", "Eligible", "Direct", "Activated"]
                },
                {
                    id: "PVP-008",
                    group: "All Roles",
                    description: "Any used role with active security warnings",
                    label: "Used Roles: With Warnings",
                    filters: {
                        Eligible: ">0",
                        Warnings: "!=empty"
                    },
                    columns: ["Role", "Tier", "Eligible", "ActivationAuthContext", "ActivationMFA", "ActivationJustification", "ActivationTicketing", "ActivationApproval", "ActivationDuration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                }
            ],
            "PIM Groups": [
                {
                    id: "PVPG-001",
                    group: "Tier",
                    description: "PIM-enabled groups with Tier-0 impact through Entra ID",
                    label: "Entra Tier-0 Groups",
                    filters: {
                        EntraMaxTier: "=Tier-0"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationMFA", "ActivationApproval", "Warnings"]
                },
                {
                    id: "PVPG-002",
                    group: "Tier",
                    description: "PIM-enabled groups with Tier-0 impact through Entra ID or Azure",
                    label: "Tier-0 Groups",
                    filters: {
                        EntraMaxTier: "or_Tier-0",
                        AzureMaxTier: "or_Tier-0"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationMFA", "ActivationApproval", "Warnings"]
                },
                {
                    id: "PVPG-003",
                    group: "Tier",
                    description: "PIM-enabled groups with Tier-0 or Tier-1 impact through Entra ID or Azure",
                    label: "Tier-0/1 Groups",
                    filters: {
                        EntraMaxTier: "or_Tier-0 || Tier-1",
                        AzureMaxTier: "or_Tier-0 || Tier-1"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationMFA", "ActivationApproval", "Warnings"]
                },
                {
                    id: "PVPG-004",
                    group: "Security",
                    description: "PIM group roles with active warnings",
                    label: "Groups With Warnings",
                    filters: {
                        Warnings: "!=empty"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationApproval", "ActivationDuration", "ActiveExpiration", "Warnings"]
                },
                {
                    id: "PVPG-005",
                    group: "Usage",
                    description: "Group roles with at least one eligible or currently active assignment",
                    label: "Used Group Roles",
                    filters: {
                        Eligible: "or_>0",
                        Active: "or_>0"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationMFA", "ActivationApproval", "Warnings"]
                },
                {
                    id: "PVPG-006",
                    group: "Usage",
                    description: "Group roles with active assignments but no eligible assignments",
                    label: "Active Without Eligible",
                    filters: {
                        Eligible: "=0",
                        Active: ">0"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActiveExpiration", "ActiveAssignMFA", "ActiveAssignJustification", "Warnings"]
                },
                {
                    id: "PVPG-007",
                    group: "Security",
                    description: "Tier-0/1 group roles missing AuthContext or approval",
                    label: "High Tier Missing Controls",
                    filters: {
                        EntraMaxTier: "or_Tier-0 || Tier-1",
                        AzureMaxTier: "or_Tier-0 || Tier-1",
                        ActivationAuthContext: "false",
                        ActivationApproval: "false"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationAuthContext", "ActivationApproval", "Warnings"]
                },
                {
                    id: "PVPG-008",
                    group: "Security",
                    description: "Group roles with long activation duration warnings",
                    label: "Long Activation Duration",
                    filters: {
                        Warnings: "long activation time"
                    },
                    columns: ["Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active", "ActivationDuration", "Warnings"]
                }
            ],
            "Agent Identities": [
                {
                    id: "PVAI-001",
                    group: "Privileges",
                    description: "Agent identities with significant API permissions, role assignments, or object ownership",
                    label: "Privileged Agent Identities",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        GrpOwn: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiDelegatedDangerous", "ApiDelegatedHigh", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVAI-002",
                    group: "Privileges",
                    description: "Agent identities with dangerous or high-severity application-level API permissions",
                    label: "Dangerous / High Application Permissions",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVAI-003",
                    group: "Privileges",
                    description: "Agent identities with dangerous or high-severity delegated API permissions",
                    label: "Dangerous / High Delegated Permissions",
                    filters: {
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "ApiDelegatedDangerous", "ApiDelegatedHigh", "ApiDelegatedMedium", "ApiDelegatedLow", "ApiDelegatedMisc", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVAI-004",
                    group: "Privileges",
                    description: "Agent identities holding Entra ID or Azure role assignments",
                    label: "Agent Identities with Roles",
                    filters: {
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "EntraRoles", "EntraMaxTier", "AzureRoles", "AzureMaxTier", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVAI-005",
                    group: "Security",
                    description: "Agent identities with ownership over apps, service principals, or groups",
                    label: "Owning Other Objects",
                    filters: {
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        GrpOwn: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVAI-006",
                    group: "Security",
                    description: "Agent identities provisioned by a blueprint from a foreign (external) tenant",
                    label: "Foreign Blueprint Origin",
                    filters: {
                        Foreign: "=True"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "Owners", "Sponsors", "AgentUsers", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    id: "PVAI-007",
                    group: "Lifecycle",
                    description: "Enabled but no sign-on activity in the last 180 days.",
                    label: "Inactive Agent Identities",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "Owners", "Sponsors", "AgentUsers", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    id: "PVAI-008",
                    group: "Lifecycle",
                    description: "Agent identities with no sponsor defined",
                    label: "No Sponsor Assigned",
                    filters: {
                        Sponsors: "=0"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "Inactive", "Sponsors", "Owners", "AgentUsers", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "Impact", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Agent Identity Blueprint Principals": [
                {
                    id: "PVBPP-001",
                    group: "Child Identities",
                    description: "Blueprint principals with linked agent identities.",
                    label: "With Agent Identities",
                    filters: {
                        AgentIdentities: ">0"
                    },
                    columns: ["DisplayName", "ParentBlueprintDisplayName", "Enabled", "Foreign", "AgentIdentities", "AgentUsers", "InheritedImpact", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVBPP-002",
                    group: "Child Identities",
                    description: "Blueprint principals with child agent users.",
                    label: "With Agent Users",
                    filters: {
                        AgentUsers: ">0"
                    },
                    columns: ["DisplayName", "ParentBlueprintDisplayName", "Enabled", "Foreign", "AgentIdentities", "AgentUsers", "InheritedImpact", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVBPP-003",
                    group: "Lifecycle",
                    description: "Blueprint principals without linked agent identities.",
                    label: "No Agent Identities",
                    filters: {
                        AgentIdentities: "=0"
                    },
                    columns: ["DisplayName", "ParentBlueprintDisplayName", "Enabled", "Foreign", "CreationInDays", "LastSignInDays", "ApiMedium", "ApiLow", "Impact", "Risk"],
                    sort: { column: "CreationInDays", direction: "desc" }
                },
                {
                    id: "PVBPP-004",
                    group: "Tenant Boundary",
                    description: "Blueprint principals whose parent blueprint is from another tenant.",
                    label: "Foreign Principals",
                    filters: {
                        Foreign: "=True"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "AgentIdentities", "AgentUsers", "Impact", "Likelihood", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVBPP-005",
                    group: "Lifecycle",
                    description: "Enabled blueprint principals with no sign-in activity in the last 180 days.",
                    label: "Inactive Enabled",
                    filters: {
                        Inactive: "=True",
                        Enabled: "=True"
                    },
                    columns: ["DisplayName", "Enabled", "Inactive", "LastSignInDays", "CreationInDays", "AgentIdentities", "AgentUsers", "Impact", "Risk"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    id: "PVBPP-006",
                    group: "API Permissions",
                    description: "Blueprint principals with configured API permissions.",
                    label: "Configured API Permissions",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        ApiDelegatedDangerous: "or_>0",
                        ApiDelegatedHigh: "or_>0",
                        ApiDelegatedMedium: "or_>0"
                    },
                    columns: ["DisplayName", "Enabled", "Foreign", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "ApiDelegatedDangerous", "ApiDelegatedHigh", "ApiDelegatedMedium", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                }
            ],
            "Agent Identity Blueprints": [
                {
                    id: "PVB-001",
                    group: "Child Objects",
                    description: "Blueprints with linked blueprint principals.",
                    label: "With Blueprints Principals",
                    filters: {
                        BlueprintPrincipals: ">0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "BlueprintPrincipals", "AgentIdentities", "AgentUsers", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-002",
                    group: "Child Objects",
                    description: "Blueprints with child agent identities.",
                    label: "With Agent Identities",
                    filters: {
                        AgentIdentities: ">0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "BlueprintPrincipals", "AgentIdentities", "AgentUsers", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-003",
                    group: "Child Objects",
                    description: "Blueprints with child agent users.",
                    label: "With Agent Users",
                    filters: {
                        AgentUsers: ">0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "BlueprintPrincipals", "AgentIdentities", "AgentUsers", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-004",
                    group: "Permissions",
                    description: "Blueprints that allow inherit API permissions to the Agent Identity.",
                    label: "Inheritable Permissions",
                    filters: {
                        InheritableScopes: "or_>0",
                        InheritableRoles: "or_>0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "BlueprintPrincipals", "AgentIdentities", "InheritableScopes", "InheritableRoles", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-005",
                    group: "Credentials",
                    description: "Blueprints with federated credentials, client secrets, or certificates configured.",
                    label: "Credentials Present",
                    filters: {
                        FederatedCreds: "or_>0",
                        SecretsCount: "or_>0",
                        CertsCount: "or_>0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "FederatedCreds", "SecretsCount", "CertsCount", "BlueprintPrincipals", "AgentIdentities", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-006",
                    group: "Credentials",
                    description: "Blueprints with client secrets.",
                    label: "Client Secrets",
                    filters: {
                        SecretsCount: ">0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "SecretsCount", "CertsCount", "FederatedCreds", "CreationInDays", "Impact", "Risk"],
                    sort: { column: "Risk", direction: "desc" }
                },
                {
                    id: "PVB-007",
                    group: "Lifecycle",
                    description: "Blueprints without linked agent identities.",
                    label: "No Agent Identities",
                    filters: {
                        AgentIdentities: "=0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "CreationInDays", "BlueprintPrincipals", "AgentIdentities", "InheritableScopes", "InheritableRoles", "FederatedCreds", "SecretsCount", "CertsCount", "Impact", "Risk"],
                    sort: { column: "CreationInDays", direction: "desc" }
                },
                {
                    id: "PVB-008",
                    group: "Lifecycle",
                    description: "Blueprints without linked blueprint principals.",
                    label: "No Principals",
                    filters: {
                        BlueprintPrincipals: "=0"
                    },
                    columns: ["DisplayName", "SignInAudience", "Enabled", "CreationInDays", "BlueprintPrincipals", "AgentIdentities", "InheritableScopes", "InheritableRoles", "FederatedCreds", "SecretsCount", "CertsCount", "Impact", "Risk"],
                    sort: { column: "CreationInDays", direction: "desc" }
                }
            ]
        };

        //Define columns which are hidden by default
        const defaultHidden = ["DeviceReg", "DeviceOwn", "LicenseStatus", "OwnersSynced", "DefaultMS", "CreationInDays", "AppRoleRequired", "SAML", "RoleAssignable", "LastSignInDays", "CreatedDays", "ParentBlueprintDisplayName", "ForeignAgent","ActiveAssignJustification","AlertAssignEligible","AlertAssignActive", "AlertActivation", "EligibleExpirationTime", "ActiveExpirationTime", "SignInFrequency", "SignInFrequencyInterval", "ApiDelegatedDangerous", "ApiDelegatedHigh", "ApiDelegatedMedium", "ApiDelegatedLow", "ApiDelegatedMisc", "IncUsersViaGroups", "ExcUsersViaGroups", "PerUserMfa", "ExcUsersViaRoles", "IncUsersViaRoles"];

        // Responsive column profiles keyed by currentReportKey from the report manifest.
        // Profiles define which columns are VISIBLE; all unlisted columns are hidden.
        // Applied once at page load — not re-evaluated on resize.
        // Skipped when ?columns= or ?view= is present in the URL.
        // Reset View always returns to full defaults, ignoring this profile.
        // When adding a new column to a report module, add it to the relevant profile(s) here too.
        const responsiveColumnProfiles = {
            // Reports with both laptop (<= 1600px) and compact (<= 1200px) tiers
            "EA": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive",
                        "Owners", "Credentials", "AppOwn", "BlueprintOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiMedium", "ApiDelegated",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "Owners", "Credentials", "AppOwn", "BlueprintOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiDelegated",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "Users": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "UPN", "Enabled", "UserType", "Agent", "OnPrem", "Protected",
                        "GrpMem", "GrpOwn", "EntraMaxTier", "AzureMaxTier",
                        "AppRoles", "AppRegOwn", "BlueprintOwn", "SPOwn",
                        "Inactive", "MfaCap",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "UPN", "Enabled", "UserType", "OnPrem",
                        "GrpMem", "GrpOwn", "EntraMaxTier",  "AzureMaxTier", "AppRegOwn", "BlueprintOwn", "SPOwn",
                        "Inactive", "MfaCap",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "Groups": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "DisplayName", "Type", "OnPrem", "Dynamic",
                        "Visibility", "Protected", "PIM", "AuUnits", "DirectOwners",
                        "Users", "SPCount","NestedGroups",
                        "AppRoles", "CAPs",  "EntraMaxTier", "AzureMaxTier",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "Type", "OnPrem", "Dynamic",
                        "Visibility", "Protected", "PIM", "DirectOwners",
                        "Users", "SPCount", "CAPs", "EntraMaxTier", "AzureMaxTier",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "CAP": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "DisplayName", "UserCoverage", "State", "IncResources", "ExcResources",
                        "IncPlatforms", "ExcPlatforms",
                        "SignInRisk", "UserRisk", "IncNw", "ExcNw", "AuthFlow", "UserActions",
                        "GrantControls", "AuthStrength", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "UserCoverage", "State", "IncResources", "ExcResources",
                        "SignInRisk", "UserRisk", "IncNw", "ExcNw", "AuthFlow", "UserActions",
                        "GrantControls", "AuthStrength", "Warnings"
                    ]
                }
            },
            "AgentIdentities": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive",
                        "AgentUsers", "Owners",
                        "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiMedium", "ApiMisc", "ApiDelegated",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "Foreign", "Enabled", "Inactive",
                        "AgentUsers",
                        "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiDelegated",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "MI": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "DisplayName", "IsExplicit", "GroupMembership", "GroupOwnership",
                        "AppOwnership", "BlueprintOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiMedium", "ApiMisc",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "GroupMembership", "GroupOwnership",
                        "AppOwnership", "BlueprintOwn", "SpOwn", "EntraMaxTier", "AzureMaxTier",
                        "ApiDangerous", "ApiHigh", "ApiMedium",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            // Reports with compact (<= 1200px) tier only — full defaults apply between 1200px and 1600px
            "AR": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "Enabled", "AppLock",
                        "AppRoles", "Owners", "CloudAppAdmins", "AppAdmins",
                        "SecretsCount", "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "AgentIdentityBlueprints": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "SignInAudience", "Enabled", "BlueprintPrincipals", "AgentIdentities",
                        "AgentUsers", "Owners", "InheritableScopes", "InheritableRoles",
                        "FederatedCreds", "SecretsCount", "CertsCount", "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "AgentIdentityBlueprintsPrincipals": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive",
                        "AgentIdentities", "AgentUsers", "AppRoles",
                        "ApiDangerous", "ApiHigh", "ApiMedium", "ApiDelegated",
                        "Impact", "Likelihood", "Risk", "Warnings"
                    ]
                }
            },
            "RoleEntra": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "Role", "RoleTier", "AssignmentType", "ActivatedViaPIM", "Expires", "Principal", "PrincipalType", "Scope"
                    ]
                }
            },
            "RoleAz": {
                laptop: {
                    maxWidth: 1600,
                    columns: [
                        "Scope", "Role", "RoleTier", "Conditions", "AssignmentType", "ActivatedViaPIM", "PrincipalType", "Principal"
                    ]
                },
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "Scope", "Role", "RoleTier", "AssignmentType", "PrincipalType", "Principal"
                    ]
                }
            },
            "PIM": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "Role", "Tier", "Eligible", "Direct",
                        "ActivationAuthContext", "ActivationMFA",
                        "ActivationDuration", "ActivationApproval",
                        "ActiveExpiration", "ActiveAssignMFA", "Warnings"
                    ]
                }
            },
            "PIMGroups": {
                compact: {
                    maxWidth: 1200,
                    columns: [
                        "Group", "Role", "EntraMaxTier", "AzureMaxTier", "Eligible", "Active",
                        "ActivationAuthContext", "ActivationMFA",
                        "ActivationDuration", "ActivationApproval",
                        "ActiveExpiration", "ActiveAssignMFA", "Warnings"
                    ]
                }
            }
        };

        // Returns the matching responsive column list for the given report key, or null if no tier applies.
        function getResponsiveProfile(reportKey) {
            const profile = responsiveColumnProfiles[reportKey];
            if (!profile) return null;
            const vw = window.innerWidth || document.documentElement.clientWidth || 9999;
            if (profile.compact && vw <= profile.compact.maxWidth) return profile.compact.columns;
            if (profile.laptop && vw <= profile.laptop.maxWidth) return profile.laptop.columns;
            return null;
        }

        // Function to obtain the GET parameters from the URL
        function getURLParams() {
            const params = new URLSearchParams(window.location.search);
            const result = {};
            for (const [key, value] of params.entries()) {
                result[key] = value;
            }
            return result;
        }

        //Tooltips for column headers
        const columnTooltips = {
            "AuUnits": "Administrative Units",
            "Impact": "Score representing the potential impact if the object is compromised",
            "Likelihood": "Score representing the likelihood of compromise",
            "Risk": "Calculation: Impact x Likelihood",
            "OnPrem": "Objects synced from on-prem AD",
            "AzureRoles": "Directly or indirectly assigned Azure IAM roles",
            "EntraRoles": "Directly or indirectly assigned Entra ID roles",
            "SAML": "SAML as preferred SSO method",
            "CAPs": "Number of Conditional Access Policies the group is used in",
            "AppLock": "App Instance Property Lock status",
            "DeviceReg": "Devices registered by the user",
            "DeviceOwn": "Devices owned by the user",
            "AppAdmins": "App Admins scoped to tenant or app",
            "CloudAppAdmins": "Cloud App Admins scoped to tenant or app",
            "MfaCap": "User has one or more MFA methods registered",
            "Inactive": "No successful sign-in during the last 180+ days",
            "AppRoles": "Application roles assigned",
            "GrpMem": "Member of groups",
            "GrpOwn": "Owner of groups",
            "SpOwn": "Owned Service Principals",
            "AppOwn": "Owned App Registrations",
            "BlueprintOwn": "Owned Agent Identity Blueprints",
            "AppRegOwn": "Owner of App Registrations",
            "EntraMaxTier": "Highest assigned Entra role tier (directly or through groups)",
            "AzureMaxTier": "Highest assigned Azure role tier (directly or through groups)",
            "SPOwn": "Owner of ServicePrincipals",
            "ApiDeleg": "Unique consented delegated API permissions",
            "PIM": "Onboarded to PIM for Groups",
            "Protected": "Not role assignable, not synced from on-prem, not in a restricted Administrative Unit.\nTherefore: cannot be modified by low-tier admin",
            "Eligible": "Number of eligible role assignments",
            "Active": "Number of currently active assignments",
            "Direct": "Number of directly assigned active role assignments that are not activated via PIM",
            "Activated": "Number of currently active role assignments activated via PIM",
            "AssignmentType": "Activated eligible assignments also appear as active",
            "Conditions": "Has additional conditions",
            "UserCoverage": "Percentage of tenant users covered by the policy after exclusions. External users are only approximated for b2bCollaborationGuest and do not include all types or tenant-specific selections.",
            "InheritableScopes": "Number of APIs for which the blueprint permits child agent identities to inherit delegated permission scopes",
            "InheritableRoles": "Number of APIs for which the blueprint permits child agent identities to inherit application role permissions",
            "Agent": "User object parented to an agent identity (agent user)",
            "ForeignAgent": "Agent user whose parent blueprint principal is foreign"
        };
    
        (function () {    
            const manifestEl = document.getElementById("report-manifest");
            const manifest = manifestEl && manifestEl.textContent ? JSON.parse(manifestEl.textContent) : null;
            window.__reportManifest = manifest;        

            const mainTableDataEl = document.getElementById("mainTableData");
            if (!mainTableDataEl) {
                return;
            }
                
            const container = document.getElementById("mainTableContainer");
            if (!container) {
                return;
            }
                
            let data = JSON.parse(document.getElementById("mainTableData").textContent);
            if (!Array.isArray(data)) {
                data = [data]; // wrap single object into an array
            }

            const rowLowerKeyMap = Object.keys(data[0] || {}).reduce((map, col) => {
                map[col.toLowerCase()] = col;
                return map;
            }, {});

            const columns = Object.keys(data[0] || {});
            const colIndexMap = {};
            for (let i = 0; i < columns.length; i++) {
                colIndexMap[columns[i]] = i;
            }

            const wrapper = container.querySelector("#tableWrapper");
            const pageSizeSelector = container.querySelector("#pageSize");
            const pagination = container.querySelector("#paginationControls");

            let currentPage = 1;
            let rowsPerPage = parseInt(pageSizeSelector.value);
            let filteredData = [...data];
            let currentSort = { column: null, asc: true };
            let columnFilters = {};
            let hiddenColumns = new Set();
            let responsiveProfileApplied = false;
            let filterDebounceTimer = null;

            function normalizeSortColumn(column) {
                if (column == null) return null;
                const desired = String(column).trim().toLowerCase();
                if (!desired) return null;
                return columns.find(col => col.toLowerCase() === desired) || null;
            }

            function isValidSortColumn(column) {
                return normalizeSortColumn(column) !== null;
            }

            function getDefaultSort() {
                const riskColumn = normalizeSortColumn("Risk");
                return riskColumn ? { column: riskColumn, asc: false } : null;
            }

            function sortEquals(a, b) {
                if (!a && !b) return true;
                if (!a || !b) return false;
                return (a.column || null) === (b.column || null) && !!a.asc === !!b.asc;
            }

            function applySort(sort) {
                if (sort && isValidSortColumn(sort.column)) {
                    currentSort = {
                        column: normalizeSortColumn(sort.column),
                        asc: !!sort.asc
                    };
                } else {
                    currentSort = { column: null, asc: true };
                }
            }

            function applyDefaultSort() {
                applySort(getDefaultSort());
            }

            container.addEventListener("input", (e) => {
                const input = e.target;
                if (!input || input.tagName !== "INPUT") return;

                const col = input.getAttribute("data-filter");
                if (!col) return;

                const existingKey = Object.keys(columnFilters).find(k => k.toLowerCase() === col.toLowerCase());
                columnFilters[existingKey || col] = input.value;

                if (filterDebounceTimer) window.clearTimeout(filterDebounceTimer);
                filterDebounceTimer = window.setTimeout(() => {
                    filterData();
                }, 800);
            });


            const columnSelector = document.createElement("div");
            const exportBtn = document.createElement("button");
            const infoBox = document.createElement("div");

            exportBtn.textContent = "\u{1F4BE} Export CSV";
            exportBtn.style.margin = "10px 0";
            infoBox.style.margin = "10px 0";

            exportBtn.onclick = () => {
            const csvRows = [];
            const visibleColumns = getVisibleColumns();
            const special = isRoleAssignmentsReport(window.__reportManifest);

            // ---------------------------
            // RoleAssignmentReports: just visible columns
            // ---------------------------
            if (special) {
                csvRows.push(visibleColumns.join(","));

                filteredData.forEach(row => {
                const line = [];

                visibleColumns.forEach(col => {
                    let val = row[col];

                    // Make Principal human-readable
                    if (col.toLowerCase() === "principal") {
                    val = stripHtmlToText(val);
                    }

                    line.push(`"${String(val ?? "").replace(/"/g, '""')}"`);
                });

                csvRows.push(line.join(","));
                });
            }
            // ---------------------------
            // NORMAL REPORTS: add ID + DisplayName from FIRST COLUMN LINK
            // ---------------------------
            else {
                const linkColumn = columns[0];
                const restVisible = visibleColumns.filter(c => c !== linkColumn);

                csvRows.push(["ID", "DisplayName", ...restVisible].join(","));

                filteredData.forEach(row => {
                const line = [];

                const { id, text } = extractAnchorIdAndText(row[linkColumn]);
                line.push(`"${String(id).replace(/"/g, '""')}"`);
                line.push(`"${String(text).replace(/"/g, '""')}"`);

                restVisible.forEach(col => {
                    const val = row[col];
                    line.push(`"${String(val ?? "").replace(/"/g, '""')}"`);
                });

                csvRows.push(line.join(","));
                });
            }

            // download
            const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;

            const baseName = decodeURIComponent(window.location.pathname
                .split("/")
                .pop()
                .replace(/\.[^/.]+$/, "")) || "export";

            a.download = `${baseName}_table_export.csv`;
            a.click();
            URL.revokeObjectURL(url);
            };



        function applyPredefinedView(view) {
            columnFilters = {};

            // Filters
            Object.entries(view.filters || {}).forEach(([col, val]) => {
                const match = columns.find(k => k.toLowerCase() === col.toLowerCase());
                columnFilters[match || col] = val;
            });

            // Columns
            if (Array.isArray(view.columns)) {
                const allCols = columns;
                const allowed = view.columns
                    .map(v => allCols.find(col => col.toLowerCase() === v.toLowerCase()))
                    .filter(Boolean); // Only valid column names

                if (allowed.length > 0) {
                    hiddenColumns = new Set(allCols.filter(col => !allowed.includes(col)));
                } else {
                    console.warn("No valid matching columns found in view.columns");
                }
            }

            // Sort
            if (view.sort) {
                const sortCol = normalizeSortColumn(view.sort.column);
                if (sortCol) {
                    currentSort.column = sortCol;
                    currentSort.asc = view.sort.direction.toLowerCase() !== "desc";
                }
            }

            filterData();
            createColumnSelector();
        }

        function getReportTypeFromManifest(manifest) {
            if (!manifest) return null;

            var key = String(manifest.currentReportKey || "").trim();
            var name = String(manifest.currentReportName || "").trim();

            if (key === "Users") return "User";
            if (key === "Groups") return "Groups";
            if (key === "EA") return "Enterprise Apps";
            if (key === "MI") return "Managed Identities";
            if (key === "AR") return "App Registrations";
            if (key === "CAP") return "Conditional Access Policies";
            if (key === "PIM") return "PIM";
            if (key === "PIMGroups") return "PIM Groups";
            if (key === "RoleEntra") return "Role Assignments Entra ID";
            if (key === "RoleAz") return "Role Assignments Azure IAM";
            if (key === "AgentIdentities") return "Agent Identities";
            if (key === "AgentIdentityBlueprintsPrincipals") return "Agent Identity Blueprint Principals";
            if (key === "AgentIdentityBlueprints") return "Agent Identity Blueprints";

            var lower = name.toLowerCase();
            if (lower.indexOf("users") !== -1) return "User";
            if (lower.indexOf("groups") !== -1) return "Groups";
            if (lower.indexOf("enterprise") !== -1) return "Enterprise Apps";
            if (lower.indexOf("managed identit") !== -1) return "Managed Identities";
            if (lower.indexOf("app registr") !== -1) return "App Registrations";
            if (lower.indexOf("conditional access") !== -1) return "Conditional Access Policies";
            if (lower.indexOf("pim") !== -1) return "PIM";
            if (lower.indexOf("role assignments entra") !== -1) return "Role Assignments Entra ID";
            if (lower.indexOf("role assignments azure") !== -1) return "Role Assignments Azure IAM";

            return null;
        }

        function isRoleAssignmentsReport(manifest) {
            var type = getReportTypeFromManifest(manifest);
            return type === "Role Assignments Entra ID" || type === "Role Assignments Azure IAM";
        }


        function stripHtmlToText(html) {
            if (html == null) return "";
            const tempDiv = document.createElement("div");
            tempDiv.innerHTML = String(html);
            return (tempDiv.textContent || tempDiv.innerText || "").trim();
            }

            // Extract anchor target + visible text from "<a href=#target>Text</a>".
            // Some reports use non-GUID synthetic detail ids such as policy ids or
            // composite keys, so do not restrict this to GUID-only anchors.
            function extractAnchorIdAndText(cellValue) {
            if (cellValue == null) return { id: "", text: "" };
            const s = String(cellValue);

            // Normal reports: <a href=#target>...</a>
            const m = s.match(/<a\s+href=#([^\s>]+)[^>]*>(.*?)<\/a>/i);
            if (m) return { id: m[1], text: stripHtmlToText(m[2]) };

            // Fallback: treat as plain text
            return { id: "", text: stripHtmlToText(s) };
        }

        function createPresetFilterModal(manifest) {
            var type = getReportTypeFromManifest(manifest);
            if (!type) return;

            var views = predefinedViews[type];
            if (!views || !views.length) return;

            const presetBtn = document.createElement("button");
            presetBtn.textContent = "\uD83E\uDDF0 Preset Views";
            presetBtn.style.margin = "10px 0px";

            const resetViewBtn = document.createElement("button");
            resetViewBtn.textContent = "\uD83D\uDD01 Reset View";
            resetViewBtn.style.margin = "10px 0px";

            const toolbarLeft = document.querySelector(".toolbar .left-section");
            if (toolbarLeft) {
				toolbarLeft.appendChild(presetBtn);
				toolbarLeft.appendChild(resetViewBtn);
			}

            //Resetview button
            resetViewBtn.addEventListener("click", () => {
                columnFilters = {};
                hiddenColumns = new Set();
                defaultHidden.forEach(col => hiddenColumns.add(col));
                applyDefaultSort();
                filterData();
                createColumnSelector();
                if (window.location.protocol !== "file:") history.replaceState(null, "", window.location.pathname);
            });

            // Build grouped items HTML
            const groupMap = new Map();
            views.forEach(v => {
                const g = v.group || "";
                if (!groupMap.has(g)) groupMap.set(g, []);
                groupMap.get(g).push(v);
            });

            let itemsHtml = "";
            let isFirstGroup = true;
            for (const [group, items] of groupMap) {
                if (group) {
                    itemsHtml += `<div class="preset-group-header${isFirstGroup ? " first" : ""}">${group}</div>`;
                }
                items.forEach(v => {
                    itemsHtml += `<button class="preset-btn" data-id="${v.id || ""}" data-label="${v.label}">` +
                        `<span class="preset-btn-label">${v.label}</span>` +
                        (v.description ? `<span class="preset-btn-sub">${v.description}</span>` : "") +
                        `</button>`;
                });
                isFirstGroup = false;
            }

            const modal = document.createElement("div");
            modal.className = "preset-modal hidden";
            modal.innerHTML = `
                <div class="preset-modal-content">
                    <div class="preset-modal-body">${itemsHtml}</div>
                    <div class="preset-modal-footer">
                        <button class="close-preset-modal">\u2716 Close</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            // Toggle visibility
            presetBtn.onclick = () => modal.classList.toggle("hidden");

            // Apply view
            modal.querySelectorAll(".preset-btn").forEach(btn => {
                btn.addEventListener("click", () => {
                    const view = views.find(v => v.id ? v.id === btn.dataset.id : v.label === btn.dataset.label);
                    if (view) {
                        applyPredefinedView(view);
                        if (view.id && window.location.protocol !== "file:") history.replaceState(null, "", "?view=" + view.id);
                    }
                    modal.classList.add("hidden");
                });
            });


            // Close on outside click
            document.addEventListener("click", (e) => {
                const isInside = modal.contains(e.target);
                const isButton = e.target === presetBtn;
                if (!isInside && !isButton) {
                    modal.classList.add("hidden");
                }
            });

            // Close on
            modal.querySelector(".close-preset-modal").addEventListener("click", () => {
                modal.classList.add("hidden");
            });
        }

        // Top toolbar
        function createToolbar() {
            const toolbar = document.createElement("div");
            toolbar.className = "toolbar";

            const leftSection = document.createElement("div");
            leftSection.className = "left-section";

            const rightSection = document.createElement("div");
            rightSection.className = "right-section";

            // Page size selector
            const pageSizeWrapper = container.querySelector(".page-size-wrapper") || pageSizeSelector;
            leftSection.appendChild(pageSizeWrapper);

            // Column toggle menu
            const columnWrapper = document.createElement("div");
            columnWrapper.appendChild(columnSelector);
            leftSection.appendChild(columnWrapper);

            // Export button
            leftSection.appendChild(exportBtn);
            const shareBtn = document.createElement("button");
            shareBtn.textContent = "\u{1F441} Share View";
            shareBtn.style.margin = "10px 0px";
            leftSection.appendChild(shareBtn);

            // Info box ("Showing entries")
            infoBox.className = "info-box";
            rightSection.appendChild(infoBox);

            toolbar.appendChild(leftSection);
            toolbar.appendChild(rightSection);

            container.insertBefore(toolbar, wrapper);

            shareBtn.onclick = (event) => {
                const url = new URL(window.location.href);
                url.search = "";

                // Add filters
                Object.entries(columnFilters).forEach(([key, val]) => {
                    if (!val.trim()) return;

                    const match = val.match(/^(or_|group\d+_)(.+)$/i);
                    if (match) {
                        const [_, groupPrefix, realVal] = match;
                        url.searchParams.set(`${groupPrefix}${key}`, realVal);
                    } else {
                        url.searchParams.set(key, val.trim());
                    }
                });

                // Add visible columns
                const visibleCols = getVisibleColumns();
                url.searchParams.set("columns", visibleCols.join(","));

                // Add sort info
                const defaultSort = getDefaultSort();
                if (isValidSortColumn(currentSort.column) && !sortEquals(currentSort, defaultSort)) {
                    url.searchParams.set("sort", currentSort.column);
                    url.searchParams.set("sortDir", currentSort.asc ? "asc" : "desc");
                }

                // Copy to clipboard
                const copyValue = (event && (event.ctrlKey || event.metaKey)) ? url.search : url.toString();
                navigator.clipboard.writeText(copyValue).then(() => {
                    showToast("View (Filter, Columns, Sorting) link copied to clipboard");
                }).catch(err => {
                    console.error("Clipboard write failed", err);
                    showToast("\u{26A0} Failed to copy URL", 4000);
                });
            };

        }

        function getVisibleColumns() {
            return columns.filter(col => !hiddenColumns.has(col));
        }
        
        // Renders main table
        function renderTable() {
            let start = (currentPage - 1) * rowsPerPage;
            let end = start + rowsPerPage;
            let pageData = filteredData.slice(start, end);

            if (pageData.length === 0 && currentPage > 1) {
                currentPage = 1;
                return renderTable();
            }

            const visibleCols = getVisibleColumns();

            //Capture active input to re-apply after filtering
            const activeElement = document.activeElement;
            let activeFilter = null;
            let caretPos = null;

            if (activeElement && activeElement.tagName === "INPUT" && activeElement.dataset.filter) {
                activeFilter = activeElement.dataset.filter;
                caretPos = activeElement.selectionStart;
            }

            let html = '<table class="overview-table"><thead><tr>';
            visibleCols.forEach(col => {
                const tooltip = columnTooltips[col] || "";
                const isSorted = currentSort.column === col;
                const sortIcon = isSorted
                    ? `<span style="font-size: 12px;"> ${currentSort.asc ? "\u{25B2}" : "\u{25BC}"}</span>`
                    : "";
                const colLower = col.toLowerCase();
                const isCopyable = colLower.includes("displayname") || colLower.includes("warnings") ||
                    colLower === "role" || colLower === "principal" || colLower === "scope" ||
                    colLower === "namelink" || colLower === "apipermissiondescription" ||
                    colLower.startsWith("upn") || colLower.includes("scoperesolved") ||
                    colLower === "name" || colLower.endsWith("name");
                const copyBtn = isCopyable
                    ? `<span class="copy-col-btn" data-copy-col="${col}" title="Copy column values">\u{1F4CB}</span>`
                    : "";
                html += `<th data-col="${col}" title="${tooltip}">${col}${sortIcon}${copyBtn}</th>`;
            });
            html += '</tr><tr>';
            visibleCols.forEach(col => {
                const val = Object.entries(columnFilters).find(([k]) => k.toLowerCase() === col.toLowerCase())?.[1] || '';
                html += `<th><input data-filter="${col}" value="${val}" placeholder="Filter..." style="width: 90%;" /></th>`;
            });
            html += '</tr></thead><tbody>';

            pageData.forEach(row => {
                html += '<tr>';
                visibleCols.forEach(col => {
                    const val = row[col];
                    const columnHeader = columns[colIndexMap[col]];
                    const columnHeaderLower = (columnHeader || "").toLowerCase();

                    const isLeftAligned =
                        columnHeader === undefined || // no matching header (cell without header)
                        columnHeaderLower.includes("displayname") ||
                        columnHeaderLower.includes("warnings") ||
                        columnHeaderLower === "group" ||
                        columnHeaderLower === "role" ||
                        columnHeaderLower === "principal" ||
                        columnHeaderLower === "scope" ||
                        columnHeaderLower === "namelink" ||
                        columnHeaderLower === "apipermissiondescription" ||
                        columnHeaderLower.startsWith("upn") ||
                        columnHeaderLower.includes("scoperesolved");

                    const cellClass = isLeftAligned ? "left-align" : "";
                    html += `<td class="${cellClass}">${val}</td>`;
                });
                html += '</tr>';
            });

            html += '</tbody></table>';
            wrapper.innerHTML = html;

            // Sorting
            container.querySelectorAll("thead tr:first-child th").forEach(th => {
                th.onclick = () => {
                    const col = th.getAttribute("data-col");
                    if (currentSort.column === col) {
                        currentSort.asc = !currentSort.asc;
                    } else {
                        currentSort.column = col;
                        currentSort.asc = false;
                    }
                    sortData();
                    renderTable();
                };
            });

            // Copy column buttons
            container.querySelectorAll("thead tr:first-child th .copy-col-btn").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const col = btn.getAttribute("data-copy-col");
                    const values = filteredData
                        .map(row => stripHtmlToText(String(row[col] ?? "")))
                        .filter(v => v !== "");
                    navigator.clipboard.writeText(values.join("\n")).then(() => {
                        btn.textContent = "\u2713";
                        setTimeout(() => { btn.textContent = "\u{1F4CB}"; }, 1500);
                    });
                });
            });

            renderPagination();
            renderInfo(start, end);

            const pageIds = pageData
                .map(row => extractAnchorIdAndText(row[columns[0]]).id)
                .filter(Boolean);
            if (window.__syncDetailsForCurrentPage) {
                window.__syncDetailsForCurrentPage(pageIds);
            } else {
                window.__pendingDetailIds = pageIds;
            }

            const table = wrapper.querySelector("table");
            if (table) {
                const headerCells = table.querySelectorAll("thead tr:first-child th");
                const headers = Array.prototype.map.call(headerCells, th => th.getAttribute("data-col") || (th.textContent || "").trim());
                window.requestAnimationFrame(() => colorCells(table, headers));
            }

            //Re-apply filter to focus
            if (activeFilter) {
                const newInput = container.querySelector(`input[data-filter="${activeFilter}"]`);
                if (newInput) {
                    newInput.focus();
                    if (caretPos !== null) {
                        newInput.setSelectionRange(caretPos, caretPos);
                    }
                }
            }        
        }

        
        //Pagination for the main table
        function renderPagination() {
            const totalPages = Math.max(1, Math.ceil(filteredData.length / rowsPerPage));
            let html = '';

            if (currentPage > 1) {
                html += `<button onclick="goToPage(${currentPage - 1})">Previous</button>`;
            }
            html += `<span> Page ${Math.min(currentPage, totalPages)} of ${totalPages} </span>`;

            if (currentPage < totalPages) {
                html += `<button onclick="goToPage(${currentPage + 1})">Next</button>`;
            }
            pagination.innerHTML = html;
        }

        
        // Displays how many entries are shown (e.g., "Showing 1-10 of 50 entries")
        function renderInfo(start, end) {
            const shownStart = filteredData.length === 0 ? 0 : start + 1;
            const shownEnd = Math.min(end, filteredData.length);
            const isFiltered = filteredData.length < data.length;
            infoBox.textContent = `Showing ${shownStart}-${shownEnd} of ${filteredData.length} entries` +
                (isFiltered ? ` (filtered from ${data.length})` : "");
        }

        window.goToPage = function (page) {
            currentPage = page;
            renderTable();
        };
        
        //MainTable sort function (special handling of cells containing links)
        function sortData() {
            const { column, asc } = currentSort;
            if (!column) return;
            const isTierColumn = ["entramaxtier", "azuremaxtier"].includes(String(column).toLowerCase());

            function normalizeApproximateDisplay(val) {
                return String(val ?? '').trim().replace(/^[~≈]\s*/, '');
            }

            function extractText(val) {
                if (typeof val === "string") {
                    // Extract text inside anchor if present
                    const match = val.match(/<a[^>]*>(.*?)<\/a>/i);
                    return normalizeApproximateDisplay(match ? match[1] : val);
                }
                return normalizeApproximateDisplay(val ?? '');
            }

            function getTierRank(val) {
                const text = String(val ?? "").trim().toLowerCase();
                const tierMatch = text.match(/^tier-(\d+)$/);
                if (tierMatch) return parseInt(tierMatch[1], 10);
                if (/^\d+$/.test(text)) return parseInt(text, 10);
                if (text === "?" || text === "tier?" || text === "uncategorized") return 98;
                if (text === "-" || text === "") return 99;
                return 97;
            }

            filteredData.sort((a, b) => {
                const valA = extractText(a[column]);
                const valB = extractText(b[column]);

                const numA = parseFloat(valA);
                const numB = parseFloat(valB);
                const isNumA = !isNaN(numA);
                const isNumB = !isNaN(numB);

                let result;
                if (isTierColumn) {
                    const tierA = getTierRank(valA);
                    const tierB = getTierRank(valB);
                    result = tierA - tierB;
                    if (result === 0) {
                        result = String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' });
                    }
                } else if (isNumA && isNumB) {
                    result = numA - numB;
                } else {
                    result = String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' });
                }

                // Tier columns are security-priority ordered: descending should show Tier-0 first.
                if (isTierColumn) {
                    return asc ? -result : result;
                }

                return asc ? result : -result;
            });
        }
        function parseOperatorFilter(input, rawValue) {
            // Extract visible text only (e.g., from anchor tags)
            function extractText(html) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;
                return tempDiv.textContent || tempDiv.innerText || '';
            }

            function normalizeApproximateDisplay(val) {
                return String(val ?? '').trim().replace(/^[~≈]\s*/, '');
            }

            // Support simple OR: "value1 || value2"
            if (input.includes('||')) {
                return input.split('||').some(part => parseOperatorFilter(part.trim(), rawValue));
            }
            if (input.includes('&&')) {
                return input.split('&&').map(part => part.trim()).filter(Boolean).every(part => parseOperatorFilter(part, rawValue));
            }
            const visibleText = extractText(rawValue).trim();
            const normalizedVisibleText = normalizeApproximateDisplay(visibleText);
            const valStr = visibleText.toLowerCase();
            const rawStr = String(rawValue).toLowerCase(); // includes HTML
            const lowerInput = input.toLowerCase();

            // Handle "=empty" and "!=empty"
            if (input.trim().toLowerCase() === "=empty") {
                return !rawStr || rawStr === "";
            }
            if (input.trim().toLowerCase() === "!=empty") {
                return !!rawStr && rawStr !== "";
            }

            // Match standard operators: =, >, <, >=, <=, ^, $, plus negated versions: !=, !^, !$
            const operatorMatch = input.match(/^(!?)([<>]=?|=|\^|\$)\s*(.+)$/);
            if (operatorMatch) {
                const [, negate, op, rawFilter] = operatorMatch;
                const num = parseFloat(rawFilter);
                const isNumeric = !isNaN(num);
                const filterStr = rawFilter.toLowerCase();

                let result = false;

                switch (op) {
                    case '=':
                        if (isNumeric && !isNaN(parseFloat(normalizedVisibleText))) {
                            result = parseFloat(normalizedVisibleText) === num;
                        } else {
                            result = valStr === filterStr;
                        }
                        break;
                    case '<':
                        result = isNumeric && parseFloat(normalizedVisibleText) < num;
                        break;
                    case '<=':
                        result = isNumeric && parseFloat(normalizedVisibleText) <= num;
                        break;
                    case '>':
                        result = isNumeric && parseFloat(normalizedVisibleText) > num;
                        break;
                    case '>=':
                        result = isNumeric && parseFloat(normalizedVisibleText) >= num;
                        break;
                    case '^':
                        result = valStr.startsWith(filterStr);
                        break;
                    case '$':
                        result = valStr.endsWith(filterStr);
                        break;
                }

                return negate ? !result : result;
            }

            // Handle general "does not contain" (!value with no operator)
            if (lowerInput.startsWith('!')) {
                const negatedFilter = lowerInput.slice(1);
                return !rawStr.includes(negatedFilter);
            }

            // Default: contains → search raw HTML (so href/id is searchable)
            return rawStr.includes(lowerInput);
        }

        
        // Applies per-column filters
        function filterData() {
            const groups = {}; // { groupName: [ { col, input } ] }

            Object.entries(columnFilters).forEach(([colKey, input]) => {
                if (!input.trim()) return;

                const match = input.match(/^(or_|group\d+_)(.+)$/i); // match prefix inside input
                if (match) {
                    const [, groupPrefix, innerInput] = match;
                    const groupName = groupPrefix.slice(0, -1); // remove trailing _
                    if (!groups[groupName]) groups[groupName] = [];
                    groups[groupName].push({ col: colKey, input: innerInput });
                } else {
                    if (!groups.default) groups.default = [];
                    groups.default.push({ col: colKey, input });
                }
            });

            filteredData = data.filter(row => {
                const defaultPass = (groups.default || []).every(f => {
                    const colMatch = rowLowerKeyMap[String(f.col || "").toLowerCase()];
                    if (!colMatch) return false;
                    return parseOperatorFilter(f.input.trim(), row[colMatch]);
                });

                if (!defaultPass) return false;

                const orGroups = Object.entries(groups).filter(([g]) => g !== "default");
                for (const [groupName, filters] of orGroups) {
                    const groupPass = filters.some(f => {
                        const colMatch = rowLowerKeyMap[String(f.col || "").toLowerCase()];
                        if (!colMatch) return false;
                        return parseOperatorFilter(f.input.trim(), row[colMatch]);
                    });
                    if (!groupPass) return false;
                }

                return true;
            });

            currentPage = 1;
            sortData();
            renderTable();

            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) loadingOverlay.style.display = 'none';
        }

        function updateColumnCountLabel(button, allCols) {
            const visibleCount = allCols.filter(col => !hiddenColumns.has(col)).length;
            button.textContent = `\u2699\uFE0F Columns (${visibleCount}/${allCols.length}) \u25BC`;
        }

        // Dropdown for toggling column visibility
        function createColumnSelector() {
            const wrapperDiv = document.createElement("div");
            wrapperDiv.className = "column-toggle-wrapper";

            const toggleButton = document.createElement("button");
            toggleButton.className = "column-toggle-button";

            const allColumns = columns;
            updateColumnCountLabel(toggleButton, allColumns); // INITIAL count

            wrapperDiv.appendChild(toggleButton);

            const menu = document.createElement("div");
            menu.className = "column-toggle-menu";

            const checkboxes = {};

            // Select/Deselect All
            const toggleAllCheckbox = document.createElement("input");
            toggleAllCheckbox.type = "checkbox";
            toggleAllCheckbox.checked = allColumns.every(c => !hiddenColumns.has(c));
            toggleAllCheckbox.onchange = () => {
                const checked = toggleAllCheckbox.checked;
                allColumns.forEach(col => {
                    checkboxes[col].checked = checked;
                    if (checked) hiddenColumns.delete(col);
                    else hiddenColumns.add(col);
                });
                updateColumnCountLabel(toggleButton, allColumns);
                renderTable();
            };

            const toggleAllWrapper = document.createElement("label");
            toggleAllWrapper.appendChild(toggleAllCheckbox);
            toggleAllWrapper.appendChild(document.createTextNode(" Select All"));
            menu.appendChild(toggleAllWrapper);
            menu.appendChild(document.createElement("hr"));

            // Individual columns
            allColumns.forEach(col => {
                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = !hiddenColumns.has(col);
                checkboxes[col] = checkbox;

                checkbox.onchange = () => {
                    if (!checkbox.checked) hiddenColumns.add(col);
                    else hiddenColumns.delete(col);
                    updateColumnCountLabel(toggleButton, allColumns);
                    renderTable();
                    toggleAllCheckbox.checked = allColumns.every(c => checkboxes[c].checked);
                };

                const label = document.createElement("label");
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(" " + col));
                label.style.display = "block";
                label.style.margin = "4px 0";
                menu.appendChild(label);
            });

            wrapperDiv.appendChild(menu);
            columnSelector.innerHTML = "";
            columnSelector.appendChild(wrapperDiv);

            toggleButton.addEventListener("click", () => {
                wrapperDiv.classList.toggle("show");
            });

            document.addEventListener("click", (e) => {
                if (!wrapperDiv.contains(e.target)) {
                    wrapperDiv.classList.remove("show");
                }
            });
        }



        // Event: Page size change
        pageSizeSelector.addEventListener("change", () => {
            rowsPerPage = parseInt(pageSizeSelector.value);
            currentPage = 1;
            renderTable();
        });

        //Apply columns selection based on GET parameters
        const urlParams = getURLParams();

        // Only apply defaultHidden if no `columns` param is present
        if (!urlParams.columns) {
            defaultHidden.forEach(col => hiddenColumns.add(col));
        }

        const columnParam = urlParams.columns;
        if (columnParam) {
            const allowedCols = columnParam.split(',').map(c => c.trim().toLowerCase());
            const allCols = columns;

            allCols.forEach(col => {
                if (!allowedCols.includes(col.toLowerCase())) {
                    hiddenColumns.add(col);
                }
            });
        }

        // Apply responsive column profile when no explicit column or view override is present.
        // Evaluated once at load time — not re-evaluated on resize.
        if (!urlParams.columns && !urlParams.view) {
            const profileColumns = getResponsiveProfile(manifest && manifest.currentReportKey);
            if (profileColumns && profileColumns.length > 0) {
                const visibleSet = new Set(profileColumns.map(v => v.toLowerCase()));
                hiddenColumns = new Set(columns.filter(col => !visibleSet.has(col.toLowerCase())));
                defaultHidden.forEach(col => hiddenColumns.add(col)); // ensure defaultHidden columns stay hidden regardless of profile content
                responsiveProfileApplied = true;
            }
        }

        //Apply filters based on GET parameters
        const lowerKeys = rowLowerKeyMap;

        Object.entries(urlParams).forEach(([key, value]) => {
            const match = key.match(/^(or|group\d+)_(.+)$/i);
            if (match) {
                const [, groupName, column] = match;
                const colKey = lowerKeys[column.toLowerCase()] || column;
                // Preserve grouped filter value as-is:
                // - `or_State=enabled` -> `or_enabled` (contains)
                // - `or_State==enabled` -> `or_=enabled` (explicit equals)
                // This avoids changing semantics when round-tripping Share View URLs.
                columnFilters[colKey] = `${groupName}_${value}`;
            } else {
                const colKey = lowerKeys[key.toLowerCase()];
                if (colKey) {
                    columnFilters[colKey] = value;
                }
            }
        });

        //Apply sort based on GET parameters
        if (urlParams.sort) {
            const sortCol = normalizeSortColumn(urlParams.sort);
            const sortDir = (urlParams.sortDir || "asc").toLowerCase();

            if (sortCol) {
                currentSort.column = sortCol;
                currentSort.asc = sortDir !== "desc";
            } else {
                applyDefaultSort();
            }
        } else {
            applyDefaultSort();
        }
 
        // Init
        createColumnSelector();
        createToolbar();
        createPresetFilterModal(manifest);

        if (urlParams.view) {
            var allViews = predefinedViews[getReportTypeFromManifest(manifest)] || [];
            var viewFromUrl = allViews.find(v => v.id === urlParams.view);
            if (viewFromUrl) applyPredefinedView(viewFromUrl);
        }

        filterData();
        })();

        // ###################################### SECTION for DETAILS ######################################
        const objectDataEl = document.getElementById('object-data');
        let objects = [];

        if (objectDataEl && objectDataEl.textContent.trim()) {
            try {
                const parsedJson = JSON.parse(objectDataEl.textContent);
                objects = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
            } catch (e) {
                console.warn("JSON parsing failed for object-data:", e);
                objects = [];
            }
        }

        const objectContainer = document.getElementById('object-container');

        if (objectContainer) {
            objectContainer.innerHTML = '';

            const updateDetailsInfo = () => {
                const infoEl = document.getElementById('details-info');
                if (!infoEl) return;
                const total = objectContainer.querySelectorAll('details').length;
                const shownStart = total === 0 ? 0 : 1;
                const shownEnd = total;
                infoEl.textContent = `Showing ${shownStart}-${shownEnd} of ${total} entries`;
            };

            const objectsById = new Map();
            objects.forEach(obj => {
                const objectId = obj["Object ID"] || obj["ObjectId"] || obj["Id"];
                if (objectId) {
                    objectsById.set(String(objectId), obj);
                }
            });
            window.__objectsById = objectsById;

            const isCapEffectiveTargetingSection = (key, value) => {
                const manifest = window.__reportManifest;
                const reportKey = manifest && manifest.currentReportKey ? String(manifest.currentReportKey).trim() : "";
                return reportKey === "CAP" && key === "Effective Targeting (Users)" && Array.isArray(value);
            };

            const parseCapTargetingDisplayNumber = (value) => {
                const normalized = String(value ?? "")
                    .replace(/^\s*~\s*/, "")
                    .trim();

                if (!normalized || normalized === "-" || normalized.toLowerCase() === "none") {
                    return null;
                }

                const match = normalized.match(/\d+(?:\.\d+)?/);
                return match ? Number(match[0]) : null;
            };

            const hasMeaningfulCapTargetingRowValues = (values) => {
                return values.some(value => {
                    if (value === null || value === undefined) return false;
                    const text = String(value).trim();
                    if (!text || text === "-") return false;
                    return text !== "0" && text !== "0.0" && text !== "0.0%";
                });
            };

            const appendCapTargetingTable = (section, caption, headers, rows, totalRowIndexes) => {
                if (!rows || rows.length === 0) return;

                const label = document.createElement("div");
                label.className = "cap-targeting-caption";
                label.textContent = caption;
                section.appendChild(label);

                const table = document.createElement("table");
                table.className = "property-table cap-targeting-table";

                const headerRow = table.insertRow();
                headers.forEach(text => {
                    const th = document.createElement("th");
                    th.textContent = text;
                    headerRow.appendChild(th);
                });

                rows.forEach((values, rowIndex) => {
                    const row = table.insertRow();
                    if (Array.isArray(totalRowIndexes) && totalRowIndexes.includes(rowIndex)) {
                        row.className = "cap-targeting-total";
                    }

                    values.forEach((value, cellIndex) => {
                        const cell = row.insertCell();
                        if (cellIndex === 0) {
                            cell.classList.add("left-align");
                        } else {
                            cell.classList.add("cap-targeting-number");
                        }

                        if (String(value ?? "").trim() === "-") {
                            cell.classList.add("cap-targeting-muted");
                        }

                        if (typeof value === "string" && value.startsWith("<a")) {
                            cell.innerHTML = value;
                        } else {
                            cell.textContent = value ?? "";
                        }
                    });
                });

                section.appendChild(table);
            };

            const renderCapEffectiveTargetingDetails = (rows, notes) => {
                const section = document.createElement("div");
                const heading = document.createElement("h3");
                heading.textContent = "Effective Targeting (Users)";
                section.appendChild(heading);

                const included = rows.find(row => String(row.Scope || "").trim().toLowerCase() === "included") || {};
                const excluded = rows.find(row => String(row.Scope || "").trim().toLowerCase() === "excluded") || {};
                const total = rows.find(row => String(row.Scope || "").trim().toLowerCase() === "total") || {};

                const totalEffectiveUsers = parseCapTargetingDisplayNumber(total.EffectiveUsers);
                const uncoveredUsers = parseCapTargetingDisplayNumber(total.UncoveredUsers);
                const totalUsers = (totalEffectiveUsers !== null && uncoveredUsers !== null)
                    ? totalEffectiveUsers + uncoveredUsers
                    : null;

                const summaryUserCoverage = totalUsers !== null
                    ? `${total.UserCoverage} (${total.EffectiveUsers} / ${totalUsers})`
                    : (total.UserCoverage ?? "");

                const summaryRows = [
                    ["UserCoverage", summaryUserCoverage],
                    ["Included Effective Users", included.EffectiveUsers ?? ""],
                    ["Excluded Effective Users", excluded.EffectiveUsers ?? ""],
                    ["Total Uncovered Users", total.UncoveredUsers ?? ""]
                ];
                appendCapTargetingTable(section, "Summary", ["Metric", "Value"], summaryRows, [3]);

                const breakdownRows = [
                    ["Direct Users", included.DirectUsers ?? "-", excluded.DirectUsers ?? "-"],
                    ["Users from Groups", included.UsersViaGroups ?? "-", excluded.UsersViaGroups ?? "-"],
                    ["Users from Roles", included.UsersViaRoles ?? "-", excluded.UsersViaRoles ?? "-"],
                    ["External Users", included.UsersViaExternalCategories ?? "-", excluded.UsersViaExternalCategories ?? "-"],
                    ["Deduplicated Overlap", included.Overlap ?? "-", excluded.Overlap ?? "-"]
                ];
                appendCapTargetingTable(section, "Breakdown", ["Metric", "Included", "Excluded"], breakdownRows);

                const eligibleRows = [
                    ["Eligible via Groups", included.PotentialUsersViaGroups ?? "-", excluded.PotentialUsersViaGroups ?? "-"],
                    ["Eligible via Roles", included.PotentialUsersViaRoles ?? "-", excluded.PotentialUsersViaRoles ?? "-"]
                ].filter(row => hasMeaningfulCapTargetingRowValues(row.slice(1)));
                appendCapTargetingTable(section, "Eligible But Not Currently Effective", ["Metric", "Included", "Excluded"], eligibleRows);

                if (notes) {
                    const notesLabel = document.createElement("div");
                    notesLabel.className = "cap-targeting-caption";
                    notesLabel.textContent = "Notes";
                    section.appendChild(notesLabel);

                    String(notes)
                        .split(/\r?\n/)
                        .map(line => line.trim())
                        .filter(Boolean)
                        .forEach(line => {
                            const noteEl = document.createElement("p");
                            noteEl.className = "detail-note";
                            noteEl.textContent = line;
                            section.appendChild(noteEl);
                        });
                }

                return section;
            };

            const renderDetailsTable = (title, data) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                const header = table.insertRow();
                Object.keys(data[0]).forEach(key => {
                    const th = document.createElement('th');
                    th.textContent = key;
                    header.appendChild(th);
                });

                data.forEach(obj => {
                    const row = table.insertRow();
                    Object.values(obj).forEach(value => {
                        const cell = row.insertCell();
                        cell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                    });
                });

                section.appendChild(table);
                return section;
            };

            const renderDetailsContent = (detailsEl, obj) => {
                if (!detailsEl || !obj || detailsEl.dataset.rendered === "true") return;

                for (let [key, value] of Object.entries(obj)) {
                    key = key.trim();
                    if (key === "Object Name" || key === "Object ID" || key === "ObjectId" || key === "Id") continue;
                    if (!value || (Array.isArray(value) && value.length === 0)) continue;

                    if (isCapEffectiveTargetingSection(key, value)) {
                        detailsEl.appendChild(renderCapEffectiveTargetingDetails(value, obj["Effective Targeting (Users) Notes"]));
                        continue;
                    }

                    if (key === "Effective Targeting (Users) Notes" && isCapEffectiveTargetingSection("Effective Targeting (Users)", obj["Effective Targeting (Users)"])) {
                        continue;
                    }

                    if (Array.isArray(value)) {
                        const allStrings = value.every(v => typeof v === 'string');
                        const objectsOnly = value.filter(v => typeof v === 'object');

                        if (objectsOnly.length) {
                            detailsEl.appendChild(renderDetailsTable(key, objectsOnly));
                        } else if (allStrings) {
                            detailsEl.appendChild(renderPreBlock(key, value));
                        }
                    } else if (typeof value === 'object') {
                        if (key === "General Information") {
                            detailsEl.appendChild(renderVerticalTable(key, value));
                        } else {
                            detailsEl.appendChild(renderDetailsTable(key, [value]));
                        }
                    } else if (typeof value === 'string') {
                        const noteEl = document.createElement('p');
                        noteEl.className = 'detail-note';
                        noteEl.textContent = value;
                        detailsEl.appendChild(noteEl);
                    }
                }

                detailsEl.dataset.rendered = "true";
            };
            window.__renderDetailsContent = renderDetailsContent;

            // Render vertical table
            const renderVerticalTable = (title, obj) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                for (const [key, value] of Object.entries(obj)) {
                    const row = table.insertRow();
                    const keyCell = row.insertCell();
                    keyCell.textContent = key;

                    const valueCell = row.insertCell();
                    valueCell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                }

                section.appendChild(table);
                return section;
            };

            const createDetailsShell = (obj) => {
                const details = document.createElement('details');
                const objectId = obj["Object ID"] || obj["ObjectId"] || obj["Id"];
                details.id = objectId;
                const summary = document.createElement('summary');
                summary.textContent = obj["Object Name"] || objectId;
                details.appendChild(summary);

                details.addEventListener('toggle', () => {
                    if (details.open) {
                        renderDetailsContent(details, obj);
                    }
                });

                return details;
            };

            window.__syncDetailsForCurrentPage = (ids) => {
                const uniqueIds = Array.isArray(ids) ? Array.from(new Set(ids.map(String))) : [];
                objectContainer.innerHTML = '';

                uniqueIds.forEach(id => {
                    const obj = objectsById.get(id);
                    if (!obj) return;
                    const details = createDetailsShell(obj);
                    objectContainer.appendChild(details);
                });

                if (window.location.hash) {
                    const targetId = window.location.hash.replace('#', '');
                    if (targetId && !uniqueIds.includes(targetId) && objectsById.has(targetId)) {
                        const obj = objectsById.get(targetId);
                        const details = createDetailsShell(obj);
                        objectContainer.appendChild(details);
                    }
                }

                updateDetailsInfo();
            };

            if (window.__pendingDetailIds) {
                window.__syncDetailsForCurrentPage(window.__pendingDetailIds);
                delete window.__pendingDetailIds;
            }


        } else {
            console.warn("Element with id 'object-container' does not exist.");
        }


        function scrollToObjectByHash() {
            const targetId = window.location.hash.replace('#', '');
            if (!targetId) return;

            let targetElement = document.getElementById(targetId);
            if (!targetElement && window.__syncDetailsForCurrentPage) {
                window.__syncDetailsForCurrentPage([targetId]);
                targetElement = document.getElementById(targetId);
            }

            if (targetElement) {
                if (targetElement.dataset.rendered !== "true" && window.__renderDetailsContent && window.__objectsById) {
                    const obj = window.__objectsById.get(targetId);
                    if (obj) {
                        window.__renderDetailsContent(targetElement, obj);
                    }
                }

                targetElement.open = true;
                setTimeout(() => {
                    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        }
        
        //YAML rendering CAP
        function renderPreBlock(title, lines) {
            const section = document.createElement('div');
            const heading = document.createElement('h3');
            heading.textContent = title;
            section.appendChild(heading);

            const pre = document.createElement('pre');
            pre.className = 'yaml-block';

            // Join lines with newlines — keep them raw so links render
            pre.innerHTML = lines.join('\n');

            section.appendChild(pre);
            return section;
        }

        window.addEventListener('DOMContentLoaded', scrollToObjectByHash);
        window.addEventListener('hashchange', scrollToObjectByHash);

        let expandedState = false; // false = collapsed, true = expanded

        function toggleAll() {
            const allDetails = document.querySelectorAll('details');

            if (!expandedState && allDetails.length >= 2000) {
                const confirmExpand = confirm(
                    `Warning: Expanding ${allDetails.length} objects at once may slow down the page.\n\nDo you want to continue?`
                );
                if (!confirmExpand) return;
            }

            allDetails.forEach(d => d.open = !expandedState);
            expandedState = !expandedState;

            // Update button label
            const btn = document.getElementById('toggle-expand');
            btn.textContent = expandedState ? 'Collapse All' : 'Expand All';
        }

        document.addEventListener("DOMContentLoaded", () => {
            const toggleExpandBtn = document.getElementById('toggle-expand');
            if (toggleExpandBtn) {
                toggleExpandBtn.addEventListener('click', toggleAll);
            }

            // Detail full-text search
            const searchInput    = document.getElementById('details-search');
            const searchClearBtn = document.getElementById('details-search-clear');
            const scopeBtns      = document.querySelectorAll('.detail-scope-toggle .scope-btn');

            if (searchInput && searchClearBtn && scopeBtns.length &&
                typeof window.__syncDetailsForCurrentPage === "function") {

                window.__detailSearchMode = "current";

                // Capture IDs already rendered by the pre-DOMContentLoaded __pendingDetailIds call,
                // which ran before the wrapper was installed and couldn't update lastSyncedDetailIds.
                const _objectContainer = document.getElementById('object-container');
                window.__lastSyncedDetailIds = _objectContainer
                    ? Array.from(_objectContainer.querySelectorAll('details'))
                          .map(d => d.id).filter(Boolean)
                    : [];

                const _origSync = window.__syncDetailsForCurrentPage;

                // Reusable detached element for HTML stripping — created once, shared across all calls.
                const _stripEl = document.createElement('div');

                // Recursively collect all primitive values from an object as lowercase strings.
                // Used so that ^, $, = operators match against individual field values
                // rather than the full JSON blob. HTML is stripped so that link-wrapped
                // values (e.g. <a href="...">GlobalAdministrator</a>) match correctly.
                function extractDetailValues(obj) {
                    function stripHtml(str) {
                        _stripEl.innerHTML = str;
                        return _stripEl.textContent || _stripEl.innerText || '';
                    }
                    const values = [];
                    function walk(val) {
                        if (val === null || val === undefined) return;
                        if (typeof val === 'string') {
                            const text = val.includes('<') ? stripHtml(val) : val;
                            values.push(text.toLowerCase());
                            return;
                        }
                        if (typeof val === 'number' || typeof val === 'boolean') {
                            values.push(String(val).toLowerCase());
                            return;
                        }
                        if (Array.isArray(val)) { val.forEach(walk); return; }
                        if (typeof val === 'object') { Object.values(val).forEach(walk); }
                    }
                    walk(obj);
                    return values;
                }

                // Match a single object against a query using the same operator syntax
                // as the main table column filters:
                //   ||   OR between terms
                //   &&   AND between terms
                //   !    negation prefix (e.g. !disabled, !^svc)
                //   =    exact value match against any field
                //   ^    starts-with match against any field
                //   $    ends-with match against any field
                //   (plain text)  substring match anywhere in the JSON
                function matchesDetailSearch(obj, query) {
                    const q = query.trim();
                    if (!q) return true;

                    if (q.includes('||')) {
                        return q.split('||').some(part => matchesDetailSearch(obj, part.trim()));
                    }
                    if (q.includes('&&')) {
                        return q.split('&&').map(p => p.trim()).filter(Boolean)
                                .every(part => matchesDetailSearch(obj, part));
                    }

                    const lower = q.toLowerCase();
                    const jsonStr = JSON.stringify(obj).toLowerCase();

                    // Operators that are meaningful per-field: =, ^, $  (with optional ! prefix)
                    const opMatch = lower.match(/^(!?)([=\^$])\s*(.+)$/);
                    if (opMatch) {
                        const [, negate, op, filterStr] = opMatch;
                        const vals = extractDetailValues(obj);
                        let result = false;
                        if (op === '=') result = vals.some(v => v === filterStr);
                        if (op === '^') result = vals.some(v => v.startsWith(filterStr));
                        if (op === '$') result = vals.some(v => v.endsWith(filterStr));
                        return negate ? !result : result;
                    }

                    // ! without a positional operator: must not contain anywhere in JSON
                    if (lower.startsWith('!') && lower.length > 1) {
                        return !jsonStr.includes(lower.slice(1));
                    }

                    // Default: substring anywhere in the full JSON
                    return jsonStr.includes(lower);
                }

                function filterIds(pool, query) {
                    return pool.filter(id => {
                        const obj = window.__objectsById && window.__objectsById.get(id);
                        return obj && matchesDetailSearch(obj, query);
                    });
                }

                function updateSearchClear() {
                    searchClearBtn.style.display = searchInput.value.trim() ? "inline-block" : "none";
                }

                function updateSearchModeBtn() {
                    scopeBtns.forEach(btn => {
                        btn.classList.toggle("active", btn.dataset.scope === window.__detailSearchMode);
                    });
                }

                function runDetailSearch() {
                    const query  = searchInput.value.trim();
                    const infoEl = document.getElementById('details-info');
                    updateSearchClear();

                    if (!query) {
                        _origSync(window.__lastSyncedDetailIds);
                        return;
                    }

                    const pool = window.__detailSearchMode === "global"
                        ? (window.__objectsById ? Array.from(window.__objectsById.keys()) : [])
                        : window.__lastSyncedDetailIds;

                    const matchingIds = filterIds(pool, query);
                    _origSync(matchingIds);

                    if (infoEl) {
                        infoEl.textContent = matchingIds.length + " of " + pool.length + " match";
                    }
                }

                // Intercept table-driven sync to track current IDs and handle active searches
                window.__syncDetailsForCurrentPage = (ids) => {
                    const uniqueIds = Array.isArray(ids) ? Array.from(new Set(ids.map(String))) : [];
                    window.__lastSyncedDetailIds = uniqueIds;

                    // Table navigation while global search is active: clear search, revert to current view
                    if (searchInput.value.trim() && window.__detailSearchMode === "global") {
                        searchInput.value = "";
                        window.__detailSearchMode = "current";
                        updateSearchModeBtn();
                        updateSearchClear();
                        _origSync(uniqueIds);
                        return;
                    }

                    // Re-apply current-mode search against the updated id set
                    if (searchInput.value.trim() && window.__detailSearchMode === "current") {
                        const matchingIds = filterIds(uniqueIds, searchInput.value.trim());
                        _origSync(matchingIds);
                        const infoEl = document.getElementById('details-info');
                        if (infoEl) infoEl.textContent = matchingIds.length + " of " + uniqueIds.length + " match";
                        return;
                    }

                    _origSync(uniqueIds);
                };

                let searchDebounce = null;
                searchInput.addEventListener("input", () => {
                    clearTimeout(searchDebounce);
                    searchDebounce = setTimeout(runDetailSearch, 300);
                });

                searchClearBtn.addEventListener("click", () => {
                    searchInput.value = "";
                    window.__detailSearchMode = "current";
                    updateSearchModeBtn();
                    runDetailSearch();
                });

                scopeBtns.forEach(btn => {
                    btn.addEventListener("click", () => {
                        window.__detailSearchMode = btn.dataset.scope;
                        updateSearchModeBtn();
                        runDetailSearch();
                    });
                });

                // Help popover toggle
                const helpBtn     = document.querySelector('.details-search-help-btn');
                const helpPopover = document.querySelector('.details-search-help-popover');
                if (helpBtn && helpPopover) {
                    helpBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        helpPopover.classList.toggle('hidden');
                    });
                    document.addEventListener('click', () => {
                        helpPopover.classList.add('hidden');
                    });
                }
            }
        });

        //Toast displayed when copy the current view
        function showToast(message, duration = 3000) {
            const toast = document.createElement("div");
            toast.textContent = message;
            toast.style.position = "fixed";
            toast.style.bottom = "30px";
            toast.style.right = "30px";
            toast.style.padding = "10px 16px";
            toast.style.background = "#333";
            toast.style.color = "#fff";
            toast.style.borderRadius = "8px";
            toast.style.boxShadow = "0 2px 6px rgba(0, 0, 0, 0.4)";
            toast.style.fontSize = "14px";
            toast.style.opacity = "0";
            toast.style.transition = "opacity 0.3s ease";

            document.body.appendChild(toast);
            requestAnimationFrame(() => toast.style.opacity = "1");

            setTimeout(() => {
                toast.style.opacity = "0";
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }


        // Coloring cells
        function colorCells(table, headers) {
            const rows = table && table.rows;
            if (!rows || rows.length < 3) return;

            const isDark = document.body.classList.contains("dark-mode");

            const redIfTrueHeaders = new Set(['Foreign', 'ForeignAgent', 'Inactive', 'PIM', 'Dynamic', 'SecurityEnabled', 'OnPrem', 'Conditions', 'IsBuiltIn', 'IsPrivileged', 'SAML', 'Agent', 'ActivatedViaPIM']);
            const redIfFalseHeaders = new Set(['AppLock', 'MfaCap', 'Protected', 'Enabled', 'RoleAssignable', 'ActivationMFA', 'ActivationAuthContext', 'ActivationApproval', 'ActiveAssignMFA', 'EligibleExpiration', 'ActiveExpiration', 'ActivationJustification', 'ActivationTicketing', 'ActiveAssignJustification', 'AlertAssignEligible', 'AlertAssignActive', 'AlertActivation']);
            const redIfContent = new Set(['all', 'alltrusted', 'report-only', 'disabled', 'public', 'guest', 'customrole', 'active', 'tier-0', 'tier-1', 'tier-2']);
            const redIfContentHeaders = new Set(['IncUsers', 'IncResources', 'IncNw', 'ExcNw', 'IncPlatforms', 'State', 'Visibility', 'UserType', 'RoleType', 'AssignmentType', 'EntraMaxTier', 'AzureMaxTier', 'PerUserMfa']);

            const redColor = isDark ? "#800000" : "#FFB6C1";
            const greenColor = isDark ? "#005f00" : "#98FB98";

            // If headers weren't passed, build once (fallback)
            if (!headers || !headers.length) {
                const headerCells = table.querySelectorAll("thead tr:first-child th");
                headers = Array.prototype.map.call(headerCells, th => th.getAttribute("data-col") || (th.textContent || "").trim());
            }


            for (let i = 2; i < rows.length; i++) {
                const cells = rows[i].cells;

                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    const columnHeader = headers[j] || "";

                    let bg = "";

                    // Fast path: boolean columns or numeric columns
                    if (redIfTrueHeaders.has(columnHeader) || redIfFalseHeaders.has(columnHeader)) {
                        const text = (cell.textContent || "").trim().toLowerCase();
                        if (text === "true" || text === "false") {
                            const boolVal = text === "true";
                            if (redIfTrueHeaders.has(columnHeader)) bg = boolVal ? redColor : greenColor;
                            if (redIfFalseHeaders.has(columnHeader)) bg = boolVal ? greenColor : redColor;
                        }
                    } else if (redIfContentHeaders.has(columnHeader)) {
                        const text = (cell.textContent || "").trim().toLowerCase();
                        bg = redIfContent.has(text) ? redColor : greenColor;
                    } else {
                        // Numeric heuristic: only attempt parse when it looks like a number
                        const raw = (cell.textContent || "").trim();
                        if (raw && raw.length < 32) {
                            const n = Number(raw);
                            if (!Number.isNaN(n)) {
                                bg = n === 0 ? greenColor : redColor;
                            }
                        }
                    }

                    // Fix stale colors: clear when no longer applicable
                    const current = cell.style.backgroundColor || "";
                    if (bg) {
                        if (current !== bg) cell.style.backgroundColor = bg;
                    } else {
                        if (current) cell.style.backgroundColor = "";
                    }
                }
            }
        }
        window.colorCells = colorCells;

    </script>
'@

$global:GLOBALJavaScript_Chart = @'
/*!
 * Chart.js v4.5.1
 * https://www.chartjs.org
 * (c) 2025 Chart.js Contributors
 * Released under the MIT License
 */
!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?module.exports=e():"function"==typeof define&&define.amd?define(e):(t="undefined"!=typeof globalThis?globalThis:t||self).Chart=e()}(this,(function(){"use strict";var t=Object.freeze({__proto__:null,get Colors(){return Jo},get Decimation(){return ta},get Filler(){return ba},get Legend(){return Ma},get SubTitle(){return Pa},get Title(){return ka},get Tooltip(){return Na}});function e(){}const i=(()=>{let t=0;return()=>t++})();function s(t){return null==t}function n(t){if(Array.isArray&&Array.isArray(t))return!0;const e=Object.prototype.toString.call(t);return"[object"===e.slice(0,7)&&"Array]"===e.slice(-6)}function o(t){return null!==t&&"[object Object]"===Object.prototype.toString.call(t)}function a(t){return("number"==typeof t||t instanceof Number)&&isFinite(+t)}function r(t,e){return a(t)?t:e}function l(t,e){return void 0===t?e:t}const h=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100:+t/e,c=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100*e:+t;function d(t,e,i){if(t&&"function"==typeof t.call)return t.apply(i,e)}function u(t,e,i,s){let a,r,l;if(n(t))if(r=t.length,s)for(a=r-1;a>=0;a--)e.call(i,t[a],a);else for(a=0;a<r;a++)e.call(i,t[a],a);else if(o(t))for(l=Object.keys(t),r=l.length,a=0;a<r;a++)e.call(i,t[l[a]],l[a])}function f(t,e){let i,s,n,o;if(!t||!e||t.length!==e.length)return!1;for(i=0,s=t.length;i<s;++i)if(n=t[i],o=e[i],n.datasetIndex!==o.datasetIndex||n.index!==o.index)return!1;return!0}function g(t){if(n(t))return t.map(g);if(o(t)){const e=Object.create(null),i=Object.keys(t),s=i.length;let n=0;for(;n<s;++n)e[i[n]]=g(t[i[n]]);return e}return t}function p(t){return-1===["__proto__","prototype","constructor"].indexOf(t)}function m(t,e,i,s){if(!p(t))return;const n=e[t],a=i[t];o(n)&&o(a)?x(n,a,s):e[t]=g(a)}function x(t,e,i){const s=n(e)?e:[e],a=s.length;if(!o(t))return t;const r=(i=i||{}).merger||m;let l;for(let e=0;e<a;++e){if(l=s[e],!o(l))continue;const n=Object.keys(l);for(let e=0,s=n.length;e<s;++e)r(n[e],t,l,i)}return t}function b(t,e){return x(t,e,{merger:_})}function _(t,e,i){if(!p(t))return;const s=e[t],n=i[t];o(s)&&o(n)?b(s,n):Object.prototype.hasOwnProperty.call(e,t)||(e[t]=g(n))}const y={"":t=>t,x:t=>t.x,y:t=>t.y};function v(t){const e=t.split("."),i=[];let s="";for(const t of e)s+=t,s.endsWith("\\")?s=s.slice(0,-1)+".":(i.push(s),s="");return i}function M(t,e){const i=y[e]||(y[e]=function(t){const e=v(t);return t=>{for(const i of e){if(""===i)break;t=t&&t[i]}return t}}(e));return i(t)}function w(t){return t.charAt(0).toUpperCase()+t.slice(1)}const k=t=>void 0!==t,S=t=>"function"==typeof t,P=(t,e)=>{if(t.size!==e.size)return!1;for(const i of t)if(!e.has(i))return!1;return!0};function D(t){return"mouseup"===t.type||"click"===t.type||"contextmenu"===t.type}const C=Math.PI,O=2*C,A=O+C,T=Number.POSITIVE_INFINITY,L=C/180,E=C/2,R=C/4,I=2*C/3,z=Math.log10,F=Math.sign;function V(t,e,i){return Math.abs(t-e)<i}function B(t){const e=Math.round(t);t=V(t,e,t/1e3)?e:t;const i=Math.pow(10,Math.floor(z(t))),s=t/i;return(s<=1?1:s<=2?2:s<=5?5:10)*i}function W(t){const e=[],i=Math.sqrt(t);let s;for(s=1;s<i;s++)t%s==0&&(e.push(s),e.push(t/s));return i===(0|i)&&e.push(i),e.sort(((t,e)=>t-e)).pop(),e}function N(t){return!function(t){return"symbol"==typeof t||"object"==typeof t&&null!==t&&!(Symbol.toPrimitive in t||"toString"in t||"valueOf"in t)}(t)&&!isNaN(parseFloat(t))&&isFinite(t)}function H(t,e){const i=Math.round(t);return i-e<=t&&i+e>=t}function j(t,e,i){let s,n,o;for(s=0,n=t.length;s<n;s++)o=t[s][i],isNaN(o)||(e.min=Math.min(e.min,o),e.max=Math.max(e.max,o))}function $(t){return t*(C/180)}function Y(t){return t*(180/C)}function U(t){if(!a(t))return;let e=1,i=0;for(;Math.round(t*e)/e!==t;)e*=10,i++;return i}function X(t,e){const i=e.x-t.x,s=e.y-t.y,n=Math.sqrt(i*i+s*s);let o=Math.atan2(s,i);return o<-.5*C&&(o+=O),{angle:o,distance:n}}function q(t,e){return Math.sqrt(Math.pow(e.x-t.x,2)+Math.pow(e.y-t.y,2))}function K(t,e){return(t-e+A)%O-C}function G(t){return(t%O+O)%O}function J(t,e,i,s){const n=G(t),o=G(e),a=G(i),r=G(o-n),l=G(a-n),h=G(n-o),c=G(n-a);return n===o||n===a||s&&o===a||r>l&&h<c}function Z(t,e,i){return Math.max(e,Math.min(i,t))}function Q(t){return Z(t,-32768,32767)}function tt(t,e,i,s=1e-6){return t>=Math.min(e,i)-s&&t<=Math.max(e,i)+s}function et(t,e,i){i=i||(i=>t[i]<e);let s,n=t.length-1,o=0;for(;n-o>1;)s=o+n>>1,i(s)?o=s:n=s;return{lo:o,hi:n}}const it=(t,e,i,s)=>et(t,i,s?s=>{const n=t[s][e];return n<i||n===i&&t[s+1][e]===i}:s=>t[s][e]<i),st=(t,e,i)=>et(t,i,(s=>t[s][e]>=i));function nt(t,e,i){let s=0,n=t.length;for(;s<n&&t[s]<e;)s++;for(;n>s&&t[n-1]>i;)n--;return s>0||n<t.length?t.slice(s,n):t}const ot=["push","pop","shift","splice","unshift"];function at(t,e){t._chartjs?t._chartjs.listeners.push(e):(Object.defineProperty(t,"_chartjs",{configurable:!0,enumerable:!1,value:{listeners:[e]}}),ot.forEach((e=>{const i="_onData"+w(e),s=t[e];Object.defineProperty(t,e,{configurable:!0,enumerable:!1,value(...e){const n=s.apply(this,e);return t._chartjs.listeners.forEach((t=>{"function"==typeof t[i]&&t[i](...e)})),n}})})))}function rt(t,e){const i=t._chartjs;if(!i)return;const s=i.listeners,n=s.indexOf(e);-1!==n&&s.splice(n,1),s.length>0||(ot.forEach((e=>{delete t[e]})),delete t._chartjs)}function lt(t){const e=new Set(t);return e.size===t.length?t:Array.from(e)}const ht="undefined"==typeof window?function(t){return t()}:window.requestAnimationFrame;function ct(t,e){let i=[],s=!1;return function(...n){i=n,s||(s=!0,ht.call(window,(()=>{s=!1,t.apply(e,i)})))}}function dt(t,e){let i;return function(...s){return e?(clearTimeout(i),i=setTimeout(t,e,s)):t.apply(this,s),e}}const ut=t=>"start"===t?"left":"end"===t?"right":"center",ft=(t,e,i)=>"start"===t?e:"end"===t?i:(e+i)/2,gt=(t,e,i,s)=>t===(s?"left":"right")?i:"center"===t?(e+i)/2:e;function pt(t,e,i){const n=e.length;let o=0,a=n;if(t._sorted){const{iScale:r,vScale:l,_parsed:h}=t,c=t.dataset&&t.dataset.options?t.dataset.options.spanGaps:null,d=r.axis,{min:u,max:f,minDefined:g,maxDefined:p}=r.getUserBounds();if(g){if(o=Math.min(it(h,d,u).lo,i?n:it(e,d,r.getPixelForValue(u)).lo),c){const t=h.slice(0,o+1).reverse().findIndex((t=>!s(t[l.axis])));o-=Math.max(0,t)}o=Z(o,0,n-1)}if(p){let t=Math.max(it(h,r.axis,f,!0).hi+1,i?0:it(e,d,r.getPixelForValue(f),!0).hi+1);if(c){const e=h.slice(t-1).findIndex((t=>!s(t[l.axis])));t+=Math.max(0,e)}a=Z(t,o,n)-o}else a=n-o}return{start:o,count:a}}function mt(t){const{xScale:e,yScale:i,_scaleRanges:s}=t,n={xmin:e.min,xmax:e.max,ymin:i.min,ymax:i.max};if(!s)return t._scaleRanges=n,!0;const o=s.xmin!==e.min||s.xmax!==e.max||s.ymin!==i.min||s.ymax!==i.max;return Object.assign(s,n),o}class xt{constructor(){this._request=null,this._charts=new Map,this._running=!1,this._lastDate=void 0}_notify(t,e,i,s){const n=e.listeners[s],o=e.duration;n.forEach((s=>s({chart:t,initial:e.initial,numSteps:o,currentStep:Math.min(i-e.start,o)})))}_refresh(){this._request||(this._running=!0,this._request=ht.call(window,(()=>{this._update(),this._request=null,this._running&&this._refresh()})))}_update(t=Date.now()){let e=0;this._charts.forEach(((i,s)=>{if(!i.running||!i.items.length)return;const n=i.items;let o,a=n.length-1,r=!1;for(;a>=0;--a)o=n[a],o._active?(o._total>i.duration&&(i.duration=o._total),o.tick(t),r=!0):(n[a]=n[n.length-1],n.pop());r&&(s.draw(),this._notify(s,i,t,"progress")),n.length||(i.running=!1,this._notify(s,i,t,"complete"),i.initial=!1),e+=n.length})),this._lastDate=t,0===e&&(this._running=!1)}_getAnims(t){const e=this._charts;let i=e.get(t);return i||(i={running:!1,initial:!0,items:[],listeners:{complete:[],progress:[]}},e.set(t,i)),i}listen(t,e,i){this._getAnims(t).listeners[e].push(i)}add(t,e){e&&e.length&&this._getAnims(t).items.push(...e)}has(t){return this._getAnims(t).items.length>0}start(t){const e=this._charts.get(t);e&&(e.running=!0,e.start=Date.now(),e.duration=e.items.reduce(((t,e)=>Math.max(t,e._duration)),0),this._refresh())}running(t){if(!this._running)return!1;const e=this._charts.get(t);return!!(e&&e.running&&e.items.length)}stop(t){const e=this._charts.get(t);if(!e||!e.items.length)return;const i=e.items;let s=i.length-1;for(;s>=0;--s)i[s].cancel();e.items=[],this._notify(t,e,Date.now(),"complete")}remove(t){return this._charts.delete(t)}}var bt=new xt;
/*!
 * @kurkle/color v0.3.2
 * https://github.com/kurkle/color#readme
 * (c) 2023 Jukka Kurkela
 * Released under the MIT License
 */function _t(t){return t+.5|0}const yt=(t,e,i)=>Math.max(Math.min(t,i),e);function vt(t){return yt(_t(2.55*t),0,255)}function Mt(t){return yt(_t(255*t),0,255)}function wt(t){return yt(_t(t/2.55)/100,0,1)}function kt(t){return yt(_t(100*t),0,100)}const St={0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,A:10,B:11,C:12,D:13,E:14,F:15,a:10,b:11,c:12,d:13,e:14,f:15},Pt=[..."0123456789ABCDEF"],Dt=t=>Pt[15&t],Ct=t=>Pt[(240&t)>>4]+Pt[15&t],Ot=t=>(240&t)>>4==(15&t);function At(t){var e=(t=>Ot(t.r)&&Ot(t.g)&&Ot(t.b)&&Ot(t.a))(t)?Dt:Ct;return t?"#"+e(t.r)+e(t.g)+e(t.b)+((t,e)=>t<255?e(t):"")(t.a,e):void 0}const Tt=/^(hsla?|hwb|hsv)\(\s*([-+.e\d]+)(?:deg)?[\s,]+([-+.e\d]+)%[\s,]+([-+.e\d]+)%(?:[\s,]+([-+.e\d]+)(%)?)?\s*\)$/;function Lt(t,e,i){const s=e*Math.min(i,1-i),n=(e,n=(e+t/30)%12)=>i-s*Math.max(Math.min(n-3,9-n,1),-1);return[n(0),n(8),n(4)]}function Et(t,e,i){const s=(s,n=(s+t/60)%6)=>i-i*e*Math.max(Math.min(n,4-n,1),0);return[s(5),s(3),s(1)]}function Rt(t,e,i){const s=Lt(t,1,.5);let n;for(e+i>1&&(n=1/(e+i),e*=n,i*=n),n=0;n<3;n++)s[n]*=1-e-i,s[n]+=e;return s}function It(t){const e=t.r/255,i=t.g/255,s=t.b/255,n=Math.max(e,i,s),o=Math.min(e,i,s),a=(n+o)/2;let r,l,h;return n!==o&&(h=n-o,l=a>.5?h/(2-n-o):h/(n+o),r=function(t,e,i,s,n){return t===n?(e-i)/s+(e<i?6:0):e===n?(i-t)/s+2:(t-e)/s+4}(e,i,s,h,n),r=60*r+.5),[0|r,l||0,a]}function zt(t,e,i,s){return(Array.isArray(e)?t(e[0],e[1],e[2]):t(e,i,s)).map(Mt)}function Ft(t,e,i){return zt(Lt,t,e,i)}function Vt(t){return(t%360+360)%360}function Bt(t){const e=Tt.exec(t);let i,s=255;if(!e)return;e[5]!==i&&(s=e[6]?vt(+e[5]):Mt(+e[5]));const n=Vt(+e[2]),o=+e[3]/100,a=+e[4]/100;return i="hwb"===e[1]?function(t,e,i){return zt(Rt,t,e,i)}(n,o,a):"hsv"===e[1]?function(t,e,i){return zt(Et,t,e,i)}(n,o,a):Ft(n,o,a),{r:i[0],g:i[1],b:i[2],a:s}}const Wt={x:"dark",Z:"light",Y:"re",X:"blu",W:"gr",V:"medium",U:"slate",A:"ee",T:"ol",S:"or",B:"ra",C:"lateg",D:"ights",R:"in",Q:"turquois",E:"hi",P:"ro",O:"al",N:"le",M:"de",L:"yello",F:"en",K:"ch",G:"arks",H:"ea",I:"ightg",J:"wh"},Nt={OiceXe:"f0f8ff",antiquewEte:"faebd7",aqua:"ffff",aquamarRe:"7fffd4",azuY:"f0ffff",beige:"f5f5dc",bisque:"ffe4c4",black:"0",blanKedOmond:"ffebcd",Xe:"ff",XeviTet:"8a2be2",bPwn:"a52a2a",burlywood:"deb887",caMtXe:"5f9ea0",KartYuse:"7fff00",KocTate:"d2691e",cSO:"ff7f50",cSnflowerXe:"6495ed",cSnsilk:"fff8dc",crimson:"dc143c",cyan:"ffff",xXe:"8b",xcyan:"8b8b",xgTMnPd:"b8860b",xWay:"a9a9a9",xgYF:"6400",xgYy:"a9a9a9",xkhaki:"bdb76b",xmagFta:"8b008b",xTivegYF:"556b2f",xSange:"ff8c00",xScEd:"9932cc",xYd:"8b0000",xsOmon:"e9967a",xsHgYF:"8fbc8f",xUXe:"483d8b",xUWay:"2f4f4f",xUgYy:"2f4f4f",xQe:"ced1",xviTet:"9400d3",dAppRk:"ff1493",dApskyXe:"bfff",dimWay:"696969",dimgYy:"696969",dodgerXe:"1e90ff",fiYbrick:"b22222",flSOwEte:"fffaf0",foYstWAn:"228b22",fuKsia:"ff00ff",gaRsbSo:"dcdcdc",ghostwEte:"f8f8ff",gTd:"ffd700",gTMnPd:"daa520",Way:"808080",gYF:"8000",gYFLw:"adff2f",gYy:"808080",honeyMw:"f0fff0",hotpRk:"ff69b4",RdianYd:"cd5c5c",Rdigo:"4b0082",ivSy:"fffff0",khaki:"f0e68c",lavFMr:"e6e6fa",lavFMrXsh:"fff0f5",lawngYF:"7cfc00",NmoncEffon:"fffacd",ZXe:"add8e6",ZcSO:"f08080",Zcyan:"e0ffff",ZgTMnPdLw:"fafad2",ZWay:"d3d3d3",ZgYF:"90ee90",ZgYy:"d3d3d3",ZpRk:"ffb6c1",ZsOmon:"ffa07a",ZsHgYF:"20b2aa",ZskyXe:"87cefa",ZUWay:"778899",ZUgYy:"778899",ZstAlXe:"b0c4de",ZLw:"ffffe0",lime:"ff00",limegYF:"32cd32",lRF:"faf0e6",magFta:"ff00ff",maPon:"800000",VaquamarRe:"66cdaa",VXe:"cd",VScEd:"ba55d3",VpurpN:"9370db",VsHgYF:"3cb371",VUXe:"7b68ee",VsprRggYF:"fa9a",VQe:"48d1cc",VviTetYd:"c71585",midnightXe:"191970",mRtcYam:"f5fffa",mistyPse:"ffe4e1",moccasR:"ffe4b5",navajowEte:"ffdead",navy:"80",Tdlace:"fdf5e6",Tive:"808000",TivedBb:"6b8e23",Sange:"ffa500",SangeYd:"ff4500",ScEd:"da70d6",pOegTMnPd:"eee8aa",pOegYF:"98fb98",pOeQe:"afeeee",pOeviTetYd:"db7093",papayawEp:"ffefd5",pHKpuff:"ffdab9",peru:"cd853f",pRk:"ffc0cb",plum:"dda0dd",powMrXe:"b0e0e6",purpN:"800080",YbeccapurpN:"663399",Yd:"ff0000",Psybrown:"bc8f8f",PyOXe:"4169e1",saddNbPwn:"8b4513",sOmon:"fa8072",sandybPwn:"f4a460",sHgYF:"2e8b57",sHshell:"fff5ee",siFna:"a0522d",silver:"c0c0c0",skyXe:"87ceeb",UXe:"6a5acd",UWay:"708090",UgYy:"708090",snow:"fffafa",sprRggYF:"ff7f",stAlXe:"4682b4",tan:"d2b48c",teO:"8080",tEstN:"d8bfd8",tomato:"ff6347",Qe:"40e0d0",viTet:"ee82ee",JHt:"f5deb3",wEte:"ffffff",wEtesmoke:"f5f5f5",Lw:"ffff00",LwgYF:"9acd32"};let Ht;function jt(t){Ht||(Ht=function(){const t={},e=Object.keys(Nt),i=Object.keys(Wt);let s,n,o,a,r;for(s=0;s<e.length;s++){for(a=r=e[s],n=0;n<i.length;n++)o=i[n],r=r.replace(o,Wt[o]);o=parseInt(Nt[a],16),t[r]=[o>>16&255,o>>8&255,255&o]}return t}(),Ht.transparent=[0,0,0,0]);const e=Ht[t.toLowerCase()];return e&&{r:e[0],g:e[1],b:e[2],a:4===e.length?e[3]:255}}const $t=/^rgba?\(\s*([-+.\d]+)(%)?[\s,]+([-+.e\d]+)(%)?[\s,]+([-+.e\d]+)(%)?(?:[\s,/]+([-+.e\d]+)(%)?)?\s*\)$/;const Yt=t=>t<=.0031308?12.92*t:1.055*Math.pow(t,1/2.4)-.055,Ut=t=>t<=.04045?t/12.92:Math.pow((t+.055)/1.055,2.4);function Xt(t,e,i){if(t){let s=It(t);s[e]=Math.max(0,Math.min(s[e]+s[e]*i,0===e?360:1)),s=Ft(s),t.r=s[0],t.g=s[1],t.b=s[2]}}function qt(t,e){return t?Object.assign(e||{},t):t}function Kt(t){var e={r:0,g:0,b:0,a:255};return Array.isArray(t)?t.length>=3&&(e={r:t[0],g:t[1],b:t[2],a:255},t.length>3&&(e.a=Mt(t[3]))):(e=qt(t,{r:0,g:0,b:0,a:1})).a=Mt(e.a),e}function Gt(t){return"r"===t.charAt(0)?function(t){const e=$t.exec(t);let i,s,n,o=255;if(e){if(e[7]!==i){const t=+e[7];o=e[8]?vt(t):yt(255*t,0,255)}return i=+e[1],s=+e[3],n=+e[5],i=255&(e[2]?vt(i):yt(i,0,255)),s=255&(e[4]?vt(s):yt(s,0,255)),n=255&(e[6]?vt(n):yt(n,0,255)),{r:i,g:s,b:n,a:o}}}(t):Bt(t)}class Jt{constructor(t){if(t instanceof Jt)return t;const e=typeof t;let i;var s,n,o;"object"===e?i=Kt(t):"string"===e&&(o=(s=t).length,"#"===s[0]&&(4===o||5===o?n={r:255&17*St[s[1]],g:255&17*St[s[2]],b:255&17*St[s[3]],a:5===o?17*St[s[4]]:255}:7!==o&&9!==o||(n={r:St[s[1]]<<4|St[s[2]],g:St[s[3]]<<4|St[s[4]],b:St[s[5]]<<4|St[s[6]],a:9===o?St[s[7]]<<4|St[s[8]]:255})),i=n||jt(t)||Gt(t)),this._rgb=i,this._valid=!!i}get valid(){return this._valid}get rgb(){var t=qt(this._rgb);return t&&(t.a=wt(t.a)),t}set rgb(t){this._rgb=Kt(t)}rgbString(){return this._valid?(t=this._rgb)&&(t.a<255?`rgba(${t.r}, ${t.g}, ${t.b}, ${wt(t.a)})`:`rgb(${t.r}, ${t.g}, ${t.b})`):void 0;var t}hexString(){return this._valid?At(this._rgb):void 0}hslString(){return this._valid?function(t){if(!t)return;const e=It(t),i=e[0],s=kt(e[1]),n=kt(e[2]);return t.a<255?`hsla(${i}, ${s}%, ${n}%, ${wt(t.a)})`:`hsl(${i}, ${s}%, ${n}%)`}(this._rgb):void 0}mix(t,e){if(t){const i=this.rgb,s=t.rgb;let n;const o=e===n?.5:e,a=2*o-1,r=i.a-s.a,l=((a*r==-1?a:(a+r)/(1+a*r))+1)/2;n=1-l,i.r=255&l*i.r+n*s.r+.5,i.g=255&l*i.g+n*s.g+.5,i.b=255&l*i.b+n*s.b+.5,i.a=o*i.a+(1-o)*s.a,this.rgb=i}return this}interpolate(t,e){return t&&(this._rgb=function(t,e,i){const s=Ut(wt(t.r)),n=Ut(wt(t.g)),o=Ut(wt(t.b));return{r:Mt(Yt(s+i*(Ut(wt(e.r))-s))),g:Mt(Yt(n+i*(Ut(wt(e.g))-n))),b:Mt(Yt(o+i*(Ut(wt(e.b))-o))),a:t.a+i*(e.a-t.a)}}(this._rgb,t._rgb,e)),this}clone(){return new Jt(this.rgb)}alpha(t){return this._rgb.a=Mt(t),this}clearer(t){return this._rgb.a*=1-t,this}greyscale(){const t=this._rgb,e=_t(.3*t.r+.59*t.g+.11*t.b);return t.r=t.g=t.b=e,this}opaquer(t){return this._rgb.a*=1+t,this}negate(){const t=this._rgb;return t.r=255-t.r,t.g=255-t.g,t.b=255-t.b,this}lighten(t){return Xt(this._rgb,2,t),this}darken(t){return Xt(this._rgb,2,-t),this}saturate(t){return Xt(this._rgb,1,t),this}desaturate(t){return Xt(this._rgb,1,-t),this}rotate(t){return function(t,e){var i=It(t);i[0]=Vt(i[0]+e),i=Ft(i),t.r=i[0],t.g=i[1],t.b=i[2]}(this._rgb,t),this}}function Zt(t){if(t&&"object"==typeof t){const e=t.toString();return"[object CanvasPattern]"===e||"[object CanvasGradient]"===e}return!1}function Qt(t){return Zt(t)?t:new Jt(t)}function te(t){return Zt(t)?t:new Jt(t).saturate(.5).darken(.1).hexString()}const ee=["x","y","borderWidth","radius","tension"],ie=["color","borderColor","backgroundColor"];const se=new Map;function ne(t,e,i){return function(t,e){e=e||{};const i=t+JSON.stringify(e);let s=se.get(i);return s||(s=new Intl.NumberFormat(t,e),se.set(i,s)),s}(e,i).format(t)}const oe={values:t=>n(t)?t:""+t,numeric(t,e,i){if(0===t)return"0";const s=this.chart.options.locale;let n,o=t;if(i.length>1){const e=Math.max(Math.abs(i[0].value),Math.abs(i[i.length-1].value));(e<1e-4||e>1e15)&&(n="scientific"),o=function(t,e){let i=e.length>3?e[2].value-e[1].value:e[1].value-e[0].value;Math.abs(i)>=1&&t!==Math.floor(t)&&(i=t-Math.floor(t));return i}(t,i)}const a=z(Math.abs(o)),r=isNaN(a)?1:Math.max(Math.min(-1*Math.floor(a),20),0),l={notation:n,minimumFractionDigits:r,maximumFractionDigits:r};return Object.assign(l,this.options.ticks.format),ne(t,s,l)},logarithmic(t,e,i){if(0===t)return"0";const s=i[e].significand||t/Math.pow(10,Math.floor(z(t)));return[1,2,3,5,10,15].includes(s)||e>.8*i.length?oe.numeric.call(this,t,e,i):""}};var ae={formatters:oe};const re=Object.create(null),le=Object.create(null);function he(t,e){if(!e)return t;const i=e.split(".");for(let e=0,s=i.length;e<s;++e){const s=i[e];t=t[s]||(t[s]=Object.create(null))}return t}function ce(t,e,i){return"string"==typeof e?x(he(t,e),i):x(he(t,""),e)}class de{constructor(t,e){this.animation=void 0,this.backgroundColor="rgba(0,0,0,0.1)",this.borderColor="rgba(0,0,0,0.1)",this.color="#666",this.datasets={},this.devicePixelRatio=t=>t.chart.platform.getDevicePixelRatio(),this.elements={},this.events=["mousemove","mouseout","click","touchstart","touchmove"],this.font={family:"'Helvetica Neue', 'Helvetica', 'Arial', sans-serif",size:12,style:"normal",lineHeight:1.2,weight:null},this.hover={},this.hoverBackgroundColor=(t,e)=>te(e.backgroundColor),this.hoverBorderColor=(t,e)=>te(e.borderColor),this.hoverColor=(t,e)=>te(e.color),this.indexAxis="x",this.interaction={mode:"nearest",intersect:!0,includeInvisible:!1},this.maintainAspectRatio=!0,this.onHover=null,this.onClick=null,this.parsing=!0,this.plugins={},this.responsive=!0,this.scale=void 0,this.scales={},this.showLine=!0,this.drawActiveElementsOnTop=!0,this.describe(t),this.apply(e)}set(t,e){return ce(this,t,e)}get(t){return he(this,t)}describe(t,e){return ce(le,t,e)}override(t,e){return ce(re,t,e)}route(t,e,i,s){const n=he(this,t),a=he(this,i),r="_"+e;Object.defineProperties(n,{[r]:{value:n[e],writable:!0},[e]:{enumerable:!0,get(){const t=this[r],e=a[s];return o(t)?Object.assign({},e,t):l(t,e)},set(t){this[r]=t}}})}apply(t){t.forEach((t=>t(this)))}}var ue=new de({_scriptable:t=>!t.startsWith("on"),_indexable:t=>"events"!==t,hover:{_fallback:"interaction"},interaction:{_scriptable:!1,_indexable:!1}},[function(t){t.set("animation",{delay:void 0,duration:1e3,easing:"easeOutQuart",fn:void 0,from:void 0,loop:void 0,to:void 0,type:void 0}),t.describe("animation",{_fallback:!1,_indexable:!1,_scriptable:t=>"onProgress"!==t&&"onComplete"!==t&&"fn"!==t}),t.set("animations",{colors:{type:"color",properties:ie},numbers:{type:"number",properties:ee}}),t.describe("animations",{_fallback:"animation"}),t.set("transitions",{active:{animation:{duration:400}},resize:{animation:{duration:0}},show:{animations:{colors:{from:"transparent"},visible:{type:"boolean",duration:0}}},hide:{animations:{colors:{to:"transparent"},visible:{type:"boolean",easing:"linear",fn:t=>0|t}}}})},function(t){t.set("layout",{autoPadding:!0,padding:{top:0,right:0,bottom:0,left:0}})},function(t){t.set("scale",{display:!0,offset:!1,reverse:!1,beginAtZero:!1,bounds:"ticks",clip:!0,grace:0,grid:{display:!0,lineWidth:1,drawOnChartArea:!0,drawTicks:!0,tickLength:8,tickWidth:(t,e)=>e.lineWidth,tickColor:(t,e)=>e.color,offset:!1},border:{display:!0,dash:[],dashOffset:0,width:1},title:{display:!1,text:"",padding:{top:4,bottom:4}},ticks:{minRotation:0,maxRotation:50,mirror:!1,textStrokeWidth:0,textStrokeColor:"",padding:3,display:!0,autoSkip:!0,autoSkipPadding:3,labelOffset:0,callback:ae.formatters.values,minor:{},major:{},align:"center",crossAlign:"near",showLabelBackdrop:!1,backdropColor:"rgba(255, 255, 255, 0.75)",backdropPadding:2}}),t.route("scale.ticks","color","","color"),t.route("scale.grid","color","","borderColor"),t.route("scale.border","color","","borderColor"),t.route("scale.title","color","","color"),t.describe("scale",{_fallback:!1,_scriptable:t=>!t.startsWith("before")&&!t.startsWith("after")&&"callback"!==t&&"parser"!==t,_indexable:t=>"borderDash"!==t&&"tickBorderDash"!==t&&"dash"!==t}),t.describe("scales",{_fallback:"scale"}),t.describe("scale.ticks",{_scriptable:t=>"backdropPadding"!==t&&"callback"!==t,_indexable:t=>"backdropPadding"!==t})}]);function fe(){return"undefined"!=typeof window&&"undefined"!=typeof document}function ge(t){let e=t.parentNode;return e&&"[object ShadowRoot]"===e.toString()&&(e=e.host),e}function pe(t,e,i){let s;return"string"==typeof t?(s=parseInt(t,10),-1!==t.indexOf("%")&&(s=s/100*e.parentNode[i])):s=t,s}const me=t=>t.ownerDocument.defaultView.getComputedStyle(t,null);function xe(t,e){return me(t).getPropertyValue(e)}const be=["top","right","bottom","left"];function _e(t,e,i){const s={};i=i?"-"+i:"";for(let n=0;n<4;n++){const o=be[n];s[o]=parseFloat(t[e+"-"+o+i])||0}return s.width=s.left+s.right,s.height=s.top+s.bottom,s}const ye=(t,e,i)=>(t>0||e>0)&&(!i||!i.shadowRoot);function ve(t,e){if("native"in t)return t;const{canvas:i,currentDevicePixelRatio:s}=e,n=me(i),o="border-box"===n.boxSizing,a=_e(n,"padding"),r=_e(n,"border","width"),{x:l,y:h,box:c}=function(t,e){const i=t.touches,s=i&&i.length?i[0]:t,{offsetX:n,offsetY:o}=s;let a,r,l=!1;if(ye(n,o,t.target))a=n,r=o;else{const t=e.getBoundingClientRect();a=s.clientX-t.left,r=s.clientY-t.top,l=!0}return{x:a,y:r,box:l}}(t,i),d=a.left+(c&&r.left),u=a.top+(c&&r.top);let{width:f,height:g}=e;return o&&(f-=a.width+r.width,g-=a.height+r.height),{x:Math.round((l-d)/f*i.width/s),y:Math.round((h-u)/g*i.height/s)}}const Me=t=>Math.round(10*t)/10;function we(t,e,i,s){const n=me(t),o=_e(n,"margin"),a=pe(n.maxWidth,t,"clientWidth")||T,r=pe(n.maxHeight,t,"clientHeight")||T,l=function(t,e,i){let s,n;if(void 0===e||void 0===i){const o=t&&ge(t);if(o){const t=o.getBoundingClientRect(),a=me(o),r=_e(a,"border","width"),l=_e(a,"padding");e=t.width-l.width-r.width,i=t.height-l.height-r.height,s=pe(a.maxWidth,o,"clientWidth"),n=pe(a.maxHeight,o,"clientHeight")}else e=t.clientWidth,i=t.clientHeight}return{width:e,height:i,maxWidth:s||T,maxHeight:n||T}}(t,e,i);let{width:h,height:c}=l;if("content-box"===n.boxSizing){const t=_e(n,"border","width"),e=_e(n,"padding");h-=e.width+t.width,c-=e.height+t.height}h=Math.max(0,h-o.width),c=Math.max(0,s?h/s:c-o.height),h=Me(Math.min(h,a,l.maxWidth)),c=Me(Math.min(c,r,l.maxHeight)),h&&!c&&(c=Me(h/2));return(void 0!==e||void 0!==i)&&s&&l.height&&c>l.height&&(c=l.height,h=Me(Math.floor(c*s))),{width:h,height:c}}function ke(t,e,i){const s=e||1,n=Me(t.height*s),o=Me(t.width*s);t.height=Me(t.height),t.width=Me(t.width);const a=t.canvas;return a.style&&(i||!a.style.height&&!a.style.width)&&(a.style.height=`${t.height}px`,a.style.width=`${t.width}px`),(t.currentDevicePixelRatio!==s||a.height!==n||a.width!==o)&&(t.currentDevicePixelRatio=s,a.height=n,a.width=o,t.ctx.setTransform(s,0,0,s,0,0),!0)}const Se=function(){let t=!1;try{const e={get passive(){return t=!0,!1}};fe()&&(window.addEventListener("test",null,e),window.removeEventListener("test",null,e))}catch(t){}return t}();function Pe(t,e){const i=xe(t,e),s=i&&i.match(/^(\d+)(\.\d+)?px$/);return s?+s[1]:void 0}function De(t){return!t||s(t.size)||s(t.family)?null:(t.style?t.style+" ":"")+(t.weight?t.weight+" ":"")+t.size+"px "+t.family}function Ce(t,e,i,s,n){let o=e[n];return o||(o=e[n]=t.measureText(n).width,i.push(n)),o>s&&(s=o),s}function Oe(t,e,i,s){let o=(s=s||{}).data=s.data||{},a=s.garbageCollect=s.garbageCollect||[];s.font!==e&&(o=s.data={},a=s.garbageCollect=[],s.font=e),t.save(),t.font=e;let r=0;const l=i.length;let h,c,d,u,f;for(h=0;h<l;h++)if(u=i[h],null==u||n(u)){if(n(u))for(c=0,d=u.length;c<d;c++)f=u[c],null==f||n(f)||(r=Ce(t,o,a,r,f))}else r=Ce(t,o,a,r,u);t.restore();const g=a.length/2;if(g>i.length){for(h=0;h<g;h++)delete o[a[h]];a.splice(0,g)}return r}function Ae(t,e,i){const s=t.currentDevicePixelRatio,n=0!==i?Math.max(i/2,.5):0;return Math.round((e-n)*s)/s+n}function Te(t,e){(e||t)&&((e=e||t.getContext("2d")).save(),e.resetTransform(),e.clearRect(0,0,t.width,t.height),e.restore())}function Le(t,e,i,s){Ee(t,e,i,s,null)}function Ee(t,e,i,s,n){let o,a,r,l,h,c,d,u;const f=e.pointStyle,g=e.rotation,p=e.radius;let m=(g||0)*L;if(f&&"object"==typeof f&&(o=f.toString(),"[object HTMLImageElement]"===o||"[object HTMLCanvasElement]"===o))return t.save(),t.translate(i,s),t.rotate(m),t.drawImage(f,-f.width/2,-f.height/2,f.width,f.height),void t.restore();if(!(isNaN(p)||p<=0)){switch(t.beginPath(),f){default:n?t.ellipse(i,s,n/2,p,0,0,O):t.arc(i,s,p,0,O),t.closePath();break;case"triangle":c=n?n/2:p,t.moveTo(i+Math.sin(m)*c,s-Math.cos(m)*p),m+=I,t.lineTo(i+Math.sin(m)*c,s-Math.cos(m)*p),m+=I,t.lineTo(i+Math.sin(m)*c,s-Math.cos(m)*p),t.closePath();break;case"rectRounded":h=.516*p,l=p-h,a=Math.cos(m+R)*l,d=Math.cos(m+R)*(n?n/2-h:l),r=Math.sin(m+R)*l,u=Math.sin(m+R)*(n?n/2-h:l),t.arc(i-d,s-r,h,m-C,m-E),t.arc(i+u,s-a,h,m-E,m),t.arc(i+d,s+r,h,m,m+E),t.arc(i-u,s+a,h,m+E,m+C),t.closePath();break;case"rect":if(!g){l=Math.SQRT1_2*p,c=n?n/2:l,t.rect(i-c,s-l,2*c,2*l);break}m+=R;case"rectRot":d=Math.cos(m)*(n?n/2:p),a=Math.cos(m)*p,r=Math.sin(m)*p,u=Math.sin(m)*(n?n/2:p),t.moveTo(i-d,s-r),t.lineTo(i+u,s-a),t.lineTo(i+d,s+r),t.lineTo(i-u,s+a),t.closePath();break;case"crossRot":m+=R;case"cross":d=Math.cos(m)*(n?n/2:p),a=Math.cos(m)*p,r=Math.sin(m)*p,u=Math.sin(m)*(n?n/2:p),t.moveTo(i-d,s-r),t.lineTo(i+d,s+r),t.moveTo(i+u,s-a),t.lineTo(i-u,s+a);break;case"star":d=Math.cos(m)*(n?n/2:p),a=Math.cos(m)*p,r=Math.sin(m)*p,u=Math.sin(m)*(n?n/2:p),t.moveTo(i-d,s-r),t.lineTo(i+d,s+r),t.moveTo(i+u,s-a),t.lineTo(i-u,s+a),m+=R,d=Math.cos(m)*(n?n/2:p),a=Math.cos(m)*p,r=Math.sin(m)*p,u=Math.sin(m)*(n?n/2:p),t.moveTo(i-d,s-r),t.lineTo(i+d,s+r),t.moveTo(i+u,s-a),t.lineTo(i-u,s+a);break;case"line":a=n?n/2:Math.cos(m)*p,r=Math.sin(m)*p,t.moveTo(i-a,s-r),t.lineTo(i+a,s+r);break;case"dash":t.moveTo(i,s),t.lineTo(i+Math.cos(m)*(n?n/2:p),s+Math.sin(m)*p);break;case!1:t.closePath()}t.fill(),e.borderWidth>0&&t.stroke()}}function Re(t,e,i){return i=i||.5,!e||t&&t.x>e.left-i&&t.x<e.right+i&&t.y>e.top-i&&t.y<e.bottom+i}function Ie(t,e){t.save(),t.beginPath(),t.rect(e.left,e.top,e.right-e.left,e.bottom-e.top),t.clip()}function ze(t){t.restore()}function Fe(t,e,i,s,n){if(!e)return t.lineTo(i.x,i.y);if("middle"===n){const s=(e.x+i.x)/2;t.lineTo(s,e.y),t.lineTo(s,i.y)}else"after"===n!=!!s?t.lineTo(e.x,i.y):t.lineTo(i.x,e.y);t.lineTo(i.x,i.y)}function Ve(t,e,i,s){if(!e)return t.lineTo(i.x,i.y);t.bezierCurveTo(s?e.cp1x:e.cp2x,s?e.cp1y:e.cp2y,s?i.cp2x:i.cp1x,s?i.cp2y:i.cp1y,i.x,i.y)}function Be(t,e,i,s,n){if(n.strikethrough||n.underline){const o=t.measureText(s),a=e-o.actualBoundingBoxLeft,r=e+o.actualBoundingBoxRight,l=i-o.actualBoundingBoxAscent,h=i+o.actualBoundingBoxDescent,c=n.strikethrough?(l+h)/2:h;t.strokeStyle=t.fillStyle,t.beginPath(),t.lineWidth=n.decorationWidth||2,t.moveTo(a,c),t.lineTo(r,c),t.stroke()}}function We(t,e){const i=t.fillStyle;t.fillStyle=e.color,t.fillRect(e.left,e.top,e.width,e.height),t.fillStyle=i}function Ne(t,e,i,o,a,r={}){const l=n(e)?e:[e],h=r.strokeWidth>0&&""!==r.strokeColor;let c,d;for(t.save(),t.font=a.string,function(t,e){e.translation&&t.translate(e.translation[0],e.translation[1]),s(e.rotation)||t.rotate(e.rotation),e.color&&(t.fillStyle=e.color),e.textAlign&&(t.textAlign=e.textAlign),e.textBaseline&&(t.textBaseline=e.textBaseline)}(t,r),c=0;c<l.length;++c)d=l[c],r.backdrop&&We(t,r.backdrop),h&&(r.strokeColor&&(t.strokeStyle=r.strokeColor),s(r.strokeWidth)||(t.lineWidth=r.strokeWidth),t.strokeText(d,i,o,r.maxWidth)),t.fillText(d,i,o,r.maxWidth),Be(t,i,o,d,r),o+=Number(a.lineHeight);t.restore()}function He(t,e){const{x:i,y:s,w:n,h:o,radius:a}=e;t.arc(i+a.topLeft,s+a.topLeft,a.topLeft,1.5*C,C,!0),t.lineTo(i,s+o-a.bottomLeft),t.arc(i+a.bottomLeft,s+o-a.bottomLeft,a.bottomLeft,C,E,!0),t.lineTo(i+n-a.bottomRight,s+o),t.arc(i+n-a.bottomRight,s+o-a.bottomRight,a.bottomRight,E,0,!0),t.lineTo(i+n,s+a.topRight),t.arc(i+n-a.topRight,s+a.topRight,a.topRight,0,-E,!0),t.lineTo(i+a.topLeft,s)}function je(t,e=[""],i,s,n=(()=>t[0])){const o=i||t;void 0===s&&(s=ti("_fallback",t));const a={[Symbol.toStringTag]:"Object",_cacheable:!0,_scopes:t,_rootScopes:o,_fallback:s,_getTarget:n,override:i=>je([i,...t],e,o,s)};return new Proxy(a,{deleteProperty:(e,i)=>(delete e[i],delete e._keys,delete t[0][i],!0),get:(i,s)=>qe(i,s,(()=>function(t,e,i,s){let n;for(const o of e)if(n=ti(Ue(o,t),i),void 0!==n)return Xe(t,n)?Ze(i,s,t,n):n}(s,e,t,i))),getOwnPropertyDescriptor:(t,e)=>Reflect.getOwnPropertyDescriptor(t._scopes[0],e),getPrototypeOf:()=>Reflect.getPrototypeOf(t[0]),has:(t,e)=>ei(t).includes(e),ownKeys:t=>ei(t),set(t,e,i){const s=t._storage||(t._storage=n());return t[e]=s[e]=i,delete t._keys,!0}})}function $e(t,e,i,s){const a={_cacheable:!1,_proxy:t,_context:e,_subProxy:i,_stack:new Set,_descriptors:Ye(t,s),setContext:e=>$e(t,e,i,s),override:n=>$e(t.override(n),e,i,s)};return new Proxy(a,{deleteProperty:(e,i)=>(delete e[i],delete t[i],!0),get:(t,e,i)=>qe(t,e,(()=>function(t,e,i){const{_proxy:s,_context:a,_subProxy:r,_descriptors:l}=t;let h=s[e];S(h)&&l.isScriptable(e)&&(h=function(t,e,i,s){const{_proxy:n,_context:o,_subProxy:a,_stack:r}=i;if(r.has(t))throw new Error("Recursion detected: "+Array.from(r).join("->")+"->"+t);r.add(t);let l=e(o,a||s);r.delete(t),Xe(t,l)&&(l=Ze(n._scopes,n,t,l));return l}(e,h,t,i));n(h)&&h.length&&(h=function(t,e,i,s){const{_proxy:n,_context:a,_subProxy:r,_descriptors:l}=i;if(void 0!==a.index&&s(t))return e[a.index%e.length];if(o(e[0])){const i=e,s=n._scopes.filter((t=>t!==i));e=[];for(const o of i){const i=Ze(s,n,t,o);e.push($e(i,a,r&&r[t],l))}}return e}(e,h,t,l.isIndexable));Xe(e,h)&&(h=$e(h,a,r&&r[e],l));return h}(t,e,i))),getOwnPropertyDescriptor:(e,i)=>e._descriptors.allKeys?Reflect.has(t,i)?{enumerable:!0,configurable:!0}:void 0:Reflect.getOwnPropertyDescriptor(t,i),getPrototypeOf:()=>Reflect.getPrototypeOf(t),has:(e,i)=>Reflect.has(t,i),ownKeys:()=>Reflect.ownKeys(t),set:(e,i,s)=>(t[i]=s,delete e[i],!0)})}function Ye(t,e={scriptable:!0,indexable:!0}){const{_scriptable:i=e.scriptable,_indexable:s=e.indexable,_allKeys:n=e.allKeys}=t;return{allKeys:n,scriptable:i,indexable:s,isScriptable:S(i)?i:()=>i,isIndexable:S(s)?s:()=>s}}const Ue=(t,e)=>t?t+w(e):e,Xe=(t,e)=>o(e)&&"adapters"!==t&&(null===Object.getPrototypeOf(e)||e.constructor===Object);function qe(t,e,i){if(Object.prototype.hasOwnProperty.call(t,e)||"constructor"===e)return t[e];const s=i();return t[e]=s,s}function Ke(t,e,i){return S(t)?t(e,i):t}const Ge=(t,e)=>!0===t?e:"string"==typeof t?M(e,t):void 0;function Je(t,e,i,s,n){for(const o of e){const e=Ge(i,o);if(e){t.add(e);const o=Ke(e._fallback,i,n);if(void 0!==o&&o!==i&&o!==s)return o}else if(!1===e&&void 0!==s&&i!==s)return null}return!1}function Ze(t,e,i,s){const a=e._rootScopes,r=Ke(e._fallback,i,s),l=[...t,...a],h=new Set;h.add(s);let c=Qe(h,l,i,r||i,s);return null!==c&&((void 0===r||r===i||(c=Qe(h,l,r,c,s),null!==c))&&je(Array.from(h),[""],a,r,(()=>function(t,e,i){const s=t._getTarget();e in s||(s[e]={});const a=s[e];if(n(a)&&o(i))return i;return a||{}}(e,i,s))))}function Qe(t,e,i,s,n){for(;i;)i=Je(t,e,i,s,n);return i}function ti(t,e){for(const i of e){if(!i)continue;const e=i[t];if(void 0!==e)return e}}function ei(t){let e=t._keys;return e||(e=t._keys=function(t){const e=new Set;for(const i of t)for(const t of Object.keys(i).filter((t=>!t.startsWith("_"))))e.add(t);return Array.from(e)}(t._scopes)),e}function ii(t,e,i,s){const{iScale:n}=t,{key:o="r"}=this._parsing,a=new Array(s);let r,l,h,c;for(r=0,l=s;r<l;++r)h=r+i,c=e[h],a[r]={r:n.parse(M(c,o),h)};return a}const si=Number.EPSILON||1e-14,ni=(t,e)=>e<t.length&&!t[e].skip&&t[e],oi=t=>"x"===t?"y":"x";function ai(t,e,i,s){const n=t.skip?e:t,o=e,a=i.skip?e:i,r=q(o,n),l=q(a,o);let h=r/(r+l),c=l/(r+l);h=isNaN(h)?0:h,c=isNaN(c)?0:c;const d=s*h,u=s*c;return{previous:{x:o.x-d*(a.x-n.x),y:o.y-d*(a.y-n.y)},next:{x:o.x+u*(a.x-n.x),y:o.y+u*(a.y-n.y)}}}function ri(t,e="x"){const i=oi(e),s=t.length,n=Array(s).fill(0),o=Array(s);let a,r,l,h=ni(t,0);for(a=0;a<s;++a)if(r=l,l=h,h=ni(t,a+1),l){if(h){const t=h[e]-l[e];n[a]=0!==t?(h[i]-l[i])/t:0}o[a]=r?h?F(n[a-1])!==F(n[a])?0:(n[a-1]+n[a])/2:n[a-1]:n[a]}!function(t,e,i){const s=t.length;let n,o,a,r,l,h=ni(t,0);for(let c=0;c<s-1;++c)l=h,h=ni(t,c+1),l&&h&&(V(e[c],0,si)?i[c]=i[c+1]=0:(n=i[c]/e[c],o=i[c+1]/e[c],r=Math.pow(n,2)+Math.pow(o,2),r<=9||(a=3/Math.sqrt(r),i[c]=n*a*e[c],i[c+1]=o*a*e[c])))}(t,n,o),function(t,e,i="x"){const s=oi(i),n=t.length;let o,a,r,l=ni(t,0);for(let h=0;h<n;++h){if(a=r,r=l,l=ni(t,h+1),!r)continue;const n=r[i],c=r[s];a&&(o=(n-a[i])/3,r[`cp1${i}`]=n-o,r[`cp1${s}`]=c-o*e[h]),l&&(o=(l[i]-n)/3,r[`cp2${i}`]=n+o,r[`cp2${s}`]=c+o*e[h])}}(t,o,e)}function li(t,e,i){return Math.max(Math.min(t,i),e)}function hi(t,e,i,s,n){let o,a,r,l;if(e.spanGaps&&(t=t.filter((t=>!t.skip))),"monotone"===e.cubicInterpolationMode)ri(t,n);else{let i=s?t[t.length-1]:t[0];for(o=0,a=t.length;o<a;++o)r=t[o],l=ai(i,r,t[Math.min(o+1,a-(s?0:1))%a],e.tension),r.cp1x=l.previous.x,r.cp1y=l.previous.y,r.cp2x=l.next.x,r.cp2y=l.next.y,i=r}e.capBezierPoints&&function(t,e){let i,s,n,o,a,r=Re(t[0],e);for(i=0,s=t.length;i<s;++i)a=o,o=r,r=i<s-1&&Re(t[i+1],e),o&&(n=t[i],a&&(n.cp1x=li(n.cp1x,e.left,e.right),n.cp1y=li(n.cp1y,e.top,e.bottom)),r&&(n.cp2x=li(n.cp2x,e.left,e.right),n.cp2y=li(n.cp2y,e.top,e.bottom)))}(t,i)}const ci=t=>0===t||1===t,di=(t,e,i)=>-Math.pow(2,10*(t-=1))*Math.sin((t-e)*O/i),ui=(t,e,i)=>Math.pow(2,-10*t)*Math.sin((t-e)*O/i)+1,fi={linear:t=>t,easeInQuad:t=>t*t,easeOutQuad:t=>-t*(t-2),easeInOutQuad:t=>(t/=.5)<1?.5*t*t:-.5*(--t*(t-2)-1),easeInCubic:t=>t*t*t,easeOutCubic:t=>(t-=1)*t*t+1,easeInOutCubic:t=>(t/=.5)<1?.5*t*t*t:.5*((t-=2)*t*t+2),easeInQuart:t=>t*t*t*t,easeOutQuart:t=>-((t-=1)*t*t*t-1),easeInOutQuart:t=>(t/=.5)<1?.5*t*t*t*t:-.5*((t-=2)*t*t*t-2),easeInQuint:t=>t*t*t*t*t,easeOutQuint:t=>(t-=1)*t*t*t*t+1,easeInOutQuint:t=>(t/=.5)<1?.5*t*t*t*t*t:.5*((t-=2)*t*t*t*t+2),easeInSine:t=>1-Math.cos(t*E),easeOutSine:t=>Math.sin(t*E),easeInOutSine:t=>-.5*(Math.cos(C*t)-1),easeInExpo:t=>0===t?0:Math.pow(2,10*(t-1)),easeOutExpo:t=>1===t?1:1-Math.pow(2,-10*t),easeInOutExpo:t=>ci(t)?t:t<.5?.5*Math.pow(2,10*(2*t-1)):.5*(2-Math.pow(2,-10*(2*t-1))),easeInCirc:t=>t>=1?t:-(Math.sqrt(1-t*t)-1),easeOutCirc:t=>Math.sqrt(1-(t-=1)*t),easeInOutCirc:t=>(t/=.5)<1?-.5*(Math.sqrt(1-t*t)-1):.5*(Math.sqrt(1-(t-=2)*t)+1),easeInElastic:t=>ci(t)?t:di(t,.075,.3),easeOutElastic:t=>ci(t)?t:ui(t,.075,.3),easeInOutElastic(t){const e=.1125;return ci(t)?t:t<.5?.5*di(2*t,e,.45):.5+.5*ui(2*t-1,e,.45)},easeInBack(t){const e=1.70158;return t*t*((e+1)*t-e)},easeOutBack(t){const e=1.70158;return(t-=1)*t*((e+1)*t+e)+1},easeInOutBack(t){let e=1.70158;return(t/=.5)<1?t*t*((1+(e*=1.525))*t-e)*.5:.5*((t-=2)*t*((1+(e*=1.525))*t+e)+2)},easeInBounce:t=>1-fi.easeOutBounce(1-t),easeOutBounce(t){const e=7.5625,i=2.75;return t<1/i?e*t*t:t<2/i?e*(t-=1.5/i)*t+.75:t<2.5/i?e*(t-=2.25/i)*t+.9375:e*(t-=2.625/i)*t+.984375},easeInOutBounce:t=>t<.5?.5*fi.easeInBounce(2*t):.5*fi.easeOutBounce(2*t-1)+.5};function gi(t,e,i,s){return{x:t.x+i*(e.x-t.x),y:t.y+i*(e.y-t.y)}}function pi(t,e,i,s){return{x:t.x+i*(e.x-t.x),y:"middle"===s?i<.5?t.y:e.y:"after"===s?i<1?t.y:e.y:i>0?e.y:t.y}}function mi(t,e,i,s){const n={x:t.cp2x,y:t.cp2y},o={x:e.cp1x,y:e.cp1y},a=gi(t,n,i),r=gi(n,o,i),l=gi(o,e,i),h=gi(a,r,i),c=gi(r,l,i);return gi(h,c,i)}const xi=/^(normal|(\d+(?:\.\d+)?)(px|em|%)?)$/,bi=/^(normal|italic|initial|inherit|unset|(oblique( -?[0-9]?[0-9]deg)?))$/;function _i(t,e){const i=(""+t).match(xi);if(!i||"normal"===i[1])return 1.2*e;switch(t=+i[2],i[3]){case"px":return t;case"%":t/=100}return e*t}const yi=t=>+t||0;function vi(t,e){const i={},s=o(e),n=s?Object.keys(e):e,a=o(t)?s?i=>l(t[i],t[e[i]]):e=>t[e]:()=>t;for(const t of n)i[t]=yi(a(t));return i}function Mi(t){return vi(t,{top:"y",right:"x",bottom:"y",left:"x"})}function wi(t){return vi(t,["topLeft","topRight","bottomLeft","bottomRight"])}function ki(t){const e=Mi(t);return e.width=e.left+e.right,e.height=e.top+e.bottom,e}function Si(t,e){t=t||{},e=e||ue.font;let i=l(t.size,e.size);"string"==typeof i&&(i=parseInt(i,10));let s=l(t.style,e.style);s&&!(""+s).match(bi)&&(console.warn('Invalid font style specified: "'+s+'"'),s=void 0);const n={family:l(t.family,e.family),lineHeight:_i(l(t.lineHeight,e.lineHeight),i),size:i,style:s,weight:l(t.weight,e.weight),string:""};return n.string=De(n),n}function Pi(t,e,i,s){let o,a,r,l=!0;for(o=0,a=t.length;o<a;++o)if(r=t[o],void 0!==r&&(void 0!==e&&"function"==typeof r&&(r=r(e),l=!1),void 0!==i&&n(r)&&(r=r[i%r.length],l=!1),void 0!==r))return s&&!l&&(s.cacheable=!1),r}function Di(t,e,i){const{min:s,max:n}=t,o=c(e,(n-s)/2),a=(t,e)=>i&&0===t?0:t+e;return{min:a(s,-Math.abs(o)),max:a(n,o)}}function Ci(t,e){return Object.assign(Object.create(t),e)}function Oi(t,e,i){return t?function(t,e){return{x:i=>t+t+e-i,setWidth(t){e=t},textAlign:t=>"center"===t?t:"right"===t?"left":"right",xPlus:(t,e)=>t-e,leftForLtr:(t,e)=>t-e}}(e,i):{x:t=>t,setWidth(t){},textAlign:t=>t,xPlus:(t,e)=>t+e,leftForLtr:(t,e)=>t}}function Ai(t,e){let i,s;"ltr"!==e&&"rtl"!==e||(i=t.canvas.style,s=[i.getPropertyValue("direction"),i.getPropertyPriority("direction")],i.setProperty("direction",e,"important"),t.prevTextDirection=s)}function Ti(t,e){void 0!==e&&(delete t.prevTextDirection,t.canvas.style.setProperty("direction",e[0],e[1]))}function Li(t){return"angle"===t?{between:J,compare:K,normalize:G}:{between:tt,compare:(t,e)=>t-e,normalize:t=>t}}function Ei({start:t,end:e,count:i,loop:s,style:n}){return{start:t%i,end:e%i,loop:s&&(e-t+1)%i==0,style:n}}function Ri(t,e,i){if(!i)return[t];const{property:s,start:n,end:o}=i,a=e.length,{compare:r,between:l,normalize:h}=Li(s),{start:c,end:d,loop:u,style:f}=function(t,e,i){const{property:s,start:n,end:o}=i,{between:a,normalize:r}=Li(s),l=e.length;let h,c,{start:d,end:u,loop:f}=t;if(f){for(d+=l,u+=l,h=0,c=l;h<c&&a(r(e[d%l][s]),n,o);++h)d--,u--;d%=l,u%=l}return u<d&&(u+=l),{start:d,end:u,loop:f,style:t.style}}(t,e,i),g=[];let p,m,x,b=!1,_=null;const y=()=>b||l(n,x,p)&&0!==r(n,x),v=()=>!b||0===r(o,p)||l(o,x,p);for(let t=c,i=c;t<=d;++t)m=e[t%a],m.skip||(p=h(m[s]),p!==x&&(b=l(p,n,o),null===_&&y()&&(_=0===r(p,n)?t:i),null!==_&&v()&&(g.push(Ei({start:_,end:t,loop:u,count:a,style:f})),_=null),i=t,x=p));return null!==_&&g.push(Ei({start:_,end:d,loop:u,count:a,style:f})),g}function Ii(t,e){const i=[],s=t.segments;for(let n=0;n<s.length;n++){const o=Ri(s[n],t.points,e);o.length&&i.push(...o)}return i}function zi(t,e){const i=t.points,s=t.options.spanGaps,n=i.length;if(!n)return[];const o=!!t._loop,{start:a,end:r}=function(t,e,i,s){let n=0,o=e-1;if(i&&!s)for(;n<e&&!t[n].skip;)n++;for(;n<e&&t[n].skip;)n++;for(n%=e,i&&(o+=n);o>n&&t[o%e].skip;)o--;return o%=e,{start:n,end:o}}(i,n,o,s);if(!0===s)return Fi(t,[{start:a,end:r,loop:o}],i,e);return Fi(t,function(t,e,i,s){const n=t.length,o=[];let a,r=e,l=t[e];for(a=e+1;a<=i;++a){const i=t[a%n];i.skip||i.stop?l.skip||(s=!1,o.push({start:e%n,end:(a-1)%n,loop:s}),e=r=i.stop?a:null):(r=a,l.skip&&(e=a)),l=i}return null!==r&&o.push({start:e%n,end:r%n,loop:s}),o}(i,a,r<a?r+n:r,!!t._fullLoop&&0===a&&r===n-1),i,e)}function Fi(t,e,i,s){return s&&s.setContext&&i?function(t,e,i,s){const n=t._chart.getContext(),o=Vi(t.options),{_datasetIndex:a,options:{spanGaps:r}}=t,l=i.length,h=[];let c=o,d=e[0].start,u=d;function f(t,e,s,n){const o=r?-1:1;if(t!==e){for(t+=l;i[t%l].skip;)t-=o;for(;i[e%l].skip;)e+=o;t%l!=e%l&&(h.push({start:t%l,end:e%l,loop:s,style:n}),c=n,d=e%l)}}for(const t of e){d=r?d:t.start;let e,o=i[d%l];for(u=d+1;u<=t.end;u++){const r=i[u%l];e=Vi(s.setContext(Ci(n,{type:"segment",p0:o,p1:r,p0DataIndex:(u-1)%l,p1DataIndex:u%l,datasetIndex:a}))),Bi(e,c)&&f(d,u-1,t.loop,c),o=r,c=e}d<u-1&&f(d,u-1,t.loop,c)}return h}(t,e,i,s):e}function Vi(t){return{backgroundColor:t.backgroundColor,borderCapStyle:t.borderCapStyle,borderDash:t.borderDash,borderDashOffset:t.borderDashOffset,borderJoinStyle:t.borderJoinStyle,borderWidth:t.borderWidth,borderColor:t.borderColor}}function Bi(t,e){if(!e)return!1;const i=[],s=function(t,e){return Zt(e)?(i.includes(e)||i.push(e),i.indexOf(e)):e};return JSON.stringify(t,s)!==JSON.stringify(e,s)}function Wi(t,e,i){return t.options.clip?t[i]:e[i]}function Ni(t,e){const i=e._clip;if(i.disabled)return!1;const s=function(t,e){const{xScale:i,yScale:s}=t;return i&&s?{left:Wi(i,e,"left"),right:Wi(i,e,"right"),top:Wi(s,e,"top"),bottom:Wi(s,e,"bottom")}:e}(e,t.chartArea);return{left:!1===i.left?0:s.left-(!0===i.left?0:i.left),right:!1===i.right?t.width:s.right+(!0===i.right?0:i.right),top:!1===i.top?0:s.top-(!0===i.top?0:i.top),bottom:!1===i.bottom?t.height:s.bottom+(!0===i.bottom?0:i.bottom)}}var Hi=Object.freeze({__proto__:null,HALF_PI:E,INFINITY:T,PI:C,PITAU:A,QUARTER_PI:R,RAD_PER_DEG:L,TAU:O,TWO_THIRDS_PI:I,_addGrace:Di,_alignPixel:Ae,_alignStartEnd:ft,_angleBetween:J,_angleDiff:K,_arrayUnique:lt,_attachContext:$e,_bezierCurveTo:Ve,_bezierInterpolation:mi,_boundSegment:Ri,_boundSegments:Ii,_capitalize:w,_computeSegments:zi,_createResolver:je,_decimalPlaces:U,_deprecated:function(t,e,i,s){void 0!==e&&console.warn(t+': "'+i+'" is deprecated. Please use "'+s+'" instead')},_descriptors:Ye,_elementsEqual:f,_factorize:W,_filterBetween:nt,_getParentNode:ge,_getStartAndCountOfVisiblePoints:pt,_int16Range:Q,_isBetween:tt,_isClickEvent:D,_isDomSupported:fe,_isPointInArea:Re,_limitValue:Z,_longestText:Oe,_lookup:et,_lookupByKey:it,_measureText:Ce,_merger:m,_mergerIf:_,_normalizeAngle:G,_parseObjectDataRadialScale:ii,_pointInLine:gi,_readValueToProps:vi,_rlookupByKey:st,_scaleRangesChanged:mt,_setMinAndMaxByKey:j,_splitKey:v,_steppedInterpolation:pi,_steppedLineTo:Fe,_textX:gt,_toLeftRightCenter:ut,_updateBezierControlPoints:hi,addRoundedRectPath:He,almostEquals:V,almostWhole:H,callback:d,clearCanvas:Te,clipArea:Ie,clone:g,color:Qt,createContext:Ci,debounce:dt,defined:k,distanceBetweenPoints:q,drawPoint:Le,drawPointLegend:Ee,each:u,easingEffects:fi,finiteOrDefault:r,fontString:function(t,e,i){return e+" "+t+"px "+i},formatNumber:ne,getAngleFromPoint:X,getDatasetClipArea:Ni,getHoverColor:te,getMaximumSize:we,getRelativePosition:ve,getRtlAdapter:Oi,getStyle:xe,isArray:n,isFinite:a,isFunction:S,isNullOrUndef:s,isNumber:N,isObject:o,isPatternOrGradient:Zt,listenArrayEvents:at,log10:z,merge:x,mergeIf:b,niceNum:B,noop:e,overrideTextDirection:Ai,readUsedSize:Pe,renderText:Ne,requestAnimFrame:ht,resolve:Pi,resolveObjectKey:M,restoreTextDirection:Ti,retinaScale:ke,setsEqual:P,sign:F,splineCurve:ai,splineCurveMonotone:ri,supportsEventListenerOptions:Se,throttled:ct,toDegrees:Y,toDimension:c,toFont:Si,toFontString:De,toLineHeight:_i,toPadding:ki,toPercentage:h,toRadians:$,toTRBL:Mi,toTRBLCorners:wi,uid:i,unclipArea:ze,unlistenArrayEvents:rt,valueOrDefault:l});function ji(t,e,i,n){const{controller:o,data:a,_sorted:r}=t,l=o._cachedMeta.iScale,h=t.dataset&&t.dataset.options?t.dataset.options.spanGaps:null;if(l&&e===l.axis&&"r"!==e&&r&&a.length){const r=l._reversePixels?st:it;if(!n){const n=r(a,e,i);if(h){const{vScale:e}=o._cachedMeta,{_parsed:i}=t,a=i.slice(0,n.lo+1).reverse().findIndex((t=>!s(t[e.axis])));n.lo-=Math.max(0,a);const r=i.slice(n.hi).findIndex((t=>!s(t[e.axis])));n.hi+=Math.max(0,r)}return n}if(o._sharedOptions){const t=a[0],s="function"==typeof t.getRange&&t.getRange(e);if(s){const t=r(a,e,i-s),n=r(a,e,i+s);return{lo:t.lo,hi:n.hi}}}}return{lo:0,hi:a.length-1}}function $i(t,e,i,s,n){const o=t.getSortedVisibleDatasetMetas(),a=i[e];for(let t=0,i=o.length;t<i;++t){const{index:i,data:r}=o[t],{lo:l,hi:h}=ji(o[t],e,a,n);for(let t=l;t<=h;++t){const e=r[t];e.skip||s(e,i,t)}}}function Yi(t,e,i,s,n){const o=[];if(!n&&!t.isPointInArea(e))return o;return $i(t,i,e,(function(i,a,r){(n||Re(i,t.chartArea,0))&&i.inRange(e.x,e.y,s)&&o.push({element:i,datasetIndex:a,index:r})}),!0),o}function Ui(t,e,i,s,n,o){let a=[];const r=function(t){const e=-1!==t.indexOf("x"),i=-1!==t.indexOf("y");return function(t,s){const n=e?Math.abs(t.x-s.x):0,o=i?Math.abs(t.y-s.y):0;return Math.sqrt(Math.pow(n,2)+Math.pow(o,2))}}(i);let l=Number.POSITIVE_INFINITY;return $i(t,i,e,(function(i,h,c){const d=i.inRange(e.x,e.y,n);if(s&&!d)return;const u=i.getCenterPoint(n);if(!(!!o||t.isPointInArea(u))&&!d)return;const f=r(e,u);f<l?(a=[{element:i,datasetIndex:h,index:c}],l=f):f===l&&a.push({element:i,datasetIndex:h,index:c})})),a}function Xi(t,e,i,s,n,o){return o||t.isPointInArea(e)?"r"!==i||s?Ui(t,e,i,s,n,o):function(t,e,i,s){let n=[];return $i(t,i,e,(function(t,i,o){const{startAngle:a,endAngle:r}=t.getProps(["startAngle","endAngle"],s),{angle:l}=X(t,{x:e.x,y:e.y});J(l,a,r)&&n.push({element:t,datasetIndex:i,index:o})})),n}(t,e,i,n):[]}function qi(t,e,i,s,n){const o=[],a="x"===i?"inXRange":"inYRange";let r=!1;return $i(t,i,e,((t,s,l)=>{t[a]&&t[a](e[i],n)&&(o.push({element:t,datasetIndex:s,index:l}),r=r||t.inRange(e.x,e.y,n))})),s&&!r?[]:o}var Ki={evaluateInteractionItems:$i,modes:{index(t,e,i,s){const n=ve(e,t),o=i.axis||"x",a=i.includeInvisible||!1,r=i.intersect?Yi(t,n,o,s,a):Xi(t,n,o,!1,s,a),l=[];return r.length?(t.getSortedVisibleDatasetMetas().forEach((t=>{const e=r[0].index,i=t.data[e];i&&!i.skip&&l.push({element:i,datasetIndex:t.index,index:e})})),l):[]},dataset(t,e,i,s){const n=ve(e,t),o=i.axis||"xy",a=i.includeInvisible||!1;let r=i.intersect?Yi(t,n,o,s,a):Xi(t,n,o,!1,s,a);if(r.length>0){const e=r[0].datasetIndex,i=t.getDatasetMeta(e).data;r=[];for(let t=0;t<i.length;++t)r.push({element:i[t],datasetIndex:e,index:t})}return r},point:(t,e,i,s)=>Yi(t,ve(e,t),i.axis||"xy",s,i.includeInvisible||!1),nearest(t,e,i,s){const n=ve(e,t),o=i.axis||"xy",a=i.includeInvisible||!1;return Xi(t,n,o,i.intersect,s,a)},x:(t,e,i,s)=>qi(t,ve(e,t),"x",i.intersect,s),y:(t,e,i,s)=>qi(t,ve(e,t),"y",i.intersect,s)}};const Gi=["left","top","right","bottom"];function Ji(t,e){return t.filter((t=>t.pos===e))}function Zi(t,e){return t.filter((t=>-1===Gi.indexOf(t.pos)&&t.box.axis===e))}function Qi(t,e){return t.sort(((t,i)=>{const s=e?i:t,n=e?t:i;return s.weight===n.weight?s.index-n.index:s.weight-n.weight}))}function ts(t,e){const i=function(t){const e={};for(const i of t){const{stack:t,pos:s,stackWeight:n}=i;if(!t||!Gi.includes(s))continue;const o=e[t]||(e[t]={count:0,placed:0,weight:0,size:0});o.count++,o.weight+=n}return e}(t),{vBoxMaxWidth:s,hBoxMaxHeight:n}=e;let o,a,r;for(o=0,a=t.length;o<a;++o){r=t[o];const{fullSize:a}=r.box,l=i[r.stack],h=l&&r.stackWeight/l.weight;r.horizontal?(r.width=h?h*s:a&&e.availableWidth,r.height=n):(r.width=s,r.height=h?h*n:a&&e.availableHeight)}return i}function es(t,e,i,s){return Math.max(t[i],e[i])+Math.max(t[s],e[s])}function is(t,e){t.top=Math.max(t.top,e.top),t.left=Math.max(t.left,e.left),t.bottom=Math.max(t.bottom,e.bottom),t.right=Math.max(t.right,e.right)}function ss(t,e,i,s){const{pos:n,box:a}=i,r=t.maxPadding;if(!o(n)){i.size&&(t[n]-=i.size);const e=s[i.stack]||{size:0,count:1};e.size=Math.max(e.size,i.horizontal?a.height:a.width),i.size=e.size/e.count,t[n]+=i.size}a.getPadding&&is(r,a.getPadding());const l=Math.max(0,e.outerWidth-es(r,t,"left","right")),h=Math.max(0,e.outerHeight-es(r,t,"top","bottom")),c=l!==t.w,d=h!==t.h;return t.w=l,t.h=h,i.horizontal?{same:c,other:d}:{same:d,other:c}}function ns(t,e){const i=e.maxPadding;function s(t){const s={left:0,top:0,right:0,bottom:0};return t.forEach((t=>{s[t]=Math.max(e[t],i[t])})),s}return s(t?["left","right"]:["top","bottom"])}function os(t,e,i,s){const n=[];let o,a,r,l,h,c;for(o=0,a=t.length,h=0;o<a;++o){r=t[o],l=r.box,l.update(r.width||e.w,r.height||e.h,ns(r.horizontal,e));const{same:a,other:d}=ss(e,i,r,s);h|=a&&n.length,c=c||d,l.fullSize||n.push(r)}return h&&os(n,e,i,s)||c}function as(t,e,i,s,n){t.top=i,t.left=e,t.right=e+s,t.bottom=i+n,t.width=s,t.height=n}function rs(t,e,i,s){const n=i.padding;let{x:o,y:a}=e;for(const r of t){const t=r.box,l=s[r.stack]||{count:1,placed:0,weight:1},h=r.stackWeight/l.weight||1;if(r.horizontal){const s=e.w*h,o=l.size||t.height;k(l.start)&&(a=l.start),t.fullSize?as(t,n.left,a,i.outerWidth-n.right-n.left,o):as(t,e.left+l.placed,a,s,o),l.start=a,l.placed+=s,a=t.bottom}else{const s=e.h*h,a=l.size||t.width;k(l.start)&&(o=l.start),t.fullSize?as(t,o,n.top,a,i.outerHeight-n.bottom-n.top):as(t,o,e.top+l.placed,a,s),l.start=o,l.placed+=s,o=t.right}}e.x=o,e.y=a}var ls={addBox(t,e){t.boxes||(t.boxes=[]),e.fullSize=e.fullSize||!1,e.position=e.position||"top",e.weight=e.weight||0,e._layers=e._layers||function(){return[{z:0,draw(t){e.draw(t)}}]},t.boxes.push(e)},removeBox(t,e){const i=t.boxes?t.boxes.indexOf(e):-1;-1!==i&&t.boxes.splice(i,1)},configure(t,e,i){e.fullSize=i.fullSize,e.position=i.position,e.weight=i.weight},update(t,e,i,s){if(!t)return;const n=ki(t.options.layout.padding),o=Math.max(e-n.width,0),a=Math.max(i-n.height,0),r=function(t){const e=function(t){const e=[];let i,s,n,o,a,r;for(i=0,s=(t||[]).length;i<s;++i)n=t[i],({position:o,options:{stack:a,stackWeight:r=1}}=n),e.push({index:i,box:n,pos:o,horizontal:n.isHorizontal(),weight:n.weight,stack:a&&o+a,stackWeight:r});return e}(t),i=Qi(e.filter((t=>t.box.fullSize)),!0),s=Qi(Ji(e,"left"),!0),n=Qi(Ji(e,"right")),o=Qi(Ji(e,"top"),!0),a=Qi(Ji(e,"bottom")),r=Zi(e,"x"),l=Zi(e,"y");return{fullSize:i,leftAndTop:s.concat(o),rightAndBottom:n.concat(l).concat(a).concat(r),chartArea:Ji(e,"chartArea"),vertical:s.concat(n).concat(l),horizontal:o.concat(a).concat(r)}}(t.boxes),l=r.vertical,h=r.horizontal;u(t.boxes,(t=>{"function"==typeof t.beforeLayout&&t.beforeLayout()}));const c=l.reduce(((t,e)=>e.box.options&&!1===e.box.options.display?t:t+1),0)||1,d=Object.freeze({outerWidth:e,outerHeight:i,padding:n,availableWidth:o,availableHeight:a,vBoxMaxWidth:o/2/c,hBoxMaxHeight:a/2}),f=Object.assign({},n);is(f,ki(s));const g=Object.assign({maxPadding:f,w:o,h:a,x:n.left,y:n.top},n),p=ts(l.concat(h),d);os(r.fullSize,g,d,p),os(l,g,d,p),os(h,g,d,p)&&os(l,g,d,p),function(t){const e=t.maxPadding;function i(i){const s=Math.max(e[i]-t[i],0);return t[i]+=s,s}t.y+=i("top"),t.x+=i("left"),i("right"),i("bottom")}(g),rs(r.leftAndTop,g,d,p),g.x+=g.w,g.y+=g.h,rs(r.rightAndBottom,g,d,p),t.chartArea={left:g.left,top:g.top,right:g.left+g.w,bottom:g.top+g.h,height:g.h,width:g.w},u(r.chartArea,(e=>{const i=e.box;Object.assign(i,t.chartArea),i.update(g.w,g.h,{left:0,top:0,right:0,bottom:0})}))}};class hs{acquireContext(t,e){}releaseContext(t){return!1}addEventListener(t,e,i){}removeEventListener(t,e,i){}getDevicePixelRatio(){return 1}getMaximumSize(t,e,i,s){return e=Math.max(0,e||t.width),i=i||t.height,{width:e,height:Math.max(0,s?Math.floor(e/s):i)}}isAttached(t){return!0}updateConfig(t){}}class cs extends hs{acquireContext(t){return t&&t.getContext&&t.getContext("2d")||null}updateConfig(t){t.options.animation=!1}}const ds="$chartjs",us={touchstart:"mousedown",touchmove:"mousemove",touchend:"mouseup",pointerenter:"mouseenter",pointerdown:"mousedown",pointermove:"mousemove",pointerup:"mouseup",pointerleave:"mouseout",pointerout:"mouseout"},fs=t=>null===t||""===t;const gs=!!Se&&{passive:!0};function ps(t,e,i){t&&t.canvas&&t.canvas.removeEventListener(e,i,gs)}function ms(t,e){for(const i of t)if(i===e||i.contains(e))return!0}function xs(t,e,i){const s=t.canvas,n=new MutationObserver((t=>{let e=!1;for(const i of t)e=e||ms(i.addedNodes,s),e=e&&!ms(i.removedNodes,s);e&&i()}));return n.observe(document,{childList:!0,subtree:!0}),n}function bs(t,e,i){const s=t.canvas,n=new MutationObserver((t=>{let e=!1;for(const i of t)e=e||ms(i.removedNodes,s),e=e&&!ms(i.addedNodes,s);e&&i()}));return n.observe(document,{childList:!0,subtree:!0}),n}const _s=new Map;let ys=0;function vs(){const t=window.devicePixelRatio;t!==ys&&(ys=t,_s.forEach(((e,i)=>{i.currentDevicePixelRatio!==t&&e()})))}function Ms(t,e,i){const s=t.canvas,n=s&&ge(s);if(!n)return;const o=ct(((t,e)=>{const s=n.clientWidth;i(t,e),s<n.clientWidth&&i()}),window),a=new ResizeObserver((t=>{const e=t[0],i=e.contentRect.width,s=e.contentRect.height;0===i&&0===s||o(i,s)}));return a.observe(n),function(t,e){_s.size||window.addEventListener("resize",vs),_s.set(t,e)}(t,o),a}function ws(t,e,i){i&&i.disconnect(),"resize"===e&&function(t){_s.delete(t),_s.size||window.removeEventListener("resize",vs)}(t)}function ks(t,e,i){const s=t.canvas,n=ct((e=>{null!==t.ctx&&i(function(t,e){const i=us[t.type]||t.type,{x:s,y:n}=ve(t,e);return{type:i,chart:e,native:t,x:void 0!==s?s:null,y:void 0!==n?n:null}}(e,t))}),t);return function(t,e,i){t&&t.addEventListener(e,i,gs)}(s,e,n),n}class Ss extends hs{acquireContext(t,e){const i=t&&t.getContext&&t.getContext("2d");return i&&i.canvas===t?(function(t,e){const i=t.style,s=t.getAttribute("height"),n=t.getAttribute("width");if(t[ds]={initial:{height:s,width:n,style:{display:i.display,height:i.height,width:i.width}}},i.display=i.display||"block",i.boxSizing=i.boxSizing||"border-box",fs(n)){const e=Pe(t,"width");void 0!==e&&(t.width=e)}if(fs(s))if(""===t.style.height)t.height=t.width/(e||2);else{const e=Pe(t,"height");void 0!==e&&(t.height=e)}}(t,e),i):null}releaseContext(t){const e=t.canvas;if(!e[ds])return!1;const i=e[ds].initial;["height","width"].forEach((t=>{const n=i[t];s(n)?e.removeAttribute(t):e.setAttribute(t,n)}));const n=i.style||{};return Object.keys(n).forEach((t=>{e.style[t]=n[t]})),e.width=e.width,delete e[ds],!0}addEventListener(t,e,i){this.removeEventListener(t,e);const s=t.$proxies||(t.$proxies={}),n={attach:xs,detach:bs,resize:Ms}[e]||ks;s[e]=n(t,e,i)}removeEventListener(t,e){const i=t.$proxies||(t.$proxies={}),s=i[e];if(!s)return;({attach:ws,detach:ws,resize:ws}[e]||ps)(t,e,s),i[e]=void 0}getDevicePixelRatio(){return window.devicePixelRatio}getMaximumSize(t,e,i,s){return we(t,e,i,s)}isAttached(t){const e=t&&ge(t);return!(!e||!e.isConnected)}}function Ps(t){return!fe()||"undefined"!=typeof OffscreenCanvas&&t instanceof OffscreenCanvas?cs:Ss}var Ds=Object.freeze({__proto__:null,BasePlatform:hs,BasicPlatform:cs,DomPlatform:Ss,_detectPlatform:Ps});const Cs="transparent",Os={boolean:(t,e,i)=>i>.5?e:t,color(t,e,i){const s=Qt(t||Cs),n=s.valid&&Qt(e||Cs);return n&&n.valid?n.mix(s,i).hexString():e},number:(t,e,i)=>t+(e-t)*i};class As{constructor(t,e,i,s){const n=e[i];s=Pi([t.to,s,n,t.from]);const o=Pi([t.from,n,s]);this._active=!0,this._fn=t.fn||Os[t.type||typeof o],this._easing=fi[t.easing]||fi.linear,this._start=Math.floor(Date.now()+(t.delay||0)),this._duration=this._total=Math.floor(t.duration),this._loop=!!t.loop,this._target=e,this._prop=i,this._from=o,this._to=s,this._promises=void 0}active(){return this._active}update(t,e,i){if(this._active){this._notify(!1);const s=this._target[this._prop],n=i-this._start,o=this._duration-n;this._start=i,this._duration=Math.floor(Math.max(o,t.duration)),this._total+=n,this._loop=!!t.loop,this._to=Pi([t.to,e,s,t.from]),this._from=Pi([t.from,s,e])}}cancel(){this._active&&(this.tick(Date.now()),this._active=!1,this._notify(!1))}tick(t){const e=t-this._start,i=this._duration,s=this._prop,n=this._from,o=this._loop,a=this._to;let r;if(this._active=n!==a&&(o||e<i),!this._active)return this._target[s]=a,void this._notify(!0);e<0?this._target[s]=n:(r=e/i%2,r=o&&r>1?2-r:r,r=this._easing(Math.min(1,Math.max(0,r))),this._target[s]=this._fn(n,a,r))}wait(){const t=this._promises||(this._promises=[]);return new Promise(((e,i)=>{t.push({res:e,rej:i})}))}_notify(t){const e=t?"res":"rej",i=this._promises||[];for(let t=0;t<i.length;t++)i[t][e]()}}class Ts{constructor(t,e){this._chart=t,this._properties=new Map,this.configure(e)}configure(t){if(!o(t))return;const e=Object.keys(ue.animation),i=this._properties;Object.getOwnPropertyNames(t).forEach((s=>{const a=t[s];if(!o(a))return;const r={};for(const t of e)r[t]=a[t];(n(a.properties)&&a.properties||[s]).forEach((t=>{t!==s&&i.has(t)||i.set(t,r)}))}))}_animateOptions(t,e){const i=e.options,s=function(t,e){if(!e)return;let i=t.options;if(!i)return void(t.options=e);i.$shared&&(t.options=i=Object.assign({},i,{$shared:!1,$animations:{}}));return i}(t,i);if(!s)return[];const n=this._createAnimations(s,i);return i.$shared&&function(t,e){const i=[],s=Object.keys(e);for(let e=0;e<s.length;e++){const n=t[s[e]];n&&n.active()&&i.push(n.wait())}return Promise.all(i)}(t.options.$animations,i).then((()=>{t.options=i}),(()=>{})),n}_createAnimations(t,e){const i=this._properties,s=[],n=t.$animations||(t.$animations={}),o=Object.keys(e),a=Date.now();let r;for(r=o.length-1;r>=0;--r){const l=o[r];if("$"===l.charAt(0))continue;if("options"===l){s.push(...this._animateOptions(t,e));continue}const h=e[l];let c=n[l];const d=i.get(l);if(c){if(d&&c.active()){c.update(d,h,a);continue}c.cancel()}d&&d.duration?(n[l]=c=new As(d,t,l,h),s.push(c)):t[l]=h}return s}update(t,e){if(0===this._properties.size)return void Object.assign(t,e);const i=this._createAnimations(t,e);return i.length?(bt.add(this._chart,i),!0):void 0}}function Ls(t,e){const i=t&&t.options||{},s=i.reverse,n=void 0===i.min?e:0,o=void 0===i.max?e:0;return{start:s?o:n,end:s?n:o}}function Es(t,e){const i=[],s=t._getSortedDatasetMetas(e);let n,o;for(n=0,o=s.length;n<o;++n)i.push(s[n].index);return i}function Rs(t,e,i,s={}){const n=t.keys,o="single"===s.mode;let r,l,h,c;if(null===e)return;let d=!1;for(r=0,l=n.length;r<l;++r){if(h=+n[r],h===i){if(d=!0,s.all)continue;break}c=t.values[h],a(c)&&(o||0===e||F(e)===F(c))&&(e+=c)}return d||s.all?e:0}function Is(t,e){const i=t&&t.options.stacked;return i||void 0===i&&void 0!==e.stack}function zs(t,e,i){const s=t[e]||(t[e]={});return s[i]||(s[i]={})}function Fs(t,e,i,s){for(const n of e.getMatchingVisibleMetas(s).reverse()){const e=t[n.index];if(i&&e>0||!i&&e<0)return n.index}return null}function Vs(t,e){const{chart:i,_cachedMeta:s}=t,n=i._stacks||(i._stacks={}),{iScale:o,vScale:a,index:r}=s,l=o.axis,h=a.axis,c=function(t,e,i){return`${t.id}.${e.id}.${i.stack||i.type}`}(o,a,s),d=e.length;let u;for(let t=0;t<d;++t){const i=e[t],{[l]:o,[h]:d}=i;u=(i._stacks||(i._stacks={}))[h]=zs(n,c,o),u[r]=d,u._top=Fs(u,a,!0,s.type),u._bottom=Fs(u,a,!1,s.type);(u._visualValues||(u._visualValues={}))[r]=d}}function Bs(t,e){const i=t.scales;return Object.keys(i).filter((t=>i[t].axis===e)).shift()}function Ws(t,e){const i=t.controller.index,s=t.vScale&&t.vScale.axis;if(s){e=e||t._parsed;for(const t of e){const e=t._stacks;if(!e||void 0===e[s]||void 0===e[s][i])return;delete e[s][i],void 0!==e[s]._visualValues&&void 0!==e[s]._visualValues[i]&&delete e[s]._visualValues[i]}}}const Ns=t=>"reset"===t||"none"===t,Hs=(t,e)=>e?t:Object.assign({},t);class js{static defaults={};static datasetElementType=null;static dataElementType=null;constructor(t,e){this.chart=t,this._ctx=t.ctx,this.index=e,this._cachedDataOpts={},this._cachedMeta=this.getMeta(),this._type=this._cachedMeta.type,this.options=void 0,this._parsing=!1,this._data=void 0,this._objectData=void 0,this._sharedOptions=void 0,this._drawStart=void 0,this._drawCount=void 0,this.enableOptionSharing=!1,this.supportsDecimation=!1,this.$context=void 0,this._syncList=[],this.datasetElementType=new.target.datasetElementType,this.dataElementType=new.target.dataElementType,this.initialize()}initialize(){const t=this._cachedMeta;this.configure(),this.linkScales(),t._stacked=Is(t.vScale,t),this.addElements(),this.options.fill&&!this.chart.isPluginEnabled("filler")&&console.warn("Tried to use the 'fill' option without the 'Filler' plugin enabled. Please import and register the 'Filler' plugin and make sure it is not disabled in the options")}updateIndex(t){this.index!==t&&Ws(this._cachedMeta),this.index=t}linkScales(){const t=this.chart,e=this._cachedMeta,i=this.getDataset(),s=(t,e,i,s)=>"x"===t?e:"r"===t?s:i,n=e.xAxisID=l(i.xAxisID,Bs(t,"x")),o=e.yAxisID=l(i.yAxisID,Bs(t,"y")),a=e.rAxisID=l(i.rAxisID,Bs(t,"r")),r=e.indexAxis,h=e.iAxisID=s(r,n,o,a),c=e.vAxisID=s(r,o,n,a);e.xScale=this.getScaleForId(n),e.yScale=this.getScaleForId(o),e.rScale=this.getScaleForId(a),e.iScale=this.getScaleForId(h),e.vScale=this.getScaleForId(c)}getDataset(){return this.chart.data.datasets[this.index]}getMeta(){return this.chart.getDatasetMeta(this.index)}getScaleForId(t){return this.chart.scales[t]}_getOtherScale(t){const e=this._cachedMeta;return t===e.iScale?e.vScale:e.iScale}reset(){this._update("reset")}_destroy(){const t=this._cachedMeta;this._data&&rt(this._data,this),t._stacked&&Ws(t)}_dataCheck(){const t=this.getDataset(),e=t.data||(t.data=[]),i=this._data;if(o(e)){const t=this._cachedMeta;this._data=function(t,e){const{iScale:i,vScale:s}=e,n="x"===i.axis?"x":"y",o="x"===s.axis?"x":"y",a=Object.keys(t),r=new Array(a.length);let l,h,c;for(l=0,h=a.length;l<h;++l)c=a[l],r[l]={[n]:c,[o]:t[c]};return r}(e,t)}else if(i!==e){if(i){rt(i,this);const t=this._cachedMeta;Ws(t),t._parsed=[]}e&&Object.isExtensible(e)&&at(e,this),this._syncList=[],this._data=e}}addElements(){const t=this._cachedMeta;this._dataCheck(),this.datasetElementType&&(t.dataset=new this.datasetElementType)}buildOrUpdateElements(t){const e=this._cachedMeta,i=this.getDataset();let s=!1;this._dataCheck();const n=e._stacked;e._stacked=Is(e.vScale,e),e.stack!==i.stack&&(s=!0,Ws(e),e.stack=i.stack),this._resyncElements(t),(s||n!==e._stacked)&&(Vs(this,e._parsed),e._stacked=Is(e.vScale,e))}configure(){const t=this.chart.config,e=t.datasetScopeKeys(this._type),i=t.getOptionScopes(this.getDataset(),e,!0);this.options=t.createResolver(i,this.getContext()),this._parsing=this.options.parsing,this._cachedDataOpts={}}parse(t,e){const{_cachedMeta:i,_data:s}=this,{iScale:a,_stacked:r}=i,l=a.axis;let h,c,d,u=0===t&&e===s.length||i._sorted,f=t>0&&i._parsed[t-1];if(!1===this._parsing)i._parsed=s,i._sorted=!0,d=s;else{d=n(s[t])?this.parseArrayData(i,s,t,e):o(s[t])?this.parseObjectData(i,s,t,e):this.parsePrimitiveData(i,s,t,e);const a=()=>null===c[l]||f&&c[l]<f[l];for(h=0;h<e;++h)i._parsed[h+t]=c=d[h],u&&(a()&&(u=!1),f=c);i._sorted=u}r&&Vs(this,d)}parsePrimitiveData(t,e,i,s){const{iScale:n,vScale:o}=t,a=n.axis,r=o.axis,l=n.getLabels(),h=n===o,c=new Array(s);let d,u,f;for(d=0,u=s;d<u;++d)f=d+i,c[d]={[a]:h||n.parse(l[f],f),[r]:o.parse(e[f],f)};return c}parseArrayData(t,e,i,s){const{xScale:n,yScale:o}=t,a=new Array(s);let r,l,h,c;for(r=0,l=s;r<l;++r)h=r+i,c=e[h],a[r]={x:n.parse(c[0],h),y:o.parse(c[1],h)};return a}parseObjectData(t,e,i,s){const{xScale:n,yScale:o}=t,{xAxisKey:a="x",yAxisKey:r="y"}=this._parsing,l=new Array(s);let h,c,d,u;for(h=0,c=s;h<c;++h)d=h+i,u=e[d],l[h]={x:n.parse(M(u,a),d),y:o.parse(M(u,r),d)};return l}getParsed(t){return this._cachedMeta._parsed[t]}getDataElement(t){return this._cachedMeta.data[t]}applyStack(t,e,i){const s=this.chart,n=this._cachedMeta,o=e[t.axis];return Rs({keys:Es(s,!0),values:e._stacks[t.axis]._visualValues},o,n.index,{mode:i})}updateRangeFromParsed(t,e,i,s){const n=i[e.axis];let o=null===n?NaN:n;const a=s&&i._stacks[e.axis];s&&a&&(s.values=a,o=Rs(s,n,this._cachedMeta.index)),t.min=Math.min(t.min,o),t.max=Math.max(t.max,o)}getMinMax(t,e){const i=this._cachedMeta,s=i._parsed,n=i._sorted&&t===i.iScale,o=s.length,r=this._getOtherScale(t),l=((t,e,i)=>t&&!e.hidden&&e._stacked&&{keys:Es(i,!0),values:null})(e,i,this.chart),h={min:Number.POSITIVE_INFINITY,max:Number.NEGATIVE_INFINITY},{min:c,max:d}=function(t){const{min:e,max:i,minDefined:s,maxDefined:n}=t.getUserBounds();return{min:s?e:Number.NEGATIVE_INFINITY,max:n?i:Number.POSITIVE_INFINITY}}(r);let u,f;function g(){f=s[u];const e=f[r.axis];return!a(f[t.axis])||c>e||d<e}for(u=0;u<o&&(g()||(this.updateRangeFromParsed(h,t,f,l),!n));++u);if(n)for(u=o-1;u>=0;--u)if(!g()){this.updateRangeFromParsed(h,t,f,l);break}return h}getAllParsedValues(t){const e=this._cachedMeta._parsed,i=[];let s,n,o;for(s=0,n=e.length;s<n;++s)o=e[s][t.axis],a(o)&&i.push(o);return i}getMaxOverflow(){return!1}getLabelAndValue(t){const e=this._cachedMeta,i=e.iScale,s=e.vScale,n=this.getParsed(t);return{label:i?""+i.getLabelForValue(n[i.axis]):"",value:s?""+s.getLabelForValue(n[s.axis]):""}}_update(t){const e=this._cachedMeta;this.update(t||"default"),e._clip=function(t){let e,i,s,n;return o(t)?(e=t.top,i=t.right,s=t.bottom,n=t.left):e=i=s=n=t,{top:e,right:i,bottom:s,left:n,disabled:!1===t}}(l(this.options.clip,function(t,e,i){if(!1===i)return!1;const s=Ls(t,i),n=Ls(e,i);return{top:n.end,right:s.end,bottom:n.start,left:s.start}}(e.xScale,e.yScale,this.getMaxOverflow())))}update(t){}draw(){const t=this._ctx,e=this.chart,i=this._cachedMeta,s=i.data||[],n=e.chartArea,o=[],a=this._drawStart||0,r=this._drawCount||s.length-a,l=this.options.drawActiveElementsOnTop;let h;for(i.dataset&&i.dataset.draw(t,n,a,r),h=a;h<a+r;++h){const e=s[h];e.hidden||(e.active&&l?o.push(e):e.draw(t,n))}for(h=0;h<o.length;++h)o[h].draw(t,n)}getStyle(t,e){const i=e?"active":"default";return void 0===t&&this._cachedMeta.dataset?this.resolveDatasetElementOptions(i):this.resolveDataElementOptions(t||0,i)}getContext(t,e,i){const s=this.getDataset();let n;if(t>=0&&t<this._cachedMeta.data.length){const e=this._cachedMeta.data[t];n=e.$context||(e.$context=function(t,e,i){return Ci(t,{active:!1,dataIndex:e,parsed:void 0,raw:void 0,element:i,index:e,mode:"default",type:"data"})}(this.getContext(),t,e)),n.parsed=this.getParsed(t),n.raw=s.data[t],n.index=n.dataIndex=t}else n=this.$context||(this.$context=function(t,e){return Ci(t,{active:!1,dataset:void 0,datasetIndex:e,index:e,mode:"default",type:"dataset"})}(this.chart.getContext(),this.index)),n.dataset=s,n.index=n.datasetIndex=this.index;return n.active=!!e,n.mode=i,n}resolveDatasetElementOptions(t){return this._resolveElementOptions(this.datasetElementType.id,t)}resolveDataElementOptions(t,e){return this._resolveElementOptions(this.dataElementType.id,e,t)}_resolveElementOptions(t,e="default",i){const s="active"===e,n=this._cachedDataOpts,o=t+"-"+e,a=n[o],r=this.enableOptionSharing&&k(i);if(a)return Hs(a,r);const l=this.chart.config,h=l.datasetElementScopeKeys(this._type,t),c=s?[`${t}Hover`,"hover",t,""]:[t,""],d=l.getOptionScopes(this.getDataset(),h),u=Object.keys(ue.elements[t]),f=l.resolveNamedOptions(d,u,(()=>this.getContext(i,s,e)),c);return f.$shared&&(f.$shared=r,n[o]=Object.freeze(Hs(f,r))),f}_resolveAnimations(t,e,i){const s=this.chart,n=this._cachedDataOpts,o=`animation-${e}`,a=n[o];if(a)return a;let r;if(!1!==s.options.animation){const s=this.chart.config,n=s.datasetAnimationScopeKeys(this._type,e),o=s.getOptionScopes(this.getDataset(),n);r=s.createResolver(o,this.getContext(t,i,e))}const l=new Ts(s,r&&r.animations);return r&&r._cacheable&&(n[o]=Object.freeze(l)),l}getSharedOptions(t){if(t.$shared)return this._sharedOptions||(this._sharedOptions=Object.assign({},t))}includeOptions(t,e){return!e||Ns(t)||this.chart._animationsDisabled}_getSharedOptions(t,e){const i=this.resolveDataElementOptions(t,e),s=this._sharedOptions,n=this.getSharedOptions(i),o=this.includeOptions(e,n)||n!==s;return this.updateSharedOptions(n,e,i),{sharedOptions:n,includeOptions:o}}updateElement(t,e,i,s){Ns(s)?Object.assign(t,i):this._resolveAnimations(e,s).update(t,i)}updateSharedOptions(t,e,i){t&&!Ns(e)&&this._resolveAnimations(void 0,e).update(t,i)}_setStyle(t,e,i,s){t.active=s;const n=this.getStyle(e,s);this._resolveAnimations(e,i,s).update(t,{options:!s&&this.getSharedOptions(n)||n})}removeHoverStyle(t,e,i){this._setStyle(t,i,"active",!1)}setHoverStyle(t,e,i){this._setStyle(t,i,"active",!0)}_removeDatasetHoverStyle(){const t=this._cachedMeta.dataset;t&&this._setStyle(t,void 0,"active",!1)}_setDatasetHoverStyle(){const t=this._cachedMeta.dataset;t&&this._setStyle(t,void 0,"active",!0)}_resyncElements(t){const e=this._data,i=this._cachedMeta.data;for(const[t,e,i]of this._syncList)this[t](e,i);this._syncList=[];const s=i.length,n=e.length,o=Math.min(n,s);o&&this.parse(0,o),n>s?this._insertElements(s,n-s,t):n<s&&this._removeElements(n,s-n)}_insertElements(t,e,i=!0){const s=this._cachedMeta,n=s.data,o=t+e;let a;const r=t=>{for(t.length+=e,a=t.length-1;a>=o;a--)t[a]=t[a-e]};for(r(n),a=t;a<o;++a)n[a]=new this.dataElementType;this._parsing&&r(s._parsed),this.parse(t,e),i&&this.updateElements(n,t,e,"reset")}updateElements(t,e,i,s){}_removeElements(t,e){const i=this._cachedMeta;if(this._parsing){const s=i._parsed.splice(t,e);i._stacked&&Ws(i,s)}i.data.splice(t,e)}_sync(t){if(this._parsing)this._syncList.push(t);else{const[e,i,s]=t;this[e](i,s)}this.chart._dataChanges.push([this.index,...t])}_onDataPush(){const t=arguments.length;this._sync(["_insertElements",this.getDataset().data.length-t,t])}_onDataPop(){this._sync(["_removeElements",this._cachedMeta.data.length-1,1])}_onDataShift(){this._sync(["_removeElements",0,1])}_onDataSplice(t,e){e&&this._sync(["_removeElements",t,e]);const i=arguments.length-2;i&&this._sync(["_insertElements",t,i])}_onDataUnshift(){this._sync(["_insertElements",0,arguments.length])}}class $s{static defaults={};static defaultRoutes=void 0;x;y;active=!1;options;$animations;tooltipPosition(t){const{x:e,y:i}=this.getProps(["x","y"],t);return{x:e,y:i}}hasValue(){return N(this.x)&&N(this.y)}getProps(t,e){const i=this.$animations;if(!e||!i)return this;const s={};return t.forEach((t=>{s[t]=i[t]&&i[t].active()?i[t]._to:this[t]})),s}}function Ys(t,e){const i=t.options.ticks,n=function(t){const e=t.options.offset,i=t._tickSize(),s=t._length/i+(e?0:1),n=t._maxLength/i;return Math.floor(Math.min(s,n))}(t),o=Math.min(i.maxTicksLimit||n,n),a=i.major.enabled?function(t){const e=[];let i,s;for(i=0,s=t.length;i<s;i++)t[i].major&&e.push(i);return e}(e):[],r=a.length,l=a[0],h=a[r-1],c=[];if(r>o)return function(t,e,i,s){let n,o=0,a=i[0];for(s=Math.ceil(s),n=0;n<t.length;n++)n===a&&(e.push(t[n]),o++,a=i[o*s])}(e,c,a,r/o),c;const d=function(t,e,i){const s=function(t){const e=t.length;let i,s;if(e<2)return!1;for(s=t[0],i=1;i<e;++i)if(t[i]-t[i-1]!==s)return!1;return s}(t),n=e.length/i;if(!s)return Math.max(n,1);const o=W(s);for(let t=0,e=o.length-1;t<e;t++){const e=o[t];if(e>n)return e}return Math.max(n,1)}(a,e,o);if(r>0){let t,i;const n=r>1?Math.round((h-l)/(r-1)):null;for(Us(e,c,d,s(n)?0:l-n,l),t=0,i=r-1;t<i;t++)Us(e,c,d,a[t],a[t+1]);return Us(e,c,d,h,s(n)?e.length:h+n),c}return Us(e,c,d),c}function Us(t,e,i,s,n){const o=l(s,0),a=Math.min(l(n,t.length),t.length);let r,h,c,d=0;for(i=Math.ceil(i),n&&(r=n-s,i=r/Math.floor(r/i)),c=o;c<0;)d++,c=Math.round(o+d*i);for(h=Math.max(o,0);h<a;h++)h===c&&(e.push(t[h]),d++,c=Math.round(o+d*i))}const Xs=(t,e,i)=>"top"===e||"left"===e?t[e]+i:t[e]-i,qs=(t,e)=>Math.min(e||t,t);function Ks(t,e){const i=[],s=t.length/e,n=t.length;let o=0;for(;o<n;o+=s)i.push(t[Math.floor(o)]);return i}function Gs(t,e,i){const s=t.ticks.length,n=Math.min(e,s-1),o=t._startPixel,a=t._endPixel,r=1e-6;let l,h=t.getPixelForTick(n);if(!(i&&(l=1===s?Math.max(h-o,a-h):0===e?(t.getPixelForTick(1)-h)/2:(h-t.getPixelForTick(n-1))/2,h+=n<e?l:-l,h<o-r||h>a+r)))return h}function Js(t){return t.drawTicks?t.tickLength:0}function Zs(t,e){if(!t.display)return 0;const i=Si(t.font,e),s=ki(t.padding);return(n(t.text)?t.text.length:1)*i.lineHeight+s.height}function Qs(t,e,i){let s=ut(t);return(i&&"right"!==e||!i&&"right"===e)&&(s=(t=>"left"===t?"right":"right"===t?"left":t)(s)),s}class tn extends $s{constructor(t){super(),this.id=t.id,this.type=t.type,this.options=void 0,this.ctx=t.ctx,this.chart=t.chart,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.width=void 0,this.height=void 0,this._margins={left:0,right:0,top:0,bottom:0},this.maxWidth=void 0,this.maxHeight=void 0,this.paddingTop=void 0,this.paddingBottom=void 0,this.paddingLeft=void 0,this.paddingRight=void 0,this.axis=void 0,this.labelRotation=void 0,this.min=void 0,this.max=void 0,this._range=void 0,this.ticks=[],this._gridLineItems=null,this._labelItems=null,this._labelSizes=null,this._length=0,this._maxLength=0,this._longestTextCache={},this._startPixel=void 0,this._endPixel=void 0,this._reversePixels=!1,this._userMax=void 0,this._userMin=void 0,this._suggestedMax=void 0,this._suggestedMin=void 0,this._ticksLength=0,this._borderValue=0,this._cache={},this._dataLimitsCached=!1,this.$context=void 0}init(t){this.options=t.setContext(this.getContext()),this.axis=t.axis,this._userMin=this.parse(t.min),this._userMax=this.parse(t.max),this._suggestedMin=this.parse(t.suggestedMin),this._suggestedMax=this.parse(t.suggestedMax)}parse(t,e){return t}getUserBounds(){let{_userMin:t,_userMax:e,_suggestedMin:i,_suggestedMax:s}=this;return t=r(t,Number.POSITIVE_INFINITY),e=r(e,Number.NEGATIVE_INFINITY),i=r(i,Number.POSITIVE_INFINITY),s=r(s,Number.NEGATIVE_INFINITY),{min:r(t,i),max:r(e,s),minDefined:a(t),maxDefined:a(e)}}getMinMax(t){let e,{min:i,max:s,minDefined:n,maxDefined:o}=this.getUserBounds();if(n&&o)return{min:i,max:s};const a=this.getMatchingVisibleMetas();for(let r=0,l=a.length;r<l;++r)e=a[r].controller.getMinMax(this,t),n||(i=Math.min(i,e.min)),o||(s=Math.max(s,e.max));return i=o&&i>s?s:i,s=n&&i>s?i:s,{min:r(i,r(s,i)),max:r(s,r(i,s))}}getPadding(){return{left:this.paddingLeft||0,top:this.paddingTop||0,right:this.paddingRight||0,bottom:this.paddingBottom||0}}getTicks(){return this.ticks}getLabels(){const t=this.chart.data;return this.options.labels||(this.isHorizontal()?t.xLabels:t.yLabels)||t.labels||[]}getLabelItems(t=this.chart.chartArea){return this._labelItems||(this._labelItems=this._computeLabelItems(t))}beforeLayout(){this._cache={},this._dataLimitsCached=!1}beforeUpdate(){d(this.options.beforeUpdate,[this])}update(t,e,i){const{beginAtZero:s,grace:n,ticks:o}=this.options,a=o.sampleSize;this.beforeUpdate(),this.maxWidth=t,this.maxHeight=e,this._margins=i=Object.assign({left:0,right:0,top:0,bottom:0},i),this.ticks=null,this._labelSizes=null,this._gridLineItems=null,this._labelItems=null,this.beforeSetDimensions(),this.setDimensions(),this.afterSetDimensions(),this._maxLength=this.isHorizontal()?this.width+i.left+i.right:this.height+i.top+i.bottom,this._dataLimitsCached||(this.beforeDataLimits(),this.determineDataLimits(),this.afterDataLimits(),this._range=Di(this,n,s),this._dataLimitsCached=!0),this.beforeBuildTicks(),this.ticks=this.buildTicks()||[],this.afterBuildTicks();const r=a<this.ticks.length;this._convertTicksToLabels(r?Ks(this.ticks,a):this.ticks),this.configure(),this.beforeCalculateLabelRotation(),this.calculateLabelRotation(),this.afterCalculateLabelRotation(),o.display&&(o.autoSkip||"auto"===o.source)&&(this.ticks=Ys(this,this.ticks),this._labelSizes=null,this.afterAutoSkip()),r&&this._convertTicksToLabels(this.ticks),this.beforeFit(),this.fit(),this.afterFit(),this.afterUpdate()}configure(){let t,e,i=this.options.reverse;this.isHorizontal()?(t=this.left,e=this.right):(t=this.top,e=this.bottom,i=!i),this._startPixel=t,this._endPixel=e,this._reversePixels=i,this._length=e-t,this._alignToPixels=this.options.alignToPixels}afterUpdate(){d(this.options.afterUpdate,[this])}beforeSetDimensions(){d(this.options.beforeSetDimensions,[this])}setDimensions(){this.isHorizontal()?(this.width=this.maxWidth,this.left=0,this.right=this.width):(this.height=this.maxHeight,this.top=0,this.bottom=this.height),this.paddingLeft=0,this.paddingTop=0,this.paddingRight=0,this.paddingBottom=0}afterSetDimensions(){d(this.options.afterSetDimensions,[this])}_callHooks(t){this.chart.notifyPlugins(t,this.getContext()),d(this.options[t],[this])}beforeDataLimits(){this._callHooks("beforeDataLimits")}determineDataLimits(){}afterDataLimits(){this._callHooks("afterDataLimits")}beforeBuildTicks(){this._callHooks("beforeBuildTicks")}buildTicks(){return[]}afterBuildTicks(){this._callHooks("afterBuildTicks")}beforeTickToLabelConversion(){d(this.options.beforeTickToLabelConversion,[this])}generateTickLabels(t){const e=this.options.ticks;let i,s,n;for(i=0,s=t.length;i<s;i++)n=t[i],n.label=d(e.callback,[n.value,i,t],this)}afterTickToLabelConversion(){d(this.options.afterTickToLabelConversion,[this])}beforeCalculateLabelRotation(){d(this.options.beforeCalculateLabelRotation,[this])}calculateLabelRotation(){const t=this.options,e=t.ticks,i=qs(this.ticks.length,t.ticks.maxTicksLimit),s=e.minRotation||0,n=e.maxRotation;let o,a,r,l=s;if(!this._isVisible()||!e.display||s>=n||i<=1||!this.isHorizontal())return void(this.labelRotation=s);const h=this._getLabelSizes(),c=h.widest.width,d=h.highest.height,u=Z(this.chart.width-c,0,this.maxWidth);o=t.offset?this.maxWidth/i:u/(i-1),c+6>o&&(o=u/(i-(t.offset?.5:1)),a=this.maxHeight-Js(t.grid)-e.padding-Zs(t.title,this.chart.options.font),r=Math.sqrt(c*c+d*d),l=Y(Math.min(Math.asin(Z((h.highest.height+6)/o,-1,1)),Math.asin(Z(a/r,-1,1))-Math.asin(Z(d/r,-1,1)))),l=Math.max(s,Math.min(n,l))),this.labelRotation=l}afterCalculateLabelRotation(){d(this.options.afterCalculateLabelRotation,[this])}afterAutoSkip(){}beforeFit(){d(this.options.beforeFit,[this])}fit(){const t={width:0,height:0},{chart:e,options:{ticks:i,title:s,grid:n}}=this,o=this._isVisible(),a=this.isHorizontal();if(o){const o=Zs(s,e.options.font);if(a?(t.width=this.maxWidth,t.height=Js(n)+o):(t.height=this.maxHeight,t.width=Js(n)+o),i.display&&this.ticks.length){const{first:e,last:s,widest:n,highest:o}=this._getLabelSizes(),r=2*i.padding,l=$(this.labelRotation),h=Math.cos(l),c=Math.sin(l);if(a){const e=i.mirror?0:c*n.width+h*o.height;t.height=Math.min(this.maxHeight,t.height+e+r)}else{const e=i.mirror?0:h*n.width+c*o.height;t.width=Math.min(this.maxWidth,t.width+e+r)}this._calculatePadding(e,s,c,h)}}this._handleMargins(),a?(this.width=this._length=e.width-this._margins.left-this._margins.right,this.height=t.height):(this.width=t.width,this.height=this._length=e.height-this._margins.top-this._margins.bottom)}_calculatePadding(t,e,i,s){const{ticks:{align:n,padding:o},position:a}=this.options,r=0!==this.labelRotation,l="top"!==a&&"x"===this.axis;if(this.isHorizontal()){const a=this.getPixelForTick(0)-this.left,h=this.right-this.getPixelForTick(this.ticks.length-1);let c=0,d=0;r?l?(c=s*t.width,d=i*e.height):(c=i*t.height,d=s*e.width):"start"===n?d=e.width:"end"===n?c=t.width:"inner"!==n&&(c=t.width/2,d=e.width/2),this.paddingLeft=Math.max((c-a+o)*this.width/(this.width-a),0),this.paddingRight=Math.max((d-h+o)*this.width/(this.width-h),0)}else{let i=e.height/2,s=t.height/2;"start"===n?(i=0,s=t.height):"end"===n&&(i=e.height,s=0),this.paddingTop=i+o,this.paddingBottom=s+o}}_handleMargins(){this._margins&&(this._margins.left=Math.max(this.paddingLeft,this._margins.left),this._margins.top=Math.max(this.paddingTop,this._margins.top),this._margins.right=Math.max(this.paddingRight,this._margins.right),this._margins.bottom=Math.max(this.paddingBottom,this._margins.bottom))}afterFit(){d(this.options.afterFit,[this])}isHorizontal(){const{axis:t,position:e}=this.options;return"top"===e||"bottom"===e||"x"===t}isFullSize(){return this.options.fullSize}_convertTicksToLabels(t){let e,i;for(this.beforeTickToLabelConversion(),this.generateTickLabels(t),e=0,i=t.length;e<i;e++)s(t[e].label)&&(t.splice(e,1),i--,e--);this.afterTickToLabelConversion()}_getLabelSizes(){let t=this._labelSizes;if(!t){const e=this.options.ticks.sampleSize;let i=this.ticks;e<i.length&&(i=Ks(i,e)),this._labelSizes=t=this._computeLabelSizes(i,i.length,this.options.ticks.maxTicksLimit)}return t}_computeLabelSizes(t,e,i){const{ctx:o,_longestTextCache:a}=this,r=[],l=[],h=Math.floor(e/qs(e,i));let c,d,f,g,p,m,x,b,_,y,v,M=0,w=0;for(c=0;c<e;c+=h){if(g=t[c].label,p=this._resolveTickFontOptions(c),o.font=m=p.string,x=a[m]=a[m]||{data:{},gc:[]},b=p.lineHeight,_=y=0,s(g)||n(g)){if(n(g))for(d=0,f=g.length;d<f;++d)v=g[d],s(v)||n(v)||(_=Ce(o,x.data,x.gc,_,v),y+=b)}else _=Ce(o,x.data,x.gc,_,g),y=b;r.push(_),l.push(y),M=Math.max(_,M),w=Math.max(y,w)}!function(t,e){u(t,(t=>{const i=t.gc,s=i.length/2;let n;if(s>e){for(n=0;n<s;++n)delete t.data[i[n]];i.splice(0,s)}}))}(a,e);const k=r.indexOf(M),S=l.indexOf(w),P=t=>({width:r[t]||0,height:l[t]||0});return{first:P(0),last:P(e-1),widest:P(k),highest:P(S),widths:r,heights:l}}getLabelForValue(t){return t}getPixelForValue(t,e){return NaN}getValueForPixel(t){}getPixelForTick(t){const e=this.ticks;return t<0||t>e.length-1?null:this.getPixelForValue(e[t].value)}getPixelForDecimal(t){this._reversePixels&&(t=1-t);const e=this._startPixel+t*this._length;return Q(this._alignToPixels?Ae(this.chart,e,0):e)}getDecimalForPixel(t){const e=(t-this._startPixel)/this._length;return this._reversePixels?1-e:e}getBasePixel(){return this.getPixelForValue(this.getBaseValue())}getBaseValue(){const{min:t,max:e}=this;return t<0&&e<0?e:t>0&&e>0?t:0}getContext(t){const e=this.ticks||[];if(t>=0&&t<e.length){const i=e[t];return i.$context||(i.$context=function(t,e,i){return Ci(t,{tick:i,index:e,type:"tick"})}(this.getContext(),t,i))}return this.$context||(this.$context=Ci(this.chart.getContext(),{scale:this,type:"scale"}))}_tickSize(){const t=this.options.ticks,e=$(this.labelRotation),i=Math.abs(Math.cos(e)),s=Math.abs(Math.sin(e)),n=this._getLabelSizes(),o=t.autoSkipPadding||0,a=n?n.widest.width+o:0,r=n?n.highest.height+o:0;return this.isHorizontal()?r*i>a*s?a/i:r/s:r*s<a*i?r/i:a/s}_isVisible(){const t=this.options.display;return"auto"!==t?!!t:this.getMatchingVisibleMetas().length>0}_computeGridLineItems(t){const e=this.axis,i=this.chart,s=this.options,{grid:n,position:a,border:r}=s,h=n.offset,c=this.isHorizontal(),d=this.ticks.length+(h?1:0),u=Js(n),f=[],g=r.setContext(this.getContext()),p=g.display?g.width:0,m=p/2,x=function(t){return Ae(i,t,p)};let b,_,y,v,M,w,k,S,P,D,C,O;if("top"===a)b=x(this.bottom),w=this.bottom-u,S=b-m,D=x(t.top)+m,O=t.bottom;else if("bottom"===a)b=x(this.top),D=t.top,O=x(t.bottom)-m,w=b+m,S=this.top+u;else if("left"===a)b=x(this.right),M=this.right-u,k=b-m,P=x(t.left)+m,C=t.right;else if("right"===a)b=x(this.left),P=t.left,C=x(t.right)-m,M=b+m,k=this.left+u;else if("x"===e){if("center"===a)b=x((t.top+t.bottom)/2+.5);else if(o(a)){const t=Object.keys(a)[0],e=a[t];b=x(this.chart.scales[t].getPixelForValue(e))}D=t.top,O=t.bottom,w=b+m,S=w+u}else if("y"===e){if("center"===a)b=x((t.left+t.right)/2);else if(o(a)){const t=Object.keys(a)[0],e=a[t];b=x(this.chart.scales[t].getPixelForValue(e))}M=b-m,k=M-u,P=t.left,C=t.right}const A=l(s.ticks.maxTicksLimit,d),T=Math.max(1,Math.ceil(d/A));for(_=0;_<d;_+=T){const t=this.getContext(_),e=n.setContext(t),s=r.setContext(t),o=e.lineWidth,a=e.color,l=s.dash||[],d=s.dashOffset,u=e.tickWidth,g=e.tickColor,p=e.tickBorderDash||[],m=e.tickBorderDashOffset;y=Gs(this,_,h),void 0!==y&&(v=Ae(i,y,o),c?M=k=P=C=v:w=S=D=O=v,f.push({tx1:M,ty1:w,tx2:k,ty2:S,x1:P,y1:D,x2:C,y2:O,width:o,color:a,borderDash:l,borderDashOffset:d,tickWidth:u,tickColor:g,tickBorderDash:p,tickBorderDashOffset:m}))}return this._ticksLength=d,this._borderValue=b,f}_computeLabelItems(t){const e=this.axis,i=this.options,{position:s,ticks:a}=i,r=this.isHorizontal(),l=this.ticks,{align:h,crossAlign:c,padding:d,mirror:u}=a,f=Js(i.grid),g=f+d,p=u?-d:g,m=-$(this.labelRotation),x=[];let b,_,y,v,M,w,k,S,P,D,C,O,A="middle";if("top"===s)w=this.bottom-p,k=this._getXAxisLabelAlignment();else if("bottom"===s)w=this.top+p,k=this._getXAxisLabelAlignment();else if("left"===s){const t=this._getYAxisLabelAlignment(f);k=t.textAlign,M=t.x}else if("right"===s){const t=this._getYAxisLabelAlignment(f);k=t.textAlign,M=t.x}else if("x"===e){if("center"===s)w=(t.top+t.bottom)/2+g;else if(o(s)){const t=Object.keys(s)[0],e=s[t];w=this.chart.scales[t].getPixelForValue(e)+g}k=this._getXAxisLabelAlignment()}else if("y"===e){if("center"===s)M=(t.left+t.right)/2-g;else if(o(s)){const t=Object.keys(s)[0],e=s[t];M=this.chart.scales[t].getPixelForValue(e)}k=this._getYAxisLabelAlignment(f).textAlign}"y"===e&&("start"===h?A="top":"end"===h&&(A="bottom"));const T=this._getLabelSizes();for(b=0,_=l.length;b<_;++b){y=l[b],v=y.label;const t=a.setContext(this.getContext(b));S=this.getPixelForTick(b)+a.labelOffset,P=this._resolveTickFontOptions(b),D=P.lineHeight,C=n(v)?v.length:1;const e=C/2,i=t.color,o=t.textStrokeColor,h=t.textStrokeWidth;let d,f=k;if(r?(M=S,"inner"===k&&(f=b===_-1?this.options.reverse?"left":"right":0===b?this.options.reverse?"right":"left":"center"),O="top"===s?"near"===c||0!==m?-C*D+D/2:"center"===c?-T.highest.height/2-e*D+D:-T.highest.height+D/2:"near"===c||0!==m?D/2:"center"===c?T.highest.height/2-e*D:T.highest.height-C*D,u&&(O*=-1),0===m||t.showLabelBackdrop||(M+=D/2*Math.sin(m))):(w=S,O=(1-C)*D/2),t.showLabelBackdrop){const e=ki(t.backdropPadding),i=T.heights[b],s=T.widths[b];let n=O-e.top,o=0-e.left;switch(A){case"middle":n-=i/2;break;case"bottom":n-=i}switch(k){case"center":o-=s/2;break;case"right":o-=s;break;case"inner":b===_-1?o-=s:b>0&&(o-=s/2)}d={left:o,top:n,width:s+e.width,height:i+e.height,color:t.backdropColor}}x.push({label:v,font:P,textOffset:O,options:{rotation:m,color:i,strokeColor:o,strokeWidth:h,textAlign:f,textBaseline:A,translation:[M,w],backdrop:d}})}return x}_getXAxisLabelAlignment(){const{position:t,ticks:e}=this.options;if(-$(this.labelRotation))return"top"===t?"left":"right";let i="center";return"start"===e.align?i="left":"end"===e.align?i="right":"inner"===e.align&&(i="inner"),i}_getYAxisLabelAlignment(t){const{position:e,ticks:{crossAlign:i,mirror:s,padding:n}}=this.options,o=t+n,a=this._getLabelSizes().widest.width;let r,l;return"left"===e?s?(l=this.right+n,"near"===i?r="left":"center"===i?(r="center",l+=a/2):(r="right",l+=a)):(l=this.right-o,"near"===i?r="right":"center"===i?(r="center",l-=a/2):(r="left",l=this.left)):"right"===e?s?(l=this.left+n,"near"===i?r="right":"center"===i?(r="center",l-=a/2):(r="left",l-=a)):(l=this.left+o,"near"===i?r="left":"center"===i?(r="center",l+=a/2):(r="right",l=this.right)):r="right",{textAlign:r,x:l}}_computeLabelArea(){if(this.options.ticks.mirror)return;const t=this.chart,e=this.options.position;return"left"===e||"right"===e?{top:0,left:this.left,bottom:t.height,right:this.right}:"top"===e||"bottom"===e?{top:this.top,left:0,bottom:this.bottom,right:t.width}:void 0}drawBackground(){const{ctx:t,options:{backgroundColor:e},left:i,top:s,width:n,height:o}=this;e&&(t.save(),t.fillStyle=e,t.fillRect(i,s,n,o),t.restore())}getLineWidthForValue(t){const e=this.options.grid;if(!this._isVisible()||!e.display)return 0;const i=this.ticks.findIndex((e=>e.value===t));if(i>=0){return e.setContext(this.getContext(i)).lineWidth}return 0}drawGrid(t){const e=this.options.grid,i=this.ctx,s=this._gridLineItems||(this._gridLineItems=this._computeGridLineItems(t));let n,o;const a=(t,e,s)=>{s.width&&s.color&&(i.save(),i.lineWidth=s.width,i.strokeStyle=s.color,i.setLineDash(s.borderDash||[]),i.lineDashOffset=s.borderDashOffset,i.beginPath(),i.moveTo(t.x,t.y),i.lineTo(e.x,e.y),i.stroke(),i.restore())};if(e.display)for(n=0,o=s.length;n<o;++n){const t=s[n];e.drawOnChartArea&&a({x:t.x1,y:t.y1},{x:t.x2,y:t.y2},t),e.drawTicks&&a({x:t.tx1,y:t.ty1},{x:t.tx2,y:t.ty2},{color:t.tickColor,width:t.tickWidth,borderDash:t.tickBorderDash,borderDashOffset:t.tickBorderDashOffset})}}drawBorder(){const{chart:t,ctx:e,options:{border:i,grid:s}}=this,n=i.setContext(this.getContext()),o=i.display?n.width:0;if(!o)return;const a=s.setContext(this.getContext(0)).lineWidth,r=this._borderValue;let l,h,c,d;this.isHorizontal()?(l=Ae(t,this.left,o)-o/2,h=Ae(t,this.right,a)+a/2,c=d=r):(c=Ae(t,this.top,o)-o/2,d=Ae(t,this.bottom,a)+a/2,l=h=r),e.save(),e.lineWidth=n.width,e.strokeStyle=n.color,e.beginPath(),e.moveTo(l,c),e.lineTo(h,d),e.stroke(),e.restore()}drawLabels(t){if(!this.options.ticks.display)return;const e=this.ctx,i=this._computeLabelArea();i&&Ie(e,i);const s=this.getLabelItems(t);for(const t of s){const i=t.options,s=t.font;Ne(e,t.label,0,t.textOffset,s,i)}i&&ze(e)}drawTitle(){const{ctx:t,options:{position:e,title:i,reverse:s}}=this;if(!i.display)return;const a=Si(i.font),r=ki(i.padding),l=i.align;let h=a.lineHeight/2;"bottom"===e||"center"===e||o(e)?(h+=r.bottom,n(i.text)&&(h+=a.lineHeight*(i.text.length-1))):h+=r.top;const{titleX:c,titleY:d,maxWidth:u,rotation:f}=function(t,e,i,s){const{top:n,left:a,bottom:r,right:l,chart:h}=t,{chartArea:c,scales:d}=h;let u,f,g,p=0;const m=r-n,x=l-a;if(t.isHorizontal()){if(f=ft(s,a,l),o(i)){const t=Object.keys(i)[0],s=i[t];g=d[t].getPixelForValue(s)+m-e}else g="center"===i?(c.bottom+c.top)/2+m-e:Xs(t,i,e);u=l-a}else{if(o(i)){const t=Object.keys(i)[0],s=i[t];f=d[t].getPixelForValue(s)-x+e}else f="center"===i?(c.left+c.right)/2-x+e:Xs(t,i,e);g=ft(s,r,n),p="left"===i?-E:E}return{titleX:f,titleY:g,maxWidth:u,rotation:p}}(this,h,e,l);Ne(t,i.text,0,0,a,{color:i.color,maxWidth:u,rotation:f,textAlign:Qs(l,e,s),textBaseline:"middle",translation:[c,d]})}draw(t){this._isVisible()&&(this.drawBackground(),this.drawGrid(t),this.drawBorder(),this.drawTitle(),this.drawLabels(t))}_layers(){const t=this.options,e=t.ticks&&t.ticks.z||0,i=l(t.grid&&t.grid.z,-1),s=l(t.border&&t.border.z,0);return this._isVisible()&&this.draw===tn.prototype.draw?[{z:i,draw:t=>{this.drawBackground(),this.drawGrid(t),this.drawTitle()}},{z:s,draw:()=>{this.drawBorder()}},{z:e,draw:t=>{this.drawLabels(t)}}]:[{z:e,draw:t=>{this.draw(t)}}]}getMatchingVisibleMetas(t){const e=this.chart.getSortedVisibleDatasetMetas(),i=this.axis+"AxisID",s=[];let n,o;for(n=0,o=e.length;n<o;++n){const o=e[n];o[i]!==this.id||t&&o.type!==t||s.push(o)}return s}_resolveTickFontOptions(t){return Si(this.options.ticks.setContext(this.getContext(t)).font)}_maxDigits(){const t=this._resolveTickFontOptions(0).lineHeight;return(this.isHorizontal()?this.width:this.height)/t}}class en{constructor(t,e,i){this.type=t,this.scope=e,this.override=i,this.items=Object.create(null)}isForType(t){return Object.prototype.isPrototypeOf.call(this.type.prototype,t.prototype)}register(t){const e=Object.getPrototypeOf(t);let i;(function(t){return"id"in t&&"defaults"in t})(e)&&(i=this.register(e));const s=this.items,n=t.id,o=this.scope+"."+n;if(!n)throw new Error("class does not have id: "+t);return n in s||(s[n]=t,function(t,e,i){const s=x(Object.create(null),[i?ue.get(i):{},ue.get(e),t.defaults]);ue.set(e,s),t.defaultRoutes&&function(t,e){Object.keys(e).forEach((i=>{const s=i.split("."),n=s.pop(),o=[t].concat(s).join("."),a=e[i].split("."),r=a.pop(),l=a.join(".");ue.route(o,n,l,r)}))}(e,t.defaultRoutes);t.descriptors&&ue.describe(e,t.descriptors)}(t,o,i),this.override&&ue.override(t.id,t.overrides)),o}get(t){return this.items[t]}unregister(t){const e=this.items,i=t.id,s=this.scope;i in e&&delete e[i],s&&i in ue[s]&&(delete ue[s][i],this.override&&delete re[i])}}class sn{constructor(){this.controllers=new en(js,"datasets",!0),this.elements=new en($s,"elements"),this.plugins=new en(Object,"plugins"),this.scales=new en(tn,"scales"),this._typedRegistries=[this.controllers,this.scales,this.elements]}add(...t){this._each("register",t)}remove(...t){this._each("unregister",t)}addControllers(...t){this._each("register",t,this.controllers)}addElements(...t){this._each("register",t,this.elements)}addPlugins(...t){this._each("register",t,this.plugins)}addScales(...t){this._each("register",t,this.scales)}getController(t){return this._get(t,this.controllers,"controller")}getElement(t){return this._get(t,this.elements,"element")}getPlugin(t){return this._get(t,this.plugins,"plugin")}getScale(t){return this._get(t,this.scales,"scale")}removeControllers(...t){this._each("unregister",t,this.controllers)}removeElements(...t){this._each("unregister",t,this.elements)}removePlugins(...t){this._each("unregister",t,this.plugins)}removeScales(...t){this._each("unregister",t,this.scales)}_each(t,e,i){[...e].forEach((e=>{const s=i||this._getRegistryForType(e);i||s.isForType(e)||s===this.plugins&&e.id?this._exec(t,s,e):u(e,(e=>{const s=i||this._getRegistryForType(e);this._exec(t,s,e)}))}))}_exec(t,e,i){const s=w(t);d(i["before"+s],[],i),e[t](i),d(i["after"+s],[],i)}_getRegistryForType(t){for(let e=0;e<this._typedRegistries.length;e++){const i=this._typedRegistries[e];if(i.isForType(t))return i}return this.plugins}_get(t,e,i){const s=e.get(t);if(void 0===s)throw new Error('"'+t+'" is not a registered '+i+".");return s}}var nn=new sn;class on{constructor(){this._init=void 0}notify(t,e,i,s){if("beforeInit"===e&&(this._init=this._createDescriptors(t,!0),this._notify(this._init,t,"install")),void 0===this._init)return;const n=s?this._descriptors(t).filter(s):this._descriptors(t),o=this._notify(n,t,e,i);return"afterDestroy"===e&&(this._notify(n,t,"stop"),this._notify(this._init,t,"uninstall"),this._init=void 0),o}_notify(t,e,i,s){s=s||{};for(const n of t){const t=n.plugin;if(!1===d(t[i],[e,s,n.options],t)&&s.cancelable)return!1}return!0}invalidate(){s(this._cache)||(this._oldCache=this._cache,this._cache=void 0)}_descriptors(t){if(this._cache)return this._cache;const e=this._cache=this._createDescriptors(t);return this._notifyStateChanges(t),e}_createDescriptors(t,e){const i=t&&t.config,s=l(i.options&&i.options.plugins,{}),n=function(t){const e={},i=[],s=Object.keys(nn.plugins.items);for(let t=0;t<s.length;t++)i.push(nn.getPlugin(s[t]));const n=t.plugins||[];for(let t=0;t<n.length;t++){const s=n[t];-1===i.indexOf(s)&&(i.push(s),e[s.id]=!0)}return{plugins:i,localIds:e}}(i);return!1!==s||e?function(t,{plugins:e,localIds:i},s,n){const o=[],a=t.getContext();for(const r of e){const e=r.id,l=an(s[e],n);null!==l&&o.push({plugin:r,options:rn(t.config,{plugin:r,local:i[e]},l,a)})}return o}(t,n,s,e):[]}_notifyStateChanges(t){const e=this._oldCache||[],i=this._cache,s=(t,e)=>t.filter((t=>!e.some((e=>t.plugin.id===e.plugin.id))));this._notify(s(e,i),t,"stop"),this._notify(s(i,e),t,"start")}}function an(t,e){return e||!1!==t?!0===t?{}:t:null}function rn(t,{plugin:e,local:i},s,n){const o=t.pluginScopeKeys(e),a=t.getOptionScopes(s,o);return i&&e.defaults&&a.push(e.defaults),t.createResolver(a,n,[""],{scriptable:!1,indexable:!1,allKeys:!0})}function ln(t,e){const i=ue.datasets[t]||{};return((e.datasets||{})[t]||{}).indexAxis||e.indexAxis||i.indexAxis||"x"}function hn(t){if("x"===t||"y"===t||"r"===t)return t}function cn(t,...e){if(hn(t))return t;for(const s of e){const e=s.axis||("top"===(i=s.position)||"bottom"===i?"x":"left"===i||"right"===i?"y":void 0)||t.length>1&&hn(t[0].toLowerCase());if(e)return e}var i;throw new Error(`Cannot determine type of '${t}' axis. Please provide 'axis' or 'position' option.`)}function dn(t,e,i){if(i[e+"AxisID"]===t)return{axis:e}}function un(t,e){const i=re[t.type]||{scales:{}},s=e.scales||{},n=ln(t.type,e),a=Object.create(null);return Object.keys(s).forEach((e=>{const r=s[e];if(!o(r))return console.error(`Invalid scale configuration for scale: ${e}`);if(r._proxy)return console.warn(`Ignoring resolver passed as options for scale: ${e}`);const l=cn(e,r,function(t,e){if(e.data&&e.data.datasets){const i=e.data.datasets.filter((e=>e.xAxisID===t||e.yAxisID===t));if(i.length)return dn(t,"x",i[0])||dn(t,"y",i[0])}return{}}(e,t),ue.scales[r.type]),h=function(t,e){return t===e?"_index_":"_value_"}(l,n),c=i.scales||{};a[e]=b(Object.create(null),[{axis:l},r,c[l],c[h]])})),t.data.datasets.forEach((i=>{const n=i.type||t.type,o=i.indexAxis||ln(n,e),r=(re[n]||{}).scales||{};Object.keys(r).forEach((t=>{const e=function(t,e){let i=t;return"_index_"===t?i=e:"_value_"===t&&(i="x"===e?"y":"x"),i}(t,o),n=i[e+"AxisID"]||e;a[n]=a[n]||Object.create(null),b(a[n],[{axis:e},s[n],r[t]])}))})),Object.keys(a).forEach((t=>{const e=a[t];b(e,[ue.scales[e.type],ue.scale])})),a}function fn(t){const e=t.options||(t.options={});e.plugins=l(e.plugins,{}),e.scales=un(t,e)}function gn(t){return(t=t||{}).datasets=t.datasets||[],t.labels=t.labels||[],t}const pn=new Map,mn=new Set;function xn(t,e){let i=pn.get(t);return i||(i=e(),pn.set(t,i),mn.add(i)),i}const bn=(t,e,i)=>{const s=M(e,i);void 0!==s&&t.add(s)};class _n{constructor(t){this._config=function(t){return(t=t||{}).data=gn(t.data),fn(t),t}(t),this._scopeCache=new Map,this._resolverCache=new Map}get platform(){return this._config.platform}get type(){return this._config.type}set type(t){this._config.type=t}get data(){return this._config.data}set data(t){this._config.data=gn(t)}get options(){return this._config.options}set options(t){this._config.options=t}get plugins(){return this._config.plugins}update(){const t=this._config;this.clearCache(),fn(t)}clearCache(){this._scopeCache.clear(),this._resolverCache.clear()}datasetScopeKeys(t){return xn(t,(()=>[[`datasets.${t}`,""]]))}datasetAnimationScopeKeys(t,e){return xn(`${t}.transition.${e}`,(()=>[[`datasets.${t}.transitions.${e}`,`transitions.${e}`],[`datasets.${t}`,""]]))}datasetElementScopeKeys(t,e){return xn(`${t}-${e}`,(()=>[[`datasets.${t}.elements.${e}`,`datasets.${t}`,`elements.${e}`,""]]))}pluginScopeKeys(t){const e=t.id;return xn(`${this.type}-plugin-${e}`,(()=>[[`plugins.${e}`,...t.additionalOptionScopes||[]]]))}_cachedScopes(t,e){const i=this._scopeCache;let s=i.get(t);return s&&!e||(s=new Map,i.set(t,s)),s}getOptionScopes(t,e,i){const{options:s,type:n}=this,o=this._cachedScopes(t,i),a=o.get(e);if(a)return a;const r=new Set;e.forEach((e=>{t&&(r.add(t),e.forEach((e=>bn(r,t,e)))),e.forEach((t=>bn(r,s,t))),e.forEach((t=>bn(r,re[n]||{},t))),e.forEach((t=>bn(r,ue,t))),e.forEach((t=>bn(r,le,t)))}));const l=Array.from(r);return 0===l.length&&l.push(Object.create(null)),mn.has(e)&&o.set(e,l),l}chartOptionScopes(){const{options:t,type:e}=this;return[t,re[e]||{},ue.datasets[e]||{},{type:e},ue,le]}resolveNamedOptions(t,e,i,s=[""]){const o={$shared:!0},{resolver:a,subPrefixes:r}=yn(this._resolverCache,t,s);let l=a;if(function(t,e){const{isScriptable:i,isIndexable:s}=Ye(t);for(const o of e){const e=i(o),a=s(o),r=(a||e)&&t[o];if(e&&(S(r)||vn(r))||a&&n(r))return!0}return!1}(a,e)){o.$shared=!1;l=$e(a,i=S(i)?i():i,this.createResolver(t,i,r))}for(const t of e)o[t]=l[t];return o}createResolver(t,e,i=[""],s){const{resolver:n}=yn(this._resolverCache,t,i);return o(e)?$e(n,e,void 0,s):n}}function yn(t,e,i){let s=t.get(e);s||(s=new Map,t.set(e,s));const n=i.join();let o=s.get(n);if(!o){o={resolver:je(e,i),subPrefixes:i.filter((t=>!t.toLowerCase().includes("hover")))},s.set(n,o)}return o}const vn=t=>o(t)&&Object.getOwnPropertyNames(t).some((e=>S(t[e])));const Mn=["top","bottom","left","right","chartArea"];function wn(t,e){return"top"===t||"bottom"===t||-1===Mn.indexOf(t)&&"x"===e}function kn(t,e){return function(i,s){return i[t]===s[t]?i[e]-s[e]:i[t]-s[t]}}function Sn(t){const e=t.chart,i=e.options.animation;e.notifyPlugins("afterRender"),d(i&&i.onComplete,[t],e)}function Pn(t){const e=t.chart,i=e.options.animation;d(i&&i.onProgress,[t],e)}function Dn(t){return fe()&&"string"==typeof t?t=document.getElementById(t):t&&t.length&&(t=t[0]),t&&t.canvas&&(t=t.canvas),t}const Cn={},On=t=>{const e=Dn(t);return Object.values(Cn).filter((t=>t.canvas===e)).pop()};function An(t,e,i){const s=Object.keys(t);for(const n of s){const s=+n;if(s>=e){const o=t[n];delete t[n],(i>0||s>e)&&(t[s+i]=o)}}}class Tn{static defaults=ue;static instances=Cn;static overrides=re;static registry=nn;static version="4.5.1";static getChart=On;static register(...t){nn.add(...t),Ln()}static unregister(...t){nn.remove(...t),Ln()}constructor(t,e){const s=this.config=new _n(e),n=Dn(t),o=On(n);if(o)throw new Error("Canvas is already in use. Chart with ID '"+o.id+"' must be destroyed before the canvas with ID '"+o.canvas.id+"' can be reused.");const a=s.createResolver(s.chartOptionScopes(),this.getContext());this.platform=new(s.platform||Ps(n)),this.platform.updateConfig(s);const r=this.platform.acquireContext(n,a.aspectRatio),l=r&&r.canvas,h=l&&l.height,c=l&&l.width;this.id=i(),this.ctx=r,this.canvas=l,this.width=c,this.height=h,this._options=a,this._aspectRatio=this.aspectRatio,this._layers=[],this._metasets=[],this._stacks=void 0,this.boxes=[],this.currentDevicePixelRatio=void 0,this.chartArea=void 0,this._active=[],this._lastEvent=void 0,this._listeners={},this._responsiveListeners=void 0,this._sortedMetasets=[],this.scales={},this._plugins=new on,this.$proxies={},this._hiddenIndices={},this.attached=!1,this._animationsDisabled=void 0,this.$context=void 0,this._doResize=dt((t=>this.update(t)),a.resizeDelay||0),this._dataChanges=[],Cn[this.id]=this,r&&l?(bt.listen(this,"complete",Sn),bt.listen(this,"progress",Pn),this._initialize(),this.attached&&this.update()):console.error("Failed to create chart: can't acquire context from the given item")}get aspectRatio(){const{options:{aspectRatio:t,maintainAspectRatio:e},width:i,height:n,_aspectRatio:o}=this;return s(t)?e&&o?o:n?i/n:null:t}get data(){return this.config.data}set data(t){this.config.data=t}get options(){return this._options}set options(t){this.config.options=t}get registry(){return nn}_initialize(){return this.notifyPlugins("beforeInit"),this.options.responsive?this.resize():ke(this,this.options.devicePixelRatio),this.bindEvents(),this.notifyPlugins("afterInit"),this}clear(){return Te(this.canvas,this.ctx),this}stop(){return bt.stop(this),this}resize(t,e){bt.running(this)?this._resizeBeforeDraw={width:t,height:e}:this._resize(t,e)}_resize(t,e){const i=this.options,s=this.canvas,n=i.maintainAspectRatio&&this.aspectRatio,o=this.platform.getMaximumSize(s,t,e,n),a=i.devicePixelRatio||this.platform.getDevicePixelRatio(),r=this.width?"resize":"attach";this.width=o.width,this.height=o.height,this._aspectRatio=this.aspectRatio,ke(this,a,!0)&&(this.notifyPlugins("resize",{size:o}),d(i.onResize,[this,o],this),this.attached&&this._doResize(r)&&this.render())}ensureScalesHaveIDs(){u(this.options.scales||{},((t,e)=>{t.id=e}))}buildOrUpdateScales(){const t=this.options,e=t.scales,i=this.scales,s=Object.keys(i).reduce(((t,e)=>(t[e]=!1,t)),{});let n=[];e&&(n=n.concat(Object.keys(e).map((t=>{const i=e[t],s=cn(t,i),n="r"===s,o="x"===s;return{options:i,dposition:n?"chartArea":o?"bottom":"left",dtype:n?"radialLinear":o?"category":"linear"}})))),u(n,(e=>{const n=e.options,o=n.id,a=cn(o,n),r=l(n.type,e.dtype);void 0!==n.position&&wn(n.position,a)===wn(e.dposition)||(n.position=e.dposition),s[o]=!0;let h=null;if(o in i&&i[o].type===r)h=i[o];else{h=new(nn.getScale(r))({id:o,type:r,ctx:this.ctx,chart:this}),i[h.id]=h}h.init(n,t)})),u(s,((t,e)=>{t||delete i[e]})),u(i,(t=>{ls.configure(this,t,t.options),ls.addBox(this,t)}))}_updateMetasets(){const t=this._metasets,e=this.data.datasets.length,i=t.length;if(t.sort(((t,e)=>t.index-e.index)),i>e){for(let t=e;t<i;++t)this._destroyDatasetMeta(t);t.splice(e,i-e)}this._sortedMetasets=t.slice(0).sort(kn("order","index"))}_removeUnreferencedMetasets(){const{_metasets:t,data:{datasets:e}}=this;t.length>e.length&&delete this._stacks,t.forEach(((t,i)=>{0===e.filter((e=>e===t._dataset)).length&&this._destroyDatasetMeta(i)}))}buildOrUpdateControllers(){const t=[],e=this.data.datasets;let i,s;for(this._removeUnreferencedMetasets(),i=0,s=e.length;i<s;i++){const s=e[i];let n=this.getDatasetMeta(i);const o=s.type||this.config.type;if(n.type&&n.type!==o&&(this._destroyDatasetMeta(i),n=this.getDatasetMeta(i)),n.type=o,n.indexAxis=s.indexAxis||ln(o,this.options),n.order=s.order||0,n.index=i,n.label=""+s.label,n.visible=this.isDatasetVisible(i),n.controller)n.controller.updateIndex(i),n.controller.linkScales();else{const e=nn.getController(o),{datasetElementType:s,dataElementType:a}=ue.datasets[o];Object.assign(e,{dataElementType:nn.getElement(a),datasetElementType:s&&nn.getElement(s)}),n.controller=new e(this,i),t.push(n.controller)}}return this._updateMetasets(),t}_resetElements(){u(this.data.datasets,((t,e)=>{this.getDatasetMeta(e).controller.reset()}),this)}reset(){this._resetElements(),this.notifyPlugins("reset")}update(t){const e=this.config;e.update();const i=this._options=e.createResolver(e.chartOptionScopes(),this.getContext()),s=this._animationsDisabled=!i.animation;if(this._updateScales(),this._checkEventBindings(),this._updateHiddenIndices(),this._plugins.invalidate(),!1===this.notifyPlugins("beforeUpdate",{mode:t,cancelable:!0}))return;const n=this.buildOrUpdateControllers();this.notifyPlugins("beforeElementsUpdate");let o=0;for(let t=0,e=this.data.datasets.length;t<e;t++){const{controller:e}=this.getDatasetMeta(t),i=!s&&-1===n.indexOf(e);e.buildOrUpdateElements(i),o=Math.max(+e.getMaxOverflow(),o)}o=this._minPadding=i.layout.autoPadding?o:0,this._updateLayout(o),s||u(n,(t=>{t.reset()})),this._updateDatasets(t),this.notifyPlugins("afterUpdate",{mode:t}),this._layers.sort(kn("z","_idx"));const{_active:a,_lastEvent:r}=this;r?this._eventHandler(r,!0):a.length&&this._updateHoverStyles(a,a,!0),this.render()}_updateScales(){u(this.scales,(t=>{ls.removeBox(this,t)})),this.ensureScalesHaveIDs(),this.buildOrUpdateScales()}_checkEventBindings(){const t=this.options,e=new Set(Object.keys(this._listeners)),i=new Set(t.events);P(e,i)&&!!this._responsiveListeners===t.responsive||(this.unbindEvents(),this.bindEvents())}_updateHiddenIndices(){const{_hiddenIndices:t}=this,e=this._getUniformDataChanges()||[];for(const{method:i,start:s,count:n}of e){An(t,s,"_removeElements"===i?-n:n)}}_getUniformDataChanges(){const t=this._dataChanges;if(!t||!t.length)return;this._dataChanges=[];const e=this.data.datasets.length,i=e=>new Set(t.filter((t=>t[0]===e)).map(((t,e)=>e+","+t.splice(1).join(",")))),s=i(0);for(let t=1;t<e;t++)if(!P(s,i(t)))return;return Array.from(s).map((t=>t.split(","))).map((t=>({method:t[1],start:+t[2],count:+t[3]})))}_updateLayout(t){if(!1===this.notifyPlugins("beforeLayout",{cancelable:!0}))return;ls.update(this,this.width,this.height,t);const e=this.chartArea,i=e.width<=0||e.height<=0;this._layers=[],u(this.boxes,(t=>{i&&"chartArea"===t.position||(t.configure&&t.configure(),this._layers.push(...t._layers()))}),this),this._layers.forEach(((t,e)=>{t._idx=e})),this.notifyPlugins("afterLayout")}_updateDatasets(t){if(!1!==this.notifyPlugins("beforeDatasetsUpdate",{mode:t,cancelable:!0})){for(let t=0,e=this.data.datasets.length;t<e;++t)this.getDatasetMeta(t).controller.configure();for(let e=0,i=this.data.datasets.length;e<i;++e)this._updateDataset(e,S(t)?t({datasetIndex:e}):t);this.notifyPlugins("afterDatasetsUpdate",{mode:t})}}_updateDataset(t,e){const i=this.getDatasetMeta(t),s={meta:i,index:t,mode:e,cancelable:!0};!1!==this.notifyPlugins("beforeDatasetUpdate",s)&&(i.controller._update(e),s.cancelable=!1,this.notifyPlugins("afterDatasetUpdate",s))}render(){!1!==this.notifyPlugins("beforeRender",{cancelable:!0})&&(bt.has(this)?this.attached&&!bt.running(this)&&bt.start(this):(this.draw(),Sn({chart:this})))}draw(){let t;if(this._resizeBeforeDraw){const{width:t,height:e}=this._resizeBeforeDraw;this._resizeBeforeDraw=null,this._resize(t,e)}if(this.clear(),this.width<=0||this.height<=0)return;if(!1===this.notifyPlugins("beforeDraw",{cancelable:!0}))return;const e=this._layers;for(t=0;t<e.length&&e[t].z<=0;++t)e[t].draw(this.chartArea);for(this._drawDatasets();t<e.length;++t)e[t].draw(this.chartArea);this.notifyPlugins("afterDraw")}_getSortedDatasetMetas(t){const e=this._sortedMetasets,i=[];let s,n;for(s=0,n=e.length;s<n;++s){const n=e[s];t&&!n.visible||i.push(n)}return i}getSortedVisibleDatasetMetas(){return this._getSortedDatasetMetas(!0)}_drawDatasets(){if(!1===this.notifyPlugins("beforeDatasetsDraw",{cancelable:!0}))return;const t=this.getSortedVisibleDatasetMetas();for(let e=t.length-1;e>=0;--e)this._drawDataset(t[e]);this.notifyPlugins("afterDatasetsDraw")}_drawDataset(t){const e=this.ctx,i={meta:t,index:t.index,cancelable:!0},s=Ni(this,t);!1!==this.notifyPlugins("beforeDatasetDraw",i)&&(s&&Ie(e,s),t.controller.draw(),s&&ze(e),i.cancelable=!1,this.notifyPlugins("afterDatasetDraw",i))}isPointInArea(t){return Re(t,this.chartArea,this._minPadding)}getElementsAtEventForMode(t,e,i,s){const n=Ki.modes[e];return"function"==typeof n?n(this,t,i,s):[]}getDatasetMeta(t){const e=this.data.datasets[t],i=this._metasets;let s=i.filter((t=>t&&t._dataset===e)).pop();return s||(s={type:null,data:[],dataset:null,controller:null,hidden:null,xAxisID:null,yAxisID:null,order:e&&e.order||0,index:t,_dataset:e,_parsed:[],_sorted:!1},i.push(s)),s}getContext(){return this.$context||(this.$context=Ci(null,{chart:this,type:"chart"}))}getVisibleDatasetCount(){return this.getSortedVisibleDatasetMetas().length}isDatasetVisible(t){const e=this.data.datasets[t];if(!e)return!1;const i=this.getDatasetMeta(t);return"boolean"==typeof i.hidden?!i.hidden:!e.hidden}setDatasetVisibility(t,e){this.getDatasetMeta(t).hidden=!e}toggleDataVisibility(t){this._hiddenIndices[t]=!this._hiddenIndices[t]}getDataVisibility(t){return!this._hiddenIndices[t]}_updateVisibility(t,e,i){const s=i?"show":"hide",n=this.getDatasetMeta(t),o=n.controller._resolveAnimations(void 0,s);k(e)?(n.data[e].hidden=!i,this.update()):(this.setDatasetVisibility(t,i),o.update(n,{visible:i}),this.update((e=>e.datasetIndex===t?s:void 0)))}hide(t,e){this._updateVisibility(t,e,!1)}show(t,e){this._updateVisibility(t,e,!0)}_destroyDatasetMeta(t){const e=this._metasets[t];e&&e.controller&&e.controller._destroy(),delete this._metasets[t]}_stop(){let t,e;for(this.stop(),bt.remove(this),t=0,e=this.data.datasets.length;t<e;++t)this._destroyDatasetMeta(t)}destroy(){this.notifyPlugins("beforeDestroy");const{canvas:t,ctx:e}=this;this._stop(),this.config.clearCache(),t&&(this.unbindEvents(),Te(t,e),this.platform.releaseContext(e),this.canvas=null,this.ctx=null),delete Cn[this.id],this.notifyPlugins("afterDestroy")}toBase64Image(...t){return this.canvas.toDataURL(...t)}bindEvents(){this.bindUserEvents(),this.options.responsive?this.bindResponsiveEvents():this.attached=!0}bindUserEvents(){const t=this._listeners,e=this.platform,i=(i,s)=>{e.addEventListener(this,i,s),t[i]=s},s=(t,e,i)=>{t.offsetX=e,t.offsetY=i,this._eventHandler(t)};u(this.options.events,(t=>i(t,s)))}bindResponsiveEvents(){this._responsiveListeners||(this._responsiveListeners={});const t=this._responsiveListeners,e=this.platform,i=(i,s)=>{e.addEventListener(this,i,s),t[i]=s},s=(i,s)=>{t[i]&&(e.removeEventListener(this,i,s),delete t[i])},n=(t,e)=>{this.canvas&&this.resize(t,e)};let o;const a=()=>{s("attach",a),this.attached=!0,this.resize(),i("resize",n),i("detach",o)};o=()=>{this.attached=!1,s("resize",n),this._stop(),this._resize(0,0),i("attach",a)},e.isAttached(this.canvas)?a():o()}unbindEvents(){u(this._listeners,((t,e)=>{this.platform.removeEventListener(this,e,t)})),this._listeners={},u(this._responsiveListeners,((t,e)=>{this.platform.removeEventListener(this,e,t)})),this._responsiveListeners=void 0}updateHoverStyle(t,e,i){const s=i?"set":"remove";let n,o,a,r;for("dataset"===e&&(n=this.getDatasetMeta(t[0].datasetIndex),n.controller["_"+s+"DatasetHoverStyle"]()),a=0,r=t.length;a<r;++a){o=t[a];const e=o&&this.getDatasetMeta(o.datasetIndex).controller;e&&e[s+"HoverStyle"](o.element,o.datasetIndex,o.index)}}getActiveElements(){return this._active||[]}setActiveElements(t){const e=this._active||[],i=t.map((({datasetIndex:t,index:e})=>{const i=this.getDatasetMeta(t);if(!i)throw new Error("No dataset found at index "+t);return{datasetIndex:t,element:i.data[e],index:e}}));!f(i,e)&&(this._active=i,this._lastEvent=null,this._updateHoverStyles(i,e))}notifyPlugins(t,e,i){return this._plugins.notify(this,t,e,i)}isPluginEnabled(t){return 1===this._plugins._cache.filter((e=>e.plugin.id===t)).length}_updateHoverStyles(t,e,i){const s=this.options.hover,n=(t,e)=>t.filter((t=>!e.some((e=>t.datasetIndex===e.datasetIndex&&t.index===e.index)))),o=n(e,t),a=i?t:n(t,e);o.length&&this.updateHoverStyle(o,s.mode,!1),a.length&&s.mode&&this.updateHoverStyle(a,s.mode,!0)}_eventHandler(t,e){const i={event:t,replay:e,cancelable:!0,inChartArea:this.isPointInArea(t)},s=e=>(e.options.events||this.options.events).includes(t.native.type);if(!1===this.notifyPlugins("beforeEvent",i,s))return;const n=this._handleEvent(t,e,i.inChartArea);return i.cancelable=!1,this.notifyPlugins("afterEvent",i,s),(n||i.changed)&&this.render(),this}_handleEvent(t,e,i){const{_active:s=[],options:n}=this,o=e,a=this._getActiveElements(t,s,i,o),r=D(t),l=function(t,e,i,s){return i&&"mouseout"!==t.type?s?e:t:null}(t,this._lastEvent,i,r);i&&(this._lastEvent=null,d(n.onHover,[t,a,this],this),r&&d(n.onClick,[t,a,this],this));const h=!f(a,s);return(h||e)&&(this._active=a,this._updateHoverStyles(a,s,e)),this._lastEvent=l,h}_getActiveElements(t,e,i,s){if("mouseout"===t.type)return[];if(!i)return e;const n=this.options.hover;return this.getElementsAtEventForMode(t,n.mode,n,s)}}function Ln(){return u(Tn.instances,(t=>t._plugins.invalidate()))}function En(){throw new Error("This method is not implemented: Check that a complete date adapter is provided.")}class Rn{static override(t){Object.assign(Rn.prototype,t)}options;constructor(t){this.options=t||{}}init(){}formats(){return En()}parse(){return En()}format(){return En()}add(){return En()}diff(){return En()}startOf(){return En()}endOf(){return En()}}var In={_date:Rn};function zn(t){const e=t.iScale,i=function(t,e){if(!t._cache.$bar){const i=t.getMatchingVisibleMetas(e);let s=[];for(let e=0,n=i.length;e<n;e++)s=s.concat(i[e].controller.getAllParsedValues(t));t._cache.$bar=lt(s.sort(((t,e)=>t-e)))}return t._cache.$bar}(e,t.type);let s,n,o,a,r=e._length;const l=()=>{32767!==o&&-32768!==o&&(k(a)&&(r=Math.min(r,Math.abs(o-a)||r)),a=o)};for(s=0,n=i.length;s<n;++s)o=e.getPixelForValue(i[s]),l();for(a=void 0,s=0,n=e.ticks.length;s<n;++s)o=e.getPixelForTick(s),l();return r}function Fn(t,e,i,s){return n(t)?function(t,e,i,s){const n=i.parse(t[0],s),o=i.parse(t[1],s),a=Math.min(n,o),r=Math.max(n,o);let l=a,h=r;Math.abs(a)>Math.abs(r)&&(l=r,h=a),e[i.axis]=h,e._custom={barStart:l,barEnd:h,start:n,end:o,min:a,max:r}}(t,e,i,s):e[i.axis]=i.parse(t,s),e}function Vn(t,e,i,s){const n=t.iScale,o=t.vScale,a=n.getLabels(),r=n===o,l=[];let h,c,d,u;for(h=i,c=i+s;h<c;++h)u=e[h],d={},d[n.axis]=r||n.parse(a[h],h),l.push(Fn(u,d,o,h));return l}function Bn(t){return t&&void 0!==t.barStart&&void 0!==t.barEnd}function Wn(t,e,i,s){let n=e.borderSkipped;const o={};if(!n)return void(t.borderSkipped=o);if(!0===n)return void(t.borderSkipped={top:!0,right:!0,bottom:!0,left:!0});const{start:a,end:r,reverse:l,top:h,bottom:c}=function(t){let e,i,s,n,o;return t.horizontal?(e=t.base>t.x,i="left",s="right"):(e=t.base<t.y,i="bottom",s="top"),e?(n="end",o="start"):(n="start",o="end"),{start:i,end:s,reverse:e,top:n,bottom:o}}(t);"middle"===n&&i&&(t.enableBorderRadius=!0,(i._top||0)===s?n=h:(i._bottom||0)===s?n=c:(o[Nn(c,a,r,l)]=!0,n=h)),o[Nn(n,a,r,l)]=!0,t.borderSkipped=o}function Nn(t,e,i,s){var n,o,a;return s?(a=i,t=Hn(t=(n=t)===(o=e)?a:n===a?o:n,i,e)):t=Hn(t,e,i),t}function Hn(t,e,i){return"start"===t?e:"end"===t?i:t}function jn(t,{inflateAmount:e},i){t.inflateAmount="auto"===e?1===i?.33:0:e}class $n extends js{static id="doughnut";static defaults={datasetElementType:!1,dataElementType:"arc",animation:{animateRotate:!0,animateScale:!1},animations:{numbers:{type:"number",properties:["circumference","endAngle","innerRadius","outerRadius","startAngle","x","y","offset","borderWidth","spacing"]}},cutout:"50%",rotation:0,circumference:360,radius:"100%",spacing:0,indexAxis:"r"};static descriptors={_scriptable:t=>"spacing"!==t,_indexable:t=>"spacing"!==t&&!t.startsWith("borderDash")&&!t.startsWith("hoverBorderDash")};static overrides={aspectRatio:1,plugins:{legend:{labels:{generateLabels(t){const e=t.data,{labels:{pointStyle:i,textAlign:s,color:n,useBorderRadius:o,borderRadius:a}}=t.legend.options;return e.labels.length&&e.datasets.length?e.labels.map(((e,r)=>{const l=t.getDatasetMeta(0).controller.getStyle(r);return{text:e,fillStyle:l.backgroundColor,fontColor:n,hidden:!t.getDataVisibility(r),lineDash:l.borderDash,lineDashOffset:l.borderDashOffset,lineJoin:l.borderJoinStyle,lineWidth:l.borderWidth,strokeStyle:l.borderColor,textAlign:s,pointStyle:i,borderRadius:o&&(a||l.borderRadius),index:r}})):[]}},onClick(t,e,i){i.chart.toggleDataVisibility(e.index),i.chart.update()}}}};constructor(t,e){super(t,e),this.enableOptionSharing=!0,this.innerRadius=void 0,this.outerRadius=void 0,this.offsetX=void 0,this.offsetY=void 0}linkScales(){}parse(t,e){const i=this.getDataset().data,s=this._cachedMeta;if(!1===this._parsing)s._parsed=i;else{let n,a,r=t=>+i[t];if(o(i[t])){const{key:t="value"}=this._parsing;r=e=>+M(i[e],t)}for(n=t,a=t+e;n<a;++n)s._parsed[n]=r(n)}}_getRotation(){return $(this.options.rotation-90)}_getCircumference(){return $(this.options.circumference)}_getRotationExtents(){let t=O,e=-O;for(let i=0;i<this.chart.data.datasets.length;++i)if(this.chart.isDatasetVisible(i)&&this.chart.getDatasetMeta(i).type===this._type){const s=this.chart.getDatasetMeta(i).controller,n=s._getRotation(),o=s._getCircumference();t=Math.min(t,n),e=Math.max(e,n+o)}return{rotation:t,circumference:e-t}}update(t){const e=this.chart,{chartArea:i}=e,s=this._cachedMeta,n=s.data,o=this.getMaxBorderWidth()+this.getMaxOffset(n)+this.options.spacing,a=Math.max((Math.min(i.width,i.height)-o)/2,0),r=Math.min(h(this.options.cutout,a),1),l=this._getRingWeight(this.index),{circumference:d,rotation:u}=this._getRotationExtents(),{ratioX:f,ratioY:g,offsetX:p,offsetY:m}=function(t,e,i){let s=1,n=1,o=0,a=0;if(e<O){const r=t,l=r+e,h=Math.cos(r),c=Math.sin(r),d=Math.cos(l),u=Math.sin(l),f=(t,e,s)=>J(t,r,l,!0)?1:Math.max(e,e*i,s,s*i),g=(t,e,s)=>J(t,r,l,!0)?-1:Math.min(e,e*i,s,s*i),p=f(0,h,d),m=f(E,c,u),x=g(C,h,d),b=g(C+E,c,u);s=(p-x)/2,n=(m-b)/2,o=-(p+x)/2,a=-(m+b)/2}return{ratioX:s,ratioY:n,offsetX:o,offsetY:a}}(u,d,r),x=(i.width-o)/f,b=(i.height-o)/g,_=Math.max(Math.min(x,b)/2,0),y=c(this.options.radius,_),v=(y-Math.max(y*r,0))/this._getVisibleDatasetWeightTotal();this.offsetX=p*y,this.offsetY=m*y,s.total=this.calculateTotal(),this.outerRadius=y-v*this._getRingWeightOffset(this.index),this.innerRadius=Math.max(this.outerRadius-v*l,0),this.updateElements(n,0,n.length,t)}_circumference(t,e){const i=this.options,s=this._cachedMeta,n=this._getCircumference();return e&&i.animation.animateRotate||!this.chart.getDataVisibility(t)||null===s._parsed[t]||s.data[t].hidden?0:this.calculateCircumference(s._parsed[t]*n/O)}updateElements(t,e,i,s){const n="reset"===s,o=this.chart,a=o.chartArea,r=o.options.animation,l=(a.left+a.right)/2,h=(a.top+a.bottom)/2,c=n&&r.animateScale,d=c?0:this.innerRadius,u=c?0:this.outerRadius,{sharedOptions:f,includeOptions:g}=this._getSharedOptions(e,s);let p,m=this._getRotation();for(p=0;p<e;++p)m+=this._circumference(p,n);for(p=e;p<e+i;++p){const e=this._circumference(p,n),i=t[p],o={x:l+this.offsetX,y:h+this.offsetY,startAngle:m,endAngle:m+e,circumference:e,outerRadius:u,innerRadius:d};g&&(o.options=f||this.resolveDataElementOptions(p,i.active?"active":s)),m+=e,this.updateElement(i,p,o,s)}}calculateTotal(){const t=this._cachedMeta,e=t.data;let i,s=0;for(i=0;i<e.length;i++){const n=t._parsed[i];null===n||isNaN(n)||!this.chart.getDataVisibility(i)||e[i].hidden||(s+=Math.abs(n))}return s}calculateCircumference(t){const e=this._cachedMeta.total;return e>0&&!isNaN(t)?O*(Math.abs(t)/e):0}getLabelAndValue(t){const e=this._cachedMeta,i=this.chart,s=i.data.labels||[],n=ne(e._parsed[t],i.options.locale);return{label:s[t]||"",value:n}}getMaxBorderWidth(t){let e=0;const i=this.chart;let s,n,o,a,r;if(!t)for(s=0,n=i.data.datasets.length;s<n;++s)if(i.isDatasetVisible(s)){o=i.getDatasetMeta(s),t=o.data,a=o.controller;break}if(!t)return 0;for(s=0,n=t.length;s<n;++s)r=a.resolveDataElementOptions(s),"inner"!==r.borderAlign&&(e=Math.max(e,r.borderWidth||0,r.hoverBorderWidth||0));return e}getMaxOffset(t){let e=0;for(let i=0,s=t.length;i<s;++i){const t=this.resolveDataElementOptions(i);e=Math.max(e,t.offset||0,t.hoverOffset||0)}return e}_getRingWeightOffset(t){let e=0;for(let i=0;i<t;++i)this.chart.isDatasetVisible(i)&&(e+=this._getRingWeight(i));return e}_getRingWeight(t){return Math.max(l(this.chart.data.datasets[t].weight,1),0)}_getVisibleDatasetWeightTotal(){return this._getRingWeightOffset(this.chart.data.datasets.length)||1}}class Yn extends js{static id="polarArea";static defaults={dataElementType:"arc",animation:{animateRotate:!0,animateScale:!0},animations:{numbers:{type:"number",properties:["x","y","startAngle","endAngle","innerRadius","outerRadius"]}},indexAxis:"r",startAngle:0};static overrides={aspectRatio:1,plugins:{legend:{labels:{generateLabels(t){const e=t.data;if(e.labels.length&&e.datasets.length){const{labels:{pointStyle:i,color:s}}=t.legend.options;return e.labels.map(((e,n)=>{const o=t.getDatasetMeta(0).controller.getStyle(n);return{text:e,fillStyle:o.backgroundColor,strokeStyle:o.borderColor,fontColor:s,lineWidth:o.borderWidth,pointStyle:i,hidden:!t.getDataVisibility(n),index:n}}))}return[]}},onClick(t,e,i){i.chart.toggleDataVisibility(e.index),i.chart.update()}}},scales:{r:{type:"radialLinear",angleLines:{display:!1},beginAtZero:!0,grid:{circular:!0},pointLabels:{display:!1},startAngle:0}}};constructor(t,e){super(t,e),this.innerRadius=void 0,this.outerRadius=void 0}getLabelAndValue(t){const e=this._cachedMeta,i=this.chart,s=i.data.labels||[],n=ne(e._parsed[t].r,i.options.locale);return{label:s[t]||"",value:n}}parseObjectData(t,e,i,s){return ii.bind(this)(t,e,i,s)}update(t){const e=this._cachedMeta.data;this._updateRadius(),this.updateElements(e,0,e.length,t)}getMinMax(){const t=this._cachedMeta,e={min:Number.POSITIVE_INFINITY,max:Number.NEGATIVE_INFINITY};return t.data.forEach(((t,i)=>{const s=this.getParsed(i).r;!isNaN(s)&&this.chart.getDataVisibility(i)&&(s<e.min&&(e.min=s),s>e.max&&(e.max=s))})),e}_updateRadius(){const t=this.chart,e=t.chartArea,i=t.options,s=Math.min(e.right-e.left,e.bottom-e.top),n=Math.max(s/2,0),o=(n-Math.max(i.cutoutPercentage?n/100*i.cutoutPercentage:1,0))/t.getVisibleDatasetCount();this.outerRadius=n-o*this.index,this.innerRadius=this.outerRadius-o}updateElements(t,e,i,s){const n="reset"===s,o=this.chart,a=o.options.animation,r=this._cachedMeta.rScale,l=r.xCenter,h=r.yCenter,c=r.getIndexAngle(0)-.5*C;let d,u=c;const f=360/this.countVisibleElements();for(d=0;d<e;++d)u+=this._computeAngle(d,s,f);for(d=e;d<e+i;d++){const e=t[d];let i=u,g=u+this._computeAngle(d,s,f),p=o.getDataVisibility(d)?r.getDistanceFromCenterForValue(this.getParsed(d).r):0;u=g,n&&(a.animateScale&&(p=0),a.animateRotate&&(i=g=c));const m={x:l,y:h,innerRadius:0,outerRadius:p,startAngle:i,endAngle:g,options:this.resolveDataElementOptions(d,e.active?"active":s)};this.updateElement(e,d,m,s)}}countVisibleElements(){const t=this._cachedMeta;let e=0;return t.data.forEach(((t,i)=>{!isNaN(this.getParsed(i).r)&&this.chart.getDataVisibility(i)&&e++})),e}_computeAngle(t,e,i){return this.chart.getDataVisibility(t)?$(this.resolveDataElementOptions(t,e).angle||i):0}}var Un=Object.freeze({__proto__:null,BarController:class extends js{static id="bar";static defaults={datasetElementType:!1,dataElementType:"bar",categoryPercentage:.8,barPercentage:.9,grouped:!0,animations:{numbers:{type:"number",properties:["x","y","base","width","height"]}}};static overrides={scales:{_index_:{type:"category",offset:!0,grid:{offset:!0}},_value_:{type:"linear",beginAtZero:!0}}};parsePrimitiveData(t,e,i,s){return Vn(t,e,i,s)}parseArrayData(t,e,i,s){return Vn(t,e,i,s)}parseObjectData(t,e,i,s){const{iScale:n,vScale:o}=t,{xAxisKey:a="x",yAxisKey:r="y"}=this._parsing,l="x"===n.axis?a:r,h="x"===o.axis?a:r,c=[];let d,u,f,g;for(d=i,u=i+s;d<u;++d)g=e[d],f={},f[n.axis]=n.parse(M(g,l),d),c.push(Fn(M(g,h),f,o,d));return c}updateRangeFromParsed(t,e,i,s){super.updateRangeFromParsed(t,e,i,s);const n=i._custom;n&&e===this._cachedMeta.vScale&&(t.min=Math.min(t.min,n.min),t.max=Math.max(t.max,n.max))}getMaxOverflow(){return 0}getLabelAndValue(t){const e=this._cachedMeta,{iScale:i,vScale:s}=e,n=this.getParsed(t),o=n._custom,a=Bn(o)?"["+o.start+", "+o.end+"]":""+s.getLabelForValue(n[s.axis]);return{label:""+i.getLabelForValue(n[i.axis]),value:a}}initialize(){this.enableOptionSharing=!0,super.initialize();this._cachedMeta.stack=this.getDataset().stack}update(t){const e=this._cachedMeta;this.updateElements(e.data,0,e.data.length,t)}updateElements(t,e,i,n){const o="reset"===n,{index:a,_cachedMeta:{vScale:r}}=this,l=r.getBasePixel(),h=r.isHorizontal(),c=this._getRuler(),{sharedOptions:d,includeOptions:u}=this._getSharedOptions(e,n);for(let f=e;f<e+i;f++){const e=this.getParsed(f),i=o||s(e[r.axis])?{base:l,head:l}:this._calculateBarValuePixels(f),g=this._calculateBarIndexPixels(f,c),p=(e._stacks||{})[r.axis],m={horizontal:h,base:i.base,enableBorderRadius:!p||Bn(e._custom)||a===p._top||a===p._bottom,x:h?i.head:g.center,y:h?g.center:i.head,height:h?g.size:Math.abs(i.size),width:h?Math.abs(i.size):g.size};u&&(m.options=d||this.resolveDataElementOptions(f,t[f].active?"active":n));const x=m.options||t[f].options;Wn(m,x,p,a),jn(m,x,c.ratio),this.updateElement(t[f],f,m,n)}}_getStacks(t,e){const{iScale:i}=this._cachedMeta,n=i.getMatchingVisibleMetas(this._type).filter((t=>t.controller.options.grouped)),o=i.options.stacked,a=[],r=this._cachedMeta.controller.getParsed(e),l=r&&r[i.axis],h=t=>{const e=t._parsed.find((t=>t[i.axis]===l)),n=e&&e[t.vScale.axis];if(s(n)||isNaN(n))return!0};for(const i of n)if((void 0===e||!h(i))&&((!1===o||-1===a.indexOf(i.stack)||void 0===o&&void 0===i.stack)&&a.push(i.stack),i.index===t))break;return a.length||a.push(void 0),a}_getStackCount(t){return this._getStacks(void 0,t).length}_getAxisCount(){return this._getAxis().length}getFirstScaleIdForIndexAxis(){const t=this.chart.scales,e=this.chart.options.indexAxis;return Object.keys(t).filter((i=>t[i].axis===e)).shift()}_getAxis(){const t={},e=this.getFirstScaleIdForIndexAxis();for(const i of this.chart.data.datasets)t[l("x"===this.chart.options.indexAxis?i.xAxisID:i.yAxisID,e)]=!0;return Object.keys(t)}_getStackIndex(t,e,i){const s=this._getStacks(t,i),n=void 0!==e?s.indexOf(e):-1;return-1===n?s.length-1:n}_getRuler(){const t=this.options,e=this._cachedMeta,i=e.iScale,s=[];let n,o;for(n=0,o=e.data.length;n<o;++n)s.push(i.getPixelForValue(this.getParsed(n)[i.axis],n));const a=t.barThickness;return{min:a||zn(e),pixels:s,start:i._startPixel,end:i._endPixel,stackCount:this._getStackCount(),scale:i,grouped:t.grouped,ratio:a?1:t.categoryPercentage*t.barPercentage}}_calculateBarValuePixels(t){const{_cachedMeta:{vScale:e,_stacked:i,index:n},options:{base:o,minBarLength:a}}=this,r=o||0,l=this.getParsed(t),h=l._custom,c=Bn(h);let d,u,f=l[e.axis],g=0,p=i?this.applyStack(e,l,i):f;p!==f&&(g=p-f,p=f),c&&(f=h.barStart,p=h.barEnd-h.barStart,0!==f&&F(f)!==F(h.barEnd)&&(g=0),g+=f);const m=s(o)||c?g:o;let x=e.getPixelForValue(m);if(d=this.chart.getDataVisibility(t)?e.getPixelForValue(g+p):x,u=d-x,Math.abs(u)<a){u=function(t,e,i){return 0!==t?F(t):(e.isHorizontal()?1:-1)*(e.min>=i?1:-1)}(u,e,r)*a,f===r&&(x-=u/2);const t=e.getPixelForDecimal(0),s=e.getPixelForDecimal(1),o=Math.min(t,s),h=Math.max(t,s);x=Math.max(Math.min(x,h),o),d=x+u,i&&!c&&(l._stacks[e.axis]._visualValues[n]=e.getValueForPixel(d)-e.getValueForPixel(x))}if(x===e.getPixelForValue(r)){const t=F(u)*e.getLineWidthForValue(r)/2;x+=t,u-=t}return{size:u,base:x,head:d,center:d+u/2}}_calculateBarIndexPixels(t,e){const i=e.scale,n=this.options,o=n.skipNull,a=l(n.maxBarThickness,1/0);let r,h;const c=this._getAxisCount();if(e.grouped){const i=o?this._getStackCount(t):e.stackCount,d="flex"===n.barThickness?function(t,e,i,s){const n=e.pixels,o=n[t];let a=t>0?n[t-1]:null,r=t<n.length-1?n[t+1]:null;const l=i.categoryPercentage;null===a&&(a=o-(null===r?e.end-e.start:r-o)),null===r&&(r=o+o-a);const h=o-(o-Math.min(a,r))/2*l;return{chunk:Math.abs(r-a)/2*l/s,ratio:i.barPercentage,start:h}}(t,e,n,i*c):function(t,e,i,n){const o=i.barThickness;let a,r;return s(o)?(a=e.min*i.categoryPercentage,r=i.barPercentage):(a=o*n,r=1),{chunk:a/n,ratio:r,start:e.pixels[t]-a/2}}(t,e,n,i*c),u="x"===this.chart.options.indexAxis?this.getDataset().xAxisID:this.getDataset().yAxisID,f=this._getAxis().indexOf(l(u,this.getFirstScaleIdForIndexAxis())),g=this._getStackIndex(this.index,this._cachedMeta.stack,o?t:void 0)+f;r=d.start+d.chunk*g+d.chunk/2,h=Math.min(a,d.chunk*d.ratio)}else r=i.getPixelForValue(this.getParsed(t)[i.axis],t),h=Math.min(a,e.min*e.ratio);return{base:r-h/2,head:r+h/2,center:r,size:h}}draw(){const t=this._cachedMeta,e=t.vScale,i=t.data,s=i.length;let n=0;for(;n<s;++n)null===this.getParsed(n)[e.axis]||i[n].hidden||i[n].draw(this._ctx)}},BubbleController:class extends js{static id="bubble";static defaults={datasetElementType:!1,dataElementType:"point",animations:{numbers:{type:"number",properties:["x","y","borderWidth","radius"]}}};static overrides={scales:{x:{type:"linear"},y:{type:"linear"}}};initialize(){this.enableOptionSharing=!0,super.initialize()}parsePrimitiveData(t,e,i,s){const n=super.parsePrimitiveData(t,e,i,s);for(let t=0;t<n.length;t++)n[t]._custom=this.resolveDataElementOptions(t+i).radius;return n}parseArrayData(t,e,i,s){const n=super.parseArrayData(t,e,i,s);for(let t=0;t<n.length;t++){const s=e[i+t];n[t]._custom=l(s[2],this.resolveDataElementOptions(t+i).radius)}return n}parseObjectData(t,e,i,s){const n=super.parseObjectData(t,e,i,s);for(let t=0;t<n.length;t++){const s=e[i+t];n[t]._custom=l(s&&s.r&&+s.r,this.resolveDataElementOptions(t+i).radius)}return n}getMaxOverflow(){const t=this._cachedMeta.data;let e=0;for(let i=t.length-1;i>=0;--i)e=Math.max(e,t[i].size(this.resolveDataElementOptions(i))/2);return e>0&&e}getLabelAndValue(t){const e=this._cachedMeta,i=this.chart.data.labels||[],{xScale:s,yScale:n}=e,o=this.getParsed(t),a=s.getLabelForValue(o.x),r=n.getLabelForValue(o.y),l=o._custom;return{label:i[t]||"",value:"("+a+", "+r+(l?", "+l:"")+")"}}update(t){const e=this._cachedMeta.data;this.updateElements(e,0,e.length,t)}updateElements(t,e,i,s){const n="reset"===s,{iScale:o,vScale:a}=this._cachedMeta,{sharedOptions:r,includeOptions:l}=this._getSharedOptions(e,s),h=o.axis,c=a.axis;for(let d=e;d<e+i;d++){const e=t[d],i=!n&&this.getParsed(d),u={},f=u[h]=n?o.getPixelForDecimal(.5):o.getPixelForValue(i[h]),g=u[c]=n?a.getBasePixel():a.getPixelForValue(i[c]);u.skip=isNaN(f)||isNaN(g),l&&(u.options=r||this.resolveDataElementOptions(d,e.active?"active":s),n&&(u.options.radius=0)),this.updateElement(e,d,u,s)}}resolveDataElementOptions(t,e){const i=this.getParsed(t);let s=super.resolveDataElementOptions(t,e);s.$shared&&(s=Object.assign({},s,{$shared:!1}));const n=s.radius;return"active"!==e&&(s.radius=0),s.radius+=l(i&&i._custom,n),s}},DoughnutController:$n,LineController:class extends js{static id="line";static defaults={datasetElementType:"line",dataElementType:"point",showLine:!0,spanGaps:!1};static overrides={scales:{_index_:{type:"category"},_value_:{type:"linear"}}};initialize(){this.enableOptionSharing=!0,this.supportsDecimation=!0,super.initialize()}update(t){const e=this._cachedMeta,{dataset:i,data:s=[],_dataset:n}=e,o=this.chart._animationsDisabled;let{start:a,count:r}=pt(e,s,o);this._drawStart=a,this._drawCount=r,mt(e)&&(a=0,r=s.length),i._chart=this.chart,i._datasetIndex=this.index,i._decimated=!!n._decimated,i.points=s;const l=this.resolveDatasetElementOptions(t);this.options.showLine||(l.borderWidth=0),l.segment=this.options.segment,this.updateElement(i,void 0,{animated:!o,options:l},t),this.updateElements(s,a,r,t)}updateElements(t,e,i,n){const o="reset"===n,{iScale:a,vScale:r,_stacked:l,_dataset:h}=this._cachedMeta,{sharedOptions:c,includeOptions:d}=this._getSharedOptions(e,n),u=a.axis,f=r.axis,{spanGaps:g,segment:p}=this.options,m=N(g)?g:Number.POSITIVE_INFINITY,x=this.chart._animationsDisabled||o||"none"===n,b=e+i,_=t.length;let y=e>0&&this.getParsed(e-1);for(let i=0;i<_;++i){const g=t[i],_=x?g:{};if(i<e||i>=b){_.skip=!0;continue}const v=this.getParsed(i),M=s(v[f]),w=_[u]=a.getPixelForValue(v[u],i),k=_[f]=o||M?r.getBasePixel():r.getPixelForValue(l?this.applyStack(r,v,l):v[f],i);_.skip=isNaN(w)||isNaN(k)||M,_.stop=i>0&&Math.abs(v[u]-y[u])>m,p&&(_.parsed=v,_.raw=h.data[i]),d&&(_.options=c||this.resolveDataElementOptions(i,g.active?"active":n)),x||this.updateElement(g,i,_,n),y=v}}getMaxOverflow(){const t=this._cachedMeta,e=t.dataset,i=e.options&&e.options.borderWidth||0,s=t.data||[];if(!s.length)return i;const n=s[0].size(this.resolveDataElementOptions(0)),o=s[s.length-1].size(this.resolveDataElementOptions(s.length-1));return Math.max(i,n,o)/2}draw(){const t=this._cachedMeta;t.dataset.updateControlPoints(this.chart.chartArea,t.iScale.axis),super.draw()}},PieController:class extends $n{static id="pie";static defaults={cutout:0,rotation:0,circumference:360,radius:"100%"}},PolarAreaController:Yn,RadarController:class extends js{static id="radar";static defaults={datasetElementType:"line",dataElementType:"point",indexAxis:"r",showLine:!0,elements:{line:{fill:"start"}}};static overrides={aspectRatio:1,scales:{r:{type:"radialLinear"}}};getLabelAndValue(t){const e=this._cachedMeta.vScale,i=this.getParsed(t);return{label:e.getLabels()[t],value:""+e.getLabelForValue(i[e.axis])}}parseObjectData(t,e,i,s){return ii.bind(this)(t,e,i,s)}update(t){const e=this._cachedMeta,i=e.dataset,s=e.data||[],n=e.iScale.getLabels();if(i.points=s,"resize"!==t){const e=this.resolveDatasetElementOptions(t);this.options.showLine||(e.borderWidth=0);const o={_loop:!0,_fullLoop:n.length===s.length,options:e};this.updateElement(i,void 0,o,t)}this.updateElements(s,0,s.length,t)}updateElements(t,e,i,s){const n=this._cachedMeta.rScale,o="reset"===s;for(let a=e;a<e+i;a++){const e=t[a],i=this.resolveDataElementOptions(a,e.active?"active":s),r=n.getPointPositionForValue(a,this.getParsed(a).r),l=o?n.xCenter:r.x,h=o?n.yCenter:r.y,c={x:l,y:h,angle:r.angle,skip:isNaN(l)||isNaN(h),options:i};this.updateElement(e,a,c,s)}}},ScatterController:class extends js{static id="scatter";static defaults={datasetElementType:!1,dataElementType:"point",showLine:!1,fill:!1};static overrides={interaction:{mode:"point"},scales:{x:{type:"linear"},y:{type:"linear"}}};getLabelAndValue(t){const e=this._cachedMeta,i=this.chart.data.labels||[],{xScale:s,yScale:n}=e,o=this.getParsed(t),a=s.getLabelForValue(o.x),r=n.getLabelForValue(o.y);return{label:i[t]||"",value:"("+a+", "+r+")"}}update(t){const e=this._cachedMeta,{data:i=[]}=e,s=this.chart._animationsDisabled;let{start:n,count:o}=pt(e,i,s);if(this._drawStart=n,this._drawCount=o,mt(e)&&(n=0,o=i.length),this.options.showLine){this.datasetElementType||this.addElements();const{dataset:n,_dataset:o}=e;n._chart=this.chart,n._datasetIndex=this.index,n._decimated=!!o._decimated,n.points=i;const a=this.resolveDatasetElementOptions(t);a.segment=this.options.segment,this.updateElement(n,void 0,{animated:!s,options:a},t)}else this.datasetElementType&&(delete e.dataset,this.datasetElementType=!1);this.updateElements(i,n,o,t)}addElements(){const{showLine:t}=this.options;!this.datasetElementType&&t&&(this.datasetElementType=this.chart.registry.getElement("line")),super.addElements()}updateElements(t,e,i,n){const o="reset"===n,{iScale:a,vScale:r,_stacked:l,_dataset:h}=this._cachedMeta,c=this.resolveDataElementOptions(e,n),d=this.getSharedOptions(c),u=this.includeOptions(n,d),f=a.axis,g=r.axis,{spanGaps:p,segment:m}=this.options,x=N(p)?p:Number.POSITIVE_INFINITY,b=this.chart._animationsDisabled||o||"none"===n;let _=e>0&&this.getParsed(e-1);for(let c=e;c<e+i;++c){const e=t[c],i=this.getParsed(c),p=b?e:{},y=s(i[g]),v=p[f]=a.getPixelForValue(i[f],c),M=p[g]=o||y?r.getBasePixel():r.getPixelForValue(l?this.applyStack(r,i,l):i[g],c);p.skip=isNaN(v)||isNaN(M)||y,p.stop=c>0&&Math.abs(i[f]-_[f])>x,m&&(p.parsed=i,p.raw=h.data[c]),u&&(p.options=d||this.resolveDataElementOptions(c,e.active?"active":n)),b||this.updateElement(e,c,p,n),_=i}this.updateSharedOptions(d,n,c)}getMaxOverflow(){const t=this._cachedMeta,e=t.data||[];if(!this.options.showLine){let t=0;for(let i=e.length-1;i>=0;--i)t=Math.max(t,e[i].size(this.resolveDataElementOptions(i))/2);return t>0&&t}const i=t.dataset,s=i.options&&i.options.borderWidth||0;if(!e.length)return s;const n=e[0].size(this.resolveDataElementOptions(0)),o=e[e.length-1].size(this.resolveDataElementOptions(e.length-1));return Math.max(s,n,o)/2}}});function Xn(t,e,i,s){const n=vi(t.options.borderRadius,["outerStart","outerEnd","innerStart","innerEnd"]);const o=(i-e)/2,a=Math.min(o,s*e/2),r=t=>{const e=(i-Math.min(o,t))*s/2;return Z(t,0,Math.min(o,e))};return{outerStart:r(n.outerStart),outerEnd:r(n.outerEnd),innerStart:Z(n.innerStart,0,a),innerEnd:Z(n.innerEnd,0,a)}}function qn(t,e,i,s){return{x:i+t*Math.cos(e),y:s+t*Math.sin(e)}}function Kn(t,e,i,s,n,o){const{x:a,y:r,startAngle:l,pixelMargin:h,innerRadius:c}=e,d=Math.max(e.outerRadius+s+i-h,0),u=c>0?c+s+i+h:0;let f=0;const g=n-l;if(s){const t=((c>0?c-s:0)+(d>0?d-s:0))/2;f=(g-(0!==t?g*t/(t+s):g))/2}const p=(g-Math.max(.001,g*d-i/C)/d)/2,m=l+p+f,x=n-p-f,{outerStart:b,outerEnd:_,innerStart:y,innerEnd:v}=Xn(e,u,d,x-m),M=d-b,w=d-_,k=m+b/M,S=x-_/w,P=u+y,D=u+v,O=m+y/P,A=x-v/D;if(t.beginPath(),o){const e=(k+S)/2;if(t.arc(a,r,d,k,e),t.arc(a,r,d,e,S),_>0){const e=qn(w,S,a,r);t.arc(e.x,e.y,_,S,x+E)}const i=qn(D,x,a,r);if(t.lineTo(i.x,i.y),v>0){const e=qn(D,A,a,r);t.arc(e.x,e.y,v,x+E,A+Math.PI)}const s=(x-v/u+(m+y/u))/2;if(t.arc(a,r,u,x-v/u,s,!0),t.arc(a,r,u,s,m+y/u,!0),y>0){const e=qn(P,O,a,r);t.arc(e.x,e.y,y,O+Math.PI,m-E)}const n=qn(M,m,a,r);if(t.lineTo(n.x,n.y),b>0){const e=qn(M,k,a,r);t.arc(e.x,e.y,b,m-E,k)}}else{t.moveTo(a,r);const e=Math.cos(k)*d+a,i=Math.sin(k)*d+r;t.lineTo(e,i);const s=Math.cos(S)*d+a,n=Math.sin(S)*d+r;t.lineTo(s,n)}t.closePath()}function Gn(t,e,i,s,n){const{fullCircles:o,startAngle:a,circumference:r,options:l}=e,{borderWidth:h,borderJoinStyle:c,borderDash:d,borderDashOffset:u,borderRadius:f}=l,g="inner"===l.borderAlign;if(!h)return;t.setLineDash(d||[]),t.lineDashOffset=u,g?(t.lineWidth=2*h,t.lineJoin=c||"round"):(t.lineWidth=h,t.lineJoin=c||"bevel");let p=e.endAngle;if(o){Kn(t,e,i,s,p,n);for(let e=0;e<o;++e)t.stroke();isNaN(r)||(p=a+(r%O||O))}g&&function(t,e,i){const{startAngle:s,pixelMargin:n,x:o,y:a,outerRadius:r,innerRadius:l}=e;let h=n/r;t.beginPath(),t.arc(o,a,r,s-h,i+h),l>n?(h=n/l,t.arc(o,a,l,i+h,s-h,!0)):t.arc(o,a,n,i+E,s-E),t.closePath(),t.clip()}(t,e,p),l.selfJoin&&p-a>=C&&0===f&&"miter"!==c&&function(t,e,i){const{startAngle:s,x:n,y:o,outerRadius:a,innerRadius:r,options:l}=e,{borderWidth:h,borderJoinStyle:c}=l,d=Math.min(h/a,G(s-i));if(t.beginPath(),t.arc(n,o,a-h/2,s+d/2,i-d/2),r>0){const e=Math.min(h/r,G(s-i));t.arc(n,o,r+h/2,i-e/2,s+e/2,!0)}else{const e=Math.min(h/2,a*G(s-i));if("round"===c)t.arc(n,o,e,i-C/2,s+C/2,!0);else if("bevel"===c){const a=2*e*e,r=-a*Math.cos(i+C/2)+n,l=-a*Math.sin(i+C/2)+o,h=a*Math.cos(s+C/2)+n,c=a*Math.sin(s+C/2)+o;t.lineTo(r,l),t.lineTo(h,c)}}t.closePath(),t.moveTo(0,0),t.rect(0,0,t.canvas.width,t.canvas.height),t.clip("evenodd")}(t,e,p),o||(Kn(t,e,i,s,p,n),t.stroke())}function Jn(t,e,i=e){t.lineCap=l(i.borderCapStyle,e.borderCapStyle),t.setLineDash(l(i.borderDash,e.borderDash)),t.lineDashOffset=l(i.borderDashOffset,e.borderDashOffset),t.lineJoin=l(i.borderJoinStyle,e.borderJoinStyle),t.lineWidth=l(i.borderWidth,e.borderWidth),t.strokeStyle=l(i.borderColor,e.borderColor)}function Zn(t,e,i){t.lineTo(i.x,i.y)}function Qn(t,e,i={}){const s=t.length,{start:n=0,end:o=s-1}=i,{start:a,end:r}=e,l=Math.max(n,a),h=Math.min(o,r),c=n<a&&o<a||n>r&&o>r;return{count:s,start:l,loop:e.loop,ilen:h<l&&!c?s+h-l:h-l}}function to(t,e,i,s){const{points:n,options:o}=e,{count:a,start:r,loop:l,ilen:h}=Qn(n,i,s),c=function(t){return t.stepped?Fe:t.tension||"monotone"===t.cubicInterpolationMode?Ve:Zn}(o);let d,u,f,{move:g=!0,reverse:p}=s||{};for(d=0;d<=h;++d)u=n[(r+(p?h-d:d))%a],u.skip||(g?(t.moveTo(u.x,u.y),g=!1):c(t,f,u,p,o.stepped),f=u);return l&&(u=n[(r+(p?h:0))%a],c(t,f,u,p,o.stepped)),!!l}function eo(t,e,i,s){const n=e.points,{count:o,start:a,ilen:r}=Qn(n,i,s),{move:l=!0,reverse:h}=s||{};let c,d,u,f,g,p,m=0,x=0;const b=t=>(a+(h?r-t:t))%o,_=()=>{f!==g&&(t.lineTo(m,g),t.lineTo(m,f),t.lineTo(m,p))};for(l&&(d=n[b(0)],t.moveTo(d.x,d.y)),c=0;c<=r;++c){if(d=n[b(c)],d.skip)continue;const e=d.x,i=d.y,s=0|e;s===u?(i<f?f=i:i>g&&(g=i),m=(x*m+e)/++x):(_(),t.lineTo(e,i),u=s,x=0,f=g=i),p=i}_()}function io(t){const e=t.options,i=e.borderDash&&e.borderDash.length;return!(t._decimated||t._loop||e.tension||"monotone"===e.cubicInterpolationMode||e.stepped||i)?eo:to}const so="function"==typeof Path2D;function no(t,e,i,s){so&&!e.options.segment?function(t,e,i,s){let n=e._path;n||(n=e._path=new Path2D,e.path(n,i,s)&&n.closePath()),Jn(t,e.options),t.stroke(n)}(t,e,i,s):function(t,e,i,s){const{segments:n,options:o}=e,a=io(e);for(const r of n)Jn(t,o,r.style),t.beginPath(),a(t,e,r,{start:i,end:i+s-1})&&t.closePath(),t.stroke()}(t,e,i,s)}class oo extends $s{static id="line";static defaults={borderCapStyle:"butt",borderDash:[],borderDashOffset:0,borderJoinStyle:"miter",borderWidth:3,capBezierPoints:!0,cubicInterpolationMode:"default",fill:!1,spanGaps:!1,stepped:!1,tension:0};static defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"};static descriptors={_scriptable:!0,_indexable:t=>"borderDash"!==t&&"fill"!==t};constructor(t){super(),this.animated=!0,this.options=void 0,this._chart=void 0,this._loop=void 0,this._fullLoop=void 0,this._path=void 0,this._points=void 0,this._segments=void 0,this._decimated=!1,this._pointsUpdated=!1,this._datasetIndex=void 0,t&&Object.assign(this,t)}updateControlPoints(t,e){const i=this.options;if((i.tension||"monotone"===i.cubicInterpolationMode)&&!i.stepped&&!this._pointsUpdated){const s=i.spanGaps?this._loop:this._fullLoop;hi(this._points,i,t,s,e),this._pointsUpdated=!0}}set points(t){this._points=t,delete this._segments,delete this._path,this._pointsUpdated=!1}get points(){return this._points}get segments(){return this._segments||(this._segments=zi(this,this.options.segment))}first(){const t=this.segments,e=this.points;return t.length&&e[t[0].start]}last(){const t=this.segments,e=this.points,i=t.length;return i&&e[t[i-1].end]}interpolate(t,e){const i=this.options,s=t[e],n=this.points,o=Ii(this,{property:e,start:s,end:s});if(!o.length)return;const a=[],r=function(t){return t.stepped?pi:t.tension||"monotone"===t.cubicInterpolationMode?mi:gi}(i);let l,h;for(l=0,h=o.length;l<h;++l){const{start:h,end:c}=o[l],d=n[h],u=n[c];if(d===u){a.push(d);continue}const f=r(d,u,Math.abs((s-d[e])/(u[e]-d[e])),i.stepped);f[e]=t[e],a.push(f)}return 1===a.length?a[0]:a}pathSegment(t,e,i){return io(this)(t,this,e,i)}path(t,e,i){const s=this.segments,n=io(this);let o=this._loop;e=e||0,i=i||this.points.length-e;for(const a of s)o&=n(t,this,a,{start:e,end:e+i-1});return!!o}draw(t,e,i,s){const n=this.options||{};(this.points||[]).length&&n.borderWidth&&(t.save(),no(t,this,i,s),t.restore()),this.animated&&(this._pointsUpdated=!1,this._path=void 0)}}function ao(t,e,i,s){const n=t.options,{[i]:o}=t.getProps([i],s);return Math.abs(e-o)<n.radius+n.hitRadius}function ro(t,e){const{x:i,y:s,base:n,width:o,height:a}=t.getProps(["x","y","base","width","height"],e);let r,l,h,c,d;return t.horizontal?(d=a/2,r=Math.min(i,n),l=Math.max(i,n),h=s-d,c=s+d):(d=o/2,r=i-d,l=i+d,h=Math.min(s,n),c=Math.max(s,n)),{left:r,top:h,right:l,bottom:c}}function lo(t,e,i,s){return t?0:Z(e,i,s)}function ho(t){const e=ro(t),i=e.right-e.left,s=e.bottom-e.top,n=function(t,e,i){const s=t.options.borderWidth,n=t.borderSkipped,o=Mi(s);return{t:lo(n.top,o.top,0,i),r:lo(n.right,o.right,0,e),b:lo(n.bottom,o.bottom,0,i),l:lo(n.left,o.left,0,e)}}(t,i/2,s/2),a=function(t,e,i){const{enableBorderRadius:s}=t.getProps(["enableBorderRadius"]),n=t.options.borderRadius,a=wi(n),r=Math.min(e,i),l=t.borderSkipped,h=s||o(n);return{topLeft:lo(!h||l.top||l.left,a.topLeft,0,r),topRight:lo(!h||l.top||l.right,a.topRight,0,r),bottomLeft:lo(!h||l.bottom||l.left,a.bottomLeft,0,r),bottomRight:lo(!h||l.bottom||l.right,a.bottomRight,0,r)}}(t,i/2,s/2);return{outer:{x:e.left,y:e.top,w:i,h:s,radius:a},inner:{x:e.left+n.l,y:e.top+n.t,w:i-n.l-n.r,h:s-n.t-n.b,radius:{topLeft:Math.max(0,a.topLeft-Math.max(n.t,n.l)),topRight:Math.max(0,a.topRight-Math.max(n.t,n.r)),bottomLeft:Math.max(0,a.bottomLeft-Math.max(n.b,n.l)),bottomRight:Math.max(0,a.bottomRight-Math.max(n.b,n.r))}}}}function co(t,e,i,s){const n=null===e,o=null===i,a=t&&!(n&&o)&&ro(t,s);return a&&(n||tt(e,a.left,a.right))&&(o||tt(i,a.top,a.bottom))}function uo(t,e){t.rect(e.x,e.y,e.w,e.h)}function fo(t,e,i={}){const s=t.x!==i.x?-e:0,n=t.y!==i.y?-e:0,o=(t.x+t.w!==i.x+i.w?e:0)-s,a=(t.y+t.h!==i.y+i.h?e:0)-n;return{x:t.x+s,y:t.y+n,w:t.w+o,h:t.h+a,radius:t.radius}}var go=Object.freeze({__proto__:null,ArcElement:class extends $s{static id="arc";static defaults={borderAlign:"center",borderColor:"#fff",borderDash:[],borderDashOffset:0,borderJoinStyle:void 0,borderRadius:0,borderWidth:2,offset:0,spacing:0,angle:void 0,circular:!0,selfJoin:!1};static defaultRoutes={backgroundColor:"backgroundColor"};static descriptors={_scriptable:!0,_indexable:t=>"borderDash"!==t};circumference;endAngle;fullCircles;innerRadius;outerRadius;pixelMargin;startAngle;constructor(t){super(),this.options=void 0,this.circumference=void 0,this.startAngle=void 0,this.endAngle=void 0,this.innerRadius=void 0,this.outerRadius=void 0,this.pixelMargin=0,this.fullCircles=0,t&&Object.assign(this,t)}inRange(t,e,i){const s=this.getProps(["x","y"],i),{angle:n,distance:o}=X(s,{x:t,y:e}),{startAngle:a,endAngle:r,innerRadius:h,outerRadius:c,circumference:d}=this.getProps(["startAngle","endAngle","innerRadius","outerRadius","circumference"],i),u=(this.options.spacing+this.options.borderWidth)/2,f=l(d,r-a),g=J(n,a,r)&&a!==r,p=f>=O||g,m=tt(o,h+u,c+u);return p&&m}getCenterPoint(t){const{x:e,y:i,startAngle:s,endAngle:n,innerRadius:o,outerRadius:a}=this.getProps(["x","y","startAngle","endAngle","innerRadius","outerRadius"],t),{offset:r,spacing:l}=this.options,h=(s+n)/2,c=(o+a+l+r)/2;return{x:e+Math.cos(h)*c,y:i+Math.sin(h)*c}}tooltipPosition(t){return this.getCenterPoint(t)}draw(t){const{options:e,circumference:i}=this,s=(e.offset||0)/4,n=(e.spacing||0)/2,o=e.circular;if(this.pixelMargin="inner"===e.borderAlign?.33:0,this.fullCircles=i>O?Math.floor(i/O):0,0===i||this.innerRadius<0||this.outerRadius<0)return;t.save();const a=(this.startAngle+this.endAngle)/2;t.translate(Math.cos(a)*s,Math.sin(a)*s);const r=s*(1-Math.sin(Math.min(C,i||0)));t.fillStyle=e.backgroundColor,t.strokeStyle=e.borderColor,function(t,e,i,s,n){const{fullCircles:o,startAngle:a,circumference:r}=e;let l=e.endAngle;if(o){Kn(t,e,i,s,l,n);for(let e=0;e<o;++e)t.fill();isNaN(r)||(l=a+(r%O||O))}Kn(t,e,i,s,l,n),t.fill()}(t,this,r,n,o),Gn(t,this,r,n,o),t.restore()}},BarElement:class extends $s{static id="bar";static defaults={borderSkipped:"start",borderWidth:0,borderRadius:0,inflateAmount:"auto",pointStyle:void 0};static defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"};constructor(t){super(),this.options=void 0,this.horizontal=void 0,this.base=void 0,this.width=void 0,this.height=void 0,this.inflateAmount=void 0,t&&Object.assign(this,t)}draw(t){const{inflateAmount:e,options:{borderColor:i,backgroundColor:s}}=this,{inner:n,outer:o}=ho(this),a=(r=o.radius).topLeft||r.topRight||r.bottomLeft||r.bottomRight?He:uo;var r;t.save(),o.w===n.w&&o.h===n.h||(t.beginPath(),a(t,fo(o,e,n)),t.clip(),a(t,fo(n,-e,o)),t.fillStyle=i,t.fill("evenodd")),t.beginPath(),a(t,fo(n,e)),t.fillStyle=s,t.fill(),t.restore()}inRange(t,e,i){return co(this,t,e,i)}inXRange(t,e){return co(this,t,null,e)}inYRange(t,e){return co(this,null,t,e)}getCenterPoint(t){const{x:e,y:i,base:s,horizontal:n}=this.getProps(["x","y","base","horizontal"],t);return{x:n?(e+s)/2:e,y:n?i:(i+s)/2}}getRange(t){return"x"===t?this.width/2:this.height/2}},LineElement:oo,PointElement:class extends $s{static id="point";parsed;skip;stop;static defaults={borderWidth:1,hitRadius:1,hoverBorderWidth:1,hoverRadius:4,pointStyle:"circle",radius:3,rotation:0};static defaultRoutes={backgroundColor:"backgroundColor",borderColor:"borderColor"};constructor(t){super(),this.options=void 0,this.parsed=void 0,this.skip=void 0,this.stop=void 0,t&&Object.assign(this,t)}inRange(t,e,i){const s=this.options,{x:n,y:o}=this.getProps(["x","y"],i);return Math.pow(t-n,2)+Math.pow(e-o,2)<Math.pow(s.hitRadius+s.radius,2)}inXRange(t,e){return ao(this,t,"x",e)}inYRange(t,e){return ao(this,t,"y",e)}getCenterPoint(t){const{x:e,y:i}=this.getProps(["x","y"],t);return{x:e,y:i}}size(t){let e=(t=t||this.options||{}).radius||0;e=Math.max(e,e&&t.hoverRadius||0);return 2*(e+(e&&t.borderWidth||0))}draw(t,e){const i=this.options;this.skip||i.radius<.1||!Re(this,e,this.size(i)/2)||(t.strokeStyle=i.borderColor,t.lineWidth=i.borderWidth,t.fillStyle=i.backgroundColor,Le(t,i,this.x,this.y))}getRange(){const t=this.options||{};return t.radius+t.hitRadius}}});function po(t,e,i,s){const n=t.indexOf(e);if(-1===n)return((t,e,i,s)=>("string"==typeof e?(i=t.push(e)-1,s.unshift({index:i,label:e})):isNaN(e)&&(i=null),i))(t,e,i,s);return n!==t.lastIndexOf(e)?i:n}function mo(t){const e=this.getLabels();return t>=0&&t<e.length?e[t]:t}function xo(t,e,{horizontal:i,minRotation:s}){const n=$(s),o=(i?Math.sin(n):Math.cos(n))||.001,a=.75*e*(""+t).length;return Math.min(e/o,a)}class bo extends tn{constructor(t){super(t),this.start=void 0,this.end=void 0,this._startValue=void 0,this._endValue=void 0,this._valueRange=0}parse(t,e){return s(t)||("number"==typeof t||t instanceof Number)&&!isFinite(+t)?null:+t}handleTickRangeOptions(){const{beginAtZero:t}=this.options,{minDefined:e,maxDefined:i}=this.getUserBounds();let{min:s,max:n}=this;const o=t=>s=e?s:t,a=t=>n=i?n:t;if(t){const t=F(s),e=F(n);t<0&&e<0?a(0):t>0&&e>0&&o(0)}if(s===n){let e=0===n?1:Math.abs(.05*n);a(n+e),t||o(s-e)}this.min=s,this.max=n}getTickLimit(){const t=this.options.ticks;let e,{maxTicksLimit:i,stepSize:s}=t;return s?(e=Math.ceil(this.max/s)-Math.floor(this.min/s)+1,e>1e3&&(console.warn(`scales.${this.id}.ticks.stepSize: ${s} would result generating up to ${e} ticks. Limiting to 1000.`),e=1e3)):(e=this.computeTickLimit(),i=i||11),i&&(e=Math.min(i,e)),e}computeTickLimit(){return Number.POSITIVE_INFINITY}buildTicks(){const t=this.options,e=t.ticks;let i=this.getTickLimit();i=Math.max(2,i);const n=function(t,e){const i=[],{bounds:n,step:o,min:a,max:r,precision:l,count:h,maxTicks:c,maxDigits:d,includeBounds:u}=t,f=o||1,g=c-1,{min:p,max:m}=e,x=!s(a),b=!s(r),_=!s(h),y=(m-p)/(d+1);let v,M,w,k,S=B((m-p)/g/f)*f;if(S<1e-14&&!x&&!b)return[{value:p},{value:m}];k=Math.ceil(m/S)-Math.floor(p/S),k>g&&(S=B(k*S/g/f)*f),s(l)||(v=Math.pow(10,l),S=Math.ceil(S*v)/v),"ticks"===n?(M=Math.floor(p/S)*S,w=Math.ceil(m/S)*S):(M=p,w=m),x&&b&&o&&H((r-a)/o,S/1e3)?(k=Math.round(Math.min((r-a)/S,c)),S=(r-a)/k,M=a,w=r):_?(M=x?a:M,w=b?r:w,k=h-1,S=(w-M)/k):(k=(w-M)/S,k=V(k,Math.round(k),S/1e3)?Math.round(k):Math.ceil(k));const P=Math.max(U(S),U(M));v=Math.pow(10,s(l)?P:l),M=Math.round(M*v)/v,w=Math.round(w*v)/v;let D=0;for(x&&(u&&M!==a?(i.push({value:a}),M<a&&D++,V(Math.round((M+D*S)*v)/v,a,xo(a,y,t))&&D++):M<a&&D++);D<k;++D){const t=Math.round((M+D*S)*v)/v;if(b&&t>r)break;i.push({value:t})}return b&&u&&w!==r?i.length&&V(i[i.length-1].value,r,xo(r,y,t))?i[i.length-1].value=r:i.push({value:r}):b&&w!==r||i.push({value:w}),i}({maxTicks:i,bounds:t.bounds,min:t.min,max:t.max,precision:e.precision,step:e.stepSize,count:e.count,maxDigits:this._maxDigits(),horizontal:this.isHorizontal(),minRotation:e.minRotation||0,includeBounds:!1!==e.includeBounds},this._range||this);return"ticks"===t.bounds&&j(n,this,"value"),t.reverse?(n.reverse(),this.start=this.max,this.end=this.min):(this.start=this.min,this.end=this.max),n}configure(){const t=this.ticks;let e=this.min,i=this.max;if(super.configure(),this.options.offset&&t.length){const s=(i-e)/Math.max(t.length-1,1)/2;e-=s,i+=s}this._startValue=e,this._endValue=i,this._valueRange=i-e}getLabelForValue(t){return ne(t,this.chart.options.locale,this.options.ticks.format)}}class _o extends bo{static id="linear";static defaults={ticks:{callback:ae.formatters.numeric}};determineDataLimits(){const{min:t,max:e}=this.getMinMax(!0);this.min=a(t)?t:0,this.max=a(e)?e:1,this.handleTickRangeOptions()}computeTickLimit(){const t=this.isHorizontal(),e=t?this.width:this.height,i=$(this.options.ticks.minRotation),s=(t?Math.sin(i):Math.cos(i))||.001,n=this._resolveTickFontOptions(0);return Math.ceil(e/Math.min(40,n.lineHeight/s))}getPixelForValue(t){return null===t?NaN:this.getPixelForDecimal((t-this._startValue)/this._valueRange)}getValueForPixel(t){return this._startValue+this.getDecimalForPixel(t)*this._valueRange}}const yo=t=>Math.floor(z(t)),vo=(t,e)=>Math.pow(10,yo(t)+e);function Mo(t){return 1===t/Math.pow(10,yo(t))}function wo(t,e,i){const s=Math.pow(10,i),n=Math.floor(t/s);return Math.ceil(e/s)-n}function ko(t,{min:e,max:i}){e=r(t.min,e);const s=[],n=yo(e);let o=function(t,e){let i=yo(e-t);for(;wo(t,e,i)>10;)i++;for(;wo(t,e,i)<10;)i--;return Math.min(i,yo(t))}(e,i),a=o<0?Math.pow(10,Math.abs(o)):1;const l=Math.pow(10,o),h=n>o?Math.pow(10,n):0,c=Math.round((e-h)*a)/a,d=Math.floor((e-h)/l/10)*l*10;let u=Math.floor((c-d)/Math.pow(10,o)),f=r(t.min,Math.round((h+d+u*Math.pow(10,o))*a)/a);for(;f<i;)s.push({value:f,major:Mo(f),significand:u}),u>=10?u=u<15?15:20:u++,u>=20&&(o++,u=2,a=o>=0?1:a),f=Math.round((h+d+u*Math.pow(10,o))*a)/a;const g=r(t.max,f);return s.push({value:g,major:Mo(g),significand:u}),s}class So extends tn{static id="logarithmic";static defaults={ticks:{callback:ae.formatters.logarithmic,major:{enabled:!0}}};constructor(t){super(t),this.start=void 0,this.end=void 0,this._startValue=void 0,this._valueRange=0}parse(t,e){const i=bo.prototype.parse.apply(this,[t,e]);if(0!==i)return a(i)&&i>0?i:null;this._zero=!0}determineDataLimits(){const{min:t,max:e}=this.getMinMax(!0);this.min=a(t)?Math.max(0,t):null,this.max=a(e)?Math.max(0,e):null,this.options.beginAtZero&&(this._zero=!0),this._zero&&this.min!==this._suggestedMin&&!a(this._userMin)&&(this.min=t===vo(this.min,0)?vo(this.min,-1):vo(this.min,0)),this.handleTickRangeOptions()}handleTickRangeOptions(){const{minDefined:t,maxDefined:e}=this.getUserBounds();let i=this.min,s=this.max;const n=e=>i=t?i:e,o=t=>s=e?s:t;i===s&&(i<=0?(n(1),o(10)):(n(vo(i,-1)),o(vo(s,1)))),i<=0&&n(vo(s,-1)),s<=0&&o(vo(i,1)),this.min=i,this.max=s}buildTicks(){const t=this.options,e=ko({min:this._userMin,max:this._userMax},this);return"ticks"===t.bounds&&j(e,this,"value"),t.reverse?(e.reverse(),this.start=this.max,this.end=this.min):(this.start=this.min,this.end=this.max),e}getLabelForValue(t){return void 0===t?"0":ne(t,this.chart.options.locale,this.options.ticks.format)}configure(){const t=this.min;super.configure(),this._startValue=z(t),this._valueRange=z(this.max)-z(t)}getPixelForValue(t){return void 0!==t&&0!==t||(t=this.min),null===t||isNaN(t)?NaN:this.getPixelForDecimal(t===this.min?0:(z(t)-this._startValue)/this._valueRange)}getValueForPixel(t){const e=this.getDecimalForPixel(t);return Math.pow(10,this._startValue+e*this._valueRange)}}function Po(t){const e=t.ticks;if(e.display&&t.display){const t=ki(e.backdropPadding);return l(e.font&&e.font.size,ue.font.size)+t.height}return 0}function Do(t,e,i,s,n){return t===s||t===n?{start:e-i/2,end:e+i/2}:t<s||t>n?{start:e-i,end:e}:{start:e,end:e+i}}function Co(t){const e={l:t.left+t._padding.left,r:t.right-t._padding.right,t:t.top+t._padding.top,b:t.bottom-t._padding.bottom},i=Object.assign({},e),s=[],o=[],a=t._pointLabels.length,r=t.options.pointLabels,l=r.centerPointLabels?C/a:0;for(let u=0;u<a;u++){const a=r.setContext(t.getPointLabelContext(u));o[u]=a.padding;const f=t.getPointPosition(u,t.drawingArea+o[u],l),g=Si(a.font),p=(h=t.ctx,c=g,d=n(d=t._pointLabels[u])?d:[d],{w:Oe(h,c.string,d),h:d.length*c.lineHeight});s[u]=p;const m=G(t.getIndexAngle(u)+l),x=Math.round(Y(m));Oo(i,e,m,Do(x,f.x,p.w,0,180),Do(x,f.y,p.h,90,270))}var h,c,d;t.setCenterPoint(e.l-i.l,i.r-e.r,e.t-i.t,i.b-e.b),t._pointLabelItems=function(t,e,i){const s=[],n=t._pointLabels.length,o=t.options,{centerPointLabels:a,display:r}=o.pointLabels,l={extra:Po(o)/2,additionalAngle:a?C/n:0};let h;for(let o=0;o<n;o++){l.padding=i[o],l.size=e[o];const n=Ao(t,o,l);s.push(n),"auto"===r&&(n.visible=To(n,h),n.visible&&(h=n))}return s}(t,s,o)}function Oo(t,e,i,s,n){const o=Math.abs(Math.sin(i)),a=Math.abs(Math.cos(i));let r=0,l=0;s.start<e.l?(r=(e.l-s.start)/o,t.l=Math.min(t.l,e.l-r)):s.end>e.r&&(r=(s.end-e.r)/o,t.r=Math.max(t.r,e.r+r)),n.start<e.t?(l=(e.t-n.start)/a,t.t=Math.min(t.t,e.t-l)):n.end>e.b&&(l=(n.end-e.b)/a,t.b=Math.max(t.b,e.b+l))}function Ao(t,e,i){const s=t.drawingArea,{extra:n,additionalAngle:o,padding:a,size:r}=i,l=t.getPointPosition(e,s+n+a,o),h=Math.round(Y(G(l.angle+E))),c=function(t,e,i){90===i||270===i?t-=e/2:(i>270||i<90)&&(t-=e);return t}(l.y,r.h,h),d=function(t){if(0===t||180===t)return"center";if(t<180)return"left";return"right"}(h),u=function(t,e,i){"right"===i?t-=e:"center"===i&&(t-=e/2);return t}(l.x,r.w,d);return{visible:!0,x:l.x,y:c,textAlign:d,left:u,top:c,right:u+r.w,bottom:c+r.h}}function To(t,e){if(!e)return!0;const{left:i,top:s,right:n,bottom:o}=t;return!(Re({x:i,y:s},e)||Re({x:i,y:o},e)||Re({x:n,y:s},e)||Re({x:n,y:o},e))}function Lo(t,e,i){const{left:n,top:o,right:a,bottom:r}=i,{backdropColor:l}=e;if(!s(l)){const i=wi(e.borderRadius),s=ki(e.backdropPadding);t.fillStyle=l;const h=n-s.left,c=o-s.top,d=a-n+s.width,u=r-o+s.height;Object.values(i).some((t=>0!==t))?(t.beginPath(),He(t,{x:h,y:c,w:d,h:u,radius:i}),t.fill()):t.fillRect(h,c,d,u)}}function Eo(t,e,i,s){const{ctx:n}=t;if(i)n.arc(t.xCenter,t.yCenter,e,0,O);else{let i=t.getPointPosition(0,e);n.moveTo(i.x,i.y);for(let o=1;o<s;o++)i=t.getPointPosition(o,e),n.lineTo(i.x,i.y)}}class Ro extends bo{static id="radialLinear";static defaults={display:!0,animate:!0,position:"chartArea",angleLines:{display:!0,lineWidth:1,borderDash:[],borderDashOffset:0},grid:{circular:!1},startAngle:0,ticks:{showLabelBackdrop:!0,callback:ae.formatters.numeric},pointLabels:{backdropColor:void 0,backdropPadding:2,display:!0,font:{size:10},callback:t=>t,padding:5,centerPointLabels:!1}};static defaultRoutes={"angleLines.color":"borderColor","pointLabels.color":"color","ticks.color":"color"};static descriptors={angleLines:{_fallback:"grid"}};constructor(t){super(t),this.xCenter=void 0,this.yCenter=void 0,this.drawingArea=void 0,this._pointLabels=[],this._pointLabelItems=[]}setDimensions(){const t=this._padding=ki(Po(this.options)/2),e=this.width=this.maxWidth-t.width,i=this.height=this.maxHeight-t.height;this.xCenter=Math.floor(this.left+e/2+t.left),this.yCenter=Math.floor(this.top+i/2+t.top),this.drawingArea=Math.floor(Math.min(e,i)/2)}determineDataLimits(){const{min:t,max:e}=this.getMinMax(!1);this.min=a(t)&&!isNaN(t)?t:0,this.max=a(e)&&!isNaN(e)?e:0,this.handleTickRangeOptions()}computeTickLimit(){return Math.ceil(this.drawingArea/Po(this.options))}generateTickLabels(t){bo.prototype.generateTickLabels.call(this,t),this._pointLabels=this.getLabels().map(((t,e)=>{const i=d(this.options.pointLabels.callback,[t,e],this);return i||0===i?i:""})).filter(((t,e)=>this.chart.getDataVisibility(e)))}fit(){const t=this.options;t.display&&t.pointLabels.display?Co(this):this.setCenterPoint(0,0,0,0)}setCenterPoint(t,e,i,s){this.xCenter+=Math.floor((t-e)/2),this.yCenter+=Math.floor((i-s)/2),this.drawingArea-=Math.min(this.drawingArea/2,Math.max(t,e,i,s))}getIndexAngle(t){return G(t*(O/(this._pointLabels.length||1))+$(this.options.startAngle||0))}getDistanceFromCenterForValue(t){if(s(t))return NaN;const e=this.drawingArea/(this.max-this.min);return this.options.reverse?(this.max-t)*e:(t-this.min)*e}getValueForDistanceFromCenter(t){if(s(t))return NaN;const e=t/(this.drawingArea/(this.max-this.min));return this.options.reverse?this.max-e:this.min+e}getPointLabelContext(t){const e=this._pointLabels||[];if(t>=0&&t<e.length){const i=e[t];return function(t,e,i){return Ci(t,{label:i,index:e,type:"pointLabel"})}(this.getContext(),t,i)}}getPointPosition(t,e,i=0){const s=this.getIndexAngle(t)-E+i;return{x:Math.cos(s)*e+this.xCenter,y:Math.sin(s)*e+this.yCenter,angle:s}}getPointPositionForValue(t,e){return this.getPointPosition(t,this.getDistanceFromCenterForValue(e))}getBasePosition(t){return this.getPointPositionForValue(t||0,this.getBaseValue())}getPointLabelPosition(t){const{left:e,top:i,right:s,bottom:n}=this._pointLabelItems[t];return{left:e,top:i,right:s,bottom:n}}drawBackground(){const{backgroundColor:t,grid:{circular:e}}=this.options;if(t){const i=this.ctx;i.save(),i.beginPath(),Eo(this,this.getDistanceFromCenterForValue(this._endValue),e,this._pointLabels.length),i.closePath(),i.fillStyle=t,i.fill(),i.restore()}}drawGrid(){const t=this.ctx,e=this.options,{angleLines:i,grid:s,border:n}=e,o=this._pointLabels.length;let a,r,l;if(e.pointLabels.display&&function(t,e){const{ctx:i,options:{pointLabels:s}}=t;for(let n=e-1;n>=0;n--){const e=t._pointLabelItems[n];if(!e.visible)continue;const o=s.setContext(t.getPointLabelContext(n));Lo(i,o,e);const a=Si(o.font),{x:r,y:l,textAlign:h}=e;Ne(i,t._pointLabels[n],r,l+a.lineHeight/2,a,{color:o.color,textAlign:h,textBaseline:"middle"})}}(this,o),s.display&&this.ticks.forEach(((t,e)=>{if(0!==e||0===e&&this.min<0){r=this.getDistanceFromCenterForValue(t.value);const i=this.getContext(e),a=s.setContext(i),l=n.setContext(i);!function(t,e,i,s,n){const o=t.ctx,a=e.circular,{color:r,lineWidth:l}=e;!a&&!s||!r||!l||i<0||(o.save(),o.strokeStyle=r,o.lineWidth=l,o.setLineDash(n.dash||[]),o.lineDashOffset=n.dashOffset,o.beginPath(),Eo(t,i,a,s),o.closePath(),o.stroke(),o.restore())}(this,a,r,o,l)}})),i.display){for(t.save(),a=o-1;a>=0;a--){const s=i.setContext(this.getPointLabelContext(a)),{color:n,lineWidth:o}=s;o&&n&&(t.lineWidth=o,t.strokeStyle=n,t.setLineDash(s.borderDash),t.lineDashOffset=s.borderDashOffset,r=this.getDistanceFromCenterForValue(e.reverse?this.min:this.max),l=this.getPointPosition(a,r),t.beginPath(),t.moveTo(this.xCenter,this.yCenter),t.lineTo(l.x,l.y),t.stroke())}t.restore()}}drawBorder(){}drawLabels(){const t=this.ctx,e=this.options,i=e.ticks;if(!i.display)return;const s=this.getIndexAngle(0);let n,o;t.save(),t.translate(this.xCenter,this.yCenter),t.rotate(s),t.textAlign="center",t.textBaseline="middle",this.ticks.forEach(((s,a)=>{if(0===a&&this.min>=0&&!e.reverse)return;const r=i.setContext(this.getContext(a)),l=Si(r.font);if(n=this.getDistanceFromCenterForValue(this.ticks[a].value),r.showLabelBackdrop){t.font=l.string,o=t.measureText(s.label).width,t.fillStyle=r.backdropColor;const e=ki(r.backdropPadding);t.fillRect(-o/2-e.left,-n-l.size/2-e.top,o+e.width,l.size+e.height)}Ne(t,s.label,0,-n,l,{color:r.color,strokeColor:r.textStrokeColor,strokeWidth:r.textStrokeWidth})})),t.restore()}drawTitle(){}}const Io={millisecond:{common:!0,size:1,steps:1e3},second:{common:!0,size:1e3,steps:60},minute:{common:!0,size:6e4,steps:60},hour:{common:!0,size:36e5,steps:24},day:{common:!0,size:864e5,steps:30},week:{common:!1,size:6048e5,steps:4},month:{common:!0,size:2628e6,steps:12},quarter:{common:!1,size:7884e6,steps:4},year:{common:!0,size:3154e7}},zo=Object.keys(Io);function Fo(t,e){return t-e}function Vo(t,e){if(s(e))return null;const i=t._adapter,{parser:n,round:o,isoWeekday:r}=t._parseOpts;let l=e;return"function"==typeof n&&(l=n(l)),a(l)||(l="string"==typeof n?i.parse(l,n):i.parse(l)),null===l?null:(o&&(l="week"!==o||!N(r)&&!0!==r?i.startOf(l,o):i.startOf(l,"isoWeek",r)),+l)}function Bo(t,e,i,s){const n=zo.length;for(let o=zo.indexOf(t);o<n-1;++o){const t=Io[zo[o]],n=t.steps?t.steps:Number.MAX_SAFE_INTEGER;if(t.common&&Math.ceil((i-e)/(n*t.size))<=s)return zo[o]}return zo[n-1]}function Wo(t,e,i){if(i){if(i.length){const{lo:s,hi:n}=et(i,e);t[i[s]>=e?i[s]:i[n]]=!0}}else t[e]=!0}function No(t,e,i){const s=[],n={},o=e.length;let a,r;for(a=0;a<o;++a)r=e[a],n[r]=a,s.push({value:r,major:!1});return 0!==o&&i?function(t,e,i,s){const n=t._adapter,o=+n.startOf(e[0].value,s),a=e[e.length-1].value;let r,l;for(r=o;r<=a;r=+n.add(r,1,s))l=i[r],l>=0&&(e[l].major=!0);return e}(t,s,n,i):s}class Ho extends tn{static id="time";static defaults={bounds:"data",adapters:{},time:{parser:!1,unit:!1,round:!1,isoWeekday:!1,minUnit:"millisecond",displayFormats:{}},ticks:{source:"auto",callback:!1,major:{enabled:!1}}};constructor(t){super(t),this._cache={data:[],labels:[],all:[]},this._unit="day",this._majorUnit=void 0,this._offsets={},this._normalized=!1,this._parseOpts=void 0}init(t,e={}){const i=t.time||(t.time={}),s=this._adapter=new In._date(t.adapters.date);s.init(e),b(i.displayFormats,s.formats()),this._parseOpts={parser:i.parser,round:i.round,isoWeekday:i.isoWeekday},super.init(t),this._normalized=e.normalized}parse(t,e){return void 0===t?null:Vo(this,t)}beforeLayout(){super.beforeLayout(),this._cache={data:[],labels:[],all:[]}}determineDataLimits(){const t=this.options,e=this._adapter,i=t.time.unit||"day";let{min:s,max:n,minDefined:o,maxDefined:r}=this.getUserBounds();function l(t){o||isNaN(t.min)||(s=Math.min(s,t.min)),r||isNaN(t.max)||(n=Math.max(n,t.max))}o&&r||(l(this._getLabelBounds()),"ticks"===t.bounds&&"labels"===t.ticks.source||l(this.getMinMax(!1))),s=a(s)&&!isNaN(s)?s:+e.startOf(Date.now(),i),n=a(n)&&!isNaN(n)?n:+e.endOf(Date.now(),i)+1,this.min=Math.min(s,n-1),this.max=Math.max(s+1,n)}_getLabelBounds(){const t=this.getLabelTimestamps();let e=Number.POSITIVE_INFINITY,i=Number.NEGATIVE_INFINITY;return t.length&&(e=t[0],i=t[t.length-1]),{min:e,max:i}}buildTicks(){const t=this.options,e=t.time,i=t.ticks,s="labels"===i.source?this.getLabelTimestamps():this._generate();"ticks"===t.bounds&&s.length&&(this.min=this._userMin||s[0],this.max=this._userMax||s[s.length-1]);const n=this.min,o=nt(s,n,this.max);return this._unit=e.unit||(i.autoSkip?Bo(e.minUnit,this.min,this.max,this._getLabelCapacity(n)):function(t,e,i,s,n){for(let o=zo.length-1;o>=zo.indexOf(i);o--){const i=zo[o];if(Io[i].common&&t._adapter.diff(n,s,i)>=e-1)return i}return zo[i?zo.indexOf(i):0]}(this,o.length,e.minUnit,this.min,this.max)),this._majorUnit=i.major.enabled&&"year"!==this._unit?function(t){for(let e=zo.indexOf(t)+1,i=zo.length;e<i;++e)if(Io[zo[e]].common)return zo[e]}(this._unit):void 0,this.initOffsets(s),t.reverse&&o.reverse(),No(this,o,this._majorUnit)}afterAutoSkip(){this.options.offsetAfterAutoskip&&this.initOffsets(this.ticks.map((t=>+t.value)))}initOffsets(t=[]){let e,i,s=0,n=0;this.options.offset&&t.length&&(e=this.getDecimalForValue(t[0]),s=1===t.length?1-e:(this.getDecimalForValue(t[1])-e)/2,i=this.getDecimalForValue(t[t.length-1]),n=1===t.length?i:(i-this.getDecimalForValue(t[t.length-2]))/2);const o=t.length<3?.5:.25;s=Z(s,0,o),n=Z(n,0,o),this._offsets={start:s,end:n,factor:1/(s+1+n)}}_generate(){const t=this._adapter,e=this.min,i=this.max,s=this.options,n=s.time,o=n.unit||Bo(n.minUnit,e,i,this._getLabelCapacity(e)),a=l(s.ticks.stepSize,1),r="week"===o&&n.isoWeekday,h=N(r)||!0===r,c={};let d,u,f=e;if(h&&(f=+t.startOf(f,"isoWeek",r)),f=+t.startOf(f,h?"day":o),t.diff(i,e,o)>1e5*a)throw new Error(e+" and "+i+" are too far apart with stepSize of "+a+" "+o);const g="data"===s.ticks.source&&this.getDataTimestamps();for(d=f,u=0;d<i;d=+t.add(d,a,o),u++)Wo(c,d,g);return d!==i&&"ticks"!==s.bounds&&1!==u||Wo(c,d,g),Object.keys(c).sort(Fo).map((t=>+t))}getLabelForValue(t){const e=this._adapter,i=this.options.time;return i.tooltipFormat?e.format(t,i.tooltipFormat):e.format(t,i.displayFormats.datetime)}format(t,e){const i=this.options.time.displayFormats,s=this._unit,n=e||i[s];return this._adapter.format(t,n)}_tickFormatFunction(t,e,i,s){const n=this.options,o=n.ticks.callback;if(o)return d(o,[t,e,i],this);const a=n.time.displayFormats,r=this._unit,l=this._majorUnit,h=r&&a[r],c=l&&a[l],u=i[e],f=l&&c&&u&&u.major;return this._adapter.format(t,s||(f?c:h))}generateTickLabels(t){let e,i,s;for(e=0,i=t.length;e<i;++e)s=t[e],s.label=this._tickFormatFunction(s.value,e,t)}getDecimalForValue(t){return null===t?NaN:(t-this.min)/(this.max-this.min)}getPixelForValue(t){const e=this._offsets,i=this.getDecimalForValue(t);return this.getPixelForDecimal((e.start+i)*e.factor)}getValueForPixel(t){const e=this._offsets,i=this.getDecimalForPixel(t)/e.factor-e.end;return this.min+i*(this.max-this.min)}_getLabelSize(t){const e=this.options.ticks,i=this.ctx.measureText(t).width,s=$(this.isHorizontal()?e.maxRotation:e.minRotation),n=Math.cos(s),o=Math.sin(s),a=this._resolveTickFontOptions(0).size;return{w:i*n+a*o,h:i*o+a*n}}_getLabelCapacity(t){const e=this.options.time,i=e.displayFormats,s=i[e.unit]||i.millisecond,n=this._tickFormatFunction(t,0,No(this,[t],this._majorUnit),s),o=this._getLabelSize(n),a=Math.floor(this.isHorizontal()?this.width/o.w:this.height/o.h)-1;return a>0?a:1}getDataTimestamps(){let t,e,i=this._cache.data||[];if(i.length)return i;const s=this.getMatchingVisibleMetas();if(this._normalized&&s.length)return this._cache.data=s[0].controller.getAllParsedValues(this);for(t=0,e=s.length;t<e;++t)i=i.concat(s[t].controller.getAllParsedValues(this));return this._cache.data=this.normalize(i)}getLabelTimestamps(){const t=this._cache.labels||[];let e,i;if(t.length)return t;const s=this.getLabels();for(e=0,i=s.length;e<i;++e)t.push(Vo(this,s[e]));return this._cache.labels=this._normalized?t:this.normalize(t)}normalize(t){return lt(t.sort(Fo))}}function jo(t,e,i){let s,n,o,a,r=0,l=t.length-1;i?(e>=t[r].pos&&e<=t[l].pos&&({lo:r,hi:l}=it(t,"pos",e)),({pos:s,time:o}=t[r]),({pos:n,time:a}=t[l])):(e>=t[r].time&&e<=t[l].time&&({lo:r,hi:l}=it(t,"time",e)),({time:s,pos:o}=t[r]),({time:n,pos:a}=t[l]));const h=n-s;return h?o+(a-o)*(e-s)/h:o}var $o=Object.freeze({__proto__:null,CategoryScale:class extends tn{static id="category";static defaults={ticks:{callback:mo}};constructor(t){super(t),this._startValue=void 0,this._valueRange=0,this._addedLabels=[]}init(t){const e=this._addedLabels;if(e.length){const t=this.getLabels();for(const{index:i,label:s}of e)t[i]===s&&t.splice(i,1);this._addedLabels=[]}super.init(t)}parse(t,e){if(s(t))return null;const i=this.getLabels();return((t,e)=>null===t?null:Z(Math.round(t),0,e))(e=isFinite(e)&&i[e]===t?e:po(i,t,l(e,t),this._addedLabels),i.length-1)}determineDataLimits(){const{minDefined:t,maxDefined:e}=this.getUserBounds();let{min:i,max:s}=this.getMinMax(!0);"ticks"===this.options.bounds&&(t||(i=0),e||(s=this.getLabels().length-1)),this.min=i,this.max=s}buildTicks(){const t=this.min,e=this.max,i=this.options.offset,s=[];let n=this.getLabels();n=0===t&&e===n.length-1?n:n.slice(t,e+1),this._valueRange=Math.max(n.length-(i?0:1),1),this._startValue=this.min-(i?.5:0);for(let i=t;i<=e;i++)s.push({value:i});return s}getLabelForValue(t){return mo.call(this,t)}configure(){super.configure(),this.isHorizontal()||(this._reversePixels=!this._reversePixels)}getPixelForValue(t){return"number"!=typeof t&&(t=this.parse(t)),null===t?NaN:this.getPixelForDecimal((t-this._startValue)/this._valueRange)}getPixelForTick(t){const e=this.ticks;return t<0||t>e.length-1?null:this.getPixelForValue(e[t].value)}getValueForPixel(t){return Math.round(this._startValue+this.getDecimalForPixel(t)*this._valueRange)}getBasePixel(){return this.bottom}},LinearScale:_o,LogarithmicScale:So,RadialLinearScale:Ro,TimeScale:Ho,TimeSeriesScale:class extends Ho{static id="timeseries";static defaults=Ho.defaults;constructor(t){super(t),this._table=[],this._minPos=void 0,this._tableRange=void 0}initOffsets(){const t=this._getTimestampsForTable(),e=this._table=this.buildLookupTable(t);this._minPos=jo(e,this.min),this._tableRange=jo(e,this.max)-this._minPos,super.initOffsets(t)}buildLookupTable(t){const{min:e,max:i}=this,s=[],n=[];let o,a,r,l,h;for(o=0,a=t.length;o<a;++o)l=t[o],l>=e&&l<=i&&s.push(l);if(s.length<2)return[{time:e,pos:0},{time:i,pos:1}];for(o=0,a=s.length;o<a;++o)h=s[o+1],r=s[o-1],l=s[o],Math.round((h+r)/2)!==l&&n.push({time:l,pos:o/(a-1)});return n}_generate(){const t=this.min,e=this.max;let i=super.getDataTimestamps();return i.includes(t)&&i.length||i.splice(0,0,t),i.includes(e)&&1!==i.length||i.push(e),i.sort(((t,e)=>t-e))}_getTimestampsForTable(){let t=this._cache.all||[];if(t.length)return t;const e=this.getDataTimestamps(),i=this.getLabelTimestamps();return t=e.length&&i.length?this.normalize(e.concat(i)):e.length?e:i,t=this._cache.all=t,t}getDecimalForValue(t){return(jo(this._table,t)-this._minPos)/this._tableRange}getValueForPixel(t){const e=this._offsets,i=this.getDecimalForPixel(t)/e.factor-e.end;return jo(this._table,i*this._tableRange+this._minPos,!0)}}});const Yo=["rgb(54, 162, 235)","rgb(255, 99, 132)","rgb(255, 159, 64)","rgb(255, 205, 86)","rgb(75, 192, 192)","rgb(153, 102, 255)","rgb(201, 203, 207)"],Uo=Yo.map((t=>t.replace("rgb(","rgba(").replace(")",", 0.5)")));function Xo(t){return Yo[t%Yo.length]}function qo(t){return Uo[t%Uo.length]}function Ko(t){let e=0;return(i,s)=>{const n=t.getDatasetMeta(s).controller;n instanceof $n?e=function(t,e){return t.backgroundColor=t.data.map((()=>Xo(e++))),e}(i,e):n instanceof Yn?e=function(t,e){return t.backgroundColor=t.data.map((()=>qo(e++))),e}(i,e):n&&(e=function(t,e){return t.borderColor=Xo(e),t.backgroundColor=qo(e),++e}(i,e))}}function Go(t){let e;for(e in t)if(t[e].borderColor||t[e].backgroundColor)return!0;return!1}var Jo={id:"colors",defaults:{enabled:!0,forceOverride:!1},beforeLayout(t,e,i){if(!i.enabled)return;const{data:{datasets:s},options:n}=t.config,{elements:o}=n,a=Go(s)||(r=n)&&(r.borderColor||r.backgroundColor)||o&&Go(o)||"rgba(0,0,0,0.1)"!==ue.borderColor||"rgba(0,0,0,0.1)"!==ue.backgroundColor;var r;if(!i.forceOverride&&a)return;const l=Ko(t);s.forEach(l)}};function Zo(t){if(t._decimated){const e=t._data;delete t._decimated,delete t._data,Object.defineProperty(t,"data",{configurable:!0,enumerable:!0,writable:!0,value:e})}}function Qo(t){t.data.datasets.forEach((t=>{Zo(t)}))}var ta={id:"decimation",defaults:{algorithm:"min-max",enabled:!1},beforeElementsUpdate:(t,e,i)=>{if(!i.enabled)return void Qo(t);const n=t.width;t.data.datasets.forEach(((e,o)=>{const{_data:a,indexAxis:r}=e,l=t.getDatasetMeta(o),h=a||e.data;if("y"===Pi([r,t.options.indexAxis]))return;if(!l.controller.supportsDecimation)return;const c=t.scales[l.xAxisID];if("linear"!==c.type&&"time"!==c.type)return;if(t.options.parsing)return;let{start:d,count:u}=function(t,e){const i=e.length;let s,n=0;const{iScale:o}=t,{min:a,max:r,minDefined:l,maxDefined:h}=o.getUserBounds();return l&&(n=Z(it(e,o.axis,a).lo,0,i-1)),s=h?Z(it(e,o.axis,r).hi+1,n,i)-n:i-n,{start:n,count:s}}(l,h);if(u<=(i.threshold||4*n))return void Zo(e);let f;switch(s(a)&&(e._data=h,delete e.data,Object.defineProperty(e,"data",{configurable:!0,enumerable:!0,get:function(){return this._decimated},set:function(t){this._data=t}})),i.algorithm){case"lttb":f=function(t,e,i,s,n){const o=n.samples||s;if(o>=i)return t.slice(e,e+i);const a=[],r=(i-2)/(o-2);let l=0;const h=e+i-1;let c,d,u,f,g,p=e;for(a[l++]=t[p],c=0;c<o-2;c++){let s,n=0,o=0;const h=Math.floor((c+1)*r)+1+e,m=Math.min(Math.floor((c+2)*r)+1,i)+e,x=m-h;for(s=h;s<m;s++)n+=t[s].x,o+=t[s].y;n/=x,o/=x;const b=Math.floor(c*r)+1+e,_=Math.min(Math.floor((c+1)*r)+1,i)+e,{x:y,y:v}=t[p];for(u=f=-1,s=b;s<_;s++)f=.5*Math.abs((y-n)*(t[s].y-v)-(y-t[s].x)*(o-v)),f>u&&(u=f,d=t[s],g=s);a[l++]=d,p=g}return a[l++]=t[h],a}(h,d,u,n,i);break;case"min-max":f=function(t,e,i,n){let o,a,r,l,h,c,d,u,f,g,p=0,m=0;const x=[],b=e+i-1,_=t[e].x,y=t[b].x-_;for(o=e;o<e+i;++o){a=t[o],r=(a.x-_)/y*n,l=a.y;const e=0|r;if(e===h)l<f?(f=l,c=o):l>g&&(g=l,d=o),p=(m*p+a.x)/++m;else{const i=o-1;if(!s(c)&&!s(d)){const e=Math.min(c,d),s=Math.max(c,d);e!==u&&e!==i&&x.push({...t[e],x:p}),s!==u&&s!==i&&x.push({...t[s],x:p})}o>0&&i!==u&&x.push(t[i]),x.push(a),h=e,m=0,f=g=l,c=d=u=o}}return x}(h,d,u,n);break;default:throw new Error(`Unsupported decimation algorithm '${i.algorithm}'`)}e._decimated=f}))},destroy(t){Qo(t)}};function ea(t,e,i,s){if(s)return;let n=e[t],o=i[t];return"angle"===t&&(n=G(n),o=G(o)),{property:t,start:n,end:o}}function ia(t,e,i){for(;e>t;e--){const t=i[e];if(!isNaN(t.x)&&!isNaN(t.y))break}return e}function sa(t,e,i,s){return t&&e?s(t[i],e[i]):t?t[i]:e?e[i]:0}function na(t,e){let i=[],s=!1;return n(t)?(s=!0,i=t):i=function(t,e){const{x:i=null,y:s=null}=t||{},n=e.points,o=[];return e.segments.forEach((({start:t,end:e})=>{e=ia(t,e,n);const a=n[t],r=n[e];null!==s?(o.push({x:a.x,y:s}),o.push({x:r.x,y:s})):null!==i&&(o.push({x:i,y:a.y}),o.push({x:i,y:r.y}))})),o}(t,e),i.length?new oo({points:i,options:{tension:0},_loop:s,_fullLoop:s}):null}function oa(t){return t&&!1!==t.fill}function aa(t,e,i){let s=t[e].fill;const n=[e];let o;if(!i)return s;for(;!1!==s&&-1===n.indexOf(s);){if(!a(s))return s;if(o=t[s],!o)return!1;if(o.visible)return s;n.push(s),s=o.fill}return!1}function ra(t,e,i){const s=function(t){const e=t.options,i=e.fill;let s=l(i&&i.target,i);void 0===s&&(s=!!e.backgroundColor);if(!1===s||null===s)return!1;if(!0===s)return"origin";return s}(t);if(o(s))return!isNaN(s.value)&&s;let n=parseFloat(s);return a(n)&&Math.floor(n)===n?function(t,e,i,s){"-"!==t&&"+"!==t||(i=e+i);if(i===e||i<0||i>=s)return!1;return i}(s[0],e,n,i):["origin","start","end","stack","shape"].indexOf(s)>=0&&s}function la(t,e,i){const s=[];for(let n=0;n<i.length;n++){const o=i[n],{first:a,last:r,point:l}=ha(o,e,"x");if(!(!l||a&&r))if(a)s.unshift(l);else if(t.push(l),!r)break}t.push(...s)}function ha(t,e,i){const s=t.interpolate(e,i);if(!s)return{};const n=s[i],o=t.segments,a=t.points;let r=!1,l=!1;for(let t=0;t<o.length;t++){const e=o[t],s=a[e.start][i],h=a[e.end][i];if(tt(n,s,h)){r=n===s,l=n===h;break}}return{first:r,last:l,point:s}}class ca{constructor(t){this.x=t.x,this.y=t.y,this.radius=t.radius}pathSegment(t,e,i){const{x:s,y:n,radius:o}=this;return e=e||{start:0,end:O},t.arc(s,n,o,e.end,e.start,!0),!i.bounds}interpolate(t){const{x:e,y:i,radius:s}=this,n=t.angle;return{x:e+Math.cos(n)*s,y:i+Math.sin(n)*s,angle:n}}}function da(t){const{chart:e,fill:i,line:s}=t;if(a(i))return function(t,e){const i=t.getDatasetMeta(e),s=i&&t.isDatasetVisible(e);return s?i.dataset:null}(e,i);if("stack"===i)return function(t){const{scale:e,index:i,line:s}=t,n=[],o=s.segments,a=s.points,r=function(t,e){const i=[],s=t.getMatchingVisibleMetas("line");for(let t=0;t<s.length;t++){const n=s[t];if(n.index===e)break;n.hidden||i.unshift(n.dataset)}return i}(e,i);r.push(na({x:null,y:e.bottom},s));for(let t=0;t<o.length;t++){const e=o[t];for(let t=e.start;t<=e.end;t++)la(n,a[t],r)}return new oo({points:n,options:{}})}(t);if("shape"===i)return!0;const n=function(t){const e=t.scale||{};if(e.getPointPositionForValue)return function(t){const{scale:e,fill:i}=t,s=e.options,n=e.getLabels().length,a=s.reverse?e.max:e.min,r=function(t,e,i){let s;return s="start"===t?i:"end"===t?e.options.reverse?e.min:e.max:o(t)?t.value:e.getBaseValue(),s}(i,e,a),l=[];if(s.grid.circular){const t=e.getPointPositionForValue(0,a);return new ca({x:t.x,y:t.y,radius:e.getDistanceFromCenterForValue(r)})}for(let t=0;t<n;++t)l.push(e.getPointPositionForValue(t,r));return l}(t);return function(t){const{scale:e={},fill:i}=t,s=function(t,e){let i=null;return"start"===t?i=e.bottom:"end"===t?i=e.top:o(t)?i=e.getPixelForValue(t.value):e.getBasePixel&&(i=e.getBasePixel()),i}(i,e);if(a(s)){const t=e.isHorizontal();return{x:t?s:null,y:t?null:s}}return null}(t)}(t);return n instanceof ca?n:na(n,s)}function ua(t,e,i){const s=da(e),{chart:n,index:o,line:a,scale:r,axis:l}=e,h=a.options,c=h.fill,d=h.backgroundColor,{above:u=d,below:f=d}=c||{},g=n.getDatasetMeta(o),p=Ni(n,g);s&&a.points.length&&(Ie(t,i),function(t,e){const{line:i,target:s,above:n,below:o,area:a,scale:r,clip:l}=e,h=i._loop?"angle":e.axis;t.save();let c=o;o!==n&&("x"===h?(fa(t,s,a.top),pa(t,{line:i,target:s,color:n,scale:r,property:h,clip:l}),t.restore(),t.save(),fa(t,s,a.bottom)):"y"===h&&(ga(t,s,a.left),pa(t,{line:i,target:s,color:o,scale:r,property:h,clip:l}),t.restore(),t.save(),ga(t,s,a.right),c=n));pa(t,{line:i,target:s,color:c,scale:r,property:h,clip:l}),t.restore()}(t,{line:a,target:s,above:u,below:f,area:i,scale:r,axis:l,clip:p}),ze(t))}function fa(t,e,i){const{segments:s,points:n}=e;let o=!0,a=!1;t.beginPath();for(const r of s){const{start:s,end:l}=r,h=n[s],c=n[ia(s,l,n)];o?(t.moveTo(h.x,h.y),o=!1):(t.lineTo(h.x,i),t.lineTo(h.x,h.y)),a=!!e.pathSegment(t,r,{move:a}),a?t.closePath():t.lineTo(c.x,i)}t.lineTo(e.first().x,i),t.closePath(),t.clip()}function ga(t,e,i){const{segments:s,points:n}=e;let o=!0,a=!1;t.beginPath();for(const r of s){const{start:s,end:l}=r,h=n[s],c=n[ia(s,l,n)];o?(t.moveTo(h.x,h.y),o=!1):(t.lineTo(i,h.y),t.lineTo(h.x,h.y)),a=!!e.pathSegment(t,r,{move:a}),a?t.closePath():t.lineTo(i,c.y)}t.lineTo(i,e.first().y),t.closePath(),t.clip()}function pa(t,e){const{line:i,target:s,property:n,color:o,scale:a,clip:r}=e,l=function(t,e,i){const s=t.segments,n=t.points,o=e.points,a=[];for(const t of s){let{start:s,end:r}=t;r=ia(s,r,n);const l=ea(i,n[s],n[r],t.loop);if(!e.segments){a.push({source:t,target:l,start:n[s],end:n[r]});continue}const h=Ii(e,l);for(const e of h){const s=ea(i,o[e.start],o[e.end],e.loop),r=Ri(t,n,s);for(const t of r)a.push({source:t,target:e,start:{[i]:sa(l,s,"start",Math.max)},end:{[i]:sa(l,s,"end",Math.min)}})}}return a}(i,s,n);for(const{source:e,target:h,start:c,end:d}of l){const{style:{backgroundColor:l=o}={}}=e,u=!0!==s;t.save(),t.fillStyle=l,ma(t,a,r,u&&ea(n,c,d)),t.beginPath();const f=!!i.pathSegment(t,e);let g;if(u){f?t.closePath():xa(t,s,d,n);const e=!!s.pathSegment(t,h,{move:f,reverse:!0});g=f&&e,g||xa(t,s,c,n)}t.closePath(),t.fill(g?"evenodd":"nonzero"),t.restore()}}function ma(t,e,i,s){const n=e.chart.chartArea,{property:o,start:a,end:r}=s||{};if("x"===o||"y"===o){let e,s,l,h;"x"===o?(e=a,s=n.top,l=r,h=n.bottom):(e=n.left,s=a,l=n.right,h=r),t.beginPath(),i&&(e=Math.max(e,i.left),l=Math.min(l,i.right),s=Math.max(s,i.top),h=Math.min(h,i.bottom)),t.rect(e,s,l-e,h-s),t.clip()}}function xa(t,e,i,s){const n=e.interpolate(i,s);n&&t.lineTo(n.x,n.y)}var ba={id:"filler",afterDatasetsUpdate(t,e,i){const s=(t.data.datasets||[]).length,n=[];let o,a,r,l;for(a=0;a<s;++a)o=t.getDatasetMeta(a),r=o.dataset,l=null,r&&r.options&&r instanceof oo&&(l={visible:t.isDatasetVisible(a),index:a,fill:ra(r,a,s),chart:t,axis:o.controller.options.indexAxis,scale:o.vScale,line:r}),o.$filler=l,n.push(l);for(a=0;a<s;++a)l=n[a],l&&!1!==l.fill&&(l.fill=aa(n,a,i.propagate))},beforeDraw(t,e,i){const s="beforeDraw"===i.drawTime,n=t.getSortedVisibleDatasetMetas(),o=t.chartArea;for(let e=n.length-1;e>=0;--e){const i=n[e].$filler;i&&(i.line.updateControlPoints(o,i.axis),s&&i.fill&&ua(t.ctx,i,o))}},beforeDatasetsDraw(t,e,i){if("beforeDatasetsDraw"!==i.drawTime)return;const s=t.getSortedVisibleDatasetMetas();for(let e=s.length-1;e>=0;--e){const i=s[e].$filler;oa(i)&&ua(t.ctx,i,t.chartArea)}},beforeDatasetDraw(t,e,i){const s=e.meta.$filler;oa(s)&&"beforeDatasetDraw"===i.drawTime&&ua(t.ctx,s,t.chartArea)},defaults:{propagate:!0,drawTime:"beforeDatasetDraw"}};const _a=(t,e)=>{let{boxHeight:i=e,boxWidth:s=e}=t;return t.usePointStyle&&(i=Math.min(i,e),s=t.pointStyleWidth||Math.min(s,e)),{boxWidth:s,boxHeight:i,itemHeight:Math.max(e,i)}};class ya extends $s{constructor(t){super(),this._added=!1,this.legendHitBoxes=[],this._hoveredItem=null,this.doughnutMode=!1,this.chart=t.chart,this.options=t.options,this.ctx=t.ctx,this.legendItems=void 0,this.columnSizes=void 0,this.lineWidths=void 0,this.maxHeight=void 0,this.maxWidth=void 0,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.height=void 0,this.width=void 0,this._margins=void 0,this.position=void 0,this.weight=void 0,this.fullSize=void 0}update(t,e,i){this.maxWidth=t,this.maxHeight=e,this._margins=i,this.setDimensions(),this.buildLabels(),this.fit()}setDimensions(){this.isHorizontal()?(this.width=this.maxWidth,this.left=this._margins.left,this.right=this.width):(this.height=this.maxHeight,this.top=this._margins.top,this.bottom=this.height)}buildLabels(){const t=this.options.labels||{};let e=d(t.generateLabels,[this.chart],this)||[];t.filter&&(e=e.filter((e=>t.filter(e,this.chart.data)))),t.sort&&(e=e.sort(((e,i)=>t.sort(e,i,this.chart.data)))),this.options.reverse&&e.reverse(),this.legendItems=e}fit(){const{options:t,ctx:e}=this;if(!t.display)return void(this.width=this.height=0);const i=t.labels,s=Si(i.font),n=s.size,o=this._computeTitleHeight(),{boxWidth:a,itemHeight:r}=_a(i,n);let l,h;e.font=s.string,this.isHorizontal()?(l=this.maxWidth,h=this._fitRows(o,n,a,r)+10):(h=this.maxHeight,l=this._fitCols(o,s,a,r)+10),this.width=Math.min(l,t.maxWidth||this.maxWidth),this.height=Math.min(h,t.maxHeight||this.maxHeight)}_fitRows(t,e,i,s){const{ctx:n,maxWidth:o,options:{labels:{padding:a}}}=this,r=this.legendHitBoxes=[],l=this.lineWidths=[0],h=s+a;let c=t;n.textAlign="left",n.textBaseline="middle";let d=-1,u=-h;return this.legendItems.forEach(((t,f)=>{const g=i+e/2+n.measureText(t.text).width;(0===f||l[l.length-1]+g+2*a>o)&&(c+=h,l[l.length-(f>0?0:1)]=0,u+=h,d++),r[f]={left:0,top:u,row:d,width:g,height:s},l[l.length-1]+=g+a})),c}_fitCols(t,e,i,s){const{ctx:n,maxHeight:o,options:{labels:{padding:a}}}=this,r=this.legendHitBoxes=[],l=this.columnSizes=[],h=o-t;let c=a,d=0,u=0,f=0,g=0;return this.legendItems.forEach(((t,o)=>{const{itemWidth:p,itemHeight:m}=function(t,e,i,s,n){const o=function(t,e,i,s){let n=t.text;n&&"string"!=typeof n&&(n=n.reduce(((t,e)=>t.length>e.length?t:e)));return e+i.size/2+s.measureText(n).width}(s,t,e,i),a=function(t,e,i){let s=t;"string"!=typeof e.text&&(s=va(e,i));return s}(n,s,e.lineHeight);return{itemWidth:o,itemHeight:a}}(i,e,n,t,s);o>0&&u+m+2*a>h&&(c+=d+a,l.push({width:d,height:u}),f+=d+a,g++,d=u=0),r[o]={left:f,top:u,col:g,width:p,height:m},d=Math.max(d,p),u+=m+a})),c+=d,l.push({width:d,height:u}),c}adjustHitBoxes(){if(!this.options.display)return;const t=this._computeTitleHeight(),{legendHitBoxes:e,options:{align:i,labels:{padding:s},rtl:n}}=this,o=Oi(n,this.left,this.width);if(this.isHorizontal()){let n=0,a=ft(i,this.left+s,this.right-this.lineWidths[n]);for(const r of e)n!==r.row&&(n=r.row,a=ft(i,this.left+s,this.right-this.lineWidths[n])),r.top+=this.top+t+s,r.left=o.leftForLtr(o.x(a),r.width),a+=r.width+s}else{let n=0,a=ft(i,this.top+t+s,this.bottom-this.columnSizes[n].height);for(const r of e)r.col!==n&&(n=r.col,a=ft(i,this.top+t+s,this.bottom-this.columnSizes[n].height)),r.top=a,r.left+=this.left+s,r.left=o.leftForLtr(o.x(r.left),r.width),a+=r.height+s}}isHorizontal(){return"top"===this.options.position||"bottom"===this.options.position}draw(){if(this.options.display){const t=this.ctx;Ie(t,this),this._draw(),ze(t)}}_draw(){const{options:t,columnSizes:e,lineWidths:i,ctx:s}=this,{align:n,labels:o}=t,a=ue.color,r=Oi(t.rtl,this.left,this.width),h=Si(o.font),{padding:c}=o,d=h.size,u=d/2;let f;this.drawTitle(),s.textAlign=r.textAlign("left"),s.textBaseline="middle",s.lineWidth=.5,s.font=h.string;const{boxWidth:g,boxHeight:p,itemHeight:m}=_a(o,d),x=this.isHorizontal(),b=this._computeTitleHeight();f=x?{x:ft(n,this.left+c,this.right-i[0]),y:this.top+c+b,line:0}:{x:this.left+c,y:ft(n,this.top+b+c,this.bottom-e[0].height),line:0},Ai(this.ctx,t.textDirection);const _=m+c;this.legendItems.forEach(((y,v)=>{s.strokeStyle=y.fontColor,s.fillStyle=y.fontColor;const M=s.measureText(y.text).width,w=r.textAlign(y.textAlign||(y.textAlign=o.textAlign)),k=g+u+M;let S=f.x,P=f.y;r.setWidth(this.width),x?v>0&&S+k+c>this.right&&(P=f.y+=_,f.line++,S=f.x=ft(n,this.left+c,this.right-i[f.line])):v>0&&P+_>this.bottom&&(S=f.x=S+e[f.line].width+c,f.line++,P=f.y=ft(n,this.top+b+c,this.bottom-e[f.line].height));if(function(t,e,i){if(isNaN(g)||g<=0||isNaN(p)||p<0)return;s.save();const n=l(i.lineWidth,1);if(s.fillStyle=l(i.fillStyle,a),s.lineCap=l(i.lineCap,"butt"),s.lineDashOffset=l(i.lineDashOffset,0),s.lineJoin=l(i.lineJoin,"miter"),s.lineWidth=n,s.strokeStyle=l(i.strokeStyle,a),s.setLineDash(l(i.lineDash,[])),o.usePointStyle){const a={radius:p*Math.SQRT2/2,pointStyle:i.pointStyle,rotation:i.rotation,borderWidth:n},l=r.xPlus(t,g/2);Ee(s,a,l,e+u,o.pointStyleWidth&&g)}else{const o=e+Math.max((d-p)/2,0),a=r.leftForLtr(t,g),l=wi(i.borderRadius);s.beginPath(),Object.values(l).some((t=>0!==t))?He(s,{x:a,y:o,w:g,h:p,radius:l}):s.rect(a,o,g,p),s.fill(),0!==n&&s.stroke()}s.restore()}(r.x(S),P,y),S=gt(w,S+g+u,x?S+k:this.right,t.rtl),function(t,e,i){Ne(s,i.text,t,e+m/2,h,{strikethrough:i.hidden,textAlign:r.textAlign(i.textAlign)})}(r.x(S),P,y),x)f.x+=k+c;else if("string"!=typeof y.text){const t=h.lineHeight;f.y+=va(y,t)+c}else f.y+=_})),Ti(this.ctx,t.textDirection)}drawTitle(){const t=this.options,e=t.title,i=Si(e.font),s=ki(e.padding);if(!e.display)return;const n=Oi(t.rtl,this.left,this.width),o=this.ctx,a=e.position,r=i.size/2,l=s.top+r;let h,c=this.left,d=this.width;if(this.isHorizontal())d=Math.max(...this.lineWidths),h=this.top+l,c=ft(t.align,c,this.right-d);else{const e=this.columnSizes.reduce(((t,e)=>Math.max(t,e.height)),0);h=l+ft(t.align,this.top,this.bottom-e-t.labels.padding-this._computeTitleHeight())}const u=ft(a,c,c+d);o.textAlign=n.textAlign(ut(a)),o.textBaseline="middle",o.strokeStyle=e.color,o.fillStyle=e.color,o.font=i.string,Ne(o,e.text,u,h,i)}_computeTitleHeight(){const t=this.options.title,e=Si(t.font),i=ki(t.padding);return t.display?e.lineHeight+i.height:0}_getLegendItemAt(t,e){let i,s,n;if(tt(t,this.left,this.right)&&tt(e,this.top,this.bottom))for(n=this.legendHitBoxes,i=0;i<n.length;++i)if(s=n[i],tt(t,s.left,s.left+s.width)&&tt(e,s.top,s.top+s.height))return this.legendItems[i];return null}handleEvent(t){const e=this.options;if(!function(t,e){if(("mousemove"===t||"mouseout"===t)&&(e.onHover||e.onLeave))return!0;if(e.onClick&&("click"===t||"mouseup"===t))return!0;return!1}(t.type,e))return;const i=this._getLegendItemAt(t.x,t.y);if("mousemove"===t.type||"mouseout"===t.type){const o=this._hoveredItem,a=(n=i,null!==(s=o)&&null!==n&&s.datasetIndex===n.datasetIndex&&s.index===n.index);o&&!a&&d(e.onLeave,[t,o,this],this),this._hoveredItem=i,i&&!a&&d(e.onHover,[t,i,this],this)}else i&&d(e.onClick,[t,i,this],this);var s,n}}function va(t,e){return e*(t.text?t.text.length:0)}var Ma={id:"legend",_element:ya,start(t,e,i){const s=t.legend=new ya({ctx:t.ctx,options:i,chart:t});ls.configure(t,s,i),ls.addBox(t,s)},stop(t){ls.removeBox(t,t.legend),delete t.legend},beforeUpdate(t,e,i){const s=t.legend;ls.configure(t,s,i),s.options=i},afterUpdate(t){const e=t.legend;e.buildLabels(),e.adjustHitBoxes()},afterEvent(t,e){e.replay||t.legend.handleEvent(e.event)},defaults:{display:!0,position:"top",align:"center",fullSize:!0,reverse:!1,weight:1e3,onClick(t,e,i){const s=e.datasetIndex,n=i.chart;n.isDatasetVisible(s)?(n.hide(s),e.hidden=!0):(n.show(s),e.hidden=!1)},onHover:null,onLeave:null,labels:{color:t=>t.chart.options.color,boxWidth:40,padding:10,generateLabels(t){const e=t.data.datasets,{labels:{usePointStyle:i,pointStyle:s,textAlign:n,color:o,useBorderRadius:a,borderRadius:r}}=t.legend.options;return t._getSortedDatasetMetas().map((t=>{const l=t.controller.getStyle(i?0:void 0),h=ki(l.borderWidth);return{text:e[t.index].label,fillStyle:l.backgroundColor,fontColor:o,hidden:!t.visible,lineCap:l.borderCapStyle,lineDash:l.borderDash,lineDashOffset:l.borderDashOffset,lineJoin:l.borderJoinStyle,lineWidth:(h.width+h.height)/4,strokeStyle:l.borderColor,pointStyle:s||l.pointStyle,rotation:l.rotation,textAlign:n||l.textAlign,borderRadius:a&&(r||l.borderRadius),datasetIndex:t.index}}),this)}},title:{color:t=>t.chart.options.color,display:!1,position:"center",text:""}},descriptors:{_scriptable:t=>!t.startsWith("on"),labels:{_scriptable:t=>!["generateLabels","filter","sort"].includes(t)}}};class wa extends $s{constructor(t){super(),this.chart=t.chart,this.options=t.options,this.ctx=t.ctx,this._padding=void 0,this.top=void 0,this.bottom=void 0,this.left=void 0,this.right=void 0,this.width=void 0,this.height=void 0,this.position=void 0,this.weight=void 0,this.fullSize=void 0}update(t,e){const i=this.options;if(this.left=0,this.top=0,!i.display)return void(this.width=this.height=this.right=this.bottom=0);this.width=this.right=t,this.height=this.bottom=e;const s=n(i.text)?i.text.length:1;this._padding=ki(i.padding);const o=s*Si(i.font).lineHeight+this._padding.height;this.isHorizontal()?this.height=o:this.width=o}isHorizontal(){const t=this.options.position;return"top"===t||"bottom"===t}_drawArgs(t){const{top:e,left:i,bottom:s,right:n,options:o}=this,a=o.align;let r,l,h,c=0;return this.isHorizontal()?(l=ft(a,i,n),h=e+t,r=n-i):("left"===o.position?(l=i+t,h=ft(a,s,e),c=-.5*C):(l=n-t,h=ft(a,e,s),c=.5*C),r=s-e),{titleX:l,titleY:h,maxWidth:r,rotation:c}}draw(){const t=this.ctx,e=this.options;if(!e.display)return;const i=Si(e.font),s=i.lineHeight/2+this._padding.top,{titleX:n,titleY:o,maxWidth:a,rotation:r}=this._drawArgs(s);Ne(t,e.text,0,0,i,{color:e.color,maxWidth:a,rotation:r,textAlign:ut(e.align),textBaseline:"middle",translation:[n,o]})}}var ka={id:"title",_element:wa,start(t,e,i){!function(t,e){const i=new wa({ctx:t.ctx,options:e,chart:t});ls.configure(t,i,e),ls.addBox(t,i),t.titleBlock=i}(t,i)},stop(t){const e=t.titleBlock;ls.removeBox(t,e),delete t.titleBlock},beforeUpdate(t,e,i){const s=t.titleBlock;ls.configure(t,s,i),s.options=i},defaults:{align:"center",display:!1,font:{weight:"bold"},fullSize:!0,padding:10,position:"top",text:"",weight:2e3},defaultRoutes:{color:"color"},descriptors:{_scriptable:!0,_indexable:!1}};const Sa=new WeakMap;var Pa={id:"subtitle",start(t,e,i){const s=new wa({ctx:t.ctx,options:i,chart:t});ls.configure(t,s,i),ls.addBox(t,s),Sa.set(t,s)},stop(t){ls.removeBox(t,Sa.get(t)),Sa.delete(t)},beforeUpdate(t,e,i){const s=Sa.get(t);ls.configure(t,s,i),s.options=i},defaults:{align:"center",display:!1,font:{weight:"normal"},fullSize:!0,padding:0,position:"top",text:"",weight:1500},defaultRoutes:{color:"color"},descriptors:{_scriptable:!0,_indexable:!1}};const Da={average(t){if(!t.length)return!1;let e,i,s=new Set,n=0,o=0;for(e=0,i=t.length;e<i;++e){const i=t[e].element;if(i&&i.hasValue()){const t=i.tooltipPosition();s.add(t.x),n+=t.y,++o}}if(0===o||0===s.size)return!1;return{x:[...s].reduce(((t,e)=>t+e))/s.size,y:n/o}},nearest(t,e){if(!t.length)return!1;let i,s,n,o=e.x,a=e.y,r=Number.POSITIVE_INFINITY;for(i=0,s=t.length;i<s;++i){const s=t[i].element;if(s&&s.hasValue()){const t=q(e,s.getCenterPoint());t<r&&(r=t,n=s)}}if(n){const t=n.tooltipPosition();o=t.x,a=t.y}return{x:o,y:a}}};function Ca(t,e){return e&&(n(e)?Array.prototype.push.apply(t,e):t.push(e)),t}function Oa(t){return("string"==typeof t||t instanceof String)&&t.indexOf("\n")>-1?t.split("\n"):t}function Aa(t,e){const{element:i,datasetIndex:s,index:n}=e,o=t.getDatasetMeta(s).controller,{label:a,value:r}=o.getLabelAndValue(n);return{chart:t,label:a,parsed:o.getParsed(n),raw:t.data.datasets[s].data[n],formattedValue:r,dataset:o.getDataset(),dataIndex:n,datasetIndex:s,element:i}}function Ta(t,e){const i=t.chart.ctx,{body:s,footer:n,title:o}=t,{boxWidth:a,boxHeight:r}=e,l=Si(e.bodyFont),h=Si(e.titleFont),c=Si(e.footerFont),d=o.length,f=n.length,g=s.length,p=ki(e.padding);let m=p.height,x=0,b=s.reduce(((t,e)=>t+e.before.length+e.lines.length+e.after.length),0);if(b+=t.beforeBody.length+t.afterBody.length,d&&(m+=d*h.lineHeight+(d-1)*e.titleSpacing+e.titleMarginBottom),b){m+=g*(e.displayColors?Math.max(r,l.lineHeight):l.lineHeight)+(b-g)*l.lineHeight+(b-1)*e.bodySpacing}f&&(m+=e.footerMarginTop+f*c.lineHeight+(f-1)*e.footerSpacing);let _=0;const y=function(t){x=Math.max(x,i.measureText(t).width+_)};return i.save(),i.font=h.string,u(t.title,y),i.font=l.string,u(t.beforeBody.concat(t.afterBody),y),_=e.displayColors?a+2+e.boxPadding:0,u(s,(t=>{u(t.before,y),u(t.lines,y),u(t.after,y)})),_=0,i.font=c.string,u(t.footer,y),i.restore(),x+=p.width,{width:x,height:m}}function La(t,e,i,s){const{x:n,width:o}=i,{width:a,chartArea:{left:r,right:l}}=t;let h="center";return"center"===s?h=n<=(r+l)/2?"left":"right":n<=o/2?h="left":n>=a-o/2&&(h="right"),function(t,e,i,s){const{x:n,width:o}=s,a=i.caretSize+i.caretPadding;return"left"===t&&n+o+a>e.width||"right"===t&&n-o-a<0||void 0}(h,t,e,i)&&(h="center"),h}function Ea(t,e,i){const s=i.yAlign||e.yAlign||function(t,e){const{y:i,height:s}=e;return i<s/2?"top":i>t.height-s/2?"bottom":"center"}(t,i);return{xAlign:i.xAlign||e.xAlign||La(t,e,i,s),yAlign:s}}function Ra(t,e,i,s){const{caretSize:n,caretPadding:o,cornerRadius:a}=t,{xAlign:r,yAlign:l}=i,h=n+o,{topLeft:c,topRight:d,bottomLeft:u,bottomRight:f}=wi(a);let g=function(t,e){let{x:i,width:s}=t;return"right"===e?i-=s:"center"===e&&(i-=s/2),i}(e,r);const p=function(t,e,i){let{y:s,height:n}=t;return"top"===e?s+=i:s-="bottom"===e?n+i:n/2,s}(e,l,h);return"center"===l?"left"===r?g+=h:"right"===r&&(g-=h):"left"===r?g-=Math.max(c,u)+n:"right"===r&&(g+=Math.max(d,f)+n),{x:Z(g,0,s.width-e.width),y:Z(p,0,s.height-e.height)}}function Ia(t,e,i){const s=ki(i.padding);return"center"===e?t.x+t.width/2:"right"===e?t.x+t.width-s.right:t.x+s.left}function za(t){return Ca([],Oa(t))}function Fa(t,e){const i=e&&e.dataset&&e.dataset.tooltip&&e.dataset.tooltip.callbacks;return i?t.override(i):t}const Va={beforeTitle:e,title(t){if(t.length>0){const e=t[0],i=e.chart.data.labels,s=i?i.length:0;if(this&&this.options&&"dataset"===this.options.mode)return e.dataset.label||"";if(e.label)return e.label;if(s>0&&e.dataIndex<s)return i[e.dataIndex]}return""},afterTitle:e,beforeBody:e,beforeLabel:e,label(t){if(this&&this.options&&"dataset"===this.options.mode)return t.label+": "+t.formattedValue||t.formattedValue;let e=t.dataset.label||"";e&&(e+=": ");const i=t.formattedValue;return s(i)||(e+=i),e},labelColor(t){const e=t.chart.getDatasetMeta(t.datasetIndex).controller.getStyle(t.dataIndex);return{borderColor:e.borderColor,backgroundColor:e.backgroundColor,borderWidth:e.borderWidth,borderDash:e.borderDash,borderDashOffset:e.borderDashOffset,borderRadius:0}},labelTextColor(){return this.options.bodyColor},labelPointStyle(t){const e=t.chart.getDatasetMeta(t.datasetIndex).controller.getStyle(t.dataIndex);return{pointStyle:e.pointStyle,rotation:e.rotation}},afterLabel:e,afterBody:e,beforeFooter:e,footer:e,afterFooter:e};function Ba(t,e,i,s){const n=t[e].call(i,s);return void 0===n?Va[e].call(i,s):n}class Wa extends $s{static positioners=Da;constructor(t){super(),this.opacity=0,this._active=[],this._eventPosition=void 0,this._size=void 0,this._cachedAnimations=void 0,this._tooltipItems=[],this.$animations=void 0,this.$context=void 0,this.chart=t.chart,this.options=t.options,this.dataPoints=void 0,this.title=void 0,this.beforeBody=void 0,this.body=void 0,this.afterBody=void 0,this.footer=void 0,this.xAlign=void 0,this.yAlign=void 0,this.x=void 0,this.y=void 0,this.height=void 0,this.width=void 0,this.caretX=void 0,this.caretY=void 0,this.labelColors=void 0,this.labelPointStyles=void 0,this.labelTextColors=void 0}initialize(t){this.options=t,this._cachedAnimations=void 0,this.$context=void 0}_resolveAnimations(){const t=this._cachedAnimations;if(t)return t;const e=this.chart,i=this.options.setContext(this.getContext()),s=i.enabled&&e.options.animation&&i.animations,n=new Ts(this.chart,s);return s._cacheable&&(this._cachedAnimations=Object.freeze(n)),n}getContext(){return this.$context||(this.$context=(t=this.chart.getContext(),e=this,i=this._tooltipItems,Ci(t,{tooltip:e,tooltipItems:i,type:"tooltip"})));var t,e,i}getTitle(t,e){const{callbacks:i}=e,s=Ba(i,"beforeTitle",this,t),n=Ba(i,"title",this,t),o=Ba(i,"afterTitle",this,t);let a=[];return a=Ca(a,Oa(s)),a=Ca(a,Oa(n)),a=Ca(a,Oa(o)),a}getBeforeBody(t,e){return za(Ba(e.callbacks,"beforeBody",this,t))}getBody(t,e){const{callbacks:i}=e,s=[];return u(t,(t=>{const e={before:[],lines:[],after:[]},n=Fa(i,t);Ca(e.before,Oa(Ba(n,"beforeLabel",this,t))),Ca(e.lines,Ba(n,"label",this,t)),Ca(e.after,Oa(Ba(n,"afterLabel",this,t))),s.push(e)})),s}getAfterBody(t,e){return za(Ba(e.callbacks,"afterBody",this,t))}getFooter(t,e){const{callbacks:i}=e,s=Ba(i,"beforeFooter",this,t),n=Ba(i,"footer",this,t),o=Ba(i,"afterFooter",this,t);let a=[];return a=Ca(a,Oa(s)),a=Ca(a,Oa(n)),a=Ca(a,Oa(o)),a}_createItems(t){const e=this._active,i=this.chart.data,s=[],n=[],o=[];let a,r,l=[];for(a=0,r=e.length;a<r;++a)l.push(Aa(this.chart,e[a]));return t.filter&&(l=l.filter(((e,s,n)=>t.filter(e,s,n,i)))),t.itemSort&&(l=l.sort(((e,s)=>t.itemSort(e,s,i)))),u(l,(e=>{const i=Fa(t.callbacks,e);s.push(Ba(i,"labelColor",this,e)),n.push(Ba(i,"labelPointStyle",this,e)),o.push(Ba(i,"labelTextColor",this,e))})),this.labelColors=s,this.labelPointStyles=n,this.labelTextColors=o,this.dataPoints=l,l}update(t,e){const i=this.options.setContext(this.getContext()),s=this._active;let n,o=[];if(s.length){const t=Da[i.position].call(this,s,this._eventPosition);o=this._createItems(i),this.title=this.getTitle(o,i),this.beforeBody=this.getBeforeBody(o,i),this.body=this.getBody(o,i),this.afterBody=this.getAfterBody(o,i),this.footer=this.getFooter(o,i);const e=this._size=Ta(this,i),a=Object.assign({},t,e),r=Ea(this.chart,i,a),l=Ra(i,a,r,this.chart);this.xAlign=r.xAlign,this.yAlign=r.yAlign,n={opacity:1,x:l.x,y:l.y,width:e.width,height:e.height,caretX:t.x,caretY:t.y}}else 0!==this.opacity&&(n={opacity:0});this._tooltipItems=o,this.$context=void 0,n&&this._resolveAnimations().update(this,n),t&&i.external&&i.external.call(this,{chart:this.chart,tooltip:this,replay:e})}drawCaret(t,e,i,s){const n=this.getCaretPosition(t,i,s);e.lineTo(n.x1,n.y1),e.lineTo(n.x2,n.y2),e.lineTo(n.x3,n.y3)}getCaretPosition(t,e,i){const{xAlign:s,yAlign:n}=this,{caretSize:o,cornerRadius:a}=i,{topLeft:r,topRight:l,bottomLeft:h,bottomRight:c}=wi(a),{x:d,y:u}=t,{width:f,height:g}=e;let p,m,x,b,_,y;return"center"===n?(_=u+g/2,"left"===s?(p=d,m=p-o,b=_+o,y=_-o):(p=d+f,m=p+o,b=_-o,y=_+o),x=p):(m="left"===s?d+Math.max(r,h)+o:"right"===s?d+f-Math.max(l,c)-o:this.caretX,"top"===n?(b=u,_=b-o,p=m-o,x=m+o):(b=u+g,_=b+o,p=m+o,x=m-o),y=b),{x1:p,x2:m,x3:x,y1:b,y2:_,y3:y}}drawTitle(t,e,i){const s=this.title,n=s.length;let o,a,r;if(n){const l=Oi(i.rtl,this.x,this.width);for(t.x=Ia(this,i.titleAlign,i),e.textAlign=l.textAlign(i.titleAlign),e.textBaseline="middle",o=Si(i.titleFont),a=i.titleSpacing,e.fillStyle=i.titleColor,e.font=o.string,r=0;r<n;++r)e.fillText(s[r],l.x(t.x),t.y+o.lineHeight/2),t.y+=o.lineHeight+a,r+1===n&&(t.y+=i.titleMarginBottom-a)}}_drawColorBox(t,e,i,s,n){const a=this.labelColors[i],r=this.labelPointStyles[i],{boxHeight:l,boxWidth:h}=n,c=Si(n.bodyFont),d=Ia(this,"left",n),u=s.x(d),f=l<c.lineHeight?(c.lineHeight-l)/2:0,g=e.y+f;if(n.usePointStyle){const e={radius:Math.min(h,l)/2,pointStyle:r.pointStyle,rotation:r.rotation,borderWidth:1},i=s.leftForLtr(u,h)+h/2,o=g+l/2;t.strokeStyle=n.multiKeyBackground,t.fillStyle=n.multiKeyBackground,Le(t,e,i,o),t.strokeStyle=a.borderColor,t.fillStyle=a.backgroundColor,Le(t,e,i,o)}else{t.lineWidth=o(a.borderWidth)?Math.max(...Object.values(a.borderWidth)):a.borderWidth||1,t.strokeStyle=a.borderColor,t.setLineDash(a.borderDash||[]),t.lineDashOffset=a.borderDashOffset||0;const e=s.leftForLtr(u,h),i=s.leftForLtr(s.xPlus(u,1),h-2),r=wi(a.borderRadius);Object.values(r).some((t=>0!==t))?(t.beginPath(),t.fillStyle=n.multiKeyBackground,He(t,{x:e,y:g,w:h,h:l,radius:r}),t.fill(),t.stroke(),t.fillStyle=a.backgroundColor,t.beginPath(),He(t,{x:i,y:g+1,w:h-2,h:l-2,radius:r}),t.fill()):(t.fillStyle=n.multiKeyBackground,t.fillRect(e,g,h,l),t.strokeRect(e,g,h,l),t.fillStyle=a.backgroundColor,t.fillRect(i,g+1,h-2,l-2))}t.fillStyle=this.labelTextColors[i]}drawBody(t,e,i){const{body:s}=this,{bodySpacing:n,bodyAlign:o,displayColors:a,boxHeight:r,boxWidth:l,boxPadding:h}=i,c=Si(i.bodyFont);let d=c.lineHeight,f=0;const g=Oi(i.rtl,this.x,this.width),p=function(i){e.fillText(i,g.x(t.x+f),t.y+d/2),t.y+=d+n},m=g.textAlign(o);let x,b,_,y,v,M,w;for(e.textAlign=o,e.textBaseline="middle",e.font=c.string,t.x=Ia(this,m,i),e.fillStyle=i.bodyColor,u(this.beforeBody,p),f=a&&"right"!==m?"center"===o?l/2+h:l+2+h:0,y=0,M=s.length;y<M;++y){for(x=s[y],b=this.labelTextColors[y],e.fillStyle=b,u(x.before,p),_=x.lines,a&&_.length&&(this._drawColorBox(e,t,y,g,i),d=Math.max(c.lineHeight,r)),v=0,w=_.length;v<w;++v)p(_[v]),d=c.lineHeight;u(x.after,p)}f=0,d=c.lineHeight,u(this.afterBody,p),t.y-=n}drawFooter(t,e,i){const s=this.footer,n=s.length;let o,a;if(n){const r=Oi(i.rtl,this.x,this.width);for(t.x=Ia(this,i.footerAlign,i),t.y+=i.footerMarginTop,e.textAlign=r.textAlign(i.footerAlign),e.textBaseline="middle",o=Si(i.footerFont),e.fillStyle=i.footerColor,e.font=o.string,a=0;a<n;++a)e.fillText(s[a],r.x(t.x),t.y+o.lineHeight/2),t.y+=o.lineHeight+i.footerSpacing}}drawBackground(t,e,i,s){const{xAlign:n,yAlign:o}=this,{x:a,y:r}=t,{width:l,height:h}=i,{topLeft:c,topRight:d,bottomLeft:u,bottomRight:f}=wi(s.cornerRadius);e.fillStyle=s.backgroundColor,e.strokeStyle=s.borderColor,e.lineWidth=s.borderWidth,e.beginPath(),e.moveTo(a+c,r),"top"===o&&this.drawCaret(t,e,i,s),e.lineTo(a+l-d,r),e.quadraticCurveTo(a+l,r,a+l,r+d),"center"===o&&"right"===n&&this.drawCaret(t,e,i,s),e.lineTo(a+l,r+h-f),e.quadraticCurveTo(a+l,r+h,a+l-f,r+h),"bottom"===o&&this.drawCaret(t,e,i,s),e.lineTo(a+u,r+h),e.quadraticCurveTo(a,r+h,a,r+h-u),"center"===o&&"left"===n&&this.drawCaret(t,e,i,s),e.lineTo(a,r+c),e.quadraticCurveTo(a,r,a+c,r),e.closePath(),e.fill(),s.borderWidth>0&&e.stroke()}_updateAnimationTarget(t){const e=this.chart,i=this.$animations,s=i&&i.x,n=i&&i.y;if(s||n){const i=Da[t.position].call(this,this._active,this._eventPosition);if(!i)return;const o=this._size=Ta(this,t),a=Object.assign({},i,this._size),r=Ea(e,t,a),l=Ra(t,a,r,e);s._to===l.x&&n._to===l.y||(this.xAlign=r.xAlign,this.yAlign=r.yAlign,this.width=o.width,this.height=o.height,this.caretX=i.x,this.caretY=i.y,this._resolveAnimations().update(this,l))}}_willRender(){return!!this.opacity}draw(t){const e=this.options.setContext(this.getContext());let i=this.opacity;if(!i)return;this._updateAnimationTarget(e);const s={width:this.width,height:this.height},n={x:this.x,y:this.y};i=Math.abs(i)<.001?0:i;const o=ki(e.padding),a=this.title.length||this.beforeBody.length||this.body.length||this.afterBody.length||this.footer.length;e.enabled&&a&&(t.save(),t.globalAlpha=i,this.drawBackground(n,t,s,e),Ai(t,e.textDirection),n.y+=o.top,this.drawTitle(n,t,e),this.drawBody(n,t,e),this.drawFooter(n,t,e),Ti(t,e.textDirection),t.restore())}getActiveElements(){return this._active||[]}setActiveElements(t,e){const i=this._active,s=t.map((({datasetIndex:t,index:e})=>{const i=this.chart.getDatasetMeta(t);if(!i)throw new Error("Cannot find a dataset at index "+t);return{datasetIndex:t,element:i.data[e],index:e}})),n=!f(i,s),o=this._positionChanged(s,e);(n||o)&&(this._active=s,this._eventPosition=e,this._ignoreReplayEvents=!0,this.update(!0))}handleEvent(t,e,i=!0){if(e&&this._ignoreReplayEvents)return!1;this._ignoreReplayEvents=!1;const s=this.options,n=this._active||[],o=this._getActiveElements(t,n,e,i),a=this._positionChanged(o,t),r=e||!f(o,n)||a;return r&&(this._active=o,(s.enabled||s.external)&&(this._eventPosition={x:t.x,y:t.y},this.update(!0,e))),r}_getActiveElements(t,e,i,s){const n=this.options;if("mouseout"===t.type)return[];if(!s)return e.filter((t=>this.chart.data.datasets[t.datasetIndex]&&void 0!==this.chart.getDatasetMeta(t.datasetIndex).controller.getParsed(t.index)));const o=this.chart.getElementsAtEventForMode(t,n.mode,n,i);return n.reverse&&o.reverse(),o}_positionChanged(t,e){const{caretX:i,caretY:s,options:n}=this,o=Da[n.position].call(this,t,e);return!1!==o&&(i!==o.x||s!==o.y)}}var Na={id:"tooltip",_element:Wa,positioners:Da,afterInit(t,e,i){i&&(t.tooltip=new Wa({chart:t,options:i}))},beforeUpdate(t,e,i){t.tooltip&&t.tooltip.initialize(i)},reset(t,e,i){t.tooltip&&t.tooltip.initialize(i)},afterDraw(t){const e=t.tooltip;if(e&&e._willRender()){const i={tooltip:e};if(!1===t.notifyPlugins("beforeTooltipDraw",{...i,cancelable:!0}))return;e.draw(t.ctx),t.notifyPlugins("afterTooltipDraw",i)}},afterEvent(t,e){if(t.tooltip){const i=e.replay;t.tooltip.handleEvent(e.event,i,e.inChartArea)&&(e.changed=!0)}},defaults:{enabled:!0,external:null,position:"average",backgroundColor:"rgba(0,0,0,0.8)",titleColor:"#fff",titleFont:{weight:"bold"},titleSpacing:2,titleMarginBottom:6,titleAlign:"left",bodyColor:"#fff",bodySpacing:2,bodyFont:{},bodyAlign:"left",footerColor:"#fff",footerSpacing:2,footerMarginTop:6,footerFont:{weight:"bold"},footerAlign:"left",padding:6,caretPadding:2,caretSize:5,cornerRadius:6,boxHeight:(t,e)=>e.bodyFont.size,boxWidth:(t,e)=>e.bodyFont.size,multiKeyBackground:"#fff",displayColors:!0,boxPadding:0,borderColor:"rgba(0,0,0,0)",borderWidth:0,animation:{duration:400,easing:"easeOutQuart"},animations:{numbers:{type:"number",properties:["x","y","width","height","caretX","caretY"]},opacity:{easing:"linear",duration:200}},callbacks:Va},defaultRoutes:{bodyFont:"font",footerFont:"font",titleFont:"font"},descriptors:{_scriptable:t=>"filter"!==t&&"itemSort"!==t&&"external"!==t,_indexable:!1,callbacks:{_scriptable:!1,_indexable:!1},animation:{_fallback:!1},animations:{_fallback:"animation"}},additionalOptionScopes:["interaction"]};return Tn.register(Un,$o,go,t),Tn.helpers={...Hi},Tn._adapters=In,Tn.Animation=As,Tn.Animations=Ts,Tn.animator=bt,Tn.controllers=nn.controllers.items,Tn.DatasetController=js,Tn.Element=$s,Tn.elements=go,Tn.Interaction=Ki,Tn.layouts=ls,Tn.platforms=Ds,Tn.Scale=tn,Tn.Ticks=ae,Object.assign(Tn,Un,$o,go,t,Ds),Tn.Chart=Tn,"undefined"!=typeof window&&(window.Chart=Tn),Tn}));
//# sourceMappingURL=chart.umd.min.js.map

'@

$global:GLOBALJavaScript_Nav = @'
    <script>
        (function () {
        function safeJsonParse(text) {
            try { return JSON.parse(text); } catch (e) { return null; }
        }

        function getManifest() {
            var el = document.getElementById("report-manifest");
            if (!el || !el.textContent) return null;
            return safeJsonParse(el.textContent);
        }

        function getReportTitle(manifest) {
        if (manifest && manifest.currentReportName) {
            var s = String(manifest.currentReportName).replace(/\s+/g, " ").trim();
            if (s) return s;
        }

        if (manifest && manifest.currentReportKey) {
            var k = String(manifest.currentReportKey).replace(/\s+/g, " ").trim();
            if (k) return k;
        }

        var h1 = document.querySelector("h1");
        if (h1) {
            var t = (h1.textContent || "").replace(/\s+/g, " ").trim();
            if (t) return t;
        }

        return "Report";
        }


        function getHeaderMeta(manifest) {
        var tenant = "";
        var executed = "";

        if (manifest) {
            if (manifest.tenantName) {
            tenant = String(manifest.tenantName).trim();
            }

            if (manifest.tenantId) {
            var tid = String(manifest.tenantId).trim();
            if (tid) {
                tenant = tenant ? (tenant + " / ID: " + tid) : ("ID: " + tid);
            }
            }

            if (manifest.executedAt) {
            executed = String(manifest.executedAt).trim();
            }
        }

        return { tenant: tenant, executed: executed };
        }


        function ensureHeadingIds() {
            var headings = document.querySelectorAll("h2");

            headings = Array.prototype.filter.call(headings, function (h2) {
                if (!h2) return false;
                // Exclude help modal heading
                if (h2.closest && h2.closest("#helpModalOverlay")) return false;

                return true;
            });
            for (var i = 0; i < headings.length; i++) {
            var h2 = headings[i];
            if (h2.id) continue;

            var id = (h2.textContent || "")
                .trim()
                .toLowerCase()
                .replace(/\s+/g, "-")
                .replace(/[^a-z0-9\-]/g, "");

            h2.id = id || ("section-" + i);
            }
        }

        function buildNavStackShell(manifest) {
            if (document.getElementById("nav-stack")) return;

            var body = document.body;
            var loading = document.getElementById("loadingOverlay");

            var stack = document.createElement("div");
            stack.id = "nav-stack";

            var header = document.createElement("div");
            header.id = "report-header";

            var left = document.createElement("div");
            left.className = "hdr-left";

            var titleWrap = document.createElement("div");
            titleWrap.className = "hdr-title";

            var name = document.createElement("span");
            name.className = "hdr-name";
            name.textContent = getReportTitle(manifest);

            titleWrap.appendChild(name);
            left.appendChild(titleWrap);

            var meta = getHeaderMeta(manifest);
            var sub = document.createElement("div");
            sub.className = "hdr-sub";
            sub.id = "hdr-subline";

            if (meta.tenant) {
            var t = document.createElement("span");
            t.className = "hdr-meta";
            t.textContent = meta.tenant;
            sub.appendChild(t);
            }

            if (meta.tenant && meta.executed) {
            var dot = document.createElement("span");
            dot.className = "hdr-dot";
            dot.textContent = "\u2022";
            sub.appendChild(dot);
            }

            if (meta.executed) {
            var e = document.createElement("span");
            e.className = "hdr-meta";
            e.innerHTML = "Executed: " + meta.executed.replace(/</g, "&lt;");
            sub.appendChild(e);
            }

            left.appendChild(sub);

            var center = document.createElement("div");
            center.className = "hdr-center";

            var right = document.createElement("div");
            right.className = "hdr-right";
            right.id = "hdr-actions";

            var warnBtn = document.createElement("button");
            warnBtn.className = "hdr-btn hdr-warn-btn";
            warnBtn.id = "hdrWarningsBtn";
            warnBtn.type = "button";
            warnBtn.hidden = true;

            var warnLabel = document.createElement("span");
            warnLabel.className = "hdr-warn-label";
            warnLabel.textContent = "\u26A0\uFE0F Warnings";

            var warnCount = document.createElement("span");
            warnCount.className = "hdr-warn-count";
            warnCount.id = "hdrWarningsCount";
            warnCount.setAttribute("aria-hidden", "true");

            warnBtn.appendChild(warnLabel);
            warnBtn.appendChild(warnCount);

            right.appendChild(warnBtn);

            header.appendChild(left);
            header.appendChild(center);
            header.appendChild(right);

            var tabstrip = document.createElement("div");
            tabstrip.id = "report-tabstrip";

            var sectionStrip = document.createElement("div");
            sectionStrip.id = "section-strip";
            sectionStrip.setAttribute("aria-label", "Sections");

            var sectionInner = document.createElement("div");
            sectionInner.className = "section-strip-inner";
            sectionInner.id = "sectionStripInner";
            sectionStrip.appendChild(sectionInner);

            stack.appendChild(header);
            stack.appendChild(tabstrip);
            stack.appendChild(sectionStrip);

            body.insertBefore(stack, body.firstChild);
            if (loading) body.insertBefore(loading, stack);

            // Warnings drawer shell
            if (!document.getElementById("warnings-drawer")) {
            var backdrop = document.createElement("div");
            backdrop.className = "contents-backdrop";
            backdrop.id = "warnings-backdrop";
            backdrop.hidden = true;

            var drawer = document.createElement("aside");
            drawer.className = "contents-drawer";
            drawer.id = "warnings-drawer";
            drawer.setAttribute("data-drawer", "warnings");
            drawer.setAttribute("aria-hidden", "true");

            var inner = document.createElement("div");
            inner.className = "contents-drawer-inner";

            var hdr = document.createElement("div");
            hdr.className = "contents-drawer-header";

            var ttl = document.createElement("div");
            ttl.className = "contents-drawer-title";
            ttl.textContent = "Execution warnings";

            var close = document.createElement("button");
            close.className = "hdr-btn";
            close.id = "warningsCloseBtn";
            close.type = "button";
            close.textContent = "Close";

            hdr.appendChild(ttl);
            hdr.appendChild(close);

            var bodyWrap = document.createElement("div");
            bodyWrap.className = "warnings-body";
            bodyWrap.id = "warnings-body";

            var list = document.createElement("ul");
            list.className = "warnings-list";
            list.id = "warnings-list";

            var empty = document.createElement("div");
            empty.className = "warnings-empty";
            empty.id = "warnings-empty";
            empty.hidden = true;
            empty.textContent = "No warnings found.";

            bodyWrap.appendChild(list);
            bodyWrap.appendChild(empty);

            inner.appendChild(hdr);
            inner.appendChild(bodyWrap);

            drawer.appendChild(inner);

            body.appendChild(backdrop);
            body.appendChild(drawer);
            }
        }

        function buildReportTabs(manifest) {
            var host = document.getElementById("report-tabstrip");
            if (!host) return;

            host.innerHTML = "";

            if (!manifest || !manifest.reports || !manifest.reports.length) return;

            var inner = document.createElement("div");
            inner.className = "tabstrip-inner";

            var curKey = String((manifest.currentReportKey || manifest.current || "")).trim();
            var curPath = (window.location.pathname || "").split("/").pop();

            for (var i = 0; i < manifest.reports.length; i++) {
            var r = manifest.reports[i] || {};
            if (!r.file) continue;

            var a = document.createElement("a");
            a.className = "report-tab";
            a.href = r.file;
            a.textContent = r.title || r.key || r.file;

            var isActive = false;
            if (curKey && (r.key === curKey || r.title === curKey)) isActive = true;
            if (!isActive && curPath && r.file.split("/").pop() === curPath) isActive = true;

            if (isActive) {
                a.classList.add("active");
                a.setAttribute("aria-current", "page");
                a.href = "#";
            }

            inner.appendChild(a);
            }

            host.appendChild(inner);

            var activeTab = inner.querySelector(".report-tab.active");
            if (activeTab && activeTab.scrollIntoView) {
                try {
                    activeTab.scrollIntoView({ block: "nearest", inline: "center" });
                } catch (e) {
                    try { activeTab.scrollIntoView(false); } catch (ignore) {}
                }
            }
        }

        function buildSectionStrip() {
            var inner = document.getElementById("sectionStripInner");
            if (!inner) return;

            while (inner.firstChild) inner.removeChild(inner.firstChild);

            var headings = document.querySelectorAll("h2");

            var added = 0;

            for (var i = 0; i < headings.length; i++) {
                var h2 = headings[i];
                if (!h2 || !h2.id) continue;

                // Exclude help modal heading (if present in DOM)
                if (h2.closest && h2.closest("#helpModalOverlay")) continue;

                // Add separator only BETWEEN items
                if (added > 0) {
                    var sep = document.createElement("span");
                    sep.className = "section-sep";
                    sep.textContent = "\u2022";
                    inner.appendChild(sep);
                }

                var a = document.createElement("a");
                a.className = "section-link";
                a.href = "#" + h2.id;
                a.textContent = (h2.textContent || "").replace(/\s+/g, " ").trim();

                // Immediately mark the clicked link active so the indicator
                // updates on click rather than waiting for the scroll event.
                a.addEventListener("click", function () {
                    var all = document.querySelectorAll("#sectionStripInner .section-link");
                    for (var k = 0; k < all.length; k++) all[k].classList.remove("active");
                    this.classList.add("active");
                });

                inner.appendChild(a);
                added++;
            }
        }

        function ensureHeaderControls() {
            var actions = document.getElementById("hdr-actions");
            if (!actions) return;

            // -------------------------
            // Theme button
            // -------------------------
            if (!document.getElementById("hdrThemeBtn")) {
                var themeBtn = document.createElement("button");
                themeBtn.id = "hdrThemeBtn";
                themeBtn.className = "hdr-btn";
                themeBtn.type = "button";
                actions.appendChild(themeBtn);
                var themeStorageKey = "EntraFalcon_theme";

                function isFirefoxBrowser() {
                    var ua = (typeof navigator !== "undefined" && navigator.userAgent) ? navigator.userAgent : "";
                    return /firefox/i.test(ua);
                }

                function canUseStorage(storage) {
                    if (!storage) return false;
                    try {
                        var probeKey = "__ef_theme_probe__";
                        storage.setItem(probeKey, "1");
                        storage.removeItem(probeKey);
                        return true;
                    } catch (e) {
                        return false;
                    }
                }

                function getThemeStorage() {
                    var preferred = isFirefoxBrowser() ? window.sessionStorage : window.localStorage;
                    if (canUseStorage(preferred)) return preferred;

                    var fallback = preferred === window.localStorage ? window.sessionStorage : window.localStorage;
                    if (canUseStorage(fallback)) return fallback;

                    return {
                        getItem: function () { return null; },
                        setItem: function () {}
                    };
                }

                var themeStorage = getThemeStorage();

                function setTheme(theme) {
                    document.body.classList.remove("light-mode", "dark-mode");
                    document.body.classList.add(theme + "-mode");
                    try { themeStorage.setItem(themeStorageKey, theme); } catch (e) {}

                    themeBtn.textContent = theme === "dark" ? "\uD83C\uDF13 Dark" : "\u2600\uFE0F Light";

                    // Recolor table if the table script exists on this page
                    if (typeof window.colorCells === "function") {
                        var table = document.querySelector("#tableWrapper table");
                        if (table) {
                            var headerCells = table.querySelectorAll("thead tr:first-child th");
                            var headers = Array.prototype.map.call(headerCells, function (th) {
                                return th.getAttribute("data-col") || (th.textContent || "").trim();
                            });
                            window.requestAnimationFrame(function () {
                                window.colorCells(table, headers);
                            });
                        }
                    }
                }

                var savedTheme = null;
                try { savedTheme = themeStorage.getItem(themeStorageKey); } catch (e) {}
                savedTheme = savedTheme || "dark";
                setTheme(savedTheme);

                themeBtn.addEventListener("click", function () {
                    var isDark = document.body.classList.contains("dark-mode");
                    setTheme(isDark ? "light" : "dark");
                });
            }

            // -------------------------
            // Help button + modal
            // -------------------------
            if (!document.getElementById("hdrHelpBtn")) {
                var helpBtn = document.createElement("button");
                helpBtn.id = "hdrHelpBtn";
                helpBtn.className = "hdr-btn";
                helpBtn.type = "button";
                helpBtn.textContent = "\u2753 Help";
                actions.appendChild(helpBtn);

                if (!document.getElementById("helpModalOverlay")) {
                    var modalOverlay = document.createElement("div");
                    modalOverlay.id = "helpModalOverlay";
                    modalOverlay.className = "help-modal-overlay";

                    var modalContent = document.createElement("div");
                    modalContent.id = "helpModalContent";
                    modalContent.className = "help-modal-content";

                    modalContent.innerHTML = `
                    <h2>How to Use This Report</h2>
                    <strong>General</strong>
                    <ul>
                        <li>Click the \u2699\uFE0F <strong>Columns</strong> button to show or hide specific columns.</li>
                        <li>Click \u{1F4BE} <strong>Export CSV</strong> to download the currently visible data as a CSV file.</li>
                        <li>Click \u{1F441} <strong>Share View</strong> to copy filters, sorting, and column selection as a shareable link.</li>
                        <li>Click \uD83E\uDDF0 <strong>Preset Views</strong> to apply preconfigured filters and column selections.</li>
                        <li>Click \uD83D\uDD01 <strong>Reset View</strong> to reset the view to the default.</li>
                        <li>Click on object names to jump to detailed information, even across reports.<br>
                        Links look like this: <a href="#" class="help-example-link" onclick="return false;">Example Link</a></li>
                        <li>When navigating within the report, use the browser's back button to return.</li>
                        <li>Some table header fields display helper text on mouse hover.</li>
                        <li>Sort data by clicking any table header.</li>
                    </ul>
                    <strong>Filtering</strong>
                    <ul>
                        <li>If no operator is specified, filtering defaults to <em>contains</em>.</li>
                        <li>Use <code>=</code> for an exact match.</li>
                        <li>Use <code>^</code> for <em>starts with</em> (e.g., <code>^Mallory</code>).</li>
                        <li>Use <code>$</code> for <em>ends with</em> (e.g., <code>$domain.ch</code>).</li>
                        <li>Comparison operators like <code>&gt;</code>, <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code> are supported (for numeric values only).</li>
                        <li>Filters can be negated by starting with <code>!</code> (except for numeric comparisons).<br>Examples: <code>!Mallory</code>, <code>!=Mallory</code>, <code>!^Mallory</code> or <code>!$domain.ch</code>.</li>
                        <li>Use <code>=empty</code> to match empty cells, or <code>!=empty</code> to match non-empty cells.</li>
                        <li>Use <code>||</code> to match any of multiple values in the same column (e.g., <code>Admin || Guest</code>).</li>
                        <li>Use <code>&amp;&amp;</code> to require multiple matches in the same column (e.g., <code>!adm &amp;&amp; !svc &amp;&amp; !sql</code>).</li>
                        <li>To apply <code>OR</code> logic across columns, use <code>or_</code> or <code>group1_</code>. Examples: Column1:<code>or_>1</code> Column2:<code>or_!Mallory</code>.</li>
                        <li>The <strong>DisplayName</strong> column includes the object's ID (hidden), allowing filtering by ID.</li>
                    </ul>
                    <strong>Rating</strong>
                    <ul>
                        <li><strong>Impact</strong>: Represents the amount or severity of permission the object has.</li>
                        <li><strong>Likelihood</strong>: Represents how easily the object can be influenced or how strongly it is protected.</li>
                        <li><strong>Risk</strong>: Calculated as: <em>Impact x Likelihood = Risk</em>.</li>
                        <li><strong>Important</strong>:
                            <ul>
                                <li>This scoring is meant as a basic evaluation to help sort and prioritize entries in the table.</li>
                                <li>Risk scores are not directly comparable between object types or reports.</li>
                                <li>It is not intended to replace a full risk assessment.</li>
                            </ul>
                        </li> 
                    </ul>
                    \u{1F4D6} More information in the <a href="https://github.com/CompassSecurity/EntraFalcon">GitHub README</a><br>
                    <button id="closeHelpModal" class="help-modal-close" type="button">\u2716 Close</button>
                    `;

                    modalOverlay.appendChild(modalContent);
                    document.body.appendChild(modalOverlay);

                    modalOverlay.addEventListener("click", function (e) {
                        if (e.target === modalOverlay || e.target.id === "closeHelpModal") {
                            modalOverlay.classList.remove("show");
                        }
                    });

                    document.addEventListener("keydown", function (e) {
                        var isVisible = modalOverlay.classList.contains("show");
                        if (e.key === "Escape" && isVisible) {
                            modalOverlay.classList.remove("show");
                        }
                    });
                }

                helpBtn.addEventListener("click", function () {
                    var overlay = document.getElementById("helpModalOverlay");
                    if (overlay) overlay.classList.add("show");
                });
            }
        }


        function getNavOffset() {
            var doc = document.documentElement;
            var raw = "";
            try {
                raw = getComputedStyle(doc).getPropertyValue("--report-header-offset") || "";
            } catch (e) {
                raw = "";
            }
            var n = parseFloat(String(raw).trim());
            return isNaN(n) ? 120 : n;
        }

        function updateActiveSectionLink() {
            var links = document.querySelectorAll("#sectionStripInner .section-link");
            if (!links.length) return;

            var activeId = "";
            var headings = document.querySelectorAll("h2[id]");

            // At the bottom of the page the last section can be too short to ever
            // cross the threshold — in that case force it active.
            var atBottom = (window.innerHeight + Math.round(window.scrollY))
                           >= document.documentElement.scrollHeight - 4;
            if (atBottom && headings.length) {
                activeId = headings[headings.length - 1].id;
            } else {
                for (var i = 0; i < headings.length; i++) {
                    var rect = headings[i].getBoundingClientRect();
                    if (rect.top <= getNavOffset() + 2) activeId = headings[i].id;
                }
            }

            for (var j = 0; j < links.length; j++) {
            var href = links[j].getAttribute("href") || "";
            var id = href.indexOf("#") === 0 ? href.slice(1) : "";
            if (id && id === activeId) {
                links[j].classList.add("active");
            } else {
                links[j].classList.remove("active");
            }
            }
        }

        function parseExecutionWarnings() {
            function normalizeWarnings(input) {
                if (!input) return [];

                var arr = [];
                if (Array.isArray(input)) {
                    arr = input;
                } else if (typeof input === "string") {
                    arr = [input];
                } else {
                    return [];
                }

                var out = [];
                for (var i = 0; i < arr.length; i++) {
                    var s = String(arr[i] || "").replace(/\s+/g, " ").trim();
                    if (s) out.push(s);
                }
                return out;
            }

            // Prefer the already-parsed manifest if present
            if (window.__reportManifest && window.__reportManifest.warnings != null) {
                return normalizeWarnings(window.__reportManifest.warnings);
            }

            // Otherwise parse from the embedded JSON script tag
            var el = document.getElementById("report-manifest");
            if (!el || !el.textContent) return [];

            try {
                var manifest = JSON.parse(el.textContent);
                return normalizeWarnings(manifest && manifest.warnings);
            } catch (e) {
                return [];
            }
        }


        function openWarnings() {
            var drawer = document.getElementById("warnings-drawer");
            var backdrop = document.getElementById("warnings-backdrop");
            if (!drawer || !backdrop) return;

            drawer.classList.add("open");
            drawer.setAttribute("aria-hidden", "false");
            backdrop.hidden = false;
        }

        function closeWarnings() {
            var drawer = document.getElementById("warnings-drawer");
            var backdrop = document.getElementById("warnings-backdrop");
            if (!drawer || !backdrop) return;

            drawer.classList.remove("open");
            drawer.setAttribute("aria-hidden", "true");
            backdrop.hidden = true;
        }

        function wireWarningsDrawer() {
            var btn = document.getElementById("hdrWarningsBtn");
            var closeBtn = document.getElementById("warningsCloseBtn");
            var backdrop = document.getElementById("warnings-backdrop");

            if (btn) btn.addEventListener("click", function () {
            var drawer = document.getElementById("warnings-drawer");
            if (drawer && drawer.classList.contains("open")) {
                closeWarnings();
            } else {
                openWarnings();
            }
            });

            if (closeBtn) closeBtn.addEventListener("click", closeWarnings);
            if (backdrop) backdrop.addEventListener("click", closeWarnings);
        }

        function renderWarningsPanel() {
            var warnings = parseExecutionWarnings();

            var btn = document.getElementById("hdrWarningsBtn");
            var countEl = document.getElementById("hdrWarningsCount");
            var list = document.getElementById("warnings-list");
            var empty = document.getElementById("warnings-empty");

            if (!btn || !countEl || !list || !empty) return;

            while (list.firstChild) list.removeChild(list.firstChild);

            if (!warnings || warnings.length === 0) {
                btn.hidden = true;
                btn.style.display = "none";
                countEl.textContent = "";
                empty.hidden = false;
                return;
            }

            btn.hidden = false;
            btn.style.display = "";

            for (var i = 0; i < warnings.length; i++) {
                var li = document.createElement("li");
                li.textContent = warnings[i];
                list.appendChild(li);
            }

            countEl.textContent = String(warnings.length);
            btn.hidden = false;
            empty.hidden = true;
        }

        function updateNavStackPadding() {
            var stack = document.getElementById("nav-stack");
            if (!stack) return;

            var h = stack.getBoundingClientRect().height || 0;
            var offset = h + 12;
            document.body.style.paddingTop = String(offset) + "px";
            document.documentElement.style.setProperty("--report-header-offset", String(Math.max(0, h - 1)) + "px");
        }

        function init() {
            var manifest = getManifest();

            ensureHeadingIds();
            buildNavStackShell(manifest);
            ensureHeaderControls();

            buildReportTabs(manifest);
            buildSectionStrip();
            renderWarningsPanel();
            wireWarningsDrawer();

            updateNavStackPadding();
            updateActiveSectionLink();

            window.addEventListener("scroll", function () {
            updateActiveSectionLink();
            }, { passive: true });

            window.addEventListener("resize", function () {
            updateNavStackPadding();
            });
        }

        document.addEventListener("DOMContentLoaded", init);
        })();
    </script>

'@

# CSS for formating the table
$global:GLOBALCss = @"
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20100%20100'%3E%3Ctext%20y='.9em'%20font-size='90'%3E%F0%9F%A6%85%3C/text%3E%3C/svg%3E">
<style>
    /* ======== Shared Styles ======== */
    html {
        scroll-behavior: smooth;
    }

    body {
        font-family: Arial, Helvetica, sans-serif;
        margin: 0;
        padding: 0;
        padding-left: 12px;
        padding-right: 12px;
    }

    table {
        width: auto;
        max-width: 100%;
        margin-top: 20px;
        border-collapse: collapse;
        font-size: 12px;
    }

    th {
        font-size: 11px;
        font-weight: bold;
        padding-top: 6px;
        padding-bottom: 6px;
        vertical-align: middle;
    }

	td {
        padding: 6px;
        max-width: 100%;
    }

    .overview-table td {
        text-align: center;
        padding: 6px;
        max-width: 100%;
    }
        
	.property-table th {
		font-size: 12px;
		padding-left: 8px;
		padding-right: 8px;
	}

    td.left-align {
        text-align: left;
    }

    thead input[data-filter] {
        width: auto;
        max-width: 90%;
        font-size: 11px;
        padding: 0px;
    }

    thead tr:first-child th {
        position: sticky;
        top: 50px;
        z-index: 2;
    }

    .copy-col-btn {
        position: absolute;
        top: 2px;
        right: 2px;
        opacity: 0;
        font-size: 9px;
        cursor: pointer;
        padding: 1px 2px;
        border-radius: 2px;
        transition: opacity 0.15s;
        user-select: none;
    }

    thead tr:first-child th:hover .copy-col-btn {
        opacity: 0.65;
    }

    .copy-col-btn:hover {
        opacity: 1 !important;
    }

    #mainTableContainer {
        padding: 0px 16px 5px 0px;
        max-width: fit-content;
        margin: 0;
    }

    #mainTableContainer table {
        width: 100%;
    }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        margin: 15px 0;
        gap: 12px 16px;
        flex-wrap: wrap;
    }

    .toolbar .left-section,
    .toolbar .right-section {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }

    .toolbar .right-section {
        margin-left: auto;
    }

    .page-size-label {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 14px;
        white-space: nowrap;
    }

    .info-box {
        font-size: 14px;
        white-space: nowrap;
        max-width: 100%;
    }

    @media (max-width: 900px) {
        .toolbar .left-section,
        .toolbar .right-section {
            width: 100%;
        }

        .toolbar .right-section {
            margin-left: 0;
            justify-content: flex-start;
        }

        .info-box {
            white-space: normal;
        }
    }

    .toolbar button,
    button {
        padding: 6px 10px;
        font-size: 14px;
        border-radius: 4px;
        border: 1px solid;
    }

    .toolbar select,
    select {
        padding: 6px 10px;
        font-size: 14px;
        border-radius: 4px;
        border: 1px solid;
    }

    .page-size-wrapper {
        display: inline-flex;
        align-items: center;
        position: relative;
        border: 1px solid;
        border-radius: 4px;
        overflow: hidden;
    }

    .page-size-icon {
        padding: 6px 5px 6px 10px;
        font-size: 14px;
        pointer-events: none;
    }

    .page-size-wrapper select {
        appearance: none;
        -webkit-appearance: none;
        border: none;
        border-radius: 0;
        padding: 6px 28px 6px 4px;
        font-size: 14px;
        background: transparent;
        cursor: pointer;
        outline: none;
    }

    .page-size-wrapper::after {
        content: "\25BC";
        position: absolute;
        right: 8px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 10px;
        pointer-events: none;
    }

    #paginationControls {
        margin-top: 16px;
    }

    #loadingOverlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(20, 20, 20, 0.85);
        z-index: 2000;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: #fff;
        font-size: 20px;
        font-weight: bold;
        backdrop-filter: blur(3px);
    }

    #loadingOverlay .spinner {
        border: 6px solid #ccc;
        border-top: 6px solid #4CAF50;
        border-radius: 50%;
        width: 60px;
        height: 60px;
        animation: spin 1s linear infinite;
        margin-bottom: 15px;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    /* -- Details Section -- */
    .details-toolbar {
        display: flex;
        align-items: center;
        margin: 12px 0;
        gap: 10px;
        padding: 0 0 8px 0;
        border-bottom: 1px solid;
    }

    .details-info {
        font-size: 13px;
        white-space: nowrap;
        margin-left: auto;
    }
    .column-toggle-wrapper {
        position: relative;
        display: inline-block;
        margin: 0;
    }

    .column-toggle-button {
        padding: 6px 10px;
        font-size: 14px;
        cursor: pointer;
        border-radius: 4px;
    }

    .column-toggle-menu {
        display: none;
        position: absolute;
        top: 110%;
        left: 0;
        padding: 8px;
        z-index: 1000;
        max-height: 200px;
        overflow-y: auto;
        min-width: 150px;
    }

    .column-toggle-wrapper.show .column-toggle-menu {
        display: block;
    }

    .column-toggle-menu label {
        display: block;
        white-space: nowrap;
        margin: 4px 0;
        font-size: 13px;
    }

    details {
        margin-bottom: 12px;
        border-radius: 8px;
        padding: 10px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.4);
        scroll-margin-top: var(--sticky-offset, 60px); /* Matches nav height */
    }

    summary {
        font-weight: bold;
        font-size: 14px;
        cursor: pointer;
    }

    pre.yaml-block {
        padding: 10px;
        border-radius: 6px;
        white-space: pre-wrap;
        font-family: Consolas, monospace;
        font-size: 12px;
        margin-top: 10px;
        overflow-x: auto;
    }

    .detail-note {
        font-size: 11px;
        font-style: italic;
        margin: 2px 0 8px 0;
        opacity: 0.75;
    }

    .cap-targeting-caption {
        font-size: 12px;
        font-weight: bold;
        margin: 16px 0 2px 0;
    }

    .cap-targeting-table {
        margin-top: 0;
    }

    .cap-targeting-muted {
        opacity: 0.65;
    }

    .cap-targeting-number {
        text-align: right;
        white-space: nowrap;
    }

    .cap-targeting-total td {
        font-weight: 700;
    }

    #toggle-expand {
        border-radius: 4px;
        padding: 5px 10px;
        cursor: pointer;
        font-size: 13px;
        white-space: nowrap;
    }

    .details-search-wrapper {
        display: flex;
        align-items: center;
        gap: 6px;
        max-width: 600px;
        min-width: 280px;
    }

    .details-search-box {
        position: relative;
        display: flex;
        flex: 1;
        min-width: 0;
    }

    #details-search {
        flex: 1;
        padding: 4px 28px 4px 8px;
        font-size: 13px;
        border-radius: 4px;
        border: 1px solid;
        min-width: 0;
    }

    .details-search-help-btn {
        position: absolute;
        right: 6px;
        top: 50%;
        transform: translateY(-50%);
        width: 18px;
        height: 18px;
        border-radius: 999px;
        border: 1px solid;
        background: transparent;
        font-size: 11px;
        font-weight: 700;
        line-height: 1;
        cursor: pointer;
        padding: 0;
    }

    .details-search-help-popover {
        position: absolute;
        left: 0;
        top: calc(100% + 6px);
        width: min(400px, 90vw);
        padding: 10px 12px;
        border-radius: 8px;
        border: 1px solid;
        z-index: 100;
        font-size: 12px;
    }

    .details-search-help-popover.hidden {
        display: none;
    }

    .details-search-help-popover .search-help-title {
        font-weight: 700;
        margin-bottom: 6px;
    }

    .details-search-help-popover .search-help-list {
        margin: 0;
        padding-left: 18px;
    }

    .details-search-help-popover .search-help-list li {
        margin: 2px 0;
    }

    #details-search-clear {
        padding: 4px 8px;
        font-size: 13px;
        border-radius: 4px;
        border: 1px solid;
        cursor: pointer;
        white-space: nowrap;
    }

    .detail-scope-toggle {
        display: flex;
        border-radius: 4px;
        overflow: hidden;
        border: 1px solid;
        white-space: nowrap;
    }

    .detail-scope-toggle .scope-btn {
        padding: 4px 10px;
        font-size: 13px;
        border: none;
        border-radius: 0;
        cursor: pointer;
    }

    .detail-scope-toggle .scope-btn + .scope-btn {
        border-left: 1px solid;
    }

    code {
        padding: 2px 5px;
        border-radius: 4px;
        font-family: Consolas, monospace;
        font-size: 90%;
    }

    .help-modal-overlay {
        position: fixed;
        inset: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(0, 0, 0, 0.6);
        display: none;
        z-index: 9999;
        justify-content: center;
        align-items: center;
        padding: 24px;
        box-sizing: border-box;
    }

    .help-modal-overlay.show {
        display: flex;
    }

    .help-modal-content {
        background: var(--nav-link-bg);
        color: var(--nav-link-text);
        padding: 24px;
        border-radius: 12px;
        max-width: 800px;
        width: min(90vw, 800px);
        max-height: calc(100vh - 48px);
        overflow-y: auto;
        box-shadow: 0 8px 16px rgba(0,0,0,0.4);
        font-size: 15px;
        line-height: 1.6;
        position: relative;
        box-sizing: border-box;
    }

    @supports (height: 100dvh) {
        .help-modal-content {
            max-height: calc(100dvh - 48px);
        }
    }

    .help-modal-content h2 {
        margin-top: 0;
    }

    .help-modal-content ul {
        margin-top: 6px;
    }

    .help-example-link {
        pointer-events: none;
    }

    .help-modal-close {
        margin-top: 16px;
        padding: 6px 12px;
        font-size: 14px;
        border-radius: 4px;
        border: 1px solid #aaa;
        cursor: pointer;
    }

    .preset-modal {
        position: fixed;
        top: 110px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        padding: 20px;
        border-radius: 12px;
        max-width: 480px;
        width: auto;
        background: var(--nav-link-bg);
        color: var(--nav-link-text);
        border: 1px solid var(--nav-link-hover-bg);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        display: none;
        flex-direction: column;
        gap: 10px;
    }

    .preset-modal-content {
        display: flex;
        flex-direction: column;
        max-height: 80vh;
        overflow: hidden;
    }

    .preset-modal-body {
        overflow-y: auto;
        flex: 1;
        display: flex;
        flex-direction: column;
    }

    .preset-modal-footer {
        flex-shrink: 0;
        padding-top: 10px;
        border-top: 1px solid var(--nav-link-hover-bg);
    }

    .preset-modal.show,
    .preset-modal:not(.hidden) {
        display: flex;
    }

    .preset-modal button {
        padding: 6px 12px;
        font-size: 14px;
        border-radius: 6px;
        cursor: pointer;
        border: 1px solid var(--nav-link-hover-bg);
        background-color: var(--nav-link-bg);
        color: var(--nav-link-text);
    }

    .preset-modal button:hover {
        background-color: var(--nav-link-hover-bg);
    }

    .preset-modal .preset-group-header {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        opacity: 0.45;
        padding: 10px 4px 2px;
        border-top: 1px solid var(--nav-link-hover-bg);
    }

    .preset-modal .preset-group-header.first {
        border-top: none;
        padding-top: 2px;
    }

    .preset-modal .preset-btn {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 8px 12px;
        text-align: left;
    }

    .preset-modal .preset-btn-label {
        font-size: 14px;
    }

    .preset-modal .preset-btn-sub {
        font-size: 11px;
        opacity: 0.55;
        font-weight: 400;
        line-height: 1.3;
    }

    /* ======== Dark Mode ======== */
    body.dark-mode {
        background-color: #121212;
        color: #E0E0E0;
    }

    body.dark-mode h1 {
        color: #bebebe;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.dark-mode h2 {
        color: #BB86FC;
        font-size: 24px;
        font-weight: bold;
    }

    body.dark-mode h3 {
        color: #03DAC6;
        font-size: 18px;
    }

    body.dark-mode table {
        background-color: #1E1E1E;
        color: #E0E0E0;
    }

    body.dark-mode th {
        background: #282a36;
        color: #E0E0E0;
        border: 1px solid #333;
    }

    body.dark-mode td {
        border: 1px solid #333;
    }

    body.dark-mode tbody tr:nth-child(even) {
        background-color: #1A1A1A;
    }

    body.dark-mode tbody tr:nth-child(odd) {
        background-color: #2A2A2A;
    }

    body.dark-mode tbody tr:hover td {
        background-color: #444 !important;
    }

    body.dark-mode a {
        color: #FFB74D;
        text-decoration: none;
    }

    body.dark-mode a:hover {
        color: #FF6F61;
        text-decoration: underline;
    }

    body.dark-mode .column-toggle-button {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode .column-toggle-menu {
        background: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #555;
        box-shadow: 0 2px 8px rgba(255, 255, 255, 0.05);
    }

    body.dark-mode .column-toggle-button:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select,
    body.dark-mode button,
    body.dark-mode .page-size-wrapper {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode select:hover,
    body.dark-mode button:hover,
    body.dark-mode .page-size-wrapper:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select:focus,
    body.dark-mode button:focus,
    body.dark-mode .page-size-wrapper:focus {
        outline: none;
        border-color: #888;
        box-shadow: 0 0 4px #888;
    }

    body.dark-mode details {
        background-color: #1c1c1c;
        border: 1px solid #333;
    }

    body.dark-mode pre.yaml-block {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #444;
    }

    body.dark-mode .details-toolbar {
        border-color: #2a2a2a;
    }

    body.dark-mode #toggle-expand {
        background-color: #333;
        color: #E0E0E0;
        border: 1px solid #666;
    }

    body.dark-mode #toggle-expand:hover {
        background-color: #444;
        border-color: #888;
    }

    body.dark-mode #details-search {
        background: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode #details-search::placeholder {
        color: #666;
    }

    body.dark-mode #details-search-clear {
        background: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode #details-search-clear:hover {
        background: #3a3a3a;
    }

    body.dark-mode .details-search-help-btn {
        border-color: rgba(255,255,255,0.28);
        color: #aaa;
    }

    body.dark-mode .details-search-help-btn:hover {
        background: rgba(255,255,255,0.1);
        color: #e0e0e0;
    }

    body.dark-mode .details-search-help-popover {
        background: #1e1e1e;
        border-color: #444;
        color: #e0e0e0;
        box-shadow: 0 8px 20px rgba(0,0,0,0.5);
    }

    body.dark-mode .detail-scope-toggle {
        border-color: #555;
    }

    body.dark-mode .detail-scope-toggle .scope-btn {
        background: #2a2a2a;
        color: #999;
        border-color: #555;
    }

    body.dark-mode .detail-scope-toggle .scope-btn:hover:not(.active) {
        background: #333;
        color: #ccc;
    }

    body.dark-mode .detail-scope-toggle .scope-btn.active {
        background: #1e3448;
        color: #8ab8e0;
    }

    body.dark-mode {
        --nav-bg: #1e1e1e;
        --nav-text: #fff;
        --nav-link-bg: #2a2a2a;
        --nav-link-text: #fff;
        --nav-link-hover-bg: #3a3a3a;
    }

    body.dark-mode code {
        background-color: #2e2e2e;
        color: #ff79c6; /* Bright pink/purple for dark contrast */
        border: 1px solid #444;
    }

    /* ======== Light Mode ======== */
    body.light-mode {
        background-color: white;
        color: black;
    }

    body.light-mode h1 {
        color: #e68a00;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.light-mode h2 {
        color: #3a3aec;
        font-size: 24px;
        font-weight: bold;
    }

    body.light-mode h3 {
        color: #000099;
        font-size: 18px;
    }

    body.light-mode th {
        background: #5d8fb8;
        color: #fff;
        border: 1px solid #d2d2d2;
    }

    body.light-mode td {
        border: 1px solid #d2d2d2;
    }

    body.light-mode tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    body.light-mode tbody tr:nth-child(odd) {
        background: white;
    }

    body.light-mode tbody tr:hover td {
        background-color: lightblue !important;
    }

    body.light-mode a {
        color: #0645AD;
        text-decoration: none;
    }

    body.light-mode a:hover {
        text-decoration: underline;
    }

    body.light-mode .column-toggle-button {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode .column-toggle-button:hover {
        background-color: #e0e0e0;
    }

    body.light-mode .column-toggle-menu {
        background: #fff;
        color: #000;
        border: 1px solid #ccc;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    body.light-mode select,
    body.light-mode button,
    body.light-mode .page-size-wrapper {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode select:hover,
    body.light-mode button:hover,
    body.light-mode .page-size-wrapper:hover {
        background-color: #e0e0e0;
    }

    body.light-mode select:focus,
    body.light-mode button:focus,
    body.light-mode .page-size-wrapper:focus {
        outline: none;
        border-color: #666;
        box-shadow: 0 0 4px #aaa;
    }

    body.light-mode details {
        background-color: rgb(250, 250, 250);
        border: 1px solid #333;
        box-shadow: 0 1px 4px rgb(213, 223, 231);
    }

    body.light-mode pre.yaml-block {
        background-color: rgb(205, 209, 211);
        border: 1px solid #444;
        color: #000;
    }

    body.light-mode .details-toolbar {
        border-color: #ddd;
    }

    body.light-mode #toggle-expand {
        background-color: rgb(231, 229, 229);
        color: #000;
        border: 1px solid #666;
    }

    body.light-mode #toggle-expand:hover {
        background-color: #e0e0e0;
        border-color: #888;
    }

    body.light-mode #details-search {
        background: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode #details-search::placeholder {
        color: #999;
    }

    body.light-mode #details-search-clear {
        background: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode #details-search-clear:hover {
        background: #e0e0e0;
    }

    body.light-mode .details-search-help-btn {
        border-color: rgba(0,0,0,0.25);
        color: #888;
    }

    body.light-mode .details-search-help-btn:hover {
        background: rgba(0,0,0,0.07);
        color: #444;
    }

    body.light-mode .details-search-help-popover {
        background: #fff;
        border-color: #ccc;
        color: #222;
        box-shadow: 0 8px 20px rgba(0,0,0,0.12);
    }

    body.light-mode .detail-scope-toggle {
        border-color: #ccc;
    }

    body.light-mode .detail-scope-toggle .scope-btn {
        background: #f4f4f4;
        color: #888;
        border-color: #ccc;
    }

    body.light-mode .detail-scope-toggle .scope-btn:hover:not(.active) {
        background: #e8e8e8;
        color: #444;
    }

    body.light-mode .detail-scope-toggle .scope-btn.active {
        background: #ddeeff;
        color: #1a4a7a;
    }

    body.light-mode {
        --nav-bg: #f9f9f9;
        --nav-text: #000;
        --nav-link-bg: #e0e0e0;
        --nav-link-text: #000;
        --nav-link-hover-bg: #ccc;
    }
    body.light-mode code {
        background-color: #f2f2f2;
        color: #d6336c;
        border: 1px solid #ddd;
    }

    /* ======== Report header + report tabs + section strip + warnings drawer ======== */
    :root{ --report-header-offset: 120px; }

    /* Fixed nav stack */
    #nav-stack{
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 2000;
        box-shadow: 0 6px 22px rgba(0,0,0,0.08);
    }

    body.light-mode #nav-stack{ background: #ffffff; }
    body.dark-mode  #nav-stack{ background: #181818; }

    /* Compact command bar */
    #report-header{
        position: relative !important;
        top: auto !important;
        display: grid;
        grid-template-columns: minmax(260px, 1fr) auto;
        gap: 10px;
        align-items: center;
        padding: 7px 12px;
        border-bottom: 1px solid rgba(0,0,0,0.10);
        background: #ffffff;
    }
    body.dark-mode #report-header{
        background: #181818;
        border-bottom: 1px solid rgba(255,255,255,0.10);
    }

    .hdr-left{
        display:flex;
        flex-direction:column;
        gap:2px;
        min-width: 0;
    }
    .hdr-title{
        display:flex;
        align-items:baseline;
        gap:10px;
        min-width: 0;
    }
    .hdr-name{
        font-size: 15px;
        font-weight: 800;
        line-height: 1.2;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .hdr-sub{
        display:flex;
        flex-wrap:nowrap;
        align-items:center;
        gap:7px;
        min-width: 0;
        font-size: 11.5px;
        line-height: 1.25;
        opacity: 0.86;
    }
    .hdr-meta{
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .hdr-dot{ opacity: 0.45; }

    .hdr-center{ display:none; }

    .hdr-right{
        display:flex;
        align-items:center;
        gap: 6px;
        flex-wrap: wrap;
        justify-content: flex-end;
        min-width: 0;
    }

    /* Buttons in header */
    .hdr-btn{
        height: 30px;
        padding: 0 9px;
        font-size: 12.5px;
        font-weight: 600;
        border-radius: 8px;
        border: 1px solid transparent;
        background: transparent;
        color: inherit;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        line-height: 28px;
        box-sizing: border-box;
        white-space: nowrap;
    }
    #hdr-actions button{
        height: 30px;
        line-height: 28px;
        padding: 0 9px;
        font-size: 12.5px;
        border-radius: 8px;
        box-sizing: border-box;
    }

    body.light-mode .hdr-btn{
        border-color: rgba(0,0,0,0.14);
        background: rgba(0,0,0,0.025);
    }
    body.light-mode .hdr-btn:hover{ background: rgba(0,0,0,0.06); }

    body.dark-mode .hdr-btn{
        border-color: rgba(255,255,255,0.14);
        background: rgba(255,255,255,0.06);
    }
    body.dark-mode .hdr-btn:hover{ background: rgba(255,255,255,0.11); }

    /* Report tab strip */
    #report-tabstrip{
        position: relative !important;
        top: auto !important;
        z-index: 999;
        border-bottom: 1px solid rgba(0,0,0,0.10);
        background: #f7faf9;
    }
    body.dark-mode #report-tabstrip{
        background: #202020;
        border-bottom: 1px solid rgba(255,255,255,0.09);
    }
    .tabstrip-inner{
        display: flex;
        gap: 3px;
        align-items: center;
        padding: 4px 12px;
        overflow-x: auto;
        overflow-y: hidden;
        overscroll-behavior-x: contain;
        scrollbar-width: thin;
        white-space: nowrap;
    }
    .tabstrip-inner::-webkit-scrollbar{ height: 8px; }
    .tabstrip-inner::-webkit-scrollbar-thumb{ border-radius: 8px; }
    body.light-mode .tabstrip-inner::-webkit-scrollbar-thumb{ background: rgba(0,0,0,0.18); }
    body.dark-mode  .tabstrip-inner::-webkit-scrollbar-thumb{ background: rgba(255,255,255,0.18); }

    .report-tab{
        display: inline-flex;
        align-items: center;
        min-height: 30px;
        padding: 0 9px;
        font-size: 12.5px;
        font-weight: 600;
        letter-spacing: 0;
        color: inherit;
        text-decoration: none;
        white-space: nowrap;
        border: 1px solid transparent;
        border-radius: 8px;
        background: transparent;
        flex: 0 0 auto;
    }
    body.light-mode .report-tab:hover{
        background: #eef3f2;
        border-color: rgba(0,0,0,0.10);
    }
    body.dark-mode .report-tab:hover{
        background: rgba(255,255,255,0.08);
        border-color: rgba(255,255,255,0.12);
    }

    body.light-mode .report-tab.active{
        background: #e2f1ef;
        border-color: #9fcfca;
        color: #004f4b;
    }
    body.dark-mode .report-tab.active{
        background: rgba(220,225,225,0.14);
        border-color: rgba(220,225,225,0.30);
        color: #f4f6f6;
    }

    /* Warnings badge */
    .hdr-warn-btn{ position: relative; }
    body.light-mode .hdr-warn-btn{
        border-color: rgba(160, 90, 0, 0.28);
        background: rgba(160, 90, 0, 0.08);
        color: #704000;
    }
    body.dark-mode .hdr-warn-btn{
        border-color: rgba(255, 180, 80, 0.28);
        background: rgba(255, 180, 80, 0.10);
        color: #ffdca8;
    }
    .hdr-warn-count{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 18px;
        height: 18px;
        padding: 0 5px;
        margin-left: 2px;
        border-radius: 8px;
        font-size: 11.5px;
        line-height: 18px;
        font-weight: 800;
    }
    body.light-mode .hdr-warn-count{
        background: rgba(160, 90, 0, 0.14);
        border: 1px solid rgba(160, 90, 0, 0.30);
    }
    body.dark-mode .hdr-warn-count{
        background: rgba(255, 180, 80, 0.14);
        border: 1px solid rgba(255, 180, 80, 0.28);
    }

    @media (max-width: 900px){
        #report-header{
            grid-template-columns: 1fr;
            align-items: start;
        }
        .hdr-right{
            justify-content: flex-start;
        }
        .hdr-sub{
            flex-wrap: wrap;
        }
    }

    /* Warnings drawer */
    .contents-backdrop{
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.45);
    z-index: 2000;
    }
    .contents-drawer{
    position: fixed;
    top: 0;
    right: 0;
    height: 100vh;
    width: min(360px, 92vw);
    background: rgba(22,22,22,0.98);
    color: inherit;
    border-left: 1px solid rgba(255,255,255,0.10);
    transform: translateX(100%);
    transition: transform 180ms ease;
    z-index: 2001;
    }
    .contents-drawer.open{ transform: translateX(0); }
    .contents-drawer-inner{
    height: 100%;
    display: flex;
    flex-direction: column;
    }
    .contents-drawer-header{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    border-bottom: 1px solid rgba(255,255,255,0.10);
    }
    .contents-drawer-title{
    font-size: 14px;
    font-weight: 650;
    letter-spacing: 0.2px;
    }
    .warnings-body{ padding: 12px 16px 16px; }
    .warnings-list{ margin: 0; padding-left: 18px; }
    .warnings-list li{ margin: 8px 0; line-height: 1.35; }
    .warnings-empty{ opacity: 0.8; font-size: 13px; padding: 10px 0; }

    /* Force-hide warnings button when hidden attribute is set */
    #hdrWarningsBtn[hidden]{
        display: none !important;
    }


    /* Warnings drawer: light mode */
    body.light-mode .contents-drawer{
        background: rgba(255,255,255,0.98);
        color: rgba(0,0,0,0.92);
        border-left: 1px solid rgba(0,0,0,0.14);
    }

    body.light-mode .contents-drawer-header{
        border-bottom: 1px solid rgba(0,0,0,0.12);
    }

    body.light-mode .warnings-empty{
        opacity: 0.85;
    }

    /* Optional: backdrop slightly lighter in light mode */
    body.light-mode .contents-backdrop{
        background: rgba(0,0,0,0.25);
    }

    /* Optional: ensure the Close button is readable in light mode */
    body.light-mode .contents-drawer .hdr-btn{
        border: 1px solid rgba(0,0,0,0.16);
        background: rgba(0,0,0,0.03);
        color: rgba(0,0,0,0.92);
    }
    body.light-mode .contents-drawer .hdr-btn:hover{
        background: rgba(0,0,0,0.06);
    }



    /* Section strip */
    #section-strip{
        position: relative !important;
        top: auto !important;
        z-index: 998;
        border-bottom: 1px solid rgba(0,0,0,0.08);
    }
    body.light-mode #section-strip{ background: #ffffff; }
    body.dark-mode  #section-strip{
        background: #181818;
        border-bottom-color: rgba(255,255,255,0.08);
    }

    .section-strip-inner{
        display: flex;
        gap: 5px;
        align-items: center;
        overflow-x: auto;
        overflow-y: hidden;
        white-space: nowrap;
        padding: 4px 12px;
        scrollbar-width: thin;
    }
    .section-strip-inner::-webkit-scrollbar{ height: 6px; }
    .section-strip-inner::-webkit-scrollbar-thumb{ border-radius: 8px; }
    body.light-mode .section-strip-inner::-webkit-scrollbar-thumb{ background: rgba(0,0,0,0.18); }
    body.dark-mode  .section-strip-inner::-webkit-scrollbar-thumb{ background: rgba(255,255,255,0.18); }

    .section-link{
        display: inline-flex;
        align-items: center;
        min-height: 24px;
        padding: 0 8px;
        border: 1px solid transparent;
        border-radius: 8px;
        text-decoration: none;
        font-size: 11.5px;
        font-weight: 600;
        opacity: 0.82;
        flex: 0 0 auto;
    }
    .section-link:hover{ opacity: 1; }
    body.light-mode .section-link:hover{
        background: #eef3f2;
        border-color: rgba(0,0,0,0.10);
    }
    body.dark-mode .section-link:hover{
        background: rgba(255,255,255,0.08);
        border-color: rgba(255,255,255,0.12);
    }
    .section-link.active{
        opacity: 1;
    }
    body.light-mode .section-link.active{
        background: #e2f1ef;
        border-color: #9fcfca;
        color: #004f4b;
    }
    body.dark-mode .section-link.active{
        background: rgba(220,225,225,0.14);
        border-color: rgba(220,225,225,0.30);
        color: #f4f6f6;
    }
    .section-sep{ display:none; }

    @media (min-width: 901px) and (max-width: 1600px) {
        .tabstrip-inner {
            flex-wrap: wrap;
            align-content: center;
            gap: 3px;
            padding: 4px 8px;
            overflow-x: visible;
            overflow-y: visible;
            white-space: normal;
            scrollbar-width: none;
        }

        .tabstrip-inner::-webkit-scrollbar {
            display: none;
        }

        .report-tab {
            min-height: 26px;
            padding: 0 7px;
            font-size: 11.5px;
            border-radius: 7px;
        }

        .section-strip-inner {
            flex-wrap: wrap;
            align-content: center;
            gap: 4px;
            padding: 4px 8px;
            overflow-x: visible;
            overflow-y: visible;
            white-space: normal;
            scrollbar-width: none;
        }

        .section-strip-inner::-webkit-scrollbar {
            display: none;
        }

        .section-link {
            min-height: 22px;
            padding: 0 7px;
            font-size: 11px;
            border-radius: 7px;
            white-space: nowrap;
        }
    }


    /* Make native form popups prefer the active color scheme */
    body.dark-mode {
        color-scheme: dark;
    }

    body.light-mode {
        color-scheme: light;
    }

    body.light-mode .section-link{ color: rgba(0,0,0,0.88); }
    body.dark-mode  .section-link{ color: rgba(255,255,255,0.88); }

    /* Make anchors work with the new fixed stack */
    h2{ scroll-margin-top: var(--report-header-offset, 120px); }
    thead tr:first-child th{ top: var(--report-header-offset, 120px); }
    details{ scroll-margin-top: var(--report-header-offset, 120px); }

</style>
"@

$global:GLOBALJavaScript = $global:GLOBALJavaScript_Table + "`n" + $global:GLOBALJavaScript_Nav

$global:GLOBALReportManifestScript = ''

############################## Internal function section ########################

# Fucntion to get the highest tier level of the assigned roles
function Get-HighestTierLabel {
    param (
        [Parameter(Mandatory = $false)]
        [Object[]]$Assignments
    )

    if (-not $Assignments -or $Assignments.Count -lt 1) {
        return "-"
    }

    $tierNumbers = @()
    $hasUnknown = $false

    foreach ($assignment in $Assignments) {
        $tier = $assignment.RoleTier
        if ($null -eq $tier) {
            continue
        }
        if ($tier -is [string] -and [string]::IsNullOrWhiteSpace($tier)) {
            continue
        }

        if ($tier -is [int]) {
            $tierNumbers += $tier
            continue
        }

        if ($tier -is [string]) {
            if ($tier -match '^Tier-(\d+)$') {
                $tierNumbers += [int]$Matches[1]
            } elseif ($tier -match '^\d+$') {
                $tierNumbers += [int]$tier
            } elseif ($tier -eq "?") {
                $hasUnknown = $true
            }
        }
    }

    if ($tierNumbers.Count -gt 0) {
        $minTier = ($tierNumbers | Measure-Object -Minimum).Minimum
        return "Tier-$minTier"
    }

    if ($hasUnknown) {
        return "?"
    }

    return "-"
}

function Resolve-TierLabel {
    param (
        [Parameter(Mandatory = $false)]
        [object]$TierLabel
    )

    if ($null -eq $TierLabel) { return "-" }
    if ($TierLabel -is [int]) { return "Tier-$TierLabel" }

    $value = "$TierLabel".Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return "-" }

    if ($value -match '^Tier-(\d+)$') { return "Tier-$($Matches[1])" }
    if ($value -match '^\d+$') { return "Tier-$value" }
    if ($value -eq "?") { return "?" }
    if ($value -eq "-") { return "-" }

    return "-"
}

function Get-TierPriority {
    param (
        [Parameter(Mandatory = $false)]
        [object]$TierLabel
    )

    $resolved = Resolve-TierLabel -TierLabel $TierLabel
    if ($resolved -match '^Tier-(\d+)$') { return [int]$Matches[1] }
    if ($resolved -eq "?") { return 98 }
    return 99
}

function Merge-HigherTierLabel {
    param (
        [Parameter(Mandatory = $false)]
        [object]$CurrentTier,
        [Parameter(Mandatory = $false)]
        [object]$CandidateTier
    )

    $currentResolved = Resolve-TierLabel -TierLabel $CurrentTier
    $candidateResolved = Resolve-TierLabel -TierLabel $CandidateTier

    if ($candidateResolved -eq "-") { return $currentResolved }

    if ((Get-TierPriority -TierLabel $candidateResolved) -lt (Get-TierPriority -TierLabel $currentResolved)) {
        return $candidateResolved
    }

    return $currentResolved
}

# Returns normalized group metadata from the cached AllGroupsDetails hashtable for membership and ownership inheritance paths.
function Get-GroupDetails {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$Group,
        [Parameter(Mandatory = $true)]
        [hashtable]$AllGroupsDetails
    )

    $GroupDetails = @()
    $MatchingGroup = $AllGroupsDetails[$($Group.id)]

    if (($MatchingGroup | Measure-Object).count -ge 1) {
        $GroupDetails = [PSCustomObject]@{
            Type                   = "Group"
            Id                     = $Group.Id
            DisplayName            = $Group.DisplayName
            Visibility             = $MatchingGroup.Visibility
            GroupType              = $MatchingGroup.Type
            SecurityEnabled        = $MatchingGroup.SecurityEnabled
            RoleAssignable         = $MatchingGroup.RoleAssignable
            AssignedRoleCount      = $MatchingGroup.EntraRoles
            AssignedPrivilegedRoles= $MatchingGroup.EntraRolePrivilegedCount
            InheritedHighValue     = $MatchingGroup.InheritedHighValue
            EntraMaxTier           = $MatchingGroup.EntraMaxTier
            EntraRoleDetails       = $MatchingGroup.EntraRoleDetails
            AzureRoles             = $MatchingGroup.AzureRoles
            AzureMaxTier           = $MatchingGroup.AzureMaxTier
            AzureRoleDetails       = $MatchingGroup.AzureRoleDetails
            CAPs                   = $MatchingGroup.CAPs
            Impact                 = $MatchingGroup.Impact
            ImpactOrg              = $MatchingGroup.ImpactOrg
            ImpactOrgActiveOnly    = $MatchingGroup.ImpactOrgActiveOnly
            Warnings               = $MatchingGroup.Warnings
        }
    }

    return $GroupDetails
}

# Returns normalized group role metrics (count, privileged count, and max tier) for active-only or active+eligible evaluation paths.
function Get-GroupActiveRoleMetrics {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$Group,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Entra", "Azure")]
        [string]$RoleSystem,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeEligible
    )

    $detailsProperty = if ($RoleSystem -eq "Entra") { "EntraRoleDetails" } else { "AzureRoleDetails" }
    $details = @($Group.$detailsProperty | Where-Object { $null -ne $_ })

    if ($details.Count -gt 0) {
        $assignmentsInScope = @(
            if ($IncludeEligible) {
                $details
            } else {
                $details | Where-Object { $_.AssignmentType -eq "Active" }
            }
        )
        $roleCount = @($assignmentsInScope).Count

        return [PSCustomObject]@{
            RoleCount       = $roleCount
            PrivilegedCount = if ($RoleSystem -eq "Entra") { @($assignmentsInScope | Where-Object { $_.IsPrivileged -eq $true }).Count } else { 0 }
            MaxTier         = Get-HighestTierLabel -Assignments $assignmentsInScope
            Source          = if ($IncludeEligible) { "DetailsAll" } else { "DetailsActive" }
        }
    }

    # Ownership path can rely on group summary counters that already include inherited role context.
    if ($IncludeEligible) {
        if ($RoleSystem -eq "Entra") {
            $roleCount = 0
            [void][int]::TryParse([string]$Group.AssignedRoleCount, [ref]$roleCount)
            $privilegedCount = 0
            [void][int]::TryParse([string]$Group.AssignedPrivilegedRoles, [ref]$privilegedCount)
            $maxTier = if ($roleCount -gt 0 -and $Group.EntraMaxTier) { $Group.EntraMaxTier } else { "-" }
        } else {
            $roleCount = 0
            [void][int]::TryParse([string]$Group.AzureRoles, [ref]$roleCount)
            $privilegedCount = 0
            $maxTier = if ($roleCount -gt 0 -and $Group.AzureMaxTier) { $Group.AzureMaxTier } else { "-" }
        }

        return [PSCustomObject]@{
            RoleCount       = $roleCount
            PrivilegedCount = $privilegedCount
            MaxTier         = $maxTier
            Source          = "SummaryAll"
        }
    }

    return [PSCustomObject]@{
        RoleCount       = 0
        PrivilegedCount = 0
        MaxTier         = "-"
        Source          = "NoDetails"
    }
}

# Returns the host operating system name in a normalized format.
function Get-EntraFalconHostOs {
    [CmdletBinding()]
    param()

    if ((Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and [bool]$IsWindows) { return "Windows" }
    if ((Get-Variable -Name IsLinux -ErrorAction SilentlyContinue) -and [bool]$IsLinux) { return "Linux" }
    if ((Get-Variable -Name IsMacOS -ErrorAction SilentlyContinue) -and [bool]$IsMacOS) { return "macOS" }

    try {
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) { return "Windows" }
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) { return "Linux" }
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) { return "macOS" }
    } catch {
        # Continue with string-based fallback.
    }

    $osString = [string]$PSVersionTable.OS
    if ($osString -match "Windows") { return "Windows" }
    if ($osString -match "Darwin|macOS|Mac OS") { return "macOS" }
    if ($osString -match "Linux") { return "Linux" }

    return "Unknown"
}

# Validates whether the selected auth flow is supported on non-Windows systems.
function Test-NonWindowsAuthFlowCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("BroCi", "AuthCode", "DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken", "ServicePrincipal")]
        [string]$AuthFlow = "BroCi",

        [Parameter(Mandatory = $false)]
        [string]$ReadmePath = "README.md"
    )

    $hostOs = Get-EntraFalconHostOs
    if ($hostOs -eq "Windows") {
        return $true
    }

    $nonWindowsSupportedFlows = @("DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken", "ServicePrincipal")
    if ($nonWindowsSupportedFlows -contains $AuthFlow) {
        return $true
    }

    $flowDisplay = @{
        "BroCi" = "BroCi"
        "AuthCode" = "Auth Code Flow"
        "DeviceCode" = "Device Code Flow"
        "ManualCode" = "Auth Code + Manual Code Flow"
        "BroCiManualCode" = "BroCi + Manual Code Flow"
        "BroCiToken" = "BroCi with Token"
        "ServicePrincipal" = "Client Credentials (App Only)"
    }

    $flowHint = @{
        "BroCi" = "-AuthFlow BroCi"
        "AuthCode" = "-AuthFlow AuthCode"
        "DeviceCode" = "-AuthFlow DeviceCode"
        "ManualCode" = "-AuthFlow ManualCode"
        "BroCiManualCode" = "-AuthFlow BroCiManualCode"
        "BroCiToken" = '-AuthFlow BroCiToken -BroCiToken "<refresh_token>"'
        "ServicePrincipal" = '-AuthFlow ServicePrincipal -SPClientId "<id>" -SPClientSecret "<secret>"'
    }

    $selectedDisplay = if ($flowDisplay.ContainsKey($AuthFlow)) { $flowDisplay[$AuthFlow] } else { $AuthFlow }
    $selectedHint = if ($flowHint.ContainsKey($AuthFlow)) { $flowHint[$AuthFlow] } else { "(custom)" }

    Write-Host ""
    Write-Host "[!] The current auth flow is not supported on $hostOs." -ForegroundColor Red
    Write-Host "[!] Selected flow: $selectedDisplay ($selectedHint)" -ForegroundColor Red
    Write-Host "[i] Supported non-Windows alternatives (Linux/macOS) are:" -ForegroundColor Yellow
    Write-Host "    - Auth Code + Manual Code Flow: -AuthFlow ManualCode"
    Write-Host "    - BroCi + Manual Code Flow: -AuthFlow BroCiManualCode"
    Write-Host "    - BroCi with Token: -AuthFlow BroCiToken -BroCiToken `"<refresh_token>`""
    Write-Host "    - Device Code Flow: -AuthFlow DeviceCode"
    Write-Host "[i] See '$ReadmePath' for more details."

    return $false
}

function Export-EntraFalconSecurityFindingsJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $true)]
        [string]$StartTimestamp,

        [Parameter(Mandatory = $true)]
        [object]$CurrentTenant,

        [Parameter(Mandatory = $true)]
        [object]$SecurityFindings
    )

    function ConvertTo-FindingsExportText {
        param(
            [object]$Value,
            [string]$Fallback = ""
        )

        $text = if ($null -eq $Value) { "" } else { [string]$Value }
        $text = $text.Trim()
        if ($text) { return $text }
        return $Fallback
    }

    function ConvertTo-FindingsExportFilePart {
        param(
            [object]$Value,
            [string]$Fallback
        )

        $text = ConvertTo-FindingsExportText -Value $Value -Fallback $Fallback
        $text = $text -replace '[<>:"/\\|?*\x00-\x1F]', '_'
        $text = $text -replace '\s+', '_'
        $text = $text -replace '_+', '_'
        $text = $text.Trim('_')
        if ([string]::IsNullOrWhiteSpace($text)) { return $Fallback }
        return $text
    }

    function ConvertFrom-FindingsExportHtml {
        param([object]$Value)

        if ($null -eq $Value) { return "" }

        $html = [string]$Value
        if ([string]::IsNullOrWhiteSpace($html)) { return "" }

        $normalized = $html `
            -replace '\r\n?', "`n" `
            -replace '<\s*br\s*/?>', "`n" `
            -replace '<\s*/p\s*>', "`n`n" `
            -replace '<\s*p[^>]*>', "" `
            -replace '<\s*li[^>]*>', "- " `
            -replace '<\s*/li\s*>', "`n" `
            -replace '<\s*/(?:ul|ol)\s*>', "`n" `
            -replace '<\s*(?:ul|ol)[^>]*>', "" `
            -replace '<\s*/div\s*>', "`n" `
            -replace '<\s*div[^>]*>', ""

        $text = $normalized -replace '<[^>]+>', ""
        $text = [System.Net.WebUtility]::HtmlDecode($text)
        $text = $text `
            -replace ([string][char]0x00A0), " " `
            -replace "[ `t]+`n", "`n" `
            -replace "`n[ `t]+", "`n" `
            -replace "`n{3,}", "`n`n"

        return $text.Trim()
    }

    function Split-FindingsExportMultiValue {
        param(
            [string]$Key,
            [object]$Value
        )

        $text = (ConvertTo-FindingsExportText -Value $Value) -replace '\r\n?', "`n"
        $text = $text.Trim()
        if (-not $text) { return @() }

        $lineParts = @($text -split "`n+" | ForEach-Object {
            ($_ -replace '^\s*-\s*', '').Trim()
        } | Where-Object { $_ })
        if ($lineParts.Count -gt 1) { return $lineParts }

        $keyHint = [regex]::IsMatch((ConvertTo-FindingsExportText -Value $Key), 'owner|owners|member|members|role|roles|permission|permissions|group|groups|warning|warnings|api permissions', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        if ($keyHint -and $text.Contains(';')) {
            $semicolonParts = @($text -split '\s*;\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($semicolonParts.Count -gt 1) { return $semicolonParts }
        }

        if ($keyHint -and $text.Contains(',') -and -not $text.Contains(':')) {
            $commaParts = @($text -split '\s*,\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($commaParts.Count -gt 1) { return $commaParts }
        }

        return @($text)
    }

    function Get-FindingsExportPropertyNames {
        param([object]$Object)

        if ($null -eq $Object) { return @() }
        if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { [string]$_ }) }
        return @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    }

    function Get-FindingsExportPropertyValue {
        param(
            [object]$Object,
            [string]$Name
        )

        if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) { return $Object[$Name] }
            return $null
        }
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    function Test-FindingsExportObjectValue {
        param([object]$Value)

        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return $false }
        if ($Value -is [System.Collections.IDictionary]) { return $true }
        if ($Value -is [System.ValueType]) { return $false }
        if ($Value -is [System.Collections.IEnumerable]) { return $false }
        return ($null -ne $Value.PSObject -and $Value.PSObject.Properties.Count -gt 0)
    }

    function ConvertTo-FindingsExportJsonString {
        param([object]$Value)

        if ($null -eq $Value) { return "" }
        return ($Value | ConvertTo-Json -Depth 20 -Compress)
    }

    function ConvertTo-FindingsExportScalarValue {
        param([object]$Value)

        if ($null -eq $Value) { return $null }
        if ($Value -is [byte] -or
            $Value -is [sbyte] -or
            $Value -is [int16] -or
            $Value -is [uint16] -or
            $Value -is [int] -or
            $Value -is [uint32] -or
            $Value -is [long] -or
            $Value -is [uint64]) {
            return $Value
        }
        if ($Value -is [float] -or $Value -is [double] -or $Value -is [decimal]) {
            $number = [decimal]$Value
            if ($number -ge [decimal][long]::MinValue -and $number -le [decimal][long]::MaxValue -and [decimal]::Truncate($number) -eq $number) {
                return [long]$number
            }
            return $Value
        }
        return $Value
    }

    function ConvertTo-FindingsExportAffectedObject {
        param([object]$Object)

        if (-not (Test-FindingsExportObjectValue -Value $Object)) { return $Object }

        $clean = [ordered]@{}
        foreach ($key in Get-FindingsExportPropertyNames -Object $Object) {
            if (-not $key -or $key[0] -eq '_') { continue }

            $value = Get-FindingsExportPropertyValue -Object $Object -Name $key

            if ($key -eq "Warnings") {
                if ($null -eq $value) {
                    $clean[$key] = ""
                } elseif ($value -is [string]) {
                    $clean[$key] = ConvertFrom-FindingsExportHtml -Value $value
                } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [System.Collections.IDictionary])) {
                    $warningParts = New-Object System.Collections.Generic.List[string]
                    foreach ($entry in @($value)) {
                        if ($null -eq $entry) { continue }
                        if ($entry -is [string]) {
                            $warningParts.Add((ConvertFrom-FindingsExportHtml -Value $entry))
                        } elseif (Test-FindingsExportObjectValue -Value $entry) {
                            $warningParts.Add((ConvertTo-FindingsExportJsonString -Value (ConvertTo-FindingsExportAffectedObject -Object $entry)))
                        } else {
                            $warningParts.Add([string]$entry)
                        }
                    }
                    $clean[$key] = ($warningParts -join " / ")
                } elseif (Test-FindingsExportObjectValue -Value $value) {
                    $clean[$key] = ConvertTo-FindingsExportJsonString -Value (ConvertTo-FindingsExportAffectedObject -Object $value)
                } else {
                    $clean[$key] = [string]$value
                }
                continue
            }

            if ($null -eq $value) {
                $clean[$key] = ""
            } elseif ($value -is [string]) {
                $plainText = ConvertFrom-FindingsExportHtml -Value $value
                $split = @(Split-FindingsExportMultiValue -Key $key -Value $plainText)
                $clean[$key] = if ($split.Count -gt 1) { $split } elseif ($split.Count -eq 1) { $split[0] } else { "" }
            } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [System.Collections.IDictionary])) {
                $entries = @($value)
                if ($entries.Count -eq 0) {
                    $clean[$key] = @()
                    continue
                }

                $objectEntries = @($entries | Where-Object { Test-FindingsExportObjectValue -Value $_ })
                if ($objectEntries.Count -eq $entries.Count) {
                    $clean[$key] = @($objectEntries | ForEach-Object { ConvertTo-FindingsExportAffectedObject -Object $_ })
                    continue
                }

                $scalarEntries = New-Object System.Collections.Generic.List[object]
                foreach ($entry in $entries) {
                    if ($null -eq $entry) { continue }
                    if ($entry -is [string]) {
                        foreach ($part in @(Split-FindingsExportMultiValue -Key $key -Value (ConvertFrom-FindingsExportHtml -Value $entry))) {
                            $scalarEntries.Add($part)
                        }
                    } elseif (Test-FindingsExportObjectValue -Value $entry) {
                        $scalarEntries.Add((ConvertTo-FindingsExportJsonString -Value (ConvertTo-FindingsExportAffectedObject -Object $entry)))
                    } else {
                        $scalarEntries.Add([string]$entry)
                    }
                }
                $clean[$key] = if ($scalarEntries.Count -gt 1) { @($scalarEntries) } elseif ($scalarEntries.Count -eq 1) { $scalarEntries[0] } else { "" }
            } elseif (Test-FindingsExportObjectValue -Value $value) {
                $clean[$key] = ConvertTo-FindingsExportAffectedObject -Object $value
            } else {
                $clean[$key] = ConvertTo-FindingsExportScalarValue -Value $value
            }
        }

        return [pscustomobject]$clean
    }

    function Get-FindingsExportAffectedSortKey {
        param(
            [object[]]$Objects,
            [string]$RequestedSortKey
        )

        $allColumns = New-Object System.Collections.Generic.List[string]
        $seenColumns = @{}

        foreach ($object in @($Objects)) {
            foreach ($column in Get-FindingsExportPropertyNames -Object $object) {
                if (-not $column -or $seenColumns.ContainsKey($column)) { continue }
                $seenColumns[$column] = $true
                $allColumns.Add($column)
            }
        }

        $visibleColumns = @($allColumns | Where-Object { $_ -and $_[0] -ne '_' })
        $sortKey = ""
        if (-not [string]::IsNullOrWhiteSpace($RequestedSortKey)) {
            $desired = $RequestedSortKey.ToLowerInvariant()
            $sortKey = [string](@($allColumns | Where-Object { $_.ToLowerInvariant() -eq $desired } | Select-Object -First 1))
            if (-not $sortKey) {
                $sortKey = [string](@($allColumns | Where-Object { $_.ToLowerInvariant().Contains($desired) } | Select-Object -First 1))
            }
        }
        if (-not $sortKey -and $visibleColumns.Count -gt 0) { $sortKey = [string]$visibleColumns[0] }
        return $sortKey
    }

    function Compare-FindingsExportAffectedObject {
        param(
            [object]$A,
            [object]$B,
            [string]$SortKey,
            [int]$SortDirection
        )

        $av = (ConvertFrom-FindingsExportHtml -Value (ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $A -Name $SortKey))).Trim()
        $bv = (ConvertFrom-FindingsExportHtml -Value (ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $B -Name $SortKey))).Trim()
        $aMissing = ($av -eq "" -or $av -eq "?")
        $bMissing = ($bv -eq "" -or $bv -eq "?")
        if ($aMissing -and -not $bMissing) { return 1 }
        if (-not $aMissing -and $bMissing) { return -1 }

        $aNumber = 0.0
        $bNumber = 0.0
        $aIsNumber = [regex]::IsMatch($av, '^-?\d+(\.\d+)?$')
        $bIsNumber = [regex]::IsMatch($bv, '^-?\d+(\.\d+)?$')
        if ($aIsNumber -and $bIsNumber) {
            $aNumber = [double]::Parse($av, [System.Globalization.CultureInfo]::InvariantCulture)
            $bNumber = [double]::Parse($bv, [System.Globalization.CultureInfo]::InvariantCulture)
            if ($aNumber -lt $bNumber) { return (-1 * $SortDirection) }
            if ($aNumber -gt $bNumber) { return (1 * $SortDirection) }
            return 0
        }

        $textCompare = [string]::Compare($av.ToLowerInvariant(), $bv.ToLowerInvariant(), [System.StringComparison]::Ordinal)
        if ($textCompare -lt 0) { return (-1 * $SortDirection) }
        if ($textCompare -gt 0) { return (1 * $SortDirection) }
        return 0
    }

    function Sort-FindingsExportAffectedObjects {
        param(
            [object[]]$Objects,
            [string]$SortKey,
            [object]$SortDirection
        )

        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($object in @($Objects)) {
            if ($null -ne $object) { $list.Add($object) }
        }
        if ($list.Count -eq 0) { return ,@() }
        if ($list.Count -eq 1) { return ,@($list[0]) }

        $direction = 1
        if ($SortDirection -is [string]) {
            if ($SortDirection.ToLowerInvariant() -eq "desc") { $direction = -1 }
        } elseif ($SortDirection -eq -1) {
            $direction = -1
        }

        $resolvedSortKey = Get-FindingsExportAffectedSortKey -Objects @($list) -RequestedSortKey $SortKey
        if ([string]::IsNullOrWhiteSpace($resolvedSortKey)) { return @($list) }

        $indexedList = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $list.Count; $i++) {
            $indexedList.Add([pscustomobject]@{
                Index = $i
                Value = $list[$i]
            })
        }

        $indexedList.Sort([System.Comparison[object]]{
            param($a, $b)
            $result = Compare-FindingsExportAffectedObject -A $a.Value -B $b.Value -SortKey $resolvedSortKey -SortDirection $direction
            if ($result -ne 0) { return $result }
            return ($a.Index - $b.Index)
        })

        return ,@($indexedList | ForEach-Object { $_.Value })
    }

    function Normalize-FindingsExportSeverity {
        param([object]$Value)

        $number = 0.0
        if (-not [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
            return 0
        }
        if ($number -lt 0 -or $number -gt 4) { return 0 }
        return [int][math]::Floor($number)
    }

    function Normalize-FindingsExportStatus {
        param([object]$Value)

        $status = (ConvertTo-FindingsExportText -Value $Value).ToLowerInvariant()
        if ($status -eq "vulnerable") { return "Vulnerable" }
        if ($status -eq "skipped") { return "Skipped" }
        return "NotVulnerable"
    }

    function ConvertTo-FindingsExportFinding {
        param([object]$Finding)

        $confidence = Get-FindingsExportPropertyValue -Object $Finding -Name "Confidence"
        if ([string]::IsNullOrWhiteSpace([string]$confidence)) {
            $confidence = Get-FindingsExportPropertyValue -Object $Finding -Name "Certainty"
        }

        $rawAffectedObjects = Get-FindingsExportPropertyValue -Object $Finding -Name "AffectedObjects"
        $affectedObjects = if ($null -eq $rawAffectedObjects) {
            @()
        } elseif (Test-FindingsExportObjectValue -Value $rawAffectedObjects) {
            @($rawAffectedObjects)
        } elseif ($rawAffectedObjects -is [System.Collections.IEnumerable] -and -not ($rawAffectedObjects -is [string]) -and -not ($rawAffectedObjects -is [System.Collections.IDictionary])) {
            @($rawAffectedObjects)
        } else {
            @()
        }

        $affectedSortKey = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "AffectedSortKey")
        $affectedSortDir = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "AffectedSortDir")
        $sortedAffectedObjects = Sort-FindingsExportAffectedObjects -Objects $affectedObjects -SortKey $affectedSortKey -SortDirection $affectedSortDir

        return [pscustomobject][ordered]@{
            FindingId        = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "FindingId")
            Title            = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Title") -Fallback "Untitled finding"
            Category         = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Category") -Fallback "Uncategorized"
            Severity         = Normalize-FindingsExportSeverity -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Severity")
            Description      = ConvertFrom-FindingsExportHtml -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Description")
            Threat           = ConvertFrom-FindingsExportHtml -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Threat")
            Status           = Normalize-FindingsExportStatus -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Status")
            Remediation      = ConvertFrom-FindingsExportHtml -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "Remediation")
            Confidence       = ConvertTo-FindingsExportText -Value $confidence -Fallback "Inconclusive"
            AffectedObjects  = @(@($sortedAffectedObjects) | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-FindingsExportAffectedObject -Object $_ })
            RelatedReportUrl = ConvertTo-FindingsExportText -Value (Get-FindingsExportPropertyValue -Object $Finding -Name "RelatedReportUrl")
            AffectedSortKey  = $affectedSortKey
            AffectedSortDir  = $affectedSortDir
            Tags             = @()
        }
    }

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        $null = New-Item -Path $OutputFolder -ItemType Directory -Force
    }
    $resolvedOutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

    $tenantLabel = if ($CurrentTenant.PSObject.Properties["DisplayName"]) { $CurrentTenant.DisplayName } elseif ($CurrentTenant.PSObject.Properties["FileSafeDisplayName"]) { $CurrentTenant.FileSafeDisplayName } else { "tenant" }
    $tenantToken = ConvertTo-FindingsExportFilePart -Value $tenantLabel -Fallback "tenant"
    $timestampToken = ConvertTo-FindingsExportFilePart -Value $StartTimestamp -Fallback "timestamp"
    $exportPath = Join-Path $resolvedOutputFolder "tenant_findings_all_$($timestampToken)_$($tenantToken).json"

    $findingsArray = @($SecurityFindings)
    $plainFindings = @($findingsArray | ForEach-Object { ConvertTo-FindingsExportFinding -Finding $_ })
    $json = ConvertTo-Json -InputObject $plainFindings -Depth 30

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($exportPath, $json, $utf8NoBom)

    try {
        return (Resolve-Path -LiteralPath $exportPath).Path
    } catch {
        return $exportPath
    }
}

function Export-EntraFalconDebugObjectDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $true)]
        [string]$StartTimestamp,

        [Parameter(Mandatory = $true)]
        [object]$CurrentTenant,

        [Parameter(Mandatory = $false)]
        [string]$EntraFalconVersion,

        [Parameter(Mandatory = $false)]
        [object]$TenantDomains,

        [Parameter(Mandatory = $false)]
        [object]$GlobalAuditSummary,

        [Parameter(Mandatory = $false)]
        [object]$AllUsersBasicHT,

        [Parameter(Mandatory = $false)]
        [object]$UserReportState,

        [Parameter(Mandatory = $false)]
        [object]$Users,

        [Parameter(Mandatory = $false)]
        [object]$AllGroupsDetails,

        [Parameter(Mandatory = $false)]
        [object]$AgentObjectBasics,

        [Parameter(Mandatory = $false)]
        [object]$ServicePrincipalSignInActivityLookup,

        [Parameter(Mandatory = $false)]
        [object]$AppRoleReferenceCache,

        [Parameter(Mandatory = $false)]
        [object]$TenantPimForGroupsAssignments,

        [Parameter(Mandatory = $false)]
        [object]$TenantPimRoleAssignments,

        [Parameter(Mandatory = $false)]
        [object]$TenantRoleAssignments,

        [Parameter(Mandatory = $false)]
        [object]$AzureIAMAssignments,

        [Parameter(Mandatory = $false)]
        [object]$AllCaps,

        [Parameter(Mandatory = $false)]
        [object]$Devices,

        [Parameter(Mandatory = $false)]
        [object]$AdminUnitWithMembers,

        [Parameter(Mandatory = $false)]
        [object]$PimforEntraRoles,

        [Parameter(Mandatory = $false)]
        [object]$PimforGroups,

        [Parameter(Mandatory = $false)]
        [object]$EnterpriseApps,

        [Parameter(Mandatory = $false)]
        [object]$AppRegistrations,

        [Parameter(Mandatory = $false)]
        [object]$ManagedIdentities,

        [Parameter(Mandatory = $false)]
        [object]$AgentIdentities,

        [Parameter(Mandatory = $false)]
        [object]$AgentIdentityBlueprintsPrincipals,

        [Parameter(Mandatory = $false)]
        [object]$AgentIdentityBlueprints,

        [Parameter(Mandatory = $false)]
        [object]$SecurityFindings
    )

    function Get-DebugObjectCount {
        param([object]$Object)

        if ($null -eq $Object) { return 0 }
        if ($Object -is [System.Collections.IDictionary]) { return $Object.Count }
        if ($Object -is [System.Collections.ICollection]) { return $Object.Count }
        if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) { return @($Object).Count }
        return 1
    }

    function Get-DebugNestedEntryCount {
        param([object]$Object)

        if ($null -eq $Object) { return 0 }

        if ($Object -is [System.Collections.IDictionary]) {
            $count = 0
            foreach ($value in $Object.Values) {
                $count += Get-DebugObjectCount -Object $value
            }
            return $count
        }

        return Get-DebugObjectCount -Object $Object
    }

    function Get-DebugObjectNameFromFileName {
        param([string]$FileName)

        $name = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        return ($name -replace '^\d+_', '')
    }

    try {
        $debugDumpFolder = Join-Path $OutputFolder "Debug_ObjectDump"
        if (-not (Test-Path -LiteralPath $debugDumpFolder)) {
            $null = New-Item -Path $debugDumpFolder -ItemType Directory -Force
        }
        $debugDumpFolderFullPath = (Resolve-Path -LiteralPath $debugDumpFolder).Path

        $debugObjects = [ordered]@{
            "01_CurrentTenant.clixml"                     = $CurrentTenant
            "02_TenantDomains.clixml"                     = $TenantDomains
            "03_GlobalAuditSummary.clixml"                = $GlobalAuditSummary
            "04_AllUsersBasicHT.clixml"                   = $AllUsersBasicHT
            "05_UserReportState.clixml"                   = $UserReportState
            "06_Users.clixml"                             = $Users
            "07_AllGroupsDetails.clixml"                  = $AllGroupsDetails
            "08_AgentObjectBasics.clixml"                 = $AgentObjectBasics
            "09_ServicePrincipalSignInActivityLookup.clixml" = $ServicePrincipalSignInActivityLookup
            "10_AppRoleReferenceCache.clixml"             = $AppRoleReferenceCache
            "11_TenantPimForGroupsAssignments.clixml"     = $TenantPimForGroupsAssignments
            "12_TenantPimRoleAssignments.clixml"          = $TenantPimRoleAssignments
            "13_TenantRoleAssignments.clixml"             = $TenantRoleAssignments
            "14_AzureIAMAssignments.clixml"               = $AzureIAMAssignments
            "15_AllCaps.clixml"                           = $AllCaps
            "16_Devices.clixml"                           = $Devices
            "17_AdminUnitWithMembers.clixml"              = $AdminUnitWithMembers
            "18_PimforEntraRoles.clixml"                  = $PimforEntraRoles
            "19_PimforGroups.clixml"                      = $PimforGroups
            "20_EnterpriseApps.clixml"                    = $EnterpriseApps
            "21_AppRegistrations.clixml"                  = $AppRegistrations
            "22_ManagedIdentities.clixml"                 = $ManagedIdentities
            "23_AgentIdentities.clixml"                   = $AgentIdentities
            "24_AgentIdentityBlueprintsPrincipals.clixml" = $AgentIdentityBlueprintsPrincipals
            "25_AgentIdentityBlueprints.clixml"           = $AgentIdentityBlueprints
            "26_SecurityFindings.clixml"                  = $SecurityFindings
        }

        $summaryProperties = [ordered]@{
            ExportedAt         = (Get-Date).ToString("s")
            EntraFalconVersion = $EntraFalconVersion
            PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
            HostOS             = Get-EntraFalconHostOs
            StartTimestamp     = $StartTimestamp
            TenantDisplayName  = $CurrentTenant.DisplayName
            TenantId           = $CurrentTenant.Id
            OutputFolder       = $OutputFolder
            DumpFolder         = $debugDumpFolderFullPath
            DumpFormat         = "CLIXML"
        }

        foreach ($export in $debugObjects.GetEnumerator()) {
            $objectName = Get-DebugObjectNameFromFileName -FileName $export.Key
            $summaryProperties["$($objectName)_Count"] = Get-DebugObjectCount -Object $export.Value
            if ($export.Value -is [System.Collections.IDictionary]) {
                $summaryProperties["$($objectName)_NestedCount"] = Get-DebugNestedEntryCount -Object $export.Value
            }
        }

        $summary = [pscustomobject]$summaryProperties
        Export-Clixml -InputObject $summary -Path (Join-Path $debugDumpFolder "00_Summary.clixml")
        $summary | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $debugDumpFolder "00_Summary.json") -Encoding utf8

        foreach ($export in $debugObjects.GetEnumerator()) {
            if ($null -eq $export.Value) {
                continue
            }

            try {
                Export-Clixml -InputObject $export.Value -Path (Join-Path $debugDumpFolder $export.Key)
            } catch {
                Write-Host "[!] Failed to export debug object '$($export.Key)': $($_.Exception.Message)"
            }
        }

        Write-Host "[+] Debug object dump written to $debugDumpFolderFullPath"
    } catch {
        Write-Host "[!] Failed to export debug object dump: $($_.Exception.Message)"
    }
}

# Check if MS Graph is authenticated; if not, call the function for interactive sign-in
function EnsureAuthMsGraph {
    $result = $false
    if (AuthCheckMSGraph) {
        write-host "[+] MS Graph session OK"
        $result = $true
        
    } else {
        if (AuthenticationMSGraph) {
            write-host "[+] MS Graph successfully authenticated"
            $result = $true
        } else {
            if (-not $GLOBALAuthParameters['Tenant']) {write-host "[i] Maybe try to specify the tenant: -Tenant"}
            Write-host "[!] Aborting"
            $result = $false
            
        }
    }
    Return $result
}


# Check if ARM API authentication worked. If not, call the function for interactive sign-in
function EnsureAuthAzurePsNative {
    if (AuthCheckAzPSNative) {
        write-host "[+] Azure PS Session OK"
        $result = $true
    } else {
        if (AuthenticationAzurePSNative) {
            write-host "[+] Azure PS successfully authenticated"
            $result = $true
        } else {
            $result = $false
        }
    }
    return $result
}

#Function to check if a valid MS Graph session exists
function AuthCheckMSGraph {
    $result = $true
    Write-host "[*] Checking session MS Graph"
    if ($null -ne $GLOBALMsGraphAccessToken.access_token) {
        try {
            Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/organization?$select=id' -erroraction Stop -UserAgent $($GlobalAuditSummary.UserAgent.Name) | out-null
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}
#Return a tenant display name variant that is safe to use inside generated file names.
function ConvertTo-EntraFalconFileNameToken {
    param(
        [AllowNull()][string]$Value,
        [AllowNull()][string]$Fallback
    )

    $token = "$Value".Trim()
    $token = $token -replace '[<>:"/\\|?*\x00-\x1F]', '_'
    $token = $token.Trim().TrimEnd([char[]]@('.', ' '))
    $token = $token -replace '_{2,}', '_'

    if ([string]::IsNullOrWhiteSpace($token)) {
        $token = "$Fallback".Trim()
    }
    if ([string]::IsNullOrWhiteSpace($token)) {
        $token = "Tenant"
    }

    return $token
}

#Get basic tenant info
function Get-OrgInfo {
    $QueryParameters = @{
        '$select' = "Id,DisplayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime"
    }
    $OrgInfo = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/organization" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($tenant in @($OrgInfo)) {
        $fileSafeDisplayName = ConvertTo-EntraFalconFileNameToken -Value $tenant.DisplayName -Fallback $tenant.Id
        $tenant | Add-Member -NotePropertyName FileSafeDisplayName -NotePropertyValue $fileSafeDisplayName -Force
        $tenant | Add-Member -NotePropertyName FileSafeDisplayNameEncoded -NotePropertyValue ([System.Uri]::EscapeDataString($fileSafeDisplayName)) -Force
    }
    return $OrgInfo
}

#Get tenant domains including federation configuration for federated domains
function Get-TenantDomains {
    Write-Host "[*] Retrieve tenant domains"
    $QueryParameters = @{
        '$select' = "id,authenticationType,isAdminManaged,isDefault,isVerified,supportedServices"
    }
    try {
        $DomainsRaw = @(Send-ApiRequest -Method GET -Uri "https://graph.microsoft.com/beta/domains" -AccessToken $GLOBALMsGraphAccessToken.access_token -QueryParameters $QueryParameters -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    } catch {
        Write-Host "[!] Could not retrieve tenant domains. Domain-related summary data will be incomplete."
        Write-Log -Level Verbose -Message "Could not retrieve tenant domains: $($_.Exception.Message)"
        $GlobalAuditSummary.Domains.Count = 0
        $GlobalAuditSummary.Domains.Federated = 0
        $GlobalAuditSummary.Domains.Verified = 0
        $GlobalAuditSummary.Domains.Default = 0
        $GlobalAuditSummary.Domains.AdminManaged = 0
        return @()
    }
    Write-Log -Level Debug -Message "Retrieved $($DomainsRaw.Count) domains"

    $federationLookupFailed = $false
    $Domains = foreach ($domain in $DomainsRaw) {
        $federatedIdpMfaBehavior = $null
        if ($domain.authenticationType -eq "Federated") {
            Write-Log -Level Debug -Message "Fetching federation configuration for domain: $($domain.id)"
            try {
                $FedConfig = @(Send-ApiRequest -Method GET -Uri "https://graph.microsoft.com/beta/domains/$($domain.id)/federationConfiguration" -AccessToken $GLOBALMsGraphAccessToken.access_token -QueryParameters @{ '$select' = 'federatedIdpMfaBehavior' } -UserAgent $($GlobalAuditSummary.UserAgent.Name))
                if ($FedConfig.Count -gt 0) {
                    if ($FedConfig.Count -gt 1) {
                        Write-Log -Level Debug -Message "Multiple federation configurations found for domain: $($domain.id). Using the first entry."
                    }
                    $federatedIdpMfaBehavior = [string]$FedConfig[0].federatedIdpMfaBehavior
                    Write-Log -Level Debug -Message "federatedIdpMfaBehavior for $($domain.id): $federatedIdpMfaBehavior"
                } else {
                    Write-Log -Level Debug -Message "No federation configuration found for domain: $($domain.id)"
                }
            } catch {
                $federationLookupFailed = $true
                Write-Log -Level Verbose -Message "Could not retrieve federation configuration for domain $($domain.id): $($_.Exception.Message)"
            }
        }
        [PSCustomObject]@{
            Id                      = $domain.id
            AuthenticationType      = $domain.authenticationType
            IsAdminManaged          = $domain.isAdminManaged
            IsDefault               = $domain.isDefault
            IsVerified              = $domain.isVerified
            SupportedServices       = @($domain.supportedServices)
            FederatedIdpMfaBehavior = $federatedIdpMfaBehavior
        }
    }

    $GlobalAuditSummary.Domains.Count = @($Domains).Count
    $GlobalAuditSummary.Domains.Federated = @($Domains | Where-Object { $_.AuthenticationType -eq "Federated" }).Count
    $GlobalAuditSummary.Domains.Verified = @($Domains | Where-Object { $_.IsVerified -eq $true }).Count
    $GlobalAuditSummary.Domains.Default = @($Domains | Where-Object { $_.IsDefault -eq $true }).Count
    $GlobalAuditSummary.Domains.AdminManaged = @($Domains | Where-Object { $_.IsAdminManaged -eq $true }).Count

    return $Domains
}

#Get information if users are MFA capable
function Get-RegisterAuthMethodsUsers {
    # Requires Premium otherwise HTTP 403:Tenant is not a B2C tenant and doesn't have premium license
    write-host "[*] Retrieve users registered auth methods"

    $QueryParameters = @{
        '$select' = "Id,IsMfaCapable"
        '$top' = "3000"
    }
    try {
        $RegisteredAuthMethods = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/reports/authenticationMethods/userRegistrationDetails" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    } catch {
        if ($($_.Exception.Message) -match "Status: 403") {
            write-host "[!] HTTP 403 Error: Most likely due to missing Entra ID premium licence. Can't retrieve users auth methods."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Can't retrieve users auth methods."
        }
    }
    
    #Convert to HT
    $UserAuthMethodsTable = @{}
    foreach ($method in $RegisteredAuthMethods ) {
        $UserAuthMethodsTable[$method.Id] = $method.IsMfaCapable
    }

    Write-Log -Level Verbose -Message "Got $($UserAuthMethodsTable.Count) auth methods"

    return $UserAuthMethodsTable
}

#Get all Users
function Get-UsersBasic {
    Param (
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

     write-host "[*] Retrieve basic user list"

    $QueryParameters = @{
        '$select' = "Id,UserPrincipalName,UserType,accountEnabled,onPremisesSyncEnabled"
        '$top' = $ApiTop
      }
      $RawResponse = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $AllUsersBasicHT = @{}
    foreach ($user in $RawResponse) {
        $AllUsersBasicHT[$user.id] = $user
    }
    Write-Log -Level Verbose -Message "Got $($AllUsersBasicHT.count) users"
    return $AllUsersBasicHT
}

function Get-AgentObjectBasics {
    Param (
        [Parameter(Mandatory = $true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

    # Preload the agent-specific object metadata that the generic service principal list cannot represent correctly.
    write-host "[*] Retrieve basic agent object list"

    $agentObjectBasics = @{
        AgentIdentities = @{}
        AgentIdentityBlueprintsPrincipals = @{}
        AgentIdentityBlueprints = @{}
    }

    $agentIdentityQueryParameters = @{
        '$select' = "Id,DisplayName,PublisherName,accountEnabled,appOwnerOrganizationId,servicePrincipalType"
        '$top' = $ApiTop
    }
    $agentIdentitiesRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals/Microsoft.Graph.AgentIdentity' -QueryParameters $agentIdentityQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($item in @($agentIdentitiesRaw)) {
        $appOwnerOrganizationId = "$($item.AppOwnerOrganizationId)".Trim()
        $publisherName = if ([string]::IsNullOrWhiteSpace($item.PublisherName)) { "-" } else { $item.PublisherName }
        $foreign = (-not [string]::IsNullOrWhiteSpace($appOwnerOrganizationId) -and $appOwnerOrganizationId -ne $CurrentTenant.id)
        $defaultMS = ($appOwnerOrganizationId -and $GLOBALMsTenantIds -contains $appOwnerOrganizationId)

        $agentObjectBasics.AgentIdentities[$item.Id] = [pscustomobject]@{
            Id                   = $item.Id
            DisplayName          = $item.DisplayName
            Enabled              = $item.accountEnabled
            PublisherName        = $publisherName
            Foreign              = $foreign
            DefaultMS            = $defaultMS
            ObjectKind           = 'AgentIdentity'
            TargetReport         = 'AgentIdentities'
            ServicePrincipalType = $item.servicePrincipalType
        }
    }

    $blueprintPrincipalQueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'Application'"
        '$select' = "Id,DisplayName,PublisherName,accountEnabled,appOwnerOrganizationId,servicePrincipalType"
        '$top' = $ApiTop
    }
    $blueprintPrincipalsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals/graph.agentIdentityBlueprintPrincipal' -QueryParameters $blueprintPrincipalQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($item in @($blueprintPrincipalsRaw)) {
        $appOwnerOrganizationId = "$($item.AppOwnerOrganizationId)".Trim()
        $publisherName = if ([string]::IsNullOrWhiteSpace($item.PublisherName)) { "-" } else { $item.PublisherName }
        $foreign = ($appOwnerOrganizationId -ne $CurrentTenant.id)
        $defaultMS = ($GLOBALMsTenantIds -contains $appOwnerOrganizationId)

        $agentObjectBasics.AgentIdentityBlueprintsPrincipals[$item.Id] = [pscustomobject]@{
            Id                   = $item.Id
            DisplayName          = $item.DisplayName
            Enabled              = $item.accountEnabled
            PublisherName        = $publisherName
            Foreign              = $foreign
            DefaultMS            = $defaultMS
            ObjectKind           = 'AgentIdentityBlueprintPrincipal'
            TargetReport         = 'AgentIdentityBlueprintsPrincipals'
            ServicePrincipalType = $item.servicePrincipalType
        }
    }

    $blueprintQueryParameters = @{
        '$select' = "Id,AppId,DisplayName,isDisabled,createdDateTime"
        '$top' = $ApiTop
    }
    $blueprintsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications/microsoft.graph.agentIdentityBlueprint' -QueryParameters $blueprintQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($item in @($blueprintsRaw)) {
        $agentObjectBasics.AgentIdentityBlueprints[$item.Id] = [pscustomobject]@{
            Id                   = $item.Id
            AppId                = $item.AppId
            DisplayName          = $item.DisplayName
            Enabled              = -not ($item.isDisabled -eq $true)
            PublisherName        = '-'
            Foreign              = $false
            DefaultMS            = $false
            ObjectKind           = 'AgentIdentityBlueprint'
            TargetReport         = 'AgentIdentityBlueprints'
            ServicePrincipalType = $null
            CreationDate         = $item.createdDateTime
        }
    }

    Write-Log -Level Verbose -Message "Got $($agentObjectBasics.AgentIdentities.Count) agent identities, $($agentObjectBasics.AgentIdentityBlueprintsPrincipals.Count) agent identity blueprint principals and $($agentObjectBasics.AgentIdentityBlueprints.Count) agent identity blueprints"
    return $agentObjectBasics
}

function Get-ServicePrincipalSignInActivityLookup {
    Param (
        [Parameter(Mandatory = $true)][int]$ApiTop
    )

    write-host "[*] Get service principal sign-in activity"

    $AppLastSignIns = @{}
    $AppLastSignInsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/reports/servicePrincipalSignInActivities" -BetaAPI -QueryParameters @{ '$top' = $ApiTop } -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $nowUtc = (Get-Date).ToUniversalTime()

    $getSignInDateInfo = {
        param([object]$Value)

        $emptyValue = [pscustomobject]@{
            Display = "-"
            Days    = "-"
        }

        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
            return $emptyValue
        }

        try {
            if ($Value -is [datetime]) {
                $dateTime = [datetime]$Value
                if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
                    $dateTime = [datetime]::SpecifyKind($dateTime, [DateTimeKind]::Utc)
                }
                $utcDateTime = $dateTime.ToUniversalTime()
            } else {
                $dateTimeOffset = [datetimeoffset]::Parse(
                    [string]$Value,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
                )
                $utcDateTime = $dateTimeOffset.UtcDateTime
            }

            return [pscustomobject]@{
                Display = $utcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", [Globalization.CultureInfo]::InvariantCulture)
                Days    = (New-TimeSpan -Start $utcDateTime -End $nowUtc).Days
            }
        } catch {
            return $emptyValue
        }
    }

    foreach ($app in @($AppLastSignInsRaw)) {
        if ([string]::IsNullOrWhiteSpace($app.appId)) { continue }

        $lastSignInInfo = & $getSignInDateInfo $app.lastSignInActivity.lastSignInDateTime
        $lastSignInAppAsClientInfo = & $getSignInDateInfo $app.applicationAuthenticationClientSignInActivity.lastSignInDateTime
        $lastSignInAppAsResourceInfo = & $getSignInDateInfo $app.applicationAuthenticationResourceSignInActivity.lastSignInDateTime
        $lastSignInDelegatedAsClientInfo = & $getSignInDateInfo $app.delegatedClientSignInActivity.lastSignInDateTime
        $lastSignInDelegatedAsResourceInfo = & $getSignInDateInfo $app.delegatedResourceSignInActivity.lastSignInDateTime

        $AppLastSignIns[$app.appId] = @{
            id = $app.appId
            lastSignIn = $lastSignInInfo.Display
            lastSignInDays = $lastSignInInfo.Days

            lastSignInAppAsClient = $lastSignInAppAsClientInfo.Display
            lastSignInAppAsClientDays = $lastSignInAppAsClientInfo.Days

            lastSignInAppAsResource = $lastSignInAppAsResourceInfo.Display
            lastSignInAppAsResourceDays = $lastSignInAppAsResourceInfo.Days

            lastSignInDelegatedAsClient = $lastSignInDelegatedAsClientInfo.Display
            lastSignInDelegatedAsClientDays = $lastSignInDelegatedAsClientInfo.Days

            lastSignInDelegatedAsResource = $lastSignInDelegatedAsResourceInfo.Display
            lastSignInDelegatedAsResourceDays = $lastSignInDelegatedAsResourceInfo.Days
        }
    }

    Write-Log -Level Debug -Message "Got $($AppLastSignInsRaw.Count) app last sign-in dates"
    return $AppLastSignIns
}

function Resolve-DirectoryObjectReference {
    Param (
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$RawType,
        [Parameter(Mandatory = $true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory = $false)][hashtable]$AllUsersBasicHT = @{},
        [Parameter(Mandatory = $false)][hashtable]$AllGroupsDetails = @{},
        [Parameter(Mandatory = $false)][hashtable]$ServicePrincipalBasics = @{},
        [Parameter(Mandatory = $false)][hashtable]$AgentObjectBasics = @{}
    )

    # Resolve mixed directory object references through the typed lookup that owns the source-of-truth metadata.
    $normalizedId = "$ObjectId".Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedId)) {
        return $null
    }

    switch ($RawType) {
        '#microsoft.graph.user' {
            if (-not $AllUsersBasicHT.ContainsKey($normalizedId)) { return $null }
            $user = $AllUsersBasicHT[$normalizedId]
            $displayName = if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { $normalizedId } else { $user.UserPrincipalName }
            return [pscustomobject]@{
                Id                   = $normalizedId
                DisplayName          = $displayName
                Enabled              = $user.accountEnabled
                PublisherName        = '-'
                Foreign              = $false
                DefaultMS            = $false
                ObjectKind           = 'User'
                TargetReport         = 'Users'
                ServicePrincipalType = $null
            }
        }

        '#microsoft.graph.agentUser' {
            if (-not $AllUsersBasicHT.ContainsKey($normalizedId)) { return $null }
            $user = $AllUsersBasicHT[$normalizedId]
            $displayName = if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { $normalizedId } else { $user.UserPrincipalName }
            return [pscustomobject]@{
                Id                   = $normalizedId
                DisplayName          = $displayName
                Enabled              = $user.accountEnabled
                PublisherName        = '-'
                Foreign              = $false
                DefaultMS            = $false
                ObjectKind           = 'AgentUser'
                TargetReport         = 'Users'
                ServicePrincipalType = $null
            }
        }

        '#microsoft.graph.group' {
            if (-not $AllGroupsDetails.ContainsKey($normalizedId)) { return $null }
            $group = $AllGroupsDetails[$normalizedId]
            return [pscustomobject]@{
                Id                   = $normalizedId
                DisplayName          = $group.DisplayName
                Enabled              = $null
                PublisherName        = '-'
                Foreign              = $false
                DefaultMS            = $false
                ObjectKind           = 'Group'
                TargetReport         = 'Groups'
                ServicePrincipalType = $null
            }
        }

        '#microsoft.graph.servicePrincipal' {
            if (-not $ServicePrincipalBasics.ContainsKey($normalizedId)) { return $null }
            $sp = $ServicePrincipalBasics[$normalizedId]
            $foreign = ($sp.servicePrincipalType -ne "ManagedIdentity" -and $sp.AppOwnerOrganizationId -ne $CurrentTenant.id)
            $defaultMS = ($sp.servicePrincipalType -ne "ManagedIdentity" -and $GLOBALMsTenantIds -contains $sp.AppOwnerOrganizationId)
            $objectKind = if ($sp.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
            $targetReport = if ($sp.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentities' } else { 'EnterpriseApps' }
            return [pscustomobject]@{
                Id                   = $sp.Id
                DisplayName          = $sp.DisplayName
                Enabled              = $sp.accountEnabled
                PublisherName        = $sp.publisherName
                Foreign              = $foreign
                DefaultMS            = $defaultMS
                ObjectKind           = $objectKind
                TargetReport         = $targetReport
                ServicePrincipalType = $sp.servicePrincipalType
            }
        }

        '#microsoft.graph.agentIdentity' {
            $agentIdentities = if ($AgentObjectBasics.ContainsKey('AgentIdentities')) { $AgentObjectBasics.AgentIdentities } else { @{} }
            if (-not $agentIdentities.ContainsKey($normalizedId)) { return $null }
            return $agentIdentities[$normalizedId]
        }

        '#microsoft.graph.agentIdentityBlueprintPrincipal' {
            $principals = if ($AgentObjectBasics.ContainsKey('AgentIdentityBlueprintsPrincipals')) { $AgentObjectBasics.AgentIdentityBlueprintsPrincipals } else { @{} }
            if (-not $principals.ContainsKey($normalizedId)) { return $null }
            return $principals[$normalizedId]
        }

        '#microsoft.graph.agentIdentityBlueprint' {
            $blueprints = if ($AgentObjectBasics.ContainsKey('AgentIdentityBlueprints')) { $AgentObjectBasics.AgentIdentityBlueprints } else { @{} }
            if (-not $blueprints.ContainsKey($normalizedId)) { return $null }
            return $blueprints[$normalizedId]
        }
    }

    return $null
}

#Get Basic User Infos
function Get-Devices {
    Param (
        [Parameter(Mandatory = $true)][int]$ApiTop
    )
     write-host "[*] Retrieve devices"

    $QueryParameters = @{
        '$select' = "Id,accountEnabled,displayName,Manufacturer,trustType,operatingSystem,operatingSystemVersion"
        '$top' = $ApiTop
    }

    $DevicesRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/devices" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    
    #Convert to HT
    $Devices = @{}
    foreach ($device in $DevicesRaw) {
        $Devices[$device.Id] = $device
    }

    Write-Log -Level Verbose -Message "Got $($Devices.Count) devices "
    
    return $Devices
}

function AuthCheckAzPSNative {
    $result = $true
    Write-host "[*] Checking access to ARM API"
    if ($null -ne $GLOBALArmAccessToken.access_token) {
        try {
            $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
            Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop | Out-Null
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}


function checkSubscriptionNative {
    $result = $true

    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $Subscription = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)
    $SubscriptionCount = $Subscription.Count

    if ($SubscriptionCount -gt 0) {
        write-host "[+] User has access to $SubscriptionCount Subscription(s)."
        $GlobalAuditSummary.Subscriptions.Count = $SubscriptionCount
    } else {
        write-host "[-] User does not have access to a Subscription."
        $result = $false
    }
    return $result
}

#Function to perform MSGraph authentication using EntraTokenAid
function AuthenticationMSGraph {
    if (-not (invoke-EntraFalconAuth -Action Auth -Purpose MainAuth @GLOBALAuthMethods)) {
        Write-Log -Level Debug -Message "Authentication failed for MainAuth."
        return $false
    }

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (MS Graph)"
        $result = $false
    }

    return $result
}


function AuthenticationAzurePSNative {
   
    #Get tokens for Azure ARM API
    invoke-EntraFalconAuth -Action Auth -Purpose Azure @GLOBALAuthMethods
    if (AuthCheckAzPSnative) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (ARM API)"
        $result = $false
    }

return $result
}

#Refresh MS Graph session
function RefreshAuthenticationMsGraph {
    $result = $true
    invoke-EntraFalconAuth -Action Refresh -Purpose MainAuth @GLOBALAuthMethods

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Token refresh failed. Subsequent API calls may fail!"
        $result = $false
    }

    return $result
}

# Authenticate Microsoft Graph token for Security Findings specific endpoints.
function EnsureAuthSecurityFindingsMsGraph {
    $result = $false
    if (-not (invoke-EntraFalconAuth -Action Auth -Purpose SecurityFindings @GLOBALAuthMethods)) {
        Write-Log -Level Verbose -Message "[SecurityFindings] Authentication failed for special Graph endpoints."
        return $false
    }

    if ($null -ne $GLOBALSecurityFindingsGraphAccessTokenSpecial) {
        $result = $true
    } else {
        Write-Log -Level Verbose -Message "[SecurityFindings] No special Graph token was returned."
    }

    return $result
}

# Refresh Microsoft Graph token for Security Findings specific endpoints.
function RefreshAuthenticationSecurityFindingsMsGraph {
    if ($null -eq $GLOBALSecurityFindingsGraphAccessTokenSpecial) {
        Write-Log -Level Verbose -Message "[SecurityFindings] Cannot refresh special Graph token because it is not initialized."
        return $false
    }

    if (Invoke-CheckTokenExpiration $GLOBALSecurityFindingsGraphAccessTokenSpecial) {
        return $true
    }

    if (-not (invoke-EntraFalconAuth -Action Refresh -Purpose SecurityFindings @GLOBALAuthMethods)) {
        Write-Log -Level Verbose -Message "[SecurityFindings] Refresh failed for special Graph token."
        return $false
    }

    return ($null -ne $GLOBALSecurityFindingsGraphAccessTokenSpecial)
}

function Invoke-CheckTokenExpiration ($Object) {
    #write-host "[*] Checking access token expiration... $($Object.Target)"
    $validForMinutes = [Math]::Ceiling((NEW-TIMESPAN -Start (Get-Date) -End $Object.Expiration_time).TotalMinutes)

    #Check if the token is valid for more than 30 minutes
    if ($validForMinutes -ge 30) {
        #write-host "[+] Token is still valid for $validForMinutes minutes"
        $result = $true

    } elseif ($validForMinutes -le 30 -and $validForMinutes -ge 0) {
        write-host "[!] Access token will expire in $validForMinutes minutes"
        $result = $false   
    } else {
        write-host "[!] Access token has expired $([Math]::Abs($validForMinutes)) minutes ago"
        $result = $false
    }
    return $result

}

#Entra role rating (Tier level per role)
$global:GLOBALEntraRoleRating = @{
    "62e90394-69f5-4237-9190-012177145e10" = 0 #Global Administrator
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = 0 #Partner Tier2 Support
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = 0 #Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = 0 #Privileged Role Administrator
    "8329153b-31d0-4727-b945-745eb3bc5f31" = 0 #Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45" = 0 #External Identity Provider Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = 0 #Hybrid Identity Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = 0 #Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7" = 0 #Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = 0 #Security Administrator
    "db506228-d27e-4b7d-95e5-295956d6615f" = 1 #Agent ID Administrator
    "d2562ede-74db-457e-a7b6-544e236ebb61" = 1 #AI Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32" = 1 #Directory Synchronization Accounts
    "a92aed5d-d78a-4d16-b381-09adb37eb3b0" = 1 #On Premises Directory Sync Account
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = 1 #Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = 1 #Authentication Administrator
    "e3973bdf-4987-49ae-837a-ba8e231c7286" = 1 #Azure DevOps Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301" = 1 #Directory Writers
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = 1 #Exchange Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = 1 #Groups Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = 1 #Helpdesk Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = 1 #Identity Governance Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = 1 #Intune Administrator
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = 1 #Knowledge Administrator
    "744ec460-397e-42ad-a462-8b3f9747a02c" = 1 #Knowledge Manager
    "59d46f88-662b-457b-bceb-5c3809e5908f" = 1 #Lifecycle Workflows Administrator
    "4ba39ca4-527c-499a-b93d-d9b492c50246" = 1 #Partner Tier1 Support
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = 1 #Password Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = 1 #SharePoint Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = 1 #Teams Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = 1 #User Administrator
    "11451d60-acb2-45eb-a7d6-43d0f0125c13" = 1 #Windows 365 Administrator
    "810a2642-a034-447f-a5e8-41beaa378541" = 1 #Yammer Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80" = 2 #Authentication Policy Administrator
    "9f06204d-73c1-4d4c-880a-6edb90606fd8" = 2 #Azure AD Joined Device Local Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2" = 2 #Cloud Device Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = 2 #Global Reader
    "95e79109-95c0-4d8e-aee3-d01accf2d47b" = 2 #Guest Inviter
    "5d6b6bb7-de71-4623-b4af-96380a352509" = 2 #Security Reader
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = 2 #Directory Readers
}

#Azure role rating (Tier level per role)
$global:GLOBALAzureRoleRating = @{
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = 0 #Owner
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" = 0 #User Access Administrator
    "b24988ac-6180-42a0-ab88-20f7382dd24c" = 0 #Contributor
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168" = 0 #Role Based Access Control Administrator
    "a8889054-8d42-49c9-bc1c-52486c10e7cd" = 0 #Reservations Administrator
    "fb1c8493-542b-48eb-b624-b4c8fea62acd" = 1 #Security Admin
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c" = 1 #Virtual Machine Contributor
    "66f75aeb-eabe-4b70-9f1e-c350c4c9ad04" = 1 #Virtual Machine Data Access Administrator
    "1c0163c0-47e6-4577-8991-ea5c82e286e4" = 1 #Virtual Machine Administrator Login
    "a6333a3e-0164-44c3-b281-7a577aff287f" = 1 #Windows Admin Center Administrator Login
    "3bc748fc-213d-45c1-8d91-9da5725539b9" = 1 #Container Registry Contributor and Data Access Configuration Administrator
    "00482a5a-887f-4fb3-b363-3b7fe8e74483" = 1 #Key Vault Administrator
    "8b54135c-b56d-4d72-a534-26097cfdc8d8" = 1 #Key Vault Data Access Administrator	
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" = 1 #Key Vault Secrets Officer
    "4633458b-17de-408a-b874-0445c86b69e6" = 1 #Key Vault Secrets User
    "3498e952-d568-435e-9b2c-8d77e338d7f7" = 1 #Azure Kubernetes Service RBAC Admin
    "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b" = 1 #Azure Kubernetes Service RBAC Cluster Admin
    "dffb1e0c-446f-4dde-a09f-99eb5cc68b96" = 1 #Azure Arc Kubernetes Admin
    "8393591c-06b9-48a2-a542-1bd6b377f6a2" = 1 #Azure Arc Kubernetes Cluster Admin
    "b748a06d-6150-4f8a-aaa9-ce3940cd96cb" = 1 #Azure Arc VMware VM Contributor
    "17d1049b-9a84-46fb-8f53-869881c3d3ab" = 1 #Storage Account Contributor
    "acdd72a7-3385-48ef-bd42-f606fba81ae7" = 2 #Reader
    "39bc4728-0917-49c7-9d2c-d95423bc2eb4" = 2 #SecurityReader
    "fb879df8-f326-4884-b1cf-06f3ad86be52" = 3 #Virtual Machine User Login
    "1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63" = 3 #Desktop Virtualization User
}

$global:GLOBALImpactScore = @{
    "EntraRoleTier0"            = 2000
    "EntraRoleTier1"            = 400
    "EntraRoleTier2"            = 80
    "EntraRoleTier?Privileged"  = 100
    "EntraRoleTier?"            = 80
    "AzureRoleTier0"            = 200
    "AzureRoleTier1"            = 70
    "AzureRoleTier2"            = 50
    "AzureRoleTier3"            = 10
    "AzureRoleTier?"            = 50
}

$global:GLOBALApiPermissionCategorizationList= @{
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "Dangerous" #RoleManagement.ReadWrite.Directory
    "06b708a9-e830-4db3-a914-8e69da51d44f" = "Dangerous" #AppRoleAssignment.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Dangerous" #Application.ReadWrite.All
    "dd199f4a-f148-40a4-a2ec-f0069cc799ec" = "Dangerous" #RoleAssignmentSchedule.ReadWrite.Directory
    "41202f2c-f7ab-45be-b001-85c9728b9d69" = "Dangerous" #PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
    "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e" = "Dangerous" #PrivilegedAccess.ReadWrite.AzureADGroup
    "fee28b28-e1f3-4841-818e-2704dc62245f" = "Dangerous" #RoleEligibilitySchedule.ReadWrite.Directory
    "618b6020-bca8-4de6-99f6-ef445fa4d857" = "Dangerous" #PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
    "7e05723c-0bb0-42da-be95-ae9f08a6e53c" = "Dangerous" #Domain.ReadWrite.All
    "fc023787-fd04-4e44-9bc7-d454f00c0f0a" = "Dangerous" #Application.ReadUpdate.All
    "7fddd33b-d884-4ec0-8696-72cff90ff825" = "High" #AgentIdentityBlueprint.ReadWrite.All
    "0510736e-bdfb-4b37-9a1f-89b4a074763a" = "High" #AgentIdentityBlueprint.AddRemoveCreds.All
    "ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9" = "High" #ADSynchronization.ReadWrite.All
    "9acd699f-1e81-4958-b001-93b1d2506e19" = "High" #EntitlementManagement.ReadWrite.All
    "292d869f-3427-49a8-9dab-8c70152b74e9" = "High" #Organization.ReadWrite.All
    "a402ca1c-2696-4531-972d-6e5ee4aa11ea" = "High" #Policy.ReadWrite.PermissionGrant
    "b38dcc4d-a239-4ed6-aa84-6c65b284f97c" = "High" #RoleManagementPolicy.ReadWrite.AzureADGroup
    "31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad" = "High" #RoleManagementPolicy.ReadWrite.Directory
    "29c18626-4985-4dcd-85c0-193eef327366" = "High" #Policy.ReadWrite.AuthenticationMethod"
    "eccc023d-eccf-4e7b-9683-8813ab36cecc" = "High" #User.DeleteRestore.All
    "3011c876-62b7-4ada-afa2-506cbbecc68c" = "High" #User.EnableDisableAccount.All
    "8e8e4742-1d95-4f68-9d56-6ee75648c72a" = "High" #DelegatedPermissionGrant.ReadWrite.All
    "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "High" #Policy.ReadWrite.ConditionalAccess
    "0e263e50-5827-48a4-b97c-d940288653c7" = "High" #Directory.AccessAsUser.All
    "9241abd9-d0e6-425a-bd4f-47ba86e767a4" = "High" #DeviceManagementConfiguration.ReadWrite.All
    "e330c4f0-4170-414e-a55a-2f022ec2b57b" = "High" #DeviceManagementRBAC.ReadWrite.Al
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "High" #Directory.ReadWrite.All
    "62a82d76-70ea-41e2-9197-370581804d09" = "High" #Group.ReadWrite.All
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" = "High" #GroupMember.ReadWrite.All
    "50483e42-d915-4231-9639-7fdb7fd190e5" = "High" #UserAuthenticationMethod.ReadWrite.All
    "cc117bb9-00cf-4eb8-b580-ea2a878fe8f7" = "High" #User-PasswordProfile.ReadWrite.All    
    "a82116e5-55eb-4c41-a434-62fe8a61c773" = "High" #Sites.FullControl.All
    "678536fe-1083-478a-9c59-b99265e6b0d3" = "High" #Sites.FullControl.All SharePointAPI
    "9bff6588-13f2-4c48-bbf2-ddab62256b36" = "High" #Sites.Manage.All SharePointAPI
    "d13f72ca-a275-4b96-b789-48ebcc4da984" = "High" #Sites.Read.All SharePointAPI
    "fbcd29d2-fcca-4405-aded-518d457caae4" = "High" #Sites.ReadWrite.All SharePointAPI
    "0c0bf378-bf22-4481-8f81-9e89a9b4960a" = "High" #Sites.Manage.All
    "332a536c-c7ef-4017-ab91-336970924f0d" = "High" #Sites.Read.All
    "9492366f-7969-46a4-8d15-ed1a20078fff" = "High" #Sites.ReadWrite.All
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "High" #Files.Read.All
    "75359482-378d-4052-8f01-80520e7db3cd" = "High" #Files.ReadWrite.All
    "db51be59-e728-414b-b800-e0f010df1a79" = "High" #DeviceLocalCredential.Read.All
    "5eb59dd3-1da2-4329-8733-9dabdc435916" = "High" #AdministrativeUnit.ReadWrite.All
    "7e9ebcc1-90aa-4471-8051-e68d6b4e9c89" = "High" #UserAuthMethod-HardwareOATH.ReadWrite.All
    "6e85d483-7092-4375-babe-0a94a8213a58" = "High" #UserAuthMethod-Phone.ReadWrite.All
    "4869299f-18c3-40c8-98f2-222657e67db1" = "High" #UserAuthMethod-QR.ReadWrite.All
    "627169a8-8c15-451c-861a-5b80e383de5c" = "High" #UserAuthMethod-TAP.ReadWrite.All
    "57f1cf28-c0c4-4ec3-9a30-19a2eaaf2f6e" = "Medium" #BitlockerKey.Read.All
    "741f803b-c850-494e-b5df-cde7c675a1ca" = "Medium" #User.ReadWrite.All
    "18a4783c-866b-4cc7-a460-3d5e5662c884" = "Medium" #Application.ReadWrite.OwnedBy
    "6b7d71aa-70aa-4810-a8d9-5d9fb2830017" = "Medium" #Chat.Read.All
    "294ce7c9-31ba-490a-ad7d-97a7d075e4ed" = "Medium" #Chat.ReadWrite.All
    "ef54d2bf-783f-4e0f-bca1-3210c0444d99" = "Medium" #Calendars.ReadWrite
    "798ee544-9d2d-430c-a058-570e29e34338" = "Medium" #Calendars.Read
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Medium" #Mail.Read
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Medium" #Mail.ReadWrite
    "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Medium" #Mail.Send
    "b8bb2037-6e08-44ac-a4ea-4674e010e2a4" = "Medium" #OnlineMeetings.ReadWrite.All  
    "de89b5e4-5b8f-48eb-8925-29c2b33bd8bd" = "Medium" #CustomSecAttributeAssignment.ReadWrite.All
    "89c8469c-83ad-45f7-8ff2-6e3d4285709e" = "Medium" #ServicePrincipalEndpoint.ReadWrite.All (Still an issue?)
    "4aa6e624-eee0-40ab-bdd8-f9639038a614" = "Medium" #AgentIdUser.ReadWrite.IdentityParentedBy
    "4c390976-b2b7-42e0-9187-c6be3bead001" = "Low" #AgentIdentity.CreateAsManager
}

$global:GLOBALDelegatedApiPermissionCategorizationList= @{
    "RoleManagement.ReadWrite.Directory" = "Dangerous" #d01b97e9-cbc0-49fe-810a-750afd5527a3
    "AppRoleAssignment.ReadWrite.All" = "Dangerous" #84bccea3-f856-4a8a-967b-dbe0a3d53a64
    "Application.ReadWrite.All" = "Dangerous" #bdfbf15f-ee85-4955-8675-146e8e5296b5
    "RoleAssignmentSchedule.ReadWrite.Directory" = "Dangerous" #8c026be3-8e26-4774-9372-8d5d6f21daff
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup" = "Dangerous" #06dbc45d-6708-4ef0-a797-f797ee68bf4b
    "PrivilegedAccess.ReadWrite.AzureADGroup" = "Dangerous" #32531c59-1f32-461f-b8df-6f8a3b89f73b
    "RoleEligibilitySchedule.ReadWrite.Directory" = "Dangerous" #62ade113-f8e0-4bf9-a6ba-5acb31db32fd
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup" = "Dangerous" #ba974594-d163-484e-ba39-c330d5897667
    "Domain.ReadWrite.All" = "Dangerous" #0b5d694c-a244-4bde-86e6-eb5cd07730fe
    "Application.ReadUpdate.All" = "Dangerous" #0586a906-4d89-4de8-b3c8-1aacdcc0c679
    "AgentIdentityBlueprint.AddRemoveCreds.All" = "High" #75b5feb2-bfe7-423f-907d-cc505186f246
    "AgentIdentityBlueprint.ReadWrite.All" = "High" #4fd490fc-1467-48eb-8a4c-421597ab0402
    "EntitlementManagement.ReadWrite.All" = "High" #ae7a573d-81d7-432b-ad44-4ed5c9d89038
    "Organization.ReadWrite.All" = "High" #46ca0847-7e6b-426e-9775-ea810a948356
    "Policy.ReadWrite.PermissionGrant" = "High" #2672f8bb-fd5e-42e0-85e1-ec764dd2614e
    "RoleManagementPolicy.ReadWrite.AzureADGroup" = "High" #0da165c7-3f15-4236-b733-c0b0f6abe41d
    "RoleManagementPolicy.ReadWrite.Directory" = "High" #1ff1be21-34eb-448c-9ac9-ce1f506b2a68
    "Policy.ReadWrite.AuthenticationMethod" = "High" #7e823077-d88e-468f-a337-e18f1f0e6c7c
    "User.DeleteRestore.All" = "High" #4bb440cd-2cf2-4f90-8004-aa2acd2537c5
    "User.EnableDisableAccount.All" = "High" #f92e74e7-2563-467f-9dd0-902688cb5863
    "DelegatedPermissionGrant.ReadWrite.All" = "High" #41ce6ca6-6826-4807-84f1-1c82854f7ee5
    "Policy.ReadWrite.ConditionalAccess" = "High" #ad902697-1014-4ef5-81ef-2b4301988e8c
    "DeviceManagementConfiguration.ReadWrite.All" = "High" #0883f392-0a7a-443d-8c76-16a6d39c7b63
    "DeviceManagementRBAC.ReadWrite.All" = "High" #0c5e8a55-87a6-4556-93ab-adc52c4d862d
    "Directory.ReadWrite.All" = "High" #c5366453-9fb0-48a5-a156-24f0c49a4b84
    "User-PasswordProfile.ReadWrite.All" = "High" #56760768-b641-451f-8906-e1b8ab31bca7
    "Group.ReadWrite.All" = "High" #4e46008b-f24c-477d-8fff-7bb4ec7aafe0
    "GroupMember.ReadWrite.All" = "High" #f81125ac-d3b7-4573-a3b2-7099cc39df9e
    "UserAuthenticationMethod.ReadWrite.All" = "High" #b7887744-6746-4312-813d-72daeaee7e2d
    "Sites.FullControl.All" = "High" #5a54b8b3-347c-476d-8f8e-42d5c7424d29
    "Sites.Manage.All" = "High" #65e50fdc-43b7-4915-933e-e8138f11f40a
    "Sites.Read.All" = "High" #205e70e5-aba6-4c52-a976-6d2d46c48043
    "Sites.ReadWrite.All" = "High" #89fe6a52-be36-487e-b7d8-d061c450a026
    "Files.Read.All" = "High" #df85f4d6-205c-4ac5-a5ea-6bf408dba283
    "Files.ReadWrite.All" = "High" #863451e7-0667-486c-a5d6-d135439485f0
    "DeviceLocalCredential.Read.All" = "High" #9917900e-410b-4d15-846e-42a357488545
    "UserAuthMethod-Phone.ReadWrite" = "High" #6c4aad61-f76b-46ad-a22c-57d4d3d962af
    "UserAuthMethod-Phone.ReadWrite.All" = "High" #48c99302-9a24-4f27-a8a7-acef4debba14
    "UserAuthMethod-Password.ReadWrite.All" = "High" #7f5b683d-df96-4690-a88d-6e336ed6dc7c
    "UserAuthMethod-Password.ReadWrite" = "High" #60cce20d-d41e-4594-b391-84bbf8cc31f3
    "AdministrativeUnit.ReadWrite.All" = "High" #7b8a2d34-6b3f-4542-a343-54651608ad81
    "User.ReadWrite.All" = "Medium" #204e0828-b5ca-4ad8-b9f3-f32a958e7cc4
    "Chat.ReadWrite.All" = "Medium" #7e9a077b-3711-42b9-b7cb-5fa5f3f7fea7
    "Mail.Read" = "Medium" #570282fd-fa5c-430d-a7fd-fc8dc98a9dca
    "Mail.ReadWrite" = "Medium" #024d486e-b451-40bb-833d-3e66d98c5c73
    "Mail.Send" = "Medium" #e383f46e-2787-4529-855e-0e479a3ffac0
    "CustomSecAttributeAssignment.ReadWrite.All" = "Medium" #ca46335e-8453-47cd-a001-8459884efeae
    "ServicePrincipalEndpoint.ReadWrite.All" = "Medium" #7297d82c-9546-4aed-91df-3d4f0a9b3ff0
    "BitlockerKey.Read.All" = "Medium" #b27a61ec-b99c-4d6a-b126-c4375d08ae30
    "Calendars.Read" = "Medium" #465a38f9-76ea-45b9-9f34-9e8b0d4b0b42
    "Calendars.Read.Shared" = "Medium" #2b9c4092-424d-4249-948d-b43879977640
    "Calendars.ReadWrite" = "Medium" #1ec239c2-d7c9-4623-a91a-a9775856bb36
    "Calendars.ReadWrite.Shared" = "Medium" #12466101-c9b8-439a-8589-dd09ee67e8e9
    "ChannelMessage.ReadWrite" = "Medium" #5922d31f-46c8-4404-9eaf-2117e390a8a4
    "ChannelMessage.Send" = "Medium" #ebf0f66e-9fb1-49e4-a278-222f76911cf4
    "Chat.ReadWrite" = "Medium" #9ff7295e-131b-4d94-90e1-69fde507ac11
    "Directory.AccessAsUser.All" = "Medium" #0e263e50-5827-48a4-b97c-d940288653c7
    "Directory.Read.All" = "Medium" #06da0dbc-49e2-44d2-8312-53f166ab848a
    "Files.ReadWrite" = "Medium" #5c28f0bf-8a70-41f1-8ab2-9032436ddb65
    "MailboxItem.ImportExport" = "Medium" #df96e8a0-f4e1-4ecf-8d83-a429f822cbd6
    "AiEnterpriseInteraction.Read" = "Medium" #859cceb9-2ec2-4e48-bcd7-b8490b5248a5
    "ChannelMessage.Edit" = "Medium" #2b61aa8a-6d36-4b2f-ac7b-f29867937c53
    "Contacts.ReadWrite" = "Medium" #d56682ec-c09e-4743-aaf4-1a3aac4caa21
    "ChatMessage.Send" = "Medium" #116b7235-7cc6-461e-b163-8e55691d839e
    "EAS.AccessAsUser.All" = "Medium" #ff91d191-45a0-43fd-b837-bd682c4a0b0f
    "EWS.AccessAsUser.All" = "Medium" #9769c687-087d-48ac-9cb3-c37dde652038
    "EntitlementMgmt-SubjectAccess.ReadWrite" = "Medium" #e9fdcbbb-8807-410f-b9ec-8d5468c7c2ac
    "IMAP.AccessAsUser.All" = "Medium" #652390e4-393a-48de-9484-05f9b1212954
    "MailboxFolder.Read" = "Medium" #52dc2051-4958-4636-8f2a-281d39c6981c
    "MailboxFolder.ReadWrite" = "Medium" #077fde41-7e0b-4c5b-bcd1-e9d743a30c80
    "MailboxItem.Read" = "Medium" #82305458-296d-4edd-8b0b-74dd74c34526
    "MailboxSettings.ReadWrite" = "Medium" #818c620a-27a9-40bd-a6a5-d96f7d610b4b
    "Notes.Read" = "Medium" #371361e4-b9e2-4a3f-8315-2a301a3b0a3d
    "Notes.Read.All" = "Medium" #dfabfca6-ee36-4db2-8208-7a28381419b3
    "Notes.ReadWrite" = "Medium" #615e26af-c38a-4150-ae3e-c3b0d4cb1d6a
    "Notes.ReadWrite.All" = "Medium" #64ac0503-b4fa-45d9-b544-71a463f05da0
    "POP.AccessAsUser.All" = "Medium" #d7b7f2d9-0f45-4ea1-9d42-e50810c06991
    "offline_access" = "Low" #7427e0e9-2fba-42fe-b0c0-848c9e6a8182
    "openid" = "Low" #37f7f235-527c-4136-accd-4a02d197296e
    "email" = "Low" #64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0
    "profile" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
    "User.Read" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
}

#Store the MS Tenant IDs in an array to check if an Enterprise Application is a Microsoft app
$global:GLOBALMsTenantIds = @("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47", "33e01921-4d64-4f8c-a055-5bdaffd5e33d", "cdc5aeea-15c5-4db6-b079-fcadd2505dc2")

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-EntraRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $EligibleImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""
        
        foreach ($Role in $RoleDetails) {
            $RoleImpact = 0
            switch ($Role.RoleTier) {
                0 {
                    $RoleImpact = $GLOBALImpactScore["EntraRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $RoleImpact = $GLOBALImpactScore["EntraRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $RoleImpact = $GLOBALImpactScore["EntraRoleTier2"]
                    $Tier2Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    if ($Role.IsPrivileged) {
                        $RoleImpact = $GLOBALImpactScore["EntraRoleTier?Privileged"]
                    } else {
                        $RoleImpact = $GLOBALImpactScore["EntraRoleTier?"]
                    }
                    break
                }
            }

            $ImpactScore += $RoleImpact
            if ($Role.AssignmentType -eq "Eligible") {
                $EligibleImpactScore += $RoleImpact
            }
        }
        
        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Entra "+$word+" assigned"
        }
        
        return [PSCustomObject]@{
            ImpactScore         = $ImpactScore
            EligibleImpactScore = $EligibleImpactScore
            Warning             = $roleSummary
        }
}

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-AzureRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $EligibleImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $Tier3Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""
        
        foreach ($Role in $RoleDetails) {
            $RoleImpact = 0
            switch ($Role.RoleTier) {
                0 {
                    $RoleImpact = $GLOBALImpactScore["AzureRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $RoleImpact = $GLOBALImpactScore["AzureRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $RoleImpact = $GLOBALImpactScore["AzureRoleTier2"]
                    $Tier2Count++
                    break
                }
                3 {
                    $RoleImpact = $GLOBALImpactScore["AzureRoleTier3"]
                    $Tier3Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    $RoleImpact = $GLOBALImpactScore["AzureRoleTier?"]
                    break
                }
            }

            $ImpactScore += $RoleImpact
            if ($Role.AssignmentType -eq "Eligible") {
                $EligibleImpactScore += $RoleImpact
            }
        }
        
        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($Tier3Count -ge 1) { $roleParts += "$Tier3Count (Tier3)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $Tier3Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Azure "+$word+" assigned"
        }
        
        return [PSCustomObject]@{
            ImpactScore         = $ImpactScore
            EligibleImpactScore = $EligibleImpactScore
            Warning             = $roleSummary
        }
}


# Function to get Azure IAM assignments
function Get-AllAzureIAMAssignmentsNative {
    [CmdletBinding()]
    param()

    Write-Host "[*] Get Azure IAM assignments"

    $IamAssignmentsHT = @{}
    $assignmentsEligible = @()
    $seenAssignments = New-Object System.Collections.Generic.HashSet[System.String]
    #Retrieve role assignments for each subscription and filter by scope
    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $subscriptions = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop) | ForEach-Object {
        [PSCustomObject]@{
            Id               = $_.subscriptionId
            DisplayName      = $_.displayName
            State            = $_.state
            ManagedByTenants = $_.managedByTenants
        }
    }

    # Build lookup tables to resolve scope IDs to readable names.
    $subscriptionScopeMap = @{}
    foreach ($sub in $subscriptions) {
        if (-not [string]::IsNullOrWhiteSpace($sub.Id) -and -not [string]::IsNullOrWhiteSpace($sub.DisplayName)) {
            $subscriptionScopeMap[$sub.Id.ToLowerInvariant()] = $sub.DisplayName
        }

        $managedTenantCount = if ($null -ne $sub.ManagedByTenants) {
            @($sub.ManagedByTenants).Count
        } else {
            0
        }
        Write-Log -Level Debug -Message "Subscription $($sub.DisplayName) $($sub.Id) | ManagedByTenants: $managedTenantCount"
    }
    $global:GLOBALAzureSubscriptionScopeMap = $subscriptionScopeMap

    $managementGroupScopeMap = @{}
    try {
        # Query Resource Graph for management group IDs and display names via the subscription.
        $url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        $body = @{
            query = "ResourceContainers| where type =~ 'microsoft.resources/subscriptions'| mv-expand mg = properties.managementGroupAncestorsChain| project ResourceId = tostring(mg.name),DisplayName = tostring(mg.displayName),tenantId | summarize DisplayName = any(DisplayName) by ResourceId"
            options = @{
                resultFormat = "objectArray"
            }
        }
        $resourceGraphResponse = Send-ApiRequest -Method POST -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -Body $body -Silent -ErrorAction Stop

        # Normalize the query response to a flat row collection.
        $managementGroups = @()
        if ($resourceGraphResponse -is [System.Collections.IEnumerable] -and -not ($resourceGraphResponse -is [string])) {
            foreach ($entry in $resourceGraphResponse) {
                if ($entry -and $entry.PSObject.Properties.Name -contains 'data' -and $entry.data) {
                    $managementGroups += @($entry.data)
                } else {
                    $managementGroups += @($entry)
                }
            }
        } elseif ($resourceGraphResponse -and $resourceGraphResponse.PSObject.Properties.Name -contains 'data' -and $resourceGraphResponse.data) {
            $managementGroups = @($resourceGraphResponse.data)
        } elseif ($null -ne $resourceGraphResponse) {
            $managementGroups = @($resourceGraphResponse)
        }

        foreach ($managementGroup in $managementGroups) {
            $managementGroupId = [string]$managementGroup.ResourceId
            $managementGroupName = [string]$managementGroup.DisplayName
            if ([string]::IsNullOrWhiteSpace($managementGroupName)) {
                $managementGroupName = $managementGroupId
            }

            if (-not [string]::IsNullOrWhiteSpace($managementGroupId)) {
                $managementGroupScopeMap[$managementGroupId.ToLowerInvariant()] = $managementGroupName
            }
        }
        Write-Log -Level Debug -Message "Got $($managementGroupScopeMap.Count) management groups for Azure scope resolution"
    } catch {
        Write-Log -Level Debug -Message "Management group scope resolution via Resource Graph unavailable. Using scope IDs. Error: $($_.Exception.Message)"
    }

    $subscriptionResourceCounts = @{}
    try {
        $body = @{
            query   = "Resources | summarize Count=count() by subscriptionId"
            options = @{ resultFormat = "objectArray" }
        }
        $resourceCountResponse = Send-ApiRequest -Method POST -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -Body $body -Silent -ErrorAction Stop
        $resourceCountRows = @()
        if ($resourceCountResponse -is [System.Collections.IEnumerable] -and -not ($resourceCountResponse -is [string])) {
            foreach ($entry in $resourceCountResponse) {
                if ($entry -and $entry.PSObject.Properties.Name -contains 'data' -and $entry.data) { $resourceCountRows += @($entry.data) }
                else { $resourceCountRows += @($entry) }
            }
        } elseif ($resourceCountResponse -and $resourceCountResponse.PSObject.Properties.Name -contains 'data' -and $resourceCountResponse.data) {
            $resourceCountRows = @($resourceCountResponse.data)
        } elseif ($resourceCountResponse) {
            $resourceCountRows = @($resourceCountResponse)
        }
        foreach ($row in $resourceCountRows) {
            if (-not [string]::IsNullOrWhiteSpace([string]$row.subscriptionId)) {
                $subscriptionResourceCounts[[string]$row.subscriptionId.ToLowerInvariant()] = [int]$row.Count
            }
        }
        Write-Log -Level Debug -Message "Got resource counts for $($subscriptionResourceCounts.Count) subscriptions"
    } catch {
        Write-Log -Level Debug -Message "Resource count query unavailable: $($_.Exception.Message)"
    }

    $GlobalAuditSummary.Subscriptions.Details = @($subscriptions | ForEach-Object {
        $resourceCount = $subscriptionResourceCounts[$_.Id.ToLowerInvariant()]
        [PSCustomObject]@{
            Id               = $_.Id
            DisplayName      = $_.DisplayName
            State            = $_.State
            ManagedByTenants = if ($null -ne $_.ManagedByTenants) { @($_.ManagedByTenants).Count } else { 0 }
            Resources        = if ($null -ne $resourceCount) { $resourceCount } else { "-" }
        }
    })

    # Resolve known scope IDs in ARM paths and keep the original path when no mapping exists.
    function Resolve-AzureIamScopePath {
        param(
            [Parameter(Mandatory = $false)]
            [string]$Scope
        )

        if ([string]::IsNullOrWhiteSpace($Scope)) {
            return $Scope
        }

        if ($Scope -imatch '^/subscriptions/([^/]+)(/.*)?$') {
            $scopeId = $Matches[1]
            $scopeSuffix = $Matches[2]
            $scopeName = $subscriptionScopeMap[$scopeId.ToLowerInvariant()]

            if (-not [string]::IsNullOrWhiteSpace($scopeName)) {
                if (-not $scopeSuffix) { $scopeSuffix = "" }
                return "/subscriptions/$scopeName$scopeSuffix"
            }
            return $Scope
        }

        if ($Scope -imatch '^/providers/Microsoft\.Management/managementGroups/([^/]+)(/.*)?$') {
            $scopeId = $Matches[1]
            $scopeSuffix = $Matches[2]
            $scopeName = $managementGroupScopeMap[$scopeId.ToLowerInvariant()]

            if (-not [string]::IsNullOrWhiteSpace($scopeName)) {
                if (-not $scopeSuffix) { $scopeSuffix = "" }
                return "/providers/Microsoft.Management/managementGroups/$scopeName$scopeSuffix"
            }
            return $Scope
        }

        return $Scope
    }

    # Build a normalized lookup key so active role assignments can be matched
    # against Azure PIM schedule instances even when the ARM object IDs differ.
    function Get-AzureIamAssignmentLookupKey {
        param(
            [Parameter(Mandatory = $true)]
            [string]$PrincipalId,
            [Parameter(Mandatory = $true)]
            [string]$RoleDefinitionId,
            [Parameter(Mandatory = $false)]
            [string]$Scope
        )

        $normalizedScope = if ([string]::IsNullOrWhiteSpace($Scope)) { "/" } else { $Scope }
        return ("{0}|{1}|{2}" -f $PrincipalId, $RoleDefinitionId, $normalizedScope).ToLowerInvariant()
    }

    # Keep the most relevant schedule instance for a lookup key. When multiple
    # instances exist, prefer the one with the latest end time.
    function Set-AzureScheduleLookupEntry {
        param(
            [Parameter(Mandatory = $true)]
            [hashtable]$Lookup,
            [Parameter(Mandatory = $true)]
            [string]$Key,
            [Parameter(Mandatory = $true)]
            [pscustomobject]$Entry
        )

        if ([string]::IsNullOrWhiteSpace($Key)) {
            return
        }

        if (-not $Lookup.ContainsKey($Key)) {
            $Lookup[$Key] = $Entry
            return
        }

        $existingEntry = $Lookup[$Key]
        $existingEnd = if ($null -ne $existingEntry.EndDateTime -and -not [string]::IsNullOrWhiteSpace([string]$existingEntry.EndDateTime)) { [datetime]$existingEntry.EndDateTime } else { [datetime]::MinValue }
        $newEnd = if ($null -ne $Entry.EndDateTime -and -not [string]::IsNullOrWhiteSpace([string]$Entry.EndDateTime)) { [datetime]$Entry.EndDateTime } else { [datetime]::MinValue }

        if ($newEnd -gt $existingEnd) {
            $Lookup[$Key] = $Entry
        }
    }

    #Get all Azure roles for lookup
    $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
    $response = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)
    $roleHashTable = @{}
    $response | ForEach-Object {
        # Extract RoleName and ObjectId
        $roleName = $_.properties.RoleName
        $RoleType = $_.properties.type
        $objectId = ($_.id -split '/')[-1]
    
        # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
        $roleHashTable[$objectId] = @{
            RoleName = $roleName
            RoleType = $roleType
            RoleId   = $objectId
        }
    }

    #Get all custom roles and add them to the HT
    $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?`$filter=type+eq+'CustomRole'&api-version=2022-04-01"
    $response = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)

    $response | ForEach-Object {
        # Extract RoleName and ObjectId
        $roleName = $_.properties.RoleName
        $RoleType = $_.properties.type
        $objectId = ($_.id -split '/')[-1]
    
        # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
        $roleHashTable[$objectId] = @{
            RoleName = $roleName
            RoleType = $roleType
            RoleId   = $objectId
        }
    }
    Write-Log -Level Debug -Message "Got $($roleHashTable.count) role definitions"


    foreach ($subscription in $subscriptions) {       
        # Two lookup strategies are used for Azure PIM activations:
        # - by originating roleAssignment id when ARM provides a direct link
        # - by principal/role/scope as a fallback for less explicit responses
        $ActiveScheduleAssignmentsByOriginId = @{}
        $ActiveScheduleAssignmentsByKey = @{}

        try {
            Write-Log -Level Debug -Message "Checking PIM activation schedule instances for subscription $($subscription.Id)"
            $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"
            $AssignmentScheduleInstances = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -Silent -ErrorAction Stop)

            foreach ($instance in $AssignmentScheduleInstances) {
                $instanceProperties = $instance.properties
                if ($null -eq $instanceProperties) {
                    continue
                }

                $roleId = ($instanceProperties.roleDefinitionId -split '/')[-1]
                $lookupKey = Get-AzureIamAssignmentLookupKey -PrincipalId ([string]$instanceProperties.principalId) -RoleDefinitionId ([string]$roleId) -Scope ([string]$instanceProperties.scope)
                $linkedEligibilityScheduleId = [string]$instanceProperties.linkedRoleEligibilityScheduleId
                # Only schedule instances linked to an eligibility schedule are
                # considered PIM activations. Plain scheduled direct assignments
                # must not be reported as "ActivatedViaPIM".
                if (
                    [string]::IsNullOrWhiteSpace($linkedEligibilityScheduleId) -and
                    [string]::IsNullOrWhiteSpace([string]$instanceProperties.linkedRoleEligibilityScheduleInstanceId)
                ) {
                    continue
                }

                $scheduleEntry = [pscustomobject]@{
                    StartDateTime          = $instanceProperties.startDateTime
                    EndDateTime            = $instanceProperties.endDateTime
                    OriginRoleAssignmentId = [string]$instanceProperties.originRoleAssignmentId
                }

                Set-AzureScheduleLookupEntry -Lookup $ActiveScheduleAssignmentsByKey -Key $lookupKey -Entry $scheduleEntry

                if (-not [string]::IsNullOrWhiteSpace($scheduleEntry.OriginRoleAssignmentId)) {
                    Set-AzureScheduleLookupEntry -Lookup $ActiveScheduleAssignmentsByOriginId -Key $scheduleEntry.OriginRoleAssignmentId.ToLowerInvariant() -Entry $scheduleEntry
                }
            }

            Write-Log -Level Debug -Message "Got $($ActiveScheduleAssignmentsByKey.Count) Azure PIM activation schedule instances for subscription $($subscription.Id)"
        } catch {
            Write-Log -Level Debug -Message "Unable to enrich Azure role assignments with PIM activation data for subscription $($subscription.Id): $($_.Exception.Message)"
        }

        #Active Roles
        $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $response = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)
        $AssignmentsActive = $response | ForEach-Object {
            $roleId = ($_.properties.roleDefinitionId -split '/')[-1]
            $rawScope = [string]$_.properties.scope
            $resolvedScope = Resolve-AzureIamScopePath -Scope $rawScope
            $lookupKey = Get-AzureIamAssignmentLookupKey -PrincipalId ([string]$_.properties.principalId) -RoleDefinitionId ([string]$roleId) -Scope $rawScope

            # Null safe check
            if (-not $roleHashTable.ContainsKey($roleId)) {
                Write-Log -Level Debug -Message "Skipping unknown RoleId: $roleId"
                return
            }
            $RoleDetails = $roleHashTable[$roleId]
            $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")


            if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                # If the RoleDefinition ID is found, return it's Tier-Level
                $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
            } else {
                # Set to ? if not assigned to a tier level
                $RoleTier = "?"
            }

            # Prefer an explicit origin-roleAssignment match. Only fall back to
            # the composite key when ARM did not expose an origin assignment id.
            $ActiveScheduleAssignment = $null
            $roleAssignmentId = [string]$_.id
            if (-not [string]::IsNullOrWhiteSpace($roleAssignmentId) -and $ActiveScheduleAssignmentsByOriginId.ContainsKey($roleAssignmentId.ToLowerInvariant())) {
                $ActiveScheduleAssignment = $ActiveScheduleAssignmentsByOriginId[$roleAssignmentId.ToLowerInvariant()]
            } elseif ($ActiveScheduleAssignmentsByKey.ContainsKey($lookupKey)) {
                $scheduleCandidate = $ActiveScheduleAssignmentsByKey[$lookupKey]
                if ([string]::IsNullOrWhiteSpace([string]$scheduleCandidate.OriginRoleAssignmentId)) {
                    $ActiveScheduleAssignment = $scheduleCandidate
                }
            }

            [PSCustomObject]@{
                ObjectId           = $_.properties.principalId
                RoleAssignmentId   = $roleAssignmentId
                RoleDefinitionName = $RoleDetails.RoleName
                RoleType           = $RoleDetails.RoleType
                RoleTier           = $RoleTier
                Scope              = $resolvedScope
                Conditions         = $hasCondition 
                PrincipalType      = $_.properties.principalType
                AssignmentType     = "Active"
                ActivatedViaPIM    = ($null -ne $ActiveScheduleAssignment)
                StartDateTime      = if ($null -ne $ActiveScheduleAssignment -and $null -ne $ActiveScheduleAssignment.StartDateTime) { $ActiveScheduleAssignment.StartDateTime } else { "-" }
                EndDateTime        = if ($null -ne $ActiveScheduleAssignment -and $null -ne $ActiveScheduleAssignment.EndDateTime) { $ActiveScheduleAssignment.EndDateTime } else { "Permanent" }
            }
        }
        Write-Log -Level Debug -Message "Got $($AssignmentsActive.count) active role assignments"

        #Eligible Roles
        # If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        $AzurePIM = $true
        $response = @()
        try {
            Write-Log -Level Debug -Message "Checking PIM assignments for subscription $($subscription.Id)"
            $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview"
            $response = @(Send-ApiRequest -Method GET -Uri $url -AccessToken $GLOBALArmAccessToken.access_token -UserAgent $($GlobalAuditSummary.UserAgent.Name) -Silent -ErrorAction Stop)
        } catch {
            $apiErrorMessage = [string]$_.Exception.Message
            Write-Log -Level Debug -Message "$apiErrorMessage"
            $AzurePIM = $false
        }
        $AssignmentsEligible = @()
        if ($AzurePIM) {
            $AssignmentsEligible = $response | ForEach-Object {
                $roleId = ($_.properties.roleDefinitionId -split '/')[-1]
                if (-not $roleHashTable.ContainsKey($roleId)) {
                    Write-Log -Level Debug -Message "Skipping unknown eligible RoleId: $roleId"
                    return
                }
                $RoleDetails = $roleHashTable[$roleId]
                $resolvedScope = Resolve-AzureIamScopePath -Scope $_.properties.scope
                $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")
                if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                    # If the RoleDefinition ID is found, return it's Tier-Level
                    $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
                } else {
                    # Set to ? if not assigned to a tier level
                    $RoleTier = "?"
                }
                [PSCustomObject]@{
                    ObjectId          = $_.properties.principalId
                    RoleDefinitionName = $RoleDetails.RoleName
                    RoleType           = $RoleDetails.RoleType
                    RoleTier           = $RoleTier
                    Scope              = $resolvedScope
                    Conditions         = $hasCondition 
                    PrincipalType      = $_.properties.principalType
                    AssignmentType     = "Eligible"
                    ActivatedViaPIM    = $false
                    StartDateTime      = if ($null -ne $_.properties.startDateTime) { $_.properties.startDateTime } else { "-" }
                    EndDateTime        = if ($null -ne $_.properties.endDateTime) { $_.properties.endDateTime } else { "Permanent" }
                }
            }
            Write-Log -Level Debug -Message "Got $($AssignmentsEligible.count) eligible role assignments"
        }
   
        # Keep the existing "Active" vs "Eligible" model and enrich only the
        # active entries with PIM activation metadata.
        $AllAssignments = @($AssignmentsActive) + @($AssignmentsEligible)

        foreach ($assignment in $AllAssignments) {
            # Create a unique key for each role assignment
            $uniqueKey = "$($assignment.ObjectId)|$($assignment.RoleDefinitionName)|$($assignment.Scope)|$($assignment.AssignmentType)"

            # Check if the role assignment has already been processed
            if (-not $seenAssignments.Contains($uniqueKey)) {
                # Add the key to the HashSet to mark it as seen
                $seenAssignments.Add($uniqueKey) | Out-Null

                # Ensure the ObjectId exists in the hashtable
                if (-not $IamAssignmentsHT.ContainsKey($assignment.ObjectId)) {
                    $IamAssignmentsHT[$assignment.ObjectId] = @()
                }

                # Add the assignment to the hashtable
                $IamAssignmentsHT[$assignment.ObjectId] += [PSCustomObject]@{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    Scope = $assignment.Scope
                    RoleType = $assignment.RoleType
                    RoleTier = $assignment.RoleTier
                    Conditions = $assignment.Conditions
                    PrincipalType = $assignment.PrincipalType
                    AssignmentType = $assignment.AssignmentType
                    ActivatedViaPIM = $assignment.ActivatedViaPIM
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                }
            }
        }
    }

    return $IamAssignmentsHT
}

# Function to check the Azure IAM role assignments for the input object
function Get-AzureRoleDetails {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )

    $azureRoleDetails = @()

    # Filtering assignments based on ObjectType and the associated IDs
    if ($AzureIAMAssignments.ContainsKey($ObjectId)) {
        # Key exists, retrieve its value
        $matchingAzureRoles = $AzureIAMAssignments[$ObjectId]
        foreach ($role in $matchingAzureRoles) {
            $roleInfo = [PSCustomObject]@{
                RoleName = $role.RoleDefinitionName
                RoleType = $role.RoleType
                Scope    = $role.Scope
                Conditions = $role.Conditions
                RoleTier = $role.RoleTier
                AssignmentType  = $role.AssignmentType
                ActivatedViaPIM = $role.ActivatedViaPIM
                StartDateTime = $role.StartDateTime
                EndDateTime = $role.EndDateTime
            }
            $azureRoleDetails += $roleInfo
        }
    }

    return $azureRoleDetails
}


# Function to get user details for PIM fro groups eligible assignments
function Get-PIMForGroupsAssignmentsDetails {
    param (
        [Parameter(Mandatory = $true)]
        [array]$TenantPimForGroupsAssignments
    )

    foreach ($item in $TenantPimForGroupsAssignments) {

        $principalId = $item.principalId
        
        # Lookup displayname and object type for each object
        $ObjectInfo = Get-ObjectInfo $principalId

        if ($ObjectInfo) {
            # Add properties to the matching entry
            $TenantPimForGroupsAssignments | ForEach-Object {
                if ($_.principalId -eq $principalId) {
                    $_ | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $ObjectInfo.DisplayName -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "Type" -Value $ObjectInfo.Type -Force
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserPrincipalName') {$_ | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $ObjectInfo.UserPrincipalName -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'AccountEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "AccountEnabled" -Value $ObjectInfo.AccountEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserType') {$_ | Add-Member -MemberType NoteProperty -Name "UserType" -Value $ObjectInfo.UserType -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'OnPremisesSyncEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "OnPremisesSyncEnabled" -Value $ObjectInfo.OnPremisesSyncEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'Department') {$_ | Add-Member -MemberType NoteProperty -Name "Department" -Value $ObjectInfo.Department -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'JobTitle') {$_ | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value $ObjectInfo.JobTitle -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'SecurityEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "SecurityEnabled" -Value $ObjectInfo.SecurityEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'IsAssignableToRole') {$_ | Add-Member -MemberType NoteProperty -Name "IsAssignableToRole" -Value $ObjectInfo.IsAssignableToRole -Force}
                }
            }
        }
    }
    return $TenantPimForGroupsAssignments
}

# Function to get all administrative units
function Get-AdministrativeUnitsWithMembers {
    Write-Host "[*] Get Administrative units with members"
    $QueryParameters = @{
        '$select' = "Id,DisplayName,IsMemberManagementRestricted"
    }
    $AdminUnits = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $AdminUnitWithMembers = foreach ($AdminUnit in $AdminUnits) {

        # Retrieve members of the current administrative unit
        $Members = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$($AdminUnit.Id)/members" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

        $MembersUser = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user'} | Select-Object id,@{n='Type';e={'User'}},displayName
        $MembersGroup = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group'}  | Select-Object id,@{n='Type';e={'Group'}},displayName
        $MembersDevices = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device'} | Select-Object id,@{n='Type';e={'Device'}},displayName
    
        # Create a custom object for the administrative unit with its members
        [pscustomobject]@{
            AuId                            = $AdminUnit.Id
            DisplayName                     = $AdminUnit.Displayname
            IsMemberManagementRestricted    = $AdminUnit.IsMemberManagementRestricted
            MembersUser                     = $MembersUser
            MembersGroup                    = $MembersGroup
            MembersDevices                  = $MembersDevices
        }
    }

    $AuCount = $($AdminUnitWithMembers | Measure-Object).Count

    #Add information to the enumeration summary
    $GlobalAuditSummary.AdministrativeUnits.Count = $AuCount

    Write-Host "[+] Got $AuCount Administrative units with members"
    Return $AdminUnitWithMembers
}

# Get Conditional Access Policies with user and group relations
function Get-ConditionalAccessPolicies {

    Write-Host "[*] Get Conditional Access Policies"
    $Caps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/identity/conditionalAccess/policies" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    if ($Caps) {
        $CapsCount = $($Caps | Measure-Object).Count
        Write-Host "[+] Got $CapsCount Conditional Access Policies"
        $CapGroups = foreach ($cap in $Caps) {
            $excludedGroups = $cap.Conditions.Users.ExcludeGroups
            $includedGroups = $cap.Conditions.Users.IncludeGroups
            $ExcludeUsers = $cap.Conditions.Users.ExcludeUsers
            $IncludeUsers = $cap.Conditions.Users.IncludeUsers
            [PSCustomObject]@{ 
                Id = $cap.Id
                CAPName = $cap.DisplayName
                ExcludedGroup = $excludedGroups
                IncludedGroup = $includedGroups
                ExcludedUser = $ExcludeUsers
                IncludedUser = $IncludeUsers
                CAPStatus = $cap.State
            } 
        }
        $global:GLOBALPermissionForCaps = $true
    } else {
        Write-Host "[!] No Conditional Access Policies found."
        $global:GLOBALPermissionForCaps = $false
    }
    Return $CapGroups
}

#Authenticate using an refresh token and get a new token for PIM
function Invoke-MsGraphAuthPIM {

    Invoke-EntraFalconAuth -Action Auth -Purpose PimforEntra @GLOBALAuthMethods
    
    #Abort if error
    if ($GLOBALPIMsGraphAccessToken) {
        if (AuthCheckMSGraph) {
            write-host "[+] MS Graph session OK"
            $result = $true
            $global:GLOBALGraphExtendedChecks = $true
            
        } else {
            Write-host "[!] Authentication with Managed Meeting Rooms client failed"
            $result = $false
            $global:GLOBALGraphExtendedChecks = $false
        }
    } else {
        write-host "[!] PIM Data will not be collected"
        $global:GLOBALGraphExtendedChecks = $false
        $result = $false
    }
    return $result
}

#Refresh PIM token
function Invoke-MsGraphRefreshPIM {

    invoke-EntraFalconAuth -Action Refresh -Purpose PimforEntra @GLOBALAuthMethods
    
}


#Get all active Entra role assignments
function Get-EntraPIMRoleAssignments {

    Write-Host "[*] Get PIM Entra role assignments"

    $TenantPIMRoleAssignments = @()

    #Ugly workaround since $_.RoleDefinition.IsPrivileged is always empty :-(
    $EntraroleDefinitions = @{}
    # Get the role definitions and populate the array

    # Get all roleassignments and store as HT
    $QueryParameters = @{
        '$select' = "Id,IsPrivileged"
    }
    $TenantRoleDefinitions= Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleDefinitions" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($role in $TenantRoleDefinitions) {
        $EntraroleDefinitions[$role.Id] = $role.IsPrivileged
    }

    try {
        # Get all PIM for Roles assignments
        $QueryParameters = @{
            '$select' = "PrincipalId,DirectoryScopeId,RoleDefinition,RoleDefinitionId,ScheduleInfo"
            '$expand' = "RoleDefinition"
        }
        $PimRoles = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleEligibilitySchedules" -QueryParameters $QueryParameters -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    
    } catch {
        if ($($_.Exception.Message) -match "Status: 400") {
            write-host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Entra roles is used."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Assuming no PIM for Entra roles is used."
        }
        #Set global var so that PIM role settigns are NOT checked
        $global:GLOBALPIMForEntraRolesChecked = $false
        Return
    }

    $PimRoles | ForEach-Object {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($_.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($_.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $_.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $_.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($_.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$_.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }


        # Add the role assignment to the array
        $TenantPIMRoleAssignments += [PSCustomObject]@{
            PrincipalId     = $_.PrincipalId
            AssignmentType  = "Eligible"
            ActivatedViaPIM = $false
            DirectoryScopeId = $_.DirectoryScopeId
            RoleDefinitionId  = $_.RoleDefinition.Id
            DisplayName      = $_.RoleDefinition.DisplayName
            IsPrivileged     = $EntraroleDefinitions[$_.RoleDefinition.Id]
            RoleTier         = $RoleTier
            IsEnabled        = $_.RoleDefinition.IsEnabled
            IsBuiltIn        = $_.RoleDefinition.IsBuiltIn
            StartDateTime    = $_.ScheduleInfo.StartDateTime
            EndDateTime      = if ($_.ScheduleInfo.Expiration.EndDateTime) {$_.ScheduleInfo.Expiration.EndDateTime} else {"Permanent"}
            RoleAssignmentScheduleId = $null
            RoleAssignmentOriginId = $null
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }

    }

    #Set global var so that PIM role settigns are checked as well
    $global:GLOBALPIMForEntraRolesChecked = $true

    Write-Host "[+] Got $($TenantPIMRoleAssignments.Count) PIM eligible Entra role assignments"
    Return $TenantPIMRoleAssignments
}

#Get all active Entra role assignments
function Get-EntraRoleAssignments {
    param (
        [Parameter(Mandatory = $false)]
        [array]$TenantPimRoleAssignments
    )

    Write-Host "[*] Get Entra role assignments"

    # Create a array to store the role assignments
    $TenantRoleAssignments = @()
    $ActiveScheduleAssignmentsByOriginId = @{}
    $ActiveScheduleAssignmentsByKey = @{}

    if ($GLOBALGraphExtendedChecks -and $GLOBALPIMsGraphAccessToken) {
        if (-not (Invoke-CheckTokenExpiration $GLOBALPIMsGraphAccessToken)) { Invoke-MsGraphRefreshPIM | Out-Null }

        try {
            $ScheduleQueryParameters = @{
                '$select' = "principalId,directoryScopeId,roleDefinitionId,startDateTime,endDateTime,assignmentType,roleAssignmentOriginId,roleAssignmentScheduleId"
            }
            $AssignmentScheduleInstances = @(Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleAssignmentScheduleInstances" -QueryParameters $ScheduleQueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop)

            foreach ($instance in $AssignmentScheduleInstances) {
                if ([string]$instance.assignmentType -notin @("Activated", "Assigned")) { continue }

                $scopeId = if ([string]::IsNullOrWhiteSpace([string]$instance.directoryScopeId)) { "/" } else { [string]$instance.directoryScopeId }
                $lookupKey = "$($instance.principalId)|$($instance.roleDefinitionId)|$scopeId"
                $scheduleEntry = [PSCustomObject]@{
                    StartDateTime            = $instance.startDateTime
                    EndDateTime              = $instance.endDateTime
                    ScheduleAssignmentType   = [string]$instance.assignmentType
                    RoleAssignmentScheduleId = $instance.roleAssignmentScheduleId
                    RoleAssignmentOriginId   = $instance.roleAssignmentOriginId
                }

                if (
                    -not $ActiveScheduleAssignmentsByKey.ContainsKey($lookupKey) -or
                    (
                        $null -ne $instance.endDateTime -and
                        (
                            $null -eq $ActiveScheduleAssignmentsByKey[$lookupKey].EndDateTime -or
                            [datetime]$instance.endDateTime -gt [datetime]$ActiveScheduleAssignmentsByKey[$lookupKey].EndDateTime
                        )
                    )
                ) {
                    $ActiveScheduleAssignmentsByKey[$lookupKey] = $scheduleEntry
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$instance.roleAssignmentOriginId)) {
                    if (
                        -not $ActiveScheduleAssignmentsByOriginId.ContainsKey($instance.roleAssignmentOriginId) -or
                        (
                            $null -ne $instance.endDateTime -and
                            (
                                $null -eq $ActiveScheduleAssignmentsByOriginId[$instance.roleAssignmentOriginId].EndDateTime -or
                                [datetime]$instance.endDateTime -gt [datetime]$ActiveScheduleAssignmentsByOriginId[$instance.roleAssignmentOriginId].EndDateTime
                            )
                        )
                    ) {
                        $ActiveScheduleAssignmentsByOriginId[$instance.roleAssignmentOriginId] = $scheduleEntry
                    }
                }
            }

            Write-Log -Level Debug -Message "Got $($ActiveScheduleAssignmentsByKey.Count) active Entra role assignment schedule instances"
        } catch {
            Write-Log -Level Debug -Message "Unable to enrich Entra role assignments with PIM activation data: $($_.Exception.Message)"
        }
    }

    # Get all roleassignments
    $QueryParameters = @{
        '$select' = "Id,PrincipalId,DirectoryScopeId,RoleDefinitionId"
        '$expand' = "RoleDefinition"
    }
    $TenantRoleAssignmentsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleAssignments" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    foreach ($role in $TenantRoleAssignmentsRaw) {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($role.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($role.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $role.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $role.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($role.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$role.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }

        $scopeId = if ([string]::IsNullOrWhiteSpace([string]$role.DirectoryScopeId)) { "/" } else { [string]$role.DirectoryScopeId }
        $lookupKey = "$($role.PrincipalId)|$($role.RoleDefinition.Id)|$scopeId"
        $ActiveScheduleAssignment = $null
        $IsActivated = $false
        $StartDateTime = "-"
        $EndDateTime = "Permanent"
        $RoleAssignmentScheduleId = $null
        $RoleAssignmentOriginId = $null

        if (-not [string]::IsNullOrWhiteSpace([string]$role.Id) -and $ActiveScheduleAssignmentsByOriginId.ContainsKey($role.Id)) {
            $ActiveScheduleAssignment = $ActiveScheduleAssignmentsByOriginId[$role.Id]
        } elseif ($ActiveScheduleAssignmentsByKey.ContainsKey($lookupKey)) {
            $ActiveScheduleAssignment = $ActiveScheduleAssignmentsByKey[$lookupKey]
        }

        if ($null -ne $ActiveScheduleAssignment) {
            $IsActivated = $ActiveScheduleAssignment.ScheduleAssignmentType -eq "Activated"
            if ($null -ne $ActiveScheduleAssignment.StartDateTime) {
                $StartDateTime = $ActiveScheduleAssignment.StartDateTime
            }
            if ($null -ne $ActiveScheduleAssignment.EndDateTime) {
                $EndDateTime = $ActiveScheduleAssignment.EndDateTime
            }
            $RoleAssignmentScheduleId = $ActiveScheduleAssignment.RoleAssignmentScheduleId
            $RoleAssignmentOriginId = $ActiveScheduleAssignment.RoleAssignmentOriginId
        }

        # Add the role assignment to the array
        $TenantRoleAssignments += [PSCustomObject]@{
            PrincipalId      = $role.PrincipalId
            AssignmentType   = "Active"
            ActivatedViaPIM  = $IsActivated
            DirectoryScopeId  = $role.DirectoryScopeId
            RoleDefinitionId = $role.RoleDefinition.Id
            DisplayName      = $role.RoleDefinition.DisplayName
            IsPrivileged     = $role.RoleDefinition.IsPrivileged
            RoleTier         = $RoleTier
            IsEnabled        = $role.RoleDefinition.IsEnabled
            IsBuiltIn        = $role.RoleDefinition.IsBuiltIn
            StartDateTime    = $StartDateTime
            EndDateTime      = $EndDateTime
            RoleAssignmentScheduleId = $RoleAssignmentScheduleId
            RoleAssignmentOriginId = $RoleAssignmentOriginId
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }
    }
    
    Write-Host "[+] Retrieved $($TenantRoleAssignments.Count) role assignments"

    if ($TenantPimRoleAssignments.count -ge 1) {
        Write-Host "[+] Merge with PIM role assignments"
        # Combine both arrays into one
        $TenantRoleAssignments = $TenantRoleAssignments + $TenantPimRoleAssignments
    }

    # Build the hashtable
    $TenantRoleAssignmentsHT = @{}

    foreach ($assignment in $TenantRoleAssignments) {
        $principalId = $assignment.PrincipalId

        if (-not $TenantRoleAssignmentsHT.ContainsKey($principalId)) {
            $TenantRoleAssignmentsHT[$principalId] = @()
        }
        $TenantRoleAssignmentsHT[$principalId] += $assignment
    }
    Return $TenantRoleAssignmentsHT
}



$global:TenantReportTabs = @()

function Initialize-TenantReportTabs {
    param(
        [Parameter(Mandatory)][string]$StartTimestamp,
        [Parameter(Mandatory)][pscustomobject]$CurrentTenant,
        [Parameter(Mandatory)][pscustomobject]$TenantReports
    )

    $tenantNameEscaped = $CurrentTenant.FileSafeDisplayNameEncoded

    $defs = @(
        @{ Prop = 'Summary';                   Key = 'Summary';    Title = 'Summary';                   File = "_EntraFalconEnumerationSummary_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'SecurityFindings';          Key = 'SecurityFindings'; Title = 'Security Findings';    File = "SecurityFindings_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'ConditionalAccessPolicies'; Key = 'CAP';        Title = 'Conditional Access';        File = "ConditionalAccessPolicies_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'Users';                     Key = 'Users';      Title = 'Users';                     File = "Users_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'Groups';                    Key = 'Groups';     Title = 'Groups';                    File = "Groups_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AppRegistrations';          Key = 'AR';         Title = 'App Registrations';         File = "AppRegistration_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'EnterpriseApps';            Key = 'EA';         Title = 'Enterprise Apps';           File = "EnterpriseApps_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'ManagedIdentities';         Key = 'MI';         Title = 'Managed Identities';        File = "ManagedIdentities_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AgentIdentityBlueprints';   Key = 'AgentIdentityBlueprints'; Title = 'Agent Blueprints'; File = "AgentIdentityBlueprints_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AgentIdentityBlueprintsPrincipals'; Key = 'AgentIdentityBlueprintsPrincipals'; Title = 'Agent Blueprint Principals'; File = "AgentIdentityBlueprintsPrincipals_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AgentIdentities';           Key = 'AgentIdentities'; Title = 'Agent Identities';     File = "AgentIdentities_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'EntraRoles';                Key = 'RoleEntra';  Title = 'Roles (Entra)';  File = "Role_Assignments_Entra_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'AzureRoles';                Key = 'RoleAz';     Title = 'Roles (Azure)';  File = "Role_Assignments_Azure_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'PimForEntra';               Key = 'PIM';        Title = 'PIM (Entra)';                File = "PIM_${StartTimestamp}_${tenantNameEscaped}.html" }
        @{ Prop = 'PimForGroups';              Key = 'PIMGroups';  Title = 'PIM (Groups)';               File = "PIM_Groups_${StartTimestamp}_${tenantNameEscaped}.html" }
    )

    $tabs = New-Object System.Collections.Generic.List[object]

    foreach ($d in $defs) {
        $prop = [string]$d.Prop
        $enabled = $false

        try {
            $value = $TenantReports.$prop
            if ($value -is [bool]) { $enabled = $value }
        } catch {
            $enabled = $false
        }

        if (-not $enabled) { continue }

        $tabs.Add([pscustomobject]@{
            key   = [string]$d.Key
            title = [string]$d.Title
            file  = [string]$d.File
        })
    }

    $global:TenantReportTabs = $tabs
}


function Set-GlobalReportManifest {
    param(
        [Parameter(Mandatory)][string]$CurrentReportKey,
        [Parameter(Mandatory)][string]$CurrentReportName,
        [Parameter()][object]$Warnings
    )

    $warningsArray = @()

    if ($null -ne $Warnings) {
        if ($Warnings -is [string]) {
            $warningsArray = @($Warnings)
        } elseif ($Warnings -is [System.Collections.IEnumerable]) {
            $warningsArray = @($Warnings) | ForEach-Object { [string]$_ }
        } else {
            $warningsArray = @([string]$Warnings)
        }

        $warningsArray = $warningsArray |
            ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
            Where-Object { $_ }
    }

    $manifest = [pscustomobject]@{
        tenantName        = $global:ReportContext.TenantName
        tenantId          = $global:ReportContext.TenantId
        executedAt        = $global:ReportContext.StartTimestamp
        currentReportKey  = $CurrentReportKey
        currentReportName = $CurrentReportName
        warnings          = $warningsArray
        reports           = $global:TenantReportTabs
    }

    $json = $manifest | ConvertTo-Json -Depth 6 -Compress
    $global:GLOBALReportManifestScript = "<script id=`"report-manifest`" type=`"application/json`">$json</script>`n"
}





#Get all active Entra role assignments
function Get-PimforGroupsAssignments {
    [CmdletBinding()]
    Param ()
    $ResultAuthCheck = $true
    $global:GLOBALPimForGroupsHT = @{}
    $global:GLOBALPimForGroupsResources = @()
    $global:GLOBALPimForGroupsAssignmentObjects = @()
    $isBroCiFlow = $false
    if ($GLOBALAuthMethods -and $GLOBALAuthMethods.ContainsKey("AuthFlow")) {
        $isBroCiFlow = @("BroCi", "BroCiManualCode", "BroCiToken") -contains [string]$GLOBALAuthMethods.AuthFlow
    }
    $isServicePrincipalFlow = ([string]$GLOBALAuthMethods.AuthFlow -eq "ServicePrincipal")
    $global:GLOBALPimForGroupsPolicySettingsSupported = $isBroCiFlow -or $isServicePrincipalFlow
    $global:GLOBALPimForGroupsPolicySettingsSkipReason = if ($isBroCiFlow -or $isServicePrincipalFlow) {
        $null
    } else {
        "PIM for Groups settings report requires BroCi authentication because non-BroCi flows do not have the required pre-consented permissions."
    }
    
    Write-Host "[*] Authentication for PIM for Groups assessment (skip with -SkipPimForGroups)"
    if (-not (invoke-EntraFalconAuth -Action Auth -Purpose PimforGroup @GLOBALAuthMethods)) {
        throw "[!] Authentication failed for PimforGroup"
    }

    # /me is not available for app-only tokens. using /organization as a connectivity check instead
    $authCheckUri = if ($GLOBALAuthMethods.AuthFlow -eq "ServicePrincipal") { '/organization?$select=id' } else { '/me?$select=id' }
    try {
        $AuthCheck = Send-GraphRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Method GET -Uri $authCheckUri -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -erroraction Stop
    } catch {
        write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
        $ResultAuthCheck = $false
        $global:GLOBALPimForGroupsChecked = $false
        $global:GLOBALPimForGroupsPolicySettingsSupported = $false
        $global:GLOBALPimForGroupsPolicySettingsSkipReason = "PIM for Groups assessment failed during authentication."
    }

    if ($ResultAuthCheck) {
        $global:GLOBALPimForGroupsChecked = $true
        $proceed = $true

        #Retrieve Pim Enabled groups. If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        try {
            #Use alternative Endpoint for BroCI since no SP with pre-consented privieleges PrivilegedAccess.Read(Write).AzureADGroup exists
            if ($isBroCiFlow) {
                Write-Host "[*] Retrieve PIM enabled groups (BroCi / using api.azrbac.mspim.azure.com)"
                $uri = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources?`$select=id,displayName&`$top=999"
                $PimEnabledGroupsRaw = @(Send-ApiRequest -Method GET -Uri $uri -AccessToken $GLOBALPimForGroupAzrbacAccessToken.access_token -Silent -UserAgent $GlobalAuditSummary.UserAgent.Name -ErrorAction Stop)
            } else {
                Write-Host "[*] Retrieve PIM enabled groups (Graph)"
                $PimEnabledGroupsRaw = Send-GraphRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Method GET -Uri "/privilegedAccess/aadGroups/resources" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
            }
        } catch {
            $apiErrorMessage = [string]$_.Exception.Message
            Write-Log -Level Debug -Message "$apiErrorMessage"
            Write-host "[*] PIM for groups is not used"

            $PIMforGroupsAssignments = ""
            $proceed = $false
        }

        if ($proceed) {
            $PimEnabledGroups = $PimEnabledGroupsRaw | ForEach-Object {
                [PSCustomObject]@{
                    Id          = $_.Id
                    displayName  = $_.displayName
                }
            }
            $global:GLOBALPimForGroupsResources = @($PimEnabledGroups)
    
            #Stored groups in global HT var to use in groups module
            $global:GLOBALPimForGroupsHT = @{}
            foreach ($item in $PimEnabledGroups) {
                $GLOBALPimForGroupsHT[$item.Id] = $item.displayName
            }
    
            $PimEnabledGroupsCount = ($PimEnabledGroups | Measure-Object).count
            if ($PimEnabledGroupsCount -ge 1) {
                Write-Host "[+] Got $PimEnabledGroupsCount PIM enabled groups"
                                     
                $Requests = @()
                $RequestID = 0
                # Loop through each group and create a request entry
                $PimEnabledGroups | ForEach-Object {
                    $RequestID++
                    $Requests += @{
                        "id"     = $RequestID  # Unique request ID
                        "method" = "GET"
                        "url"    =   "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$select=accessId,groupId,principalId&`$filter=groupId eq '$($_.id)'"
                    }
                }
                Write-Host "[*] Get eligible objects for those groups"
                # Send Batch request
                $PIMforGroupsAssignments = (Send-GraphBatchRequest -AccessToken $GLOBALPimForGroupAccessToken.access_token -Requests $Requests -BetaAPI -BatchDelay 1 -MaxBatchSize 8 -UserAgent $($GlobalAuditSummary.UserAgent.Name)).response.value
                $global:GLOBALPimForGroupsAssignmentObjects = @($PIMforGroupsAssignments)
                Write-Host "[+] Got $($PIMforGroupsAssignments.Count) objects eligible for a PIM-enabled group"
                
            } else {
                Write-Host "[!] No PIM enabled groups found"
                $PIMforGroupsAssignments = ""
                $global:GLOBALPimForGroupsResources = @()
                $global:GLOBALPimForGroupsAssignmentObjects = @()
            }
        }
    }

    Return $PIMforGroupsAssignments
}

#Function to check the API permission for known Dangerous or high
function Get-APIPermissionCategory{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$InputPermission,
        [Parameter(Mandatory=$true)][string]$PermissionType
    )

    if ($PermissionType -eq "application") {
            # Check if the input permission ID exists in the hashtable
        if ($GLOBALApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }

    } elseif ($PermissionType -eq "delegated") {
        # Check if the input permission ID exists in the hashtable
        if ($GLOBALDelegatedApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALDelegatedApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }
    } else {
        return "ApiPermissionLookupError"
    }
}

# Build a reusable cache of application app roles keyed by both service principal object ID and app ID.
function New-AppRoleReferenceCache {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][object[]]$ServicePrincipals
    )

    $cache = @{
        ByAppId             = @{}
        ByResourceId        = @{}
        ApiNamesByAppId     = @{}
        ApiNamesByResourceId = @{}
        AppIdsByResourceId  = @{}
    }

    foreach ($item in @($ServicePrincipals)) {
        if ($null -eq $item) { continue }

        $resourceId = if ([string]::IsNullOrWhiteSpace("$($item.Id)".Trim())) { $null } else { "$($item.Id)".Trim() }
        $resourceAppId = if ([string]::IsNullOrWhiteSpace("$($item.AppId)".Trim())) { $null } else { "$($item.AppId)".Trim() }
        $apiName = if ([string]::IsNullOrWhiteSpace($item.DisplayName)) { "-" } else { $item.DisplayName }

        if ($resourceId) {
            $cache.ApiNamesByResourceId[$resourceId] = $apiName
            $cache.AppIdsByResourceId[$resourceId] = $resourceAppId
            if (-not $cache.ByResourceId.ContainsKey($resourceId)) {
                $cache.ByResourceId[$resourceId] = @{}
            }
        }

        if ($resourceAppId) {
            $cache.ApiNamesByAppId[$resourceAppId] = $apiName
            if (-not $cache.ByAppId.ContainsKey($resourceAppId)) {
                $cache.ByAppId[$resourceAppId] = @{}
            }
        }

        foreach ($appRole in @($item.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "Application" })) {
            $permissionId = if ([string]::IsNullOrWhiteSpace("$($appRole.Id)".Trim())) { $null } else { "$($appRole.Id)".Trim() }
            if (-not $permissionId) { continue }

            $entry = [pscustomobject]@{
                PermissionId                  = $permissionId
                ApiPermission                 = if ([string]::IsNullOrWhiteSpace($appRole.Value)) { $permissionId } else { $appRole.Value }
                ApiPermissionDisplayName      = if ([string]::IsNullOrWhiteSpace($appRole.DisplayName)) { "-" } else { $appRole.DisplayName }
                ApiPermissionDescription      = if ([string]::IsNullOrWhiteSpace($appRole.Description)) { "-" } else { $appRole.Description }
                ApiPermissionCategorization   = Get-APIPermissionCategory -InputPermission $permissionId -PermissionType "application"
                ApiName                       = $apiName
                ResourceId                    = $resourceId
                ResourceAppId                 = $resourceAppId
            }

            if ($resourceId) {
                $cache.ByResourceId[$resourceId][$permissionId] = $entry
            }
            if ($resourceAppId) {
                $cache.ByAppId[$resourceAppId][$permissionId] = $entry
            }
        }
    }

    return $cache
}

# Resolve a resource service principal ID to its backing app ID from the shared cache.
function Get-AppRoleReferenceResourceAppId {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][hashtable]$AppRoleReferenceCache,
        [Parameter(Mandatory = $false)][string]$ResourceId,
        [Parameter(Mandatory = $false)][string]$ResourceAppId
    )

    if (-not [string]::IsNullOrWhiteSpace($ResourceAppId)) {
        return $ResourceAppId
    }

    if (-not $AppRoleReferenceCache) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($ResourceId) -and
        $AppRoleReferenceCache.ContainsKey('AppIdsByResourceId') -and
        $AppRoleReferenceCache.AppIdsByResourceId.ContainsKey($ResourceId)) {
        return $AppRoleReferenceCache.AppIdsByResourceId[$ResourceId]
    }

    return $null
}

# Resolve a single application permission ID from the shared cache.
function Resolve-AppRoleReference {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][hashtable]$AppRoleReferenceCache,
        [Parameter(Mandatory = $true)][string]$PermissionId,
        [Parameter(Mandatory = $false)][string]$ResourceId,
        [Parameter(Mandatory = $false)][string]$ResourceAppId
    )

    if ([string]::IsNullOrWhiteSpace($PermissionId)) {
        return $null
    }

    if (-not $AppRoleReferenceCache) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($ResourceId) -and
        $AppRoleReferenceCache.ContainsKey('ByResourceId') -and
        $AppRoleReferenceCache.ByResourceId.ContainsKey($ResourceId) -and
        $AppRoleReferenceCache.ByResourceId[$ResourceId].ContainsKey($PermissionId)) {
        return $AppRoleReferenceCache.ByResourceId[$ResourceId][$PermissionId]
    }

    if (-not [string]::IsNullOrWhiteSpace($ResourceAppId) -and
        $AppRoleReferenceCache.ContainsKey('ByAppId') -and
        $AppRoleReferenceCache.ByAppId.ContainsKey($ResourceAppId) -and
        $AppRoleReferenceCache.ByAppId[$ResourceAppId].ContainsKey($PermissionId)) {
        return $AppRoleReferenceCache.ByAppId[$ResourceAppId][$PermissionId]
    }

    return $null
}

# Return the cached API display name for a resource service principal ID or app ID.
function Get-AppRoleReferenceApiName {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][hashtable]$AppRoleReferenceCache,
        [Parameter(Mandatory = $false)][string]$ResourceId,
        [Parameter(Mandatory = $false)][string]$ResourceAppId
    )

    if (-not $AppRoleReferenceCache) {
        return "-"
    }

    if (-not [string]::IsNullOrWhiteSpace($ResourceId) -and
        $AppRoleReferenceCache.ContainsKey('ApiNamesByResourceId') -and
        $AppRoleReferenceCache.ApiNamesByResourceId.ContainsKey($ResourceId)) {
        return $AppRoleReferenceCache.ApiNamesByResourceId[$ResourceId]
    }

    if (-not [string]::IsNullOrWhiteSpace($ResourceAppId) -and
        $AppRoleReferenceCache.ContainsKey('ApiNamesByAppId') -and
        $AppRoleReferenceCache.ApiNamesByAppId.ContainsKey($ResourceAppId)) {
        return $AppRoleReferenceCache.ApiNamesByAppId[$ResourceAppId]
    }

    return "-"
}

# Build normalized delegated permission rows using the shared app-role reference cache.
function Resolve-DelegatedPermissionGrantDetails {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][hashtable]$AppRoleReferenceCache,
        [Parameter(Mandatory = $false)][object[]]$DelegatedPermissions = @()
    )

    $rows = [System.Collections.ArrayList]::new()
    foreach ($permission in @($DelegatedPermissions)) {
        if ($null -eq $permission) { continue }

        $resourceId = if ($permission.PSObject.Properties['ResourceId']) { [string]$permission.ResourceId } else { '' }
        $resourceAppId = Get-AppRoleReferenceResourceAppId -AppRoleReferenceCache $AppRoleReferenceCache -ResourceId $resourceId
        $apiName = Get-AppRoleReferenceApiName -AppRoleReferenceCache $AppRoleReferenceCache -ResourceId $resourceId -ResourceAppId $resourceAppId
        $scopeText = if ($permission.PSObject.Properties['Scope']) { [string]$permission.Scope } else { '' }
        $scopes = @($scopeText.Trim() -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($scopes.Count -eq 0) { continue }

        $consentType = if ($permission.PSObject.Properties['ConsentType']) { [string]$permission.ConsentType } else { '' }
        $principal = if ($consentType -eq "Principal" -and $permission.PSObject.Properties['PrincipalId']) {
            [string]$permission.PrincipalId
        } else {
            "-"
        }

        foreach ($scope in $scopes) {
            [void]$rows.Add([pscustomobject]@{
                ResourceId                  = $resourceId
                ResourceAppId               = $resourceAppId
                ConsentType                 = $consentType
                Scope                       = $scope
                APIName                     = $apiName
                Principal                   = $principal
                ApiPermissionCategorization = Get-APIPermissionCategory -InputPermission $scope -PermissionType "delegated"
            })
        }
    }

    return @($rows)
}

# Build the normalized permission object used by report modules from a cached app-role lookup.
function Resolve-AppRoleAssignmentRecord {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][hashtable]$AppRoleReferenceCache,
        [Parameter(Mandatory = $true)][string]$PermissionId,
        [Parameter(Mandatory = $false)][string]$ResourceId,
        [Parameter(Mandatory = $false)][string]$ResourceAppId,
        [Parameter(Mandatory = $false)][string]$ApiNameOverride
    )

    if ([string]::IsNullOrWhiteSpace($PermissionId)) {
        return $null
    }

    $resolvedResourceAppId = Get-AppRoleReferenceResourceAppId -AppRoleReferenceCache $AppRoleReferenceCache -ResourceId $ResourceId -ResourceAppId $ResourceAppId
    $resolved = Resolve-AppRoleReference -AppRoleReferenceCache $AppRoleReferenceCache -PermissionId $PermissionId -ResourceId $ResourceId -ResourceAppId $resolvedResourceAppId
    $apiName =
        if (-not [string]::IsNullOrWhiteSpace($ApiNameOverride)) {
            $ApiNameOverride
        } elseif ($resolved -and -not [string]::IsNullOrWhiteSpace($resolved.ApiName)) {
            $resolved.ApiName
        } else {
            Get-AppRoleReferenceApiName -AppRoleReferenceCache $AppRoleReferenceCache -ResourceId $ResourceId -ResourceAppId $resolvedResourceAppId
        }

    [pscustomobject]@{
        Type                         = "Permission"
        PermissionId                 = $PermissionId
        ResourceId                   = $ResourceId
        ResourceAppId                = $resolvedResourceAppId
        ApiPermission                = if ($resolved) { $resolved.ApiPermission } else { $PermissionId }
        ApiName                      = if ([string]::IsNullOrWhiteSpace($apiName)) { "-" } else { $apiName }
        ApiPermissionDisplayname     = if ($resolved) { $resolved.ApiPermissionDisplayName } else { "-" }
        ApiPermissionDescription     = if ($resolved) { $resolved.ApiPermissionDescription } else { "-" }
        ApiPermissionCategorization  = if ($resolved) { $resolved.ApiPermissionCategorization } else { Get-APIPermissionCategory -InputPermission $PermissionId -PermissionType "application" }
    }
}

# Summarize API-permission counts and impact using the shared scoring model.
function Get-ApiPermissionImpactSummary {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][object[]]$ApplicationPermissions = @(),
        [Parameter(Mandatory = $false)][object[]]$DelegatedPermissions = @(),
        [Parameter(Mandatory = $false)][switch]$DeduplicateApplication,
        [Parameter(Mandatory = $false)][switch]$DeduplicateDelegated
    )

    $scoreMap = @{
        Dangerous     = 800
        High          = 400
        Medium        = 100
        Low           = 50
        Uncategorized = 20
    }
    $delegatedScoreMap = @{
        Dangerous     = 200
        High          = 100
        Medium        = 60
        Low           = 20
        Uncategorized = 20
    }
    $categories = @('Dangerous', 'High', 'Medium', 'Low', 'Uncategorized')

    $dedupByKey = {
        param(
            [object[]]$Rows,
            [scriptblock]$KeySelector
        )

        $result = [System.Collections.ArrayList]::new()
        $seen = @{}
        foreach ($row in @($Rows)) {
            if ($null -eq $row) { continue }
            $key = & $KeySelector $row
            if ([string]::IsNullOrWhiteSpace([string]$key)) {
                $key = [guid]::NewGuid().Guid
            }
            if ($seen.ContainsKey($key)) {
                continue
            }
            $seen[$key] = $true
            [void]$result.Add($row)
        }
        return @($result)
    }

    $applicationRows = @($ApplicationPermissions)
    if ($DeduplicateApplication) {
        $applicationRows = & $dedupByKey $applicationRows {
            param($row)
            $resourceAppId = if ($row.PSObject.Properties['ResourceAppId']) { [string]$row.ResourceAppId } else { '' }
            $permissionId = if ($row.PSObject.Properties['PermissionId']) { [string]$row.PermissionId } else { [string]$row.ApiPermission }
            "APP|$resourceAppId|$permissionId"
        }
    }

    $delegatedRows = @($DelegatedPermissions)
    if ($DeduplicateDelegated) {
        $delegatedRows = & $dedupByKey $delegatedRows {
            param($row)
            $resourceAppId = if ($row.PSObject.Properties['ResourceAppId']) { [string]$row.ResourceAppId } else { '' }
            $scope = if ($row.PSObject.Properties['Scope']) { [string]$row.Scope } else { [string]$row.Permission }
            "DEL|$resourceAppId|$scope"
        }
    }

    $applicationCounts = @{}
    $delegatedCounts = @{}
    foreach ($category in $categories) {
        $applicationCounts[$category] = 0
        $delegatedCounts[$category] = 0
    }

    $impact = 0
    foreach ($row in $applicationRows) {
        $category = if ($row.PSObject.Properties['ApiPermissionCategorization']) { [string]$row.ApiPermissionCategorization } else { 'Uncategorized' }
        if (-not $applicationCounts.ContainsKey($category)) {
            $category = 'Uncategorized'
        }
        $applicationCounts[$category]++
        $impact += $scoreMap[$category]
    }

    foreach ($row in $delegatedRows) {
        $category = if ($row.PSObject.Properties['ApiPermissionCategorization']) { [string]$row.ApiPermissionCategorization } else { 'Uncategorized' }
        if (-not $delegatedCounts.ContainsKey($category)) {
            $category = 'Uncategorized'
        }
        $delegatedCounts[$category]++
    }

    foreach ($category in $categories) {
        if ($delegatedCounts[$category] -gt 0) {
            $impact += $delegatedScoreMap[$category]
        }
    }

    [pscustomobject]@{
        ApplicationPermissions = @($applicationRows)
        DelegatedPermissions   = @($delegatedRows)
        ApplicationCounts      = $applicationCounts
        DelegatedCounts        = $delegatedCounts
        ApplicationCount       = @($applicationRows).Count
        DelegatedCount         = @($delegatedRows).Count
        Impact                 = $impact
    }
}

#Function to check if objects exist to determine if the reports wil lbe generated.
function Get-TenantReportAvailability {
    $requests = New-Object 'System.Collections.Generic.List[object]'

    $requestSpecs = @(
        @{ Name = 'Groups';           Url = '/groups' }
        @{ Name = 'AppRegistrations'; Url = '/applications' }
        @{ Name = 'ManagedIdentities'; Url = '/servicePrincipals'; Query = @{ '$filter' = "servicePrincipalType eq 'ManagedIdentity'" } }
        @{ Name = 'AgentIdentities'; Url = '/servicePrincipals/Microsoft.Graph.AgentIdentity' }
        @{ Name = 'AgentIdentityBlueprintsPrincipals'; Url = '/servicePrincipals/graph.agentIdentityBlueprintPrincipal' }
        @{ Name = 'AgentIdentityBlueprints'; Url = '/applications/microsoft.graph.agentIdentityBlueprint' }
        #@{ Name = 'EnterpriseApps';   Url = '/servicePrincipals'; Query = @{ '$filter' = "servicePrincipalType eq 'Application'" } }
    )

    foreach ($spec in $requestSpecs) {
        $req = @{
            id     = $spec.Name
            method = 'GET'
            url    = $spec.Url
        }

        if ($spec.ContainsKey('Query') -and $spec.Query) {
            $req.queryParameters = $spec.Query
        }

        $requests.Add($req)
    }

    $response = Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $requests -BetaAPI -UserAgent $GlobalAuditSummary.UserAgent.Name -QueryParameters @{ '$select' = 'id'; '$top' = '1' } -DisablePagination

    $result = [ordered]@{}
    foreach ($spec in $requestSpecs) {
        $result[$spec.Name] = $false
    }

    foreach ($r in @($response)) {
        if ($null -eq $r.id) { continue }
        if (-not $result.Contains($r.id)) { continue }

        if ($r.status -ge 200 -and $r.status -lt 300) {
            $result[$r.id] = (@($r.response.value).Count -gt 0)
        } else {
            $result[$r.id] = $false
        }
    }

    [pscustomobject]$result
}

#Function to provide detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
#The type can specified to save some GraphAPI calls
if (-not $script:ObjectInfoCache) {
    $script:ObjectInfoCache = @{}
}
function Get-ObjectInfo {
    param(
        [Parameter(Mandatory)][string]$ObjectID,
        [string]$type = "unknown"
    )

    # Caching
    $normalizedType = $type.ToString().ToLowerInvariant()
    $cacheKey = "$normalizedType|$ObjectID"
    if ($script:ObjectInfoCache.ContainsKey($cacheKey)) {
        Write-Log -Level Trace -Message "Cache hit for $ObjectID"
        return $script:ObjectInfoCache[$cacheKey]
    }

    Write-Log -Level Trace -Message "Manually resolve $ObjectID"

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "serviceprincipal" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $EnterpriseApp = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($EnterpriseApp) {
            $object = [PSCustomObject]@{ 
                DisplayName = $EnterpriseApp.DisplayName
                Type = "Enterprise Application"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "appregistration" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $AppRegistration = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/applications/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AppRegistration) {
            $object = [PSCustomObject]@{ 
                DisplayName = $AppRegistration.DisplayName
                Type = "App Registration"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "administrativeunit" ) {
        $QueryParameters = @{
            '$select' = "DisplayName"
        }
        $AdministrativeUnit = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AdministrativeUnit) {
            $object = [PSCustomObject]@{ 
                DisplayName = $AdministrativeUnit.DisplayName
                Type = "Administrative Unit"
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "user" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,OnPremisesSyncEnabled,JobTitle,Department"
        }
        $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($user) {
            $object = [PSCustomObject]@{ 
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Type = "User"
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                JobTitle = $user.JobTitle
                Department = $user.Department
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        }
    }

    if ($normalizedType -eq "unknown" -or $normalizedType -eq "group" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,SecurityEnabled,IsAssignableToRole"
        }
        $group = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/groups/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        
        if ($group) {
            $IsAssignabletoRole = if ($null -ne $group.IsAssignableToRole) { $group.IsAssignableToRole } else { $false }
            $object = [PSCustomObject]@{ 
                DisplayName = $group.DisplayName
                Type = "Group"
                SecurityEnabled = $group.SecurityEnabled
                IsAssignableToRole = $isAssignabletoRole
            }

            $script:ObjectInfoCache[$cacheKey] = $object
            Return $object
        } 
    }

    if ($normalizedType -eq "unknown") {
        Write-Log -Level Debug -Message "Unknown Object: $ObjectID"
        $object = [PSCustomObject]@{ 
            DisplayName = $ObjectID
            Type = "Unknown"
        }

        $script:ObjectInfoCache[$cacheKey] = $object
        return $object
    }
}

#Function to define global summary variable
function start-InitTasks {
    Param (
        [Parameter(Mandatory=$false)][string]$UserAgent = "EntraFalcon",
        [Parameter(Mandatory=$true)][string]$EntraFalconVersion
    )

    $Global:GlobalAuditSummary = @{
        Time                   = @{ Start = Get-Date -Format "yyyyMMdd HH:mm:ss"; End = ""}
        Tenant                 = @{ Name = ""; Id = ""; OnPremisesSyncEnabled = $null; OnPremisesLastSyncDateTime = $null }
        EntraFalcon            = @{ Version = "$EntraFalconVersion"; Source = "https://github.com/CompassSecurity/EntraFalcon" }
        TenantLicense          = @{ Name = ""; Level = 0}
        Subscriptions          = @{ Count = 0; Details = @() }
        UserAgent              = @{ Name = $UserAgent}
        Users                  = @{ Count = 0; Guests = 0; Inactive = 0; Enabled=0; OnPrem=0; MfaCapable=0; SignInActivity = @{ '0-1 month' = 0; '1-2 months' = 0; '2-3 months' = 0; '3-4 months' = 0; '4-5 months' = 0; '5-6 months' = 0; '6+ months' = 0; 'Never' = 0 }}
        Groups                 = @{ Count = 0; M365 = 0; PublicM365 = 0; PimOnboarded = 0; OnPrem = 0}
        AppRegistrations       = @{ Count = 0; AppLock = 0; Credentials = @{ 'AppsSecrets' = 0; 'AppsCerts' = 0; 'AppsFederatedCreds' = 0; 'AppsNoCreds' = 0}; Audience = @{ 'SingleTenant' = 0; 'MultiTenant' = 0; 'MultiTenantPersonal' = 0} }
        EnterpriseApps         = @{ Count = 0; Foreign = 0; IncludeMsApps = $false; Credentials = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0}; SignInActivity = @{ '0-1 month' = 0; '1-2 months' = 0; '2-3 months' = 0; '3-4 months' = 0; '4-5 months' = 0; '5-6 months' = 0; '6+ months' = 0; 'Never' = 0 }}
        ManagedIdentities      = @{ Count = 0; IsExplicit = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0} }
        AgentIdentities        = @{ Count = 0; Foreign = 0; Inactive = 0; TotalAgentUsers = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0 } }
        AgentIdentityBlueprintsPrincipals = @{ Count = 0; Foreign = 0 }
        AgentIdentityBlueprints = @{ Count = 0; Credentials = @{ 'Secrets' = 0; 'Certificates' = 0; 'Federated Credentials' = 0; 'None' = 0 } }
        AdministrativeUnits    = @{ Count = 0 }
        ConditionalAccess      = @{ Count = 0; Enabled = 0 }
        SecurityFindings       = @{ Vulnerable = 0; NotVulnerable = 0; Skipped = 0; Total = 0 }
        EntraRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'App' = 0; 'MI' = 0; 'AgentIdentity' = 0; 'BlueprintPrincipal' = 0; 'Unknown' = 0}; Tiers = @{ 'Tier-0' = 0; 'Tier-1' = 0; 'Tier-2' = 0; 'Uncategorized' = 0} }
        AzureRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'SP' = 0; 'MI' = 0; 'AgentIdentity' = 0; 'BlueprintPrincipal' = 0; 'Unknown' = 0}; Tiers = @{ 'Tier-0' = 0; 'Tier-1' = 0; 'Tier-2' = 0; 'Tier-3' = 0; 'Uncategorized' = 0} }
        PimSettings            = @{ Count = 0}
        Domains                = @{ Count = 0; Federated = 0; Verified = 0; Default = 0; AdminManaged = 0 }
        Errors                 = @()
    }
}


#Function to get the applied Entra teant license
function Get-EffectiveEntraLicense {
    [CmdletBinding()]

    $planPriority = @(
        @{ Plan = 'AAD_PREMIUM_P2'; Name = 'Microsoft Entra ID P2';    Int = 4 }
        @{ Plan = 'AAD_PREMIUM';    Name = 'Microsoft Entra ID P1';    Int = 3 }
        @{ Plan = 'AAD_BASIC';      Name = 'Microsoft Entra ID Basic'; Int = 2 }
        @{ Plan = 'AAD_FREE';       Name = 'Microsoft Entra ID Free';  Int = 1 }
    )

    $QueryParameters = @{
        '$select' = "capabilityStatus,servicePlans"
    }
    try {
        $response = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/subscribedSkus' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    } catch {
        Write-Log -Level Debug -Message "Can't get Entra Tenant license. Request to /subscribedSkus failed"
        return [pscustomobject]@{
            EntraIDLicencesString = 'Unknown'
            EntraIDLicencesInt    = 0
        }
    }
    $skus =
        if ($null -eq $response) { @() }
        elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) { @($response) }
        elseif ($response.PSObject.Properties.Name -contains 'value') { @($response.value) }
        else { @($response) }

    # Entra Free does not have any SKUs
    if ($skus.Count -eq 0) {
        return [pscustomobject]@{
            EntraIDLicencesString = 'Microsoft Entra ID Free'
            EntraIDLicencesInt    = 1
        }
    }

    $observedPlans = New-Object System.Collections.Generic.HashSet[string]

    foreach ($sku in $skus) {
        if ($null -eq $sku) { continue }

        $capabilityStatus = $sku.capabilityStatus
        if ($capabilityStatus -ne 'Enabled' -and $capabilityStatus -ne 'Warning') { continue }

        foreach ($plan in @($sku.servicePlans)) {
            if ($null -eq $plan) { continue }

            if ($plan.provisioningStatus -ne 'Success') { continue }

            $servicePlanName = [string]$plan.servicePlanName
            [void]$observedPlans.Add($servicePlanName)
        }
    }

    foreach ($item in $planPriority) {
        if ($observedPlans.Contains($item.Plan)) {
            Write-Log -Level Verbose -Message "Entra Tenant license: $($item.Name)"
            return [pscustomobject]@{
                EntraIDLicencesString = $item.Name
                EntraIDLicencesInt    = $item.Int
            }
        }
    }

    Write-Log -Level Verbose -Message "Entra Tenant license: Unknown"
    return [pscustomobject]@{
        EntraIDLicencesString = 'Unknown'
        EntraIDLicencesInt    = 0
    }
}



# Function to help built the TXT report (avoiding using slow stuff like format-table)
function Format-ReportSection {
    param (
        [string]$Title,
        [array]$Objects,
        [string[]]$Properties,
        [hashtable]$ColumnWidths
    )

    $sb = New-Object System.Text.StringBuilder

    $line = "=" * 120
    [void]$sb.AppendLine($line)
    [void]$sb.AppendLine($Title)
    [void]$sb.AppendLine($line)

    # Header
    $header = ""
    foreach ($prop in $Properties) {
        $header += ("{0,-$($ColumnWidths[$prop])} " -f $prop)
    }
    [void]$sb.AppendLine($header)

    # Rows
    foreach ($obj in $Objects) {
        $row = ""
        foreach ($prop in $Properties) {
            $val = $obj.$prop
            $row += ("{0,-$($ColumnWidths[$prop])} " -f $val)
        }
        [void]$sb.AppendLine($row)
    }

    return $sb.ToString()
}


function invoke-EntraFalconAuth {
    <#
    .SYNOPSIS
    Routes and executes Entra ID, Microsoft Graph, PIM, and Azure ARM authentication or token refresh flows.

    .DESCRIPTION
    invoke-EntraFalconAuth is an internal orchestration helper that selects and executes the correct authentication
    or token refresh routine based on Action, Purpose, and AuthFlow.

    The function supports flow-native selection (BroCi, AuthCode, DeviceCode, ManualCode, BroCiManualCode, BroCiToken),
    token refresh and token exchange scenarios, as well as the BroCi flow with optional Bring-Your-Own BroCi refresh token support.
    When a BroCi token is supplied with AuthFlow BroCiToken, the initial BroCi bootstrap authentication step is skipped and the provided
    token is used directly for subsequent token exchanges.

    The function prints a short status message, invokes the required underlying helper functions
    (Invoke-Auth, Invoke-DeviceCodeFlow, Invoke-Refresh), stores resulting tokens in predefined global variables,
    and returns $true on success or $false on failure.

    .PARAMETER AuthFlow
    Specifies which authentication flow to use.
    Valid values: BroCi, AuthCode, DeviceCode, ManualCode, BroCiManualCode, BroCiToken.

    .PARAMETER BroCiToken
    Optional BroCi refresh token provided by the caller.
    Required when AuthFlow is BroCiToken.

    .PARAMETER Action
    Specifies whether to authenticate or refresh tokens.
    Valid values: Auth, Refresh.

    .PARAMETER Purpose
    Specifies which token to obtain or refresh.
    Valid values: MainAuth, PimforEntra, PimforGroup, Azure, SecurityFindings.

    .OUTPUTS
    System.Boolean.
    Returns $true when the selected flow completes successfully; otherwise returns $false.
    Throws for invalid parameter combinations.

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose MainAuth -AuthFlow DeviceCode

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose MainAuth -AuthFlow BroCiToken -BroCiToken $BroCiRefreshToken

    .EXAMPLE
    invoke-EntraFalconAuth -Action Auth -Purpose PimforEntra -AuthFlow BroCi

    .EXAMPLE
    invoke-EntraFalconAuth -Action Refresh -Purpose MainAuth -AuthFlow BroCiManualCode
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("BroCi", "AuthCode", "DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken", "ServicePrincipal")]
        [string]$AuthFlow = "BroCi",

        # Action
        [Parameter(Mandatory = $true)]
        [ValidateSet("Auth", "Refresh")]
        [string]$Action,

        # Purpose
        [Parameter(Mandatory = $true)]
        [ValidateSet("MainAuth", "PimforEntra", "PimforGroup", "Azure", "SecurityFindings")]
        [string]$Purpose,

        # BroCiToken
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

    Write-Log -Level Debug -Message "Starting authentication: Action=$Action Purpose=$Purpose AuthFlow=$AuthFlow"

    if ($AuthFlow -eq "BroCiToken" -and [string]::IsNullOrWhiteSpace($BroCiToken)) {
        throw "Invalid parameter combination: -AuthFlow BroCiToken requires -BroCiToken."
    }
    if ($AuthFlow -ne "BroCiToken" -and -not [string]::IsNullOrWhiteSpace($BroCiToken)) {
        throw "Invalid parameter combination: -BroCiToken can only be used with -AuthFlow BroCiToken."
    }
    if ($AuthFlow -eq "ServicePrincipal" -and [string]::IsNullOrWhiteSpace($SPClientId)) {
        throw "Invalid parameter combination: -AuthFlow ServicePrincipal requires -SPClientId."
    }
    if ($AuthFlow -eq "ServicePrincipal" -and [string]::IsNullOrWhiteSpace($GLOBALAuthParameters['Tenant'])) {
        throw "ServicePrincipal flow requires a tenant. Use -Tenant."
    }

    $isBroCiFlow = @("BroCi", "BroCiManualCode", "BroCiToken") -contains $AuthFlow
    $authMethodKey = switch ($AuthFlow) {
        "DeviceCode" { "DeviceCode" }
        "ManualCode" { "ManualCode" }
        "BroCiManualCode" { "ManualCode" }
        "ServicePrincipal" { "ServicePrincipal" }
        default { "AuthCode" }
    }

    if (-not [string]::IsNullOrWhiteSpace($BroCiToken)) {
        $BroCiTokenObj = [pscustomobject]@{ refresh_token = $BroCiToken }
    } else {
        $BroCiTokenObj = $null
    }

    function Get-Plan {
        param(
            [hashtable]$Table,
            [string[]]$Keys
        )
        $node = $Table
        foreach ($k in $Keys) {
            if ($node -isnot [hashtable] -or -not $node.ContainsKey($k)) {
                return $null
            }
            $node = $node[$k]
        }
        return $node
    }

    function Get-EntraFalconStatusMessage {
        param(
            [ValidateSet("Auth", "Refresh")]
            [string]$Action,

            [ValidateSet("MainAuth", "PimforEntra", "PimforGroup", "Azure", "SecurityFindings")]
            [string]$Purpose,

            [ValidateSet("BroCi", "AuthCode", "DeviceCode", "ManualCode", "BroCiManualCode", "BroCiToken", "ServicePrincipal")]
            [string]$AuthFlow
        )

        switch ($Action) {
            'Auth' {
                return "[*] Authenticating for $Purpose using $AuthFlow"
            }
            'Refresh' {
                return "[*] Refreshing $Purpose access token ($AuthFlow)"
            }
        }
    }

    # Builds the Invoke-ClientCredential parameter hashtable from whichever SP* credential params were supplied.
    $InvokeCC = {
        param([string]$Api = "graph.microsoft.com")
        $ccParams = @{
            ClientId          = $SPClientId
            TenantId          = $GLOBALAuthParameters['Tenant']
            Api               = $Api
            DisableJwtParsing = $true
            Silent            = ((Get-LogLevel) -eq "Off")
        }
        if ($SPClientSecret) {
            $ccParams['ClientSecret'] = $SPClientSecret
        } elseif ($SPCertificatePath) {
            $ccParams['CertificatePath'] = $SPCertificatePath
            if ($SPCertificatePassword) { $ccParams['CertificatePassword'] = $SPCertificatePassword }
        } elseif ($SPCertificatePemPath) {
            $ccParams['CertificatePemPath']  = $SPCertificatePemPath
            $ccParams['PrivateKeyPemPath']   = $SPPrivateKeyPemPath
            if ($SPPrivateKeyPemPassword) { $ccParams['PrivateKeyPemPassword'] = $SPPrivateKeyPemPassword }
        }
        $token = Invoke-ClientCredential @ccParams
        if (-not $token -or [string]::IsNullOrWhiteSpace($token.access_token)) {
            throw "Service principal authentication did not return an access token. Check tenant, client ID, credential, and admin-consented application permissions."
        }

        return $token
    }

    # --------------------------
    # ROUTING TABLE ("plans")
    # --------------------------
    $Routes = @{
        Auth = @{
            NoBroCi = @{
                MainAuth = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -DisableJwtParsing -ManualCode @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALMsGraphAccessToken = & $InvokeCC
                        $true
                    }
                }

                PimforGroup = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                             -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                                       -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -ManualCode `
                                             -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' `
                                             -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALPimForGroupAccessToken = & $InvokeCC
                        $true
                    }
                }

                Azure = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token `
                                                -Api management.azure.com `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALArmAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALArmAccessToken = & $InvokeCC -Api "management.azure.com"
                        $true
                    }
                }

                PimforEntra = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                             -RedirectUrl 'http://localhost:13824/' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    DeviceCode = {
                        $tokens = Invoke-DeviceCodeFlow -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                                       -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -ManualCode `
                                             -ClientID '51f81489-12ee-4a9e-aaae-a2591f45987d' `
                                             -RedirectUrl 'http://localhost:13824/' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALPIMsGraphAccessToken = & $InvokeCC
                        $true
                    }
                }

                SecurityFindings = @{
                    AuthCode = {
                        $tokens = Invoke-Auth -ClientID '80ccca67-54bd-44ab-8625-4b79c4dc7775' `
                                             -RedirectUrl 'https://transition.security.microsoft.com/Blank' `
                                             -Origin 'https://doesnotmatter' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALSecurityFindingsGraphAccessTokenSpecial = $tokens
                        $true
                    }
                    DeviceCode = {
                        # There is no client which can be used for this :-(
                        $true
                    }
                    ManualCode = {
                        $tokens = Invoke-Auth -ManualCode `
                                             -ClientID '80ccca67-54bd-44ab-8625-4b79c4dc7775' `
                                             -RedirectUrl 'https://transition.security.microsoft.com/Blank' `
                                             -Origin 'https://doesnotmatter' `
                                             -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALSecurityFindingsGraphAccessTokenSpecial = $tokens
                        $true
                    }
                }
            }

            BroCi = @{
                MainAuth = @{
                    AuthCode = {
                        # If caller provided a BroCi token use it
                        if ($BroCiTokenObj) {
                            $global:GLOBALBrociAccessToken = $BroCiTokenObj
                        } else {
                            $tokens = Invoke-Auth -ClientID "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" `
                                                -RedirectUrl "https://startups.portal.azure.com/auth/login/" `
                                                -Origin "https://doesnotmatter" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                            $global:GLOBALBrociAccessToken = $tokens
                        }


                        $tokensIbiza = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                     -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                     -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                     -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                     -Origin 'https://portal.azure.com' @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokensIbiza
                        $true
                    }

                    ManualCode = {
                        # If caller provided a BroCi token use it
                         if ($BroCiTokenObj) {
                            $global:GLOBALBrociAccessToken = $BroCiTokenObj
                        } else {
                            $tokens = Invoke-Auth -ClientID 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUrl 'https://startups.portal.azure.com/auth/login/' `
                                                -Origin 'https://doesnotmatter' `
                                                -DisableJwtParsing -ManualCode @GLOBALAuthParameters
                            $global:GLOBALBrociAccessToken = $tokens
                        }

                        $tokensIbiza = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                     -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                     -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                     -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                     -Origin 'https://portal.azure.com' @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokensIbiza
                        $true
                    }

                    
                }

                PimforGroup = @{
                    Any = {
                        #Note: Maybe use the Ibiza Token
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '50aaa389-5a33-4f1a-91d7-2c45ecd8dac8' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAccessToken = $tokens

                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '50aaa389-5a33-4f1a-91d7-2c45ecd8dac8' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Api 'api.azrbac.mspim.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPimForGroupAzrbacAccessToken = $tokens
                        $true
                    }
                }

                Azure = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -Api "management.azure.com" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALArmAccessToken = $tokens
                        $true
                    }
                }

                PimforEntra = @{
                    Any = {
                        #Note: Maybe use the Ibiza Token
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }
        }

        Refresh = @{
            NoBroCi = @{
                MainAuth = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALMsGraphAccessToken = & $InvokeCC
                        $true
                    }
                }
                PimforEntra = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALPIMsGraphAccessToken.refresh_token `
                                                -ClientId "51f81489-12ee-4a9e-aaae-a2591f45987d" `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                    ServicePrincipal = {
                        $global:GLOBALPIMsGraphAccessToken = & $InvokeCC
                        $true
                    }
                }
                SecurityFindings = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALSecurityFindingsGraphAccessTokenSpecial.refresh_token `
                                                -ClientId "80ccca67-54bd-44ab-8625-4b79c4dc7775" `
                                                -Origin 'https://doesnotmatter' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALSecurityFindingsGraphAccessTokenSpecial = $tokens
                        $true
                    }
                }
            }

            BroCi = @{
                MainAuth = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALMsGraphAccessToken = $tokens
                        $true
                    }
                }
                PimforEntra = @{
                    Any = {
                        $tokens = Invoke-Refresh -RefreshToken $GLOBALBrociAccessToken.refresh_token `
                                                -ClientID '74658136-14ec-4630-ad9b-26e160ff0fc6' `
                                                -BrkClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' `
                                                -RedirectUri 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' `
                                                -Origin 'https://portal.azure.com' `
                                                -DisableJwtParsing @GLOBALAuthParameters
                        $global:GLOBALPIMsGraphAccessToken = $tokens
                        $true
                    }
                }
            }
        }
    }

    # --------------------------
    # EXECUTION
    # --------------------------
    $broKey = if ($isBroCiFlow) { 'BroCi' } else { 'NoBroCi' }

    try {
        $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, $authMethodKey)

        #Fallback to any if no explicit is found
        if (-not $plan -and $Action -eq "Auth") {
            $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, "Any")
        }

        # For Refresh, try the exact authMethodKey first (e.g. ServicePrincipal), then fall back to Any
        if (-not $plan -and $Action -eq 'Refresh') {
            $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, $authMethodKey)
        }
        if (-not $plan -and $Action -eq 'Refresh') {
            $plan = Get-Plan -Table $Routes -Keys @($Action, $broKey, $Purpose, 'Any')
        }

        if (-not $plan) {
            return $false
        }

        $status = Get-EntraFalconStatusMessage `
            -Action $Action `
            -Purpose $Purpose `
            -AuthFlow $AuthFlow

        Write-Host $status

        & $plan
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "[!] Authentication flow failed for $Purpose" -ForegroundColor Red

        if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
            Write-Host "[!] $errorMessage" -ForegroundColor Red
        }

        $debugDetails = [System.Collections.Generic.List[string]]::new()
        $debugDetails.Add("Authentication failure context: Action=$Action; Purpose=$Purpose; AuthFlow=$AuthFlow")
        if ($_.Exception) {
            $debugDetails.Add("ExceptionType=$($_.Exception.GetType().FullName)")
        }
        Write-Log -Level Debug -Message ($debugDetails -join [Environment]::NewLine)
        return $false
    }
}



# Remove global variables
function start-CleanUp {
    remove-variable -Scope Global GLOBALMsGraphAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALGraphExtendedChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALArmAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALUserAppRoles -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsHT -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsResources -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsAssignmentObjects -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsPolicySettingsSupported -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsPolicySettingsSkipReason -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuditSummary -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMainTableDetailsHEAD -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript_Table -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript_Nav -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALCss -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALDelegatedApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMsTenantIds -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPermissionForCaps -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsChecked -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALUserSignInActivityAvailable -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzurePsChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureSubscriptionScopeMap -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureIamWarningText -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuthParameters -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALEntraRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALImpactScore -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPIMsGraphAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPIMForEntraRolesChecked -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALBrociAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuthMethods -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupAzrbacAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALEntraFalconLogLevel -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALSecurityFindingsAccessContext -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALSecurityFindingsGraphAccessTokenSpecial -ErrorAction SilentlyContinue


}

enum LogLevel {
    Off     = 0
    Verbose = 1
    Debug   = 2
    Trace   = 3
}

function Get-LogLevel {
    [CmdletBinding()]
    param()

    $raw = $global:GLOBALEntraFalconLogLevel
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [LogLevel]::Off
    }

    try {
        return [LogLevel]::$raw
    } catch {
        return [LogLevel]::Off
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [LogLevel]$Level,

        [switch]$Timestamp
    )

    $currentLevel = Get-LogLevel
    if ($currentLevel -eq [LogLevel]::Off) { return }
    if ([int]$Level -gt [int]$currentLevel) { return }

    $prefix = if ($Timestamp) {
        "[{0}] [{1}]" -f $Level, (Get-Date -Format 'HH:mm:ss')
    } else {
        "[{0}]" -f $Level
    }

    Write-Information "$prefix $Message" -InformationAction Continue
}



function Show-EntraFalconBanner {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$EntraFalconVersion
    )
    $banner = @'

    ______      __                ______      __               
   / ____/___  / /__________ _   / ____/___ _/ /________  ____ 
  / __/ / __ \/ __/ ___/ __ `/  / /_  / __ `/ / ___/ __ \/ __ \
 / /___/ / / / /_/ /  / /_/ /  / __/ / /_/ / / /__/ /_/ / / / /
/_____/_/ /_/\__/_/   \__,_/  /_/    \__,_/_/\___/\____/_/ /_/ 
                                                               
'@

    # Show Banner with color
    Write-Host $banner -ForegroundColor Cyan
    If ($EntraFalconVersion) {Write-Host $EntraFalconVersion -ForegroundColor Cyan}
    Write-Host ""
}

Export-ModuleMember -Function Show-EntraFalconBanner,AuthenticationMSGraph,Get-TenantReportAvailability,Get-TenantDomains,Initialize-TenantReportTabs,Set-GlobalReportManifest,Get-EffectiveEntraLicense,Get-Devices,Get-UsersBasic,Get-AgentObjectBasics,Get-ServicePrincipalSignInActivityLookup,Resolve-DirectoryObjectReference,Export-EntraFalconDebugObjectDump,Export-EntraFalconSecurityFindingsJson,start-CleanUp,Format-ReportSection,Get-OrgInfo,Get-LogLevel,Write-Log,Invoke-MsGraphRefreshPIM,Write-LogVerbose,Invoke-AzureRoleProcessing,Get-RegisterAuthMethodsUsers,Invoke-EntraRoleProcessing,Get-EntraPIMRoleAssignments,AuthCheckMSGraph,RefreshAuthenticationMsGraph,EnsureAuthSecurityFindingsMsGraph,RefreshAuthenticationSecurityFindingsMsGraph,Get-PimforGroupsAssignments,Invoke-CheckTokenExpiration,Invoke-MsGraphAuthPIM,EnsureAuthMsGraph,Get-AzureRoleDetails,Get-AdministrativeUnitsWithMembers,Get-ConditionalAccessPolicies,Get-EntraRoleAssignments,Get-APIPermissionCategory,New-AppRoleReferenceCache,Resolve-AppRoleReference,Get-AppRoleReferenceApiName,Get-AppRoleReferenceResourceAppId,Resolve-DelegatedPermissionGrantDetails,Resolve-AppRoleAssignmentRecord,Get-ApiPermissionImpactSummary,Get-ObjectInfo,EnsureAuthAzurePsNative,checkSubscriptionNative,Get-AllAzureIAMAssignmentsNative,Get-PIMForGroupsAssignmentsDetails,Show-EnumerationSummary,start-InitTasks,Get-HighestTierLabel,Merge-HigherTierLabel,Get-GroupDetails,Get-GroupActiveRoleMetrics,Get-EntraFalconHostOs,Test-NonWindowsAuthFlowCompatibility,Get-KnownMaliciousEnterpriseApp
