<#
.SYNOPSIS
    Sends requests to the Microsoft Graph API.

.DESCRIPTION
    Sends single requests to Microsoft Graph API with automatic pagination, retries, and exponential backoff.

.PARAMETER AccessToken
    OAuth token for Microsoft Graph authentication.

.PARAMETER Method
    HTTP method (GET, POST, PUT, PATCH, DELETE).

.PARAMETER Uri
    API resource URI (relative, e.g., /users).

.PARAMETER Body
    Request body as PowerShell hashtable/object.

.PARAMETER MaxRetries
    Maximum retry attempts. Default: 5.

.PARAMETER BetaAPI
    Switch to use Beta API endpoint.

.PARAMETER RawJson
    Returns the raw JSON string instead of a PowerShell object.

.PARAMETER Proxy
    Proxy URL (e.g., http://proxyserver:port).

.PARAMETER UserAgent
    Specify the User-Agent HTTP header.

.PARAMETER VerboseMode
    Enable detailed logging.

.PARAMETER Suppress404
    Supress 404 error messages

.PARAMETER DisablePagination
    If specified, prevents the function from automatically following @odata.nextLink for paginated results.

.PARAMETER AdditionalHeaders
    Add additional headers, example -AdditionalHeaders @{ 'ConsistencyLevel' = 'eventual' }

.PARAMETER QueryParameters
    Query parameters for more complex queries (e.g. -QueryParameters @{ '$filter' = "startswith(displayName,'Alex')" })

.EXAMPLE
    Send-GraphRequest -AccessToken $token -Method GET -Uri '/users'

.EXAMPLE
    Send-GraphRequest -AccessToken $token -Method GET -Uri '/groups?$select=displayName' -VerboseMode

.EXAMPLE
    Send-GraphRequest -AccessToken $token -Method GET -Uri '/groups?$select=displayName' -proxy "http://127.0.0.1:8080"

.EXAMPLE
    Send-GraphRequest -AccessToken $token -Method GET -Uri '/users' -AdditionalHeaders @{ 'ConsistencyLevel' = 'eventual' }

.EXAMPLE
    Send-GraphRequest -AccessToken $token -Method GET -Uri '/users' -QueryParameters @{ '$filter' = "startswith(displayName,'Alex')" }"

.EXAMPLE
    $Body = @{
        displayName     = "Test Security Group2"
        mailEnabled     = $false
        mailNickname    = "TestSecurityGroup$(Get-Random)"
        securityEnabled = $true
        groupTypes      = @()
    }
    $result = Send-GraphRequest -AccessToken $token -Method POST -Uri "/groups" -Body $Body -VerboseMode


.NOTES
    Author: ZH54321
    GitHub: https://github.com/zh54321/GraphRequest
#>

function Send-GraphRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [ValidateSet("GET", "POST", "PATCH", "PUT", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,
        [hashtable]$Body,
        [int]$MaxRetries = 5,
        [switch]$BetaAPI,
        [string]$UserAgent = 'PowerShell GraphRequest Module',
        [switch]$RawJson,
        [string]$Proxy,
        [switch]$DisablePagination,
        [switch]$VerboseMode,
        [switch]$Suppress404,
        [hashtable]$QueryParameters,
        [hashtable]$AdditionalHeaders,
        [int]$JsonDepthResponse = 10
    )

    $ApiVersion = if ($BetaAPI) { "beta" } else { "v1.0" }
    $BaseUri = "https://graph.microsoft.com/$ApiVersion"
    $FullUri = "$BaseUri$Uri"

    #Add query parameters
    if ($QueryParameters) {
        $QueryString = ($QueryParameters.GetEnumerator() |
            ForEach-Object {
                "$($_.Key)=$([uri]::EscapeDataString($_.Value))"
            }) -join '&'
        $FullUri = "$FullUri`?$QueryString"
    }


    #Define basic headers
    $Headers = @{
        Authorization  = "Bearer $AccessToken"
        'Content-Type' = 'application/json'
        'User-Agent'   = $UserAgent
    }

    #Add custom headers if required
    if ($AdditionalHeaders) {
        $Headers += $AdditionalHeaders
    }

    $RetryCount = 0
    $Results = @()

    # Prepare Invoke-RestMethod parameters
    $irmParams = @{
        Uri             = $FullUri
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }

    if ($Body) {
        $irmParams.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }

    if ($Proxy) {
        $irmParams.Proxy = $Proxy
    }

    do {
        try {
            if ($VerboseMode) { Write-Host "[*] Request [$Method]: $FullUri" }

            $Response = Invoke-RestMethod @irmParams

            if ($Response.PSObject.Properties.Name -contains 'value') {
                if ($Response.value.Count -eq 0) {
                    if ($VerboseMode) { Write-Host "[i] Empty 'value' array detected on current page." }
                } else {
                    $Results += $Response.value
                }
            } else {
                $Results += $Response
            }

            # Pagination handling
            while ($Response.'@odata.nextLink' -and -not $DisablePagination) {
                if ($VerboseMode) { Write-Host "[*] Following pagination link: $($Response.'@odata.nextLink')" }

                $irmParams.Uri = $Response.'@odata.nextLink'
                # Remove Body for paginated GET requests
                $irmParams.Remove('Body')

                $Response = Invoke-RestMethod @irmParams
                if ($Response.PSObject.Properties.Name -contains 'value') {
                    if ($Response.value.Count -eq 0) {
                        if ($VerboseMode) { Write-Host "[i] Empty 'value' array detected on current page." }
                    } else {
                        $Results += $Response.value
                    }
                } else {
                    $Results += $Response
                }
            }

            break
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            $StatusDesc = $_.Exception.Message
            # Map HTTP status code to a PowerShell ErrorCategory
            switch ($StatusCode) {
                400 { $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument }
                401 { $errorCategory = [System.Management.Automation.ErrorCategory]::AuthenticationError }
                403 { $errorCategory = [System.Management.Automation.ErrorCategory]::PermissionDenied }
                404 { $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound }
                409 { $errorCategory = [System.Management.Automation.ErrorCategory]::ResourceExists }
                429 { $errorCategory = [System.Management.Automation.ErrorCategory]::LimitsExceeded }
                500 { $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidResult }
                502 { $errorCategory = [System.Management.Automation.ErrorCategory]::ProtocolError }
                503 { $errorCategory = [System.Management.Automation.ErrorCategory]::ResourceUnavailable }
                504 { $errorCategory = [System.Management.Automation.ErrorCategory]::OperationTimeout }
                default { $errorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified }
            }

             if ($StatusCode -in @(429,500,502,503,504) -and $RetryCount -lt $MaxRetries) {
                $RetryAfter = $_.Exception.Response.Headers['Retry-After']
                if ($RetryAfter) {
                    Write-Host "[i] [$StatusCode] - Throttled. Retrying after $RetryAfter seconds..."
                    Start-Sleep -Seconds ([int]$RetryAfter)
                } elseif ($RetryCount -eq 0) {
                    Write-Host "[*] [$StatusCode] - Retrying immediately..."
                    Start-Sleep -Seconds 0
                } else {
                    $Backoff = [math]::Pow(2, $RetryCount)
                    Write-Host "[*] [$StatusCode] - Retrying in $Backoff seconds..."
                    Start-Sleep -Seconds $Backoff
                }
                $RetryCount++
            } else {
                if (-not ($StatusCode -eq 404 -and $Suppress404)) {
                    $msg = "[!] Graph API request failed after $RetryCount retries. Status: $StatusCode. Message: $StatusDesc"
                    $exception = New-Object System.Exception($msg)

                    $errorRecord = New-Object System.Management.Automation.ErrorRecord (
                        $exception,
                        "GraphApiRequestFailed",
                        $errorCategory,
                        $FullUri
                    )

                    Write-Error $errorRecord
                }

                return
            }
        }
    } while ($RetryCount -le $MaxRetries)

    if ($RawJson) {
        return $Results | ConvertTo-Json -Depth $JsonDepthResponse
    }
    else {
        return $Results
    }
}
