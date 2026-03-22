<#
.SYNOPSIS
    Sends a single API request with retry, pagination, and robust error parsing.

.DESCRIPTION
    Send-ApiRequest is a generic wrapper around Invoke-RestMethod.
    It supports automatic pagination, retry logic for transient failures,
    custom headers/query parameters, proxy usage, and improved response error parsing.

    .LINK
    https://github.com/zh54321/Send-ApiRequest
#>

function Add-ApiQueryParameters {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$QueryParameters
    )

    if (-not $QueryParameters -or $QueryParameters.Count -eq 0) {
        return $Uri
    }

    $pairs = foreach ($entry in $QueryParameters.GetEnumerator()) {
        $value = $entry.Value
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $value = ($value -join ',')
        }

        "{0}={1}" -f $entry.Key, [uri]::EscapeDataString([string]$value)
    }

    $queryString = ($pairs -join '&')
    if ($Uri -match '\?') {
        return "$Uri&$queryString"
    }

    return "$Uri`?$queryString"
}

function Get-ApiErrorDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $statusCode = $null
    $errorCode = $null
    $errorMessage = $null
    $rawBody = $null

    if ($ErrorRecord.Exception.Response) {
        $response = $ErrorRecord.Exception.Response

        if ($null -ne $response.StatusCode) {
            try {
                if ($response.StatusCode -is [int]) {
                    $statusCode = [int]$response.StatusCode
                }
                elseif ($response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                    $statusCode = [int]$response.StatusCode.value__
                }
                else {
                    $statusCode = [int]$response.StatusCode
                }
            } catch {
                # Status code extraction is best-effort; format varies by exception type
                Write-Verbose "Could not extract HTTP status code: $($_.Exception.Message)"
            }
        }

        try {
            if ($response -is [System.Net.Http.HttpResponseMessage]) {
                $rawBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
            elseif ($response.PSObject.Methods.Name -contains 'GetResponseStream') {
                $stream = $response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $rawBody = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()
                }
            }
            elseif ($response.PSObject.Properties.Name -contains 'Content' -and $response.Content) {
                if ($response.Content -is [string]) {
                    $rawBody = $response.Content
                }
                elseif ($response.Content.PSObject.Methods.Name -contains 'ReadAsStringAsync') {
                    $rawBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                }
            }
        } catch {
            # Response body extraction is best-effort; stream may be closed or unavailable
            Write-Verbose "Could not read response body: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($rawBody) -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $rawBody = $ErrorRecord.ErrorDetails.Message
    }

    if (-not [string]::IsNullOrWhiteSpace($rawBody)) {
        try {
            $parsedError = $rawBody | ConvertFrom-Json -ErrorAction Stop

            if ($parsedError.error) {
                $errorCode = [string]$parsedError.error.code
                $errorMessage = [string]$parsedError.error.message
            }
            else {
                if ($parsedError.code) { $errorCode = [string]$parsedError.code }
                if ($parsedError.message) { $errorMessage = [string]$parsedError.message }
            }
        } catch {
            # JSON parsing is best-effort; body may not be valid JSON
            Write-Verbose "Could not parse error response as JSON: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($errorMessage) -and $ErrorRecord.Exception.Message) {
        $errorMessage = ($ErrorRecord.Exception.Message -split "`r?`n")[0]
    }

    return [pscustomobject]@{
        StatusCode   = $statusCode
        ErrorCode    = $errorCode
        ErrorMessage = $errorMessage
        RawBody      = $rawBody
    }
}

function Get-ApiErrorCategory {
    [CmdletBinding()]
    param (
        [int]$StatusCode
    )

    switch ($StatusCode) {
        400 { return [System.Management.Automation.ErrorCategory]::InvalidArgument }
        401 { return [System.Management.Automation.ErrorCategory]::AuthenticationError }
        403 { return [System.Management.Automation.ErrorCategory]::PermissionDenied }
        404 { return [System.Management.Automation.ErrorCategory]::ObjectNotFound }
        409 { return [System.Management.Automation.ErrorCategory]::ResourceExists }
        429 { return [System.Management.Automation.ErrorCategory]::LimitsExceeded }
        500 { return [System.Management.Automation.ErrorCategory]::InvalidResult }
        502 { return [System.Management.Automation.ErrorCategory]::ProtocolError }
        503 { return [System.Management.Automation.ErrorCategory]::ResourceUnavailable }
        504 { return [System.Management.Automation.ErrorCategory]::OperationTimeout }
        default { return [System.Management.Automation.ErrorCategory]::NotSpecified }
    }
}

function Get-ApiNextLink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Response
    )

    foreach ($propertyName in @('@odata.nextLink', 'nextLink', 'odata.nextLink')) {
        if ($Response.PSObject.Properties.Name -contains $propertyName) {
            $nextLink = [string]$Response.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
                return $nextLink
            }
        }
    }

    return $null
}

function Send-ApiRequest {
    <#
    .SYNOPSIS
        Sends a single HTTP request to any API with retry, pagination, and detailed error parsing.

    .DESCRIPTION
        Wraps Invoke-RestMethod for resilient API calls.
        Handles transient API failures (429/500/502/503/504) with exponential backoff, follows pagination links,
        and extracts structured error details from API response bodies.

    .PARAMETER Method
        HTTP method to use: GET, POST, PATCH, PUT, DELETE.

    .PARAMETER Uri
        Absolute or relative request URI.

    .PARAMETER AccessToken
        Optional bearer token. If provided, Authorization header is set to "Bearer <token>".

    .PARAMETER Body
        Optional request body.
        By default, non-string bodies are serialized as JSON.

    .PARAMETER MaxRetries
        Maximum retry attempts for transient status codes (429, 500, 502, 503, 504).
        Default: 6

    .PARAMETER UserAgent
        User-Agent header value.

    .PARAMETER Proxy
        Optional proxy URL (for example http://127.0.0.1:8080).

    .PARAMETER SkipCertificateCheck
        If set, forwards SkipCertificateCheck to Invoke-RestMethod.
        If not supported by the current PowerShell runtime, a warning is shown and execution continues.

    .PARAMETER DisablePagination
        Disables automatic following of nextLink pagination.

    .PARAMETER VerboseMode
        Writes request and pagination progress to console.

    .PARAMETER Silent
        Suppresses informational retry and failure host output.
        Errors are still emitted via Write-Error.

    .PARAMETER RawJson
        Returns JSON string output instead of PowerShell objects.

    .PARAMETER QueryParameters
        Hashtable of query parameters to append to the initial URI.

    .PARAMETER AdditionalHeaders
        Additional headers merged into the request (overrides defaults if same key is provided).

    .PARAMETER JsonDepthRequest
        JSON serialization depth for request body conversion.

    .PARAMETER JsonDepthResponse
        JSON serialization depth when using -RawJson.

    .EXAMPLE
        Send-ApiRequest -Method GET -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -AccessToken $token

    .EXAMPLE
        Send-ApiRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users' -AccessToken $token -QueryParameters @{ '$top' = 50 }

    .EXAMPLE
        Send-ApiRequest -Method POST -Uri 'https://api.contoso.local/v1/items' `
            -Body @{ name = 'item01'; enabled = $true } `
            -AdditionalHeaders @{ 'x-trace-id' = 'abc123' }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("GET", "POST", "PATCH", "PUT", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$AccessToken,
        [object]$Body,
        [int]$MaxRetries = 6,
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-us) PowerShell/7.5.0",
        [string]$Proxy,
        [switch]$SkipCertificateCheck,
        [switch]$DisablePagination,
        [switch]$VerboseMode,
        [switch]$Silent,
        [switch]$RawJson,
        [hashtable]$QueryParameters,
        [hashtable]$AdditionalHeaders,
        [int]$JsonDepthRequest = 10,
        [int]$JsonDepthResponse = 10
    )

    $retryableStatusCodes = @(429, 500, 502, 503, 504)
    $results = New-Object 'System.Collections.Generic.List[object]'
    $seenNextLinks = New-Object 'System.Collections.Generic.HashSet[string]'
    $sawValueResponse = $false
    $irmSupportsSkipCertificateCheck = (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')

    $headers = @{
        'User-Agent' = $UserAgent
    }

    if ($AccessToken) {
        $headers['Authorization'] = "Bearer $AccessToken"
    }

    if ($AdditionalHeaders) {
        foreach ($key in $AdditionalHeaders.Keys) {
            $headers[$key] = $AdditionalHeaders[$key]
        }
    }

    if (-not $headers.ContainsKey('Content-Type')) {
        $headers['Content-Type'] = 'application/json'
    }

    if (-not $headers.ContainsKey('Accept')) {
        $headers['Accept'] = 'application/json'
    }

    $currentUri = Add-ApiQueryParameters -Uri $Uri -QueryParameters $QueryParameters
    $requestMethod = $Method
    $requestBody = $Body

    while (-not [string]::IsNullOrWhiteSpace($currentUri)) {
        $retryCount = 0
        $response = $null

        do {
            $irmParams = @{
                Uri         = $currentUri
                Method      = $requestMethod
                Headers     = $headers
                ErrorAction = 'Stop'
            }

            if ($Proxy) {
                $irmParams['Proxy'] = $Proxy
            }

            if ($SkipCertificateCheck) {
                if ($irmSupportsSkipCertificateCheck) {
                    $irmParams['SkipCertificateCheck'] = $true
                }
                elseif (-not $Silent) {
                    Write-Warning "SkipCertificateCheck is not supported by this PowerShell version. Continuing without it."
                }
            }

            if ($null -ne $requestBody) {
                if ($requestBody -is [string]) {
                    $irmParams['Body'] = $requestBody
                }
                else {
                    $irmParams['Body'] = ($requestBody | ConvertTo-Json -Depth $JsonDepthRequest -Compress)
                }
            }

            try {
                if ($VerboseMode) {
                    Write-Host ("[*] Request [{0}]: {1}" -f $requestMethod, $currentUri)
                }

                $response = Invoke-RestMethod @irmParams
                break
            }
            catch {
                $errorDetails = Get-ApiErrorDetails -ErrorRecord $_
                $statusCode = $errorDetails.StatusCode

                if ($statusCode -in $retryableStatusCodes -and $retryCount -lt $MaxRetries) {
                    $retryDelaySeconds = [int][math]::Pow(2, $retryCount)

                    if (-not $Silent) {
                        if ($statusCode -eq 429) {
                            Write-Host ("[i] Request was throttled (429). Retrying automatically in {0}s (attempt {1}/{2}). No action needed." -f $retryDelaySeconds, ($retryCount + 1), $MaxRetries)
                        }
                        else {
                            Write-Host ("[i] Request hit a temporary API error ({0}). Retrying automatically in {1}s (attempt {2}/{3})." -f $statusCode, $retryDelaySeconds, ($retryCount + 1), $MaxRetries)
                        }
                    }

                    Start-Sleep -Seconds $retryDelaySeconds
                    $retryCount++
                    continue
                }

                $displayStatus = if ($statusCode) { $statusCode } else { "unknown" }
                $displayCode = if ($errorDetails.ErrorCode) { $errorDetails.ErrorCode } else { "unknown_error" }
                $displayMessage = if ($errorDetails.ErrorMessage) { $errorDetails.ErrorMessage } else { "No error message returned by API." }

                if (-not $Silent) {
                    Write-Host ("[!] API Request failed with status {0}: {1} - {2}" -f $displayStatus, $displayCode, $displayMessage)
                }

                $msg = "API request failed with status ${displayStatus}: $displayCode - $displayMessage"
                $exception = New-Object System.Exception($msg)
                $errorRecord = New-Object System.Management.Automation.ErrorRecord(
                    $exception,
                    "ApiRequestFailed",
                    (Get-ApiErrorCategory -StatusCode $statusCode),
                    $currentUri
                )
                Write-Error $errorRecord
                return
            }
        } while ($retryCount -le $MaxRetries)

        if ($null -eq $response) {
            return
        }

        if ($response.PSObject.Properties.Name -contains 'value') {
            $sawValueResponse = $true

            if ($null -ne $response.value) {
                foreach ($item in @($response.value)) {
                    $results.Add($item)
                }
            }
        }
        else {
            $results.Add($response)
        }

        if ($DisablePagination) {
            break
        }

        $nextLink = Get-ApiNextLink -Response $response
        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            break
        }

        if (-not $seenNextLinks.Add($nextLink)) {
            Write-Warning "Pagination aborted because the API returned a repeated nextLink."
            break
        }

        if ($VerboseMode) {
            Write-Host ("[*] Following pagination link: {0}" -f $nextLink)
        }

        $currentUri = $nextLink
        $requestMethod = 'GET'
        $requestBody = $null
    }

    if ($results.Count -eq 0) {
        $output = @()
    }
    elseif ($sawValueResponse -or $results.Count -ne 1) {
        $output = $results.ToArray()
    }
    else {
        $output = $results[0]
    }

    if ($RawJson) {
        return $output | ConvertTo-Json -Depth $JsonDepthResponse
    }

    return $output
}

Export-ModuleMember -Function Send-ApiRequest
