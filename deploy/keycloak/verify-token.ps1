#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Fetches a development token from Keycloak and asserts the claims the Rust
    control plane depends on.

.DESCRIPTION
    Uses the resource-owner password grant against the control-plane client to
    prove that:
      - the client accepts the configured credentials
      - aud contains the control-plane client id
      - tenant_id is present and equals the expected tenant

    Development only. Never run password grants against production realms.
#>
[CmdletBinding()]
param(
    [string] $KeycloakUrl = $(if ($env:KC_URL) { $env:KC_URL } else { 'http://127.0.0.1:8080' }),
    [string] $Realm = 'agentic-platform',
    [string] $ClientId = 'rust-control-plane',
    [string] $ClientSecret = $(if ($env:KC_CLIENT_SECRET) { $env:KC_CLIENT_SECRET } else { 'REDACTED-IN-PUBLIC-HISTORY' }),
    [string] $Username = 'dev-user',
    [string] $Password = 'REDACTED-IN-PUBLIC-HISTORY',
    [string] $ExpectedTenantId = 'tenant-acme'
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-Base64Url {
    param([string] $Value)
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { throw 'invalid base64url segment' }
    }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
}

$body = @{
    grant_type    = 'password'
    client_id     = $ClientId
    client_secret = $ClientSecret
    username      = $Username
    password      = $Password
    scope         = 'openid'
}

$response = Invoke-RestMethod -Method Post `
    -Uri "$KeycloakUrl/realms/$Realm/protocol/openid-connect/token" `
    -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30

$parts = $response.access_token.Split('.')
if ($parts.Count -ne 3) { throw 'access token is not a JWT' }

$header = ConvertFrom-Base64Url $parts[0] | ConvertFrom-Json
$claims = ConvertFrom-Base64Url $parts[1] | ConvertFrom-Json

Write-Host ''
Write-Host 'Header:'
$header | ConvertTo-Json -Depth 5
Write-Host 'Claims:'
$claims | ConvertTo-Json -Depth 10

$audiences = @($claims.aud)
$failures = @()
if ($header.alg -ne 'RS256') { $failures += "expected alg RS256, got $($header.alg)" }
if ($audiences -notcontains $ClientId) { $failures += "aud does not contain $ClientId (got: $($audiences -join ', '))" }
if (-not $claims.tenant_id) { $failures += 'tenant_id claim is missing' }
elseif ($claims.tenant_id -ne $ExpectedTenantId) { $failures += "tenant_id is $($claims.tenant_id), expected $ExpectedTenantId" }
if (-not $claims.sub) { $failures += 'sub claim is missing' }
if (-not $claims.exp) { $failures += 'exp claim is missing' }

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host 'FAILED:' -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

Write-Host 'OK: token has RS256 signature, audience, tenant_id and subject.' -ForegroundColor Green
exit 0
