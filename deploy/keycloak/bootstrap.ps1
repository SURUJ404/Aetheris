#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Idempotently configures the Keycloak realm used by the agentic platform.

.DESCRIPTION
    Creates/updates:
      - the OIDC client used by the Rust control plane (confidential, PKCE)
      - an audience mapper so access tokens carry aud=rust-control-plane
      - a tenant_id claim mapper backed by the user attribute tenant_id
      - a local development user carrying tenant_id

    Safe to re-run. Existing resources are updated in place.

    Development only. The defaults below are throwaway credentials and must
    never be used for anything reachable outside localhost.

.EXAMPLE
    ./bootstrap.ps1
    ./bootstrap.ps1 -Realm agentic-platform -ClientSecret 'something-else'
#>
[CmdletBinding()]
param(
    [string] $KeycloakUrl = $(if ($env:KC_URL) { $env:KC_URL } else { 'http://127.0.0.1:8080' }),
    [string] $AdminRealm = 'master',
    [string] $AdminUser = $(if ($env:KC_ADMIN_USER) { $env:KC_ADMIN_USER } else { 'admin' }),
    [string] $AdminPassword = $(if ($env:KC_ADMIN_PASSWORD) { $env:KC_ADMIN_PASSWORD } else { 'REDACTED-IN-PUBLIC-HISTORY' }),
    [string] $Realm = 'agentic-platform',
    [string] $ClientId = 'rust-control-plane',
    [string] $ClientSecret = $(if ($env:KC_CLIENT_SECRET) { $env:KC_CLIENT_SECRET } else { 'REDACTED-IN-PUBLIC-HISTORY' }),
    [string] $DevUsername = 'dev-user',
    [string] $DevPassword = 'REDACTED-IN-PUBLIC-HISTORY',
    [string] $DevTenantId = 'tenant-acme'
)

$ErrorActionPreference = 'Stop'

function Get-AdminToken {
    $body = @{
        grant_type = 'password'
        client_id  = 'admin-cli'
        username   = $AdminUser
        password   = $AdminPassword
    }
    $token = Invoke-RestMethod -Method Post `
        -Uri "$KeycloakUrl/realms/$AdminRealm/protocol/openid-connect/token" `
        -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
    return $token.access_token
}

function Get-StatusCode {
    param($ErrorRecord)
    if ($ErrorRecord.Exception.Response) {
        return [int] $ErrorRecord.Exception.Response.StatusCode
    }
    return 0
}

function Invoke-Kc {
    param(
        [string] $Method,
        [string] $Path,
        $Body,
        [switch] $AllowNotFound
    )
    $uri = "$KeycloakUrl/admin$Path"
    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $script:AuthHeaders
        TimeoutSec  = 30
        ContentType = 'application/json'
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }
    try {
        return Invoke-RestMethod @params
    }
    catch {
        $status = Get-StatusCode $_
        if ($status -eq 404 -and $AllowNotFound) { return $null }
        throw "Keycloak $Method $Path failed with HTTP $status. $($_.ErrorDetails.Message)"
    }
}

function Ensure-Realm {
    $existing = Invoke-Kc -Method Get -Path "/realms/$Realm" -AllowNotFound
    if ($existing) {
        Write-Host "realm '$Realm' already exists"
        return
    }
    $payload = @{
        realm       = $Realm
        enabled     = $true
        displayName = 'Agentic Platform'
        # Access tokens are short-lived; refresh tokens carry the session.
        accessTokenLifespan = 300
        ssoSessionIdleTimeout = 1800
        ssoSessionMaxLifespan = 28800
        loginWithEmailAllowed = $true
        duplicateEmailsAllowed = $false
        resetPasswordAllowed = $true
        editUsernameAllowed = $false
        bruteForceProtected = $true
    }
    Invoke-Kc -Method Post -Path '/realms' -Body $payload | Out-Null
    Write-Host "created realm '$Realm'"
}

function Ensure-Client {
    $existing = Invoke-Kc -Method Get -Path "/realms/$Realm/clients?clientId=$ClientId"
    $payload = @{
        clientId                  = $ClientId
        name                      = 'Rust Control Plane'
        description               = 'Resource server and OIDC client for the Rust control plane'
        enabled                   = $true
        protocol                  = 'openid-connect'
        publicClient              = $false
        bearerOnly                = $false
        standardFlowEnabled       = $true
        implicitFlowEnabled       = $false
        directAccessGrantsEnabled = $true
        serviceAccountsEnabled    = $true
        clientAuthenticatorType   = 'client-secret'
        secret                    = $ClientSecret
        redirectUris              = @('http://127.0.0.1:8081/*', 'http://localhost:8081/*')
        webOrigins                = @('http://127.0.0.1:8081', 'http://localhost:8081')
        attributes                = @{
            'pkce.code.challenge.method' = 'S256'
            'access.token.lifespan'      = '300'
            'post.logout.redirect.uris'  = 'http://127.0.0.1:8081/*'
        }
    }

    if ($existing -and $existing.Count -gt 0) {
        $id = $existing[0].id
        $payload['id'] = $id
        Invoke-Kc -Method Put -Path "/realms/$Realm/clients/$id" -Body $payload | Out-Null
        Write-Host "updated client '$ClientId'"
        return $id
    }

    Invoke-Kc -Method Post -Path "/realms/$Realm/clients" -Body $payload | Out-Null
    $created = Invoke-Kc -Method Get -Path "/realms/$Realm/clients?clientId=$ClientId"
    Write-Host "created client '$ClientId'"
    return $created[0].id
}

function Ensure-Mapper {
    param(
        [string] $ClientInternalId,
        [hashtable] $Mapper
    )
    $existing = Invoke-Kc -Method Get -Path "/realms/$Realm/clients/$ClientInternalId/protocol-mappers/models"
    $match = $existing | Where-Object { $_.name -eq $Mapper.name }
    if ($match) {
        $Mapper['id'] = $match.id
        Invoke-Kc -Method Put -Path "/realms/$Realm/clients/$ClientInternalId/protocol-mappers/models/$($match.id)" -Body $Mapper | Out-Null
        Write-Host "updated mapper '$($Mapper.name)'"
        return
    }
    Invoke-Kc -Method Post -Path "/realms/$Realm/clients/$ClientInternalId/protocol-mappers/models" -Body $Mapper | Out-Null
    Write-Host "created mapper '$($Mapper.name)'"
}

function Ensure-UserProfileAttribute {
    param(
        [string] $Name,
        [string] $DisplayName
    )
    # Keycloak >= 24 uses the declarative user profile. Undeclared attributes
    # are silently discarded on write unless unmanaged attributes are enabled,
    # so the tenant attribute must be part of the profile schema.
    $profile = Invoke-Kc -Method Get -Path "/realms/$Realm/users/profile"
    $names = @($profile.attributes | ForEach-Object { $_.name })
    if ($names -contains $Name) {
        Write-Host "user profile attribute '$Name' already declared"
        return
    }

    $attribute = [ordered]@{
        name         = $Name
        displayName  = $DisplayName
        multivalued  = $false
        permissions  = @{
            view = @('admin', 'user')
            edit = @('admin')
        }
        validations  = @{
            length = @{ min = 1; max = 64 }
        }
    }

    $profile.attributes = @($profile.attributes) + $attribute
    Invoke-Kc -Method Put -Path "/realms/$Realm/users/profile" -Body $profile | Out-Null
    Write-Host "declared user profile attribute '$Name'"
}

function Ensure-User {
    $existing = Invoke-Kc -Method Get -Path "/realms/$Realm/users?username=$DevUsername&exact=true"
    $payload = @{
        username      = $DevUsername
        enabled       = $true
        emailVerified = $true
        firstName     = 'Dev'
        lastName      = 'User'
        email         = "$DevUsername@example.test"
        attributes    = @{ tenant_id = @($DevTenantId) }
        credentials   = @(@{
            type      = 'password'
            value     = $DevPassword
            temporary = $false
        })
    }

    if ($existing -and $existing.Count -gt 0) {
        $id = $existing[0].id
        $payload.Remove('credentials')
        Invoke-Kc -Method Put -Path "/realms/$Realm/users/$id" -Body $payload | Out-Null
        Invoke-Kc -Method Put -Path "/realms/$Realm/users/$id/reset-password" -Body @{
            type      = 'password'
            value     = $DevPassword
            temporary = $false
        } | Out-Null
        Write-Host "updated user '$DevUsername'"
        return $id
    }

    Invoke-Kc -Method Post -Path "/realms/$Realm/users" -Body $payload | Out-Null
    $created = Invoke-Kc -Method Get -Path "/realms/$Realm/users?username=$DevUsername&exact=true"
    Write-Host "created user '$DevUsername'"
    return $created[0].id
}

$script:AuthHeaders = @{ Authorization = "Bearer $(Get-AdminToken)" }

Ensure-Realm
$clientInternalId = Ensure-Client

Ensure-Mapper -ClientInternalId $clientInternalId -Mapper @{
    name           = 'rust-control-plane-audience'
    protocol       = 'openid-connect'
    protocolMapper = 'oidc-audience-mapper'
    config         = @{
        'included.custom.audience' = $ClientId
        'access.token.claim'       = 'true'
        'id.token.claim'           = 'false'
        'introspection.token.claim' = 'true'
    }
}

Ensure-Mapper -ClientInternalId $clientInternalId -Mapper @{
    name           = 'tenant-id'
    protocol       = 'openid-connect'
    protocolMapper = 'oidc-usermodel-attribute-mapper'
    config         = @{
        'user.attribute'        = 'tenant_id'
        'claim.name'            = 'tenant_id'
        'jsonType.label'        = 'String'
        'access.token.claim'    = 'true'
        'id.token.claim'        = 'true'
        'userinfo.token.claim'  = 'true'
        'introspection.token.claim' = 'true'
    }
}

Ensure-UserProfileAttribute -Name 'tenant_id' -DisplayName 'Tenant ID'
Ensure-User | Out-Null

Write-Host ''
Write-Host 'Realm configuration complete.'
Write-Host "  issuer : $KeycloakUrl/realms/$Realm"
Write-Host "  client : $ClientId"
Write-Host "  user   : $DevUsername (tenant_id=$DevTenantId)"
Write-Host ''
Write-Host 'Verify a token with:'
Write-Host "  ./verify-token.ps1 -Realm $Realm -ClientId $ClientId"
