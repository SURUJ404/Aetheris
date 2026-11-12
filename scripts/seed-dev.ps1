#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Seeds a development tenant, principal and membership into PostgreSQL.

.DESCRIPTION
    Resolves the Keycloak user's `sub` (the token subject), then upserts:
      - the tenant
      - the principal keyed by (issuer, subject)
      - an active membership with the given role

    Safe to re-run: existing rows are updated in place. The issuer must match
    `OIDC_ISSUER` exactly as the control plane sees it, because principals are
    keyed by (issuer, subject). Host runs use http://127.0.0.1:8080; containers
    reach Keycloak by service name and therefore need a different issuer.

    Development only. Never run against a production database.

.PARAMETER Issuer
    Issuer stored with the principal. Defaults to `$KeycloakUrl/realms/$Realm`.

.EXAMPLE
    ./seed-dev.ps1
    ./seed-dev.ps1 -Role member
    ./seed-dev.ps1 -KeycloakUrl http://keycloak:8080 -Issuer http://keycloak:8080/realms/agentic-platform
#>
[CmdletBinding()]
param(
    [string] $KeycloakUrl = $(if ($env:KC_URL) { $env:KC_URL } else { 'http://127.0.0.1:8080' }),
    [string] $AdminRealm = 'master',
    [string] $AdminUser = $(if ($env:KC_ADMIN_USER) { $env:KC_ADMIN_USER } else { 'admin' }),
    [string] $AdminPassword = $(if ($env:KC_ADMIN_PASSWORD) { $env:KC_ADMIN_PASSWORD } else { 'REDACTED-IN-PUBLIC-HISTORY' }),
    [string] $Realm = 'agentic-platform',
    [string] $Username = 'dev-user',
    [string] $Issuer = '',
    [string] $TenantId = 'tenant-acme',
    [string] $TenantName = 'Acme (development)',
    [ValidateSet('owner', 'admin', 'member', 'viewer')]
    [string] $Role = 'owner',
    [string] $PostgresContainer = 'agentic-postgres',
    [string] $Database = 'agentic',
    [string] $DatabaseUser = 'agentic'
)

$ErrorActionPreference = 'Stop'

if (-not $Issuer) {
    $Issuer = "$KeycloakUrl/realms/$Realm"
}

function ConvertTo-SqlLiteral {
    param([string] $Value)
    return "'" + ($Value -replace "'", "''") + "'"
}

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

function Get-UserSubject {
    $encoded = [uri]::EscapeDataString($Username)
    $users = Invoke-RestMethod -Method Get `
        -Uri "$KeycloakUrl/admin/realms/$Realm/users?username=$encoded&exact=true" `
        -Headers @{ Authorization = "Bearer $(Get-AdminToken)" } -TimeoutSec 30

    if (-not $users -or $users.Count -eq 0) {
        throw "user '$Username' not found in realm '$Realm'. Run deploy/keycloak/bootstrap.ps1 first."
    }
    return [string] $users[0].id
}

function Assert-DatabaseRunning {
    $running = docker inspect -f '{{.State.Running}}' $PostgresContainer 2>$null
    if ($LASTEXITCODE -ne 0 -or $running.Trim() -ne 'true') {
        throw "container '$PostgresContainer' is not running. Start it with: docker compose -f compose.yaml up -d"
    }
}

$subject = Get-UserSubject
if ($subject -notmatch '^[0-9a-fA-F-]{36}$') {
    throw "Keycloak returned a non-UUID subject '$subject'; refusing to seed."
}

Assert-DatabaseRunning

$tenant = ConvertTo-SqlLiteral $TenantId
$name = ConvertTo-SqlLiteral $TenantName
$issuerLiteral = ConvertTo-SqlLiteral $Issuer
$subjectLiteral = ConvertTo-SqlLiteral $subject
$roleLiteral = ConvertTo-SqlLiteral $Role

# One round trip so a partial seed cannot leave a tenant without a membership.
$sql = @"
BEGIN;

INSERT INTO tenants (id, name, status)
VALUES ($tenant, $name, 'active')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name,
        status = 'active';

INSERT INTO principals (issuer, subject)
VALUES ($issuerLiteral, $subjectLiteral)
ON CONFLICT (issuer, subject) DO NOTHING;

INSERT INTO memberships (tenant_id, principal_id, role, status)
SELECT $tenant, p.id, $roleLiteral, 'active'
FROM principals p
WHERE p.issuer = $issuerLiteral
  AND p.subject = $subjectLiteral
ON CONFLICT (tenant_id, principal_id) DO UPDATE
    SET role = EXCLUDED.role,
        status = 'active';

COMMIT;
"@

$sql | docker exec -i $PostgresContainer psql -v ON_ERROR_STOP=1 -U $DatabaseUser -d $Database
if ($LASTEXITCODE -ne 0) {
    throw "seeding failed (psql exit $LASTEXITCODE)"
}

Write-Host ''
Write-Host 'Seeded development authorization data.'
Write-Host "  issuer     : $Issuer"
Write-Host "  subject    : $subject ($Username)"
Write-Host "  tenant     : $TenantId"
Write-Host "  role       : $Role"
Write-Host ''
Write-Host 'Request a token, then check /v1/session:'
Write-Host "  ./deploy/keycloak/verify-token.ps1 -Realm $Realm"
