//! Caller identity endpoints.
//!
//! `/v1/me` answers "who is calling" from the token alone. `/v1/session`
//! answers "what may they do" by joining the token to PostgreSQL-backed
//! membership and permission data. Keeping them separate means a database
//! outage does not break token introspection, and identity data never implies
//! authority.

use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Principal;
use crate::principal::TenantContext;

/// Identity proven by a validated token. Contains no authorization data.
#[derive(Debug, Serialize)]
pub struct IdentityView {
    /// Stable subject identifier from the provider.
    pub subject: String,
    /// Issuer that signed the token.
    pub issuer: String,
    /// Audiences present on the token.
    pub audiences: Vec<String>,
    /// Space-delimited scopes, split into individual strings.
    pub scopes: Vec<String>,
    /// Provider token identifier, useful for revocation and audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Token expiry as a Unix timestamp in seconds.
    pub expires_at: u64,
}

impl From<Principal> for IdentityView {
    fn from(principal: Principal) -> Self {
        Self {
            subject: principal.subject,
            issuer: principal.issuer,
            audiences: principal.audiences,
            scopes: principal.scopes,
            token_id: principal.token_id,
            expires_at: principal.expires_at,
        }
    }
}

/// Echo the authenticated identity.
///
/// Exists to prove the token path end to end and to let clients inspect the
/// claims Rust accepted. It reads no database and exposes nothing beyond the
/// token itself.
pub async fn me(principal: Principal) -> Json<IdentityView> {
    Json(principal.into())
}

/// The caller's effective authorization inside one tenant.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// Internal principal id, stable across sessions and providers.
    pub principal_id: Uuid,
    /// Identity subject the principal was resolved from.
    pub subject: String,
    /// Tenant boundary enforced by every downstream operation.
    pub tenant_id: String,
    /// Role granted by the membership.
    pub role: String,
    /// Effective permissions derived from the role.
    pub permissions: Vec<String>,
    /// Token expiry as a Unix timestamp in seconds.
    pub expires_at: u64,
}

/// Resolve the caller against memberships and permissions.
///
/// A valid token without an active membership in an active tenant is denied by
/// the [`TenantContext`] extractor before this handler runs.
pub async fn session(context: TenantContext) -> Json<SessionView> {
    Json(SessionView {
        principal_id: context.resolved.principal_id,
        subject: context.identity.subject,
        tenant_id: context.resolved.tenant_id,
        role: context.resolved.role,
        permissions: context.resolved.permissions,
        expires_at: context.identity.expires_at,
    })
}
