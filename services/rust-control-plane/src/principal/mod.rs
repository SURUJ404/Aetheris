//! Principal resolution: combine a validated token with Postgres-backed
//! membership and permission data.
//!
//! The token answers "who is calling". PostgreSQL answers "what may they do in
//! this tenant". Neither is sufficient alone, and a valid token without an
//! active membership is denied.

use axum::extract::FromRequestParts;
use axum::http::header::RETRY_AFTER;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

use crate::auth::{AuthError, Principal};
use crate::persistence::{ResolvedPrincipal, StoreError};
use crate::state::AppState;

/// An authenticated caller resolved against tenant authorization data.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Identity proven by the token.
    pub identity: Principal,
    /// Membership, role and effective permissions from PostgreSQL.
    pub resolved: ResolvedPrincipal,
}

impl TenantContext {
    /// Whether the caller holds a permission derived from their role.
    ///
    /// Policy evaluation is the next slice; this is the primitive it builds on.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.resolved
            .permissions
            .iter()
            .any(|granted| granted == permission)
    }
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = AccessError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let identity = Principal::from_request_parts(parts, state).await?;

        let resolved = state
            .principal_store
            .resolve(&identity.issuer, &identity.subject, &identity.tenant_id)
            .await
            .map_err(AccessError::Store)?
            .ok_or_else(|| AccessError::NotAMember(identity.tenant_id.clone()))?;

        Ok(Self { identity, resolved })
    }
}

/// Rejections produced while resolving a principal.
#[derive(Debug, Error)]
pub enum AccessError {
    /// The token itself was missing or invalid. Delegated to [`AuthError`] so
    /// the 401 shape stays identical across extractors.
    #[error(transparent)]
    Unauthenticated(#[from] AuthError),

    /// The identity is valid but has no active membership in the tenant.
    #[error("principal is not an active member of tenant `{0}`")]
    NotAMember(String),

    /// The authorization store could not be reached.
    #[error("authorization store is unavailable")]
    Store(#[source] StoreError),
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated(err) => err.into_response(),

            Self::NotAMember(tenant) => {
                tracing::info!(%tenant, "principal has no active membership");
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "access_denied",
                        "error_description": "principal is not a member of this tenant",
                    })),
                )
                    .into_response()
            }

            Self::Store(err) => {
                tracing::error!(error = %err, "authorization store failure");
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "temporarily_unavailable",
                        "error_description": "authorization store is unavailable",
                    })),
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                response
            }
        }
    }
}
