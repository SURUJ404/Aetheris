//! Authentication and authorization. Enforce tenant/resource boundaries here.
//!
//! Identity claims are input, never authority. Rust decides what a principal
//! may do; the provider only says who they are.

mod error;
mod jwks;
mod verifier;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::Serialize;

use crate::state::AppState;

pub use error::AuthError;
pub use jwks::JwksCache;
pub use verifier::JwtVerifier;

/// An authenticated caller, derived exclusively from a validated token.
#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    /// Stable subject identifier from the provider.
    pub subject: String,
    /// Tenant boundary enforced by every downstream operation.
    pub tenant_id: String,
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

impl Principal {
    /// Whether the token carries a given scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|candidate| candidate == scope)
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?;
        let value = header.to_str().map_err(|_| AuthError::MalformedHeader)?;
        let token = bearer_token(value)?;
        state.verifier.verify(token).await
    }
}

/// Extract the credential from an `Authorization: Bearer <token>` value.
///
/// The scheme is case-insensitive per RFC 7235; the token itself is opaque.
fn bearer_token(value: &str) -> Result<&str, AuthError> {
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::MalformedHeader)?;
    let token = token.trim();

    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(AuthError::MalformedHeader);
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn accepts_bearer_scheme_case_insensitively() {
        assert_eq!(bearer_token("Bearer abc.def.ghi").unwrap(), "abc.def.ghi");
        assert_eq!(bearer_token("bearer abc.def.ghi").unwrap(), "abc.def.ghi");
        assert_eq!(
            bearer_token("BEARER  abc.def.ghi  ").unwrap(),
            "abc.def.ghi"
        );
    }

    #[test]
    fn rejects_malformed_authorization_values() {
        assert!(bearer_token("").is_err());
        assert!(bearer_token("Bearer").is_err());
        assert!(bearer_token("Bearer ").is_err());
        assert!(bearer_token("Basic abc").is_err());
        assert!(bearer_token("abc.def.ghi").is_err());
    }
}
