//! Authentication failures and their HTTP representation.

use axum::http::header::{RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

/// Failure to establish an authenticated principal.
///
/// Every variant is safe to expose to a caller: none contains token material,
/// key material, or upstream response bodies.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,

    #[error("authorization header is not a valid bearer credential")]
    MalformedHeader,

    #[error("token is malformed")]
    MalformedToken,

    #[error("token signature is invalid")]
    InvalidSignature,

    #[error("token has expired")]
    Expired,

    #[error("token is not valid yet")]
    NotYetValid,

    /// An OIDC ID token proves interactive authentication to a client; it is
    /// not a bearer credential for this API. Accepting one would let a client
    /// present its login proof as an API access token.
    #[error("ID tokens are not accepted as API access tokens")]
    IdTokenRejected,

    #[error("token issuer is not trusted")]
    InvalidIssuer,

    #[error("token audience is not trusted")]
    InvalidAudience,

    #[error("token signing algorithm is not allowed")]
    UnsupportedAlgorithm,

    #[error("token signing key is unknown")]
    UnknownKeyId,

    #[error("required tenant claim `{0}` is missing or empty")]
    MissingTenant(String),

    #[error("identity provider signing keys are unavailable")]
    KeysUnavailable,

    #[error("internal authentication error")]
    Internal,
}

impl AuthError {
    fn status(&self) -> StatusCode {
        match self {
            Self::KeysUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::MalformedHeader => "invalid_request",
            Self::KeysUnavailable => "temporarily_unavailable",
            Self::Internal => "server_error",
            _ => "invalid_token",
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = Json(json!({
            "error": self.code(),
            "error_description": self.to_string(),
        }));
        let mut response = (status, body).into_response();

        // RFC 6750: a request without credentials gets a bare challenge; a
        // rejected token gets `error="invalid_token"`.
        if status == StatusCode::UNAUTHORIZED {
            let challenge = match self {
                Self::MissingToken | Self::MalformedHeader => "Bearer",
                _ => "Bearer error=\"invalid_token\"",
            };
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }

        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("5"));
        }

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "authentication infrastructure failure");
        }

        response
    }
}
