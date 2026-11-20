//! OIDC access-token verification.
//!
//! The verifier is the only place a token becomes a [`Principal`]. It enforces
//! signature, algorithm, issuer, audience, expiry and the tenant claim before
//! any handler runs.

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::auth::{AuthError, JwksCache, Principal};
use crate::config::IdentityConfig;

/// Verifies RS256 access tokens against a cached JWKS.
pub struct JwtVerifier {
    config: IdentityConfig,
    keys: JwksCache,
    validation: Validation,
}

impl JwtVerifier {
    /// Build a verifier. Validation rules are fixed at construction so a
    /// request cannot weaken them.
    pub fn new(config: IdentityConfig, keys: JwksCache) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[config.issuer.as_str()]);
        validation.set_audience(&[config.audience.as_str()]);
        validation.set_required_spec_claims(&["sub", "exp", "iss", "aud"]);
        validation.leeway = config.leeway.as_secs();
        validation.validate_nbf = true;

        Self {
            config,
            keys,
            validation,
        }
    }

    /// Validate a compact JWT and project it into a [`Principal`].
    pub async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let header = decode_header(token).map_err(map_jwt_error)?;

        // Check before touching a key: prevents algorithm-confusion attacks
        // such as HS256 signed with the public key material.
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::UnsupportedAlgorithm);
        }

        let key = self.keys.get(header.kid.as_deref()).await?;
        let data = decode::<RawClaims>(token, &key, &self.validation).map_err(map_jwt_error)?;
        let claims = data.claims;

        // An ID token is a client authentication artifact, not an API bearer
        // credential. Providers mark it with `typ: ID` and, for OIDC flows, a
        // `nonce` bound to the client's authentication request. Reject both;
        // a valid access token from Keycloak carries `typ: Bearer` and no nonce.
        // Checking this after signature validation keeps the rejection from
        // becoming an oracle for unsigned token contents.
        if claims
            .typ
            .as_deref()
            .is_some_and(|typ| typ.eq_ignore_ascii_case("ID"))
            || claims.nonce.is_some()
        {
            return Err(AuthError::IdTokenRejected);
        }

        let tenant_id = claims
            .extra
            .get(&self.config.tenant_claim)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::MissingTenant(self.config.tenant_claim.clone()))?;

        Ok(Principal {
            subject: claims.sub,
            tenant_id: tenant_id.to_owned(),
            issuer: claims.iss,
            audiences: claims.aud.into_vec(),
            scopes: claims
                .scope
                .unwrap_or_default()
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect(),
            token_id: claims.jti,
            expires_at: claims.exp,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: u64,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    /// Provider token type. Keycloak access tokens use `Bearer`; ID tokens use
    /// `ID`. Absence is accepted for providers that omit it.
    #[serde(default)]
    typ: Option<String>,
    /// Present on OIDC ID tokens to bind them to the client's auth request.
    #[serde(default)]
    nonce: Option<Value>,
    /// Every claim not modelled above, including the configured tenant claim.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// `aud` is a string in some providers and an array in others.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Default for Audience {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl Audience {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

fn map_jwt_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        ErrorKind::ExpiredSignature => AuthError::Expired,
        ErrorKind::ImmatureSignature => AuthError::NotYetValid,
        ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
        ErrorKind::InvalidAudience => AuthError::InvalidAudience,
        ErrorKind::InvalidSignature => AuthError::InvalidSignature,
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::UnsupportedAlgorithm
        | ErrorKind::MissingAlgorithm => AuthError::UnsupportedAlgorithm,
        _ => AuthError::MalformedToken,
    }
}
