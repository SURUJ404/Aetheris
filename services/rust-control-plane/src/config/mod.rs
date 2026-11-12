//! Typed configuration. Fail closed on missing production secrets.
//!
//! Identity settings are provider-agnostic. Swapping Keycloak for another OIDC
//! provider means changing environment values, not code. See
//! `migration/adr/0001-identity-provider.md`.

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Process-wide configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Address the HTTP server binds to. Never `0.0.0.0` by default.
    pub bind_addr: SocketAddr,
    /// Identity provider settings used to authenticate callers.
    pub identity: IdentityConfig,
}

/// Settings for validating OIDC access tokens.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Exact expected `iss` claim.
    pub issuer: String,
    /// Required member of the token's `aud` claim.
    pub audience: String,
    /// JWKS endpoint used to fetch signing keys.
    pub jwks_uri: String,
    /// Claim carrying the tenant identifier. Never read from a request body.
    pub tenant_claim: String,
    /// Clock skew allowance for `exp` and `nbf`.
    pub leeway: Duration,
    /// Maximum age of cached signing keys before a background refresh.
    pub jwks_ttl: Duration,
    /// Per-request timeout when fetching JWKS.
    pub jwks_timeout: Duration,
}

/// Configuration failures. Messages intentionally name the variable but never
/// echo its value.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable `{0}` is not set")]
    Missing(&'static str),
    #[error("environment variable `{name}` is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl AppConfig {
    /// Load configuration from the process environment.
    ///
    /// Fails when identity settings are absent: the control plane is the
    /// authority for identity and must not start in an unauthenticated mode.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = optional("BIND_ADDR", "127.0.0.1:8081")?.parse().map_err(
            |err: std::net::AddrParseError| ConfigError::Invalid {
                name: "BIND_ADDR",
                reason: err.to_string(),
            },
        )?;

        Ok(Self {
            bind_addr,
            identity: IdentityConfig::from_env()?,
        })
    }
}

impl IdentityConfig {
    /// Load identity settings from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = required("OIDC_ISSUER")?;
        let audience = required("OIDC_AUDIENCE")?;
        let jwks_uri = required("OIDC_JWKS_URI")?;
        let tenant_claim = optional("OIDC_TENANT_CLAIM", "tenant_id")?;

        for (name, value) in [("OIDC_ISSUER", &issuer), ("OIDC_JWKS_URI", &jwks_uri)] {
            if !(value.starts_with("https://") || value.starts_with("http://")) {
                return Err(ConfigError::Invalid {
                    name,
                    reason: "must be an absolute http(s) URL".into(),
                });
            }
        }

        Ok(Self {
            issuer,
            audience,
            jwks_uri,
            tenant_claim,
            leeway: seconds("OIDC_LEEWAY_SECS", 30)?,
            jwks_ttl: seconds("OIDC_JWKS_TTL_SECS", 300)?,
            jwks_timeout: seconds("OIDC_JWKS_TIMEOUT_SECS", 5)?,
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) => Err(ConfigError::Missing(name)),
        Err(env::VarError::NotPresent) => Err(ConfigError::Missing(name)),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid {
            name,
            reason: "value is not valid UTF-8".into(),
        }),
    }
}

fn optional(name: &'static str, default: &str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) => Ok(default.to_owned()),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid {
            name,
            reason: "value is not valid UTF-8".into(),
        }),
    }
}

fn seconds(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    let raw = optional(name, &default.to_string())?;
    let value = raw.parse::<u64>().map_err(|err| ConfigError::Invalid {
        name,
        reason: err.to_string(),
    })?;
    Ok(Duration::from_secs(value))
}
