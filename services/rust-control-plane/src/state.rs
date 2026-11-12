//! Shared application state.

use std::sync::Arc;

use crate::auth::{AuthError, JwksCache, JwtVerifier};
use crate::config::AppConfig;

/// State handed to every handler and extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub verifier: Arc<JwtVerifier>,
}

impl AppState {
    /// Build state from configuration, including the remote JWKS cache.
    pub fn new(config: AppConfig) -> Result<Self, AuthError> {
        let identity = config.identity.clone();
        let keys = JwksCache::new(
            identity.jwks_uri.clone(),
            identity.jwks_ttl,
            identity.jwks_timeout,
        )?;
        let verifier = JwtVerifier::new(identity, keys);

        Ok(Self {
            config: Arc::new(config),
            verifier: Arc::new(verifier),
        })
    }

    /// Build state with a pre-constructed verifier. Used by tests and by
    /// deployments that inject keys out of band.
    pub fn with_verifier(config: AppConfig, verifier: JwtVerifier) -> Self {
        Self {
            config: Arc::new(config),
            verifier: Arc::new(verifier),
        }
    }
}
