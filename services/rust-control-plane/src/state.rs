//! Shared application state.

use std::sync::Arc;

use crate::auth::{AuthError, JwksCache, JwtVerifier};
use crate::config::AppConfig;
use crate::persistence::PrincipalStore;

/// State handed to every handler and extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub verifier: Arc<JwtVerifier>,
    pub principal_store: Arc<dyn PrincipalStore>,
}

impl AppState {
    /// Build state from configuration, including the remote JWKS cache.
    pub fn new(
        config: AppConfig,
        principal_store: Arc<dyn PrincipalStore>,
    ) -> Result<Self, AuthError> {
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
            principal_store,
        })
    }

    /// Build state from pre-constructed parts. Used by tests and by
    /// deployments that inject keys or a store implementation.
    pub fn with_parts(
        config: AppConfig,
        verifier: JwtVerifier,
        principal_store: Arc<dyn PrincipalStore>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            verifier: Arc::new(verifier),
            principal_store,
        }
    }
}
