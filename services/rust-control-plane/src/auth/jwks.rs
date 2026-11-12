//! JWKS retrieval and caching.
//!
//! Signing keys are cached until the configured TTL. An unknown `kid` triggers
//! one forced refresh so key rotation does not require a restart. A failed
//! refresh never discards previously cached keys.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::auth::AuthError;

#[derive(Debug, Deserialize)]
struct JwkSet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

struct CacheState {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

/// Cached set of RSA verification keys keyed by `kid`.
pub struct JwksCache {
    uri: String,
    client: reqwest::Client,
    ttl: Duration,
    state: RwLock<CacheState>,
    refresh_lock: Mutex<()>,
    static_keys: bool,
}

impl JwksCache {
    /// Build a cache backed by a remote JWKS endpoint.
    pub fn new(
        uri: impl Into<String>,
        ttl: Duration,
        timeout: Duration,
    ) -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|err| {
                tracing::error!(error = %err, "failed to build JWKS HTTP client");
                AuthError::Internal
            })?;

        Ok(Self {
            uri: uri.into(),
            client,
            ttl,
            state: RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
            }),
            refresh_lock: Mutex::new(()),
            static_keys: false,
        })
    }

    /// Build a cache from keys that are already known.
    ///
    /// Used by tests and by deployments that inject keys out of band. The
    /// cache never performs network I/O in this mode.
    pub fn from_keys(uri: impl Into<String>, keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            uri: uri.into(),
            client: reqwest::Client::new(),
            ttl: Duration::ZERO,
            state: RwLock::new(CacheState {
                keys,
                fetched_at: Some(Instant::now()),
            }),
            refresh_lock: Mutex::new(()),
            static_keys: true,
        }
    }

    /// Resolve a signing key by `kid`.
    ///
    /// A token without `kid` is accepted only when the cache holds exactly one
    /// key; guessing among several keys would be unsound.
    pub async fn get(&self, kid: Option<&str>) -> Result<DecodingKey, AuthError> {
        if !self.static_keys && self.is_stale() {
            if let Err(err) = self.refresh().await {
                if !self.has_keys() {
                    return Err(err);
                }
                tracing::warn!(error = %err, "JWKS refresh failed; serving cached keys");
            }
        }

        if let Some(key) = self.lookup(kid) {
            return Ok(key);
        }

        if self.static_keys {
            return Err(AuthError::UnknownKeyId);
        }

        // Unknown kid usually means the provider rotated keys. Refresh once;
        // the TTL check above would not have fired for a fresh-looking cache.
        self.refresh().await?;
        self.lookup(kid).ok_or(AuthError::UnknownKeyId)
    }

    fn is_stale(&self) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match state.fetched_at {
            Some(fetched_at) => fetched_at.elapsed() >= self.ttl,
            None => true,
        }
    }

    fn has_keys(&self) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !state.keys.is_empty()
    }

    fn lookup(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match kid {
            Some(kid) => state.keys.get(kid).cloned(),
            None if state.keys.len() == 1 => state.keys.values().next().cloned(),
            None => None,
        }
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        let _guard = self.refresh_lock.lock().await;

        let response = self.client.get(&self.uri).send().await.map_err(|err| {
            tracing::warn!(error = %err, uri = %self.uri, "JWKS request failed");
            AuthError::KeysUnavailable
        })?;

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                uri = %self.uri,
                "JWKS endpoint returned a non-success status"
            );
            return Err(AuthError::KeysUnavailable);
        }

        let set: JwkSet = response.json().await.map_err(|err| {
            tracing::warn!(error = %err, uri = %self.uri, "JWKS response was not valid JSON");
            AuthError::KeysUnavailable
        })?;

        let mut keys = HashMap::new();
        for (index, jwk) in set.keys.into_iter().enumerate() {
            if jwk.kty != "RSA" {
                continue;
            }
            if jwk.key_use.as_deref().is_some_and(|usage| usage != "sig") {
                continue;
            }
            if jwk.alg.as_deref().is_some_and(|alg| alg != "RS256") {
                continue;
            }
            let (Some(modulus), Some(exponent)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
                continue;
            };

            match DecodingKey::from_rsa_components(modulus, exponent) {
                Ok(key) => {
                    let kid = jwk
                        .kid
                        .clone()
                        .unwrap_or_else(|| format!("__unnamed_{index}"));
                    keys.insert(kid, key);
                }
                Err(err) => {
                    tracing::warn!(error = %err, "ignored malformed JWK");
                }
            }
        }

        if keys.is_empty() {
            tracing::warn!(uri = %self.uri, "JWKS contained no usable RS256 signing keys");
            return Err(AuthError::KeysUnavailable);
        }

        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.keys = keys;
        state.fetched_at = Some(Instant::now());

        Ok(())
    }
}
