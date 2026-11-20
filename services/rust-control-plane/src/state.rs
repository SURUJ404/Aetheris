//! Shared application state.

use std::sync::Arc;

use crate::auth::{AuthError, JwksCache, JwtVerifier};
use crate::broker::Broker;
use crate::config::AppConfig;
use crate::execution::ExecutionStore;
use crate::persistence::PrincipalStore;
use crate::runtime::{RuntimeRegistry, WorkloadRegistry};
use crate::task::{MemoryTaskStore, TaskStore};

/// State handed to every handler and extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub verifier: Arc<JwtVerifier>,
    pub principal_store: Arc<dyn PrincipalStore>,
    pub task_store: Arc<dyn TaskStore>,
    /// The only path from a request to a sandbox.
    pub broker: Arc<Broker>,
}

impl AppState {
    /// Build state from configuration, including the remote JWKS cache and the
    /// execution broker.
    ///
    /// Durable execution state is injected separately from the principal store
    /// even though both are PostgreSQL in production: the broker must depend on
    /// the execution contract, not on the storage driver.
    pub fn new(
        config: AppConfig,
        principal_store: Arc<dyn PrincipalStore>,
        execution_store: Arc<dyn ExecutionStore>,
        task_store: Arc<dyn TaskStore>,
        runtimes: RuntimeRegistry,
        workloads: WorkloadRegistry,
    ) -> Result<Self, AuthError> {
        let identity = config.identity.clone();
        let keys = JwksCache::new(
            identity.jwks_uri.clone(),
            identity.jwks_ttl,
            identity.jwks_timeout,
        )?;
        let verifier = JwtVerifier::new(identity, keys);

        let broker = Arc::new(Broker::new(
            execution_store,
            runtimes,
            workloads,
            config.execution.clone(),
        ));

        Ok(Self {
            config: Arc::new(config),
            verifier: Arc::new(verifier),
            principal_store,
            task_store,
            broker,
        })
    }

    /// Build state from pre-constructed parts. Used by tests and by
    /// deployments that inject keys, a store implementation or a broker.
    pub fn with_parts(
        config: AppConfig,
        verifier: JwtVerifier,
        principal_store: Arc<dyn PrincipalStore>,
        broker: Arc<Broker>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            verifier: Arc::new(verifier),
            principal_store,
            task_store: Arc::new(MemoryTaskStore::new()),
            broker,
        }
    }
}
