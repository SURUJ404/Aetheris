//! Shared fixtures for integration tests: a throwaway RSA key pair, token
//! builders, and an in-memory [`PrincipalStore`].
//!
//! Included via `mod common;` from each test crate. Items are not all used by
//! every test crate, so dead-code warnings are suppressed here.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::{json, Value};

use rust_control_plane::auth::{JwksCache, JwtVerifier};
use rust_control_plane::broker::Broker;
use rust_control_plane::config::{
    AppConfig, AppEnvironment, DatabaseConfig, ExecutionConfig, IdentityConfig,
};
use rust_control_plane::execution::MemoryExecutionStore;
use rust_control_plane::persistence::{PrincipalStore, ResolvedPrincipal, StoreError};
use rust_control_plane::runtime::{RuntimeRegistry, WorkloadRegistry};
use rust_control_plane::state::AppState;

pub const KID: &str = "test-key-1";
pub const ISSUER: &str = "https://issuer.test/realms/agentic";
pub const AUDIENCE: &str = "rust-control-plane";
pub const TENANT: &str = "tenant-acme";

// Test-only key. Never valid for any deployed environment.
const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCs5rBy05i7KLj6
T1YT+OfJY0svRhKwqtuxLmX929DcD4U/2am7hH9mCBcFymydGs96PlaQCt6XuFYs
8Rxqy0fxRA8FpBSeUTMDMw7ZjnfzJ71X2ezCIJISk0qmEKEGmitlO/83cwbP6Xhr
ruhug8yfo1XbsKBHUCmZY/dm4WtY2QiUWFIn3ZfmhCAxt5XbeMa/UyKfJQ6Ghn4m
Joj8tdmeQpGHlJO6nIxxl7vZiR2v6gR2U86LrCc377rIio1EWBlnTz7ab+YyX2M1
xi9s9KzkYEfeHUcSBGsi0ahKyJ8rUmLNtnm5pma5v6u/lrMbgdpuWdNp3cjxATYk
1gTgynuPAgMBAAECggEAM8gdJS6Y6ciO6axUB8Q+StKZhE10sINjK2PNeONZ4GYn
jpFWI4pRi1G1726J691JMP+1dgtDUeYLrQcC7zr1T10GMLbM1ANWh0lF08M2ylRn
AQYLwbH2fWiubSDC0RLgF0AKNeWVrzPpdDqccui3IkJNJu/1eJYZ9034nM+7Eg7i
1SSx9yeYt5HHzZcNxzQ5QzTTFACHSthMP1gJ+sFZyZlygvySmLez4p6ENmt8CqIM
OPKE1NJroyfqvUoWESXrVjks7kjgtzum6BcOmx/AaGmCV04D/2QL0o04QDLMFpT4
WoJpXB2dAOBa8Empvww8y0JjbTf51Q7LqQ5pP7MeTQKBgQDvHFOkwDVDPWX/pU01
/k31WYjTuo6nP6NIjL7UMiWe5uS1dElzZWXmI406M/CDv8w0fzkb7M72xHg55658
gXHbbVAojx9Ekt3+D4qaUtd5FCgzpHPFNzb5pW/PM533Gp/uAedBtYNOhmZjmTIC
nfEhgP7leowYZHK2OvghwqbgtQKBgQC5HSQuXmjH3dmqn2G95L7DqGY7jXJDoC9L
SAAfIgZieMVE4Em6yIxTxy9chWCkItApx2WKef0HDu5lx2vzS1dyx2pyqiplYFjI
vfEmgjl8TcV2BFneplmN3QaC0Aem7pvQhvwo8CzctJYfevMDa9IVIK09q95vZ91/
cH0FGYEJswKBgQDN9PZPGIhITKCI3VduRIfd56slxLGPeg8pNKJCoJcrEfK6IVoL
HbHx03mYQpjOwuwf493LIeT7RSvRpK/06oKp4LSE2xKxvFeeuMBIQUb8MdKW+PYH
T5H44vk13l4YNETBe744KSLbBoU3EQO0oVrL4xKrky0M7aipMo38dm/LaQKBgC3u
4zl2R73AePBzmAdMqWFXefaxBHdvWgzuEsmm4bqxiRGsLd9hQCDRvhjRJ8fSs6CK
T9HqrzR/KfyrXUgDm/FpNiq5usdo/t7g8uPBUI5dpe/A6KPs1y/ydlkjUaLEdnlp
5UwrPJaPYOjy0zY4HOsNLq+s5Ab02Ot0eDE5wOEtAoGBAMXlaCUFC9SFFkq26dxM
uKFp0Y11G9b8LPf+CJuB9nnnfV9vPUVHzvbg58uehLAi160ZOLjQu1oujBI/iNg9
a+kPM7N7faIFDHfjOsL2rLeXYrELLwZIO6vou7Jq/DbPSpWWPKUf36VTFbzv3KqN
MxSxtVL2Mg24RK8dMtz/bEuk
-----END PRIVATE KEY-----
"#;

const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOawctOYuyi4+k9WE/jn
yWNLL0YSsKrbsS5l/dvQ3A+FP9mpu4R/ZggXBcpsnRrPej5WkArel7hWLPEcastH
8UQPBaQUnlEzAzMO2Y538ye9V9nswiCSEpNKphChBporZTv/N3MGz+l4a67oboPM
n6NV27CgR1ApmWP3ZuFrWNkIlFhSJ92X5oQgMbeV23jGv1MinyUOhoZ+JiaI/LXZ
nkKRh5STupyMcZe72Ykdr+oEdlPOi6wnN++6yIqNRFgZZ08+2m/mMl9jNcYvbPSs
5GBH3h1HEgRrItGoSsifK1JizbZ5uaZmub+rv5azG4HablnTad3I8QE2JNYE4Mp7
jwIDAQAB
-----END PUBLIC KEY-----
"#;

pub fn identity() -> IdentityConfig {
    IdentityConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: "https://issuer.test/jwks".into(),
        tenant_claim: "tenant_id".into(),
        leeway: Duration::from_secs(30),
        jwks_ttl: Duration::from_secs(300),
        jwks_timeout: Duration::from_secs(5),
    }
}

pub fn verifier() -> JwtVerifier {
    let mut keys = HashMap::new();
    let key = DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).expect("test public key");
    keys.insert(KID.to_string(), key);

    JwtVerifier::new(
        identity(),
        JwksCache::from_keys("https://issuer.test/jwks", keys),
    )
}

pub fn config() -> AppConfig {
    AppConfig {
        environment: AppEnvironment::Development,
        bind_addr: "127.0.0.1:0".parse().expect("socket address"),
        task_grpc_addr: "127.0.0.1:0".parse().expect("socket address"),
        identity: identity(),
        database: DatabaseConfig {
            // Tests never open this connection; the stub store replaces it.
            url: "postgresql://unused/unused".into(),
            max_connections: 1,
            migrate_on_start: false,
        },
        execution: ExecutionConfig::default(),
    }
}

/// A broker backed by an in-memory execution store and no runtimes. Handler
/// tests that do not touch `/v1/executions` still need a broker in state.
pub fn test_broker(config: &AppConfig) -> Arc<Broker> {
    Arc::new(Broker::new(
        Arc::new(MemoryExecutionStore::new()),
        RuntimeRegistry::default(),
        WorkloadRegistry::default(),
        config.execution.clone(),
    ))
}

pub fn state_with_store(store: Arc<dyn PrincipalStore>) -> AppState {
    let config = config();
    let broker = test_broker(&config);
    AppState::with_parts(config, verifier(), store, broker)
}

pub fn state() -> AppState {
    state_with_store(Arc::new(StubStore::unavailable()))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

pub fn claims() -> Value {
    json!({
        "sub": "user-1",
        "iss": ISSUER,
        "aud": [AUDIENCE, "account"],
        "exp": now() + 300,
        "iat": now(),
        "jti": "token-1",
        "scope": "openid profile",
        "tenant_id": TENANT,
    })
}

pub fn sign(claims: &Value) -> String {
    sign_with_kid(claims, KID)
}

pub fn sign_with_kid(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).expect("test private key");
    encode(&header, claims, &key).expect("sign token")
}

/// A principal holding the permissions granted to the `member` role.
pub fn member() -> ResolvedPrincipal {
    ResolvedPrincipal {
        principal_id: uuid::Uuid::nil(),
        tenant_id: TENANT.into(),
        role: "member".into(),
        permissions: vec![
            "task:read".into(),
            "task:write".into(),
            "tenant:read".into(),
            "tool:invoke".into(),
        ],
    }
}

/// Behaviour the stub store returns.
pub enum StubBehavior {
    Member(ResolvedPrincipal),
    NoMembership,
    Unavailable,
}

/// In-memory [`PrincipalStore`] for extractor and handler tests.
pub struct StubStore {
    behavior: StubBehavior,
}

impl StubStore {
    pub fn member(principal: ResolvedPrincipal) -> Self {
        Self {
            behavior: StubBehavior::Member(principal),
        }
    }

    pub fn no_membership() -> Self {
        Self {
            behavior: StubBehavior::NoMembership,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            behavior: StubBehavior::Unavailable,
        }
    }

    pub fn shared(behavior: StubBehavior) -> Arc<dyn PrincipalStore> {
        Arc::new(Self { behavior })
    }
}

#[async_trait]
impl PrincipalStore for StubStore {
    async fn resolve(
        &self,
        _issuer: &str,
        _subject: &str,
        _tenant_id: &str,
    ) -> Result<Option<ResolvedPrincipal>, StoreError> {
        match &self.behavior {
            StubBehavior::Member(principal) => Ok(Some(principal.clone())),
            StubBehavior::NoMembership => Ok(None),
            StubBehavior::Unavailable => Err(StoreError::Database(sqlx::Error::PoolTimedOut)),
        }
    }

    async fn ping(&self) -> Result<(), StoreError> {
        match &self.behavior {
            StubBehavior::Unavailable => Err(StoreError::Database(sqlx::Error::PoolTimedOut)),
            _ => Ok(()),
        }
    }
}
