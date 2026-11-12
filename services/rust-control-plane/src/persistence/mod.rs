//! Durable state. PostgreSQL is the source of truth for memberships, roles and
//! permission grants; Redis will only ever hold derived, disposable data.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::FromRow;
use thiserror::Error;
use uuid::Uuid;

/// A caller's authorization data for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    /// Internal principal id. Stable across sessions and providers.
    pub principal_id: Uuid,
    /// Tenant the membership applies to.
    pub tenant_id: String,
    /// Role granted by the membership.
    pub role: String,
    /// Effective permissions derived from the role.
    pub permissions: Vec<String>,
}

/// Storage failures. The `Display` output is deliberately generic: callers must
/// never receive connection strings, SQL, or row data.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("database migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

/// The authorization data source used by request handlers.
///
/// A trait so tests and future read replicas can substitute an implementation
/// without changing the extractor.
#[async_trait]
pub trait PrincipalStore: Send + Sync {
    /// Resolve an active membership for an authenticated identity.
    ///
    /// Returns `None` when the principal is unknown, the membership is
    /// suspended, or the tenant is suspended. Callers must treat `None` as a
    /// denial, not as an anonymous principal.
    async fn resolve(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: &str,
    ) -> Result<Option<ResolvedPrincipal>, StoreError>;

    /// Cheap liveness probe used by the readiness endpoint.
    async fn ping(&self) -> Result<(), StoreError>;
}

/// PostgreSQL-backed store.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connect to PostgreSQL with a bounded pool and a short acquisition
    /// timeout so a sick database fails requests quickly.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    /// Apply embedded migrations. Safe to call on every start: sqlx tracks
    /// applied versions in `_sqlx_migrations`.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Expose the pool for integration tests and future write paths.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[derive(FromRow)]
struct MembershipRow {
    principal_id: Uuid,
    tenant_id: String,
    role: String,
    permissions: Vec<String>,
}

const RESOLVE_SQL: &str = r#"
    SELECT
        p.id AS principal_id,
        m.tenant_id,
        m.role,
        COALESCE(
            ARRAY_AGG(rp.permission) FILTER (WHERE rp.permission IS NOT NULL),
            ARRAY[]::TEXT[]
        ) AS permissions
    FROM principals p
    JOIN memberships m ON m.principal_id = p.id
    JOIN tenants t ON t.id = m.tenant_id
    LEFT JOIN role_permissions rp ON rp.role = m.role
    WHERE p.issuer = $1
      AND p.subject = $2
      AND m.tenant_id = $3
      AND m.status = 'active'
      AND t.status = 'active'
    GROUP BY p.id, m.tenant_id, m.role
"#;

#[async_trait]
impl PrincipalStore for PgStore {
    async fn resolve(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: &str,
    ) -> Result<Option<ResolvedPrincipal>, StoreError> {
        let row = sqlx::query_as::<_, MembershipRow>(RESOLVE_SQL)
            .bind(issuer)
            .bind(subject)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|mut row| {
            // Aggregation has no inherent order; sort so API output and tests
            // do not depend on Postgres plan details.
            row.permissions.sort();
            ResolvedPrincipal {
                principal_id: row.principal_id,
                tenant_id: row.tenant_id,
                role: row.role,
                permissions: row.permissions,
            }
        }))
    }

    async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
