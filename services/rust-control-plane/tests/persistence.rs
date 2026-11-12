//! PostgreSQL-backed resolution tests.
//!
//! Gated on `TEST_DATABASE_URL`: without it the tests print a skip notice and
//! return, so the default suite needs no database. CI or a local run sets it to
//! a disposable database (see `compose.yaml` for the development instance).
//!
//! Each test inserts its own tenant and principal and cleans up afterwards, so
//! runs do not depend on ordering.

use uuid::Uuid;

use rust_control_plane::persistence::{PgStore, PrincipalStore};

fn database_url() -> Option<String> {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("TEST_DATABASE_URL not set; skipping database test");
            None
        }
    }
}

async fn store(url: &str) -> PgStore {
    let store = PgStore::connect(url, 2)
        .await
        .expect("connect to test database");
    store.migrate().await.expect("apply migrations");
    store
}

struct Fixture {
    tenant_id: String,
    subject: String,
    principal_id: Uuid,
}

async fn fixture(store: &PgStore, role: &str) -> Fixture {
    let fixture = Fixture {
        tenant_id: format!("tenant-test-{}", Uuid::new_v4()),
        subject: format!("subject-test-{}", Uuid::new_v4()),
        principal_id: Uuid::new_v4(),
    };

    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(&fixture.tenant_id)
        .bind(format!("{} display name", fixture.tenant_id))
        .execute(store.pool())
        .await
        .expect("insert tenant");

    sqlx::query("INSERT INTO principals (id, issuer, subject) VALUES ($1, $2, $3)")
        .bind(fixture.principal_id)
        .bind("https://issuer.test/realms/agentic")
        .bind(&fixture.subject)
        .execute(store.pool())
        .await
        .expect("insert principal");

    sqlx::query("INSERT INTO memberships (tenant_id, principal_id, role) VALUES ($1, $2, $3)")
        .bind(&fixture.tenant_id)
        .bind(fixture.principal_id)
        .bind(role)
        .execute(store.pool())
        .await
        .expect("insert membership");

    fixture
}

async fn cleanup(store: &PgStore, fixture: &Fixture) {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&fixture.tenant_id)
        .execute(store.pool())
        .await
        .expect("delete tenant");
    sqlx::query("DELETE FROM principals WHERE id = $1")
        .bind(fixture.principal_id)
        .execute(store.pool())
        .await
        .expect("delete principal");
}

const ISSUER: &str = "https://issuer.test/realms/agentic";

#[tokio::test]
async fn active_membership_resolves_role_and_permissions() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    let fixture = fixture(&store, "member").await;

    let resolved = store
        .resolve(ISSUER, &fixture.subject, &fixture.tenant_id)
        .await
        .expect("query")
        .expect("resolved");

    assert_eq!(resolved.principal_id, fixture.principal_id);
    assert_eq!(resolved.tenant_id, fixture.tenant_id);
    assert_eq!(resolved.role, "member");
    assert_eq!(
        resolved.permissions,
        vec!["task:read", "task:write", "tenant:read", "tool:invoke"]
    );

    cleanup(&store, &fixture).await;
}

#[tokio::test]
async fn unknown_principal_does_not_resolve() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;

    let resolved = store
        .resolve(ISSUER, "nobody", "tenant-acme")
        .await
        .expect("query");
    assert!(resolved.is_none());
}

#[tokio::test]
async fn suspended_membership_does_not_resolve() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    let fixture = fixture(&store, "member").await;

    sqlx::query(
        "UPDATE memberships SET status = 'suspended' WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&fixture.tenant_id)
    .bind(fixture.principal_id)
    .execute(store.pool())
    .await
    .expect("suspend membership");

    let resolved = store
        .resolve(ISSUER, &fixture.subject, &fixture.tenant_id)
        .await
        .expect("query");
    assert!(resolved.is_none());

    cleanup(&store, &fixture).await;
}

#[tokio::test]
async fn suspended_tenant_does_not_resolve() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    let fixture = fixture(&store, "owner").await;

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(&fixture.tenant_id)
        .execute(store.pool())
        .await
        .expect("suspend tenant");

    let resolved = store
        .resolve(ISSUER, &fixture.subject, &fixture.tenant_id)
        .await
        .expect("query");
    assert!(resolved.is_none());

    cleanup(&store, &fixture).await;
}

#[tokio::test]
async fn membership_in_a_different_tenant_does_not_resolve() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    let fixture = fixture(&store, "member").await;

    let resolved = store
        .resolve(ISSUER, &fixture.subject, "tenant-somewhere-else")
        .await
        .expect("query");
    assert!(resolved.is_none());

    cleanup(&store, &fixture).await;
}

#[tokio::test]
async fn ping_reports_a_live_database() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    store.ping().await.expect("ping");
}
