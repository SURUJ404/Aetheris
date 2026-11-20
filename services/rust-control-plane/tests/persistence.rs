//! PostgreSQL-backed resolution tests.
//!
//! Gated on `TEST_DATABASE_URL`: without it the tests print a skip notice and
//! return, so the default suite needs no database. CI or a local run sets it to
//! a disposable database (see `compose.yaml` for the development instance).
//!
//! Each test inserts its own tenant and principal and cleans up afterwards, so
//! runs do not depend on ordering.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use rust_control_plane::persistence::{PgStore, PrincipalStore};
use rust_control_plane::policy::{Action, Permission, POLICY_VERSION};
use rust_control_plane::task::{
    canonical_approval_hash, ApprovalStatus, NewApproval, NewTask, TaskStatus, TaskStore,
};

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

#[tokio::test]
async fn seeded_grants_cover_the_policy_vocabulary() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;

    // The owner role is the completeness guard: if a permission is added in
    // code but not seeded, this fails instead of silently denying every caller.
    let owner: Vec<String> =
        sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role = 'owner'")
            .fetch_all(store.pool())
            .await
            .expect("query owner grants");

    for action in Action::ALL {
        let permission = action.required_permission().as_str();
        assert!(
            owner.iter().any(|granted| granted == permission),
            "owner role does not grant {permission}"
        );
    }

    // Every declared permission must be granted by at least one role, otherwise
    // no principal can ever perform the corresponding action.
    for permission in Permission::ALL {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM role_permissions WHERE permission = $1")
                .bind(permission.as_str())
                .fetch_one(store.pool())
                .await
                .expect("count grants");
        assert!(count > 0, "permission {permission} is not granted");
    }

    // The member role is the least-privilege guard for approval rights.
    let member: Vec<String> =
        sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role = 'member'")
            .fetch_all(store.pool())
            .await
            .expect("query member grants");
    assert!(!member.iter().any(|granted| granted == "tool:approve"));
    assert!(!member.iter().any(|granted| granted == "member:manage"));
}

#[tokio::test]
async fn approval_lookup_and_single_use_consumption_are_tenant_scoped() {
    let Some(url) = database_url() else {
        return;
    };
    let store = store(&url).await;
    let fixture = fixture(&store, "member").await;
    let task_id = Uuid::new_v4();

    store
        .insert(NewTask {
            id: task_id,
            tenant_id: fixture.tenant_id.clone(),
            principal_id: fixture.principal_id,
            title: "approved run".into(),
            input: "{}".into(),
            policy_version: POLICY_VERSION.into(),
            idempotency_key: None,
            status: TaskStatus::WaitingApproval,
        })
        .await
        .expect("insert task");
    let (arguments_json, action_hash) =
        canonical_approval_hash("echo", &json!({"stdin": "hello"})).expect("canonical hash");
    let approval = store
        .add_approval(NewApproval {
            id: Uuid::new_v4(),
            task_id,
            tenant_id: fixture.tenant_id.clone(),
            proposer_principal_id: fixture.principal_id,
            tool_name: "echo".into(),
            arguments_json,
            action_hash,
            policy_version: POLICY_VERSION.into(),
            nonce: Uuid::new_v4(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .expect("add approval");
    store
        .approve(
            &fixture.tenant_id,
            task_id,
            approval.id,
            Uuid::new_v4(),
            Utc::now(),
        )
        .await
        .expect("approve");

    assert!(store
        .get_approval(&fixture.tenant_id, task_id, approval.id)
        .await
        .expect("own approval lookup")
        .is_some());
    assert!(store
        .get_approval("tenant-somewhere-else", task_id, approval.id)
        .await
        .expect("cross-tenant approval lookup")
        .is_none());

    let (consumed, running) = store
        .consume_approval(
            &fixture.tenant_id,
            task_id,
            approval.id,
            Uuid::new_v4(),
            Utc::now(),
        )
        .await
        .expect("consume approval");
    assert_eq!(consumed.status, ApprovalStatus::Consumed);
    assert_eq!(running.status, TaskStatus::Running);

    assert!(matches!(
        store
            .consume_approval(
                &fixture.tenant_id,
                task_id,
                approval.id,
                Uuid::new_v4(),
                Utc::now(),
            )
            .await,
        Err(rust_control_plane::task::TaskStoreError::ApprovalConsumed)
    ));

    cleanup(&store, &fixture).await;
}
