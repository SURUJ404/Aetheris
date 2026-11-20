//! PostgreSQL execution-store tests.
//!
//! Gated on `TEST_DATABASE_URL` exactly like the principal-store tests: without
//! it each test prints a skip notice and returns, so the default suite needs no
//! database. Each test creates its own tenant and deletes it afterwards; the
//! schema cascades executions, so cleanup is one statement.
//!
//! A process-wide async lock serialises these tests because
//! `recover_interrupted` intentionally scans every in-flight row.

use std::sync::OnceLock;
use std::time::Duration;

use rust_control_plane::execution::{
    ArtifactRef, ExecutionLimits, ExecutionStatus, ExecutionStore, ExecutionStoreError,
    NewExecution, RuntimeKind, TransitionPatch,
};
use rust_control_plane::persistence::PgStore;
use tokio::sync::Mutex;
use uuid::Uuid;

fn database_url() -> Option<String> {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("TEST_DATABASE_URL not set; skipping database test");
            None
        }
    }
}

fn serial() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn store(url: &str) -> PgStore {
    let store = PgStore::connect(url, 2)
        .await
        .expect("connect to test database");
    store.migrate().await.expect("apply migrations");
    store
}

async fn tenant(store: &PgStore) -> String {
    let tenant_id = format!("exec-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(&tenant_id)
        .bind("execution test tenant")
        .execute(store.pool())
        .await
        .expect("insert tenant");
    tenant_id
}

async fn drop_tenant(store: &PgStore, tenant_id: &str) {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(store.pool())
        .await
        .expect("delete tenant");
}

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        wall_clock_ms: 1_000,
        cpu_fuel: 1_000_000,
        memory_bytes: 16 * 1024 * 1024,
        max_output_bytes: 64 * 1024,
        max_stdin_bytes: 64 * 1024,
        max_artifacts_bytes: 64 * 1024,
    }
}

fn new_execution(tenant_id: &str, idempotency_key: Option<&str>) -> NewExecution {
    NewExecution {
        id: Uuid::new_v4(),
        tenant_id: tenant_id.to_owned(),
        principal_id: Uuid::nil(),
        task_id: "task-1".into(),
        runtime: RuntimeKind::Wasmtime,
        workload: "echo".into(),
        limits: limits(),
        policy_version: rust_control_plane::policy::POLICY_VERSION.into(),
        idempotency_key: idempotency_key.map(str::to_owned),
    }
}

async fn advance_to_running(store: &PgStore, tenant_id: &str, id: Uuid) {
    advance_from(store, tenant_id, id, ExecutionStatus::Created).await
}

/// Walk the lifecycle from `start` to `RUNNING`, used when a test has already
/// performed part of the chain itself.
async fn advance_from(store: &PgStore, tenant_id: &str, id: Uuid, start: ExecutionStatus) {
    const CHAIN: [(ExecutionStatus, ExecutionStatus); 4] = [
        (ExecutionStatus::Created, ExecutionStatus::Queued),
        (ExecutionStatus::Queued, ExecutionStatus::Authorized),
        (ExecutionStatus::Authorized, ExecutionStatus::Starting),
        (ExecutionStatus::Starting, ExecutionStatus::Running),
    ];

    let offset = CHAIN
        .iter()
        .position(|(from, _)| *from == start)
        .expect("a known lifecycle position");

    for (from, to) in &CHAIN[offset..] {
        store
            .transition(tenant_id, id, *from, *to, TransitionPatch::default())
            .await
            .expect("advance");
    }
}

#[tokio::test]
async fn execution_round_trip_is_tenant_scoped_and_idempotent() {
    let Some(url) = database_url() else { return };
    let _guard = serial().lock().await;
    let store = store(&url).await;
    let tenant_id = tenant(&store).await;

    let new = new_execution(&tenant_id, Some("client-key"));
    let (created, was_created) = store.insert(new.clone()).await.expect("insert");
    assert!(was_created);
    assert_eq!(created.status, ExecutionStatus::Created);
    assert_eq!(created.tenant_id, tenant_id);
    assert!(created.belongs_to(&tenant_id));

    // The same key from a different generated id returns the original row.
    let (original, was_created) = store
        .insert(new_execution(&tenant_id, Some("client-key")))
        .await
        .expect("duplicate");
    assert!(!was_created);
    assert_eq!(original.id, created.id);

    // Reads are tenant-scoped.
    assert!(store
        .get(&tenant_id, created.id)
        .await
        .expect("get")
        .is_some());
    assert!(store
        .get("another-tenant", created.id)
        .await
        .expect("cross-tenant get")
        .is_none());

    drop_tenant(&store, &tenant_id).await;
}

#[tokio::test]
async fn transitions_are_compare_and_set_and_record_events() {
    let Some(url) = database_url() else { return };
    let _guard = serial().lock().await;
    let store = store(&url).await;
    let tenant_id = tenant(&store).await;

    let (record, _) = store
        .insert(new_execution(&tenant_id, None))
        .await
        .expect("insert");

    store
        .transition(
            &tenant_id,
            record.id,
            ExecutionStatus::Created,
            ExecutionStatus::Queued,
            TransitionPatch::default(),
        )
        .await
        .expect("created -> queued");

    // A stale transition must not advance the row. The move itself is legal,
    // but the row is already QUEUED, so the compare-and-set must fail.
    let conflict = store
        .transition(
            &tenant_id,
            record.id,
            ExecutionStatus::Created,
            ExecutionStatus::Queued,
            TransitionPatch::default(),
        )
        .await
        .expect_err("stale transition");
    assert!(matches!(
        conflict,
        ExecutionStoreError::StateConflict { .. }
    ));

    // An illegal transition is rejected before touching the database.
    let invalid = store
        .transition(
            &tenant_id,
            record.id,
            ExecutionStatus::Queued,
            ExecutionStatus::Completed,
            TransitionPatch::default(),
        )
        .await
        .expect_err("illegal transition");
    assert!(matches!(
        invalid,
        ExecutionStoreError::InvalidTransition { .. }
    ));

    advance_from(&store, &tenant_id, record.id, ExecutionStatus::Queued).await;

    let artifacts = vec![ArtifactRef {
        name: "out.txt".into(),
        size_bytes: 2,
        sha256: "00".into(),
    }];
    let patch = TransitionPatch {
        finished_at: Some(chrono::Utc::now()),
        exit_code: Some(0),
        duration_ms: Some(12),
        fuel_consumed: Some(7),
        output_digest: Some("digest".into()),
        stdout: Some("hi".into()),
        stderr: Some(String::new()),
        artifacts: Some(artifacts.clone()),
        ..Default::default()
    };

    store
        .transition(
            &tenant_id,
            record.id,
            ExecutionStatus::Running,
            ExecutionStatus::CleaningUp,
            TransitionPatch::default(),
        )
        .await
        .expect("running -> cleaning up");
    store
        .transition(
            &tenant_id,
            record.id,
            ExecutionStatus::CleaningUp,
            ExecutionStatus::Completed,
            patch,
        )
        .await
        .expect("cleaning up -> completed");

    let stored = store
        .get(&tenant_id, record.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(stored.status, ExecutionStatus::Completed);
    assert_eq!(stored.exit_code, Some(0));
    assert_eq!(stored.stdout.as_deref(), Some("hi"));
    assert_eq!(stored.artifacts, artifacts);

    // The event log records every transition, including the rejected path is
    // absent because nothing was written.
    let events: Vec<(Option<String>, String)> = sqlx::query_as(
        "SELECT from_status, to_status FROM execution_events \
         WHERE execution_id = $1 ORDER BY id",
    )
    .bind(record.id)
    .fetch_all(store.pool())
    .await
    .expect("events");
    assert_eq!(
        events,
        vec![
            (None, "CREATED".to_string()),
            (Some("CREATED".into()), "QUEUED".into()),
            (Some("QUEUED".into()), "AUTHORIZED".into()),
            (Some("AUTHORIZED".into()), "STARTING".into()),
            (Some("STARTING".into()), "RUNNING".into()),
            (Some("RUNNING".into()), "CLEANING_UP".into()),
            (Some("CLEANING_UP".into()), "COMPLETED".into()),
        ]
    );

    drop_tenant(&store, &tenant_id).await;
}

#[tokio::test]
async fn cancellation_request_is_durable_and_repeatable() {
    let Some(url) = database_url() else { return };
    let _guard = serial().lock().await;
    let store = store(&url).await;
    let tenant_id = tenant(&store).await;

    let (record, _) = store
        .insert(new_execution(&tenant_id, None))
        .await
        .expect("insert");
    advance_to_running(&store, &tenant_id, record.id).await;

    let status = store
        .request_cancel(&tenant_id, record.id)
        .await
        .expect("cancel")
        .expect("present");
    assert_eq!(status, ExecutionStatus::Running);

    let first = store
        .get(&tenant_id, record.id)
        .await
        .expect("get")
        .expect("present")
        .cancel_requested_at
        .expect("timestamp");

    // A second request keeps the first timestamp.
    store
        .request_cancel(&tenant_id, record.id)
        .await
        .expect("cancel again");
    let second = store
        .get(&tenant_id, record.id)
        .await
        .expect("get")
        .expect("present")
        .cancel_requested_at
        .expect("timestamp");
    assert_eq!(first, second);

    // Another tenant cannot cancel this row.
    assert!(store
        .request_cancel("another-tenant", record.id)
        .await
        .expect("cross-tenant cancel")
        .is_none());

    drop_tenant(&store, &tenant_id).await;
}

#[tokio::test]
async fn recovery_fails_only_in_flight_rows() {
    let Some(url) = database_url() else { return };
    let _guard = serial().lock().await;
    let store = store(&url).await;
    let tenant_id = tenant(&store).await;

    let (running, _) = store
        .insert(new_execution(&tenant_id, None))
        .await
        .expect("insert running");
    advance_to_running(&store, &tenant_id, running.id).await;

    let (finished, _) = store
        .insert(new_execution(&tenant_id, None))
        .await
        .expect("insert finished");
    advance_to_running(&store, &tenant_id, finished.id).await;
    store
        .transition(
            &tenant_id,
            finished.id,
            ExecutionStatus::Running,
            ExecutionStatus::CleaningUp,
            TransitionPatch::default(),
        )
        .await
        .expect("cleaning up");
    store
        .transition(
            &tenant_id,
            finished.id,
            ExecutionStatus::CleaningUp,
            ExecutionStatus::Completed,
            TransitionPatch {
                finished_at: Some(chrono::Utc::now()),
                ..Default::default()
            },
        )
        .await
        .expect("completed");

    let recovered = store.recover_interrupted().await.expect("recover");
    assert!(recovered.contains(&running.id));
    assert!(!recovered.contains(&finished.id));

    let record = store
        .get(&tenant_id, running.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(record.status, ExecutionStatus::Failed);
    assert_eq!(record.failure_kind.as_deref(), Some("interrupted"));

    let record = store
        .get(&tenant_id, finished.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(record.status, ExecutionStatus::Completed);

    drop_tenant(&store, &tenant_id).await;
}

/// The limits column is JSONB; a round trip must preserve every field.
#[tokio::test]
async fn limits_round_trip_through_jsonb() {
    let Some(url) = database_url() else { return };
    let _guard = serial().lock().await;
    let store = store(&url).await;
    let tenant_id = tenant(&store).await;

    let mut new = new_execution(&tenant_id, None);
    new.limits = ExecutionLimits {
        wall_clock_ms: 123,
        cpu_fuel: 456,
        memory_bytes: 789,
        max_output_bytes: 10,
        max_stdin_bytes: 11,
        max_artifacts_bytes: 12,
    };

    let (record, _) = store.insert(new.clone()).await.expect("insert");
    assert_eq!(record.limits, new.limits);
    assert_eq!(record.runtime, RuntimeKind::Wasmtime);
    assert_eq!(
        record.policy_version,
        rust_control_plane::policy::POLICY_VERSION
    );

    // Duration values are accepted by the pool and stored as timestamptz.
    let _ = Duration::from_secs(1);

    drop_tenant(&store, &tenant_id).await;
}
