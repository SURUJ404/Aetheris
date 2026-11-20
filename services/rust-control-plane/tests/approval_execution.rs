//! Approval-bound execution endpoint tests.
//!
//! These tests exercise the additive `POST /v1/tasks/{id}/execute` path with an
//! in-memory task store, execution store and fake sandbox runtime. They prove
//! that the approval—not the request body—is the authority for workload and
//! stdin, that the broker preflight runs before an approval is burned, and
//! that a consumed approval cannot be replayed.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::to_bytes;
use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use rust_control_plane::api;
use rust_control_plane::api::tasks::ExecuteApprovedRequest;
use rust_control_plane::auth::Principal;
use rust_control_plane::broker::Broker;
use rust_control_plane::execution::{ExecutionLimits, MemoryExecutionStore};
use rust_control_plane::persistence::ResolvedPrincipal;
use rust_control_plane::policy::POLICY_VERSION;
use rust_control_plane::principal::TenantContext;
use rust_control_plane::runtime::{
    FilesystemAccess, NetworkAccess, RuntimeCapabilities, RuntimeHealth, RuntimeRegistry,
    SandboxError, SandboxResult, SandboxRuntime, SandboxSpec, Termination, Workload,
    WorkloadRegistry,
};
use rust_control_plane::state::AppState;
use rust_control_plane::task::{canonical_approval_hash, NewApproval, NewTask, TaskStatus};

/// Fake runtime that echoes stdin and counts dispatches.
struct EchoRuntime {
    calls: AtomicUsize,
}

impl EchoRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl SandboxRuntime for EchoRuntime {
    fn kind(&self) -> rust_control_plane::execution::RuntimeKind {
        rust_control_plane::execution::RuntimeKind::Wasmtime
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            runtime: self.kind(),
            available: true,
            unavailable_reason: None,
            filesystem: FilesystemAccess::None,
            network: NetworkAccess::Disabled,
            arbitrary_python: false,
            shell: false,
            package_install: false,
            supports_cancellation: true,
            max_wall_clock_ms: 60_000,
            max_memory_bytes: 512 * 1024 * 1024,
        }
    }

    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }

    async fn execute(
        &self,
        spec: SandboxSpec,
        _cancel: CancellationToken,
    ) -> Result<SandboxResult, SandboxError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SandboxResult {
            termination: Termination::Completed,
            exit_code: Some(0),
            stdout: spec.stdin,
            stderr: Vec::new(),
            duration: Duration::from_millis(1),
            fuel_consumed: Some(1),
            memory_peak_bytes: Some(1024),
            artifacts: Vec::new(),
            failure: None,
        })
    }
}

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        wall_clock_ms: 1_000,
        cpu_fuel: 100_000,
        memory_bytes: 32 * 1024 * 1024,
        max_output_bytes: 8 * 1024,
        max_stdin_bytes: 8 * 1024,
        max_artifacts_bytes: 8 * 1024,
    }
}

fn harness() -> (AppState, Arc<MemoryExecutionStore>, Arc<EchoRuntime>) {
    let config = common::config();
    let executions = Arc::new(MemoryExecutionStore::new());
    let runtime = EchoRuntime::new();
    let runtimes: Vec<Arc<dyn SandboxRuntime>> = vec![runtime.clone()];
    let workloads = WorkloadRegistry::from_workloads([Workload {
        name: "echo".into(),
        module: Arc::new(Vec::new()),
        sha256: "test".into(),
    }]);
    let broker = Arc::new(Broker::new(
        executions.clone(),
        RuntimeRegistry::new(runtimes),
        workloads,
        config.execution.clone(),
    ));
    let principal_store = common::StubStore::shared(common::StubBehavior::Unavailable);
    let state = AppState::with_parts(config, common::verifier(), principal_store, broker);
    (state, executions, runtime)
}

fn context(tenant: &str, invoke: bool) -> TenantContext {
    let mut permissions = vec![
        "task:read".to_string(),
        "task:write".to_string(),
        "tenant:read".to_string(),
    ];
    if invoke {
        permissions.push("tool:invoke".to_string());
    }
    TenantContext {
        identity: Principal {
            subject: "user-1".into(),
            tenant_id: tenant.into(),
            issuer: common::ISSUER.into(),
            audiences: vec![common::AUDIENCE.into()],
            scopes: vec!["openid".into()],
            token_id: None,
            expires_at: u64::MAX,
        },
        resolved: ResolvedPrincipal {
            principal_id: Uuid::nil(),
            tenant_id: tenant.into(),
            role: "member".into(),
            permissions,
        },
    }
}

async fn approved_task(
    state: &AppState,
    tool: &str,
    stdin: &str,
    expires_at: DateTime<Utc>,
) -> (Uuid, Uuid) {
    let task = state
        .task_store
        .insert(NewTask {
            id: Uuid::new_v4(),
            tenant_id: common::TENANT.into(),
            principal_id: Uuid::nil(),
            title: "approved run".into(),
            input: "{}".into(),
            policy_version: POLICY_VERSION.into(),
            idempotency_key: None,
            status: TaskStatus::WaitingApproval,
        })
        .await
        .expect("insert task")
        .0;
    let (arguments_json, action_hash) =
        canonical_approval_hash(tool, &json!({"stdin": stdin})).expect("canonical hash");
    let approval = state
        .task_store
        .add_approval(NewApproval {
            id: Uuid::new_v4(),
            task_id: task.id,
            tenant_id: common::TENANT.into(),
            proposer_principal_id: Uuid::nil(),
            tool_name: tool.into(),
            arguments_json,
            action_hash,
            policy_version: POLICY_VERSION.into(),
            nonce: Uuid::new_v4(),
            expires_at,
        })
        .await
        .expect("add approval");
    state
        .task_store
        .approve(
            common::TENANT,
            task.id,
            approval.id,
            Uuid::new_v4(),
            Utc::now(),
        )
        .await
        .expect("approve");
    (task.id, approval.id)
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("response is JSON")
}

async fn dispatch(
    state: &AppState,
    task_id: Uuid,
    approval_id: Uuid,
    invoke: bool,
) -> axum::response::Response {
    api::tasks::execute_approved(
        State(state.clone()),
        context(common::TENANT, invoke),
        Path(task_id.to_string()),
        Ok(Json(ExecuteApprovedRequest {
            approval_id,
            runtime: "wasmtime".into(),
            limits: limits(),
        })),
    )
    .await
}

#[tokio::test]
async fn approved_action_dispatches_using_only_the_stored_workload_and_stdin() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "echo",
        "hello from approval",
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await;

    let response = dispatch(&state, task_id, approval_id, true).await;
    assert_eq!(response.status(), 201);
    let response = body(response).await;
    assert_eq!(response["execution"]["workload"], "echo");
    assert_eq!(response["execution"]["stdout"], "hello from approval");
    assert_eq!(response["approval"]["status"], "consumed");
    assert_eq!(response["task"]["status"], "running");

    assert_eq!(executions.len(), 1);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    let approval = state
        .task_store
        .get_approval(common::TENANT, task_id, approval_id)
        .await
        .expect("approval lookup")
        .expect("approval exists");
    assert_eq!(
        approval.status,
        rust_control_plane::task::ApprovalStatus::Consumed
    );
    let task = state
        .task_store
        .get(common::TENANT, task_id)
        .await
        .expect("task lookup")
        .expect("task exists");
    assert_eq!(task.status, TaskStatus::Running);
}

#[tokio::test]
async fn a_consumed_approval_cannot_be_replayed() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "echo",
        "once",
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await;

    assert_eq!(
        dispatch(&state, task_id, approval_id, true).await.status(),
        201
    );
    let replay = dispatch(&state, task_id, approval_id, true).await;
    assert_eq!(replay.status(), 409);
    let replay = body(replay).await;
    assert_eq!(replay["error"], "approval_conflict");

    assert_eq!(executions.len(), 1);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_expired_approval_is_not_consumed_or_dispatched() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "echo",
        "too late",
        Utc::now() + chrono::Duration::seconds(1),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let response = dispatch(&state, task_id, approval_id, true).await;
    assert_eq!(response.status(), 409);
    let response = body(response).await;
    assert_eq!(response["error"], "approval_expired");

    assert_eq!(executions.len(), 0);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let task = state
        .task_store
        .get(common::TENANT, task_id)
        .await
        .expect("task lookup")
        .expect("task exists");
    assert_eq!(task.status, TaskStatus::Ready);
}

#[tokio::test]
async fn another_tenant_cannot_execute_the_approval() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "echo",
        "secret",
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await;

    let response = api::tasks::execute_approved(
        State(state.clone()),
        context("tenant-other", true),
        Path(task_id.to_string()),
        Ok(Json(ExecuteApprovedRequest {
            approval_id,
            runtime: "wasmtime".into(),
            limits: limits(),
        })),
    )
    .await;
    assert_eq!(response.status(), 404);
    let response = body(response).await;
    assert_eq!(response["error"], "not_found");

    assert_eq!(executions.len(), 0);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let approval = state
        .task_store
        .get_approval(common::TENANT, task_id, approval_id)
        .await
        .expect("approval lookup")
        .expect("approval exists");
    assert_eq!(
        approval.status,
        rust_control_plane::task::ApprovalStatus::Approved
    );
}

#[tokio::test]
async fn a_caller_without_tool_invoke_cannot_burn_an_approval() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "echo",
        "blocked",
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await;

    let response = dispatch(&state, task_id, approval_id, false).await;
    assert_eq!(response.status(), 403);
    let response = body(response).await;
    assert_eq!(response["error"], "access_denied");

    assert_eq!(executions.len(), 0);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let approval = state
        .task_store
        .get_approval(common::TENANT, task_id, approval_id)
        .await
        .expect("approval lookup")
        .expect("approval exists");
    assert_eq!(
        approval.status,
        rust_control_plane::task::ApprovalStatus::Approved
    );
}

#[tokio::test]
async fn an_unapproved_workload_is_rejected_before_consumption() {
    let (state, executions, runtime) = harness();
    let (task_id, approval_id) = approved_task(
        &state,
        "not-approved",
        "ignored",
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await;

    let response = dispatch(&state, task_id, approval_id, true).await;
    assert_eq!(response.status(), 400);
    let response = body(response).await;
    assert_eq!(response["error"], "unknown_workload");

    assert_eq!(executions.len(), 0);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let approval = state
        .task_store
        .get_approval(common::TENANT, task_id, approval_id)
        .await
        .expect("approval lookup")
        .expect("approval exists");
    assert_eq!(
        approval.status,
        rust_control_plane::task::ApprovalStatus::Approved
    );
}

#[test]
fn execute_request_rejects_restated_or_replacement_arguments() {
    let base = json!({
        "approval_id": Uuid::new_v4().to_string(),
        "runtime": "wasmtime",
        "limits": limits(),
    });

    assert!(serde_json::from_value::<ExecuteApprovedRequest>(base.clone()).is_ok());
    for (field, value) in [
        ("arguments", json!({"stdin": "evil"})),
        ("stdin", json!("evil")),
        ("workload", json!("other")),
        ("tenant_id", json!("tenant-other")),
        ("principal_id", json!("other")),
        ("task_id", json!("other")),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        assert!(
            serde_json::from_value::<ExecuteApprovedRequest>(changed).is_err(),
            "{field} must not be accepted on the execute route"
        );
    }
}
