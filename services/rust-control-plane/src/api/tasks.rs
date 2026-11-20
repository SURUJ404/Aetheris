//! Tenant-scoped durable task lifecycle endpoints.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::executions::{broker_error, ExecutionView};
use crate::broker::ExecutionRequest;
use crate::execution::{ExecutionLimits, RuntimeKind};
use crate::policy::POLICY_VERSION;
use crate::principal::TenantContext;
use crate::state::AppState;
use crate::task::{
    approved_stdin, canonical_approval_hash, ApprovalRecord, ApprovalStatus, NewApproval, NewTask,
    TaskRecord, TaskStatus, TaskStoreError,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTaskRequest {
    pub title: String,
    pub input: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub approval: Option<ApprovalRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default = "default_approval_ttl")]
    pub expires_in_seconds: i64,
}

fn default_approval_ttl() -> i64 {
    900
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub approval_id: Uuid,
}

/// Body of `POST /v1/tasks/{id}/execute`.
///
/// The approved action is never restated here: workload and stdin come from the
/// stored approval. Unknown fields are rejected so a caller cannot smuggle a
/// replacement `workload`, `stdin`, `arguments` or identity through this route.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteApprovedRequest {
    pub approval_id: Uuid,
    #[serde(default = "default_runtime")]
    pub runtime: String,
    pub limits: ExecutionLimits,
}

fn default_runtime() -> String {
    RuntimeKind::Wasmtime.as_str().into()
}

#[derive(Debug, Serialize)]
pub struct TaskView {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub title: String,
    pub input: String,
    pub status: TaskStatus,
    pub policy_version: String,
    pub idempotency_key: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub finished_at: Option<chrono::DateTime<Utc>>,
    pub failure: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApprovalView {
    pub id: Uuid,
    pub task_id: Uuid,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub action_hash: String,
    pub status: ApprovalStatus,
    pub expires_at: chrono::DateTime<Utc>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<chrono::DateTime<Utc>>,
}

impl From<&TaskRecord> for TaskView {
    fn from(task: &TaskRecord) -> Self {
        Self {
            id: task.id,
            tenant_id: task.tenant_id.clone(),
            principal_id: task.principal_id,
            title: task.title.clone(),
            input: task.input.clone(),
            status: task.status,
            policy_version: task.policy_version.clone(),
            idempotency_key: task.idempotency_key.clone(),
            created_at: task.created_at,
            updated_at: task.updated_at,
            finished_at: task.finished_at,
            failure: task.failure.clone(),
        }
    }
}

impl TryFrom<&ApprovalRecord> for ApprovalView {
    type Error = serde_json::Error;

    fn try_from(approval: &ApprovalRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: approval.id,
            task_id: approval.task_id,
            tool_name: approval.tool_name.clone(),
            arguments: serde_json::from_str(&approval.arguments_json)?,
            action_hash: approval.action_hash.clone(),
            status: approval.status,
            expires_at: approval.expires_at,
            approved_by: approval.approved_by,
            approved_at: approval.approved_at,
        })
    }
}

pub async fn create(
    State(state): State<AppState>,
    context: TenantContext,
    request: Result<Json<CreateTaskRequest>, JsonRejection>,
) -> Response {
    if !context.has_permission("task:write") {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Json(request) = match request {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if request.title.trim().is_empty()
        || request.title.len() > 256
        || request.input.len() > 1_048_576
    {
        return error(StatusCode::BAD_REQUEST, "invalid_task");
    }

    let (status, approval) = match request.approval {
        Some(approval) => {
            if !(1..=86_400).contains(&approval.expires_in_seconds) {
                return error(StatusCode::BAD_REQUEST, "invalid_approval_expiry");
            }
            let (arguments_json, action_hash) =
                match canonical_approval_hash(&approval.tool_name, &approval.arguments) {
                    Ok(value) => value,
                    Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_approval"),
                };
            (
                TaskStatus::WaitingApproval,
                Some((approval, arguments_json, action_hash)),
            )
        }
        None => (TaskStatus::Ready, None),
    };

    let task_id = Uuid::new_v4();
    let (task, created) = match state
        .task_store
        .insert(NewTask {
            id: task_id,
            tenant_id: context.resolved.tenant_id.clone(),
            principal_id: context.resolved.principal_id,
            title: request.title,
            input: request.input,
            policy_version: POLICY_VERSION.into(),
            idempotency_key: request.idempotency_key,
            status,
        })
        .await
    {
        Ok(result) => result,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };

    let approval_view = if created {
        match approval {
            Some((approval, arguments_json, action_hash)) => {
                let record = match state
                    .task_store
                    .add_approval(NewApproval {
                        id: Uuid::new_v4(),
                        task_id: task.id,
                        tenant_id: context.resolved.tenant_id.clone(),
                        proposer_principal_id: context.resolved.principal_id,
                        tool_name: approval.tool_name,
                        arguments_json,
                        action_hash,
                        policy_version: POLICY_VERSION.into(),
                        nonce: Uuid::new_v4(),
                        expires_at: Utc::now() + Duration::seconds(approval.expires_in_seconds),
                    })
                    .await
                {
                    Ok(record) => record,
                    Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
                };
                match ApprovalView::try_from(&record) {
                    Ok(view) => Some(view),
                    Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
                }
            }
            None => None,
        }
    } else {
        None
    };

    (
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({ "task": TaskView::from(&task), "approval": approval_view })),
    )
        .into_response()
}

pub async fn get(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
) -> Response {
    if !context.has_permission("task:read") {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Ok(id) = Uuid::parse_str(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_task_id");
    };
    match state.task_store.get(&context.resolved.tenant_id, id).await {
        Ok(Some(task)) => Json(TaskView::from(&task)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

pub async fn cancel(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
) -> Response {
    if !context.has_permission("task:write") {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Ok(id) = Uuid::parse_str(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_task_id");
    };
    let task = match state.task_store.get(&context.resolved.tenant_id, id).await {
        Ok(Some(task)) => task,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    match state
        .task_store
        .transition(
            &context.resolved.tenant_id,
            id,
            task.status,
            TaskStatus::Cancelled,
            None,
        )
        .await
    {
        Ok(task) => Json(TaskView::from(&task)).into_response(),
        Err(TaskStoreError::StateConflict) => error(StatusCode::CONFLICT, "state_conflict"),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

pub async fn approve(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
    request: Result<Json<ApproveRequest>, JsonRejection>,
) -> Response {
    if !context.has_permission("tool:approve") {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Ok(task_id) = Uuid::parse_str(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_task_id");
    };
    let Json(request) = match request {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    match state
        .task_store
        .approve(
            &context.resolved.tenant_id,
            task_id,
            request.approval_id,
            context.resolved.principal_id,
            Utc::now(),
        )
        .await
    {
        Ok((approval, task)) => match ApprovalView::try_from(&approval) {
            Ok(approval) => Json(json!({
                "task": TaskView::from(&task),
                "approval": approval,
            }))
            .into_response(),
            Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        },
        Err(TaskStoreError::SelfApproval) => error(StatusCode::FORBIDDEN, "self_approval"),
        Err(TaskStoreError::ApprovalExpired) => error(StatusCode::CONFLICT, "approval_expired"),
        Err(TaskStoreError::ApprovalConflict | TaskStoreError::StateConflict) => {
            error(StatusCode::CONFLICT, "approval_conflict")
        }
        Err(TaskStoreError::NotFound) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

/// Dispatch one approved action through the broker.
///
/// The approval is the authority for workload and stdin. The broker preflight
/// proves the resulting request would be accepted before the approval is
/// burned; consumption is then atomic and single-use. If dispatch fails after
/// consumption, the task is failed rather than left RUNNING with no execution.
pub async fn execute_approved(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
    request: Result<Json<ExecuteApprovedRequest>, JsonRejection>,
) -> Response {
    if !context.has_permission("tool:invoke") {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Ok(task_id) = Uuid::parse_str(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_task_id");
    };
    let Json(request) = match request {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let Some(runtime) = RuntimeKind::parse(&request.runtime) else {
        return error(StatusCode::BAD_REQUEST, "unsupported_runtime");
    };

    let tenant = &context.resolved.tenant_id;
    let task = match state.task_store.get(tenant, task_id).await {
        Ok(Some(task)) => task,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let approval = match state
        .task_store
        .get_approval(tenant, task_id, request.approval_id)
        .await
    {
        Ok(Some(approval)) => approval,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    // Approval state is checked before task state so a replay is always
    // identified as a consumed approval, even though the first dispatch has
    // already moved the task to RUNNING.
    if approval.status != ApprovalStatus::Approved {
        return error(StatusCode::CONFLICT, "approval_conflict");
    }
    if approval.expires_at <= Utc::now() {
        return error(StatusCode::CONFLICT, "approval_expired");
    }
    if task.status != TaskStatus::Ready {
        return error(StatusCode::CONFLICT, "task_not_ready");
    }
    if !approval_action_is_intact(&approval) {
        tracing::error!(approval_id = %approval.id, "stored approval action failed its hash check");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    if approval.policy_version != task.policy_version {
        return error(StatusCode::CONFLICT, "policy_drift");
    }

    let stdin = match approved_stdin(&approval.arguments_json) {
        Ok(stdin) => stdin,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let proposal = ExecutionRequest {
        task_id: task.id.to_string(),
        runtime,
        workload: approval.tool_name.clone(),
        stdin: stdin.into_bytes(),
        limits: request.limits,
        // The approval itself is the retry key. Consumption below still makes
        // a second dispatch impossible.
        idempotency_key: Some(approval.id.to_string()),
    };

    if let Err(err) = state.broker.validate_request(&context, &proposal) {
        return broker_error(err);
    }

    let (_, running) = match state
        .task_store
        .consume_approval(
            tenant,
            task_id,
            approval.id,
            context.resolved.principal_id,
            Utc::now(),
        )
        .await
    {
        Ok(result) => result,
        Err(TaskStoreError::NotFound) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(
            TaskStoreError::ApprovalConsumed
            | TaskStoreError::ApprovalConflict
            | TaskStoreError::ApprovalExpired
            | TaskStoreError::PolicyDrift
            | TaskStoreError::StateConflict,
        ) => return error(StatusCode::CONFLICT, "approval_conflict"),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };

    let record = match state.broker.submit(&context, proposal).await {
        Ok(record) => record,
        Err(err) => {
            if let Err(transition_error) = state
                .task_store
                .transition(
                    tenant,
                    task_id,
                    TaskStatus::Running,
                    TaskStatus::Failed,
                    Some("execution submission failed after approval was consumed".into()),
                )
                .await
            {
                tracing::error!(
                    task_id = %task_id,
                    error = %transition_error,
                    "could not fail a task whose approved dispatch failed"
                );
            }
            return broker_error(err);
        }
    };

    let approval_view = match ApprovalView::try_from(&approval) {
        Ok(mut view) => {
            view.status = ApprovalStatus::Consumed;
            view
        }
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "task": TaskView::from(&running),
            "approval": approval_view,
            "execution": ExecutionView::from(&record),
        })),
    )
        .into_response()
}

fn approval_action_is_intact(approval: &ApprovalRecord) -> bool {
    let Ok(arguments) = serde_json::from_str(&approval.arguments_json) else {
        return false;
    };
    match canonical_approval_hash(&approval.tool_name, &arguments) {
        Ok((canonical, hash)) => {
            canonical == approval.arguments_json && hash == approval.action_hash
        }
        Err(_) => false,
    }
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}
