//! Execution API.
//!
//! Every route requires a validated [`TenantContext`]; the tenant is never read
//! from a body or path. The handler only translates HTTP into a broker request
//! and a [`ExecutionRecord`] back into a view: all authorization, limits and
//! lifecycle decisions live in the broker.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::broker::{BrokerError, ExecutionRequest};
use crate::execution::{ArtifactRef, ExecutionLimits, ExecutionRecord, RuntimeKind};
use crate::principal::TenantContext;
use crate::state::AppState;

/// Body of `POST /v1/executions`.
///
/// The runtime is named explicitly so an operator allowlist, not a caller's
/// preference, decides whether it can run. Input is text for the current
/// workload set; binary input is a documented gap until a workload needs it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    /// Tenant-scoped task label.
    pub task_id: String,
    /// `wasmtime` or `firecracker`.
    pub runtime: String,
    /// Approved workload name.
    pub workload: String,
    /// Standard input, as UTF-8 text.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Requested limits. Every field is required so a default can never widen
    /// what the caller intended.
    pub limits: ExecutionLimits,
    /// Optional client idempotency key.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// Failure detail in a response body.
#[derive(Debug, Serialize)]
pub struct FailureView {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One execution as returned to a client. Never includes another tenant's row.
#[derive(Debug, Serialize)]
pub struct ExecutionView {
    pub id: Uuid,
    pub task_id: String,
    pub runtime: &'static str,
    pub workload: String,
    pub status: &'static str,
    pub policy_version: String,
    pub limits: ExecutionLimits,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_requested_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_consumed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    pub artifacts: Vec<ArtifactRef>,
}

impl From<&ExecutionRecord> for ExecutionView {
    fn from(record: &ExecutionRecord) -> Self {
        Self {
            id: record.id,
            task_id: record.task_id.clone(),
            runtime: record.runtime.as_str(),
            workload: record.workload.clone(),
            status: record.status.as_str(),
            policy_version: record.policy_version.clone(),
            limits: record.limits,
            created_at: record.created_at,
            started_at: record.started_at,
            finished_at: record.finished_at,
            cancel_requested_at: record.cancel_requested_at,
            exit_code: record.exit_code,
            failure: record.failure_kind.as_ref().map(|kind| FailureView {
                kind: kind.clone(),
                message: record.failure_message.clone(),
            }),
            duration_ms: record.duration_ms,
            fuel_consumed: record.fuel_consumed,
            memory_peak_bytes: record.memory_peak_bytes,
            output_digest: record.output_digest.clone(),
            stdout: record.stdout.clone(),
            stderr: record.stderr.clone(),
            artifacts: record.artifacts.clone(),
        }
    }
}

/// Submit an execution proposal.
pub async fn submit(
    State(state): State<AppState>,
    context: TenantContext,
    request: Result<Json<SubmitRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(rejection) => {
            return error(rejection.status(), "invalid_request", rejection.body_text());
        }
    };

    let Some(runtime) = RuntimeKind::parse(&request.runtime) else {
        return error(
            StatusCode::BAD_REQUEST,
            "unsupported_runtime",
            "runtime must be `wasmtime` or `firecracker`".into(),
        );
    };

    if !state.broker.runtimes().contains(&runtime) {
        return error(
            StatusCode::BAD_REQUEST,
            "runtime_disabled",
            "the requested runtime is not enabled on this deployment".into(),
        );
    }

    let proposal = ExecutionRequest {
        task_id: request.task_id,
        runtime,
        workload: request.workload,
        stdin: request.stdin.unwrap_or_default().into_bytes(),
        limits: request.limits,
        idempotency_key: request.idempotency_key,
    };

    match state.broker.submit(&context, proposal).await {
        Ok(record) => (StatusCode::CREATED, Json(ExecutionView::from(&record))).into_response(),
        Err(err) => broker_error(err),
    }
}

/// Read an execution in the caller's tenant.
pub async fn get_execution(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_execution_id",
            "execution id must be a UUID".into(),
        );
    };

    match state.broker.get(&context, id).await {
        Ok(record) => Json(ExecutionView::from(&record)).into_response(),
        Err(err) => broker_error(err),
    }
}

/// Request cancellation of an execution.
pub async fn cancel(
    State(state): State<AppState>,
    context: TenantContext,
    Path(id): Path<String>,
) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_execution_id",
            "execution id must be a UUID".into(),
        );
    };

    match state.broker.cancel(&context, id).await {
        Ok(record) => Json(ExecutionView::from(&record)).into_response(),
        Err(err) => broker_error(err),
    }
}

/// Translate broker failures into stable HTTP responses.
pub(crate) fn broker_error(error: BrokerError) -> Response {
    let status = match &error {
        BrokerError::Forbidden { .. } => StatusCode::FORBIDDEN,
        BrokerError::RuntimeDisabled(_)
        | BrokerError::UnknownWorkload(_)
        | BrokerError::InvalidLimits(_)
        | BrokerError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        BrokerError::Busy => StatusCode::TOO_MANY_REQUESTS,
        BrokerError::NotFound => StatusCode::NOT_FOUND,
        BrokerError::NotCancellable(..) | BrokerError::Conflict => StatusCode::CONFLICT,
        BrokerError::RuntimeUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        BrokerError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };

    // Client-visible text is intentionally generic; the variant is a stable
    // machine-readable code.
    let code = match &error {
        BrokerError::Forbidden { .. } => "access_denied",
        BrokerError::RuntimeDisabled(_) => "runtime_disabled",
        BrokerError::UnknownWorkload(_) => "unknown_workload",
        BrokerError::InvalidLimits(_) => "invalid_limits",
        BrokerError::InvalidRequest(_) => "invalid_request",
        BrokerError::Busy => "too_many_executions",
        BrokerError::NotFound => "not_found",
        BrokerError::NotCancellable(..) => "not_cancellable",
        BrokerError::Conflict => "conflict",
        BrokerError::RuntimeUnavailable(_) => "runtime_unavailable",
        BrokerError::Internal => "internal_error",
    };

    if status.is_server_error() {
        tracing::error!(error = %error, "execution request failed");
    }

    (
        status,
        Json(json!({
            "error": code,
            "error_description": error.to_string(),
        })),
    )
        .into_response()
}

fn error(status: StatusCode, code: &'static str, description: String) -> Response {
    (
        status,
        Json(json!({
            "error": code,
            "error_description": description,
        })),
    )
        .into_response()
}
