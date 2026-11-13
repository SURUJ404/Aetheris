//! Authorization decision endpoint.
//!
//! `/v1/authorize` exposes the same deterministic evaluation the broker will
//! run before dispatch. It is advisory: a client may use it to enable or hide
//! UI affordances, but the broker re-evaluates at execution time, so a decision
//! can never be replayed as an execution token.

use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::policy::{Action, DenyReason, PolicyDecision, PolicyEngine};
use crate::principal::TenantContext;

/// Body of an authorization request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRequest {
    /// Canonical action name, e.g. `tool.invoke`.
    #[serde(default)]
    pub action: Option<String>,
}

/// Successful decision body.
#[derive(Debug, Serialize)]
pub struct AllowedView {
    /// Always `true`; denials use an error response.
    pub allowed: bool,
    /// Evaluated action.
    pub action: &'static str,
    /// Permission that authorized it.
    pub permission: &'static str,
    /// Role of the resolved membership.
    pub role: String,
}

/// Evaluate one action for the authenticated caller.
pub async fn authorize(
    context: TenantContext,
    request: Result<Json<AuthorizeRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(rejection) => {
            return error(rejection.status(), "invalid_request", rejection.body_text());
        }
    };

    let Some(action) = request.action.as_deref().and_then(Action::parse) else {
        return error(
            StatusCode::BAD_REQUEST,
            "unsupported_action",
            "action is missing or not recognized".to_owned(),
        );
    };

    match PolicyEngine::new().evaluate(&context, action) {
        PolicyDecision::Allow { permission, .. } => {
            tracing::debug!(
                tenant = %context.identity.tenant_id,
                subject = %context.identity.subject,
                action = action.as_str(),
                permission = permission.as_str(),
                "authorization allowed"
            );
            (
                StatusCode::OK,
                Json(AllowedView {
                    allowed: true,
                    action: action.as_str(),
                    permission: permission.as_str(),
                    role: context.resolved.role.clone(),
                }),
            )
                .into_response()
        }

        PolicyDecision::Deny {
            permission, reason, ..
        } => {
            if reason == DenyReason::TenantMismatch {
                // Indicates a store or resolver defect, not a normal denial.
                tracing::error!(
                    subject = %context.identity.subject,
                    token_tenant = %context.identity.tenant_id,
                    resolved_tenant = %context.resolved.tenant_id,
                    "authorization context tenant mismatch"
                );
            } else {
                tracing::info!(
                    tenant = %context.identity.tenant_id,
                    subject = %context.identity.subject,
                    action = action.as_str(),
                    permission = permission.as_str(),
                    reason = reason.as_str(),
                    "authorization denied"
                );
            }

            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "access_denied",
                    "error_description": "the role does not grant the required permission",
                    "reason": reason.as_str(),
                    "action": action.as_str(),
                    "required_permission": permission.as_str(),
                })),
            )
                .into_response()
        }
    }
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
