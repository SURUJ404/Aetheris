//! Policy evaluation tests: deny by default, grant only from resolved
//! permissions, and never authorize across a tenant mismatch.

mod common;

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use serde_json::Value;

use common::{now, ISSUER, TENANT};
use rust_control_plane::api::authorization::{authorize, AuthorizeRequest};
use rust_control_plane::auth::Principal;
use rust_control_plane::persistence::ResolvedPrincipal;
use rust_control_plane::policy::{Action, DenyReason, Permission, PolicyDecision, PolicyEngine};
use rust_control_plane::principal::TenantContext;

fn identity(tenant_id: &str) -> Principal {
    Principal {
        subject: "user-1".into(),
        tenant_id: tenant_id.into(),
        issuer: ISSUER.into(),
        audiences: vec!["rust-control-plane".into()],
        scopes: vec!["openid".into()],
        token_id: Some("token-1".into()),
        expires_at: now() + 300,
    }
}

fn context(role: &str, permissions: &[Permission]) -> TenantContext {
    TenantContext {
        identity: identity(TENANT),
        resolved: ResolvedPrincipal {
            principal_id: uuid::Uuid::nil(),
            tenant_id: TENANT.into(),
            role: role.into(),
            permissions: permissions
                .iter()
                .map(|permission| permission.as_str().to_string())
                .collect(),
        },
    }
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn allows_an_action_the_role_grants() {
    let context = context("member", &[Permission::TaskRead, Permission::ToolInvoke]);

    let decision = PolicyEngine::new().evaluate(&context, Action::ToolInvoke);

    assert_eq!(
        decision,
        PolicyDecision::Allow {
            action: Action::ToolInvoke,
            permission: Permission::ToolInvoke,
        }
    );
    assert!(decision.is_allowed());
    assert_eq!(decision.deny_reason(), None);
}

#[tokio::test]
async fn denies_an_action_the_role_lacks() {
    let context = context("member", &[Permission::TaskRead, Permission::ToolInvoke]);

    let decision = PolicyEngine::new().evaluate(&context, Action::ToolApprove);

    assert_eq!(
        decision,
        PolicyDecision::Deny {
            action: Action::ToolApprove,
            permission: Permission::ToolApprove,
            reason: DenyReason::MissingPermission,
        }
    );
    assert!(!decision.is_allowed());
    assert_eq!(decision.deny_reason(), Some(DenyReason::MissingPermission));
}

#[tokio::test]
async fn empty_permissions_deny_everything() {
    let context = context("viewer", &[]);

    for action in Action::ALL {
        assert!(
            !PolicyEngine::new().evaluate(&context, action).is_allowed(),
            "{} should be denied",
            action.as_str()
        );
    }
}

#[tokio::test]
async fn owner_grants_are_sufficient_for_every_action() {
    let context = context("owner", &Permission::ALL);

    for action in Action::ALL {
        assert_eq!(
            PolicyEngine::new().evaluate(&context, action),
            PolicyDecision::Allow {
                action,
                permission: action.required_permission(),
            }
        );
    }
}

#[tokio::test]
async fn tenant_mismatch_is_denied_even_with_the_permission() {
    let mut context = context("owner", &Permission::ALL);
    context.resolved.tenant_id = "tenant-other".into();

    let decision = PolicyEngine::new().evaluate(&context, Action::ToolInvoke);

    assert_eq!(decision.deny_reason(), Some(DenyReason::TenantMismatch));
}

#[tokio::test]
async fn authorize_handler_returns_the_decision() {
    let context = context("member", &[Permission::ToolInvoke]);
    let response = authorize(
        context,
        Ok(Json(AuthorizeRequest {
            action: Some("tool.invoke".into()),
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["allowed"], true);
    assert_eq!(body["action"], "tool.invoke");
    assert_eq!(body["permission"], "tool:invoke");
    assert_eq!(body["role"], "member");
}

#[tokio::test]
async fn authorize_handler_denies_with_403_and_reason() {
    let context = context("member", &[Permission::ToolInvoke]);
    let response = authorize(
        context,
        Ok(Json(AuthorizeRequest {
            action: Some("tool.approve".into()),
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["reason"], "missing_permission");
    assert_eq!(body["action"], "tool.approve");
    assert_eq!(body["required_permission"], "tool:approve");
}

#[tokio::test]
async fn authorize_handler_rejects_unknown_actions() {
    let context = context("owner", &Permission::ALL);
    let response = authorize(
        context,
        Ok(Json(AuthorizeRequest {
            action: Some("tool.delete".into()),
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "unsupported_action");
}

#[tokio::test]
async fn authorize_handler_rejects_a_missing_action() {
    let context = context("owner", &Permission::ALL);
    let response = authorize(context, Ok(Json(AuthorizeRequest { action: None }))).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "unsupported_action");
}
