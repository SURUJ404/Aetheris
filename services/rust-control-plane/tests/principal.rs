//! Principal resolution tests: a validated token is only the first step.
//! Membership, role and permissions come from the store, and every failure mode
//! is denied rather than downgraded to anonymous access.

mod common;

use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{FromRequestParts, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use common::{claims, member, sign, state_with_store, StubBehavior, StubStore, TENANT};
use rust_control_plane::api;
use rust_control_plane::persistence::PrincipalStore;
use rust_control_plane::principal::{AccessError, TenantContext};

async fn context_with(
    store: Arc<dyn PrincipalStore>,
    token: Option<&str>,
) -> Result<TenantContext, AccessError> {
    let state = state_with_store(store);
    let mut builder = Request::builder().uri("/v1/session");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let (mut parts, _) = builder.body(()).expect("request").into_parts();

    TenantContext::from_request_parts(&mut parts, &state).await
}

async fn json_body(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn active_membership_resolves_tenant_context() {
    let store = StubStore::shared(StubBehavior::Member(member()));
    let context = context_with(store, Some(&sign(&claims())))
        .await
        .expect("resolved");

    assert_eq!(context.identity.subject, "user-1");
    assert_eq!(context.identity.tenant_id, TENANT);
    assert_eq!(context.resolved.tenant_id, TENANT);
    assert_eq!(context.resolved.role, "member");
}

#[tokio::test]
async fn permissions_come_from_the_role() {
    let store = StubStore::shared(StubBehavior::Member(member()));
    let context = context_with(store, Some(&sign(&claims())))
        .await
        .expect("resolved");

    assert!(context.has_permission("tool:invoke"));
    assert!(context.has_permission("task:write"));
    assert!(!context.has_permission("tool:approve"));
    assert!(!context.has_permission("member:manage"));
}

#[tokio::test]
async fn missing_membership_is_forbidden() {
    let store = StubStore::shared(StubBehavior::NoMembership);
    let error = context_with(store, Some(&sign(&claims())))
        .await
        .expect_err("denied");

    assert!(matches!(error, AccessError::NotAMember(ref tenant) if tenant == TENANT));

    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json_body(response).await;
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn store_failure_is_service_unavailable_with_retry_after() {
    let store = StubStore::shared(StubBehavior::Unavailable);
    let error = context_with(store, Some(&sign(&claims())))
        .await
        .expect_err("store down");

    assert!(matches!(error, AccessError::Store(_)));

    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "5");
    let body = json_body(response).await;
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn invalid_token_is_unauthorized_before_any_lookup() {
    // The store would resolve a member, but the token never reaches it.
    let store = StubStore::shared(StubBehavior::Member(member()));
    let error = context_with(store, Some("not-a-token"))
        .await
        .expect_err("rejected");

    assert!(matches!(error, AccessError::Unauthenticated(_)));
    assert_eq!(error.into_response().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_token_is_unauthorized() {
    let store = StubStore::shared(StubBehavior::NoMembership);
    let error = context_with(store, None).await.expect_err("rejected");

    assert!(matches!(error, AccessError::Unauthenticated(_)));
}

#[tokio::test]
async fn readiness_fails_when_store_is_unreachable() {
    let state = state_with_store(StubStore::shared(StubBehavior::Unavailable));
    let (status, _) = api::health::ready(State(state)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn readiness_succeeds_when_store_answers() {
    let state = state_with_store(StubStore::shared(StubBehavior::Member(member())));
    let (status, body) = api::health::ready(State(state)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ready");
}
