//! Liveness and readiness probes.
//!
//! Readiness is dependency-aware: a process that cannot reach the authorization
//! store is not ready to serve authenticated traffic.

use axum::extract::State;
use axum::http::StatusCode;

use crate::state::AppState;

pub async fn live() -> &'static str {
    "ok"
}

/// Report readiness by probing PostgreSQL.
///
/// Returns `503` with a short body when the store is unreachable so a load
/// balancer stops sending traffic. The error detail is logged, never returned.
pub async fn ready(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match state.principal_store.ping().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(err) => {
            tracing::warn!(error = %err, "readiness probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization store unavailable",
            )
        }
    }
}
