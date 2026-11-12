//! Caller identity endpoints.

use axum::Json;

use crate::auth::Principal;

/// Echo the authenticated principal.
///
/// Exists to prove the token path end to end and to give clients a cheap way to
/// discover their tenant and scopes. It exposes no data beyond the token.
pub async fn me(principal: Principal) -> Json<Principal> {
    Json(principal)
}
