use std::sync::Arc;

use axum::{routing::get, Router};
use rust_control_plane::{
    api, config::AppConfig, observability, persistence::PgStore, state::AppState,
};

#[tokio::main]
async fn main() {
    observability::init();

    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    // The control plane is useless without durable authorization state, so a
    // failed connection is fatal rather than lazily retried per request.
    let store = match PgStore::connect(&config.database.url, config.database.max_connections).await
    {
        Ok(store) => store,
        Err(err) => {
            eprintln!("database connection failed: {err}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        max_connections = config.database.max_connections,
        "database connected"
    );

    if config.database.migrate_on_start {
        if let Err(err) = store.migrate().await {
            eprintln!("database migration failed: {err}");
            std::process::exit(1);
        }
        tracing::info!("database migrations applied");
    }

    let state = match AppState::new(config, Arc::new(store)) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("authentication initialisation failed: {err}");
            std::process::exit(1);
        }
    };

    let addr = state.config.bind_addr;
    let issuer = state.config.identity.issuer.clone();

    // Health liveness is unauthenticated so orchestrators can probe the
    // process before identity is reachable. Readiness checks the database.
    // Everything under /v1 requires a validated principal.
    let app = Router::new()
        .route("/health/live", get(api::health::live))
        .route("/health/ready", get(api::health::ready))
        .route("/v1/me", get(api::identity::me))
        .route("/v1/session", get(api::identity::session))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");

    tracing::info!(%addr, %issuer, "control plane listening");

    axum::serve(listener, app).await.expect("server");
}
