use axum::{routing::get, Router};
use rust_control_plane::{api, config::AppConfig, observability, state::AppState};

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

    let state = match AppState::new(config) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("authentication initialisation failed: {err}");
            std::process::exit(1);
        }
    };

    let addr = state.config.bind_addr;
    let issuer = state.config.identity.issuer.clone();

    // Health endpoints are unauthenticated so orchestrators can probe the
    // process before identity is reachable. Everything under /v1 requires a
    // validated principal.
    let app = Router::new()
        .route("/health/live", get(api::health::live))
        .route("/health/ready", get(api::health::ready))
        .route("/v1/me", get(api::identity::me))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");

    tracing::info!(%addr, %issuer, "control plane listening");

    axum::serve(listener, app).await.expect("server");
}
