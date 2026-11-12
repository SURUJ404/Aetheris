use axum::{routing::get, Router};
use rust_control_plane::{api, observability};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    observability::init();

    let app = Router::new()
        .route("/health/live", get(api::health::live))
        .route("/health/ready", get(api::health::ready));

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let addr: SocketAddr = bind_addr
        .parse()
        .expect("BIND_ADDR must be a valid socket address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!(%addr, "control plane listening");
    axum::serve(listener, app).await.expect("server");
}
