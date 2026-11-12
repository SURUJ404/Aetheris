use axum::{routing::get, Router};
use rust_control_plane::{api, observability};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    observability::init();

    let app = Router::new()
        .route("/health/live", get(api::health::live))
        .route("/health/ready", get(api::health::ready));

    let addr: SocketAddr = "0.0.0.0:8080".parse().expect("valid bind address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!(%addr, "control plane listening");
    axum::serve(listener, app).await.expect("server");
}
