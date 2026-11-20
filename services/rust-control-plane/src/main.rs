use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use rust_control_plane::{
    api,
    config::AppConfig,
    execution::{ExecutionStore, RuntimeKind},
    grpc::TaskGrpcService,
    observability,
    persistence::{PgStore, PrincipalStore},
    runtime::{
        FirecrackerConfig, FirecrackerRuntime, RuntimeRegistry, SandboxRuntime, WasmtimeConfig,
        WasmtimeRuntime, WorkloadRegistry,
    },
    state::AppState,
};

#[tokio::main]
async fn main() {
    let _telemetry = observability::init();

    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    // Approved workloads are loaded and hash-verified before the server binds.
    // A tampered or missing manifest is a deployment error, not a runtime one.
    let workloads = match WorkloadRegistry::load(&config.execution.workload_dir) {
        Ok(workloads) => workloads,
        Err(err) => {
            eprintln!("workload registry error: {err}");
            eprintln!(
                "expected an approved workload directory at {}",
                config.execution.workload_dir.display()
            );
            std::process::exit(1);
        }
    };

    // Only configure-enabled runtimes are constructed. A runtime that is not in
    // the list cannot be requested, even if its host prerequisites exist.
    let mut runtimes: Vec<Arc<dyn SandboxRuntime>> = Vec::new();
    for kind in &config.execution.enabled_runtimes {
        match kind {
            RuntimeKind::Wasmtime => {
                let wasmtime = WasmtimeRuntime::new(WasmtimeConfig {
                    enable_scratch: config.execution.wasmtime_enable_scratch,
                    max_stack_bytes: config.execution.wasmtime_max_stack_bytes,
                });
                match wasmtime {
                    Ok(runtime) => runtimes.push(Arc::new(runtime)),
                    Err(err) => {
                        eprintln!("wasmtime initialisation failed: {err:?}");
                        std::process::exit(1);
                    }
                }
            }
            RuntimeKind::Firecracker => {
                let runtime = FirecrackerRuntime::new(FirecrackerConfig {
                    binary: config.execution.firecracker_binary.clone(),
                    kernel_image: config.execution.firecracker_kernel_image.clone(),
                    rootfs_image: config.execution.firecracker_rootfs_image.clone(),
                    vcpu_count: config.execution.firecracker_vcpu_count,
                    memory_mib: config.execution.firecracker_memory_mib,
                    scratch_root: config.execution.firecracker_scratch_root.clone(),
                    ..FirecrackerConfig::default()
                });
                runtimes.push(Arc::new(runtime));
            }
        }
    }
    let runtimes = RuntimeRegistry::new(runtimes);
    tracing::info!(
        runtimes = ?runtimes.kinds(),
        workloads = ?workloads.names(),
        "execution runtimes configured"
    );

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

    let store = Arc::new(store);
    let principal_store: Arc<dyn PrincipalStore> = store.clone();
    let execution_store: Arc<dyn ExecutionStore> = store.clone();
    let task_store: Arc<dyn rust_control_plane::task::TaskStore> = store.clone();

    let state = match AppState::new(
        config,
        principal_store,
        execution_store,
        task_store,
        runtimes,
        workloads,
    ) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("authentication initialisation failed: {err}");
            std::process::exit(1);
        }
    };

    // Nothing is running for rows left in flight by a previous process, so fail
    // them before accepting traffic rather than leaving them RUNNING forever.
    if let Err(err) = state.broker.recover().await {
        eprintln!("execution recovery failed: {err}");
        std::process::exit(1);
    }

    let addr = state.config.bind_addr;
    let task_grpc_addr = state.config.task_grpc_addr;
    let issuer = state.config.identity.issuer.clone();
    let task_grpc = TaskGrpcService::new(
        state.verifier.clone(),
        state.principal_store.clone(),
        state.task_store.clone(),
    );

    // Health liveness is unauthenticated so orchestrators can probe the
    // process before identity is reachable. Readiness checks the database.
    // Everything under /v1 requires a validated principal.
    let app = Router::new()
        .route("/health/live", get(api::health::live))
        .route("/health/ready", get(api::health::ready))
        .route("/v1/me", get(api::identity::me))
        .route("/v1/session", get(api::identity::session))
        .route("/v1/authorize", post(api::authorization::authorize))
        .route("/v1/executions", post(api::executions::submit))
        .route("/v1/executions/{id}", get(api::executions::get_execution))
        .route("/v1/executions/{id}/cancel", post(api::executions::cancel))
        .route("/v1/tasks", post(api::tasks::create))
        .route("/v1/tasks/{id}", get(api::tasks::get))
        .route("/v1/tasks/{id}/cancel", post(api::tasks::cancel))
        .route("/v1/tasks/{id}/approve", post(api::tasks::approve))
        .route("/v1/tasks/{id}/execute", post(api::tasks::execute_approved))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");

    tracing::info!(%addr, %issuer, "control plane listening");

    tracing::info!(%task_grpc_addr, "task gRPC service listening");

    // One shutdown signal drains both listeners: HTTP stops accepting and
    // finishes in-flight requests, gRPC stops accepting and lets handlers
    // return. The process exits only once both servers have finished, so a
    // deployment rollout cannot cut a request in half.
    let (shutdown, _) = tokio::sync::watch::channel(false);

    let mut http_shutdown = shutdown.subscribe();
    let http = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown.changed().await;
            })
            .await
    });

    let mut grpc_shutdown = shutdown.subscribe();
    let grpc = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                rust_control_plane::proto::task_service_server::TaskServiceServer::new(task_grpc),
            )
            .serve_with_shutdown(task_grpc_addr, async move {
                let _ = grpc_shutdown.changed().await;
            })
            .await
    });

    wait_for_shutdown_signal().await;
    tracing::info!("shutdown signal received; draining listeners");
    let _ = shutdown.send(true);

    if let Err(error) = http.await.expect("http server task") {
        tracing::error!(error = %error, "http server stopped with an error");
    }
    if let Err(error) = grpc.await.expect("gRPC server task") {
        tracing::error!(error = %error, "task gRPC server stopped with an error");
    }
    tracing::info!("control plane stopped");
}

/// Resolve on the first termination signal: `SIGINT` (Ctrl-C) or `SIGTERM`
/// (container stop, orchestrator rollout).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "could not listen for Ctrl-C");
            // Never resolve: the other signal path is still armed.
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
