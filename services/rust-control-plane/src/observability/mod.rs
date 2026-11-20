use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{runtime, trace::TracerProvider as SdkTracerProvider, Resource};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Keeps the OTLP provider alive for the lifetime of the control plane and
/// flushes pending spans during shutdown.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

pub fn init() -> TelemetryGuard {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
    });
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    let Some(endpoint) =
        std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").filter(|value| !value.is_empty())
    else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .init();
        return TelemetryGuard { provider: None };
    };

    let endpoint = endpoint.to_string_lossy().into_owned();
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rust-control-plane".into());
    let exporter = match SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(error) => {
            eprintln!("OpenTelemetry exporter disabled: {error}");
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            return TelemetryGuard { provider: None };
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(Resource::new([KeyValue::new("service.name", service_name)]))
        .build();
    let tracer = provider.tracer("agentic-control-plane");
    global::set_tracer_provider(provider.clone());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    TelemetryGuard {
        provider: Some(provider),
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}
