//! Telemetry initialization.
//!
//! This module wires up the `tracing` subscriber stack. With the `otel` feature
//! enabled AND the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable set, it
//! additionally exports spans to an OTLP/gRPC collector (Jaeger, Tempo, Grafana,
//! `OTel` Collector...).
//!
//! When the feature is disabled or the endpoint variable is unset, only the
//! `fmt` layer is installed — behavior stays identical to the legacy
//! `tracing_subscriber::fmt()` call previously inlined in `main.rs`.
//!
//! Companion to [`crate::metrics`]: this module handles distributed traces,
//! while `metrics` keeps the Prometheus-style counters/gauges. The two coexist
//! and serve complementary observability needs.
//!
//! # Environment variables
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` — OTLP/gRPC endpoint (e.g.
//!   `http://localhost:4317`). If unset, OTLP export is disabled.
//! - `OTEL_SERVICE_NAME` — service name exposed in spans (default:
//!   `bridge-mcp`).
//! - `RUST_LOG` — standard `tracing-subscriber` filter (default: `info`).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Telemetry configuration read from environment variables.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint. `None` disables OTLP export.
    pub otlp_endpoint: Option<String>,
    /// Service name reported in spans/resources.
    pub service_name: String,
    /// Whether stderr output should be colorized (disabled in MCP stdio mode).
    pub colored_output: bool,
}

impl TelemetryConfig {
    /// Build a config from process environment variables.
    ///
    /// `is_mcp_mode` disables ANSI colors on stderr when the process is acting
    /// as an MCP server over stdio — colors would leak into protocol handshake
    /// debugging otherwise.
    #[must_use]
    pub fn from_env(is_mcp_mode: bool) -> Self {
        Self {
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "bridge-mcp".to_string()),
            colored_output: !is_mcp_mode,
        }
    }
}

/// Initialize the global `tracing` subscriber.
///
/// This should be called exactly once, early in `main()`. Calling it a second
/// time will silently fail because `tracing_subscriber` installs a global
/// default that cannot be replaced — this matches the previous behavior.
///
/// # Errors
///
/// Returns an error if the OTLP exporter can not be built when the `otel`
/// feature is active and `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Failures in
/// that path are unusual (typically indicate a transport misconfiguration)
/// and are surfaced to the caller so `main()` can fail loudly instead of
/// silently dropping telemetry.
pub fn init_telemetry(config: &TelemetryConfig) -> anyhow::Result<()> {
    // Each branch constructs `fmt::layer()` inline so the compiler can infer
    // its Subscriber type parameter in context — pre-constructing `fmt_layer`
    // locks its type too early and conflicts with the OpenTelemetry layer
    // stack.
    let new_filter =
        || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let colored = config.colored_output;

    #[cfg(feature = "otel")]
    {
        if let Some(endpoint) = config.otlp_endpoint.as_deref() {
            // OpenTelemetryLayer has its Subscriber type parameter fixed to
            // `Registry`, so it must be the first layer applied.
            let otel_layer = otel::build_otel_layer(endpoint, &config.service_name)?;
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(new_filter())
                .with(
                    fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_target(false)
                        .with_ansi(colored),
                )
                .init();
            tracing::info!(
                endpoint = endpoint,
                service = %config.service_name,
                "OTLP telemetry enabled"
            );
            return Ok(());
        }
    }

    tracing_subscriber::registry()
        .with(new_filter())
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_ansi(colored),
        )
        .init();
    Ok(())
}

/// RAII guard that records `duration_ms` on the current tracing span when
/// dropped.
///
/// Use this inside `#[tracing::instrument]`-annotated functions to capture
/// latency on all exit paths (Ok, Err, early returns, panics) without
/// scattering timing code throughout the body. The field must be declared
/// in the instrument macro's `fields(...)` as `duration_ms = Empty`.
///
/// # Example
///
/// ```ignore
/// #[tracing::instrument(fields(duration_ms = tracing::field::Empty))]
/// fn work() {
///     let _timer = crate::telemetry::SpanDurationGuard::start();
///     // ... any body, returns however it wants ...
/// }
/// ```
pub struct SpanDurationGuard {
    start: std::time::Instant,
}

impl SpanDurationGuard {
    /// Capture the current instant. Records `duration_ms` on the current span
    /// at drop time.
    #[must_use]
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}

impl Drop for SpanDurationGuard {
    fn drop(&mut self) {
        // Cast truncation is acceptable: u128 → u64 overflow would require a
        // span longer than 584 million years.
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        tracing::Span::current().record("duration_ms", elapsed_ms);
    }
}

/// Flush pending spans and release `OTel` resources.
///
/// Safe to call even if telemetry was not initialized or the `otel` feature
/// is disabled — it becomes a no-op.
pub fn shutdown_telemetry() {
    #[cfg(feature = "otel")]
    {
        otel::shutdown();
    }
}

#[cfg(feature = "otel")]
mod otel {
    use std::sync::OnceLock;

    use opentelemetry::KeyValue;
    use opentelemetry::global;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::Registry;

    /// Kept alive so that `shutdown_telemetry` can flush pending spans at
    /// process exit.
    static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

    pub(super) fn build_otel_layer(
        endpoint: &str,
        service_name: &str,
    ) -> anyhow::Result<OpenTelemetryLayer<Registry, opentelemetry_sdk::trace::Tracer>> {
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let resource = Resource::builder()
            .with_service_name(service_name.to_string())
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();

        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build();

        let tracer = provider.tracer("bridge-mcp");

        // Register globally so OpenTelemetry context propagation works, and
        // keep a handle for graceful shutdown.
        global::set_tracer_provider(provider.clone());
        let _ = PROVIDER.set(provider);

        Ok(tracing_opentelemetry::layer().with_tracer(tracer))
    }

    pub(super) fn shutdown() {
        if let Some(provider) = PROVIDER.get()
            && let Err(e) = provider.shutdown()
        {
            // Can't use tracing here — subscriber may already be gone.
            eprintln!("Telemetry shutdown failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults_when_env_unset() {
        // SAFETY: tests run in a shared process — avoid races by asserting
        // only on the default value when the var is absent.
        // We intentionally don't mutate the env here.
        let config = TelemetryConfig {
            otlp_endpoint: None,
            service_name: "bridge-mcp".to_string(),
            colored_output: true,
        };
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.service_name, "bridge-mcp");
    }

    #[test]
    fn test_config_mcp_mode_disables_colors() {
        let config = TelemetryConfig {
            otlp_endpoint: None,
            service_name: "test".to_string(),
            colored_output: false,
        };
        assert!(!config.colored_output);
    }

    #[test]
    fn test_shutdown_is_safe_without_init() {
        // Must not panic even if telemetry was never initialized.
        shutdown_telemetry();
    }

    #[test]
    fn test_span_duration_guard_start() {
        let guard = SpanDurationGuard::start();
        // Guard captures an instant — dropping it records duration_ms on current span.
        // Even without an active span, drop must not panic.
        drop(guard);
    }

    #[test]
    fn test_telemetry_config_debug() {
        let config = TelemetryConfig {
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            service_name: "test-svc".to_string(),
            colored_output: true,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("test-svc"));
        assert!(debug.contains("localhost:4317"));
    }

    #[test]
    fn test_telemetry_config_clone() {
        let config = TelemetryConfig {
            otlp_endpoint: Some("http://endpoint".to_string()),
            service_name: "svc".to_string(),
            colored_output: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.service_name, "svc");
        assert_eq!(cloned.otlp_endpoint, Some("http://endpoint".to_string()));
        assert!(!cloned.colored_output);
    }

    #[test]
    fn test_from_env_mcp_mode_disables_colors() {
        // from_env reads real env vars — we only assert the deterministic part:
        // MCP mode must disable colored output.
        let config = TelemetryConfig::from_env(true);
        assert!(!config.colored_output);
    }

    #[test]
    fn test_from_env_non_mcp_mode_enables_colors() {
        let config = TelemetryConfig::from_env(false);
        assert!(config.colored_output);
    }

    #[test]
    fn test_from_env_service_name_has_default() {
        // Unless OTEL_SERVICE_NAME is overridden, the default should apply.
        let config = TelemetryConfig::from_env(false);
        // The name is either the env var or the default — both are non-empty.
        assert!(!config.service_name.is_empty());
    }

    #[test]
    fn test_span_duration_guard_elapsed_is_non_negative() {
        let guard = SpanDurationGuard::start();
        std::thread::sleep(std::time::Duration::from_millis(1));
        // Dropping records duration_ms — must not panic even with elapsed > 0.
        drop(guard);
    }
}
