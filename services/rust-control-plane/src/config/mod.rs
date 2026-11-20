//! Typed configuration. Fail closed on missing production secrets.
//!
//! Identity settings are provider-agnostic. Swapping Keycloak for another OIDC
//! provider means changing environment values, not code. See
//! `migration/adr/0001-identity-provider.md`.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::execution::RuntimeKind;

/// Deployment environment. Gates the checks that are only safe to relax
/// locally, such as plaintext OIDC endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnvironment {
    /// Local development. Plaintext OIDC endpoints are allowed.
    Development,
    /// Anything that is not local development. TLS is mandatory.
    Production,
}

impl AppEnvironment {
    /// Parse `APP_ENV`. Unknown values are rejected rather than defaulted, so a
    /// typo cannot silently downgrade the TLS requirement.
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" | "local" | "test" => Ok(Self::Development),
            "production" | "prod" | "staging" | "stage" => Ok(Self::Production),
            _ => Err(ConfigError::Invalid {
                name: "APP_ENV",
                reason: "expected development or production".into(),
            }),
        }
    }

    /// Whether relaxed local-only settings are permitted.
    pub const fn is_development(self) -> bool {
        matches!(self, Self::Development)
    }
}

/// Process-wide configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Deployment environment.
    pub environment: AppEnvironment,
    /// Address the HTTP server binds to. Never `0.0.0.0` by default.
    pub bind_addr: SocketAddr,
    /// Internal gRPC address used by the Python cognitive client.
    pub task_grpc_addr: SocketAddr,
    /// Identity provider settings used to authenticate callers.
    pub identity: IdentityConfig,
    /// Durable authorization state.
    pub database: DatabaseConfig,
    /// Sandbox execution settings.
    pub execution: ExecutionConfig,
}

/// PostgreSQL settings for memberships, roles and permission grants.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Connection string.
    pub url: String,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Apply embedded migrations at startup. Convenient in development; a
    /// production deployment may prefer a separate migration step.
    pub migrate_on_start: bool,
}

/// Settings for validating OIDC access tokens.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Exact expected `iss` claim.
    pub issuer: String,
    /// Required member of the token's `aud` claim.
    pub audience: String,
    /// JWKS endpoint used to fetch signing keys.
    pub jwks_uri: String,
    /// Claim carrying the tenant identifier. Never read from a request body.
    pub tenant_claim: String,
    /// Clock skew allowance for `exp` and `nbf`.
    pub leeway: Duration,
    /// Maximum age of cached signing keys before a background refresh.
    pub jwks_ttl: Duration,
    /// Per-request timeout when fetching JWKS.
    pub jwks_timeout: Duration,
}

/// Configuration failures. Messages intentionally name the variable but never
/// echo its value.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable `{0}` is not set")]
    Missing(&'static str),
    #[error("environment variable `{name}` is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl AppConfig {
    /// Load configuration from the process environment.
    ///
    /// Fails when identity settings are absent: the control plane is the
    /// authority for identity and must not start in an unauthenticated mode.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = optional("BIND_ADDR", "127.0.0.1:8081")?.parse().map_err(
            |err: std::net::AddrParseError| ConfigError::Invalid {
                name: "BIND_ADDR",
                reason: err.to_string(),
            },
        )?;
        let task_grpc_addr = optional("TASK_GRPC_BIND_ADDR", "127.0.0.1:50052")?
            .parse()
            .map_err(|err: std::net::AddrParseError| ConfigError::Invalid {
                name: "TASK_GRPC_BIND_ADDR",
                reason: err.to_string(),
            })?;

        let environment = AppEnvironment::parse(&optional("APP_ENV", "development")?)?;

        Ok(Self {
            environment,
            bind_addr,
            task_grpc_addr,
            identity: IdentityConfig::from_env(environment)?,
            database: DatabaseConfig::from_env()?,
            execution: ExecutionConfig::from_env()?,
        })
    }
}

/// Sandbox execution settings.
///
/// Every value is operator-controlled. A caller may lower a limit inside its
/// request, but the ceilings here are the maximum the deployment will run.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// Runtimes this deployment is allowed to use, in preference order.
    pub enabled_runtimes: Vec<RuntimeKind>,
    /// Directory containing `manifest.json` and the approved modules.
    pub workload_dir: PathBuf,
    /// Parent directory for per-execution scratch directories.
    pub scratch_root: PathBuf,
    /// Upper bound on concurrent executions per tenant.
    pub max_concurrent_per_tenant: usize,
    /// Ceilings applied by [`crate::execution::ExecutionLimits::enforce`].
    pub max_wall_clock_ms: u64,
    pub max_cpu_fuel: u64,
    pub max_memory_bytes: u64,
    pub max_output_bytes: u64,
    pub max_stdin_bytes: u64,
    pub max_artifacts_bytes: u64,
    /// Expose a per-execution scratch directory to Wasmtime guests.
    pub wasmtime_enable_scratch: bool,
    /// Maximum wasm operand stack per Wasmtime execution.
    pub wasmtime_max_stack_bytes: usize,
    /// Firecracker binary path.
    pub firecracker_binary: PathBuf,
    /// Uncompressed kernel image.
    pub firecracker_kernel_image: PathBuf,
    /// Root filesystem image containing the guest agent.
    pub firecracker_rootfs_image: PathBuf,
    /// vCPUs per microVM.
    pub firecracker_vcpu_count: u8,
    /// Guest memory in MiB.
    pub firecracker_memory_mib: u32,
    /// Parent directory for per-execution microVM workspaces.
    pub firecracker_scratch_root: PathBuf,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            enabled_runtimes: vec![RuntimeKind::Wasmtime],
            workload_dir: PathBuf::from("workloads"),
            scratch_root: std::env::temp_dir().join("agentic-execution"),
            max_concurrent_per_tenant: 4,
            max_wall_clock_ms: 30_000,
            max_cpu_fuel: 1_000_000_000,
            max_memory_bytes: 256 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_stdin_bytes: 1024 * 1024,
            max_artifacts_bytes: 8 * 1024 * 1024,
            wasmtime_enable_scratch: true,
            wasmtime_max_stack_bytes: 512 * 1024,
            firecracker_binary: PathBuf::from("/usr/local/bin/firecracker"),
            firecracker_kernel_image: PathBuf::from("/var/lib/agentic/vmlinux.bin"),
            firecracker_rootfs_image: PathBuf::from("/var/lib/agentic/rootfs.ext4"),
            firecracker_vcpu_count: 1,
            firecracker_memory_mib: 512,
            firecracker_scratch_root: std::env::temp_dir().join("agentic-firecracker"),
        }
    }
}

impl ExecutionConfig {
    /// Load execution settings from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let defaults = Self::default();

        let enabled_runtimes = parse_runtimes(&optional("EXECUTION_RUNTIMES", "wasmtime")?)?;

        let config = Self {
            enabled_runtimes,
            workload_dir: path("EXECUTION_WORKLOAD_DIR", &defaults.workload_dir),
            scratch_root: path("EXECUTION_SCRATCH_ROOT", &defaults.scratch_root),
            max_concurrent_per_tenant: number(
                "EXECUTION_MAX_CONCURRENT_PER_TENANT",
                defaults.max_concurrent_per_tenant as u64,
            )? as usize,
            max_wall_clock_ms: number("EXECUTION_MAX_WALL_CLOCK_MS", defaults.max_wall_clock_ms)?,
            max_cpu_fuel: number("EXECUTION_MAX_CPU_FUEL", defaults.max_cpu_fuel)?,
            max_memory_bytes: number("EXECUTION_MAX_MEMORY_BYTES", defaults.max_memory_bytes)?,
            max_output_bytes: number("EXECUTION_MAX_OUTPUT_BYTES", defaults.max_output_bytes)?,
            max_stdin_bytes: number("EXECUTION_MAX_STDIN_BYTES", defaults.max_stdin_bytes)?,
            max_artifacts_bytes: number(
                "EXECUTION_MAX_ARTIFACTS_BYTES",
                defaults.max_artifacts_bytes,
            )?,
            wasmtime_enable_scratch: boolean(
                "EXECUTION_WASMTIME_SCRATCH",
                defaults.wasmtime_enable_scratch,
            )?,
            wasmtime_max_stack_bytes: number(
                "EXECUTION_WASMTIME_MAX_STACK_BYTES",
                defaults.wasmtime_max_stack_bytes as u64,
            )? as usize,
            firecracker_binary: path("FIRECRACKER_BINARY", &defaults.firecracker_binary),
            firecracker_kernel_image: path(
                "FIRECRACKER_KERNEL_IMAGE",
                &defaults.firecracker_kernel_image,
            ),
            firecracker_rootfs_image: path(
                "FIRECRACKER_ROOTFS_IMAGE",
                &defaults.firecracker_rootfs_image,
            ),
            firecracker_vcpu_count: number(
                "FIRECRACKER_VCPU_COUNT",
                defaults.firecracker_vcpu_count as u64,
            )? as u8,
            firecracker_memory_mib: number(
                "FIRECRACKER_MEMORY_MIB",
                defaults.firecracker_memory_mib as u64,
            )? as u32,
            firecracker_scratch_root: path(
                "FIRECRACKER_SCRATCH_ROOT",
                &defaults.firecracker_scratch_root,
            ),
        };

        // Fail at startup, not on the first request: a deployment that cannot
        // run any enabled runtime is a configuration error.
        if config.enabled_runtimes.is_empty() {
            return Err(ConfigError::Invalid {
                name: "EXECUTION_RUNTIMES",
                reason: "at least one runtime must be enabled".into(),
            });
        }
        if config.max_concurrent_per_tenant == 0 {
            return Err(ConfigError::Invalid {
                name: "EXECUTION_MAX_CONCURRENT_PER_TENANT",
                reason: "must be greater than zero".into(),
            });
        }

        Ok(config)
    }
}

/// Parse a comma-separated runtime list. Unknown names are rejected rather
/// than ignored, so a typo cannot silently disable the runtime an operator
/// intended to enable.
fn parse_runtimes(raw: &str) -> Result<Vec<RuntimeKind>, ConfigError> {
    let mut runtimes = Vec::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let runtime = RuntimeKind::parse(name).ok_or_else(|| ConfigError::Invalid {
            name: "EXECUTION_RUNTIMES",
            reason: format!("unknown runtime `{name}`"),
        })?;
        if !runtimes.contains(&runtime) {
            runtimes.push(runtime);
        }
    }
    Ok(runtimes)
}

impl DatabaseConfig {
    /// Load PostgreSQL settings from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let url = required("DATABASE_URL")?;
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(ConfigError::Invalid {
                name: "DATABASE_URL",
                reason: "must be a postgres:// or postgresql:// URL".into(),
            });
        }

        let max_connections = optional("DATABASE_MAX_CONNECTIONS", "10")?
            .parse::<u32>()
            .map_err(|err| ConfigError::Invalid {
                name: "DATABASE_MAX_CONNECTIONS",
                reason: err.to_string(),
            })?
            .clamp(1, 200);

        Ok(Self {
            url,
            max_connections,
            migrate_on_start: boolean("DATABASE_MIGRATE", true)?,
        })
    }
}

impl IdentityConfig {
    /// Load identity settings from the process environment.
    ///
    /// In production, both the issuer and the JWKS endpoint must use HTTPS.
    /// Accepting a plaintext JWKS URL would let anyone on the network swap the
    /// signing keys and mint tokens the control plane accepts.
    pub fn from_env(environment: AppEnvironment) -> Result<Self, ConfigError> {
        let issuer = required("OIDC_ISSUER")?;
        let audience = required("OIDC_AUDIENCE")?;
        let jwks_uri = required("OIDC_JWKS_URI")?;
        let tenant_claim = optional("OIDC_TENANT_CLAIM", "tenant_id")?;

        for (name, value) in [("OIDC_ISSUER", &issuer), ("OIDC_JWKS_URI", &jwks_uri)] {
            validate_identity_url(environment, name, value)?;
        }

        Ok(Self {
            issuer,
            audience,
            jwks_uri,
            tenant_claim,
            leeway: seconds("OIDC_LEEWAY_SECS", 30)?,
            jwks_ttl: seconds("OIDC_JWKS_TTL_SECS", 300)?,
            jwks_timeout: seconds("OIDC_JWKS_TIMEOUT_SECS", 5)?,
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) => Err(ConfigError::Missing(name)),
        Err(env::VarError::NotPresent) => Err(ConfigError::Missing(name)),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid {
            name,
            reason: "value is not valid UTF-8".into(),
        }),
    }
}

/// Validate one OIDC URL against the environment's transport requirement.
///
/// Kept separate from [`IdentityConfig::from_env`] so the rule is testable
/// without mutating process-wide environment variables.
fn validate_identity_url(
    environment: AppEnvironment,
    name: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    if !(value.starts_with("https://") || value.starts_with("http://")) {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be an absolute http(s) URL".into(),
        });
    }
    if !environment.is_development() && !value.starts_with("https://") {
        return Err(ConfigError::Invalid {
            name,
            reason: "must use https outside development".into(),
        });
    }
    Ok(())
}

fn optional(name: &'static str, default: &str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) => Ok(default.to_owned()),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid {
            name,
            reason: "value is not valid UTF-8".into(),
        }),
    }
}

fn number(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    let raw = optional(name, &default.to_string())?;
    raw.parse::<u64>().map_err(|err| ConfigError::Invalid {
        name,
        reason: err.to_string(),
    })
}

/// Filesystem path from the environment, or the supplied default.
///
/// Operators should set absolute paths for sandbox directories; the process
/// working directory is not a stable security boundary.
fn path(name: &'static str, default: &std::path::Path) -> PathBuf {
    match optional(name, &default.to_string_lossy()) {
        Ok(raw) => PathBuf::from(raw),
        Err(_) => default.to_path_buf(),
    }
}

fn seconds(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    let raw = optional(name, &default.to_string())?;
    let value = raw.parse::<u64>().map_err(|err| ConfigError::Invalid {
        name,
        reason: err.to_string(),
    })?;
    Ok(Duration::from_secs(value))
}

fn boolean(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    let raw = optional(name, if default { "true" } else { "false" })?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid {
            name,
            reason: "expected true/false".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_env_parser_is_exact_and_fails_closed() {
        assert!(matches!(
            AppEnvironment::parse("development"),
            Ok(AppEnvironment::Development)
        ));
        assert!(matches!(
            AppEnvironment::parse("  PROD "),
            Ok(AppEnvironment::Production)
        ));
        // A typo must not silently downgrade the deployment to development.
        assert!(AppEnvironment::parse("devlopment").is_err());
        assert!(AppEnvironment::parse("").is_err());
    }

    #[test]
    fn plaintext_oidc_is_only_accepted_in_development() {
        assert!(validate_identity_url(
            AppEnvironment::Development,
            "OIDC_ISSUER",
            "http://127.0.0.1:8080/realms/agentic"
        )
        .is_ok());
        assert!(validate_identity_url(
            AppEnvironment::Production,
            "OIDC_ISSUER",
            "http://idp.example.test/realms/agentic"
        )
        .is_err());
        assert!(validate_identity_url(
            AppEnvironment::Production,
            "OIDC_JWKS_URI",
            "https://idp.example.test/realms/agentic/certs"
        )
        .is_ok());
    }

    #[test]
    fn non_http_urls_are_rejected_in_every_environment() {
        for environment in [AppEnvironment::Development, AppEnvironment::Production] {
            assert!(
                validate_identity_url(environment, "OIDC_JWKS_URI", "file:///etc/passwd").is_err()
            );
        }
    }

    #[test]
    fn unknown_runtimes_are_rejected_rather_than_ignored() {
        assert_eq!(
            parse_runtimes("wasmtime").expect("valid"),
            vec![RuntimeKind::Wasmtime]
        );
        assert!(parse_runtimes("wasmtime,docker").is_err());
    }
}
