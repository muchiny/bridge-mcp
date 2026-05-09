// The 337-handler vec! in create_filtered_registry exceeds 16 KiB on the stack
// during test compilation; suppress this lint for test builds.
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

// Alias the current crate under its own name so the `#[mcp_tool]`
// proc macro (defined in `mcp-ssh-bridge-macros`) can emit fully-
// qualified paths like `::mcp_ssh_bridge::mcp::registry::…` that
// resolve both from within this crate AND from downstream crates.
extern crate self as mcp_ssh_bridge;

// Use mimalloc allocator when the feature is enabled (recommended for musl builds)
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Re-export the `inventory` crate so code produced by the
/// `#[mcp_tool]` proc macro can reference it via a fully-qualified
/// path (`::mcp_ssh_bridge::inventory::submit!`) without requiring
/// callers to add `inventory` to their own `Cargo.toml`.
pub use ::inventory;

/// Re-export the `#[mcp_tool]` and `#[mcp_standard_tool]` attribute
/// macros so handler files only need
/// `use mcp_ssh_bridge::{mcp_tool, mcp_standard_tool};`.
pub use mcp_ssh_bridge_macros::{mcp_standard_tool, mcp_tool};

#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
#[cfg(feature = "cli")]
pub mod daemon;
pub mod domain;
pub mod error;
pub mod mcp;
pub mod metrics;
pub mod path_utils;
pub mod ports;
pub mod security;
pub mod ssh;
pub mod telemetry;

#[cfg(any(feature = "azure", feature = "gcp"))]
pub mod cloud_exec;
#[cfg(feature = "k8s-exec")]
pub mod k8s_exec;
#[cfg(feature = "psrp")]
pub mod psrp;
#[cfg(feature = "serial")]
pub mod serial_port;
#[cfg(feature = "ssm")]
pub mod ssm;
#[cfg(feature = "telnet")]
pub mod telnet;
#[cfg(feature = "winrm")]
pub mod winrm;

pub use config::Config;
pub use error::{BridgeError, Result};
pub use mcp::McpServer;
pub use ports::{
    ExecutorRouter, RemoteExecutor, SshExecutor, ToolAnnotations, ToolContext, ToolHandler,
    ToolSchema,
};
pub use security::{AuditLogger, Sanitizer};

// Re-exports for fuzzing
#[doc(hidden)]
pub use config::{HostConfig, SecurityConfig};
#[doc(hidden)]
pub use domain::output_truncator::{ceil_char_boundary, floor_char_boundary, truncate_output};
#[doc(hidden)]
pub use domain::use_cases::ansible::AnsibleCommandBuilder;
#[doc(hidden)]
pub use domain::use_cases::kubernetes::{
    HelmCommandBuilder, KubernetesCommandBuilder, helm_detect_prefix, kubectl_detect_prefix,
};
#[doc(hidden)]
pub use domain::use_cases::parse_metrics::{parse_cpu, parse_disk, parse_load, parse_memory};
#[doc(hidden)]
pub use mcp::protocol::{JsonRpcRequest, ToolCallParams};
#[doc(hidden)]
pub use security::{AuditEvent, CommandResult, CommandValidator, RateLimiter};
#[doc(hidden)]
pub use ssh::TransferMode;
// Protocol types for fuzzing (MCP Tasks + Completions + Logging + Elicitation + Sampling)
#[doc(hidden)]
pub use mcp::protocol::{
    CompletionsCompleteParams, ElicitationCreateParams, InitializeParams, LoggingSetLevelParams,
    PromptsGetParams, ResourcesReadParams, SamplingCreateMessageParams, TaskCancelParams,
    TaskGetParams, TaskListParams, TaskRequest, TaskResultParams,
};
