//! Tool Registry
//!
//! This module provides a registry for tool handlers, enabling
//! dynamic registration and lookup of tools at runtime.
//!
//! # Inventory-backed auto-registration (Sprint 3 Phase C)
//!
//! Handler files can annotate their struct with
//! `#[mcp_tool(name, group, annotation)]` to auto-register via the
//! `inventory` crate. The macro emits an `inventory::submit!` call
//! producing a [`ToolRegistryEntry`] that [`create_filtered_registry`],
//! [`tool_group`], and [`tool_annotations`] read as a fallback
//! *before* consulting the legacy match tables. Handlers that have
//! not been migrated yet continue to work through the legacy
//! tables, so migration is incremental and safe.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde_json::{Value, json};

use crate::config::ToolGroupsConfig;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{Tool, ToolAnnotations, ToolCallResult, ToolExecution};
#[cfg(test)]
use crate::ports::ToolSchema;
use crate::ports::{ToolContext, ToolHandler};

/// Annotation kind surfaced by a handler.
///
/// Maps 1-to-1 to the three factory methods on
/// [`crate::mcp::protocol::ToolAnnotations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAnnotationKind {
    /// Read-only; can run in parallel, no side effects.
    ReadOnly,
    /// Mutating; modifies state on the remote host.
    Mutating,
    /// Mutating but convergent — repeating the same call leaves the
    /// system in the same final state (e.g. `kubectl apply`,
    /// `systemctl restart`, `nginx reload`).
    MutatingIdempotent,
    /// Destructive; irreversible side effects (rm -rf, drop table).
    Destructive,
}

impl ToolAnnotationKind {
    /// Materialize this kind as a full [`ToolAnnotations`] with the
    /// handler name as the title. Matches what the legacy
    /// [`tool_annotations`] function returned by hand.
    #[must_use]
    pub fn into_annotations(self, tool_name: &str) -> ToolAnnotations {
        match self {
            Self::ReadOnly => ToolAnnotations::read_only(tool_name),
            Self::Mutating => ToolAnnotations::mutating(tool_name),
            Self::MutatingIdempotent => ToolAnnotations::mutating_idempotent(tool_name),
            Self::Destructive => ToolAnnotations::destructive(tool_name),
        }
    }
}

/// Registration entry produced by the `#[mcp_tool]` proc macro.
///
/// The `factory` function builds a boxed handler on demand; it is a
/// `fn` pointer so it can be stored in an `inventory` static table.
pub struct ToolRegistryEntry {
    pub name: &'static str,
    pub group: &'static str,
    pub annotation_kind: ToolAnnotationKind,
    pub factory: fn() -> Arc<dyn ToolHandler>,
}

inventory::collect!(ToolRegistryEntry);

/// Global (lazy) cache of `name -> group` for inventory-registered
/// tools. Built on first call and reused for the life of the process.
fn inventory_group_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for entry in inventory::iter::<ToolRegistryEntry>() {
            m.insert(entry.name, entry.group);
        }
        m
    })
}

/// Global (lazy) cache of `name -> ToolAnnotationKind` for
/// inventory-registered tools.
fn inventory_annotation_map() -> &'static HashMap<&'static str, ToolAnnotationKind> {
    static MAP: OnceLock<HashMap<&'static str, ToolAnnotationKind>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for entry in inventory::iter::<ToolRegistryEntry>() {
            m.insert(entry.name, entry.annotation_kind);
        }
        m
    })
}

/// Registry for tool handlers
///
/// The registry maintains a collection of tool handlers and provides
/// methods for registering, looking up, and listing available tools.
#[derive(Default)]
pub struct ToolRegistry {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl ToolRegistry {
    /// Create a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a tool handler
    pub fn register(&mut self, handler: Arc<dyn ToolHandler>) {
        let name = handler.name().to_string();
        self.handlers.insert(name, handler);
    }

    /// Get a tool handler by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn ToolHandler>> {
        self.handlers.get(name)
    }

    /// Execute a tool by name
    ///
    /// # Errors
    ///
    /// Returns an error if the tool is not found or if the tool execution fails.
    pub async fn execute(
        &self,
        tool_name: &str,
        args: Option<serde_json::Value>,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let handler = self
            .get(tool_name)
            .ok_or_else(|| BridgeError::McpUnknownTool {
                tool: tool_name.to_string(),
            })?;

        handler.execute(args, ctx).await
    }

    /// Get all registered tools as MCP Tool definitions
    #[must_use]
    pub fn list_tools(&self) -> Vec<Tool> {
        self.handlers
            .values()
            .map(|handler| {
                let schema = handler.schema();
                let annotations = tool_annotations(schema.name);
                let mut input_schema: Value = serde_json::from_str(schema.input_schema)
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            tool = schema.name,
                            error = %e,
                            "Invalid tool input schema JSON, falling back to empty schema"
                        );
                        json!({})
                    });

                // Inject data reduction params based on output kind
                inject_reduction_schema(&mut input_schema, handler.output_kind());

                Tool {
                    name: schema.name.to_string(),
                    description: schema.description.to_string(),
                    input_schema,
                    annotations: if annotations.is_empty() {
                        None
                    } else {
                        Some(annotations)
                    },
                    execution: Some(ToolExecution {
                        task_support: "optional".to_string(),
                    }),
                    output_schema: handler.output_schema(),
                    icons: tool_icons(schema.name),
                    meta: tool_meta(schema.name),
                }
            })
            .collect()
    }

    /// Get the number of registered tools
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Inject data-reduction parameters into a tool's JSON schema based on its
/// [`crate::domain::output_kind::OutputKind`].
///
/// - `Json` → `jq_filter` + `output_format`
/// - `Tabular` → `columns`
/// - `Yaml` → `yq_filter` + `output_format`
/// - `Auto` → `jq_filter` + `columns` + `output_format`
/// - `RawText` → nothing
///
/// All `Json`/`Yaml`/`Auto` tools also accept `limit`.
pub fn inject_reduction_schema(schema: &mut Value, kind: crate::domain::output_kind::OutputKind) {
    use crate::domain::output_kind::OutputKind;

    let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };

    if kind.supports_jq() {
        props.insert(
            "jq_filter".to_string(),
            json!({
                "type": "string",
                "description": "RECOMMENDED: jq expression applied server-side to JSON output \
                    before returning to reduce token consumption. Always extract only the fields \
                    you need. Examples: '.[] | {name, status}' (select fields), \
                    '.items[0:5]' (first 5 items), \
                    '[.items[] | {name: .metadata.name}]' (K8s pod names). \
                    For minimal token usage, return arrays and combine with output_format='tsv': \
                    '.[] | [.name, .status]' + output_format='tsv'. \
                    Only works when command output is valid JSON."
            }),
        );
    }

    if kind.supports_yq() {
        props.insert(
            "yq_filter".to_string(),
            json!({
                "type": "string",
                "description": "RECOMMENDED: jq-syntax expression applied server-side to YAML \
                    output (parsed via serde-saphyr to a generic value tree). Same syntax as \
                    jq_filter. Use this when the underlying command produces YAML \
                    (e.g., kubectl/helm/ansible-navigator with yaml output). \
                    Combine with output_format='tsv' for minimal tokens: \
                    '.all.children.webservers.hosts | keys' + output_format='tsv'."
            }),
        );
    }

    if kind.supports_columns() {
        props.insert(
            "columns".to_string(),
            json!({
                "type": "array",
                "items": {"type": "string"},
                "description": "RECOMMENDED: Filter output to only the columns you need to \
                    reduce token consumption. Case-insensitive header match. Always specify \
                    this when you don't need all columns. Example: [\"NAME\", \"STATUS\"]. \
                    Unknown columns are silently ignored."
            }),
        );
    }

    if kind.supports_limit() {
        props.insert(
            "limit".to_string(),
            json!({
                "type": "integer",
                "minimum": 1,
                "description": "RECOMMENDED: Maximum number of items to return. \
                    For tabular output: caps data rows (header always kept). \
                    For JSON output: caps top-level array elements. \
                    Use this to reduce token consumption when you only need the top N results. \
                    Example: limit=10 returns only 10 rows/items."
            }),
        );
    }

    if kind.supports_jq() || kind.supports_yq() {
        props.insert(
            "output_format".to_string(),
            json!({
                "type": "string",
                "enum": ["json", "tsv"],
                "description": "Output serialization for jq_filter/yq_filter results. \
                    Default 'json' returns the jq result as JSON. \
                    'tsv' joins each result row with tabs (and rows with newlines) for \
                    maximum token efficiency. To use TSV, your filter MUST produce arrays \
                    (e.g., '.[] | [.name, .status]'). Objects work too but the field order \
                    is alphabetical. Token savings: ~60-80% on tabular data."
            }),
        );
    }

    // RawText: nothing injected
    let _ = kind == OutputKind::RawText;
}

/// Map a tool name to its group.
///
/// Tools are organized into logical groups that can be enabled/disabled
/// via the `tool_groups` configuration to reduce MCP context.
///
/// **Sprint 3 Phase C — pure inventory lookup.** Every handler is
/// registered via `#[mcp_tool(group = "…")]` or
/// `#[mcp_standard_tool(group = "…")]`, which emits an
/// `inventory::submit!` that this function consults. Tool names not
/// found in the inventory fall back to `"core"` to preserve the
/// legacy catch-all behavior for unknown names.
#[must_use]
pub fn tool_group(tool_name: &str) -> &'static str {
    inventory_group_map()
        .get(tool_name)
        .copied()
        .unwrap_or("core")
}

/// Return MCP annotations for a tool (MCP 2025-03-26+).
///
/// Annotations provide behavioral hints to MCP clients. Claude Code uses
/// `readOnlyHint` to enable parallel execution and skip confirmation, and
/// `destructiveHint` to trigger confirmation dialogs.
///
/// **Sprint 3 Phase C — pure inventory lookup.** Every handler is
/// registered via `#[mcp_tool(annotation = "…")]` or
/// `#[mcp_standard_tool(annotation = "…")]`, which emits an
/// `inventory::submit!` carrying the annotation kind. Unknown names
/// fall through to the empty `ToolAnnotations::default()`, matching
/// the legacy "match fall-through" behavior.
#[must_use]
pub fn tool_annotations(tool_name: &str) -> ToolAnnotations {
    inventory_annotation_map()
        .get(tool_name)
        .copied()
        .map_or_else(
            // Unknown tool name → empty annotations (preserves the
            // previous "fall through the match → default" behavior
            // that `test_unknown_tool_returns_empty_annotations`
            // depends on).
            ToolAnnotations::default,
            |kind| kind.into_annotations(tool_name),
        )
}

/// Returns `_meta` hints for tools known to produce large output.
///
/// Claude Code uses `anthropic/maxResultSizeChars` to raise its
/// default 25K-token persist threshold (up to 500K chars).
#[must_use]
pub fn tool_meta(tool_name: &str) -> Option<Value> {
    const LARGE: usize = 200_000;
    match tool_name {
        // Core (arbitrary commands), file ops, containers, Kubernetes,
        // journald/logs, databases, Windows events, pagination
        "ssh_exec"
        | "ssh_exec_multi"
        | "ssh_pty_exec"
        | "ssh_file_read"
        | "ssh_tail"
        | "ssh_docker_logs"
        | "ssh_podman_logs"
        | "ssh_container_log_search"
        | "ssh_container_log_stats"
        | "ssh_k8s_get"
        | "ssh_k8s_describe"
        | "ssh_k8s_logs"
        | "ssh_helm_status"
        | "ssh_helm_history"
        | "ssh_journal_query"
        | "ssh_journal_follow"
        | "ssh_service_logs"
        | "ssh_log_search_multi"
        | "ssh_log_tail_multi"
        | "ssh_log_aggregate"
        | "ssh_db_dump"
        | "ssh_mysql_query"
        | "ssh_postgresql_query"
        | "ssh_win_event_query"
        | "ssh_win_event_tail"
        | "ssh_win_event_export"
        | "ssh_output_fetch" => Some(json!({
            "anthropic/maxResultSizeChars": LARGE
        })),
        _ => None,
    }
}

/// Base URL for committed group icons (SEP-973).
///
/// Per-group SVGs live under `dxt/icons/<group>.svg` and are served raw from
/// GitHub `main`. Clients fetch lazily and tolerate a 404, so an unmapped or
/// not-yet-authored group simply renders without an icon.
const ICON_BASE_URL: &str = "https://raw.githubusercontent.com/muchini/bridge-mcp/main/dxt/icons";

/// Return the icon for a tool group, or `None` for groups without a curated
/// icon. The curated subset can grow without touching any test (the tests only
/// assert mapped groups serialize an icon and unmapped groups omit it).
#[must_use]
pub fn group_icon(group: &str) -> Option<crate::mcp::protocol::Icon> {
    let slug = match group {
        "docker" | "podman" => "docker",
        "kubernetes" => "kubernetes",
        "systemd" | "systemd_timers" => "systemd",
        "database" | "redis" | "postgresql" | "mysql" | "mongodb" => "database",
        "nginx" | "apache" => "webserver",
        "git" => "git",
        "vault" => "vault",
        "terraform" => "terraform",
        "cloud" | "multicloud" => "cloud",
        _ => return None,
    };
    Some(crate::mcp::protocol::Icon {
        src: format!("{ICON_BASE_URL}/{slug}.svg"),
        mime_type: Some("image/svg+xml".to_string()),
        sizes: Some(vec!["any".to_string()]),
        theme: None,
    })
}

/// Return SEP-973 icons for a tool, resolved through its group. Tools whose
/// group has no curated icon return `None` so the `icons` field is omitted.
#[must_use]
pub fn tool_icons(tool_name: &str) -> Option<Vec<crate::mcp::protocol::Icon>> {
    group_icon(tool_group(tool_name)).map(|icon| vec![icon])
}

/// Create a registry with the default tool group profile
/// (FIND-024: 8 minimal-profile groups; everything else is opt-in).
#[must_use]
pub fn create_default_registry() -> ToolRegistry {
    create_filtered_registry(&ToolGroupsConfig::default())
}

/// Create a registry with EVERY tool group enabled — the pre-FIND-024 default.
///
/// Use only for tests that need to exercise the full inventory (e.g.
/// pagination, group dispatch, default-list assertions). Production code must
/// always use [`create_filtered_registry`] with the operator's `ToolGroupsConfig`.
#[must_use]
#[doc(hidden)]
pub fn create_all_enabled_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for entry in inventory::iter::<ToolRegistryEntry>() {
        registry.register((entry.factory)());
    }
    registry
}

/// Build a `ToolGroupsConfig` that explicitly enables every group registered
/// via `#[mcp_tool]` / `#[mcp_standard_tool]` — the pre-FIND-024 default.
///
/// Use only for tests that need to exercise the full handler inventory
/// (e.g. pagination, group dispatch, all-tools-present assertions).
/// Production code must always use the operator-supplied `ToolGroupsConfig`.
#[must_use]
#[doc(hidden)]
pub fn all_enabled_tool_groups_config_for_test() -> ToolGroupsConfig {
    let mut groups = HashMap::new();
    for entry in inventory::iter::<ToolRegistryEntry>() {
        groups.insert(entry.group.to_string(), true);
    }
    ToolGroupsConfig { groups }
}

/// Create a registry filtered by the tool groups configuration.
///
/// Only tools whose group is enabled in the config will be registered.
///
/// **Sprint 3 Phase C — pure inventory loop.** Every handler is
/// registered via the `#[mcp_tool]` / `#[mcp_standard_tool]` proc
/// macro in its source file, which emits an `inventory::submit!` that
/// this function walks at startup. No legacy manual `Vec` anymore.
#[must_use]
pub fn create_filtered_registry(tool_groups: &ToolGroupsConfig) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for entry in inventory::iter::<ToolRegistryEntry>() {
        if tool_groups.is_group_enabled(entry.group) {
            registry.register((entry.factory)());
        }
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::mcp::protocol::ToolCallResult;
    use crate::ports::ToolContext;
    use crate::ports::mock::create_test_context;
    use async_trait::async_trait;

    struct TestHandler;

    #[async_trait]
    impl ToolHandler for TestHandler {
        fn name(&self) -> &'static str {
            "test_tool"
        }

        fn description(&self) -> &'static str {
            "A test tool"
        }

        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: "test_tool",
                description: "A test tool",
                input_schema: r#"{"type": "object", "properties": {}}"#,
            }
        }

        async fn execute(
            &self,
            _args: Option<serde_json::Value>,
            _ctx: &ToolContext,
        ) -> Result<ToolCallResult> {
            Ok(ToolCallResult::text("test result"))
        }
    }

    /// Total number of tools registered via the `#[mcp_tool]` /
    /// `#[mcp_standard_tool]` inventory. Computed once per test binary
    /// from `inventory::iter()` so the assertions don't need to be
    /// kept in sync with an ever-growing static number.
    fn all_tools_count() -> usize {
        inventory::iter::<ToolRegistryEntry>().count()
    }

    /// Number of tools that belong to `group`. Used by disable-group
    /// tests to assert `create_filtered_registry` correctly omits
    /// them.
    fn group_size(group: &str) -> usize {
        inventory::iter::<ToolRegistryEntry>()
            .filter(|e| e.group == group)
            .count()
    }

    #[test]
    fn test_register_and_get() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));

        assert!(registry.get("test_tool").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_list_tools() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));

        let tools = registry.list_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "test_tool");
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(Arc::new(TestHandler));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_enabled_registry_has_all_tools() {
        // FIND-024: `create_default_registry()` now returns the minimal
        // 8-group profile. This test exists to verify that every handler
        // declared via `#[mcp_tool]` / `#[mcp_standard_tool]` is present
        // when ALL groups are enabled, so we use `create_all_enabled_registry()`.
        let registry = create_all_enabled_registry();
        assert_eq!(registry.len(), all_tools_count());
        // Core
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_exec_multi").is_some());
        assert!(registry.get("ssh_status").is_some());
        assert!(registry.get("ssh_history").is_some());
        assert!(registry.get("ssh_health").is_some());
        assert!(registry.get("ssh_output_fetch").is_some());
        // Monitoring
        assert!(registry.get("ssh_metrics").is_some());
        assert!(registry.get("ssh_metrics_multi").is_some());
        assert!(registry.get("ssh_tail").is_some());
        // File transfer
        assert!(registry.get("ssh_upload").is_some());
        assert!(registry.get("ssh_download").is_some());
        assert!(registry.get("ssh_sync").is_some());
        // Sessions
        assert!(registry.get("ssh_session_create").is_some());
        assert!(registry.get("ssh_session_exec").is_some());
        assert!(registry.get("ssh_session_list").is_some());
        assert!(registry.get("ssh_session_close").is_some());
        // Tunnels
        assert!(registry.get("ssh_tunnel_create").is_some());
        assert!(registry.get("ssh_tunnel_list").is_some());
        assert!(registry.get("ssh_tunnel_close").is_some());
        // Directory
        assert!(registry.get("ssh_ls").is_some());
        assert!(registry.get("ssh_find").is_some());
        // Monitoring extra
        assert!(registry.get("ssh_disk_usage").is_some());
        // Database
        assert!(registry.get("ssh_db_query").is_some());
        assert!(registry.get("ssh_db_dump").is_some());
        assert!(registry.get("ssh_db_restore").is_some());
        // Backup
        assert!(registry.get("ssh_backup_create").is_some());
        assert!(registry.get("ssh_backup_list").is_some());
        assert!(registry.get("ssh_backup_restore").is_some());
        // Docker
        assert!(registry.get("ssh_docker_ps").is_some());
        assert!(registry.get("ssh_docker_logs").is_some());
        assert!(registry.get("ssh_docker_inspect").is_some());
        assert!(registry.get("ssh_docker_exec").is_some());
        assert!(registry.get("ssh_docker_compose").is_some());
        assert!(registry.get("ssh_docker_images").is_some());
        assert!(registry.get("ssh_docker_stats").is_some());
        assert!(registry.get("ssh_docker_volume_ls").is_some());
        assert!(registry.get("ssh_docker_network_ls").is_some());
        assert!(registry.get("ssh_docker_volume_inspect").is_some());
        assert!(registry.get("ssh_docker_network_inspect").is_some());
        // ESXi
        assert!(registry.get("ssh_esxi_vm_list").is_some());
        assert!(registry.get("ssh_esxi_vm_info").is_some());
        assert!(registry.get("ssh_esxi_vm_power").is_some());
        assert!(registry.get("ssh_esxi_snapshot").is_some());
        assert!(registry.get("ssh_esxi_host_info").is_some());
        assert!(registry.get("ssh_esxi_datastore_list").is_some());
        assert!(registry.get("ssh_esxi_network_list").is_some());
        // Git
        assert!(registry.get("ssh_git_status").is_some());
        assert!(registry.get("ssh_git_log").is_some());
        assert!(registry.get("ssh_git_diff").is_some());
        assert!(registry.get("ssh_git_pull").is_some());
        assert!(registry.get("ssh_git_clone").is_some());
        assert!(registry.get("ssh_git_branch").is_some());
        assert!(registry.get("ssh_git_checkout").is_some());
        // Kubernetes (kubectl)
        assert!(registry.get("ssh_k8s_get").is_some());
        assert!(registry.get("ssh_k8s_logs").is_some());
        assert!(registry.get("ssh_k8s_describe").is_some());
        assert!(registry.get("ssh_k8s_apply").is_some());
        assert!(registry.get("ssh_k8s_delete").is_some());
        assert!(registry.get("ssh_k8s_rollout").is_some());
        assert!(registry.get("ssh_k8s_scale").is_some());
        assert!(registry.get("ssh_k8s_exec").is_some());
        assert!(registry.get("ssh_k8s_top").is_some());
        // Kubernetes (helm)
        assert!(registry.get("ssh_helm_list").is_some());
        assert!(registry.get("ssh_helm_status").is_some());
        assert!(registry.get("ssh_helm_upgrade").is_some());
        assert!(registry.get("ssh_helm_install").is_some());
        assert!(registry.get("ssh_helm_rollback").is_some());
        assert!(registry.get("ssh_helm_history").is_some());
        assert!(registry.get("ssh_helm_uninstall").is_some());
        // Ansible
        assert!(registry.get("ssh_ansible_playbook").is_some());
        assert!(registry.get("ssh_ansible_inventory").is_some());
        assert!(registry.get("ssh_ansible_adhoc").is_some());
        assert!(registry.get("ssh_ansible_config").is_some());
        assert!(registry.get("ssh_ansible_facts").is_some());
        assert!(registry.get("ssh_ansible_lint").is_some());
        assert!(registry.get("ssh_ansible_recap").is_some());
        assert!(registry.get("ssh_ansible_events").is_some());
        assert!(registry.get("ssh_ansible_run_background").is_some());
        // AWX
        assert!(registry.get("ssh_awx_status").is_some());
        assert!(registry.get("ssh_awx_templates").is_some());
        assert!(registry.get("ssh_awx_template_detail").is_some());
        assert!(registry.get("ssh_awx_job_launch").is_some());
        assert!(registry.get("ssh_awx_job_status").is_some());
        assert!(registry.get("ssh_awx_job_events").is_some());
        assert!(registry.get("ssh_awx_job_summary").is_some());
        assert!(registry.get("ssh_awx_job_stdout").is_some());
        assert!(registry.get("ssh_awx_job_cancel").is_some());
        assert!(registry.get("ssh_awx_inventories").is_some());
        assert!(registry.get("ssh_awx_inventory_hosts").is_some());
        assert!(registry.get("ssh_awx_project_sync").is_some());
        assert!(registry.get("ssh_awx_job_follow").is_some());
        // Systemd
        assert!(registry.get("ssh_service_status").is_some());
        assert!(registry.get("ssh_service_start").is_some());
        assert!(registry.get("ssh_service_stop").is_some());
        assert!(registry.get("ssh_service_restart").is_some());
        assert!(registry.get("ssh_service_list").is_some());
        assert!(registry.get("ssh_service_logs").is_some());
        assert!(registry.get("ssh_service_enable").is_some());
        assert!(registry.get("ssh_service_disable").is_some());
        assert!(registry.get("ssh_service_daemon_reload").is_some());
        // Network
        assert!(registry.get("ssh_net_connections").is_some());
        assert!(registry.get("ssh_net_interfaces").is_some());
        assert!(registry.get("ssh_net_routes").is_some());
        assert!(registry.get("ssh_net_ping").is_some());
        assert!(registry.get("ssh_net_traceroute").is_some());
        assert!(registry.get("ssh_net_dns").is_some());
        // Process
        assert!(registry.get("ssh_process_list").is_some());
        assert!(registry.get("ssh_process_kill").is_some());
        assert!(registry.get("ssh_process_top").is_some());
        // Package
        assert!(registry.get("ssh_pkg_list").is_some());
        assert!(registry.get("ssh_pkg_search").is_some());
        assert!(registry.get("ssh_pkg_install").is_some());
        assert!(registry.get("ssh_pkg_update").is_some());
        assert!(registry.get("ssh_pkg_remove").is_some());
        // Firewall
        assert!(registry.get("ssh_firewall_status").is_some());
        assert!(registry.get("ssh_firewall_list").is_some());
        assert!(registry.get("ssh_firewall_allow").is_some());
        assert!(registry.get("ssh_firewall_deny").is_some());
        // Cron
        assert!(registry.get("ssh_cron_list").is_some());
        assert!(registry.get("ssh_cron_add").is_some());
        assert!(registry.get("ssh_cron_remove").is_some());
        // Certificates
        assert!(registry.get("ssh_cert_check").is_some());
        assert!(registry.get("ssh_cert_info").is_some());
        assert!(registry.get("ssh_cert_expiry").is_some());
        // Nginx
        assert!(registry.get("ssh_nginx_status").is_some());
        assert!(registry.get("ssh_nginx_test").is_some());
        assert!(registry.get("ssh_nginx_reload").is_some());
        assert!(registry.get("ssh_nginx_list_sites").is_some());
        // Diagnostics
        assert!(registry.get("ssh_diagnose").is_some());
        assert!(registry.get("ssh_incident_triage").is_some());
        assert!(registry.get("ssh_compare_state").is_some());
        // Orchestration
        assert!(registry.get("ssh_canary_exec").is_some());
        assert!(registry.get("ssh_rolling_exec").is_some());
        assert!(registry.get("ssh_fleet_diff").is_some());
        // Runbooks
        assert!(registry.get("ssh_runbook_list").is_some());
        assert!(registry.get("ssh_runbook_execute").is_some());
        assert!(registry.get("ssh_runbook_validate").is_some());
        // Recording
        assert!(registry.get("ssh_recording_start").is_some());
        assert!(registry.get("ssh_recording_stop").is_some());
        assert!(registry.get("ssh_recording_list").is_some());
        assert!(registry.get("ssh_recording_replay").is_some());
        assert!(registry.get("ssh_recording_verify").is_some());
        // Redis
        assert!(registry.get("ssh_redis_info").is_some());
        assert!(registry.get("ssh_redis_cli").is_some());
        assert!(registry.get("ssh_redis_keys").is_some());
        // PostgreSQL
        assert!(registry.get("ssh_postgresql_query").is_some());
        assert!(registry.get("ssh_postgresql_status").is_some());
        // MySQL
        assert!(registry.get("ssh_mysql_query").is_some());
        assert!(registry.get("ssh_mysql_status").is_some());
        // Apache
        assert!(registry.get("ssh_apache_status").is_some());
        assert!(registry.get("ssh_apache_vhosts").is_some());
        // Let's Encrypt
        assert!(registry.get("ssh_letsencrypt_status").is_some());
        // MongoDB
        assert!(registry.get("ssh_mongodb_status").is_some());
        // Terraform
        assert!(registry.get("ssh_terraform_init").is_some());
        assert!(registry.get("ssh_terraform_plan").is_some());
        assert!(registry.get("ssh_terraform_apply").is_some());
        assert!(registry.get("ssh_terraform_state").is_some());
        assert!(registry.get("ssh_terraform_output").is_some());
        // Vault
        assert!(registry.get("ssh_vault_status").is_some());
        assert!(registry.get("ssh_vault_read").is_some());
        assert!(registry.get("ssh_vault_list").is_some());
        assert!(registry.get("ssh_vault_write").is_some());
        // Config
        assert!(registry.get("ssh_config_get").is_some());
        assert!(registry.get("ssh_config_set").is_some());
        // Windows Services
        assert!(registry.get("ssh_win_service_status").is_some());
        assert!(registry.get("ssh_win_service_start").is_some());
        assert!(registry.get("ssh_win_service_stop").is_some());
        assert!(registry.get("ssh_win_service_restart").is_some());
        assert!(registry.get("ssh_win_service_list").is_some());
        assert!(registry.get("ssh_win_service_enable").is_some());
        assert!(registry.get("ssh_win_service_disable").is_some());
        assert!(registry.get("ssh_win_service_config").is_some());
        assert!(registry.get("ssh_win_event_logs").is_some());
        // Windows Events
        assert!(registry.get("ssh_win_event_query").is_some());
        assert!(registry.get("ssh_win_event_sources").is_some());
        assert!(registry.get("ssh_win_event_tail").is_some());
        assert!(registry.get("ssh_win_event_export").is_some());
        // Active Directory
        assert!(registry.get("ssh_ad_user_list").is_some());
        assert!(registry.get("ssh_ad_user_info").is_some());
        assert!(registry.get("ssh_ad_group_list").is_some());
        assert!(registry.get("ssh_ad_group_members").is_some());
        assert!(registry.get("ssh_ad_computer_list").is_some());
        assert!(registry.get("ssh_ad_domain_info").is_some());
        // Scheduled Tasks
        assert!(registry.get("ssh_schtask_list").is_some());
        assert!(registry.get("ssh_schtask_info").is_some());
        assert!(registry.get("ssh_schtask_run").is_some());
        assert!(registry.get("ssh_schtask_enable").is_some());
        assert!(registry.get("ssh_schtask_disable").is_some());
        // Windows Firewall
        assert!(registry.get("ssh_win_firewall_status").is_some());
        assert!(registry.get("ssh_win_firewall_list").is_some());
        assert!(registry.get("ssh_win_firewall_allow").is_some());
        assert!(registry.get("ssh_win_firewall_deny").is_some());
        assert!(registry.get("ssh_win_firewall_remove").is_some());
        // IIS
        assert!(registry.get("ssh_iis_status").is_some());
        assert!(registry.get("ssh_iis_list_sites").is_some());
        assert!(registry.get("ssh_iis_list_pools").is_some());
        assert!(registry.get("ssh_iis_start").is_some());
        assert!(registry.get("ssh_iis_stop").is_some());
        assert!(registry.get("ssh_iis_restart").is_some());
        // Windows Updates
        assert!(registry.get("ssh_win_update_list").is_some());
        assert!(registry.get("ssh_win_update_history").is_some());
        assert!(registry.get("ssh_win_update_install").is_some());
        assert!(registry.get("ssh_win_update_search").is_some());
        assert!(registry.get("ssh_win_update_reboot").is_some());
        // Windows Performance
        assert!(registry.get("ssh_win_perf_cpu").is_some());
        assert!(registry.get("ssh_win_perf_memory").is_some());
        assert!(registry.get("ssh_win_perf_disk").is_some());
        assert!(registry.get("ssh_win_perf_network").is_some());
        assert!(registry.get("ssh_win_perf_overview").is_some());
        // Hyper-V
        assert!(registry.get("ssh_hyperv_vm_list").is_some());
        assert!(registry.get("ssh_hyperv_vm_info").is_some());
        assert!(registry.get("ssh_hyperv_vm_start").is_some());
        assert!(registry.get("ssh_hyperv_vm_stop").is_some());
        assert!(registry.get("ssh_hyperv_snapshot_list").is_some());
        assert!(registry.get("ssh_hyperv_snapshot_create").is_some());
        assert!(registry.get("ssh_hyperv_host_info").is_some());
        assert!(registry.get("ssh_hyperv_switch_list").is_some());
        // Windows Registry
        assert!(registry.get("ssh_reg_query").is_some());
        assert!(registry.get("ssh_reg_set").is_some());
        assert!(registry.get("ssh_reg_list").is_some());
        assert!(registry.get("ssh_reg_export").is_some());
        assert!(registry.get("ssh_reg_delete").is_some());
        // Windows Features
        assert!(registry.get("ssh_win_feature_list").is_some());
        assert!(registry.get("ssh_win_feature_info").is_some());
        assert!(registry.get("ssh_win_feature_install").is_some());
        assert!(registry.get("ssh_win_feature_remove").is_some());
        // Windows Network
        assert!(registry.get("ssh_win_net_adapters").is_some());
        assert!(registry.get("ssh_win_net_ip").is_some());
        assert!(registry.get("ssh_win_net_routes").is_some());
        assert!(registry.get("ssh_win_net_connections").is_some());
        assert!(registry.get("ssh_win_net_ping").is_some());
        assert!(registry.get("ssh_win_net_dns").is_some());
        // Windows Process
        assert!(registry.get("ssh_win_process_list").is_some());
        assert!(registry.get("ssh_win_process_info").is_some());
        assert!(registry.get("ssh_win_process_kill").is_some());
        assert!(registry.get("ssh_win_process_top").is_some());
        assert!(registry.get("ssh_win_process_by_name").is_some());
        assert!(registry.get("ssh_win_disk_usage").is_some());
    }

    #[tokio::test]
    async fn test_execute_unknown_tool() {
        let registry = ToolRegistry::new();
        let ctx = create_test_context();
        let result = registry.execute("unknown", None, &ctx).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpUnknownTool { tool } => {
                assert_eq!(tool, "unknown");
            }
            e => panic!("Expected McpUnknownTool error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_execute_registered_tool() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));
        let ctx = create_test_context();

        let result = registry.execute("test_tool", None, &ctx).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_tool_group_mapping() {
        assert_eq!(tool_group("ssh_exec"), "core");
        assert_eq!(tool_group("ssh_exec_multi"), "core");
        assert_eq!(tool_group("ssh_status"), "core");
        assert_eq!(tool_group("ssh_health"), "core");
        assert_eq!(tool_group("ssh_history"), "core");
        assert_eq!(tool_group("ssh_output_fetch"), "core");
        assert_eq!(tool_group("ssh_upload"), "file_transfer");
        assert_eq!(tool_group("ssh_download"), "file_transfer");
        assert_eq!(tool_group("ssh_sync"), "file_transfer");
        assert_eq!(tool_group("ssh_session_create"), "sessions");
        assert_eq!(tool_group("ssh_session_exec"), "sessions");
        assert_eq!(tool_group("ssh_session_list"), "sessions");
        assert_eq!(tool_group("ssh_session_close"), "sessions");
        assert_eq!(tool_group("ssh_metrics"), "monitoring");
        assert_eq!(tool_group("ssh_metrics_multi"), "monitoring");
        assert_eq!(tool_group("ssh_tail"), "monitoring");
        assert_eq!(tool_group("ssh_tunnel_create"), "tunnels");
        assert_eq!(tool_group("ssh_tunnel_list"), "tunnels");
        assert_eq!(tool_group("ssh_tunnel_close"), "tunnels");
        assert_eq!(tool_group("ssh_ls"), "directory");
        assert_eq!(tool_group("ssh_find"), "directory");
        assert_eq!(tool_group("ssh_disk_usage"), "monitoring");
        assert_eq!(tool_group("ssh_db_query"), "database");
        assert_eq!(tool_group("ssh_db_dump"), "database");
        assert_eq!(tool_group("ssh_db_restore"), "database");
        assert_eq!(tool_group("ssh_backup_create"), "backup");
        assert_eq!(tool_group("ssh_backup_list"), "backup");
        assert_eq!(tool_group("ssh_backup_restore"), "backup");
        // Docker
        assert_eq!(tool_group("ssh_docker_ps"), "docker");
        assert_eq!(tool_group("ssh_docker_logs"), "docker");
        assert_eq!(tool_group("ssh_docker_inspect"), "docker");
        assert_eq!(tool_group("ssh_docker_exec"), "docker");
        assert_eq!(tool_group("ssh_docker_compose"), "docker");
        assert_eq!(tool_group("ssh_docker_images"), "docker");
        assert_eq!(tool_group("ssh_docker_stats"), "docker");
        assert_eq!(tool_group("ssh_docker_volume_ls"), "docker");
        assert_eq!(tool_group("ssh_docker_network_ls"), "docker");
        assert_eq!(tool_group("ssh_docker_volume_inspect"), "docker");
        assert_eq!(tool_group("ssh_docker_network_inspect"), "docker");
        // ESXi
        assert_eq!(tool_group("ssh_esxi_vm_list"), "esxi");
        assert_eq!(tool_group("ssh_esxi_vm_info"), "esxi");
        assert_eq!(tool_group("ssh_esxi_vm_power"), "esxi");
        assert_eq!(tool_group("ssh_esxi_snapshot"), "esxi");
        assert_eq!(tool_group("ssh_esxi_host_info"), "esxi");
        assert_eq!(tool_group("ssh_esxi_datastore_list"), "esxi");
        assert_eq!(tool_group("ssh_esxi_network_list"), "esxi");
        // Git
        assert_eq!(tool_group("ssh_git_status"), "git");
        assert_eq!(tool_group("ssh_git_log"), "git");
        assert_eq!(tool_group("ssh_git_diff"), "git");
        assert_eq!(tool_group("ssh_git_pull"), "git");
        assert_eq!(tool_group("ssh_git_clone"), "git");
        assert_eq!(tool_group("ssh_git_branch"), "git");
        assert_eq!(tool_group("ssh_git_checkout"), "git");
        // Kubernetes (kubectl)
        assert_eq!(tool_group("ssh_k8s_get"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_logs"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_describe"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_apply"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_delete"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_rollout"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_scale"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_exec"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_top"), "kubernetes");
        // Kubernetes (helm)
        assert_eq!(tool_group("ssh_helm_list"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_status"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_upgrade"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_install"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_rollback"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_history"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_uninstall"), "kubernetes");
        // Ansible
        assert_eq!(tool_group("ssh_ansible_playbook"), "ansible");
        assert_eq!(tool_group("ssh_ansible_inventory"), "ansible");
        assert_eq!(tool_group("ssh_ansible_adhoc"), "ansible");
        assert_eq!(tool_group("ssh_ansible_config"), "ansible");
        assert_eq!(tool_group("ssh_ansible_facts"), "ansible");
        assert_eq!(tool_group("ssh_ansible_lint"), "ansible");
        assert_eq!(tool_group("ssh_ansible_recap"), "ansible");
        assert_eq!(tool_group("ssh_ansible_events"), "ansible");
        assert_eq!(tool_group("ssh_ansible_run_background"), "ansible");
        // AWX
        assert_eq!(tool_group("ssh_awx_status"), "awx");
        assert_eq!(tool_group("ssh_awx_templates"), "awx");
        assert_eq!(tool_group("ssh_awx_template_detail"), "awx");
        assert_eq!(tool_group("ssh_awx_job_launch"), "awx");
        assert_eq!(tool_group("ssh_awx_job_status"), "awx");
        assert_eq!(tool_group("ssh_awx_job_events"), "awx");
        assert_eq!(tool_group("ssh_awx_job_summary"), "awx");
        assert_eq!(tool_group("ssh_awx_job_stdout"), "awx");
        assert_eq!(tool_group("ssh_awx_job_cancel"), "awx");
        assert_eq!(tool_group("ssh_awx_inventories"), "awx");
        assert_eq!(tool_group("ssh_awx_inventory_hosts"), "awx");
        assert_eq!(tool_group("ssh_awx_project_sync"), "awx");
        assert_eq!(tool_group("ssh_awx_job_follow"), "awx");
        // Systemd
        assert_eq!(tool_group("ssh_service_status"), "systemd");
        assert_eq!(tool_group("ssh_service_start"), "systemd");
        assert_eq!(tool_group("ssh_service_stop"), "systemd");
        assert_eq!(tool_group("ssh_service_restart"), "systemd");
        assert_eq!(tool_group("ssh_service_list"), "systemd");
        assert_eq!(tool_group("ssh_service_logs"), "systemd");
        assert_eq!(tool_group("ssh_service_enable"), "systemd");
        assert_eq!(tool_group("ssh_service_disable"), "systemd");
        assert_eq!(tool_group("ssh_service_daemon_reload"), "systemd");
        // Network
        assert_eq!(tool_group("ssh_net_connections"), "network");
        assert_eq!(tool_group("ssh_net_interfaces"), "network");
        assert_eq!(tool_group("ssh_net_routes"), "network");
        assert_eq!(tool_group("ssh_net_ping"), "network");
        assert_eq!(tool_group("ssh_net_traceroute"), "network");
        assert_eq!(tool_group("ssh_net_dns"), "network");
        // Process
        assert_eq!(tool_group("ssh_process_list"), "process");
        assert_eq!(tool_group("ssh_process_kill"), "process");
        assert_eq!(tool_group("ssh_process_top"), "process");
        // Package
        assert_eq!(tool_group("ssh_pkg_list"), "package");
        assert_eq!(tool_group("ssh_pkg_search"), "package");
        assert_eq!(tool_group("ssh_pkg_install"), "package");
        assert_eq!(tool_group("ssh_pkg_update"), "package");
        assert_eq!(tool_group("ssh_pkg_remove"), "package");
        // Firewall
        assert_eq!(tool_group("ssh_firewall_status"), "firewall");
        assert_eq!(tool_group("ssh_firewall_list"), "firewall");
        assert_eq!(tool_group("ssh_firewall_allow"), "firewall");
        assert_eq!(tool_group("ssh_firewall_deny"), "firewall");
        // Cron
        assert_eq!(tool_group("ssh_cron_list"), "cron");
        assert_eq!(tool_group("ssh_cron_add"), "cron");
        assert_eq!(tool_group("ssh_cron_remove"), "cron");
        // Certificates
        assert_eq!(tool_group("ssh_cert_check"), "certificates");
        assert_eq!(tool_group("ssh_cert_info"), "certificates");
        assert_eq!(tool_group("ssh_cert_expiry"), "certificates");
        // Nginx
        assert_eq!(tool_group("ssh_nginx_status"), "nginx");
        assert_eq!(tool_group("ssh_nginx_test"), "nginx");
        assert_eq!(tool_group("ssh_nginx_reload"), "nginx");
        assert_eq!(tool_group("ssh_nginx_list_sites"), "nginx");
        // Diagnostics
        assert_eq!(tool_group("ssh_diagnose"), "diagnostics");
        assert_eq!(tool_group("ssh_incident_triage"), "diagnostics");
        assert_eq!(tool_group("ssh_compare_state"), "diagnostics");
        // Orchestration
        assert_eq!(tool_group("ssh_canary_exec"), "orchestration");
        assert_eq!(tool_group("ssh_rolling_exec"), "orchestration");
        assert_eq!(tool_group("ssh_fleet_diff"), "orchestration");
        // Drift
        assert_eq!(tool_group("ssh_env_snapshot"), "drift");
        assert_eq!(tool_group("ssh_env_diff"), "drift");
        assert_eq!(tool_group("ssh_env_drift"), "drift");
        // File Advanced (in file_ops group)
        assert_eq!(tool_group("ssh_file_diff"), "file_ops");
        assert_eq!(tool_group("ssh_file_patch"), "file_ops");
        assert_eq!(tool_group("ssh_file_template"), "file_ops");
        assert_eq!(tool_group("ssh_files_write"), "file_ops");
        // Security Scanning
        assert_eq!(tool_group("ssh_sbom_generate"), "security_scan");
        assert_eq!(tool_group("ssh_vuln_scan"), "security_scan");
        assert_eq!(tool_group("ssh_compliance_check"), "security_scan");
        // Runbooks
        assert_eq!(tool_group("ssh_runbook_list"), "runbooks");
        assert_eq!(tool_group("ssh_runbook_execute"), "runbooks");
        assert_eq!(tool_group("ssh_runbook_validate"), "runbooks");
        // Recording
        assert_eq!(tool_group("ssh_recording_start"), "recording");
        assert_eq!(tool_group("ssh_recording_stop"), "recording");
        assert_eq!(tool_group("ssh_recording_list"), "recording");
        assert_eq!(tool_group("ssh_recording_replay"), "recording");
        assert_eq!(tool_group("ssh_recording_verify"), "recording");
        // Redis
        assert_eq!(tool_group("ssh_redis_info"), "redis");
        assert_eq!(tool_group("ssh_redis_cli"), "redis");
        assert_eq!(tool_group("ssh_redis_keys"), "redis");
        // Terraform
        assert_eq!(tool_group("ssh_terraform_init"), "terraform");
        assert_eq!(tool_group("ssh_terraform_plan"), "terraform");
        assert_eq!(tool_group("ssh_terraform_apply"), "terraform");
        assert_eq!(tool_group("ssh_terraform_state"), "terraform");
        assert_eq!(tool_group("ssh_terraform_output"), "terraform");
        // Vault
        assert_eq!(tool_group("ssh_vault_status"), "vault");
        assert_eq!(tool_group("ssh_vault_read"), "vault");
        assert_eq!(tool_group("ssh_vault_list"), "vault");
        assert_eq!(tool_group("ssh_vault_write"), "vault");
        // Config
        assert_eq!(tool_group("ssh_config_get"), "config");
        assert_eq!(tool_group("ssh_config_set"), "config");
        // Windows Services
        assert_eq!(tool_group("ssh_win_service_status"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_start"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_stop"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_restart"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_list"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_enable"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_disable"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_config"), "windows_services");
        // Windows Events
        assert_eq!(tool_group("ssh_win_event_logs"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_query"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_sources"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_tail"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_export"), "windows_events");
        // Active Directory
        assert_eq!(tool_group("ssh_ad_user_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_user_info"), "active_directory");
        assert_eq!(tool_group("ssh_ad_group_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_group_members"), "active_directory");
        assert_eq!(tool_group("ssh_ad_computer_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_domain_info"), "active_directory");
        // Scheduled Tasks
        assert_eq!(tool_group("ssh_schtask_list"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_info"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_run"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_enable"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_disable"), "scheduled_tasks");
        // Windows Firewall
        assert_eq!(tool_group("ssh_win_firewall_status"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_list"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_allow"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_deny"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_remove"), "windows_firewall");
        // IIS
        assert_eq!(tool_group("ssh_iis_status"), "iis");
        assert_eq!(tool_group("ssh_iis_list_sites"), "iis");
        assert_eq!(tool_group("ssh_iis_list_pools"), "iis");
        assert_eq!(tool_group("ssh_iis_start"), "iis");
        assert_eq!(tool_group("ssh_iis_stop"), "iis");
        assert_eq!(tool_group("ssh_iis_restart"), "iis");
        // Windows Updates
        assert_eq!(tool_group("ssh_win_update_list"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_history"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_install"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_search"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_reboot"), "windows_updates");
        // Windows Performance
        assert_eq!(tool_group("ssh_win_perf_cpu"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_memory"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_disk"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_network"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_overview"), "windows_perf");
        assert_eq!(tool_group("ssh_win_disk_usage"), "windows_perf");
        // Hyper-V
        assert_eq!(tool_group("ssh_hyperv_vm_list"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_info"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_start"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_stop"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_snapshot_list"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_snapshot_create"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_host_info"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_switch_list"), "hyperv");
        // Windows Registry
        assert_eq!(tool_group("ssh_reg_query"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_set"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_list"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_export"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_delete"), "windows_registry");
        // Windows Features
        assert_eq!(tool_group("ssh_win_feature_list"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_info"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_install"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_remove"), "windows_features");
        // Windows Network
        assert_eq!(tool_group("ssh_win_net_adapters"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_ip"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_routes"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_connections"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_ping"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_dns"), "windows_network");
        // Windows Process
        assert_eq!(tool_group("ssh_win_process_list"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_info"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_kill"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_top"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_by_name"), "windows_process");
        // Unknown defaults to core
        assert_eq!(tool_group("unknown_tool"), "core");
    }

    #[test]
    fn test_filtered_registry_all_enabled() {
        // Pre-FIND-024 behaviour: a config that explicitly enables every
        // group must register every tool from the inventory.
        let config = all_enabled_tool_groups_config_for_test();
        let registry = create_filtered_registry(&config);
        assert_eq!(registry.len(), all_tools_count());
    }

    #[test]
    fn test_filtered_registry_disable_sessions() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 338 total minus 4 session tools
        assert_eq!(registry.len(), all_tools_count() - group_size("sessions"));
        assert!(registry.get("ssh_session_create").is_none());
        assert!(registry.get("ssh_session_exec").is_none());
        assert!(registry.get("ssh_session_list").is_none());
        assert!(registry.get("ssh_session_close").is_none());
        // Core tools still present
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_monitoring() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("monitoring".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 monitoring tools  = 246
        assert_eq!(registry.len(), all_tools_count() - group_size("monitoring"));
        assert!(registry.get("ssh_metrics").is_none());
        assert!(registry.get("ssh_metrics_multi").is_none());
        assert!(registry.get("ssh_tail").is_none());
    }

    #[test]
    fn test_filtered_registry_disable_file_transfer() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("file_transfer".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 file transfer tools  = 247
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("file_transfer")
        );
        assert!(registry.get("ssh_upload").is_none());
        assert!(registry.get("ssh_download").is_none());
        assert!(registry.get("ssh_sync").is_none());
    }

    #[test]
    fn test_filtered_registry_disable_multiple_groups() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("sessions".to_string(), false);
        groups.insert("monitoring".to_string(), false);
        groups.insert("file_transfer".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        let disabled =
            group_size("sessions") + group_size("monitoring") + group_size("file_transfer");
        assert_eq!(registry.len(), all_tools_count() - disabled);
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_exec_multi").is_some());
        assert!(registry.get("ssh_status").is_some());
        assert!(registry.get("ssh_health").is_some());
        assert!(registry.get("ssh_history").is_some());
    }

    #[test]
    fn test_filtered_registry_explicit_enable() {
        // FIND-024: explicit `true` for `core` + `sessions` on top of an
        // all-enabled fixture is a no-op; every tool stays registered.
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("core".to_string(), true);
        groups.insert("sessions".to_string(), true);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        assert_eq!(registry.len(), all_tools_count());
    }

    #[test]
    fn test_filtered_registry_disable_tunnels() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("tunnels".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 tunnel tools  = 247
        assert_eq!(registry.len(), all_tools_count() - group_size("tunnels"));
        assert!(registry.get("ssh_tunnel_create").is_none());
        assert!(registry.get("ssh_tunnel_list").is_none());
        assert!(registry.get("ssh_tunnel_close").is_none());
        // Core tools still present
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_kubernetes() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("kubernetes".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 16 kubernetes tools (9 k8s + 7 helm)  = 234
        assert_eq!(registry.len(), all_tools_count() - group_size("kubernetes"));
        // kubectl tools removed
        assert!(registry.get("ssh_k8s_get").is_none());
        assert!(registry.get("ssh_k8s_logs").is_none());
        assert!(registry.get("ssh_k8s_describe").is_none());
        assert!(registry.get("ssh_k8s_apply").is_none());
        assert!(registry.get("ssh_k8s_delete").is_none());
        assert!(registry.get("ssh_k8s_rollout").is_none());
        assert!(registry.get("ssh_k8s_scale").is_none());
        assert!(registry.get("ssh_k8s_exec").is_none());
        assert!(registry.get("ssh_k8s_top").is_none());
        // helm tools removed
        assert!(registry.get("ssh_helm_list").is_none());
        assert!(registry.get("ssh_helm_status").is_none());
        assert!(registry.get("ssh_helm_upgrade").is_none());
        assert!(registry.get("ssh_helm_install").is_none());
        assert!(registry.get("ssh_helm_rollback").is_none());
        assert!(registry.get("ssh_helm_history").is_none());
        assert!(registry.get("ssh_helm_uninstall").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_ansible_playbook").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_ansible() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("ansible".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 357 total minus 9 ansible tools = 348
        assert_eq!(registry.len(), all_tools_count() - group_size("ansible"));
        assert!(registry.get("ssh_ansible_playbook").is_none());
        assert!(registry.get("ssh_ansible_inventory").is_none());
        assert!(registry.get("ssh_ansible_adhoc").is_none());
        assert!(registry.get("ssh_ansible_config").is_none());
        assert!(registry.get("ssh_ansible_events").is_none());
        assert!(registry.get("ssh_ansible_facts").is_none());
        assert!(registry.get("ssh_ansible_lint").is_none());
        assert!(registry.get("ssh_ansible_recap").is_none());
        assert!(registry.get("ssh_ansible_run_background").is_none());
        // Kubernetes tools still present
        assert!(registry.get("ssh_k8s_get").is_some());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_awx() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("awx".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 357 total minus 13 awx tools = 344
        assert_eq!(registry.len(), all_tools_count() - group_size("awx"));
        assert!(registry.get("ssh_awx_status").is_none());
        assert!(registry.get("ssh_awx_templates").is_none());
        assert!(registry.get("ssh_awx_template_detail").is_none());
        assert!(registry.get("ssh_awx_job_follow").is_none());
        assert!(registry.get("ssh_awx_job_launch").is_none());
        assert!(registry.get("ssh_awx_job_status").is_none());
        assert!(registry.get("ssh_awx_job_events").is_none());
        assert!(registry.get("ssh_awx_job_summary").is_none());
        assert!(registry.get("ssh_awx_job_stdout").is_none());
        assert!(registry.get("ssh_awx_job_cancel").is_none());
        assert!(registry.get("ssh_awx_inventories").is_none());
        assert!(registry.get("ssh_awx_inventory_hosts").is_none());
        assert!(registry.get("ssh_awx_project_sync").is_none());
        // Other groups still present
        assert!(registry.get("ssh_ansible_playbook").is_some());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_docker() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("docker".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 11 docker tools  = 270
        assert_eq!(registry.len(), all_tools_count() - group_size("docker"));
        assert!(registry.get("ssh_docker_ps").is_none());
        assert!(registry.get("ssh_docker_logs").is_none());
        assert!(registry.get("ssh_docker_inspect").is_none());
        assert!(registry.get("ssh_docker_exec").is_none());
        assert!(registry.get("ssh_docker_compose").is_none());
        assert!(registry.get("ssh_docker_images").is_none());
        assert!(registry.get("ssh_docker_stats").is_none());
        assert!(registry.get("ssh_docker_volume_ls").is_none());
        assert!(registry.get("ssh_docker_network_ls").is_none());
        assert!(registry.get("ssh_docker_volume_inspect").is_none());
        assert!(registry.get("ssh_docker_network_inspect").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_k8s_get").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_esxi() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("esxi".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 7 esxi tools  = 243
        assert_eq!(registry.len(), all_tools_count() - group_size("esxi"));
        assert!(registry.get("ssh_esxi_vm_list").is_none());
        assert!(registry.get("ssh_esxi_vm_info").is_none());
        assert!(registry.get("ssh_esxi_vm_power").is_none());
        assert!(registry.get("ssh_esxi_snapshot").is_none());
        assert!(registry.get("ssh_esxi_host_info").is_none());
        assert!(registry.get("ssh_esxi_datastore_list").is_none());
        assert!(registry.get("ssh_esxi_network_list").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_docker_ps").is_some());
        assert!(registry.get("ssh_k8s_get").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_git() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("git".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 7 git tools  = 243
        assert_eq!(registry.len(), all_tools_count() - group_size("git"));
        assert!(registry.get("ssh_git_status").is_none());
        assert!(registry.get("ssh_git_log").is_none());
        assert!(registry.get("ssh_git_diff").is_none());
        assert!(registry.get("ssh_git_pull").is_none());
        assert!(registry.get("ssh_git_clone").is_none());
        assert!(registry.get("ssh_git_branch").is_none());
        assert!(registry.get("ssh_git_checkout").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_docker_ps").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_systemd() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("systemd".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 9 systemd tools  = 272
        assert_eq!(registry.len(), all_tools_count() - group_size("systemd"));
        assert!(registry.get("ssh_service_status").is_none());
        assert!(registry.get("ssh_service_start").is_none());
        assert!(registry.get("ssh_service_stop").is_none());
        assert!(registry.get("ssh_service_restart").is_none());
        assert!(registry.get("ssh_service_list").is_none());
        assert!(registry.get("ssh_service_logs").is_none());
        assert!(registry.get("ssh_service_enable").is_none());
        assert!(registry.get("ssh_service_disable").is_none());
        assert!(registry.get("ssh_service_daemon_reload").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_network() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("network".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 network tools  = 244
        assert_eq!(registry.len(), all_tools_count() - group_size("network"));
        assert!(registry.get("ssh_net_connections").is_none());
        assert!(registry.get("ssh_net_interfaces").is_none());
        assert!(registry.get("ssh_net_routes").is_none());
        assert!(registry.get("ssh_net_ping").is_none());
        assert!(registry.get("ssh_net_traceroute").is_none());
        assert!(registry.get("ssh_net_dns").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_process() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("process".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 process tools  = 247
        assert_eq!(registry.len(), all_tools_count() - group_size("process"));
        assert!(registry.get("ssh_process_list").is_none());
        assert!(registry.get("ssh_process_kill").is_none());
        assert!(registry.get("ssh_process_top").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_package() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("package".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 package tools  = 276
        assert_eq!(registry.len(), all_tools_count() - group_size("package"));
        assert!(registry.get("ssh_pkg_list").is_none());
        assert!(registry.get("ssh_pkg_search").is_none());
        assert!(registry.get("ssh_pkg_install").is_none());
        assert!(registry.get("ssh_pkg_update").is_none());
        assert!(registry.get("ssh_pkg_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_firewall() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("firewall".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 firewall tools  = 246
        assert_eq!(registry.len(), all_tools_count() - group_size("firewall"));
        assert!(registry.get("ssh_firewall_status").is_none());
        assert!(registry.get("ssh_firewall_list").is_none());
        assert!(registry.get("ssh_firewall_allow").is_none());
        assert!(registry.get("ssh_firewall_deny").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_cron() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("cron".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 cron tools  = 247
        assert_eq!(registry.len(), all_tools_count() - group_size("cron"));
        assert!(registry.get("ssh_cron_list").is_none());
        assert!(registry.get("ssh_cron_add").is_none());
        assert!(registry.get("ssh_cron_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_certificates() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("certificates".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 certificate tools  = 247
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("certificates")
        );
        assert!(registry.get("ssh_cert_check").is_none());
        assert!(registry.get("ssh_cert_info").is_none());
        assert!(registry.get("ssh_cert_expiry").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_nginx() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("nginx".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 nginx tools  = 246
        assert_eq!(registry.len(), all_tools_count() - group_size("nginx"));
        assert!(registry.get("ssh_nginx_status").is_none());
        assert!(registry.get("ssh_nginx_test").is_none());
        assert!(registry.get("ssh_nginx_reload").is_none());
        assert!(registry.get("ssh_nginx_list_sites").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_redis() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("redis".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 redis tools  = 247
        assert_eq!(registry.len(), all_tools_count() - group_size("redis"));
        assert!(registry.get("ssh_redis_info").is_none());
        assert!(registry.get("ssh_redis_cli").is_none());
        assert!(registry.get("ssh_redis_keys").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_terraform() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("terraform".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 terraform tools  = 276
        assert_eq!(registry.len(), all_tools_count() - group_size("terraform"));
        assert!(registry.get("ssh_terraform_init").is_none());
        assert!(registry.get("ssh_terraform_plan").is_none());
        assert!(registry.get("ssh_terraform_apply").is_none());
        assert!(registry.get("ssh_terraform_state").is_none());
        assert!(registry.get("ssh_terraform_output").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_vault() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("vault".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 vault tools  = 246
        assert_eq!(registry.len(), all_tools_count() - group_size("vault"));
        assert!(registry.get("ssh_vault_status").is_none());
        assert!(registry.get("ssh_vault_read").is_none());
        assert!(registry.get("ssh_vault_list").is_none());
        assert!(registry.get("ssh_vault_write").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_config() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("config".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 config tools  = 248
        assert_eq!(registry.len(), all_tools_count() - group_size("config"));
        assert!(registry.get("ssh_config_get").is_none());
        assert!(registry.get("ssh_config_set").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    // ============== Tool Annotations Tests ==============

    #[test]
    fn test_filtered_registry_disable_windows_services() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_services".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 8 windows_services tools  = 242
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_services")
        );
        assert!(registry.get("ssh_win_service_status").is_none());
        assert!(registry.get("ssh_win_service_start").is_none());
        assert!(registry.get("ssh_win_service_stop").is_none());
        assert!(registry.get("ssh_win_service_restart").is_none());
        assert!(registry.get("ssh_win_service_list").is_none());
        assert!(registry.get("ssh_win_service_enable").is_none());
        assert!(registry.get("ssh_win_service_disable").is_none());
        assert!(registry.get("ssh_win_service_config").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_events() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_events".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 windows_events tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_events")
        );
        assert!(registry.get("ssh_win_event_logs").is_none());
        assert!(registry.get("ssh_win_event_query").is_none());
        assert!(registry.get("ssh_win_event_sources").is_none());
        assert!(registry.get("ssh_win_event_tail").is_none());
        assert!(registry.get("ssh_win_event_export").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_active_directory() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("active_directory".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 active_directory tools  = 244
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("active_directory")
        );
        assert!(registry.get("ssh_ad_user_list").is_none());
        assert!(registry.get("ssh_ad_user_info").is_none());
        assert!(registry.get("ssh_ad_group_list").is_none());
        assert!(registry.get("ssh_ad_group_members").is_none());
        assert!(registry.get("ssh_ad_computer_list").is_none());
        assert!(registry.get("ssh_ad_domain_info").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_scheduled_tasks() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("scheduled_tasks".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 scheduled_tasks tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("scheduled_tasks")
        );
        assert!(registry.get("ssh_schtask_list").is_none());
        assert!(registry.get("ssh_schtask_info").is_none());
        assert!(registry.get("ssh_schtask_run").is_none());
        assert!(registry.get("ssh_schtask_enable").is_none());
        assert!(registry.get("ssh_schtask_disable").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_firewall() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_firewall".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 windows_firewall tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_firewall")
        );
        assert!(registry.get("ssh_win_firewall_status").is_none());
        assert!(registry.get("ssh_win_firewall_list").is_none());
        assert!(registry.get("ssh_win_firewall_allow").is_none());
        assert!(registry.get("ssh_win_firewall_deny").is_none());
        assert!(registry.get("ssh_win_firewall_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_iis() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("iis".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 iis tools  = 244
        assert_eq!(registry.len(), all_tools_count() - group_size("iis"));
        assert!(registry.get("ssh_iis_status").is_none());
        assert!(registry.get("ssh_iis_list_sites").is_none());
        assert!(registry.get("ssh_iis_list_pools").is_none());
        assert!(registry.get("ssh_iis_start").is_none());
        assert!(registry.get("ssh_iis_stop").is_none());
        assert!(registry.get("ssh_iis_restart").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_updates() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_updates".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 windows_updates tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_updates")
        );
        assert!(registry.get("ssh_win_update_list").is_none());
        assert!(registry.get("ssh_win_update_history").is_none());
        assert!(registry.get("ssh_win_update_install").is_none());
        assert!(registry.get("ssh_win_update_search").is_none());
        assert!(registry.get("ssh_win_update_reboot").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_perf() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_perf".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 windows_perf tools  = 244
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_perf")
        );
        assert!(registry.get("ssh_win_perf_cpu").is_none());
        assert!(registry.get("ssh_win_perf_memory").is_none());
        assert!(registry.get("ssh_win_perf_disk").is_none());
        assert!(registry.get("ssh_win_perf_network").is_none());
        assert!(registry.get("ssh_win_perf_overview").is_none());
        assert!(registry.get("ssh_win_disk_usage").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_hyperv() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("hyperv".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 8 hyperv tools  = 242
        assert_eq!(registry.len(), all_tools_count() - group_size("hyperv"));
        assert!(registry.get("ssh_hyperv_vm_list").is_none());
        assert!(registry.get("ssh_hyperv_vm_info").is_none());
        assert!(registry.get("ssh_hyperv_vm_start").is_none());
        assert!(registry.get("ssh_hyperv_vm_stop").is_none());
        assert!(registry.get("ssh_hyperv_snapshot_list").is_none());
        assert!(registry.get("ssh_hyperv_snapshot_create").is_none());
        assert!(registry.get("ssh_hyperv_host_info").is_none());
        assert!(registry.get("ssh_hyperv_switch_list").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_registry() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_registry".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 windows_registry tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_registry")
        );
        assert!(registry.get("ssh_reg_query").is_none());
        assert!(registry.get("ssh_reg_set").is_none());
        assert!(registry.get("ssh_reg_list").is_none());
        assert!(registry.get("ssh_reg_export").is_none());
        assert!(registry.get("ssh_reg_delete").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_features() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_features".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 windows_features tools  = 246
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_features")
        );
        assert!(registry.get("ssh_win_feature_list").is_none());
        assert!(registry.get("ssh_win_feature_info").is_none());
        assert!(registry.get("ssh_win_feature_install").is_none());
        assert!(registry.get("ssh_win_feature_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_network() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_network".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 windows_network tools  = 244
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_network")
        );
        assert!(registry.get("ssh_win_net_adapters").is_none());
        assert!(registry.get("ssh_win_net_ip").is_none());
        assert!(registry.get("ssh_win_net_routes").is_none());
        assert!(registry.get("ssh_win_net_connections").is_none());
        assert!(registry.get("ssh_win_net_ping").is_none());
        assert!(registry.get("ssh_win_net_dns").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_process() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("windows_process".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 windows_process tools  = 276
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("windows_process")
        );
        assert!(registry.get("ssh_win_process_list").is_none());
        assert!(registry.get("ssh_win_process_info").is_none());
        assert!(registry.get("ssh_win_process_kill").is_none());
        assert!(registry.get("ssh_win_process_top").is_none());
        assert!(registry.get("ssh_win_process_by_name").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_directory() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("directory".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 directory tools
        assert_eq!(registry.len(), all_tools_count() - group_size("directory"));
        assert!(registry.get("ssh_ls").is_none());
        assert!(registry.get("ssh_find").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_database() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("database".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 database tools
        assert_eq!(registry.len(), all_tools_count() - group_size("database"));
        assert!(registry.get("ssh_db_query").is_none());
        assert!(registry.get("ssh_db_dump").is_none());
        assert!(registry.get("ssh_db_restore").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_backup() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("backup".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 backup tools
        assert_eq!(registry.len(), all_tools_count() - group_size("backup"));
        assert!(registry.get("ssh_backup_create").is_none());
        assert!(registry.get("ssh_backup_list").is_none());
        assert!(registry.get("ssh_backup_restore").is_none());
        assert!(registry.get("ssh_backup_snapshot").is_none());
        assert!(registry.get("ssh_backup_verify").is_none());
        assert!(registry.get("ssh_backup_schedule").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_cron_analysis() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("cron_analysis".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 cron_analysis tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("cron_analysis")
        );
        assert!(registry.get("ssh_cron_analyze").is_none());
        assert!(registry.get("ssh_cron_history").is_none());
        assert!(registry.get("ssh_at_jobs").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_performance() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("performance".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 performance tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("performance")
        );
        assert!(registry.get("ssh_perf_trace").is_none());
        assert!(registry.get("ssh_io_trace").is_none());
        assert!(registry.get("ssh_latency_test").is_none());
        assert!(registry.get("ssh_benchmark").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_container_logs() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("container_logs".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 container_logs tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("container_logs")
        );
        assert!(registry.get("ssh_container_log_search").is_none());
        assert!(registry.get("ssh_container_log_stats").is_none());
        assert!(registry.get("ssh_container_events").is_none());
        assert!(registry.get("ssh_container_health_history").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_network_security() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("network_security".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 network_security tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("network_security")
        );
        assert!(registry.get("ssh_port_scan").is_none());
        assert!(registry.get("ssh_ssl_audit").is_none());
        assert!(registry.get("ssh_network_capture").is_none());
        assert!(registry.get("ssh_fail2ban_status").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_compliance() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("compliance".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 compliance tools
        assert_eq!(registry.len(), all_tools_count() - group_size("compliance"));
        assert!(registry.get("ssh_cis_benchmark").is_none());
        assert!(registry.get("ssh_stig_check").is_none());
        assert!(registry.get("ssh_compliance_score").is_none());
        assert!(registry.get("ssh_compliance_report").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_alerting() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("alerting".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 alerting tools
        assert_eq!(registry.len(), all_tools_count() - group_size("alerting"));
        assert!(registry.get("ssh_alert_set").is_none());
        assert!(registry.get("ssh_alert_list").is_none());
        assert!(registry.get("ssh_alert_check").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_capacity() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("capacity".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 capacity tools
        assert_eq!(registry.len(), all_tools_count() - group_size("capacity"));
        assert!(registry.get("ssh_capacity_collect").is_none());
        assert!(registry.get("ssh_capacity_trend").is_none());
        assert!(registry.get("ssh_capacity_predict").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_incident() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("incident".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 incident tools
        assert_eq!(registry.len(), all_tools_count() - group_size("incident"));
        assert!(registry.get("ssh_incident_timeline").is_none());
        assert!(registry.get("ssh_incident_correlate").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_log_aggregation() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("log_aggregation".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 log_aggregation tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("log_aggregation")
        );
        assert!(registry.get("ssh_log_search_multi").is_none());
        assert!(registry.get("ssh_log_aggregate").is_none());
        assert!(registry.get("ssh_log_tail_multi").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_key_management() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("key_management".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 key_management tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("key_management")
        );
        assert!(registry.get("ssh_key_generate").is_none());
        assert!(registry.get("ssh_key_distribute").is_none());
        assert!(registry.get("ssh_key_audit").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_chatops() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("chatops".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 chatops tools
        assert_eq!(registry.len(), all_tools_count() - group_size("chatops"));
        assert!(registry.get("ssh_webhook_send").is_none());
        assert!(registry.get("ssh_notify").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_templates() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("templates".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 templates tools
        assert_eq!(registry.len(), all_tools_count() - group_size("templates"));
        assert!(registry.get("ssh_template_list").is_none());
        assert!(registry.get("ssh_template_show").is_none());
        assert!(registry.get("ssh_template_apply").is_none());
        assert!(registry.get("ssh_template_validate").is_none());
        assert!(registry.get("ssh_template_diff").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_pty() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("pty".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 pty tools
        assert_eq!(registry.len(), all_tools_count() - group_size("pty"));
        assert!(registry.get("ssh_pty_exec").is_none());
        assert!(registry.get("ssh_pty_interact").is_none());
        assert!(registry.get("ssh_pty_resize").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_cloud() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("cloud".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 cloud tools
        assert_eq!(registry.len(), all_tools_count() - group_size("cloud"));
        assert!(registry.get("ssh_aws_cli").is_none());
        assert!(registry.get("ssh_cloud_metadata").is_none());
        assert!(registry.get("ssh_cloud_tags").is_none());
        assert!(registry.get("ssh_cloud_cost").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_inventory() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("inventory".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 inventory tools
        assert_eq!(registry.len(), all_tools_count() - group_size("inventory"));
        assert!(registry.get("ssh_discover_hosts").is_none());
        assert!(registry.get("ssh_inventory_sync").is_none());
        assert!(registry.get("ssh_host_tags").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_multicloud() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("multicloud".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 multicloud tools
        assert_eq!(registry.len(), all_tools_count() - group_size("multicloud"));
        assert!(registry.get("ssh_multicloud_list").is_none());
        assert!(registry.get("ssh_multicloud_sync").is_none());
        assert!(registry.get("ssh_multicloud_compare").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_postgresql() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("postgresql".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 postgresql tools
        assert_eq!(registry.len(), all_tools_count() - group_size("postgresql"));
        assert!(registry.get("ssh_postgresql_query").is_none());
        assert!(registry.get("ssh_postgresql_status").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_mysql() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("mysql".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 mysql tools
        assert_eq!(registry.len(), all_tools_count() - group_size("mysql"));
        assert!(registry.get("ssh_mysql_query").is_none());
        assert!(registry.get("ssh_mysql_status").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_apache() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("apache".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 2 apache tools
        assert_eq!(registry.len(), all_tools_count() - group_size("apache"));
        assert!(registry.get("ssh_apache_status").is_none());
        assert!(registry.get("ssh_apache_vhosts").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_letsencrypt() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("letsencrypt".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 1 letsencrypt tool
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("letsencrypt")
        );
        assert!(registry.get("ssh_letsencrypt_status").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_mongodb() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("mongodb".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 1 mongodb tool
        assert_eq!(registry.len(), all_tools_count() - group_size("mongodb"));
        assert!(registry.get("ssh_mongodb_status").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_diagnostics() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("diagnostics".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 diagnostics tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("diagnostics")
        );
        assert!(registry.get("ssh_diagnose").is_none());
        assert!(registry.get("ssh_incident_triage").is_none());
        assert!(registry.get("ssh_compare_state").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_runbooks() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("runbooks".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 runbooks tools
        assert_eq!(registry.len(), all_tools_count() - group_size("runbooks"));
        assert!(registry.get("ssh_runbook_list").is_none());
        assert!(registry.get("ssh_runbook_execute").is_none());
        assert!(registry.get("ssh_runbook_validate").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_recording() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("recording".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 recording tools
        assert_eq!(registry.len(), all_tools_count() - group_size("recording"));
        assert!(registry.get("ssh_recording_start").is_none());
        assert!(registry.get("ssh_recording_stop").is_none());
        assert!(registry.get("ssh_recording_list").is_none());
        assert!(registry.get("ssh_recording_replay").is_none());
        assert!(registry.get("ssh_recording_verify").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_orchestration() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("orchestration".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 orchestration tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("orchestration")
        );
        assert!(registry.get("ssh_canary_exec").is_none());
        assert!(registry.get("ssh_rolling_exec").is_none());
        assert!(registry.get("ssh_fleet_diff").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_drift() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("drift".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 drift tools
        assert_eq!(registry.len(), all_tools_count() - group_size("drift"));
        assert!(registry.get("ssh_env_snapshot").is_none());
        assert!(registry.get("ssh_env_diff").is_none());
        assert!(registry.get("ssh_env_drift").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_security_scan() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("security_scan".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 3 security_scan tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("security_scan")
        );
        assert!(registry.get("ssh_sbom_generate").is_none());
        assert!(registry.get("ssh_vuln_scan").is_none());
        assert!(registry.get("ssh_compliance_check").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_file_ops() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("file_ops".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 338 total minus 9 file_ops tools
        assert_eq!(registry.len(), all_tools_count() - group_size("file_ops"));
        assert!(registry.get("ssh_file_read").is_none());
        assert!(registry.get("ssh_file_write").is_none());
        assert!(registry.get("ssh_files_write").is_none());
        assert!(registry.get("ssh_file_chmod").is_none());
        assert!(registry.get("ssh_file_chown").is_none());
        assert!(registry.get("ssh_file_stat").is_none());
        assert!(registry.get("ssh_file_diff").is_none());
        assert!(registry.get("ssh_file_patch").is_none());
        assert!(registry.get("ssh_file_template").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_user_management() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("user_management".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 8 user_management tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("user_management")
        );
        assert!(registry.get("ssh_user_list").is_none());
        assert!(registry.get("ssh_user_info").is_none());
        assert!(registry.get("ssh_user_add").is_none());
        assert!(registry.get("ssh_user_modify").is_none());
        assert!(registry.get("ssh_user_delete").is_none());
        assert!(registry.get("ssh_group_list").is_none());
        assert!(registry.get("ssh_group_add").is_none());
        assert!(registry.get("ssh_group_delete").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_storage() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("storage".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 7 storage tools
        assert_eq!(registry.len(), all_tools_count() - group_size("storage"));
        assert!(registry.get("ssh_storage_lsblk").is_none());
        assert!(registry.get("ssh_storage_df").is_none());
        assert!(registry.get("ssh_storage_mount").is_none());
        assert!(registry.get("ssh_storage_umount").is_none());
        assert!(registry.get("ssh_storage_lvm").is_none());
        assert!(registry.get("ssh_storage_fdisk").is_none());
        assert!(registry.get("ssh_storage_fstab").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_journald() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("journald".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 4 journald tools
        assert_eq!(registry.len(), all_tools_count() - group_size("journald"));
        assert!(registry.get("ssh_journal_query").is_none());
        assert!(registry.get("ssh_journal_follow").is_none());
        assert!(registry.get("ssh_journal_boots").is_none());
        assert!(registry.get("ssh_journal_disk_usage").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_systemd_timers() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("systemd_timers".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 systemd_timers tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("systemd_timers")
        );
        assert!(registry.get("ssh_timer_list").is_none());
        assert!(registry.get("ssh_timer_info").is_none());
        assert!(registry.get("ssh_timer_enable").is_none());
        assert!(registry.get("ssh_timer_disable").is_none());
        assert!(registry.get("ssh_timer_trigger").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_security_modules() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("security_modules".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 security_modules tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("security_modules")
        );
        assert!(registry.get("ssh_selinux_status").is_none());
        assert!(registry.get("ssh_selinux_booleans").is_none());
        assert!(registry.get("ssh_apparmor_status").is_none());
        assert!(registry.get("ssh_apparmor_profiles").is_none());
        assert!(registry.get("ssh_security_audit").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_network_equipment() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("network_equipment".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 8 network_equipment tools
        assert_eq!(
            registry.len(),
            all_tools_count() - group_size("network_equipment")
        );
        assert!(registry.get("ssh_net_equip_show_run").is_none());
        assert!(registry.get("ssh_net_equip_show_interfaces").is_none());
        assert!(registry.get("ssh_net_equip_show_routes").is_none());
        assert!(registry.get("ssh_net_equip_show_arp").is_none());
        assert!(registry.get("ssh_net_equip_show_version").is_none());
        assert!(registry.get("ssh_net_equip_show_vlans").is_none());
        assert!(registry.get("ssh_net_equip_config").is_none());
        assert!(registry.get("ssh_net_equip_save").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_podman() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("podman".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 6 podman tools
        assert_eq!(registry.len(), all_tools_count() - group_size("podman"));
        assert!(registry.get("ssh_podman_ps").is_none());
        assert!(registry.get("ssh_podman_logs").is_none());
        assert!(registry.get("ssh_podman_inspect").is_none());
        assert!(registry.get("ssh_podman_exec").is_none());
        assert!(registry.get("ssh_podman_images").is_none());
        assert!(registry.get("ssh_podman_compose").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_ldap() {
        let mut groups = all_enabled_tool_groups_config_for_test().groups;
        groups.insert("ldap".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 337 total minus 5 ldap tools
        assert_eq!(registry.len(), all_tools_count() - group_size("ldap"));
        assert!(registry.get("ssh_ldap_search").is_none());
        assert!(registry.get("ssh_ldap_user_info").is_none());
        assert!(registry.get("ssh_ldap_group_members").is_none());
        assert!(registry.get("ssh_ldap_add").is_none());
        assert!(registry.get("ssh_ldap_modify").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_all_tools_have_annotations_with_title() {
        let registry = create_all_enabled_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            assert!(
                ann.title.is_some(),
                "Tool '{}' missing annotation title",
                tool.name
            );
        }
    }

    #[test]
    fn test_list_tools_includes_annotations() {
        let registry = create_all_enabled_registry();
        let tools = registry.list_tools();
        // All tools should have annotations since all have titles
        for tool in &tools {
            assert!(
                tool.annotations.is_some(),
                "Tool '{}' missing annotations in list_tools()",
                tool.name
            );
        }
    }

    #[test]
    fn test_read_only_tools_annotations() {
        let read_only = [
            "ssh_status",
            "ssh_health",
            "ssh_history",
            "ssh_output_fetch",
            "ssh_metrics",
            "ssh_tail",
            "ssh_ls",
            "ssh_docker_ps",
            "ssh_docker_logs",
            "ssh_docker_inspect",
            "ssh_docker_images",
            "ssh_docker_stats",
            "ssh_k8s_get",
            "ssh_k8s_logs",
            "ssh_k8s_describe",
            "ssh_k8s_top",
            "ssh_helm_list",
            "ssh_helm_status",
            "ssh_helm_history",
            "ssh_service_status",
            "ssh_service_list",
            "ssh_service_logs",
            "ssh_net_connections",
            "ssh_net_ping",
            "ssh_process_list",
            "ssh_process_top",
            "ssh_pkg_list",
            "ssh_firewall_status",
            "ssh_cron_list",
            "ssh_cert_check",
            "ssh_nginx_status",
            "ssh_redis_info",
            "ssh_terraform_state",
            "ssh_vault_status",
            "ssh_config_get",
            "ssh_session_list",
            "ssh_tunnel_list",
            "ssh_backup_list",
        ];
        for name in &read_only {
            let ann = tool_annotations(name);
            assert_eq!(ann.read_only_hint, Some(true), "{name} should be read-only");
            assert_eq!(
                ann.destructive_hint,
                Some(false),
                "{name} should not be destructive"
            );
        }
    }

    #[test]
    fn test_destructive_tools_annotations() {
        let destructive = [
            "ssh_k8s_delete",
            "ssh_helm_uninstall",
            "ssh_process_kill",
            "ssh_cron_remove",
            "ssh_session_close",
            "ssh_tunnel_close",
            "ssh_firewall_deny",
            "ssh_service_stop",
            // Behaviorally-destructive despite benign names (audit 2026-06-20).
            "ssh_exec",
        ];
        for name in &destructive {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.destructive_hint,
                Some(true),
                "{name} should be destructive"
            );
            assert_eq!(
                ann.read_only_hint,
                Some(false),
                "{name} should not be read-only"
            );
        }
    }

    #[test]
    fn test_idempotent_tools_annotations() {
        let idempotent = [
            "ssh_k8s_apply",
            "ssh_service_restart",
            "ssh_terraform_init",
            "ssh_nginx_reload",
        ];
        for name in &idempotent {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.idempotent_hint,
                Some(true),
                "{name} should be idempotent"
            );
        }
    }

    #[test]
    fn test_mutating_tools_annotations() {
        let mutating = [
            "ssh_exec_multi",
            "ssh_docker_exec",
            "ssh_git_pull",
            "ssh_helm_install",
            "ssh_terraform_apply",
            "ssh_upload",
            "ssh_db_query",
        ];
        for name in &mutating {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.read_only_hint,
                Some(false),
                "{name} should not be read-only"
            );
            assert_eq!(
                ann.destructive_hint,
                Some(false),
                "{name} should not be destructive"
            );
        }
    }

    #[test]
    fn test_unknown_tool_returns_empty_annotations() {
        let ann = tool_annotations("nonexistent_tool");
        assert!(ann.is_empty());
    }

    #[test]
    fn test_no_duplicate_tool_names() {
        let registry = create_all_enabled_registry();
        let tools = registry.list_tools();
        let mut seen = std::collections::HashSet::new();
        for tool in &tools {
            assert!(
                seen.insert(&tool.name),
                "Duplicate tool name: {}",
                tool.name
            );
        }
    }

    #[test]
    fn test_all_tools_have_valid_schema_json() {
        let registry = create_all_enabled_registry();
        for tool in registry.list_tools() {
            assert!(
                tool.input_schema.is_object(),
                "Tool '{}' has invalid input_schema (not a JSON object)",
                tool.name
            );
            assert_eq!(
                tool.input_schema["type"], "object",
                "Tool '{}' schema type must be 'object'",
                tool.name
            );
            assert!(
                tool.input_schema.get("properties").is_some(),
                "Tool '{}' schema missing 'properties'",
                tool.name
            );
        }
    }

    #[test]
    fn test_tool_groups_cover_all_tools() {
        let valid_groups = [
            "core",
            "file_transfer",
            "sessions",
            "monitoring",
            "tunnels",
            "directory",
            "database",
            "backup",
            "docker",
            "esxi",
            "git",
            "kubernetes",
            "ansible",
            "awx",
            "systemd",
            "network",
            "process",
            "package",
            "firewall",
            "cron",
            "certificates",
            "nginx",
            "redis",
            "terraform",
            "vault",
            "config",
            "windows_services",
            "windows_events",
            "active_directory",
            "scheduled_tasks",
            "windows_firewall",
            "iis",
            "windows_updates",
            "windows_perf",
            "hyperv",
            "windows_registry",
            "windows_features",
            "windows_network",
            "windows_process",
            "file_ops",
            "user_management",
            "storage",
            "journald",
            "systemd_timers",
            "security_modules",
            "network_equipment",
            "podman",
            "ldap",
            "postgresql",
            "mysql",
            "apache",
            "letsencrypt",
            "mongodb",
            "recording",
            "diagnostics",
            "runbooks",
            "orchestration",
            "drift",
            "security_scan",
            "cron_analysis",
            "performance",
            "container_logs",
            "network_security",
            "compliance",
            "cloud",
            "inventory",
            "multicloud",
            "alerting",
            "capacity",
            "incident",
            "log_aggregation",
            "key_management",
            "chatops",
            "templates",
            "pty",
        ];
        let registry = create_all_enabled_registry();
        for tool in registry.list_tools() {
            let group = tool_group(&tool.name);
            assert!(
                valid_groups.contains(&group),
                "Tool '{}' has unknown group '{group}'",
                tool.name
            );
        }
    }

    #[test]
    fn test_annotation_consistency_read_only_not_destructive() {
        let registry = create_all_enabled_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            if ann.read_only_hint == Some(true) {
                assert_ne!(
                    ann.destructive_hint,
                    Some(true),
                    "Tool '{}' is read-only but marked destructive",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn test_annotation_consistency_destructive_not_read_only() {
        let registry = create_all_enabled_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            if ann.destructive_hint == Some(true) {
                assert_ne!(
                    ann.read_only_hint,
                    Some(true),
                    "Tool '{}' is destructive but marked read-only",
                    tool.name
                );
            }
        }
    }

    /// FIND-024 regression: `create_default_registry()` must only register
    /// tools whose group is in `MINIMAL_DEFAULT_GROUPS`. The pre-FIND-024
    /// behaviour exposed all 357 handlers by default — that is the bug
    /// this test pins.
    #[test]
    fn test_default_registry_only_contains_minimal_profile() {
        use crate::config::types::MINIMAL_DEFAULT_GROUPS;

        let registry = create_default_registry();
        let tools: Vec<String> = registry.list_tools().into_iter().map(|t| t.name).collect();

        // Every tool in the default registry must belong to a
        // minimal-profile group.
        for tool_name in &tools {
            let g = tool_group(tool_name);
            assert!(
                MINIMAL_DEFAULT_GROUPS.contains(&g),
                "FIND-024: tool '{tool_name}' (group '{g}') is in default \
                 registry but not in MINIMAL_DEFAULT_GROUPS"
            );
        }

        // Each minimal-profile group must register at least one handler.
        for &g in MINIMAL_DEFAULT_GROUPS {
            let count_in_g = tools.iter().filter(|t| tool_group(t) == g).count();
            assert!(
                count_in_g > 0,
                "FIND-024: minimal-profile group '{g}' should have at \
                 least one tool registered"
            );
        }

        // Sanity: the default profile must not register every handler
        // (otherwise the FIND-024 fix is silently regressed).
        assert!(
            tools.len() < all_tools_count(),
            "FIND-024: default registry size ({}) equals total tool \
             count ({}) — has the default-disabled semantic regressed?",
            tools.len(),
            all_tools_count()
        );
    }

    #[test]
    fn test_tool_meta_large_output_tools() {
        // Tools known to produce large output should have _meta
        assert!(tool_meta("ssh_exec").is_some());
        assert!(tool_meta("ssh_file_read").is_some());
        assert!(tool_meta("ssh_docker_logs").is_some());
        assert!(tool_meta("ssh_k8s_logs").is_some());
        assert!(tool_meta("ssh_output_fetch").is_some());

        // Small-output tools should not have _meta
        assert!(tool_meta("ssh_status").is_none());
        assert!(tool_meta("ssh_health").is_none());
        assert!(tool_meta("ssh_disk_usage").is_none());
    }

    #[test]
    fn test_tool_meta_value_format() {
        let meta = tool_meta("ssh_exec").unwrap();
        assert_eq!(meta["anthropic/maxResultSizeChars"], 200_000);
    }

    /// A handler that overrides `output_schema()` to return a concrete
    /// JSON Schema. Proves `list_tools` serializes the handler's schema
    /// into `Tool.output_schema` instead of the previous hard-coded None.
    struct SchemaHandler;

    #[async_trait]
    impl ToolHandler for SchemaHandler {
        fn name(&self) -> &'static str {
            "schema_tool"
        }

        fn description(&self) -> &'static str {
            "A tool with an output schema"
        }

        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: "schema_tool",
                description: "A tool with an output schema",
                input_schema: r#"{"type":"object","properties":{}}"#,
            }
        }

        fn output_schema(&self) -> Option<serde_json::Value> {
            Some(json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": { "items": { "type": "array" } }
            }))
        }

        async fn execute(
            &self,
            _args: Option<serde_json::Value>,
            _ctx: &ToolContext,
        ) -> Result<ToolCallResult> {
            Ok(ToolCallResult::text("ok"))
        }
    }

    #[test]
    fn test_default_output_schema_is_none() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));
        let tools = registry.list_tools();
        assert_eq!(tools.len(), 1);
        assert!(tools[0].output_schema.is_none());
    }

    #[test]
    fn test_list_tools_serializes_output_schema() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(SchemaHandler));
        let tools = registry.list_tools();
        assert_eq!(tools.len(), 1);
        let schema = tools[0]
            .output_schema
            .as_ref()
            .expect("output_schema must be populated from handler.output_schema()");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["type"], "object");
        let wire = serde_json::to_value(&tools[0]).unwrap();
        assert!(wire.get("outputSchema").is_some());
    }

    #[test]
    fn test_group_icon_known_group_has_icon() {
        let icon = group_icon("docker").expect("docker group must map to an icon");
        assert!(
            icon.src.contains("docker"),
            "docker icon src should reference docker: {}",
            icon.src
        );
        assert_eq!(icon.mime_type.as_deref(), Some("image/svg+xml"));
    }

    #[test]
    fn test_group_icon_unknown_group_is_none() {
        assert!(group_icon("pty").is_none());
        assert!(group_icon("does_not_exist").is_none());
    }

    #[test]
    fn test_tool_icons_maps_via_group() {
        let icons = tool_icons("ssh_docker_ps").expect("docker tool must carry an icon");
        assert_eq!(icons.len(), 1);
        assert!(icons[0].src.contains("docker"));
    }

    #[test]
    fn test_tool_icons_uncurated_group_is_none() {
        assert!(tool_icons("ssh_pty_exec").is_none());
    }
}
