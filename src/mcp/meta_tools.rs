//! Progressive-discovery meta-tools.
//!
//! 338 tools is enough to overflow the context window of a small client when
//! `tools/list` is called eagerly. These three meta-tools let a client
//! discover the registry on demand: browse groups, search by keyword, then
//! fetch the full schema only for the one tool it actually needs.
//!
//! The logic here is pure (takes a `ToolRegistry` reference and plain
//! arguments, returns a `ToolCallResult`) so the `McpServer` dispatch can
//! call it without threading the registry through `ToolContext`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::protocol::{Tool, ToolExecution};
use super::registry::{ToolRegistry, inject_reduction_schema, tool_annotations, tool_group};
use crate::domain::output_truncator::truncate_chars;
use crate::ports::{ToolAnnotations, ToolCallResult, ToolContent};

/// Tool name for the group-listing meta-tool.
pub const LIST_TOOL_GROUPS: &str = "mcp_list_tool_groups";
/// Tool name for the search meta-tool.
pub const SEARCH_TOOLS: &str = "mcp_search_tools";
/// Tool name for the describe meta-tool.
pub const DESCRIBE_TOOL: &str = "mcp_describe_tool";
/// Generic dispatcher surfaced when `tool_groups.listing = progressive`:
/// invokes any enabled registry tool by name so the client only ever
/// needs the four meta-schemas in context.
pub const CALL_TOOL: &str = "mcp_call_tool";

/// Returns `true` when `name` matches one of the three meta-tools.
#[must_use]
pub fn is_meta_tool(name: &str) -> bool {
    matches!(name, LIST_TOOL_GROUPS | SEARCH_TOOLS | DESCRIBE_TOOL)
}

/// The `execution.taskSupport` value advertised for `tool_name`.
///
/// The three meta-tools are dispatched before the task branch in
/// `handle_tools_call`, so they cannot honor a task and say so. Everything else
/// — including the `mcp_call_tool` dispatcher, whose rewritten inner name does
/// reach the task branch — supports tasks optionally.
#[must_use]
pub fn task_support(tool_name: &str) -> &'static str {
    if is_meta_tool(tool_name) {
        "forbidden"
    } else {
        "optional"
    }
}

/// Build the three virtual `Tool` entries for `tools/list`.
///
/// These are surfaced alongside the registry so clients can discover them
/// without a separate mechanism. The schemas are tiny (no data-reduction
/// params) and the annotations mark them as read-only so clients are free
/// to call them in parallel.
#[must_use]
pub fn definitions() -> Vec<Tool> {
    vec![
        Tool {
            name: LIST_TOOL_GROUPS.to_string(),
            description:
                "List all tool groups (docker, k8s, cloud, serial, winrm, …) with their tool \
                 counts. Call this first to see the broad landscape, then `mcp_search_tools` \
                 to narrow in, then `mcp_describe_tool` to fetch the one schema you need."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("List tool groups")),
            execution: Some(ToolExecution {
                task_support: "forbidden".to_string(),
            }),
            output_schema: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: SEARCH_TOOLS.to_string(),
            description:
                "Search the tool registry by keyword (case-insensitive substring on name and \
                 description). Returns compact entries (name + group + short description) \
                 without the full schema, so the AI can scan hundreds of tools without \
                 saturating context. Filter further with `group` or cap results with `limit`."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Case-insensitive substring matched against tool name and description"
                    },
                    "group": {
                        "type": "string",
                        "description": "Restrict results to this tool group (e.g. 'docker', 'k8s')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results (default 20, max 200)",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 20
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("Search tools")),
            execution: Some(ToolExecution {
                task_support: "forbidden".to_string(),
            }),
            output_schema: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: DESCRIBE_TOOL.to_string(),
            description:
                "Return the full schema and reduction strategy for a single tool. Use after \
                 `mcp_search_tools` to fetch the one schema you need; avoids the ~100 K-token \
                 cost of loading all 338 schemas up front."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Exact tool name (use mcp_search_tools to find it)"
                    }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("Describe a tool")),
            execution: Some(ToolExecution {
                task_support: "forbidden".to_string(),
            }),
            output_schema: None,
            icons: None,
            meta: None,
        },
    ]
}

/// Definition of the generic `mcp_call_tool` dispatcher.
/// Surfaced in `tools/list` in both listing modes — the rewrite at the top of
/// `handle_tools_call` is not gated on listing mode, so it dispatches in both
/// (audit G-21, 2026-08-19).
#[must_use]
pub fn call_tool_definition() -> Tool {
    Tool {
        name: CALL_TOOL.to_string(),
        description: "Invoke any enabled bridge tool by name. Discovery workflow: \
                      mcp_list_tool_groups → mcp_search_tools → mcp_describe_tool \
                      (fetch the schema + Reduction Strategy) → mcp_call_tool. \
                      The target tool's own annotations, destructive-op elicitation \
                      gate, and output-reduction params (jq_filter/columns/limit/\
                      output_format) all apply exactly as if called directly."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Exact tool name (use mcp_search_tools to find it)"
                },
                "arguments": {
                    "type": "object",
                    "description": "Arguments for the target tool, exactly as its \
                                    schema describes — including reduction params \
                                    like jq_filter, columns, limit, output_format"
                }
            },
            "required": ["name"]
        }),
        // Conservative by construction: the dispatcher's target is unknown at
        // listing time, and MCP's own default for an absent `destructiveHint`
        // is `true`. The real gate is unaffected — the elicitation check keys
        // on the REWRITTEN inner tool name, not on this one.
        annotations: Some(ToolAnnotations::destructive("Invoke any bridge tool")),
        execution: Some(ToolExecution {
            task_support: "optional".to_string(),
        }),
        output_schema: None,
        icons: None,
        meta: None,
    }
}

/// Unwrap `mcp_call_tool` arguments into `(inner_tool_name, inner_arguments)`.
///
/// # Errors
///
/// Returns a client-facing message when `name` is absent, empty, or not a
/// string. The inner name's existence is NOT checked here — the registry
/// dispatch reports `McpUnknownTool` with the normal error path.
pub fn unwrap_call_tool(
    args: Option<&Value>,
) -> std::result::Result<(String, Option<Value>), String> {
    let Some(obj) = args else {
        return Err(format!(
            "{CALL_TOOL}: missing arguments — expected {{\"name\": \"<tool>\", \"arguments\": {{…}}}}"
        ));
    };
    let Some(name) = obj
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(format!(
            "{CALL_TOOL}: `name` (string, non-empty) is required. \
             Use mcp_search_tools to discover tool names."
        ));
    };
    Ok((name.to_string(), obj.get("arguments").cloned()))
}

/// Execute one of the three meta-tools. Returns `None` when `tool_name` is
/// not a meta-tool (caller should then dispatch to the regular registry).
pub fn execute(
    tool_name: &str,
    args: Option<&Value>,
    registry: &ToolRegistry,
) -> Option<ToolCallResult> {
    match tool_name {
        LIST_TOOL_GROUPS => Some(list_groups(registry)),
        SEARCH_TOOLS => Some(search(args, registry)),
        DESCRIBE_TOOL => Some(describe(args, registry)),
        _ => None,
    }
}

fn list_groups(registry: &ToolRegistry) -> ToolCallResult {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for tool in registry.list_tools() {
        *counts.entry(tool_group(&tool.name)).or_insert(0) += 1;
    }

    let groups: Vec<Value> = counts
        .iter()
        .map(|(group, count)| json!({ "group": group, "count": count }))
        .collect();

    let payload = json!({
        "total_groups": groups.len(),
        "total_tools": counts.values().sum::<usize>(),
        "groups": groups,
    });

    success_json(payload)
}

/// Relevance tier for one tool against a lowercased query. Lower sorts first;
/// `None` means "no match".
///
/// Tiers: exact name, name prefix, name substring, description substring. The
/// MCP search path had no ranking at all and cut with `Vec::truncate`, so the
/// best hit was routinely thrown away (audit G-14, 2026-08-19). The CLI path
/// (`src/cli/runner.rs`) already sorted by name; this adds the tiers on top.
fn relevance_rank(name: &str, description: &str, query_lower: &str) -> Option<u8> {
    let name_lower = name.to_lowercase();
    if name_lower == query_lower {
        return Some(0);
    }
    if name_lower.starts_with(query_lower) {
        return Some(1);
    }
    if name_lower.contains(query_lower) {
        return Some(2);
    }
    if description.to_lowercase().contains(query_lower) {
        return Some(3);
    }
    None
}

fn search(args: Option<&Value>, registry: &ToolRegistry) -> ToolCallResult {
    let args = args.and_then(Value::as_object);
    let Some(query) = args
        .and_then(|o| o.get("query"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return ToolCallResult::error("mcp_search_tools: `query` (string, non-empty) is required");
    };
    let group_filter = args.and_then(|o| o.get("group")).and_then(Value::as_str);
    let limit = args
        .and_then(|o| o.get("limit"))
        .and_then(Value::as_u64)
        .map_or(20_usize, |n| n.min(200) as usize)
        .max(1);

    let query_lower = query.to_lowercase();
    let mut ranked: Vec<(u8, Tool)> = registry
        .list_tools()
        .into_iter()
        .filter(|t| group_filter.is_none_or(|g| tool_group(&t.name) == g))
        .filter_map(|t| relevance_rank(&t.name, &t.description, &query_lower).map(|r| (r, t)))
        .collect();
    // `list_tools()` is name-sorted and `sort_by_key` is stable, so ties inside
    // a tier stay alphabetical: identical input gives identical output on every
    // call and in every process.
    ranked.sort_by_key(|(rank, _)| *rank);

    let total = ranked.len();
    let matches: Vec<Value> = ranked
        .into_iter()
        .take(limit)
        .map(|(_, t)| {
            let group = tool_group(&t.name);
            // Character-wise: several descriptions contain `→`, and a
            // byte-index slice inside one aborts the server (audit
            // 2026-08-02).
            let short = if t.description.chars().count() > 160 {
                format!("{}…", truncate_chars(&t.description, 160))
            } else {
                t.description.clone()
            };
            json!({
                "name": t.name,
                "group": group,
                "description": short,
                "annotations": annotations_value(&t.name),
            })
        })
        .collect();

    let payload = json!({
        "query": query,
        "group": group_filter,
        "returned": matches.len(),
        "total_matches": total,
        "limit": limit,
        "results": matches,
    });
    success_json(payload)
}

fn describe(args: Option<&Value>, registry: &ToolRegistry) -> ToolCallResult {
    let Some(name) = args
        .and_then(Value::as_object)
        .and_then(|o| o.get("name"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return ToolCallResult::error("mcp_describe_tool: `name` (string, non-empty) is required");
    };

    let Some(handler) = registry.get(name) else {
        return ToolCallResult::error(format!(
            "mcp_describe_tool: unknown tool `{name}`. Use mcp_search_tools to discover valid names."
        ));
    };

    let schema = handler.schema();
    let output_kind = handler.output_kind();
    let mut input_schema: Value =
        serde_json::from_str(schema.input_schema).unwrap_or_else(|_| json!({}));
    inject_reduction_schema(&mut input_schema, output_kind);

    let payload = json!({
        "name": schema.name,
        "group": tool_group(name),
        "description": schema.description,
        "output_kind": format!("{output_kind:?}"),
        "reduction_strategy": output_kind.strategy_hint(),
        "reduce_marker": output_kind.short_marker(),
        "annotations": annotations_value(name),
        "task_support": task_support(name),
        "input_schema": input_schema,
    });
    success_json(payload)
}

/// A tool's MCP annotations as JSON for the discovery payloads, or `Null` when
/// the tool declares none. Progressive mode hides `tools/list`, so this is the
/// only place a client can read `readOnlyHint`/`destructiveHint` before it
/// invokes anything (audit G-19, 2026-08-19).
fn annotations_value(tool_name: &str) -> Value {
    let ann = tool_annotations(tool_name);
    if ann.is_empty() {
        Value::Null
    } else {
        serde_json::to_value(&ann).unwrap_or(Value::Null)
    }
}

fn success_json(value: Value) -> ToolCallResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    ToolCallResult {
        content: vec![ToolContent::Text { text }],
        is_error: Some(false),
        structured_content: Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::create_all_enabled_registry;

    #[test]
    fn is_meta_tool_recognises_all_three() {
        assert!(is_meta_tool(LIST_TOOL_GROUPS));
        assert!(is_meta_tool(SEARCH_TOOLS));
        assert!(is_meta_tool(DESCRIBE_TOOL));
        assert!(!is_meta_tool("ssh_exec"));
        assert!(!is_meta_tool(""));
    }

    #[test]
    fn definitions_contains_three_entries() {
        let defs = definitions();
        assert_eq!(defs.len(), 3);
        let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&LIST_TOOL_GROUPS));
        assert!(names.contains(&SEARCH_TOOLS));
        assert!(names.contains(&DESCRIBE_TOOL));
    }

    #[test]
    fn list_groups_returns_structured_payload() {
        let registry = create_all_enabled_registry();
        let result = execute(LIST_TOOL_GROUPS, None, &registry).expect("meta tool");
        let payload = result.structured_content.expect("structured");
        assert!(payload["total_groups"].as_u64().unwrap() > 0);
        assert!(payload["total_tools"].as_u64().unwrap() > 0);
        assert!(payload["groups"].is_array());
    }

    #[test]
    fn search_requires_query() {
        let registry = create_all_enabled_registry();
        let result = execute(SEARCH_TOOLS, Some(&json!({})), &registry).expect("meta tool");
        assert_eq!(result.is_error, Some(true));
    }

    /// Regression (audit 2026-08-02): a match whose description carried a
    /// multi-byte char across the 160-byte cut aborted the process —
    /// `byte index 160 is not a char boundary; it is inside '→'`. With
    /// `listing: progressive` the model reaches every tool through this
    /// path, so one such search killed the whole MCP server.
    #[test]
    fn search_survives_multibyte_descriptions() {
        let registry = create_all_enabled_registry();
        // 'container' matches ssh_crictl_inspect, whose description uses `→`.
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "container"})),
            &registry,
        )
        .expect("meta");
        assert_ne!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured");
        assert!(payload["total_matches"].as_u64().unwrap() > 0);

        // Every emitted description must be valid, non-split UTF-8 and
        // stay within the 160-char budget (+1 for the ellipsis).
        for m in payload["results"].as_array().expect("results") {
            let d = m["description"].as_str().expect("description");
            assert!(d.chars().count() <= 161, "description over budget: {d}");
        }
    }

    /// Same cut, the CLI's narrower 52-char budget.
    #[test]
    fn search_descriptions_are_char_truncated_not_byte_truncated() {
        let long: String = "→".repeat(400);
        assert_eq!(truncate_chars(&long, 160).chars().count(), 160);
        assert!(truncate_chars(&long, 52).is_char_boundary(truncate_chars(&long, 52).len()));
    }

    #[test]
    fn search_matches_on_name_substring() {
        let registry = create_all_enabled_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "docker", "limit": 5})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        let results = payload["results"].as_array().expect("array");
        assert!(!results.is_empty());
        for entry in results {
            let name = entry["name"].as_str().unwrap();
            let full_desc = registry.get(name).expect("registry has tool").description();
            assert!(
                name.to_lowercase().contains("docker")
                    || full_desc.to_lowercase().contains("docker"),
                "match {name} does not contain 'docker' in name or full description"
            );
        }
    }

    #[test]
    fn search_respects_group_filter() {
        let registry = create_all_enabled_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "", "group": "docker", "limit": 50})),
            &registry,
        )
        .expect("meta tool");
        // Empty query is explicitly rejected — this asserts that guard.
        assert_eq!(result.is_error, Some(true));
    }

    /// Collect just the tool names returned by `mcp_search_tools`, in order.
    fn search_names(registry: &ToolRegistry, query: &str, limit: u64) -> Vec<String> {
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": query, "limit": limit})),
            registry,
        )
        .expect("meta tool");
        result.structured_content.expect("structured")["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|e| e["name"].as_str().expect("name").to_string())
            .collect()
    }

    /// G-14 (audit 2026-08-19). `ToolRegistry.handlers` is a `HashMap` with
    /// `RandomState`, `list_tools()` never ordered, and `search` truncated with
    /// `matches.truncate(limit)` and no ranking. Six fresh processes returned
    /// six different result sets for `{query:"restart",limit:5}`, and the best
    /// hit `ssh_service_restart` survived only 2 runs out of 9. Truncation is
    /// the common case: "list" matches 117 tools, "file" 75, "status" 55.
    #[test]
    fn search_is_deterministic_and_ranks_name_matches_first() {
        let registry = create_all_enabled_registry();

        // 1. The source of the instability: registry listing order.
        let listed: Vec<String> = registry.list_tools().into_iter().map(|t| t.name).collect();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(
            listed, sorted,
            "ToolRegistry::list_tools must be name-sorted"
        );

        // 2. Determinism: repeated calls in one process return the same list.
        let first = search_names(&registry, "restart", 5);
        for _ in 0..5 {
            assert_eq!(search_names(&registry, "restart", 5), first);
        }

        // 3. Name matches outrank description-only matches, so the three tools
        //    whose NAME contains "restart" all survive limit = 5.
        assert!(
            first.contains(&"ssh_service_restart".to_string()),
            "got: {first:?}"
        );
        assert!(
            first.contains(&"ssh_iis_restart".to_string()),
            "got: {first:?}"
        );
        assert!(
            first.contains(&"ssh_win_service_restart".to_string()),
            "got: {first:?}"
        );

        // 4. An exact name match survives the hardest possible truncation.
        let exact = search_names(&registry, "ssh_service_restart", 1);
        assert_eq!(exact, vec!["ssh_service_restart".to_string()]);
    }

    #[test]
    fn describe_unknown_returns_error() {
        let registry = create_all_enabled_registry();
        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": "nonexistent_xyz"})),
            &registry,
        )
        .expect("meta tool");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn describe_known_returns_schema() {
        let registry = create_all_enabled_registry();
        // Pick any real tool from the registry.
        let some_tool = registry
            .list_tools()
            .into_iter()
            .find(|t| !is_meta_tool(&t.name))
            .expect("registry has tools");
        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": some_tool.name})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        assert_eq!(payload["name"], some_tool.name);
        assert!(payload["input_schema"].is_object());
        assert!(payload["reduction_strategy"].is_string());
    }

    /// G-19 (audit 2026-08-19): in `listing: progressive` the client never sees
    /// `tools/list` entries, so `readOnlyHint` / `destructiveHint` were
    /// unreachable — `describe` and `search` both omitted them, contradicting
    /// the ANNOTATIONS paragraph in the server instructions. The CLI never had
    /// this hole (`src/cli/runner.rs` emits "annotations").
    #[test]
    fn describe_exposes_annotations() {
        let registry = create_all_enabled_registry();

        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": "ssh_status"})),
            &registry,
        )
        .expect("meta");
        let payload = result.structured_content.expect("structured");
        assert_eq!(payload["annotations"]["readOnlyHint"], json!(true));
        assert_eq!(payload["annotations"]["destructiveHint"], json!(false));

        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": "ssh_service_restart"})),
            &registry,
        )
        .expect("meta");
        let payload = result.structured_content.expect("structured");
        assert_eq!(payload["annotations"]["readOnlyHint"], json!(false));
        assert_eq!(payload["annotations"]["idempotentHint"], json!(true));
    }

    #[test]
    fn search_exposes_annotations() {
        let registry = create_all_enabled_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "ssh_service_restart", "limit": 1})),
            &registry,
        )
        .expect("meta");
        let payload = result.structured_content.expect("structured");
        let entry = &payload["results"][0];
        assert_eq!(entry["name"], json!("ssh_service_restart"));
        assert_eq!(entry["annotations"]["readOnlyHint"], json!(false));
        assert_eq!(entry["annotations"]["destructiveHint"], json!(false));
    }

    /// `mcp_call_tool` dispatches to an arbitrary tool, so its own annotations
    /// must be conservative rather than `null`. The MCP default for an absent
    /// `destructiveHint` is already `true`; declaring it explicitly adds a
    /// title and stops clients from having to guess.
    #[test]
    fn call_tool_definition_declares_conservative_annotations() {
        let ann = call_tool_definition()
            .annotations
            .expect("mcp_call_tool must declare annotations");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, Some(false));
        assert_eq!(ann.open_world_hint, Some(true));
        assert!(ann.title.is_some());
    }

    // ============== Targeted mutation-killing tests for `search` ==============

    /// `replace == with !=` on the group-filter equality test (line
    /// ~185) — when a `group` filter is supplied, the helper must
    /// only return tools whose group **equals** the filter.
    #[test]
    fn search_with_group_filter_returns_only_matching_group() {
        let registry = create_all_enabled_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "ps", "group": "docker", "limit": 50})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        let results = payload["results"].as_array().expect("results is array");
        assert!(
            !results.is_empty(),
            "docker group should have at least one tool matching 'ps'"
        );
        for entry in results {
            assert_eq!(
                entry["group"].as_str().unwrap(),
                "docker",
                "every result must be in the requested group, got {entry:?}"
            );
        }
    }

    /// `replace || with &&` on the name/description match (line ~187).
    /// Build a synthetic registry where one tool has the substring in
    /// its name only and another has it in its description only —
    /// both must surface under `||`, but neither would under `&&`.
    #[test]
    fn search_or_match_covers_name_xor_description() {
        use crate::mcp::registry::ToolRegistry;
        use crate::ports::{ToolContext, ToolHandler, ToolSchema};
        use std::sync::Arc;

        struct StaticHandler {
            name: &'static str,
            description: &'static str,
        }
        #[async_trait::async_trait]
        impl ToolHandler for StaticHandler {
            fn name(&self) -> &'static str {
                self.name
            }
            fn description(&self) -> &'static str {
                self.description
            }
            fn schema(&self) -> ToolSchema {
                ToolSchema {
                    name: self.name,
                    description: self.description,
                    input_schema: r#"{"type":"object"}"#,
                }
            }
            async fn execute(
                &self,
                _args: Option<Value>,
                _ctx: &ToolContext,
            ) -> crate::error::Result<ToolCallResult> {
                Ok(ToolCallResult::text("ok"))
            }
        }

        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(StaticHandler {
            name: "ssh_xyzname",
            description: "Run nothing in particular.",
        }));
        registry.register(Arc::new(StaticHandler {
            name: "ssh_other_tool",
            description: "Trigger the xyzname behaviour on remote.",
        }));

        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "xyzname", "limit": 50})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        let results = payload["results"].as_array().unwrap();
        let names: Vec<&str> = results
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"ssh_xyzname"),
            "match in name only must surface — got {names:?}"
        );
        assert!(
            names.contains(&"ssh_other_tool"),
            "match in description only must surface — got {names:?}"
        );
    }

    /// `replace > with ==` / `<` / `>=` on the truncation length check
    /// (line ~191): descriptions longer than 160 chars must be
    /// truncated, descriptions of exactly 160 chars must NOT be.
    /// Build a synthetic registry to make both sides observable.
    #[test]
    fn search_truncates_strict_above_160_chars() {
        use crate::mcp::registry::ToolRegistry;
        use crate::ports::{ToolContext, ToolHandler, ToolSchema};
        use std::sync::Arc;

        // Static descriptions sized exactly 160 and 161 chars so we
        // can pin the boundary behavior of `len() > 160`.
        const DESC_160: &str = "0123456789012345678901234567890123456789\
                                0123456789012345678901234567890123456789\
                                0123456789012345678901234567890123456789\
                                0123456789012345678901234567890123456789";
        const DESC_161: &str = "0123456789012345678901234567890123456789\
                                0123456789012345678901234567890123456789\
                                0123456789012345678901234567890123456789\
                                01234567890123456789012345678901234567890";

        struct StaticHandler {
            name: &'static str,
            description: &'static str,
        }
        #[async_trait::async_trait]
        impl ToolHandler for StaticHandler {
            fn name(&self) -> &'static str {
                self.name
            }
            fn description(&self) -> &'static str {
                self.description
            }
            fn schema(&self) -> ToolSchema {
                ToolSchema {
                    name: self.name,
                    description: self.description,
                    input_schema: r#"{"type":"object"}"#,
                }
            }
            async fn execute(
                &self,
                _args: Option<Value>,
                _ctx: &ToolContext,
            ) -> crate::error::Result<ToolCallResult> {
                Ok(ToolCallResult::text("ok"))
            }
        }

        // Sanity at compile/test time.
        assert_eq!(DESC_160.len(), 160, "DESC_160 must be exactly 160 bytes");
        assert_eq!(DESC_161.len(), 161, "DESC_161 must be exactly 161 bytes");

        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(StaticHandler {
            name: "ssh_match_160",
            description: DESC_160,
        }));
        registry.register(Arc::new(StaticHandler {
            name: "ssh_match_161",
            description: DESC_161,
        }));

        // Use a query that hits both names (substring `match_`).
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "match_", "limit": 50})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        let results = payload["results"].as_array().unwrap();

        let entry_160 = results
            .iter()
            .find(|r| r["name"] == "ssh_match_160")
            .expect("160-char entry present");
        let entry_161 = results
            .iter()
            .find(|r| r["name"] == "ssh_match_161")
            .expect("161-char entry present");

        let desc_160 = entry_160["description"].as_str().unwrap();
        let desc_161 = entry_161["description"].as_str().unwrap();

        assert!(
            !desc_160.ends_with('…'),
            "160-char description must NOT be truncated (kills `> -> >=`)"
        );
        assert_eq!(
            desc_160.len(),
            160,
            "160-char description must be returned verbatim"
        );
        assert!(
            desc_161.ends_with('…'),
            "161-char description must be truncated (kills `> -> ==` and `> -> <`)"
        );
    }

    // ============== `unwrap_call_tool` (mcp_call_tool dispatcher) ==============

    #[test]
    fn test_unwrap_call_tool_ok() {
        let args = json!({"name": "ssh_status", "arguments": {"host": "pi"}});
        let (name, inner) = unwrap_call_tool(Some(&args)).unwrap();
        assert_eq!(name, "ssh_status");
        assert_eq!(inner.unwrap()["host"], "pi");
    }

    #[test]
    fn test_unwrap_call_tool_no_arguments_key() {
        let args = json!({"name": "ssh_status"});
        let (name, inner) = unwrap_call_tool(Some(&args)).unwrap();
        assert_eq!(name, "ssh_status");
        assert!(inner.is_none());
    }

    #[test]
    fn test_unwrap_call_tool_missing_name_is_error() {
        let args = json!({"arguments": {}});
        assert!(unwrap_call_tool(Some(&args)).is_err());
        assert!(unwrap_call_tool(None).is_err());
    }

    #[test]
    fn test_unwrap_call_tool_whitespace_only_name_is_error() {
        let args = json!({"name": "   ", "arguments": {}});
        let err = unwrap_call_tool(Some(&args)).unwrap_err();
        assert!(
            err.contains("`name` (string, non-empty) is required"),
            "got: {err}"
        );
    }

    /// The three meta-tools advertised `taskSupport: "optional"` but are
    /// dispatched in `handle_tools_call` BEFORE the task branch, so `params.task`
    /// was silently dropped. `mcp_call_tool` advertised nothing (spec default:
    /// "forbidden") yet accepted a task, because the name rewrite happens before
    /// the task branch. Coherent assignment: meta-tools forbid, the dispatcher
    /// allows (audit 2026-08-19).
    #[test]
    fn task_support_is_coherent_with_dispatch() {
        assert_eq!(task_support(LIST_TOOL_GROUPS), "forbidden");
        assert_eq!(task_support(SEARCH_TOOLS), "forbidden");
        assert_eq!(task_support(DESCRIBE_TOOL), "forbidden");
        assert_eq!(task_support(CALL_TOOL), "optional");
        assert_eq!(task_support("ssh_status"), "optional");

        for def in definitions() {
            assert_eq!(
                def.execution.expect("execution").task_support,
                "forbidden",
                "meta-tool {} must forbid tasks",
                def.name
            );
        }
        assert_eq!(
            call_tool_definition()
                .execution
                .expect("execution")
                .task_support,
            "optional"
        );
    }

    #[test]
    fn describe_reports_task_support() {
        let registry = create_all_enabled_registry();
        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": "ssh_status"})),
            &registry,
        )
        .expect("meta");
        let payload = result.structured_content.expect("structured");
        assert_eq!(payload["task_support"], json!("optional"));
    }
}
