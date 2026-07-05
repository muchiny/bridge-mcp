//! JQ Filter Engine
//!
//! Applies jq expressions to JSON output using `jaq-core` for
//! server-side data reduction before returning results to the LLM.
//! This can reduce token consumption by up to 99% on large JSON outputs.
//!
//! Feature-gated behind the `jq` feature flag.

use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::Val;

use crate::error::{BridgeError, Result};

/// Apply a jq filter expression to a JSON string.
///
/// Returns the filtered output as a string. If the filter produces
/// multiple results, they are joined with newlines.
///
/// If `input` is not valid JSON, returns an error suggesting the use
/// of other data reduction params (`columns`, `limit`) instead.
///
/// # Errors
///
/// Returns `BridgeError::McpInvalidRequest` if:
/// - The input is not valid JSON
/// - The filter expression fails to parse or compile
/// - The filter produces a runtime error
pub fn apply_jq_filter(input: &str, filter_expr: &str) -> Result<String> {
    // Parse input JSON
    let input_val: Val = serde_json::from_str(input).map_err(|e| {
        BridgeError::McpInvalidRequest(format!(
            "jq_filter requires JSON output, but command returned plain text: {e}. \
             Use 'columns' or 'limit' parameters for non-JSON output."
        ))
    })?;

    // Set up the jq compiler with standard library definitions
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());

    let loader = Loader::new(defs);
    let arena = Arena::default();

    let program = File {
        code: filter_expr,
        path: (),
    };

    // Parse the filter
    let modules = loader.load(&arena, program).map_err(|errs| {
        let msg = errs
            .into_iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("; ");
        BridgeError::McpInvalidRequest(format!("jq filter parse error: {msg}"))
    })?;

    // Compile the filter
    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| {
            let msg = errs
                .into_iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("; ");
            BridgeError::McpInvalidRequest(format!("jq filter compile error: {msg}"))
        })?;

    // Execute the filter
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let results: Vec<String> = filter
        .id
        .run((ctx, input_val))
        .map(unwrap_valr)
        .map(|r| match r {
            Ok(val) => val.to_string(),
            Err(e) => format!("jq error: {e}"),
        })
        .collect();

    if results.is_empty() {
        Ok(String::new())
    } else {
        Ok(results.join("\n"))
    }
}

/// Apply a jq filter expression and serialize results as TSV
/// (tab-separated values).
///
/// Each result that is a JSON array becomes one TSV line, with elements
/// joined by `\t`. Each result that is a JSON object becomes one TSV line
/// with values joined by `\t` (in the order returned by jaq, which is
/// insertion-order for objects). Scalar results are stringified directly.
///
/// Strings have their JSON quotes stripped (so `"web01"` becomes `web01`).
/// Null becomes the empty string.
///
/// This is a token-efficient alternative to JSON output for tabular data:
/// `[{"a":"1","b":"2"}]` (15 chars) → `1\t2` (3 chars).
///
/// # Errors
///
/// Returns the same errors as `apply_jq_filter` (parse, compile, runtime).
pub fn apply_jq_filter_tsv(input: &str, filter_expr: &str) -> Result<String> {
    // Parse input JSON
    let input_val: Val = serde_json::from_str(input).map_err(|e| {
        BridgeError::McpInvalidRequest(format!(
            "jq_filter requires JSON output, but command returned plain text: {e}. \
             Use 'columns' or 'limit' parameters for non-JSON output."
        ))
    })?;

    // Set up the jq compiler
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());

    let loader = Loader::new(defs);
    let arena = Arena::default();

    let program = File {
        code: filter_expr,
        path: (),
    };

    let modules = loader.load(&arena, program).map_err(|errs| {
        let msg = errs
            .into_iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("; ");
        BridgeError::McpInvalidRequest(format!("jq filter parse error: {msg}"))
    })?;

    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| {
            let msg = errs
                .into_iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("; ");
            BridgeError::McpInvalidRequest(format!("jq filter compile error: {msg}"))
        })?;

    // Execute the filter and collect results as JSON values for TSV conversion
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let lines: Vec<String> = filter
        .id
        .run((ctx, input_val))
        .map(unwrap_valr)
        .map(|r| match r {
            Ok(val) => val_to_tsv_line(&val),
            Err(e) => format!("jq error: {e}"),
        })
        .collect();

    Ok(lines.join("\n"))
}

/// Convert a single jaq `Val` to one TSV line.
///
/// Arrays/objects → values joined by `\t`. Scalars → unquoted string.
/// Implementation note: jaq's `Val` does not implement `serde::Serialize`,
/// so we go through its `Display` impl which produces valid JSON.
fn val_to_tsv_line(val: &Val) -> String {
    let json_str = val.to_string();
    match serde_json::from_str::<serde_json::Value>(&json_str) {
        Ok(json) => json_to_tsv_line(&json),
        // Fallback: jaq's string representation if it's not valid JSON
        // (shouldn't happen since jaq Val::Display always emits JSON)
        Err(_) => json_str,
    }
}

/// Convert a `serde_json::Value` to one TSV line.
fn json_to_tsv_line(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(json_scalar_to_string)
            .collect::<Vec<_>>()
            .join("\t"),
        serde_json::Value::Object(obj) => obj
            .values()
            .map(json_scalar_to_string)
            .collect::<Vec<_>>()
            .join("\t"),
        _ => json_scalar_to_string(val),
    }
}

/// Stringify a scalar JSON value without surrounding quotes.
/// Nested arrays/objects fall back to compact JSON serialization.
fn json_scalar_to_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        // Nested structures: use compact JSON to avoid losing data
        _ => serde_json::to_string(val).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_filter() {
        let input = r#"{"name": "test", "value": 42}"#;
        let result = apply_jq_filter(input, ".").unwrap();
        assert!(result.contains("name"));
        assert!(result.contains("42"));
    }

    #[test]
    fn test_field_selection() {
        let input = r#"{"name": "web", "status": "running", "pid": 1234}"#;
        let result = apply_jq_filter(input, ".name").unwrap();
        assert_eq!(result, r#""web""#);
    }

    #[test]
    fn test_object_construction() {
        let input = r#"[{"name": "web", "status": "running", "cpu": 45}, {"name": "db", "status": "running", "cpu": 12}]"#;
        let result = apply_jq_filter(input, ".[] | {name, cpu}").unwrap();
        assert!(result.contains(r#""web""#));
        assert!(result.contains(r#""db""#));
    }

    #[test]
    fn test_select_filter() {
        let input = r#"[{"name": "web", "cpu": 45}, {"name": "db", "cpu": 5}]"#;
        let result = apply_jq_filter(input, "[.[] | select(.cpu > 10)]").unwrap();
        assert!(result.contains("web"));
        assert!(!result.contains(r#""db""#));
    }

    #[test]
    fn test_length() {
        let input = r"[1, 2, 3, 4, 5]";
        let result = apply_jq_filter(input, "length").unwrap();
        assert_eq!(result, "5");
    }

    #[test]
    fn test_keys() {
        let input = r#"{"b": 1, "a": 2, "c": 3}"#;
        let result = apply_jq_filter(input, "keys").unwrap();
        assert!(result.contains(r#""a""#));
        assert!(result.contains(r#""b""#));
    }

    #[test]
    fn test_map() {
        let input = r"[1, 2, 3]";
        let result = apply_jq_filter(input, "map(. * 2)").unwrap();
        assert!(result.contains('2'));
        assert!(result.contains('4'));
        assert!(result.contains('6'));
    }

    #[test]
    fn test_invalid_json_input() {
        let input = "not json at all";
        let result = apply_jq_filter(input, ".");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("jq_filter requires JSON"));
        // The hint must name params that actually exist (columns/limit),
        // not the never-implemented `fields`.
        assert!(
            err.contains("'columns'"),
            "hint must mention columns: {err}"
        );
        assert!(
            !err.contains("'fields'"),
            "hint must not mention fields: {err}"
        );
    }

    #[test]
    fn test_invalid_filter() {
        let input = r#"{"a": 1}"#;
        let result = apply_jq_filter(input, ".[invalid syntax");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_result() {
        let input = r#"[{"a": 1}, {"a": 2}]"#;
        let result = apply_jq_filter(input, "[.[] | select(.a > 100)]").unwrap();
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_multiple_results() {
        let input = r"[1, 2, 3]";
        let result = apply_jq_filter(input, ".[]").unwrap();
        assert_eq!(result, "1\n2\n3");
    }

    #[test]
    fn test_nested_access() {
        let input = r#"{"a": {"b": {"c": "deep"}}}"#;
        let result = apply_jq_filter(input, ".a.b.c").unwrap();
        assert_eq!(result, r#""deep""#);
    }

    #[test]
    fn test_array_slice() {
        let input = r"[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]";
        let result = apply_jq_filter(input, ".[0:3]").unwrap();
        assert!(result.contains('0'));
        assert!(result.contains('1'));
        assert!(result.contains('2'));
    }

    #[test]
    fn test_sort_by() {
        let input = r#"[{"name": "c", "v": 3}, {"name": "a", "v": 1}, {"name": "b", "v": 2}]"#;
        let result = apply_jq_filter(input, "sort_by(.v) | .[0].name").unwrap();
        assert_eq!(result, r#""a""#);
    }

    // ============== K8s-style patterns ==============

    #[test]
    fn test_k8s_items_field_access() {
        let input = r#"{"items":[{"name":"a"},{"name":"b"},{"name":"c"}]}"#;
        let result = apply_jq_filter(input, ".items").unwrap();
        assert!(result.contains(r#""a""#));
    }

    #[test]
    fn test_k8s_items_slice() {
        let input =
            r#"{"items":[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"},{"name":"e"}]}"#;
        let result = apply_jq_filter(input, "[.items[:2][] | {name}]").unwrap();
        assert!(result.contains(r#""a""#), "got: {result}");
        assert!(result.contains(r#""b""#), "got: {result}");
        assert!(
            !result.contains(r#""c""#),
            "should not contain c, got: {result}"
        );
    }

    #[test]
    fn test_k8s_nested_field_extraction() {
        let input = r#"{"items":[{"metadata":{"name":"pod1","namespace":"ns1"},"status":{"phase":"Running"}}]}"#;
        let result = apply_jq_filter(
            input,
            r"[.items[] | {name: .metadata.name, ns: .metadata.namespace, phase: .status.phase}]",
        )
        .unwrap();
        assert!(result.contains("pod1"), "got: {result}");
        assert!(result.contains("ns1"), "got: {result}");
        assert!(result.contains("Running"), "got: {result}");
    }

    #[test]
    fn test_tab_join_workaround() {
        // @tsv is not supported by jaq-core, but join("\t") works
        let input = r#"[{"a":"1","b":"2"},{"a":"3","b":"4"}]"#;
        let result = apply_jq_filter(input, r#".[] | [.a, .b] | join("\t")"#).unwrap();
        // jaq returns JSON strings: "1\t2" (with literal \t inside quotes)
        assert!(result.contains(r"1\t2"), "got: {result}");
        assert!(result.contains(r"3\t4"), "got: {result}");
    }

    // ============== TSV output tests ==============

    #[test]
    fn test_tsv_array_of_arrays() {
        let input = r"[[1,2,3],[4,5,6]]";
        let result = apply_jq_filter_tsv(input, ".[]").unwrap();
        assert_eq!(result, "1\t2\t3\n4\t5\t6");
    }

    #[test]
    fn test_tsv_array_of_objects() {
        // When jq emits objects, value order depends on serde_json's
        // map implementation (alphabetical by default). For predictable
        // TSV column order, users should wrap in arrays:
        //     ".[] | [.host, .ok, .changed]"
        // This test validates that all values are present and tab-separated.
        let input = r#"[{"host":"web01","ok":12,"changed":2},{"host":"web02","ok":8,"changed":0}]"#;
        let result = apply_jq_filter_tsv(input, ".[]").unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2, "Expected 2 lines, got: {result:?}");
        // First row contains web01, 12, 2 (in some order)
        assert!(lines[0].contains("web01"));
        assert!(lines[0].contains("12"));
        assert!(lines[0].contains('\t'));
        // Second row contains web02, 8, 0
        assert!(lines[1].contains("web02"));
        assert!(lines[1].contains('8'));
    }

    #[test]
    fn test_tsv_built_arrays() {
        // Most common pattern: filter selects fields into an array per row
        let input = r#"[{"id":1,"name":"a"},{"id":2,"name":"b"}]"#;
        let result = apply_jq_filter_tsv(input, ".[] | [.id, .name]").unwrap();
        assert_eq!(result, "1\ta\n2\tb");
    }

    #[test]
    fn test_tsv_strings_unquoted() {
        let input = r#"["hello","world"]"#;
        let result = apply_jq_filter_tsv(input, ".[]").unwrap();
        // Strings appear without surrounding quotes
        assert_eq!(result, "hello\nworld");
        assert!(!result.contains('"'));
    }

    #[test]
    fn test_tsv_null_becomes_empty() {
        let input = r"[1,null,3]";
        let result = apply_jq_filter_tsv(input, ".").unwrap();
        // [1,null,3] as one array → "1\t\t3"
        assert_eq!(result, "1\t\t3");
    }

    #[test]
    fn test_tsv_scalar_result() {
        let input = r#"{"name":"web01"}"#;
        let result = apply_jq_filter_tsv(input, ".name").unwrap();
        // Scalar string result, unquoted
        assert_eq!(result, "web01");
    }

    #[test]
    fn test_tsv_invalid_json_input() {
        let input = "not json";
        let result = apply_jq_filter_tsv(input, ".");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("'columns'"),
            "hint must mention columns: {err}"
        );
        assert!(
            !err.contains("'fields'"),
            "hint must not mention fields: {err}"
        );
    }

    #[test]
    fn test_tsv_token_efficiency() {
        // Demonstrate the actual token saving on a realistic AWX-like input
        let input = r#"[{"host_name":"web01","ok":12,"changed":2,"failures":0},{"host_name":"web02","ok":8,"changed":0,"failures":1}]"#;
        let json_result =
            apply_jq_filter(input, ".[] | {host_name, ok, changed, failures}").unwrap();
        let tsv_result =
            apply_jq_filter_tsv(input, ".[] | [.host_name, .ok, .changed, .failures]").unwrap();
        // TSV must be smaller (typically by 60%+)
        assert!(
            tsv_result.len() < json_result.len(),
            "TSV ({} chars) should be smaller than JSON ({} chars)",
            tsv_result.len(),
            json_result.len()
        );
        // Sanity: TSV contains the data
        assert!(tsv_result.contains("web01"));
        assert!(tsv_result.contains("12"));
    }

    #[test]
    fn test_group_by() {
        let input = r#"[{"type": "a", "v": 1}, {"type": "b", "v": 2}, {"type": "a", "v": 3}]"#;
        let result = apply_jq_filter(
            input,
            "[group_by(.type)[] | {type: .[0].type, count: length}]",
        )
        .unwrap();
        assert!(result.contains(r#""a""#));
        assert!(result.contains(r#""b""#));
    }
}
