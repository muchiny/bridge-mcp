//! YQ Filter Engine
//!
//! Applies jq-syntax filter expressions to YAML output by parsing the
//! YAML to a generic value tree (`serde_json::Value`) via `serde-saphyr`,
//! then feeding the resulting JSON through the existing `apply_jq_filter`
//! / `apply_jq_filter_tsv` pipeline.
//!
//! Feature-gated behind the `jq` feature flag (the YAML parser is part
//! of the same data-reduction story).

use crate::error::{BridgeError, Result};

/// Apply a jq-syntax filter to YAML input.
///
/// The YAML is parsed into `serde_json::Value` via `serde-saphyr`, then
/// re-serialized to a JSON string and fed to the existing jq engine.
///
/// # Errors
///
/// - `BridgeError::McpInvalidRequest` if the YAML cannot be parsed
/// - Any error from `apply_jq_filter` (filter parse/compile/runtime)
pub fn apply_yq_filter(input: &str, filter_expr: &str) -> Result<String> {
    let json_str = yaml_to_json_string(input)?;
    crate::domain::jq_filter::apply_jq_filter(&json_str, filter_expr)
}

/// Apply a jq-syntax filter to YAML input and serialize results as TSV.
///
/// Same conversion as [`apply_yq_filter`] but uses the TSV serializer.
///
/// # Errors
///
/// Same as [`apply_yq_filter`].
pub fn apply_yq_filter_tsv(input: &str, filter_expr: &str) -> Result<String> {
    let json_str = yaml_to_json_string(input)?;
    crate::domain::jq_filter::apply_jq_filter_tsv(&json_str, filter_expr)
}

/// Parse YAML to a `serde_json::Value` tree, then re-serialize to a
/// JSON string suitable for the jq engine.
fn yaml_to_json_string(yaml: &str) -> Result<String> {
    let value: serde_json::Value = super::yaml::parse_yaml(yaml).map_err(|e| {
        BridgeError::McpInvalidRequest(format!(
            "yq_filter requires YAML input, but failed to parse: {e}"
        ))
    })?;
    serde_json::to_string(&value)
        .map_err(|e| BridgeError::McpInvalidRequest(format!("YAML→JSON conversion failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yq_simple_field() {
        let yaml = "name: web01\nstatus: running\n";
        let result = apply_yq_filter(yaml, ".name").unwrap();
        assert_eq!(result, "\"web01\"");
    }

    #[test]
    fn test_yq_nested_access() {
        let yaml = "
all:
  children:
    webservers:
      hosts:
        web01:
          ansible_host: 10.0.0.1
        web02:
          ansible_host: 10.0.0.2
";
        let result = apply_yq_filter(yaml, ".all.children.webservers.hosts | keys").unwrap();
        assert!(result.contains("web01"));
        assert!(result.contains("web02"));
    }

    #[test]
    fn test_yq_array() {
        let yaml = "items:\n  - foo\n  - bar\n  - baz\n";
        let result = apply_yq_filter(yaml, ".items | length").unwrap();
        assert_eq!(result, "3");
    }

    #[test]
    fn test_yq_invalid_yaml() {
        let yaml = "this: is: not: valid: yaml: : :";
        let result = apply_yq_filter(yaml, ".");
        assert!(result.is_err());
    }

    #[test]
    fn test_yq_tsv_array_extraction() {
        let yaml = "
hosts:
  - name: web01
    status: running
  - name: web02
    status: stopped
";
        let result = apply_yq_filter_tsv(yaml, ".hosts[] | [.name, .status]").unwrap();
        assert_eq!(result, "web01\trunning\nweb02\tstopped");
    }

    #[test]
    fn test_yq_tsv_keys() {
        let yaml = "alpha: 1\nbeta: 2\ngamma: 3\n";
        let result = apply_yq_filter_tsv(yaml, "keys").unwrap();
        // keys returns an array of strings; TSV joins them with \t
        assert_eq!(result, "alpha\tbeta\tgamma");
    }
}
