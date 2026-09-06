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

/// Apply a jq program to a YAML document or stream.
///
/// `helm template` prints several documents separated by `---`; like
/// `yq eval`, the program runs on each document and the outputs are
/// concatenated, one result per line. A single document behaves as before.
///
/// # Errors
///
/// - `BridgeError::McpInvalidRequest` if the YAML cannot be parsed
/// - Any error from `apply_jq_filter` (filter parse/compile/runtime)
pub fn apply_yq_filter(input: &str, filter_expr: &str) -> Result<String> {
    let mut out = Vec::new();
    for doc in yaml_documents_as_json(input)? {
        let result = crate::domain::jq_filter::apply_jq_filter(&doc, filter_expr)?;
        if !result.is_empty() {
            out.push(result);
        }
    }
    Ok(out.join("\n"))
}

/// Same as [`apply_yq_filter`], each result rendered as one TSV row.
///
/// # Errors
///
/// Same as [`apply_yq_filter`].
pub fn apply_yq_filter_tsv(input: &str, filter_expr: &str) -> Result<String> {
    let mut out = Vec::new();
    for doc in yaml_documents_as_json(input)? {
        let result = crate::domain::jq_filter::apply_jq_filter_tsv(&doc, filter_expr)?;
        if !result.is_empty() {
            out.push(result);
        }
    }
    Ok(out.join("\n"))
}

/// Every non-null document of the stream as a compact JSON string, in order.
fn yaml_documents_as_json(yaml: &str) -> Result<Vec<String>> {
    let docs: Vec<serde_json::Value> = super::yaml::parse_yaml_documents(yaml).map_err(|e| {
        BridgeError::McpInvalidRequest(format!(
            "yq_filter requires YAML input, but failed to parse: {e}"
        ))
    })?;
    docs.into_iter()
        .filter(|doc| !doc.is_null())
        .map(|doc| {
            serde_json::to_string(&doc).map_err(|e| {
                BridgeError::McpInvalidRequest(format!("YAML→JSON conversion failed: {e}"))
            })
        })
        .collect()
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

    #[test]
    fn yq_runs_on_every_document_of_a_stream() {
        let yaml = "---\n# Source: a.yaml\nkind: ServiceAccount\nmetadata:\n  name: sa\n---\nkind: Deployment\nmetadata:\n  name: app\n";
        assert_eq!(
            apply_yq_filter(yaml, ".kind").unwrap(),
            "\"ServiceAccount\"\n\"Deployment\""
        );
        assert_eq!(
            apply_yq_filter_tsv(yaml, "[.kind, .metadata.name]").unwrap(),
            "ServiceAccount\tsa\nDeployment\tapp"
        );
    }

    #[test]
    fn yq_helm_template_fixture_lists_every_kind() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sanitizer/helm_template.yaml"
        ))
        .expect("fixture");
        assert_eq!(
            apply_yq_filter_tsv(&raw, ".kind").unwrap(),
            "Secret\nDeployment"
        );
    }

    #[test]
    fn yq_document_without_output_contributes_nothing() {
        let yaml = "---\nkind: A\n---\nother: 1\n";
        assert_eq!(
            apply_yq_filter(yaml, ".kind | select(. != null)").unwrap(),
            "\"A\""
        );
    }

    #[test]
    fn yq_comment_only_leading_segment_is_skipped() {
        let yaml = "---\n# generated\n---\nkind: A\n";
        assert_eq!(apply_yq_filter(yaml, ".kind").unwrap(), "\"A\"");
    }
}
