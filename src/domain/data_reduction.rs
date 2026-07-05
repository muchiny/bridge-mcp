//! Data Reduction Utilities
//!
//! Extracts universal data-reduction parameters (`jq_filter`, `columns`)
//! from tool arguments for server-side output filtering before returning
//! results to the LLM.

use serde::Deserialize;

#[cfg(not(feature = "jq"))]
use crate::error::BridgeError;
use crate::error::Result;

/// Universal data reduction parameters extracted from tool arguments.
///
/// Extracted from the raw JSON before tool-specific argument parsing
/// so these keys don't cause deserialization errors.
#[derive(Debug, Default, Deserialize)]
pub struct DataReductionArgs {
    /// jq filter expression for JSON output (requires `jq` feature).
    /// Example: `.[] | {name, status}`
    #[cfg(feature = "jq")]
    pub jq_filter: Option<String>,

    /// yq filter expression for YAML output (requires `jq` feature).
    /// Same syntax as jq, applied after parsing YAML to a generic value tree.
    /// Example: `.all.children.webservers.hosts | keys`
    #[cfg(feature = "jq")]
    pub yq_filter: Option<String>,

    /// Column filter for tabular output.
    /// Case-insensitive header match; unknown columns are silently ignored.
    /// Example: `["NAME", "STATUS", "CPU"]`
    pub columns: Option<Vec<String>>,

    /// Maximum number of data rows to return (header always kept).
    /// Applied after column filtering.
    pub limit: Option<u64>,

    /// Output format for jq/yq filter results. `"json"` (default) returns
    /// jaq-native JSON serialization. `"tsv"` joins array elements with
    /// tabs and rows with newlines for maximum token efficiency.
    /// The jq/yq filter must produce arrays for TSV output (objects
    /// fall back to JSON serialization).
    #[cfg(feature = "jq")]
    pub output_format: Option<String>,
}

impl DataReductionArgs {
    /// Extract data reduction params from a JSON value, removing them
    /// so they don't interfere with tool-specific argument parsing.
    ///
    /// # Errors
    ///
    /// When the binary is built WITHOUT the `jq` feature and the caller
    /// supplied `jq_filter`, `yq_filter`, or `output_format`, returns
    /// `BridgeError::McpInvalidRequest` instead of silently ignoring the
    /// param — the model must not believe its filter was applied.
    pub fn extract(value: &mut serde_json::Value) -> Result<Self> {
        let Some(obj) = value.as_object_mut() else {
            return Ok(Self::default());
        };

        #[cfg(not(feature = "jq"))]
        for key in ["jq_filter", "yq_filter", "output_format"] {
            if obj.contains_key(key) {
                return Err(BridgeError::McpInvalidRequest(format!(
                    "'{key}' is not available: this bridge-mcp binary was built \
                     without the 'jq' feature. Use 'columns' (tabular output) or \
                     'limit' instead, or rebuild with --features full."
                )));
            }
        }

        #[cfg(feature = "jq")]
        let jq_filter = obj
            .remove("jq_filter")
            .and_then(|v| v.as_str().map(String::from));

        #[cfg(feature = "jq")]
        let yq_filter = obj
            .remove("yq_filter")
            .and_then(|v| v.as_str().map(String::from));

        let columns = obj.remove("columns").and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect()
            })
        });

        let limit = obj.remove("limit").and_then(|v| v.as_u64());

        #[cfg(feature = "jq")]
        let output_format = obj
            .remove("output_format")
            .and_then(|v| v.as_str().map(String::from));

        Ok(Self {
            #[cfg(feature = "jq")]
            jq_filter,
            #[cfg(feature = "jq")]
            yq_filter,
            columns,
            limit,
            #[cfg(feature = "jq")]
            output_format,
        })
    }

    /// Returns true if no data reduction is requested.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jq")]
        if self.jq_filter.is_some() {
            return false;
        }
        #[cfg(feature = "jq")]
        if self.yq_filter.is_some() {
            return false;
        }
        if self.columns.is_some() {
            return false;
        }
        if self.limit.is_some() {
            return false;
        }
        true
    }

    /// Returns true if TSV output format was requested.
    #[cfg(feature = "jq")]
    #[must_use]
    pub fn wants_tsv(&self) -> bool {
        self.output_format
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("tsv"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty() {
        let mut v = serde_json::json!({"host": "prod"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(args.is_empty());
        assert!(v.get("host").is_some());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_extract_jq_filter() {
        let mut v = serde_json::json!({"host": "prod", "jq_filter": ".[] | {name}"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert_eq!(args.jq_filter.as_deref(), Some(".[] | {name}"));
        assert!(v.get("jq_filter").is_none());
        assert!(v.get("host").is_some());
    }

    #[test]
    fn test_extract_non_object() {
        let mut v = serde_json::json!("string");
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(args.is_empty());
    }

    #[cfg(not(feature = "jq"))]
    #[test]
    fn test_extract_jq_param_without_feature_is_error() {
        let mut v = serde_json::json!({"host": "prod", "jq_filter": ".name"});
        let err = DataReductionArgs::extract(&mut v).unwrap_err().to_string();
        assert!(err.contains("'jq' feature"), "got: {err}");
        assert!(
            err.contains("columns"),
            "must suggest working fallbacks: {err}"
        );
    }

    #[cfg(not(feature = "jq"))]
    #[test]
    fn test_extract_output_format_without_feature_is_error() {
        let mut v = serde_json::json!({"output_format": "tsv"});
        assert!(DataReductionArgs::extract(&mut v).is_err());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_is_empty_with_filter() {
        let mut v = serde_json::json!({"jq_filter": ".name"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.is_empty());
    }

    #[test]
    fn test_extract_columns() {
        let mut v = serde_json::json!({"host": "prod", "columns": ["NAME", "STATUS"]});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert_eq!(
            args.columns.as_deref(),
            Some(&["NAME".to_string(), "STATUS".to_string()][..])
        );
        assert!(v.get("columns").is_none());
        assert!(v.get("host").is_some());
    }

    #[test]
    fn test_is_empty_with_columns() {
        let mut v = serde_json::json!({"columns": ["PID"]});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.is_empty());
    }

    #[test]
    fn test_extract_columns_non_string_items_ignored() {
        let mut v = serde_json::json!({"columns": ["NAME", 42, "STATUS", null]});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        let cols = args.columns.unwrap();
        assert_eq!(cols, vec!["NAME", "STATUS"]);
    }

    #[test]
    fn test_extract_columns_not_array() {
        let mut v = serde_json::json!({"columns": "NAME"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(args.columns.is_none());
    }

    #[test]
    fn test_extract_limit() {
        let mut v = serde_json::json!({"host": "prod", "limit": 10});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert_eq!(args.limit, Some(10));
        assert!(v.get("limit").is_none());
        assert!(v.get("host").is_some());
    }

    #[test]
    fn test_is_empty_with_limit() {
        let mut v = serde_json::json!({"limit": 5});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.is_empty());
    }

    #[test]
    fn test_extract_limit_not_integer() {
        let mut v = serde_json::json!({"limit": "ten"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(args.limit.is_none());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_extract_yq_filter() {
        let mut v = serde_json::json!({"host": "prod", "yq_filter": ".all.children | keys"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert_eq!(args.yq_filter.as_deref(), Some(".all.children | keys"));
        assert!(v.get("yq_filter").is_none());
        assert!(v.get("host").is_some());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_is_empty_with_yq_filter() {
        let mut v = serde_json::json!({"yq_filter": ".name"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.is_empty());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_extract_output_format_tsv() {
        let mut v = serde_json::json!({"output_format": "tsv"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert_eq!(args.output_format.as_deref(), Some("tsv"));
        assert!(args.wants_tsv());
        assert!(v.get("output_format").is_none());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_wants_tsv_case_insensitive() {
        let mut v = serde_json::json!({"output_format": "TSV"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(args.wants_tsv());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_wants_tsv_default_false() {
        let v = serde_json::json!({});
        let mut v = v;
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.wants_tsv());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_wants_tsv_json_format() {
        let mut v = serde_json::json!({"output_format": "json"});
        let args = DataReductionArgs::extract(&mut v).expect("extract must succeed");
        assert!(!args.wants_tsv());
    }
}
