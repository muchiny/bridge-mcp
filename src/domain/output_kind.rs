//! Output Kind Classification
//!
//! Declares the expected output format of a tool, enabling type-aware
//! data reduction (jq filtering for JSON, column selection for tabular)
//! and schema injection (only expose relevant params per tool).

/// Declares the expected output format of a tool.
///
/// Used by `StandardToolHandler` to:
/// 1. Inject the right data-reduction params into the tool schema
///    (`jq_filter` for JSON, `columns` for tabular, both for auto).
/// 2. Apply the correct reduction pipeline at runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputKind {
    /// Raw text passthrough — no data reduction available.
    #[default]
    RawText,

    /// Columnar CLI output — supports `columns` filter.
    ///
    /// For tools whose commands produce fixed-width columnar text
    /// (like `ps`, `df`, `ss`).
    Tabular,

    /// Guaranteed JSON output — supports `jq_filter`.
    ///
    /// For tools whose commands always return JSON.
    Json,

    /// Guaranteed YAML output — supports `yq_filter`.
    ///
    /// For tools whose commands always return YAML (e.g., kubectl/helm
    /// with `-o yaml`, ansible-navigator, ansible-inventory --yaml).
    /// At runtime the YAML is parsed via serde-saphyr to a generic value
    /// tree and the same jaq-core engine is used to filter it.
    Yaml,

    /// Output may be JSON or tabular depending on parameters —
    /// supports both `jq_filter` and `columns`.
    ///
    /// At runtime the pipeline tries JSON first, then falls back to tabular.
    Auto,
}

impl OutputKind {
    /// Whether this kind supports `jq_filter`.
    #[must_use]
    pub const fn supports_jq(&self) -> bool {
        matches!(self, Self::Json | Self::Auto)
    }

    /// Whether this kind supports `yq_filter`.
    #[must_use]
    pub const fn supports_yq(&self) -> bool {
        matches!(self, Self::Yaml)
    }

    /// Whether this kind supports `columns`.
    #[must_use]
    pub const fn supports_columns(&self) -> bool {
        matches!(self, Self::Tabular | Self::Auto)
    }

    /// Whether this kind supports `limit`.
    #[must_use]
    pub const fn supports_limit(&self) -> bool {
        matches!(self, Self::Tabular | Self::Auto | Self::Json | Self::Yaml)
    }

    /// Human-readable reduction-strategy hint for this kind.
    ///
    /// Used by `describe-tool` (CLI) and schema metadata to tell the
    /// AI consumer exactly which data-reduction params to use and how.
    #[must_use]
    pub const fn strategy_hint(&self) -> &'static str {
        match self {
            Self::RawText => {
                "None (raw text output). Use save_output=/path/to/file to persist \
                 full untruncated output; truncated results return an output_id \
                 for pagination via ssh_output_fetch."
            }
            Self::Tabular => {
                "Tabular — use columns=[\"A\",\"B\"] to pick fields and limit=N to \
                 cap rows. Header is always preserved."
            }
            Self::Json => {
                "JSON — use jq_filter='.field' to extract only what you need and \
                 output_format='tsv' for 60-80% token savings on list-shaped data. \
                 Example: jq_filter='.items[] | [.name, .status]' output_format=tsv."
            }
            Self::Yaml => {
                "YAML — use yq_filter='.field' (jaq engine over parsed YAML) and \
                 output_format='tsv' for list-shaped data."
            }
            Self::Auto => {
                "Auto-detect JSON or tabular at runtime — accepts all reduction \
                 params (jq_filter, columns, limit, output_format). JSON is tried \
                 first; tabular is the fallback."
            }
        }
    }

    /// Short, actionable remediation appended to truncation messages.
    ///
    /// Unlike [`Self::strategy_hint`] (schema/describe-tool documentation),
    /// this is injected into the tool RESPONSE when output was truncated,
    /// so the model learns the server-side alternative to pagination at
    /// the exact moment it needs it. `RawText` has no reduction params,
    /// hence `None`.
    #[must_use]
    pub const fn truncation_tip(&self) -> Option<&'static str> {
        match self {
            Self::RawText => None,
            Self::Tabular => Some(
                "re-run with columns=[\"COL1\",\"COL2\"] and limit=N to keep \
                 only the fields you need (filtered server-side, before truncation)",
            ),
            Self::Json => Some(
                "re-run with jq_filter='.field' (add output_format=\"tsv\" for \
                 array results) to extract only what you need server-side",
            ),
            Self::Yaml => Some(
                "re-run with yq_filter='.field' (add output_format=\"tsv\" for \
                 array results) to extract only what you need server-side",
            ),
            Self::Auto => Some(
                "re-run with jq_filter='...' (JSON output) or columns=[...] and \
                 limit=N (tabular output) to reduce the output server-side",
            ),
        }
    }

    /// Short compact marker for list-tools output ("jq+tsv", "cols", "—", …).
    #[must_use]
    pub const fn short_marker(&self) -> &'static str {
        match self {
            Self::RawText => "—",
            Self::Tabular => "cols",
            Self::Json => "jq+tsv",
            Self::Yaml => "yq+tsv",
            Self::Auto => "*",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_raw_text() {
        assert_eq!(OutputKind::default(), OutputKind::RawText);
    }

    #[test]
    fn test_supports_jq() {
        assert!(!OutputKind::RawText.supports_jq());
        assert!(!OutputKind::Tabular.supports_jq());
        assert!(OutputKind::Json.supports_jq());
        assert!(!OutputKind::Yaml.supports_jq());
        assert!(OutputKind::Auto.supports_jq());
    }

    #[test]
    fn test_supports_yq() {
        assert!(!OutputKind::RawText.supports_yq());
        assert!(!OutputKind::Tabular.supports_yq());
        assert!(!OutputKind::Json.supports_yq());
        assert!(OutputKind::Yaml.supports_yq());
        assert!(!OutputKind::Auto.supports_yq());
    }

    #[test]
    fn test_supports_columns() {
        assert!(!OutputKind::RawText.supports_columns());
        assert!(OutputKind::Tabular.supports_columns());
        assert!(!OutputKind::Json.supports_columns());
        assert!(!OutputKind::Yaml.supports_columns());
        assert!(OutputKind::Auto.supports_columns());
    }

    #[test]
    fn test_supports_limit() {
        assert!(!OutputKind::RawText.supports_limit());
        assert!(OutputKind::Tabular.supports_limit());
        assert!(OutputKind::Json.supports_limit());
        assert!(OutputKind::Yaml.supports_limit());
        assert!(OutputKind::Auto.supports_limit());
    }

    #[test]
    fn test_debug_display() {
        assert_eq!(format!("{:?}", OutputKind::Auto), "Auto");
    }

    #[test]
    fn test_clone_copy() {
        let kind = OutputKind::Json;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }

    #[test]
    fn test_strategy_hint_mentions_expected_params() {
        assert!(OutputKind::RawText.strategy_hint().contains("save_output"));
        assert!(
            OutputKind::RawText
                .strategy_hint()
                .contains("ssh_output_fetch")
        );
        assert!(OutputKind::Tabular.strategy_hint().contains("columns"));
        assert!(OutputKind::Tabular.strategy_hint().contains("limit"));
        assert!(OutputKind::Json.strategy_hint().contains("jq_filter"));
        assert!(OutputKind::Json.strategy_hint().contains("tsv"));
        assert!(OutputKind::Yaml.strategy_hint().contains("yq_filter"));
        assert!(OutputKind::Auto.strategy_hint().contains("jq_filter"));
        assert!(OutputKind::Auto.strategy_hint().contains("columns"));
    }

    #[test]
    fn test_short_marker() {
        assert_eq!(OutputKind::RawText.short_marker(), "—");
        assert_eq!(OutputKind::Tabular.short_marker(), "cols");
        assert_eq!(OutputKind::Json.short_marker(), "jq+tsv");
        assert_eq!(OutputKind::Yaml.short_marker(), "yq+tsv");
        assert_eq!(OutputKind::Auto.short_marker(), "*");
    }

    #[test]
    fn test_truncation_tip_per_kind() {
        assert!(OutputKind::RawText.truncation_tip().is_none());
        assert!(
            OutputKind::Tabular
                .truncation_tip()
                .is_some_and(|t| t.contains("columns") && t.contains("limit"))
        );
        assert!(
            OutputKind::Json
                .truncation_tip()
                .is_some_and(|t| t.contains("jq_filter"))
        );
        assert!(
            OutputKind::Yaml
                .truncation_tip()
                .is_some_and(|t| t.contains("yq_filter"))
        );
        assert!(
            OutputKind::Auto
                .truncation_tip()
                .is_some_and(|t| t.contains("jq_filter") && t.contains("columns"))
        );
    }
}
