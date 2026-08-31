//! Reject tool arguments the tool does not declare.
//!
//! An unknown key used to be dropped in silence on both call paths. The keys
//! most likely to be mistyped are the reduction params, and a typo in one of
//! those does not fail — it returns the full unreduced output, which looks
//! exactly like a working call. `ssh_firewall_status limit=3` is the shape of
//! the problem: `limit` is not in that tool's schema, so the caller asked for
//! three lines and got 66,443 characters with nothing to say why.
//!
//! Shared by the CLI and the `StandardTool` pipeline deliberately. The CLI got
//! this check first and the MCP path did not, so the same call was rejected
//! through one door and accepted through the other — the same split that let
//! `relevance_rank` mean two different things depending on which search you
//! used.

use crate::error::{BridgeError, Result};

/// Levenshtein distance between two short strings.
///
/// Written out rather than pulled in: the only edit-distance need in the crate
/// is suggesting an argument name, over strings a few characters long.
#[must_use]
pub fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut cur = vec![0usize; b_chars.len() + 1];

    for (i, ca) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_chars.len()]
}

/// The closest declared argument name to `key`, if one is close enough to be
/// worth suggesting.
///
/// The threshold scales with the name's length so `hostt` -> `host` is offered
/// while an unrelated word is not: a wrong suggestion is worse than none,
/// because it sends the reader looking in the wrong place.
#[must_use]
pub fn nearest_key<'a>(key: &str, candidates: &'a [String]) -> Option<&'a str> {
    let budget = (key.len() / 3).max(1);
    candidates
        .iter()
        .map(|c| (edit_distance(key, c), c.as_str()))
        .filter(|(d, _)| *d <= budget)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Property names declared by a JSON-Schema object, or an empty vec when the
/// schema cannot be read.
///
/// Empty means "no grounds to call any key wrong", and callers skip the check
/// rather than guessing.
#[must_use]
pub fn declared_keys(schema: &serde_json::Value) -> Vec<String> {
    schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

/// Reject any key in `provided` that `known` does not declare.
///
/// `known` empty is a no-op: an unreadable schema is not evidence that a key is
/// wrong.
///
/// # Errors
///
/// Returns [`BridgeError::McpInvalidRequest`] naming the first unknown key, and
/// the nearest declared name when there is a plausible one.
pub fn reject_unknown_args<'a, I>(tool_name: &str, provided: I, known: &[String]) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    if known.is_empty() {
        return Ok(());
    }

    for key in provided {
        if known.iter().any(|k| k == key) {
            continue;
        }
        let hint =
            nearest_key(key, known).map_or_else(String::new, |k| format!(" Did you mean `{k}`?"));
        return Err(BridgeError::McpInvalidRequest(format!(
            "Unknown argument `{key}` for tool `{tool_name}`.{hint} \
             Call mcp_describe_tool (or `bridge-mcp describe-tool {tool_name}`) \
             to list valid arguments."
        )));
    }
    Ok(())
}

/// Reject a reduction param the tool's `OutputKind` does not support.
///
/// `DataReductionArgs::extract` removes these keys from the request object
/// unconditionally, before `deny_unknown_fields` could ever see them — so on a
/// `RawText` tool they were stripped and silently forgotten.
/// `ssh_firewall_status limit=3` is the case that exposed it: the caller asked
/// for three lines and got 66,443 characters, with nothing to say that `limit`
/// is not a parameter of a raw-text tool. The schema does not advertise it
/// either, so the only way to learn was to compare the output size against what
/// was asked for.
///
/// # Errors
///
/// Returns [`BridgeError::McpInvalidRequest`] naming the param and the kind of
/// output the tool actually produces.
pub fn reject_unsupported_reduction(
    tool_name: &str,
    kind: crate::domain::output_kind::OutputKind,
    provided: &[&str],
) -> Result<()> {
    for param in provided {
        let supported = match *param {
            "jq_filter" => kind.supports_jq(),
            "yq_filter" => kind.supports_yq(),
            "columns" => kind.supports_columns(),
            "limit" => kind.supports_limit(),
            // `output_format` only shapes a jq/yq result, so it rides on those.
            "output_format" => kind.supports_jq() || kind.supports_yq(),
            _ => true,
        };
        if !supported {
            return Err(BridgeError::McpInvalidRequest(format!(
                "`{param}` is not supported by `{tool_name}`: it returns {kind:?} output. \
                 {hint} Call mcp_describe_tool (or `bridge-mcp describe-tool {tool_name}`) \
                 to see its Reduction Strategy.",
                hint = kind.strategy_hint(),
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn edit_distance_counts_single_edits() {
        assert_eq!(edit_distance("host", "host"), 0);
        assert_eq!(edit_distance("hostt", "host"), 1);
        assert_eq!(edit_distance("hos", "host"), 1);
        assert_eq!(edit_distance("hoat", "host"), 1);
        assert_eq!(edit_distance("", "host"), 4);
        assert_eq!(edit_distance("host", ""), 4);
    }

    #[test]
    fn nearest_key_suggests_a_close_typo() {
        let keys = [
            "host".to_string(),
            "command".to_string(),
            "jq_filter".to_string(),
        ];
        assert_eq!(nearest_key("hostt", &keys), Some("host"));
        assert_eq!(nearest_key("jq_fitler", &keys), Some("jq_filter"));
    }

    /// A wrong suggestion is worse than none.
    #[test]
    fn nearest_key_declines_when_nothing_is_close() {
        let keys = ["host".to_string(), "command".to_string()];
        assert_eq!(nearest_key("param_bidon", &keys), None);
        assert_eq!(nearest_key("zzzzzzzz", &keys), None);
        assert_eq!(nearest_key("host", &[]), None);
    }

    #[test]
    fn declared_keys_reads_schema_properties() {
        let schema = json!({"properties": {"host": {}, "command": {}}});
        let mut keys = declared_keys(&schema);
        keys.sort();
        assert_eq!(keys, vec!["command".to_string(), "host".to_string()]);
    }

    #[test]
    fn declared_keys_is_empty_for_an_unreadable_schema() {
        assert!(declared_keys(&json!({})).is_empty());
        assert!(declared_keys(&json!("not an object")).is_empty());
    }

    #[test]
    fn reject_unknown_args_accepts_declared_keys() {
        let known = ["host".to_string(), "command".to_string()];
        let provided = vec!["host".to_string(), "command".to_string()];
        reject_unknown_args("ssh_exec", &provided, &known).expect("declared keys must pass");
    }

    /// The exact call that exposed the gap: `limit` on a `RawText` tool that
    /// never declared it, silently ignored, returning 66 KB instead of 3 lines.
    #[test]
    fn reject_unknown_args_catches_a_param_the_tool_does_not_have() {
        let known = ["host".to_string(), "firewall_tool".to_string()];
        let provided = vec!["host".to_string(), "limit".to_string()];

        let err = reject_unknown_args("ssh_firewall_status", &provided, &known)
            .expect_err("an undeclared param must be refused");
        let msg = err.to_string();

        assert!(msg.contains("limit"), "must name the offending key: {msg}");
        assert!(
            msg.contains("ssh_firewall_status"),
            "must name the tool: {msg}"
        );
    }

    #[test]
    fn reject_unknown_args_suggests_the_intended_key() {
        let known = ["host".to_string(), "jq_filter".to_string()];
        let provided = vec!["jq_fitler".to_string()];

        let msg = reject_unknown_args("ssh_metrics", &provided, &known)
            .expect_err("typo must be refused")
            .to_string();

        assert!(msg.contains("Did you mean `jq_filter`?"), "got: {msg}");
    }

    // ============== reduction-param support ==============

    /// The call that exposed the gap: `limit` on a `RawText` tool.
    #[test]
    fn reduction_param_is_refused_when_the_kind_cannot_use_it() {
        use crate::domain::output_kind::OutputKind;

        let err =
            reject_unsupported_reduction("ssh_firewall_status", OutputKind::RawText, &["limit"])
                .expect_err("RawText supports no reduction params");
        let msg = err.to_string();

        assert!(msg.contains("limit"), "must name the param: {msg}");
        assert!(
            msg.contains("ssh_firewall_status"),
            "must name the tool: {msg}"
        );
    }

    #[test]
    fn raw_text_refuses_every_reduction_param() {
        use crate::domain::output_kind::OutputKind;

        for param in [
            "jq_filter",
            "yq_filter",
            "columns",
            "limit",
            "output_format",
        ] {
            assert!(
                reject_unsupported_reduction("t", OutputKind::RawText, &[param]).is_err(),
                "{param} must be refused on RawText"
            );
        }
    }

    #[test]
    fn a_kind_that_supports_the_param_accepts_it() {
        use crate::domain::output_kind::OutputKind;

        reject_unsupported_reduction("t", OutputKind::Json, &["jq_filter"])
            .expect("Json supports jq_filter");
        reject_unsupported_reduction("t", OutputKind::Tabular, &["columns", "limit"])
            .expect("Tabular supports columns and limit");
    }

    /// Params outside the reduction vocabulary are none of this check's
    /// business — `deny_unknown_fields` owns those.
    #[test]
    fn unrelated_params_pass_through() {
        use crate::domain::output_kind::OutputKind;

        reject_unsupported_reduction("t", OutputKind::RawText, &["host", "command"])
            .expect("only reduction params are judged here");
    }

    /// An unreadable schema is not evidence that a key is wrong.
    #[test]
    fn reject_unknown_args_is_a_no_op_without_a_schema() {
        let provided = vec!["anything".to_string()];
        reject_unknown_args("t", &provided, &[]).expect("no schema means no grounds to refuse");
    }
}
