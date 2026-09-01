//! History Resource Handler
//!
//! Exposes recent command history as an MCP resource.
//!
//! # URI format
//!
//! Base URI: `history://recent`
//!
//! Supported query parameters (all optional, combinable):
//!
//! - `host=<alias>` — filter to entries on a specific host
//! - `since=<duration>` — only entries newer than the relative duration
//!   (supported units: `s`, `m`, `h`, `d`; e.g. `since=1h`, `since=30m`,
//!   `since=2d`)
//! - `limit=<N>` — cap the returned entries (default: 50)
//!
//! Example queries:
//!
//! - `history://recent`
//! - `history://recent?limit=100`
//! - `history://recent?host=prod`
//! - `history://recent?since=1h`
//! - `history://recent?host=prod&since=24h&limit=200`
//!
//! This resource reads directly from the in-memory `CommandHistory`
//! without needing an SSH connection.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};

/// Default number of entries returned when `limit` is not specified.
const DEFAULT_LIMIT: usize = 50;

/// Resource handler for command history
pub struct HistoryResourceHandler;

#[async_trait]
impl ResourceHandler for HistoryResourceHandler {
    fn scheme(&self) -> &'static str {
        "history"
    }

    fn description(&self) -> &'static str {
        "Recent command execution history (filter by host, since, limit)"
    }

    async fn list(&self, _ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        Ok(vec![ResourceDefinition {
            uri: "history://recent".to_string(),
            name: "Recent command history".to_string(),
            description: Some(
                "Command execution history. Supports query params: \
                 host=<alias>, since=<1h|30m|2d>, limit=<N>. \
                 Example: history://recent?host=prod&since=1h&limit=100"
                    .to_string(),
            ),
            mime_type: Some("application/json".to_string()),
        }])
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        // Split the URI into scheme+path and optional query string.
        let (scheme_path, query) = match uri.split_once('?') {
            Some((sp, q)) => (sp, Some(q)),
            None => (uri, None),
        };

        if scheme_path != "history://recent" {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Invalid history URI: {uri}. Use 'history://recent' with optional \
                 ?host=..., ?since=..., ?limit=..."
            )));
        }

        let params = parse_query(query);

        let limit: usize = params
            .get("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LIMIT);

        let host = params.get("host").map(String::as_str);

        let since = match params.get("since") {
            Some(s) => Some(parse_relative_duration(s).map_err(|e| {
                BridgeError::McpInvalidRequest(format!("Invalid 'since' parameter: {e}"))
            })?),
            None => None,
        };

        let entries = match (host, since) {
            (Some(h), Some(ts)) => ctx.history.for_host_since(h, ts, limit),
            (Some(h), None) => ctx.history.for_host(h, limit),
            (None, Some(ts)) => ctx.history.recent_since(ts, limit),
            (None, None) => ctx.history.recent(limit),
        };

        let json = serde_json::to_string_pretty(&entries)
            .unwrap_or_else(|e| format!("Error serializing history: {e}"));

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(json),
        }])
    }
}

/// Parse an ampersand-delimited query string into a map of `key=value` pairs.
///
/// Unlike a full URL parser this is forgiving: unknown params are ignored,
/// missing values become empty strings, and duplicate keys use the last
/// occurrence. URL-decoding is NOT applied — history URIs are internal and
/// don't carry arbitrary user input.
fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    query
        .map(|q| {
            q.split('&')
                .filter(|s| !s.is_empty())
                .map(|kv| {
                    kv.split_once('=')
                        .map_or((kv.to_string(), String::new()), |(k, v)| {
                            (k.to_string(), v.to_string())
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a relative duration string like `1h`, `30m`, `24h`, `2d` into an
/// absolute `DateTime<Utc>` computed as `now - duration`.
///
/// Supported unit suffixes (single character): `s`, `m`, `h`, `d`.
/// Returns `Err(String)` with a human-readable message on malformed input.
fn parse_relative_duration(s: &str) -> std::result::Result<DateTime<Utc>, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    // Split the trailing unit character off the numeric prefix.
    // Using `char_indices().next_back()` handles multi-byte-safe slicing.
    let (num_str, unit) = match s.char_indices().next_back() {
        Some((idx, unit_char)) => (&s[..idx], unit_char),
        None => return Err("empty duration".to_string()),
    };

    if num_str.is_empty() {
        return Err(format!("missing number in '{s}'"));
    }

    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("invalid number in '{s}'"))?;

    if num < 0 {
        return Err(format!("negative duration in '{s}'"));
    }

    // `Duration::days` and friends are the PANICKING constructors, and
    // `DateTime - TimeDelta` panics on overflow too. The magnitude was never
    // bounded: the sign and the unit were checked, the number was not. So
    // `resources/read {"uri": "history://recent?since=100000000d"}` — a string
    // a client sends, and a model can produce by accident — aborted the
    // process, because the release profile sets `panic = "abort"`. The daemon
    // socket serves every client from one process, so one malformed URI from
    // one client took down the bridge for all of them.
    let duration = match unit {
        's' => Duration::try_seconds(num),
        'm' => Duration::try_minutes(num),
        'h' => Duration::try_hours(num),
        'd' => Duration::try_days(num),
        other => {
            return Err(format!(
                "unknown unit '{other}' in '{s}' (expected s/m/h/d)"
            ));
        }
    }
    .ok_or_else(|| format!("duration too large in '{s}'"))?;

    Utc::now()
        .checked_sub_signed(duration)
        .ok_or_else(|| format!("duration out of range in '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A magnitude nobody bounded reached chrono's panicking constructors.
    /// With `panic = "abort"` in the release profile and one process serving
    /// every daemon client, that is a remote kill from a query string.
    #[test]
    fn an_enormous_duration_is_an_error_not_a_panic() {
        for hostile in [
            "100000000d",    // overflows the subtraction
            "200000000000d", // overflows TimeDelta itself
            "9223372036854775807s",
            "9223372036854775807m",
            "9223372036854775807h",
        ] {
            parse_relative_duration(hostile)
                .expect_err("an unrepresentable duration must be refused, not abort the process");
        }
    }

    #[test]
    fn ordinary_durations_still_parse() {
        for ok in ["30s", "15m", "6h", "7d", "0s"] {
            parse_relative_duration(ok).unwrap_or_else(|e| panic!("{ok} must parse: {e}"));
        }
    }
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_scheme() {
        let handler = HistoryResourceHandler;
        assert_eq!(handler.scheme(), "history");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_single_resource() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "history://recent");
        assert_eq!(resources[0].mime_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn test_read_empty_history() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let contents = handler.read("history://recent", &ctx).await.unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].uri, "history://recent");

        // Empty history should produce valid JSON (empty array)
        let text = contents[0].text.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_read_with_history_entries() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        history.record_success("server1", "uptime", 0, 150);
        history.record_success("server2", "df -h", 0, 200);

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler.read("history://recent", &ctx).await.unwrap();
        let text = contents[0].text.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        let entries = parsed.as_array().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let result = handler.read("history://unknown", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("history://unknown"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== Query filtering tests ==============

    #[tokio::test]
    async fn test_read_with_host_filter() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        history.record_success("prod", "cmd1", 0, 10);
        history.record_success("staging", "cmd2", 0, 10);
        history.record_success("prod", "cmd3", 0, 10);

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler
            .read("history://recent?host=prod", &ctx)
            .await
            .unwrap();
        let text = contents[0].text.as_deref().unwrap();
        let entries: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e["host"] == "prod"));
    }

    #[tokio::test]
    async fn test_read_with_limit() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        for i in 0..20 {
            history.record_success("h", &format!("cmd{i}"), 0, 10);
        }

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler
            .read("history://recent?limit=5", &ctx)
            .await
            .unwrap();
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(contents[0].text.as_deref().unwrap()).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test]
    async fn test_read_with_since_filter_includes_recent() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        history.record_success("h", "cmd1", 0, 10);

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler
            .read("history://recent?since=1h", &ctx)
            .await
            .unwrap();
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(contents[0].text.as_deref().unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_read_with_host_since_and_limit_combined() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        for i in 0..10 {
            history.record_success("prod", &format!("p_cmd{i}"), 0, 10);
        }
        history.record_success("staging", "s_cmd1", 0, 10);

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler
            .read("history://recent?host=prod&since=24h&limit=3", &ctx)
            .await
            .unwrap();
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(contents[0].text.as_deref().unwrap()).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e["host"] == "prod"));
    }

    #[tokio::test]
    async fn test_read_invalid_since_unit_rejected() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();
        let result = handler.read("history://recent?since=5x", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => assert!(msg.contains("since")),
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_invalid_since_non_numeric_rejected() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();
        let result = handler.read("history://recent?since=abch", &ctx).await;
        assert!(result.is_err());
    }

    // ============== parse_relative_duration unit tests ==============

    #[test]
    fn test_parse_duration_seconds() {
        let result = parse_relative_duration("30s").unwrap();
        let diff = Utc::now() - result;
        assert!(diff.num_seconds() >= 30 && diff.num_seconds() < 32);
    }

    #[test]
    fn test_parse_duration_minutes() {
        let result = parse_relative_duration("5m").unwrap();
        let diff = Utc::now() - result;
        assert_eq!(diff.num_minutes(), 5);
    }

    #[test]
    fn test_parse_duration_hours() {
        let result = parse_relative_duration("2h").unwrap();
        let diff = Utc::now() - result;
        assert_eq!(diff.num_hours(), 2);
    }

    #[test]
    fn test_parse_duration_days() {
        let result = parse_relative_duration("7d").unwrap();
        let diff = Utc::now() - result;
        assert_eq!(diff.num_days(), 7);
    }

    #[test]
    fn test_parse_duration_empty_is_error() {
        assert!(parse_relative_duration("").is_err());
    }

    #[test]
    fn test_parse_duration_negative_is_error() {
        assert!(parse_relative_duration("-5m").is_err());
    }

    #[test]
    fn test_parse_duration_unknown_unit_is_error() {
        let err = parse_relative_duration("5x").unwrap_err();
        assert!(err.contains("unknown unit"));
    }

    #[test]
    fn test_parse_query_empty() {
        assert!(parse_query(None).is_empty());
        assert!(parse_query(Some("")).is_empty());
    }

    #[test]
    fn test_parse_query_single_param() {
        let map = parse_query(Some("host=prod"));
        assert_eq!(map.get("host").map(String::as_str), Some("prod"));
    }

    #[test]
    fn test_parse_query_multiple_params() {
        let map = parse_query(Some("host=prod&since=1h&limit=10"));
        assert_eq!(map.get("host").map(String::as_str), Some("prod"));
        assert_eq!(map.get("since").map(String::as_str), Some("1h"));
        assert_eq!(map.get("limit").map(String::as_str), Some("10"));
    }

    #[test]
    fn test_parse_query_value_without_equal_sign() {
        // A bare key with no value becomes (key, "")
        let map = parse_query(Some("flag"));
        assert_eq!(map.get("flag").map(String::as_str), Some(""));
    }
}
