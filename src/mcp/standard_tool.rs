//! Standard Tool Handler
//!
//! Generic handler that implements the common 16-step execution pipeline
//! shared by ~170 of the 337 tool handlers. Each standard tool only needs
//! to define its args struct, schema, and `build_command` function.

use std::marker::PhantomData;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::{info, warn};

use crate::config::{HostConfig, OsType};
use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Trait for accessing common fields present in all standard tool args.
pub trait CommonArgs {
    /// The SSH host alias.
    fn host(&self) -> &str;
    /// Optional timeout override in seconds.
    fn timeout_seconds(&self) -> Option<u64>;
    /// Optional max output characters override.
    fn max_output(&self) -> Option<u64>;
    /// Optional file path to save full output.
    fn save_output(&self) -> Option<&str>;
}

/// Implement [`CommonArgs`] for a struct that has the standard fields:
/// `host: String`, `timeout_seconds: Option<u64>`,
/// `max_output: Option<u64>`, `save_output: Option<String>`.
macro_rules! impl_common_args {
    ($type:ty) => {
        impl $crate::mcp::standard_tool::CommonArgs for $type {
            fn host(&self) -> &str {
                &self.host
            }
            fn timeout_seconds(&self) -> Option<u64> {
                self.timeout_seconds
            }
            fn max_output(&self) -> Option<u64> {
                self.max_output
            }
            fn save_output(&self) -> Option<&str> {
                self.save_output.as_deref()
            }
        }
    };
}
pub(crate) use impl_common_args;

/// Trait for tools that follow the standard execution pipeline.
///
/// The pipeline is: parse args → host lookup → OS guard → validate →
/// build command → `validate_builtin` → rate limit → execute with retry →
/// process success → truncate → save output → return.
pub trait StandardTool: Send + Sync + 'static {
    /// The deserialized arguments type.
    type Args: DeserializeOwned + Send + CommonArgs;

    /// Tool name (used for routing and logging).
    const NAME: &'static str;
    /// Tool description shown to MCP clients.
    const DESCRIPTION: &'static str;
    /// JSON schema string for the tool's input.
    const SCHEMA: &'static str;

    /// Optional OS restriction. `None` = no restriction.
    /// `Some(OsType::Linux)` = reject Windows hosts.
    /// `Some(OsType::Windows)` = reject non-Windows hosts.
    const OS_GUARD: Option<OsType> = None;

    /// Expected output format. Controls which data-reduction params are
    /// advertised in the schema and which reduction pipeline runs at runtime.
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::RawText;

    /// Optional JSON Schema (2020-12) string describing this tool's
    /// `structuredContent` return value. `None` (default) = no contract.
    ///
    /// When `Some`, [`StandardToolHandler::output_schema`] parses and
    /// advertises it in `tools/list` under `outputSchema`.
    const OUTPUT_SCHEMA: Option<&'static str> = None;

    /// Build the shell command from parsed arguments.
    ///
    /// This is the only method that MUST be implemented per tool.
    /// Return `Ok(command_string)` for the command to execute via SSH.
    fn build_command(args: &Self::Args, host_config: &HostConfig) -> Result<String>;

    /// Optional extra validation before command execution.
    ///
    /// Override this to add domain-specific input validation
    /// (e.g., `validate_service_name`, `validate_port`).
    /// Default: no-op (always succeeds).
    fn validate(_args: &Self::Args, _host_config: &HostConfig) -> Result<()> {
        Ok(())
    }

    /// Paths to validate against workspace root scope.
    ///
    /// Override for file-operation tools to enforce path scoping.
    /// Default: empty (no scoping).
    fn scoped_paths(_args: &Self::Args) -> Vec<&str> {
        Vec::new()
    }

    /// Optional post-processing to enrich the result with App content.
    ///
    /// Override this to add dashboard, table, or chart components
    /// to the tool result. The default is a no-op (returns result as-is).
    /// `output` is the raw (unsanitized) command output text.
    /// `dr` contains data-reduction params (e.g. `columns` for column filtering).
    fn post_process(
        result: ToolCallResult,
        _args: &Self::Args,
        _output: &str,
        _dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        result
    }

    /// Produce machine-readable `structuredContent` from the raw command
    /// output, INDEPENDENT of any MCP App component (GAP #2 decoupling).
    ///
    /// `output` is the raw (unsanitized) command stdout; `dr` carries the
    /// data-reduction params so the structured rows can be reduced to match
    /// the text view. Return `None` (default) to emit no structured content.
    ///
    /// The returned `Value` SHOULD conform to the tool's
    /// [`Self::OUTPUT_SCHEMA`] and MUST be a JSON object (MCP requires
    /// `structuredContent` to be an object, not a bare array).
    fn structured(
        _args: &Self::Args,
        _output: &str,
        _dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> Option<Value> {
        None
    }

    /// Async hook invoked AFTER args parsing/validation but BEFORE the
    /// command is built or executed. Receives the full [`ToolContext`]
    /// so handlers can call `ctx.elicit_confirm`, inspect `ctx.roots`,
    /// emit log notifications, etc.
    ///
    /// Returning `Ok(Some(result))` short-circuits the pipeline — the
    /// returned `ToolCallResult` is sent straight to the client without
    /// running `build_command` / `exec` / `post_process`. Use this when
    /// the user declines an elicitation prompt or when an early policy
    /// check needs to abort with a custom message.
    ///
    /// Returning `Ok(None)` continues the pipeline normally. The
    /// default implementation is a no-op for that reason.
    ///
    /// # Errors
    ///
    /// Propagate `BridgeError::*` for transport-level failures (the
    /// elicitation channel closed, the LLM call timed out). Do NOT use
    /// errors for "user declined" — return `Ok(Some(error_result))`
    /// so the response is structured.
    fn pre_execute(
        _args: &Self::Args,
        _ctx: &ToolContext,
    ) -> impl std::future::Future<Output = Result<Option<ToolCallResult>>> + Send {
        async { Ok(None) }
    }

    /// Async hook invoked AFTER `post_process` produced its result and
    /// BEFORE the response is shipped to the client. Receives the raw
    /// (pre-truncation) output and the full [`ToolContext`].
    ///
    /// Designed for tools that opt into LLM-side analysis via
    /// `ctx.sample(...)` (e.g. `ssh_diagnose summarize=true`). The
    /// handler should always return the raw data alongside any summary
    /// — never replace the source content with the LLM output, since
    /// downstream automation must be able to verify the bridge's own
    /// findings.
    ///
    /// Returning the input result unchanged is the safe default, hence
    /// the no-op default impl.
    ///
    /// # Errors
    ///
    /// Propagate `BridgeError::*` for transport-level failures.
    fn enrich(
        result: ToolCallResult,
        _args: &Self::Args,
        _output: &str,
        _ctx: &ToolContext,
    ) -> impl std::future::Future<Output = Result<ToolCallResult>> + Send {
        async move { Ok(result) }
    }
}

/// Generic handler that wraps a [`StandardTool`] and implements [`ToolHandler`].
///
/// The 16-step execution pipeline is implemented once here and reused
/// for every `StandardTool` implementation via monomorphization.
pub struct StandardToolHandler<T: StandardTool>(PhantomData<T>);

impl<T: StandardTool> Default for StandardToolHandler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: StandardTool> StandardToolHandler<T> {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

#[async_trait]
impl<T: StandardTool> ToolHandler for StandardToolHandler<T> {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn description(&self) -> &'static str {
        T::DESCRIPTION
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: T::NAME,
            description: T::DESCRIPTION,
            input_schema: T::SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        T::OUTPUT_KIND
    }

    fn output_schema(&self) -> Option<Value> {
        T::OUTPUT_SCHEMA.and_then(|s| serde_json::from_str(s).ok())
    }

    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        name = "mcp.tool.execute",
        skip(self, args, ctx),
        fields(
            tool = T::NAME,
            host = tracing::field::Empty,
            exit_code = tracing::field::Empty,
            bytes_out = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        )
    )]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        // RAII guard records `duration_ms` on the span regardless of exit path.
        let _timer = crate::telemetry::SpanDurationGuard::start();

        // Step 0: Extract universal data reduction params before tool-specific parsing
        let Some(mut v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);

        // Step 1: Parse args
        let args: T::Args =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Step 2: Host config lookup
        let host = args.host().to_string();
        tracing::Span::current().record("host", host.as_str());
        let host_config = ctx
            .config
            .hosts
            .get(&host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        // Step 3: OS guard
        if let Some(required_os) = T::OS_GUARD {
            match required_os {
                OsType::Windows => {
                    if host_config.os_type != OsType::Windows {
                        return Ok(ToolCallResult::error(format!(
                            "Tool '{}' is only available on Windows hosts. \
                             Use Linux-specific tools instead.",
                            T::NAME
                        )));
                    }
                }
                OsType::Linux => {
                    if host_config.os_type == OsType::Windows {
                        return Ok(ToolCallResult::error(format!(
                            "Tool '{}' is not available on Windows hosts. \
                             Use Windows-specific tools instead.",
                            T::NAME
                        )));
                    }
                }
            }
        }

        // Step 4: Domain validation (optional)
        T::validate(&args, host_config)?;

        // Step 4b: Root scope validation for file-operation tools
        for path in T::scoped_paths(&args) {
            ctx.validate_root_scope(path)?;
        }

        // Step 4c: Optional async pre-execute hook with `ToolContext`
        // access. Used by destructive tools to call `ctx.elicit_confirm`
        // and short-circuit the pipeline when the user declines.
        if let Some(early) = T::pre_execute(&args, ctx).await? {
            return Ok(early);
        }

        // Step 5: Build command
        let command = T::build_command(&args, host_config)?;

        // Step 6: Validate against security policy
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case.log_denied(&host, &command, &reason);
            return Err(e);
        }

        // Step 7: Rate limit
        if ctx.rate_limiter.check(&host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{host}'. Please wait before sending more requests.",
            )));
        }

        // Step 8: Log intent
        info!(host = %host, tool = T::NAME, "Executing tool");

        // Step 9: Timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds() {
            limits.command_timeout_seconds = timeout;
        }

        // Step 10: Retry config + jump host
        let retry_config = limits.retry_config();
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Step 10b: Force C locale for consistent columnar output parsing.
        // Only StandardToolHandler commands are prefixed — ssh_exec and
        // other custom handlers preserve the user's native locale.
        // Use `export ...; cmd` form so the locale applies to compound
        // commands (`if`, `for`, `{...}`); a bare `LC_ALL=C cmd` prefix
        // only works for simple commands and parses as a syntax error
        // when followed by a shell reserved word.
        let command = format!("export LC_ALL=C; {command}");

        // Step 11: Execute with retry and cancellation support.
        //
        // The `tokio::select!` is *inside* the retry closure so a pending
        // retry backoff (`sleep` inside `with_retry_if`) does NOT block the
        // cancel. On each retry, a fresh `select!` races the new exec
        // against `token.cancelled()`.
        //
        // The `biased` directive guarantees the cancel branch is polled
        // first, giving the cancellation maximum reactivity.
        //
        // `is_retryable_error` returns `false` for `BridgeError::Cancelled`
        // (see `src/ssh/retry.rs`), so once the cancel branch wins the
        // outer loop bails immediately without retrying.
        //
        // russh channels inside `conn.exec()` are dropped when the future
        // is cancelled. We poison the pooled connection with
        // `mark_failed()` to prevent reuse of a potentially half-closed
        // channel on the next request.
        let cancel_token = ctx.cancel_token.clone();
        let output = with_retry_if(
            &retry_config,
            T::NAME,
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&host, host_config, &limits, jump_host)
                    .await?;

                let result = if let Some(token) = &cancel_token {
                    tokio::select! {
                        biased;
                        () = token.cancelled() => {
                            Err(BridgeError::Cancelled)
                        }
                        r = conn.exec(&command, &limits) => r,
                    }
                } else {
                    conn.exec(&command, &limits).await
                };

                match result {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            is_retryable_error,
        )
        .await;

        // Step 12: Log failure
        let output = output.inspect_err(|e| {
            ctx.execute_use_case
                .log_failure(&host, &command, &e.to_string());
        })?;

        // Step 13: Process success (audit + history + sanitize)
        let mut response = ctx
            .execute_use_case
            .process_success(&host, &command, &output.into());
        let raw_chars = response.stdout.len();

        // Step 14: Warn on non-zero exit
        if response.exit_code != 0 {
            warn!(
                host = %host,
                tool = T::NAME,
                exit_code = response.exit_code,
                "Tool returned non-zero exit code"
            );
        }

        // Step 14: Typed data reduction pipeline (applied before truncation)
        // Save raw output for post_process (which needs the original for App content)
        let raw_output = response.stdout.clone();
        let mut jq_was_applied = false;
        if response.exit_code == 0 && !dr.is_empty() {
            jq_was_applied = apply_reduction(&mut response.stdout, &dr, T::OUTPUT_KIND)?;
        }

        let post_reduction_chars = response.stdout.len();

        // Step 15: Truncate stdout for display
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output()
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated_stdout =
            truncate_output_with_cache(&response.stdout, max_chars, ctx.output_cache.as_deref())
                .await;

        // Step 16: Save full output to file if requested
        let mut save_info: Option<String> = None;
        if let Some(save_path) = args.save_output() {
            match crate::mcp::tool_handlers::utils::save_output_to_file(save_path, &response.output)
                .await
            {
                Ok(msg) => save_info = Some(msg),
                Err(msg) => save_info = Some(format!("save_output error: {msg}")),
            }
        }

        // Step 17: Format for LLM (raw text on success, [exit:N] on error)
        let mut output_text = response.format_for_llm(&truncated_stdout);
        if let Some(info) = save_info {
            output_text = format!("{output_text}\n{info}");
        }

        // Record pipeline stats for token consumption analytics
        if let Some(ref metrics) = ctx.metrics {
            let truncated = truncated_stdout.len() < post_reduction_chars;
            metrics.record_pipeline_stats(
                raw_chars as u64,
                post_reduction_chars as u64,
                truncated,
                &format!("{:?}", T::OUTPUT_KIND),
            );
        }

        // Step 18: Post-process + structured content (GAP #2 decoupling).
        // Skip post_process when jq already filtered the output — post_process
        // would try to parse the raw output as columnar text, overwriting jq's work.
        let result = ToolCallResult::text(output_text);
        let mut result = if jq_was_applied {
            result
        } else {
            T::post_process(result, &args, &raw_output, &dr)
        };

        // Step 18a: Fill structured_content from structured() BEFORE enrich,
        // independent of App content (GAP #2 decoupling). Only on success.
        if result.structured_content.is_none()
            && response.exit_code == 0
            && let Some(data) = T::structured(&args, &raw_output, &dr)
        {
            result.structured_content = Some(data);
        }

        // Step 18b: Optional async enrichment hook with `ToolContext` access.
        // Used by diagnostic tools that opt into LLM-side analysis via
        // `ctx.sample()` (e.g. `ssh_diagnose summarize=true`).
        let mut result = T::enrich(result, &args, &raw_output, ctx).await?;

        // Record telemetry fields for this successful execution.
        let span = tracing::Span::current();
        span.record("exit_code", response.exit_code);
        #[allow(clippy::cast_possible_truncation)]
        span.record("bytes_out", post_reduction_chars as u64);

        // Step 18c: Fallback — populate structured_content from App data if
        // structured() returned None (backward-compat with App-based tools).
        if result.structured_content.is_none() {
            result = auto_populate_structured_content(result);
        }

        Ok(result)
    }
}

/// Apply typed data reduction based on [`crate::domain::output_kind::OutputKind`].
///
/// Returns `true` if a jq filter was applied (so `post_process` should be skipped).
///
/// Apply server-side data reduction to a tool's stdout based on its `OutputKind`.
///
/// This is the public entry point used both by `StandardToolHandler` (step 14
/// of the standard pipeline) and by custom (non-`StandardTool`) handlers that
/// want to opt into the same reduction semantics.
///
/// Strategy:
/// - `Json` → apply `jq_filter` if present, fall back to `limit` on top-level arrays
/// - `Tabular` → apply `columns`/`limit` filter (parse columnar → select → TSV)
/// - `Yaml` → apply `yq_filter` if present
/// - `Auto` → try JSON+jq first, fall back to tabular+columns+limit
/// - `RawText` → no-op
///
/// Returns `true` if `jq_filter` or `yq_filter` was applied (used by the
/// caller to skip post-processing steps that would duplicate filtering).
#[allow(clippy::unnecessary_wraps)]
pub fn apply_reduction(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
    kind: crate::domain::output_kind::OutputKind,
) -> Result<bool> {
    use crate::domain::output_kind::OutputKind;

    let mut jq_applied = false;

    match kind {
        OutputKind::Json => {
            jq_applied = try_apply_jq(stdout, dr)?;
            if !jq_applied {
                try_apply_json_limit(stdout, dr);
            }
        }
        OutputKind::Tabular => {
            try_apply_tabular_reduction(stdout, dr);
        }
        OutputKind::Yaml => {
            jq_applied = try_apply_yq(stdout, dr)?;
        }
        OutputKind::Auto => {
            // Try JSON + jq first (if jq_filter is present and output parses as JSON)
            jq_applied = try_apply_jq(stdout, dr)?;
            if !jq_applied {
                // Fall back to tabular + columns/limit
                try_apply_tabular_reduction(stdout, dr);
            }
        }
        OutputKind::RawText => {}
    }

    Ok(jq_applied)
}

/// Try to apply a `yq_filter` to stdout. Returns `true` if applied.
///
/// Parses the YAML stdout to a generic value tree, then runs the jaq engine
/// (with optional TSV serialization).
#[allow(clippy::unnecessary_wraps)]
fn try_apply_yq(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) -> Result<bool> {
    let _ = &(&stdout, &dr);

    #[cfg(feature = "jq")]
    if let Some(ref filter) = dr.yq_filter {
        let before = stdout.len();
        *stdout = if dr.wants_tsv() {
            crate::domain::yq_filter::apply_yq_filter_tsv(stdout, filter)?
        } else {
            crate::domain::yq_filter::apply_yq_filter(stdout, filter)?
        };
        tracing::debug!(
            before_chars = before,
            after_chars = stdout.len(),
            filter = filter.as_str(),
            tsv = dr.wants_tsv(),
            "yq_filter applied"
        );
        return Ok(true);
    }

    Ok(false)
}

/// Try to apply a `jq_filter` to stdout. Returns `true` if applied.
///
/// When `output_format="tsv"` is set, results are emitted as tab-separated
/// values instead of JSON for maximum token efficiency.
#[allow(clippy::unnecessary_wraps)]
fn try_apply_jq(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) -> Result<bool> {
    let _ = &(&stdout, &dr);

    #[cfg(feature = "jq")]
    if let Some(ref filter) = dr.jq_filter {
        let before = stdout.len();
        *stdout = if dr.wants_tsv() {
            crate::domain::jq_filter::apply_jq_filter_tsv(stdout, filter)?
        } else {
            crate::domain::jq_filter::apply_jq_filter(stdout, filter)?
        };
        tracing::debug!(
            before_chars = before,
            after_chars = stdout.len(),
            filter = filter.as_str(),
            tsv = dr.wants_tsv(),
            "jq_filter applied"
        );
        return Ok(true);
    }

    Ok(false)
}

/// Try to apply tabular reduction (`columns` + `limit`) to stdout.
fn try_apply_tabular_reduction(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) {
    if dr.columns.is_none() && dr.limit.is_none() {
        return;
    }
    if let Some(mut table) = crate::mcp::tool_handlers::utils::parse_columnar_output(stdout) {
        if let Some(ref cols) = dr.columns {
            table = table.select_columns(cols);
        }
        if let Some(limit) = dr.limit {
            table.limit_rows(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        *stdout = table.to_tsv();
    }
}

/// Try to apply `limit` to a JSON array output.
///
/// If `limit` is set and stdout parses as a JSON array, truncates to the
/// first N elements. Objects and non-JSON are left unchanged.
fn try_apply_json_limit(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) {
    let Some(limit) = dr.limit else { return };
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return;
    };
    if let serde_json::Value::Array(arr) = parsed
        && arr.len() > limit
    {
        let truncated = serde_json::Value::Array(arr.into_iter().take(limit).collect());
        if let Ok(s) = serde_json::to_string_pretty(&truncated) {
            *stdout = s;
        }
    }
}

/// Auto-populate `structuredContent` from `AppContent` data.
///
/// If the result contains an App component (table, dashboard, chart),
/// extract its data into `structured_content` for MCP clients that
/// support structured output (MCP 2025-06-18+).
fn auto_populate_structured_content(mut result: ToolCallResult) -> ToolCallResult {
    use crate::mcp::protocol::ToolContent;

    // Only populate if not already set
    if result.structured_content.is_some() {
        return result;
    }

    // Find the first App content and extract its data
    for content in &result.content {
        if let ToolContent::App { app } = content {
            result.structured_content = Some(app.data.clone());
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde::Deserialize;
    use serde_json::json;

    // ---- Mock tool for testing the generic pipeline ----

    #[derive(Debug, Deserialize)]
    struct MockArgs {
        host: String,
        timeout_seconds: Option<u64>,
        max_output: Option<u64>,
        save_output: Option<String>,
    }

    impl_common_args!(MockArgs);

    struct MockTool;

    impl StandardTool for MockTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_tool";
        const DESCRIPTION: &'static str = "A mock tool for testing";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": {
                "host": { "type": "string" }
            },
            "required": ["host"]
        }"#;

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("echo hello".to_string())
        }
    }

    // ---- Mock tool with OS guard for testing ----

    struct MockWindowsTool;

    impl StandardTool for MockWindowsTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_windows_tool";
        const DESCRIPTION: &'static str = "A mock Windows tool";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;
        const OS_GUARD: Option<OsType> = Some(OsType::Windows);

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("Get-Process".to_string())
        }
    }

    struct MockLinuxTool;

    impl StandardTool for MockLinuxTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_linux_tool";
        const DESCRIPTION: &'static str = "A mock Linux tool";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;
        const OS_GUARD: Option<OsType> = Some(OsType::Linux);

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("ps aux".to_string())
        }
    }

    // ---- Mock tool with validation ----

    struct MockValidatingTool;

    impl StandardTool for MockValidatingTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_validating_tool";
        const DESCRIPTION: &'static str = "A mock tool with validation";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("echo validated".to_string())
        }

        fn validate(_args: &MockArgs, _host_config: &HostConfig) -> Result<()> {
            Err(BridgeError::Config("validation failed".to_string()))
        }
    }

    // ---- Pipeline tests ----

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = StandardToolHandler::<MockTool>::new();
        assert_eq!(handler.name(), "mock_tool");
        assert_eq!(handler.description(), "A mock tool for testing");
        let schema = handler.schema();
        assert_eq!(schema.name, "mock_tool");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[tokio::test]
    async fn test_os_guard_windows_rejects_linux_host() {
        let handler = StandardToolHandler::<MockWindowsTool>::new();
        let ctx = create_test_context_with_host(); // server1 is Linux
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("only available on Windows"));
    }

    #[tokio::test]
    async fn test_validation_failure() {
        let handler = StandardToolHandler::<MockValidatingTool>::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = StandardToolHandler::<MockLinuxTool>::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token
        assert!(ctx.rate_limiter.check("server1").is_ok());

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("Rate limit exceeded"));
    }

    // ============== OS Guard tests ==============

    #[tokio::test]
    async fn test_os_guard_linux_rejects_windows_host() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        use std::collections::HashMap;

        let handler = StandardToolHandler::<MockLinuxTool>::new();
        let mut hosts = HashMap::new();
        hosts.insert(
            "winhost".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Windows,
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        let ctx = crate::ports::mock::create_test_context_with_hosts(hosts);
        // Wrap in `tokio::time::timeout` so a mutated guard that lets
        // the call slip past the OS check fails fast instead of hanging
        // on a real SSH dial to 10.0.0.1.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handler.execute(Some(json!({"host": "winhost"})), &ctx),
        )
        .await
        .expect("OS guard must reject without dialing the SSH host")
        .unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("not available on Windows"));
    }

    #[tokio::test]
    async fn test_os_guard_none_allows_any_os() {
        // MockTool has no OS guard — should pass host lookup for any OS
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context_with_host(); // server1 is Linux
        // This will fail at SSH connection (step 11) but pass OS guard (step 3)
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        // Should NOT be an OS guard error — it should be a connection error
        if let Ok(r) = &result {
            // If it somehow succeeds, it should not be an OS guard error
            if let Some(true) = r.is_error {
                let crate::ports::protocol::ToolContent::Text { text } = &r.content[0] else {
                    panic!("Expected text content")
                };
                assert!(!text.contains("not available on Windows"));
                assert!(!text.contains("only available on Windows"));
            }
        }
        // Err case: Connection error is expected — OS guard passed
    }

    #[tokio::test]
    async fn test_data_reduction_extraction() {
        // Verify data reduction params are stripped before arg parsing
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context_with_host();
        // Adding columns/limit should not cause parse errors
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "columns": ["NAME"],
                    "limit": 5
                })),
                &ctx,
            )
            .await;
        // Should fail at SSH connection, not at arg parsing
        assert!(result.is_err());
        if let BridgeError::McpInvalidRequest(_) = result.unwrap_err() {
            panic!("columns/limit should have been stripped before parsing");
        }
        // Other errors (connection error or similar) are expected
    }

    // ============== apply_reduction tests ==============

    #[test]
    fn test_apply_reduction_raw_text_noop() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout = "hello world".to_string();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::RawText).unwrap();
        assert!(!jq);
        assert_eq!(stdout, "hello world");
    }

    #[test]
    fn test_apply_reduction_tabular_with_columns() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout = "NAME           STATUS    CPU\nnginx          running   5%\npostgres       running   12%\n".to_string();
        let mut v = json!({"columns": ["NAME", "STATUS"]});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Tabular).unwrap();
        assert!(!jq);
        // After tabular reduction, only NAME and STATUS columns should remain
        assert!(stdout.contains("NAME"));
        assert!(stdout.contains("STATUS"));
    }

    #[test]
    fn test_apply_reduction_tabular_with_limit() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout =
            "NAME           STATUS\nrow1           ok\nrow2           ok\nrow3           ok\n"
                .to_string();
        let mut v = json!({"limit": 1});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Tabular).unwrap();
        assert!(!jq);
        // Should keep header + 1 row
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2); // header + 1 data row
    }

    #[test]
    fn test_apply_reduction_tabular_no_params_noop() {
        use crate::domain::output_kind::OutputKind;
        let original = "NAME  STATUS\nfoo   bar\n".to_string();
        let mut stdout = original.clone();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Tabular).unwrap();
        assert!(!jq);
        assert_eq!(stdout, original);
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_apply_reduction_json_with_jq() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout = r#"{"name": "test", "value": 42}"#.to_string();
        let mut v = json!({"jq_filter": ".name"});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Json).unwrap();
        assert!(jq);
        assert!(stdout.contains("test"));
    }

    #[test]
    fn test_apply_reduction_json_without_jq_noop() {
        use crate::domain::output_kind::OutputKind;
        let original = r#"{"name": "test"}"#.to_string();
        let mut stdout = original.clone();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Json).unwrap();
        assert!(!jq);
        assert_eq!(stdout, original);
    }

    #[test]
    fn test_apply_reduction_auto_falls_back_to_tabular() {
        use crate::domain::output_kind::OutputKind;
        // Non-JSON output with columns param → should fall back to tabular reduction
        let mut stdout = "NAME           STATUS\nnginx          running\n".to_string();
        let mut v = json!({"columns": ["NAME"]});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Auto).unwrap();
        assert!(!jq); // jq not applied (not JSON)
        assert!(stdout.contains("NAME"));
    }

    // ============== try_apply_tabular_reduction tests ==============

    #[test]
    fn test_tabular_reduction_unparsable_noop() {
        // Non-columnar output should be left unchanged
        let mut stdout = "this is just a random string without columns".to_string();
        let mut v = json!({"columns": ["NAME"]});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_tabular_reduction(&mut stdout, &dr);
        assert_eq!(stdout, "this is just a random string without columns");
    }

    #[test]
    fn test_tabular_reduction_empty_dr_noop() {
        let mut stdout = "NAME  STATUS\nfoo   bar\n".to_string();
        let original = stdout.clone();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        try_apply_tabular_reduction(&mut stdout, &dr);
        assert_eq!(stdout, original);
    }

    // ============== try_apply_json_limit tests ==============

    #[test]
    fn test_json_limit_truncates_array() {
        let mut stdout = r#"[{"a":1},{"a":2},{"a":3},{"a":4},{"a":5}]"#.to_string();
        let mut v = json!({"limit": 2});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_json_limit(&mut stdout, &dr);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_json_limit_no_op_on_object() {
        let original = r#"{"name": "test"}"#.to_string();
        let mut stdout = original.clone();
        let mut v = json!({"limit": 1});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_json_limit(&mut stdout, &dr);
        assert_eq!(stdout, original);
    }

    #[test]
    fn test_json_limit_no_op_when_under_limit() {
        let original = r#"[{"a":1},{"a":2}]"#.to_string();
        let mut stdout = original.clone();
        let mut v = json!({"limit": 10});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_json_limit(&mut stdout, &dr);
        assert_eq!(stdout, original);
    }

    #[test]
    fn test_json_limit_no_op_on_non_json() {
        let original = "not json at all".to_string();
        let mut stdout = original.clone();
        let mut v = json!({"limit": 1});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_json_limit(&mut stdout, &dr);
        assert_eq!(stdout, original);
    }

    #[test]
    fn test_json_limit_no_op_without_limit() {
        let original = r#"[{"a":1},{"a":2},{"a":3}]"#.to_string();
        let mut stdout = original.clone();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        try_apply_json_limit(&mut stdout, &dr);
        assert_eq!(stdout, original);
    }

    #[test]
    fn test_apply_reduction_json_with_limit() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout = r#"[{"a":1},{"a":2},{"a":3}]"#.to_string();
        let mut v = json!({"limit": 1});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Json).unwrap();
        assert!(!jq);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    // ============== auto_populate_structured_content tests ==============

    #[test]
    fn test_auto_populate_no_app_noop() {
        let result = ToolCallResult::text("just text");
        let result = auto_populate_structured_content(result);
        assert!(result.structured_content.is_none());
    }

    #[test]
    fn test_auto_populate_already_set_noop() {
        let mut result = ToolCallResult::text("text");
        result.structured_content = Some(json!({"existing": true}));
        let result = auto_populate_structured_content(result);
        assert_eq!(result.structured_content, Some(json!({"existing": true})));
    }

    #[test]
    fn test_auto_populate_from_app_content() {
        use crate::ports::protocol::AppContent;

        let app = AppContent {
            app_type: "table".to_string(),
            title: Some("Test".to_string()),
            data: json!({"rows": [{"name": "foo"}]}),
            actions: None,
        };
        let result = ToolCallResult::text("text").with_app(app);
        assert!(result.structured_content.is_none());
        let result = auto_populate_structured_content(result);
        assert!(result.structured_content.is_some());
        assert_eq!(
            result.structured_content.unwrap(),
            json!({"rows": [{"name": "foo"}]})
        );
    }

    // ============== try_apply_jq tests ==============

    #[test]
    fn test_try_apply_jq_no_filter_noop() {
        let mut stdout = r#"{"key": "value"}"#.to_string();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let applied = try_apply_jq(&mut stdout, &dr).unwrap();
        assert!(!applied);
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_try_apply_jq_with_filter() {
        let mut stdout = r#"{"name": "test", "value": 42}"#.to_string();
        let mut v = json!({"jq_filter": ".name"});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let applied = try_apply_jq(&mut stdout, &dr).unwrap();
        assert!(applied);
        assert!(stdout.contains("test"));
    }

    // ============== Full pipeline tests (steps 7-18 via mock executor) ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn mock_output_with_exit(stdout: &str, exit_code: u32) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: crate::config::HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: crate::config::OsType::default(),
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("hello world"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("hello world"));
    }

    /// Verifies that `StandardToolHandler::execute` emits a span named
    /// `mcp.tool.execute` with the expected structured fields (`tool`,
    /// `host`, `exit_code`, `bytes_out`, `duration_ms`). This is the
    /// integration contract consumed by the `otel` feature — if it breaks,
    /// Grafana/Jaeger dashboards built on these fields stop working.
    ///
    /// Uses `flavor = "current_thread"` so the tracing subscriber installed
    /// via `set_default` stays thread-local for the whole future.
    #[tokio::test(flavor = "current_thread")]
    async fn test_execute_emits_mcp_tool_execute_span_with_fields() {
        use std::sync::{Arc, Mutex};
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::fmt::format::FmtSpan;

        // Shared buffer writer so we can inspect what the subscriber emitted.
        #[derive(Clone)]
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut inner) = self.0.lock() {
                    inner.extend_from_slice(buf);
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for SharedWriter {
            type Writer = SharedWriter;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(buf.clone());

        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_max_level(tracing::Level::INFO)
            .finish();

        // Use `WithSubscriber` to attach the subscriber to the future rather
        // than the thread. This is robust against parallel tests installing
        // competing subscribers on other threads — `set_default` is
        // thread-local and leaks across task migrations in multi-threaded
        // runtimes, causing flaky parallel runs.
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("span test"),
        );

        async {
            handler
                .execute(Some(json!({"host": "server1"})), &ctx)
                .await
                .expect("handler execute should succeed");
        }
        .with_subscriber(subscriber)
        .await;

        let captured = String::from_utf8(
            buf.lock()
                .expect("buffer mutex should not be poisoned")
                .clone(),
        )
        .expect("captured output must be valid UTF-8");

        // The span name must appear — proves the instrument attribute is wired.
        assert!(
            captured.contains("mcp.tool.execute"),
            "expected 'mcp.tool.execute' span, got: {captured}"
        );
        // Tool name is set at span creation.
        assert!(
            captured.contains("tool=\"mock_tool\"") || captured.contains("tool=mock_tool"),
            "expected tool field = mock_tool, got: {captured}"
        );
        // Host is recorded after Step 2.
        assert!(
            captured.contains("host=\"server1\"") || captured.contains("host=server1"),
            "expected host field = server1, got: {captured}"
        );
        // Drop guard recorded duration on CLOSE.
        assert!(
            captured.contains("duration_ms="),
            "expected duration_ms field to be populated, got: {captured}"
        );
        // exit_code recorded on the success path.
        assert!(
            captured.contains("exit_code=0") || captured.contains("exit_code=\"0\""),
            "expected exit_code=0, got: {captured}"
        );
    }

    // ============== Cancellation (commit 6) ==============

    /// End-to-end proof that a `CancellationToken` propagated via
    /// `ToolContext.cancel_token` races ahead of a blocking `conn.exec()`
    /// inside the `with_retry_if` closure, yielding `BridgeError::Cancelled`.
    ///
    /// The mock executor sleeps 2s; we fire the cancel after 50ms and
    /// assert the handler returns in well under 2s.
    #[tokio::test(flavor = "current_thread")]
    async fn test_cancel_token_interrupts_in_flight_exec() {
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let handler = StandardToolHandler::<MockTool>::new();
        let mut ctx = crate::ports::mock::create_test_context_with_blocking_mock_executor(
            server1_hosts(),
            mock_output("should never arrive"),
            Duration::from_secs(2), // mock sleeps 2 seconds
        );

        let token = CancellationToken::new();
        ctx.cancel_token = Some(token.clone());

        // Spawn the handler and the canceller concurrently.
        let cancel_task = tokio::spawn({
            let token = token.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                token.cancel();
            }
        });

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;

        cancel_task.await.expect("canceller task panicked");

        // The handler must return Err(BridgeError::Cancelled), NOT the
        // mock output.
        match result {
            Err(BridgeError::Cancelled) => {}
            Err(other) => panic!("expected Cancelled, got: {other:?}"),
            Ok(ok) => panic!("expected Cancelled error, got success: {ok:?}"),
        }
    }

    /// When no cancel token is present (legacy path), the handler must
    /// still run the blocking mock to completion.
    #[tokio::test(flavor = "current_thread")]
    async fn test_no_cancel_token_runs_to_completion() {
        use std::time::Duration;

        let handler = StandardToolHandler::<MockTool>::new();
        // ctx.cancel_token stays None.
        let ctx = crate::ports::mock::create_test_context_with_blocking_mock_executor(
            server1_hosts(),
            mock_output("finished"),
            Duration::from_millis(100),
        );

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .expect("execute should succeed without cancel token");

        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("expected text content");
        };
        assert!(text.contains("finished"), "output: {text}");
    }

    /// When the cancel token is present but never fires, the handler must
    /// still return the mock output normally.
    #[tokio::test(flavor = "current_thread")]
    async fn test_cancel_token_never_fired_completes_normally() {
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let handler = StandardToolHandler::<MockTool>::new();
        let mut ctx = crate::ports::mock::create_test_context_with_blocking_mock_executor(
            server1_hosts(),
            mock_output("ok"),
            Duration::from_millis(50),
        );
        ctx.cancel_token = Some(CancellationToken::new());

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .expect("execute should succeed when cancel never fires");

        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("expected text content");
        };
        assert!(text.contains("ok"), "output: {text}");
    }

    #[tokio::test]
    async fn test_full_pipeline_nonzero_exit() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output_with_exit("error output", 1),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        // Non-zero exit should include exit code in output
        assert!(text.contains("exit") || text.contains("error output"));
    }

    #[tokio::test]
    async fn test_full_pipeline_with_timeout_override() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("timeout test"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "timeout_seconds": 5})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("timeout test"));
    }

    #[tokio::test]
    async fn test_full_pipeline_with_max_output_truncation() {
        let handler = StandardToolHandler::<MockTool>::new();
        let long_output = "x".repeat(10_000);
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(&long_output),
        );
        // Set max_output to 100 chars
        let result = handler
            .execute(Some(json!({"host": "server1", "max_output": 100})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        // Output should be truncated (less than 10000 chars)
        assert!(text.len() < 500);
    }

    #[tokio::test]
    async fn test_full_pipeline_with_save_output() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("saved output"),
        );
        let dir = tempfile::tempdir().unwrap();
        let save_path = dir.path().join("test_output.txt");
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "save_output": save_path.to_str().unwrap()
                })),
                &ctx,
            )
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        // Should mention save success
        assert!(text.contains("saved") || text.contains("Saved") || text.contains("output"));
        // File should exist
        assert!(save_path.exists());
    }

    #[tokio::test]
    async fn test_full_pipeline_with_data_reduction_columns() {
        // Use a tool with Tabular output kind
        struct MockTabularTool;
        impl StandardTool for MockTabularTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_tabular_tool";
            const DESCRIPTION: &'static str = "Mock tabular tool";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
                crate::domain::output_kind::OutputKind::Tabular;

            fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
                Ok("echo tabular".to_string())
            }
        }

        let handler = StandardToolHandler::<MockTabularTool>::new();
        let tabular = "NAME           STATUS    CPU\nnginx          running   5%\npostgres       running   12%\n";
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(tabular),
        );
        let result = handler
            .execute(
                Some(json!({"host": "server1", "columns": ["NAME", "STATUS"]})),
                &ctx,
            )
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("NAME"));
        assert!(text.contains("STATUS"));
    }

    #[cfg(feature = "jq")]
    #[tokio::test]
    async fn test_full_pipeline_with_jq_filter() {
        struct MockJsonTool;
        impl StandardTool for MockJsonTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_json_tool";
            const DESCRIPTION: &'static str = "Mock JSON tool";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
                crate::domain::output_kind::OutputKind::Json;

            fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
                Ok("echo json".to_string())
            }
        }

        let handler = StandardToolHandler::<MockJsonTool>::new();
        let json_output = r#"{"name": "test", "value": 42, "extra": "data"}"#;
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(json_output),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "jq_filter": ".name"})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("test"));
        // jq filter should reduce the output
        assert!(!text.contains("extra"));
    }

    #[tokio::test]
    async fn test_full_pipeline_with_post_process() {
        // Mock tool with post_process that adds App content
        struct MockPostProcessTool;
        impl StandardTool for MockPostProcessTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_pp_tool";
            const DESCRIPTION: &'static str = "Mock with post_process";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;

            fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
                Ok("echo pp".to_string())
            }

            fn post_process(
                result: ToolCallResult,
                _args: &MockArgs,
                _output: &str,
                _dr: &crate::domain::data_reduction::DataReductionArgs,
            ) -> ToolCallResult {
                use crate::ports::protocol::AppContent;
                let app = AppContent {
                    app_type: "table".to_string(),
                    title: Some("Test Table".to_string()),
                    data: json!({"rows": [{"col1": "val1"}]}),
                    actions: None,
                };
                result.with_app(app)
            }
        }

        let handler = StandardToolHandler::<MockPostProcessTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("post process output"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        // Should have text + app content
        assert!(result.content.len() >= 2);
        // structured_content should be auto-populated from App
        assert!(result.structured_content.is_some());
    }

    #[tokio::test]
    async fn test_full_pipeline_security_denied() {
        // MockTool builds "echo hello" which is safe. Test with a validating tool
        // that always validates but uses a command the security policy rejects.
        struct MockDangerousTool;
        impl StandardTool for MockDangerousTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_dangerous";
            const DESCRIPTION: &'static str = "Mock dangerous tool";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;

            fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
                // This command should be blocked by the validator
                Ok("rm -rf /".to_string())
            }
        }

        let _handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("should not reach"),
        );
        let handler_dangerous = StandardToolHandler::<MockDangerousTool>::new();
        let result = handler_dangerous
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        // Should be denied by security validation
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_full_pipeline_empty_output() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(""),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    #[tokio::test]
    async fn test_full_pipeline_with_limit_data_reduction() {
        struct MockTabularTool2;
        impl StandardTool for MockTabularTool2 {
            type Args = MockArgs;
            const NAME: &'static str = "mock_tab2";
            const DESCRIPTION: &'static str = "Mock tabular 2";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
                crate::domain::output_kind::OutputKind::Tabular;
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo tab".to_string())
            }
        }

        let handler = StandardToolHandler::<MockTabularTool2>::new();
        let tabular =
            "NAME           STATUS\nrow1           ok\nrow2           ok\nrow3           ok\n";
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(tabular),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "limit": 1})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        // With limit=1, should have header + 1 row max
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines.len() <= 3); // header + 1 data row + possible exit info
    }

    // ============== Targeted mutation-killing tests ==============

    /// `try_apply_json_limit` must NOT truncate when the array length
    /// exactly equals the limit — only strict-greater triggers the cut.
    /// Kills `> -> >=` and `> -> ==` / `> -> <` mutations on line 638.
    #[test]
    fn test_json_limit_no_op_at_exact_length() {
        let original = r#"[{"a":1},{"a":2},{"a":3}]"#.to_string();
        let mut stdout = original.clone();
        let mut v = json!({"limit": 3});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        try_apply_json_limit(&mut stdout, &dr);
        assert_eq!(stdout, original, "exact-length array must not be truncated");
    }

    /// `try_apply_yq` must report "not applied" when no `yq_filter` is
    /// set, regardless of whether the `jq` feature is compiled in.
    /// Kills `Ok(true)` and `Ok(false)` mutations on line 550 (the
    /// `Ok(false)` mutation is equivalent on a feature-off build but
    /// caught when the function is exercised under the `jq` feature).
    #[test]
    fn test_try_apply_yq_no_filter_returns_false() {
        let mut stdout = "key: value\n".to_string();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let applied = try_apply_yq(&mut stdout, &dr).unwrap();
        assert!(
            !applied,
            "yq must not flag itself as applied without a yq_filter"
        );
        assert_eq!(stdout, "key: value\n", "stdout must be untouched");
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_try_apply_yq_with_filter_returns_true() {
        let mut stdout = "name: test\nvalue: 42\n".to_string();
        let mut v = json!({"yq_filter": ".name"});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let applied = try_apply_yq(&mut stdout, &dr).unwrap();
        assert!(applied, "yq must report applied when yq_filter is set");
        assert!(stdout.contains("test"));
    }

    /// `<impl ToolHandler for StandardToolHandler<T>>::output_kind` must
    /// dispatch to `T::OUTPUT_KIND`, not the trait default.
    /// Kills the `Default::default()` mutation on line 213.
    #[test]
    fn test_handler_output_kind_dispatches_to_associated_const() {
        use crate::domain::output_kind::OutputKind;
        use crate::ports::ToolHandler;

        struct MockJsonHandler;
        impl StandardTool for MockJsonHandler {
            type Args = MockArgs;
            const NAME: &'static str = "mock_kind_json";
            const DESCRIPTION: &'static str = "kind probe";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: OutputKind = OutputKind::Json;
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo".to_string())
            }
        }

        let handler = StandardToolHandler::<MockJsonHandler>::new();
        assert_eq!(
            handler.output_kind(),
            OutputKind::Json,
            "must dispatch to T::OUTPUT_KIND, not Default::default() (=RawText)"
        );
    }

    #[test]
    fn test_standard_handler_output_schema_default_none() {
        use crate::ports::ToolHandler;
        let handler = StandardToolHandler::<MockTool>::new();
        assert!(handler.output_schema().is_none());
    }

    #[test]
    fn test_standard_handler_output_schema_parses_const() {
        use crate::ports::ToolHandler;
        struct MockSchemaTool;
        impl StandardTool for MockSchemaTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_schema_tool";
            const DESCRIPTION: &'static str = "schema probe";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_SCHEMA: Option<&'static str> = Some(
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            );
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo".to_string())
            }
        }
        let handler = StandardToolHandler::<MockSchemaTool>::new();
        let schema = handler
            .output_schema()
            .expect("OUTPUT_SCHEMA Some must surface");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["type"], "object");
    }

    #[tokio::test]
    async fn test_standard_handler_populates_structured_without_app() {
        struct MockStructuredTool;
        impl StandardTool for MockStructuredTool {
            type Args = MockArgs;
            const NAME: &'static str = "mock_structured_tool";
            const DESCRIPTION: &'static str = "structured probe";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo".to_string())
            }
            fn structured(
                _args: &MockArgs,
                _output: &str,
                _dr: &crate::domain::data_reduction::DataReductionArgs,
            ) -> Option<Value> {
                Some(json!({"items": [{"name": "nginx"}]}))
            }
        }
        let handler = StandardToolHandler::<MockStructuredTool>::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("raw text output"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(
            !result
                .content
                .iter()
                .any(|c| matches!(c, crate::ports::protocol::ToolContent::App { .. })),
            "this tool emits no App content"
        );
        assert_eq!(
            result.structured_content,
            Some(json!({"items": [{"name": "nginx"}]})),
            "structured() output must populate structured_content independent of Apps"
        );
    }

    /// `apply_reduction` for `OutputKind::Auto` with no `jq_filter` must
    /// fall through to tabular reduction. Kills `delete !` on line 530.
    #[test]
    fn test_apply_reduction_auto_falls_through_to_tabular_when_no_jq() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout =
            "NAME           STATUS\nrow1           ok\nrow2           ok\n".to_string();
        let mut v = json!({"columns": ["NAME"]});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Auto).unwrap();
        assert!(!jq, "no jq_filter, jq must not be reported applied");
        assert!(
            !stdout.contains("STATUS"),
            "Auto branch must fall through to tabular column selection"
        );
        assert!(stdout.contains("NAME"));
    }

    /// Default trait `scoped_paths` must return an empty vec — handlers
    /// that opt out of root-scoping must NOT trigger validation. Kills
    /// `vec![""]` and `vec!["xyzzy"]` mutations on line 102 (the
    /// `vec![]` mutation is equivalent and excluded).
    #[tokio::test]
    async fn test_default_scoped_paths_does_not_validate_against_roots() {
        // MockTool does NOT override scoped_paths — uses trait default.
        // Even with non-empty roots, execute must succeed because the
        // default scoped_paths is empty.
        let handler = StandardToolHandler::<MockTool>::new();
        let mut ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("hello"),
        );
        ctx.roots = vec![crate::mcp::protocol::RootEntry {
            uri: "file:///nowhere/nothing".to_string(),
            name: None,
        }];
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(
            result.is_ok(),
            "tool that does not override scoped_paths must not be \
             scoped to client roots — got {result:?}"
        );
    }

    /// `apply_reduction` for `OutputKind::Json` must apply the
    /// `try_apply_json_limit` fallback **only** when jq did not run.
    /// With both `jq_filter` and `limit` present, jq wins and limit
    /// is skipped. Kills `delete !` in the
    /// `if !jq_applied { try_apply_json_limit(...) }` line of
    /// `apply_reduction` (Json branch, around line 517).
    #[cfg(feature = "jq")]
    #[test]
    fn test_apply_reduction_json_jq_wins_over_limit() {
        use crate::domain::output_kind::OutputKind;
        let mut stdout = r#"[{"a":1},{"a":2},{"a":3},{"a":4},{"a":5}]"#.to_string();
        let mut v = json!({"jq_filter": ".[0:1]", "limit": 2});
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);
        let jq = apply_reduction(&mut stdout, &dr, OutputKind::Json).unwrap();
        assert!(jq, "jq must be applied for Json kind with jq_filter");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            parsed.len(),
            1,
            "jq's `.[0:1]` slice (1 element) must win over limit=2"
        );
    }

    /// The reduction step in the pipeline runs only when both
    /// `exit_code == 0` AND `!dr.is_empty()`. A mutation that flips
    /// the `&&` to `||` (line 417) makes reduction run on failed
    /// commands too. Tabular reduction is feature-independent, so
    /// this test holds in every default build.
    #[tokio::test]
    async fn test_tabular_reduction_skipped_on_non_zero_exit() {
        struct MockTabExit;
        impl StandardTool for MockTabExit {
            type Args = MockArgs;
            const NAME: &'static str = "mock_tab_exit";
            const DESCRIPTION: &'static str = "Mock tabular tool with non-zero exit";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
                crate::domain::output_kind::OutputKind::Tabular;
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo".to_string())
            }
        }

        let handler = StandardToolHandler::<MockTabExit>::new();
        let table = "NAME           STATUS\nrow1           ok\nrow2           ok\n";
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output_with_exit(table, 1),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "columns": ["NAME"]})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(
            text.contains("STATUS"),
            "non-zero exit must preserve raw output even with `columns` — got {text:?}"
        );
    }

    /// `truncated = truncated_stdout.len() < post_reduction_chars` is
    /// the boolean fed into `metrics.record_pipeline_stats`. Mutations
    /// `< -> ==`, `< -> >`, `< -> <=` survive coverage-only tests but
    /// each produces an observably wrong `truncation_events` counter.
    /// Two paths together kill all three:
    /// * Output bigger than `max_output` (with enough margin so the
    ///   truncation marker doesn't itself overshoot the original) →
    ///   original increments by 1. `==` and `>` would skip; `<=`
    ///   would still increment.
    /// * Output exactly fits → original increments by 0. `<=` would
    ///   increment; `==` would also increment.
    #[tokio::test]
    async fn test_truncation_event_counter_strict_less_than() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        // ---- Path 1: forced truncation. Use a large input so the
        // output is genuinely shorter than the source even after the
        // verbose truncation marker is injected (`head + marker + tail`
        // marker is ~150 chars, so we need a much larger original).
        let big = "a".repeat(5_000);
        let metrics_a = Arc::new(crate::metrics::Metrics::new());
        let mut ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(&big),
        );
        ctx.metrics = Some(metrics_a.clone());
        let handler = StandardToolHandler::<MockTool>::new();
        handler
            .execute(Some(json!({"host": "server1", "max_output": 200})), &ctx)
            .await
            .unwrap();
        assert_eq!(
            metrics_a.truncation_events.load(Ordering::Relaxed),
            1,
            "forced truncation must record exactly one event"
        );

        // ---- Path 2: output exactly fits ----
        let metrics_b = Arc::new(crate::metrics::Metrics::new());
        let mut ctx2 = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("ok"),
        );
        ctx2.metrics = Some(metrics_b.clone());
        handler
            .execute(Some(json!({"host": "server1", "max_output": 1024})), &ctx2)
            .await
            .unwrap();
        assert_eq!(
            metrics_b.truncation_events.load(Ordering::Relaxed),
            0,
            "output that fits must NOT record a truncation event"
        );
    }

    /// jq variant of the same exit-code-gates-reduction invariant —
    /// runs only when the `jq` feature is on.
    #[cfg(feature = "jq")]
    #[tokio::test]
    async fn test_jq_skipped_on_non_zero_exit() {
        struct MockJsonExit;
        impl StandardTool for MockJsonExit {
            type Args = MockArgs;
            const NAME: &'static str = "mock_json_exit";
            const DESCRIPTION: &'static str = "Mock JSON tool with non-zero exit";
            const SCHEMA: &'static str =
                r#"{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}"#;
            const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
                crate::domain::output_kind::OutputKind::Json;
            fn build_command(_a: &MockArgs, _h: &HostConfig) -> Result<String> {
                Ok("echo".to_string())
            }
        }

        let handler = StandardToolHandler::<MockJsonExit>::new();
        let json_output = r#"{"name": "test", "extra": "preserved"}"#;
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output_with_exit(json_output, 1),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "jq_filter": ".name"})), &ctx)
            .await
            .unwrap();
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(
            text.contains("preserved"),
            "non-zero exit must preserve raw output even with jq_filter — got {text:?}"
        );
    }
}
