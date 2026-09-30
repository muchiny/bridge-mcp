//! SSH AWX Job Follow Tool Handler
//!
//! Launches an AWX job and polls until completion, returning a structured
//! summary. Combines `job_launch` + polling `job_status` + `job_host_summaries`
//! into a single atomic operation.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_job_follow` tool.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshAwxJobFollowArgs {
    template_id: u64,
    #[serde(default)]
    extra_vars: Option<Value>,
    #[serde(default)]
    limit: Option<String>,
    /// Poll interval in seconds (default: 5, min: 2, max: 30).
    #[serde(default = "default_poll_interval")]
    poll_interval: u32,
    /// Maximum wait time in seconds (default: 600 = 10 min).
    #[serde(default = "default_max_wait")]
    max_wait: u64,
}

fn default_poll_interval() -> u32 {
    5
}

fn default_max_wait() -> u64 {
    600
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "template_id": {
            "type": "integer",
            "description": "AWX job template ID to launch",
            "minimum": 1
        },
        "extra_vars": {
            "type": "object",
            "description": "Extra variables to pass to the job template"
        },
        "limit": {
            "type": "string",
            "description": "AWX host-filter pattern passed to the job template (e.g. 'webservers' or 'host1,host2'). This is NOT a row/pagination limit — it restricts which inventory hosts participate in the run."
        },
        "poll_interval": {
            "type": "integer",
            "description": "Seconds between status polls (default: 5, min: 2, max: 30)",
            "minimum": 2,
            "maximum": 30
        },
        "max_wait": {
            "type": "integer",
            "description": "Maximum seconds to wait for job completion (default: 600 = 10 min)",
            "minimum": 10,
            "maximum": 3600
        }
    },
    "required": ["template_id"]
}"#;

/// The marker `AwxCommandBuilder::build_api_call_checked` asks `curl` to print
/// in front of the HTTP status.
///
/// Duplicated from the builder, whose own constant is private and stays that
/// way. The duplication is bound by
/// `the_script_splits_the_marker_the_builder_actually_writes`, which asserts
/// the built command carries this exact text: a rename in the builder then
/// fails a test here instead of silently turning every status check into a
/// refusal (an unsplit body never matches `[23][0-9][0-9]`).
const STATUS_MARKER: &str = "HTTP_STATUS:";

/// Build the launch → poll → summarise script this tool relays over SSH.
///
/// Split out of `execute` because the interesting part of this tool is shell,
/// not Rust: three HTTP status checks, four exit codes, and a `set -e` that
/// decides whether an arm ever reaches its `echo`. Only a real shell can
/// answer that, so the tests run this text under `bash`.
///
/// # Why `AwxCommandBuilder::parse_checked_response` is not called here
///
/// Every other AWX handler hands curl's stdout straight back and lets
/// `parse_checked_response` classify it. This one cannot: its three curl calls
/// are consumed *inside* the script — the launch body feeds the job-id
/// extraction, the poll body feeds the status extraction, the summary body is
/// interpolated into the document the tool emits — and the handler only ever
/// sees the script's final stdout. `parse_checked_response` classifies the
/// *last* marker in whatever it is given, so applied to that final stdout it
/// would classify whatever leaked through rather than an HTTP response. The
/// three statuses are therefore checked here, per call, and nothing is left
/// for the handler to classify.
///
/// # Reading the shell
///
/// Each call is captured raw and then split with two parameter expansions,
/// because `build_api_call_checked` makes curl append `\n<marker><code>` to
/// the body:
/// * `${RAW##*<marker>}` — longest prefix up to and including the last
///   marker removed, leaving the code;
/// * `${RAW%?<marker>*}` — shortest suffix from one character before that
///   same marker removed, the `?` swallowing the newline curl wrote. Without
///   the `?` the body keeps a trailing newline that would land inside the
///   emitted JSON document.
///
/// A command substitution strips trailing newlines, so the raw value is
/// exactly `<body>\n<marker><code>` and both expansions are exact. A third
/// expansion, `${CODE##*[!0-9]}`, then keeps only trailing digits: it makes
/// the code safe to interpolate into the error document, and it stops a body
/// that arrived with no marker at all from passing the check merely because it
/// happens to start with `2`.
///
/// `|| true` inside each substitution is deliberate. curl exits non-zero on a
/// transport failure (connection refused, DNS, `--max-time`) while still
/// writing its `-w` line with `%{http_code}` = `000` — the case
/// `AwxCommandBuilder::parse_checked_response` documents. Under `set -e` the
/// assignment alone would abort the script there, before the check could name
/// which of the three calls died, and with nothing at all on stdout.
fn build_follow_script(
    awx: &crate::config::AwxConfig,
    template_id: u64,
    launch_body: &str,
    poll_interval: u32,
    max_wait: u64,
) -> String {
    let launch_cmd = AwxCommandBuilder::build_api_call_checked(
        &awx.url,
        &awx.token,
        &format!("/api/v2/job_templates/{template_id}/launch/"),
        HttpMethod::Post,
        Some(launch_body),
        awx.verify_ssl,
        &[],
        awx.api_timeout,
    );
    let status_cmd = AwxCommandBuilder::build_api_call_checked(
        &awx.url,
        &awx.token,
        "/api/v2/jobs/'$JOB_ID'/",
        HttpMethod::Get,
        None,
        awx.verify_ssl,
        &[],
        awx.api_timeout,
    );
    let summary_cmd = AwxCommandBuilder::build_api_call_checked(
        &awx.url,
        &awx.token,
        "/api/v2/jobs/'$JOB_ID'/job_host_summaries/",
        HttpMethod::Get,
        None,
        awx.verify_ssl,
        &[],
        awx.api_timeout,
    );

    format!(
        r#"set -e
LAUNCH_RAW=$({launch_cmd} || true)
LAUNCH_CODE=${{LAUNCH_RAW##*{STATUS_MARKER}}}
LAUNCH_BODY=${{LAUNCH_RAW%?{STATUS_MARKER}*}}
LAUNCH_CODE=${{LAUNCH_CODE##*[!0-9]}}
case "$LAUNCH_CODE" in
  [23][0-9][0-9]) ;;
  *) echo '{{"error":"AWX job launch request failed","request":"POST /api/v2/job_templates/{template_id}/launch/","http_status":"'"$LAUNCH_CODE"'"}}'; exit 1 ;;
esac
JOB_ID=$(echo "$LAUNCH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "$LAUNCH_BODY" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ -z "$JOB_ID" ]; then echo '{{"error":"Failed to launch job","response":'"$LAUNCH_BODY"'}}'; exit 1; fi
echo '{{"launched":true,"job_id":'$JOB_ID'}}' >&2
ELAPSED=0
while [ $ELAPSED -lt {max_wait} ]; do
  sleep {poll_interval}
  ELAPSED=$((ELAPSED + {poll_interval}))
  POLL_RAW=$({status_cmd} || true)
  POLL_CODE=${{POLL_RAW##*{STATUS_MARKER}}}
  POLL_BODY=${{POLL_RAW%?{STATUS_MARKER}*}}
  POLL_CODE=${{POLL_CODE##*[!0-9]}}
  case "$POLL_CODE" in
    [23][0-9][0-9]) ;;
    *) echo '{{"error":"AWX job status request failed","request":"GET /api/v2/jobs/'$JOB_ID'/","job_id":'$JOB_ID',"http_status":"'"$POLL_CODE"'"}}'; exit 1 ;;
  esac
  STATUS=$(echo "$POLL_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
  case "$STATUS" in
    successful) JOB_EXIT=0 ;;
    failed|error|canceled) JOB_EXIT=1 ;;
    *) continue ;;
  esac
  SUMMARY_RAW=$({summary_cmd} || true)
  SUMMARY_CODE=${{SUMMARY_RAW##*{STATUS_MARKER}}}
  SUMMARY_BODY=${{SUMMARY_RAW%?{STATUS_MARKER}*}}
  SUMMARY_CODE=${{SUMMARY_CODE##*[!0-9]}}
  case "$SUMMARY_CODE" in
    [23][0-9][0-9]) ;;
    *) echo '{{"error":"AWX job host summaries request failed","request":"GET /api/v2/jobs/'$JOB_ID'/job_host_summaries/","job_id":'$JOB_ID',"status":"'$STATUS'","http_status":"'"$SUMMARY_CODE"'"}}'; exit 1 ;;
  esac
  echo '{{"job_id":'$JOB_ID',"status":"'$STATUS'","elapsed":'$ELAPSED',"summary":'$SUMMARY_BODY'}}'
  exit $JOB_EXIT
done
echo '{{"job_id":'$JOB_ID',"status":"timeout","elapsed":'$ELAPSED',"message":"Job still running after {max_wait}s. Use ssh_awx_job_status to check."}}'
exit 1
"#,
    )
}

/// Handler for the `ssh_awx_job_follow` tool.
#[mcp_tool(name = "ssh_awx_job_follow", group = "awx", annotation = "mutating")]
pub struct SshAwxJobFollowHandler;

impl Default for SshAwxJobFollowHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobFollowHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl ToolHandler for SshAwxJobFollowHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_follow"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX job and wait for completion, returning a structured summary. \
         Combines launch + poll + summary into one call. Returns per-host ok/changed/failed \
         counts and failure details. Use poll_interval and max_wait to control timing. \
         For long jobs, prefer ssh_awx_job_launch + ssh_awx_job_status polling instead. \
         Requires AWX — for direct SSH-based playbook execution with a compact summary, \
         use ssh_ansible_recap instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_follow",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut raw = args.ok_or_else(|| BridgeError::McpMissingParam {
            param: "arguments".to_string(),
        })?;
        let dr = crate::domain::data_reduction::DataReductionArgs::extract_for(
            &mut raw,
            self.name(),
            self.output_kind(),
        )?;
        let args: SshAwxJobFollowArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.template_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let host = &awx.ssh_host;
        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        let limits = ctx.config.limits.clone();

        // Build a shell script that: 1) launches the job, 2) polls status, 3) fetches summary
        let poll_interval = args.poll_interval.clamp(2, 30);
        let max_wait = args.max_wait.clamp(10, 3600);

        // Build launch body
        let mut body_obj = serde_json::Map::new();
        if let Some(extra) = &args.extra_vars {
            body_obj.insert("extra_vars".to_string(), extra.clone());
        }
        if let Some(lim) = &args.limit {
            body_obj.insert("limit".to_string(), Value::String(lim.clone()));
        }
        let body = if body_obj.is_empty() {
            "{}".to_string()
        } else {
            serde_json::to_string(&body_obj).unwrap_or_else(|_| "{}".to_string())
        };

        // Construct the all-in-one shell script: launch → extract job_id →
        // poll → fetch summary. See `build_follow_script` for why the HTTP
        // checks live in the shell rather than in `parse_checked_response`.
        let script = build_follow_script(awx, args.template_id, &body, poll_interval, max_wait);

        let cmd = format!(
            "bash -c {}",
            crate::domain::use_cases::shell::escape(&script, crate::config::ShellType::Posix)
        );

        // Execute with extended timeout
        let mut exec_limits = limits.clone();
        exec_limits.command_timeout_seconds = max_wait + 30; // extra buffer

        let mut conn = ctx
            .connection_pool
            .get_connection_with_jump(host, host_config, &exec_limits, None)
            .await?;
        let output = conn.exec(&cmd, &exec_limits).await?;

        // Third argument is the *command*, not the tool name: audit and
        // history both re-export it verbatim, so passing "ssh_awx_job_follow"
        // recorded the tool name where every other handler records what ran.
        //
        // The SCRIPT is recorded rather than `cmd`, and that is a secret
        // question, not a cosmetic one. `cmd` wraps the script in
        // `bash -c '<script>'`, which escapes every `'` in it as `'\''`, so
        // the auth header reads `Bearer '\''<token>'\''`. The sanitizer's
        // opaque-bearer pattern allows a single optional quote between
        // `Bearer` and the token and stops at the backslash, so the token
        // would reach audit.log and the history in clear. In the script the
        // header is escaped once, `Bearer '<token>'`, which is the shape the
        // sanitizer redacts — and the shape every other AWX handler records.
        // `the_history_redacts_the_awx_token` pins this.
        let response =
            ctx.execute_use_case
                .process_success(self.name(), host, &script, &output.into(), &[]);
        let mut stdout = response.stdout;

        crate::mcp::standard_tool::apply_reduction_recorded(
            ctx,
            &mut stdout,
            &dr,
            crate::domain::output_kind::OutputKind::Json,
        )?;

        let result = ToolCallResult::text(stdout);
        if response.exit_code == 0 {
            return Ok(result);
        }
        // `with_remote_exit_code`, which also sets `is_error`, rather than
        // `with_remote_exit_code_only`: this tool wrote the script, the caller
        // did not. A job AWX finished in `failed`, a status request AWX
        // refused, or a job still running at `max_wait` are failures of what
        // the tool was asked to do, not neutral facts for the caller to
        // interpret — unlike `ssh_exec`, where a non-zero code is the answer.
        Ok(result.with_remote_exit_code(i32::try_from(response.exit_code).unwrap_or(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    /// AWX settings every test in this module builds its script from.
    fn test_awx_config() -> crate::config::AwxConfig {
        crate::config::AwxConfig {
            ssh_host: "server1".to_string(),
            url: "https://awx.test".to_string(),
            token: crate::config::RedactedSecret::from("awx-token"),
            api_timeout: 30,
            verify_ssl: true,
        }
    }

    /// A `ToolContext` carrying [`test_awx_config`] and a mock executor that
    /// answers every `exec` with `(exit_code, stdout)`.
    fn ctx_with_output(exit_code: u32, stdout: &str) -> crate::ports::ToolContext {
        let mut config = (*crate::ports::mock::create_test_context_with_host().config).clone();
        config.awx = Some(test_awx_config());
        crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code,
                stdout: stdout.to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        )
    }

    // ===================================================================
    // The script, run under a real shell
    //
    // Everything this task changed below the handler is shell: three HTTP
    // checks, four exit codes, and a `set -e` that decides whether an arm
    // reaches its `echo`. Asserting on the script *text* cannot answer that,
    // so these tests execute the generated script with `bash`, against stub
    // `curl` and `sleep` binaries placed ahead of the real ones on `PATH`.
    // ===================================================================

    /// Stand-in for `curl`. Reproduces only what the script depends on: the
    /// body, and the `-w '\nHTTP_STATUS:<code>'` line the real curl appends.
    /// That the real builder asks for that write-out is asserted separately by
    /// `the_script_splits_the_marker_the_builder_actually_writes` here and by
    /// `test_build_api_call_checked_appends_status_writeout` in the domain
    /// builder — the stub is not the evidence for it.
    ///
    /// `000` also exits non-zero, because that is what curl does on a
    /// transport failure while still writing its `-w` line.
    #[cfg(unix)]
    const CURL_STUB: &str = r#"#!/bin/sh
url=
for a in "$@"; do
  case "$a" in
    http://*|https://*) url=$a ;;
  esac
done
case "$url" in
  */launch/)
    body='{"id":4242}'
    code=$STUB_LAUNCH_CODE
    ;;
  */job_host_summaries/)
    body='{"results":[{"host_name":"h1","ok":2,"failures":0}]}'
    code=$STUB_SUMMARY_CODE
    ;;
  *)
    body="{\"status\":\"$STUB_JOB_STATUS\"}"
    code=$STUB_POLL_CODE
    ;;
esac
printf '%s\nHTTP_STATUS:%s' "$body" "$code"
case "$code" in
  000) exit 7 ;;
esac
"#;

    /// Stand-in for `sleep`, so the poll loop costs nothing. `poll_interval`
    /// is clamped to at least 2s and `max_wait` to at least 10s, which would
    /// otherwise make the timeout test alone a ten-second test.
    #[cfg(unix)]
    const SLEEP_STUB: &str = "#!/bin/sh\nexit 0\n";

    #[cfg(unix)]
    struct ScriptRun {
        code: i32,
        stdout: String,
    }

    /// Run the generated script under `bash` with the stubs on `PATH`.
    ///
    /// The three HTTP codes and the job status the stub reports are passed
    /// through the environment, so one harness drives every arm.
    #[cfg(unix)]
    fn run_follow_script(
        launch_code: &str,
        poll_code: &str,
        summary_code: &str,
        job_status: &str,
    ) -> ScriptRun {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir for the curl/sleep stubs");
        for (name, body) in [("curl", CURL_STUB), ("sleep", SLEEP_STUB)] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).expect("write stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("make the stub executable");
        }

        let script = build_follow_script(&test_awx_config(), 7, "{}", 2, 10);
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("STUB_LAUNCH_CODE", launch_code)
            .env("STUB_POLL_CODE", poll_code)
            .env("STUB_SUMMARY_CODE", summary_code)
            .env("STUB_JOB_STATUS", job_status)
            .output()
            .expect("bash must be on PATH for the ssh_awx_job_follow script tests");

        ScriptRun {
            code: output
                .status
                .code()
                .expect("the script must exit, not die on a signal"),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        }
    }

    /// Parse the script's stdout as JSON, which also proves the `HTTP_STATUS:`
    /// marker did not leak into the emitted document.
    #[cfg(unix)]
    fn emitted_json(run: &ScriptRun) -> Value {
        serde_json::from_str(&run.stdout).unwrap_or_else(|e| {
            panic!(
                "the script must emit one JSON document on stdout ({e}): {:?}",
                run.stdout
            )
        })
    }

    #[cfg(unix)]
    #[test]
    fn a_successful_job_exits_zero_and_carries_the_summary() {
        let run = run_follow_script("201", "200", "200", "successful");
        assert_eq!(run.code, 0, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["status"], "successful");
        assert_eq!(doc["job_id"], 4242);
        // The summary is the *split* body: had the marker line survived the
        // split, this document would not have parsed at all.
        assert_eq!(doc["summary"]["results"][0]["host_name"], "h1");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_job_exits_one() {
        let run = run_follow_script("201", "200", "200", "failed");
        assert_eq!(run.code, 1, "stdout: {:?}", run.stdout);
        assert_eq!(emitted_json(&run)["status"], "failed");
    }

    #[cfg(unix)]
    #[test]
    fn an_errored_job_exits_one() {
        let run = run_follow_script("201", "200", "200", "error");
        assert_eq!(run.code, 1, "stdout: {:?}", run.stdout);
        assert_eq!(emitted_json(&run)["status"], "error");
    }

    #[cfg(unix)]
    #[test]
    fn a_canceled_job_exits_one() {
        let run = run_follow_script("201", "200", "200", "canceled");
        assert_eq!(run.code, 1, "stdout: {:?}", run.stdout);
        assert_eq!(emitted_json(&run)["status"], "canceled");
    }

    #[cfg(unix)]
    #[test]
    fn a_job_still_running_at_max_wait_exits_one() {
        // The loop falls through and the timeout document is emitted. It used
        // to be the script's last command, so the script returned 0 and a
        // conditional chain carried on over a job that was still running.
        let run = run_follow_script("201", "200", "200", "running");
        assert_eq!(run.code, 1, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["status"], "timeout");
        assert_eq!(doc["job_id"], 4242);
    }

    #[cfg(unix)]
    #[test]
    fn a_non_2xx_on_the_launch_call_names_the_launch_call() {
        let run = run_follow_script("403", "200", "200", "successful");
        assert_ne!(run.code, 0, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["http_status"], "403");
        let request = doc["request"].as_str().expect("request field");
        assert!(
            request.contains("/launch/"),
            "the error must name which of the three calls failed: {request}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_2xx_on_the_status_poll_names_the_status_call() {
        let run = run_follow_script("201", "500", "200", "successful");
        assert_ne!(run.code, 0, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["http_status"], "500");
        let request = doc["request"].as_str().expect("request field");
        assert!(
            request.contains("/api/v2/jobs/") && !request.contains("job_host_summaries"),
            "the error must name the status poll, not another call: {request}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_2xx_on_the_summary_call_names_the_summary_call() {
        let run = run_follow_script("201", "200", "502", "successful");
        assert_ne!(run.code, 0, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["http_status"], "502");
        let request = doc["request"].as_str().expect("request field");
        assert!(
            request.contains("job_host_summaries"),
            "the error must name the summary call: {request}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_curl_transport_failure_is_reported_rather_than_aborting_the_script() {
        // curl exits non-zero here while writing `HTTP_STATUS:000`. Without
        // the `|| true` inside the substitution, `set -e` would kill the
        // script on the assignment and the caller would get an empty stdout
        // with no hint of which call died.
        let run = run_follow_script("201", "000", "200", "successful");
        assert_ne!(run.code, 0, "stdout: {:?}", run.stdout);
        let doc = emitted_json(&run);
        assert_eq!(doc["http_status"], "000");
        assert!(
            doc["request"]
                .as_str()
                .is_some_and(|r| r.contains("/api/v2/jobs/")),
            "{doc}"
        );
    }

    #[test]
    fn the_script_splits_the_marker_the_builder_actually_writes() {
        let script = build_follow_script(&test_awx_config(), 7, "{}", 5, 600);

        // All three calls go through the checked builder: one write-out each.
        let write_out = format!("-w '\\n{STATUS_MARKER}%{{http_code}}'");
        assert_eq!(
            script.matches(&write_out).count(),
            3,
            "the launch, status and summary calls must all be checked: {script}"
        );
        // And that write-out really is what the builder emits — this binds the
        // marker duplicated in `STATUS_MARKER` to the builder's private one.
        let built = AwxCommandBuilder::build_api_call_checked(
            "https://awx.test",
            "t",
            "/api/v2/jobs/1/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        assert!(built.ends_with(&write_out), "builder emits: {built}");

        // Every consumer reads the split body, never the raw capture. Each
        // `_RAW` name may appear exactly three times: the capture, and the two
        // expansions that split it. Any fourth occurrence is a consumer that
        // would see the marker line.
        for var in ["LAUNCH", "POLL", "SUMMARY"] {
            let uses: Vec<&str> = script
                .match_indices(&format!("{var}_RAW"))
                .map(|(i, _)| &script[i..(i + 40).min(script.len())])
                .collect();
            assert_eq!(
                uses.len(),
                3,
                "{var}_RAW must appear exactly three times — the capture and \
                 its two split expansions: {uses:?}"
            );
            assert!(uses[0].starts_with(&format!("{var}_RAW=$(")), "{uses:?}");
            assert!(
                uses[1].starts_with(&format!("{var}_RAW##*{STATUS_MARKER}}}")),
                "{uses:?}"
            );
            assert!(
                uses[2].starts_with(&format!("{var}_RAW%?{STATUS_MARKER}*}}")),
                "{uses:?}"
            );
        }
        assert!(
            script.contains("echo \"$LAUNCH_BODY\" | python3"),
            "the job id must be parsed from the split body: {script}"
        );
        assert!(
            script.contains("echo \"$POLL_BODY\" | python3"),
            "the job status must be parsed from the split body: {script}"
        );
        assert!(
            script.contains("\"summary\":'$SUMMARY_BODY'"),
            "the emitted document must carry the split body: {script}"
        );
    }

    // ===================================================================
    // The handler
    // ===================================================================

    #[tokio::test]
    async fn a_failing_script_reaches_the_caller_as_a_failed_tool_call() {
        let ctx = ctx_with_output(1, r#"{"job_id":4242,"status":"failed"}"#);
        let result = SshAwxJobFollowHandler::new()
            .execute(Some(json!({"template_id": 7})), &ctx)
            .await
            .expect("the handler must return a result, not an error");
        assert_eq!(
            result.remote_exit_code,
            Some(1),
            "the script's exit code must reach the caller: {result:?}"
        );
        assert_eq!(
            result.is_error,
            Some(true),
            "this tool wrote the script, so a non-zero exit is a failed call: {result:?}"
        );
    }

    #[tokio::test]
    async fn a_successful_script_is_not_announced_as_a_failure() {
        let ctx = ctx_with_output(0, r#"{"job_id":4242,"status":"successful"}"#);
        let result = SshAwxJobFollowHandler::new()
            .execute(Some(json!({"template_id": 7})), &ctx)
            .await
            .expect("the handler must return a result");
        assert_eq!(result.remote_exit_code, None, "{result:?}");
        assert_eq!(result.is_error, None, "{result:?}");
    }

    #[tokio::test]
    async fn the_history_records_the_command_and_not_the_tool_name() {
        let ctx = ctx_with_output(0, "{}");
        SshAwxJobFollowHandler::new()
            .execute(Some(json!({"template_id": 7})), &ctx)
            .await
            .expect("the handler must return a result");
        let recorded = ctx.history.recent(1);
        let command = &recorded.first().expect("one history entry").command;
        assert_ne!(
            command, "ssh_awx_job_follow",
            "the third argument of process_success is the command, not the tool name"
        );
        assert!(
            command.contains("curl") && command.contains("/api/v2/job_templates/7/launch/"),
            "the history must hold what ran: {command}"
        );
    }

    #[tokio::test]
    async fn the_history_redacts_the_awx_token() {
        // Recording the command instead of the tool name only stays safe as
        // long as what is recorded is singly escaped: the sanitizer's bearer
        // pattern accepts one optional quote after `Bearer` and stops at a
        // backslash, so the `bash -c '<script>'` form — where `'` becomes
        // `'\''` — would carry the token into audit.log and the history in
        // clear.
        let ctx = ctx_with_output(0, "{}");
        SshAwxJobFollowHandler::new()
            .execute(Some(json!({"template_id": 7})), &ctx)
            .await
            .expect("the handler must return a result");
        let recorded = ctx.history.recent(1);
        let command = &recorded.first().expect("one history entry").command;
        assert!(
            !command.contains("awx-token"),
            "the AWX bearer token reached the history in clear: {command}"
        );
        assert!(
            command.contains("[BEARER_TOKEN_REDACTED]"),
            "the token must be redacted, not merely absent: {command}"
        );
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxJobFollowHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxJobFollowHandler::new();
        assert_eq!(handler.name(), "ssh_awx_job_follow");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_follow");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("template_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "template_id": 42,
            "extra_vars": {"env": "prod"},
            "limit": "webservers",
            "poll_interval": 10,
            "max_wait": 300
        });
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 42);
        assert!(args.extra_vars.is_some());
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.poll_interval, 10);
        assert_eq!(args.max_wait, 300);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"template_id": 1});
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 1);
        assert!(args.extra_vars.is_none());
        assert!(args.limit.is_none());
        assert_eq!(args.poll_interval, 5);
        assert_eq!(args.max_wait, 600);
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"template_id": 1});
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert!(format!("{args:?}").contains("SshAwxJobFollowArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobFollowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"template_id": "abc"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxJobFollowHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"template_id": 1})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("AWX not configured"));
    }
}
