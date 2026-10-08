//! The first test in this repo that observes the exit code of a real process.
//!
//! Scope, stated plainly: these runs need no network and no SSH host, so they
//! observe the codes the bridge produces for ITS OWN failures: `map_exit_code`
//! (destructive gate, unknown host) and `main`'s `EXIT_CONFIG_ERROR` for any
//! config that fails to load. They do NOT observe a remote command
//! failing under the daemon (`ssh_exec host=X command=false`), which needs a
//! reachable SSH host.

use std::process::{Command, Output};

fn run(config: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bridge-mcp"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env("HOME", config.parent().unwrap())
        // The config has no `audit:` section, so the default audit path is
        // `data_local_dir()`, which prefers XDG_DATA_HOME over HOME: left
        // set, it is the developer's REAL ~/.local/share/bridge-mcp.
        .env_remove("XDG_DATA_HOME")
        // `daemon::default_socket_path()` is `$XDG_RUNTIME_DIR/bridge-mcp.sock`,
        // so left inherited these runs would reach whatever daemon the
        // developer's session happens to have up — and the daemon changes what
        // every one of these exit codes means. Pointed at this test's own
        // directory, which holds no socket unless the test puts one there.
        .env("XDG_RUNTIME_DIR", config.parent().unwrap())
        .output()
        .expect("spawn bridge-mcp")
}

/// A daemon that is only a socket: it accepts one connection, answers a
/// successful `tools/call` result, and that is all. It exists so a test can
/// observe what the CLI does when a daemon IS up — no SSH, no real daemon,
/// no host.
///
/// Returned handle: dropping it stops the accept loop at the next connection.
fn stub_daemon(runtime_dir: &std::path::Path) -> std::thread::JoinHandle<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let socket = runtime_dir.join("bridge-mcp.sock");
    let listener = UnixListener::bind(&socket).expect("bind the stub daemon socket");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut line = String::new();
            let _ = BufReader::new(stream.try_clone().expect("clone")).read_line(&mut line);
            let id: serde_json::Value = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": "served by the stub daemon"}],
                    "isError": false,
                    "_meta": {
                        "io.modelcontextprotocol/remoteExitCode": 0,
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28"
                    }
                }
            });
            let _ = writeln!(stream, "{response}");
            let _ = stream.flush();
        }
    })
}

/// **The placement invariant, pinned.** The destructive gate must decide
/// before the daemon branch, because which path serves a call is an accident
/// of whether a daemon happens to be up — and until 2026-08-31 that accident
/// decided whether a destructive tool was refused or ran unchallenged.
///
/// Every other test in this file runs with no daemon, so all of them pass
/// just as well with the gate moved below the daemon branch. This one does
/// not: with a daemon up, a gate placed after the forward would never be
/// reached and this call would be served (exit 0) instead of refused.
#[test]
fn the_destructive_gate_still_refuses_when_a_daemon_is_up() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let _daemon = stub_daemon(dir.path());

    let out = run(&cfg, &["tool", "ssh_exec", "host=real", "command=false"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a live daemon must not get a destructive call past the gate; stderr={stderr}"
    );
    assert!(
        stderr.contains("stdin is not a terminal"),
        "the refusal must be the gate's, not the daemon's: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("served by the stub daemon"),
        "the daemon must never have been asked"
    );

    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    let log = std::fs::read_to_string(&audit)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", audit.display()));
    assert!(
        log.contains(r#""event_type":"command_denied""#),
        "the refusal must be audited even with a daemon up, got {log:?}"
    );
}

/// The other half of the same invariant, and the one that measures the drain:
/// a confirmed destructive call that a daemon serves still writes its gate
/// line. The writer task dies with the process, so this only passes if the
/// daemon path reaches `finish_audit_wiring` before returning.
#[test]
fn a_daemon_served_call_still_drains_the_gate_line_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let _daemon = stub_daemon(dir.path());

    let out = run(
        &cfg,
        &["--yes", "tool", "ssh_exec", "host=real", "command=true"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the stub daemon answers success; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("served by the stub daemon"),
        "this must be the daemon path, not the in-process one: {stdout}"
    );

    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    let log = std::fs::read_to_string(&audit)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", audit.display()));
    assert!(
        log.contains(r#""event_type":"command_confirmed""#)
            && log.contains(r#""Confirmed":{"by":"--yes"}"#),
        "the gate line must survive the daemon path's early return, got {log:?}"
    );
}

/// A file passed to a destructive tool must not be copied into the trail.
/// Through the real binary, because the bound has to hold on the path an
/// operator actually uses.
///
/// 100 KB, not the 400 KB of the unit test: Linux caps a single argv entry at
/// `MAX_ARG_STRLEN` (32 pages, 128 KB), so a 400 KB `content=` cannot be
/// spawned at all — `execve` fails with `E2BIG` before the binary starts.
/// That bounds how large a gate line the **CLI** could ever have written; the
/// unbounded case needs the daemon or MCP path, which the unit test covers.
#[test]
fn a_large_argument_is_not_copied_into_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let content = "S".repeat(100 * 1024);
    let json_args = serde_json::json!({
        "host": "real",
        "path": "/etc/motd",
        "content": content,
    })
    .to_string();

    let out = run(
        &cfg,
        &["--yes", "tool", "ssh_file_write", "--json-args", &json_args],
    );
    // Whatever the call then does (no reachable host here), the gate line is
    // already written.
    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    let log = std::fs::read_to_string(&audit)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", audit.display()));
    assert!(
        log.contains(r#""event_type":"command_confirmed""#),
        "the gate must have recorded its decision, got {log:?} (exit {:?})",
        out.status.code()
    );
    assert!(
        !log.contains(&content),
        "a 100 KB content= must not reach the audit file ({} bytes written)",
        log.len()
    );
    assert!(
        log.contains(&format!("<elided: {} chars>", content.chars().count())),
        "the elision must say what was dropped, got {log:?}"
    );
}

fn empty_config(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        "hosts:\n  real:\n    hostname: \"10.0.0.1\"\n    user: u\n    auth:\n      type: agent\n",
    )
    .unwrap();
    // The loader refuses a config readable by group/other.
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    path
}

// The destructive gate runs before the host lookup, which is why the unknown-host
// test passes `--yes`; if that order changes, these two move together.
#[test]
fn a_destructive_tool_without_a_terminal_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let out = run(&cfg, &["tool", "ssh_exec", "host=real", "command=false"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--yes`'s help text promises that the gate's choice "is recorded in the
/// audit log". The unit tests in `cli::runner` observe the channel the logger
/// sends on; this one observes the file, because the decision used to go to
/// `tracing::warn!` — which reaches stderr and never `audit.path`, and no
/// in-process assertion on the channel can tell those two apart.
#[test]
fn a_refused_destructive_tool_writes_its_denial_to_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let out = run(&cfg, &["tool", "ssh_exec", "host=real", "command=false"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `run` points HOME at the config's own directory and clears
    // XDG_DATA_HOME, and the config declares no `audit:` section, so the
    // default path resolves inside this tempdir.
    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    let log = std::fs::read_to_string(&audit)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", audit.display()));
    assert!(
        log.contains(r#""event_type":"command_denied""#),
        "the refusal must be audited as a denial, got {log:?}"
    );
    // Pin the line to this call: without the name a denial reads like any
    // other, and without the host it could be some earlier line.
    assert!(
        log.contains(r#""tool_name":"ssh_exec""#) && log.contains(r#""host":"real""#),
        "the denial must name the tool and the host, got {log:?}"
    );
}

/// The other half: a destructive call the gate LETS THROUGH writes a line
/// too, so the absence of one on a destructive call means it never met the
/// gate. Exit 3 (unknown host) is incidental — the gate runs before the host
/// lookup, which is the order `an_unknown_host_exits_3…` already depends on.
#[test]
fn a_confirmed_destructive_tool_writes_its_confirmation_to_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let out = run(
        &cfg,
        &["--yes", "tool", "ssh_exec", "host=nope", "command=false"],
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    let log = std::fs::read_to_string(&audit)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", audit.display()));
    assert!(
        log.contains(r#""event_type":"command_confirmed""#)
            && log.contains(r#""Confirmed":{"by":"--yes"}"#),
        "the gate's confirmation must name what answered, got {log:?}"
    );
    assert!(
        log.contains(r#""tool_name":"ssh_exec""#),
        "the confirmation must name the tool, got {log:?}"
    );
}

#[test]
fn an_unknown_host_exits_3_not_1_and_not_the_remote_failure_code() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let out = run(
        &cfg,
        &["--yes", "tool", "ssh_exec", "host=nope", "command=false"],
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Pin the cause: 3 would also come out of an `SshConnection` error.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nope"),
        "stderr should name the unknown host"
    );
}

#[test]
fn a_config_that_fails_to_load_exits_5() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.yaml");
    let out = run(&missing, &["tool", "ssh_exec", "host=x", "command=false"]);
    // Fails inside `main` before `run_tool`; `main` exits `EXIT_CONFIG_ERROR`
    // for any `load_config` failure, by call site and NOT through
    // `map_exit_code`. Before that it exited 1 (measured).
    assert_eq!(out.status.code(), Some(5));
    // Pin the cause: 5 would also come out of any other configuration error.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to load config") && stderr.contains("absent.yaml"),
        "stderr should name the config path, got {stderr}"
    );
}

/// Not `ConfigNotFound`/`ConfigInvalid`: `load_config` returns `SshKeyNotFound`
/// here, a variant `map_exit_code` does not list. It exits 5 because `main`
/// classifies any load failure by call site (measured: 1 before).
#[test]
fn a_missing_ssh_key_file_exits_5_like_any_config_that_fails_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let missing_key = dir.path().join("no-such-key");
    std::fs::write(
        &path,
        format!(
            "hosts:\n  real:\n    hostname: \"10.0.0.1\"\n    user: u\n    auth:\n      type: key\n      path: {}\n",
            missing_key.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let out = run(&path, &["status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "stderr={stderr}");
    assert!(
        stderr.contains("no-such-key"),
        "stderr should name the key: {stderr}"
    );
}

/// The production default audit path, end to end. Unit-test builds point
/// `default_audit_path()` at a temp dir, so only a real binary can show that a
/// release build still audits to `<data_local_dir>/bridge-mcp/audit.log` when
/// the config has no `audit:` section. `history` reaches
/// `create_context_with_audit` with no host and no network, and `run` points
/// `data_local_dir` at the tempdir (`HOME` set, `XDG_DATA_HOME` removed).
#[test]
fn a_config_without_audit_writes_the_production_default_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = empty_config(&dir);
    let out = run(&cfg, &["history"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let audit = dir.path().join(".local/share/bridge-mcp/audit.log");
    assert!(
        audit.exists(),
        "a release build must audit to the production default {}",
        audit.display()
    );
}
