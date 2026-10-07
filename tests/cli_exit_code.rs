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
        .output()
        .expect("spawn bridge-mcp")
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
