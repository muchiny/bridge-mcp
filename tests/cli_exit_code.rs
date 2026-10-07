//! The first test in this repo that observes the exit code of a real process.
//!
//! Scope, stated plainly: these runs need no network and no SSH host, so they
//! observe the codes the bridge produces for ITS OWN failures (`map_exit_code`
//! and the anyhow flattening in `main`). They do NOT observe a remote command
//! failing under the daemon (`ssh_exec host=X command=false`), which needs a
//! reachable SSH host.

use std::process::{Command, Output};

fn run(config: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bridge-mcp"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env("HOME", config.parent().unwrap())
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
}

#[test]
fn an_unreadable_config_exits_1_through_main_s_anyhow_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.yaml");
    let out = run(&missing, &["tool", "ssh_exec", "host=x", "command=false"]);
    // Not routed through `map_exit_code`: pins the flattening so a change to it
    // is a decision, not an accident.
    assert_eq!(out.status.code(), Some(1));
}
