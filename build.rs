//! Build script: stamps the git revision of the working tree into the binary.
//!
//! `--version` alone cannot tell a fresh binary from a stale one: it prints
//! `CARGO_PKG_VERSION`, which is identical for every build of a given release.
//! The binary deployed to `~/.local/bin` on 2026-08-02 printed exactly the
//! same string as one built from HEAD 23 commits later, and nothing noticed
//! for 17 days. `BRIDGE_MCP_BUILD_REV` is what makes the two distinguishable.

use std::process::Command;

fn main() {
    // Re-run when the checked-out commit changes, and when any source file
    // changes — the latter is what keeps the `-dirty` suffix honest.
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=src");
    println!("cargo::rerun-if-env-changed=BRIDGE_MCP_BUILD_REV");

    // Distro packagers building from an exported tarball can pin the value.
    let rev = std::env::var("BRIDGE_MCP_BUILD_REV")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(git_rev);

    println!("cargo::rustc-env=BRIDGE_MCP_BUILD_REV={rev}");
}

/// `<12 hex chars>`, `<12 hex chars>-dirty`, or `unknown` when git is not
/// usable here (crates.io tarball, vendored source, git not installed).
fn git_rev() -> String {
    let Some(sha) = run(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    if sha.is_empty() {
        return "unknown".to_string();
    }
    // `--untracked-files=no`: a stray untracked file does not end up in the
    // binary, so it must not flip the marker. The `verify-install` Make target
    // runs this exact command — the two definitions of "dirty" must not drift.
    match run(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(status) if !status.is_empty() => format!("{sha}-dirty"),
        Some(_) => sha,
        None => "unknown".to_string(),
    }
}

fn run(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
