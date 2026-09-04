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
    //
    // Watching the literal path `.git/HEAD` is not enough: committing again
    // on the same branch rewrites `refs/heads/<branch>` (or the reftable
    // backend), not `.git/HEAD` itself, so Cargo never notices and keeps
    // serving a stale rev forever after the first build. `logs/HEAD` (the
    // reflog) is appended on every commit regardless of branch or ref
    // backend, so it is the one that actually catches this. Resolving both
    // through `git rev-parse --git-path` rather than hardcoding `.git/...`
    // also makes this correct inside a linked worktree, where `.git` is a
    // gitlink file and the real per-worktree HEAD lives elsewhere.
    for p in ["HEAD", "logs/HEAD"] {
        if let Some(path) = run(&["rev-parse", "--git-path", p]) {
            println!("cargo::rerun-if-changed={path}");
        }
    }
    println!("cargo::rerun-if-changed=src");
    // A dependency bump dirties the tree without touching `src`, and it is
    // precisely the kind of change a build stamp must not lie about.
    println!("cargo::rerun-if-changed=Cargo.toml");
    println!("cargo::rerun-if-changed=Cargo.lock");
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
