//! Bash Syntax Regression Suite
//!
//! Runs every command emitted by a domain `build_*_command()` (and every
//! `*_detect_prefix()`) through `bash -n` (parse-only) wrapped in the same
//! `export LC_ALL=C; <cmd>` shell that `StandardToolHandler` produces at
//! runtime.
//!
//! Catches two regression classes that have previously shipped silently:
//!
//! 1. Reserved-word collisions — adding a `LC_ALL=C ` prefix in front of a
//!    builder that begins with `if`/`for`/`while`/`{` produces a hard parse
//!    error before any subprocess runs. Using `export LC_ALL=C; cmd` form
//!    instead, this is a non-issue, but we still assert it once per
//!    compound builder so future prefix changes can't reintroduce the bug.
//! 2. Detect-prefix sentinels — when a `$(...)` subshell echoes a literal
//!    `ERROR_X_NOT_FOUND` token, that token becomes the outer command and
//!    fails with `command not found` (exit 127) instead of a clean
//!    structured error. Asserting the prefix contains `echo false` (the
//!    fixed shape) ensures the outer command short-circuits to exit 1.
//!
//! All targets here are pure-domain string builders, so the suite runs
//! without touching the network and finishes in <1s. It is *not* gated by
//! `#[ignore]` — every CI run executes it.

use std::process::Command;

use bridge_mcp::domain::use_cases::docker::{
    DockerCommandBuilder, docker_compose_detect_prefix, docker_detect_prefix,
};
use bridge_mcp::domain::use_cases::firewall::{
    FirewallCommandBuilder, firewall_detect, validate_port,
};
use bridge_mcp::domain::use_cases::kubernetes::{
    KubernetesCommandBuilder, helm_detect_prefix, kubectl_detect_prefix,
};
use bridge_mcp::domain::use_cases::package::{PackageCommandBuilder, pkg_detect_prefix};
use bridge_mcp::domain::use_cases::templates::TemplateCommandBuilder;

// ---- helpers --------------------------------------------------------------

/// Run the candidate command through `bash -n` after the runtime locale
/// prefix is applied. Panics with a useful diff on syntax error.
#[track_caller]
fn assert_runtime_form_parses(cmd: &str, label: &str) {
    let wrapped = format!("export LC_ALL=C; {cmd}");
    let out = Command::new("bash")
        .args(["-n", "-c", &wrapped])
        .output()
        .expect("bash must be in PATH for builder_syntax tests");
    assert!(
        out.status.success(),
        "{label}: bash -n rejected the command\n  CMD: {wrapped}\n  STDERR: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Assert that a `*_detect_prefix()` returns the post-fix shape (clear error
/// message + `echo false` fallback) so a missing binary on the host yields
/// `false ...` (exit 1) instead of `ERROR_X_NOT_FOUND ...` (exit 127, with
/// the confusing `command not found` message).
#[track_caller]
fn assert_detect_prefix_uses_echo_false(prefix: &str, label: &str) {
    assert!(
        prefix.contains("echo false"),
        "{label}: detect prefix must end with `echo false` so the outer \
         command exits cleanly when the binary is missing.\n  PREFIX: {prefix}"
    );
    assert!(
        prefix.contains(">&2"),
        "{label}: detect prefix must redirect the human-readable reason \
         to stderr.\n  PREFIX: {prefix}"
    );
    // Ensure no legacy `ERROR_X_NOT_FOUND` sentinel survives.
    assert!(
        !prefix.contains("ERROR_") || !prefix.contains("_NOT_FOUND"),
        "{label}: legacy ERROR_*_NOT_FOUND sentinel reintroduced.\n  PREFIX: {prefix}"
    );
}

// ---- detect-prefix shape --------------------------------------------------

#[test]
fn docker_detect_prefix_clean_failure() {
    assert_detect_prefix_uses_echo_false(&docker_detect_prefix(None), "docker_detect_prefix");
}

#[test]
fn docker_compose_detect_prefix_clean_failure() {
    assert_detect_prefix_uses_echo_false(
        &docker_compose_detect_prefix(None),
        "docker_compose_detect_prefix",
    );
}

#[test]
fn firewall_detect_clean_failure() {
    assert_detect_prefix_uses_echo_false(&firewall_detect(), "firewall_detect");
}

#[test]
fn kubectl_detect_prefix_clean_failure() {
    assert_detect_prefix_uses_echo_false(&kubectl_detect_prefix(None), "kubectl_detect_prefix");
}

#[test]
fn helm_detect_prefix_clean_failure() {
    assert_detect_prefix_uses_echo_false(&helm_detect_prefix(None), "helm_detect_prefix");
}

#[test]
fn pkg_detect_prefix_clean_failure() {
    assert_detect_prefix_uses_echo_false(&pkg_detect_prefix(None), "pkg_detect_prefix");
}

// ---- compound-command builders (LC_ALL prefix vulnerability) -------------

#[test]
fn firewall_status_compound_parses() {
    assert_runtime_form_parses(
        &FirewallCommandBuilder::build_status_command(None),
        "firewall_status auto-detect",
    );
    assert_runtime_form_parses(
        &FirewallCommandBuilder::build_status_command(Some("ufw")),
        "firewall_status ufw",
    );
}

#[test]
fn firewall_list_compound_parses() {
    assert_runtime_form_parses(
        &FirewallCommandBuilder::build_list_command(None, None),
        "firewall_list auto-detect",
    );
}

#[test]
fn firewall_allow_compound_parses() {
    validate_port("80").unwrap();
    let cmd = FirewallCommandBuilder::build_allow_command(None, "80", Some("tcp"), None).unwrap();
    assert_runtime_form_parses(&cmd, "firewall_allow auto-detect");
}

#[test]
fn firewall_deny_compound_parses() {
    let cmd = FirewallCommandBuilder::build_deny_command(None, "80", Some("tcp"), None).unwrap();
    assert_runtime_form_parses(&cmd, "firewall_deny auto-detect");
}

#[test]
fn pkg_update_compound_parses() {
    assert_runtime_form_parses(
        &PackageCommandBuilder::build_update_command(None, None),
        "pkg_update auto-detect",
    );
}

// ---- subshell-prefixed builders (sentinel vulnerability) -----------------

#[test]
fn docker_ps_subshell_parses() {
    assert_runtime_form_parses(
        &DockerCommandBuilder::build_ps_command(None, false, None, None),
        "docker_ps auto-detect",
    );
}

#[test]
fn kubectl_get_subshell_parses() {
    let cmd = KubernetesCommandBuilder::build_get_command(
        None, "pods", None, None, false, None, None, None, None, false, false, false, None,
    );
    assert_runtime_form_parses(&cmd, "kubectl_get auto-detect");
}

#[test]
fn pkg_list_subshell_parses() {
    assert_runtime_form_parses(
        &PackageCommandBuilder::build_list_command(None, None),
        "pkg_list auto-detect",
    );
}

// ---- simple builders smoke (regression coverage) -------------------------

#[test]
fn template_list_parses_and_yields_clean_table() {
    let cmd = TemplateCommandBuilder::build_template_list_command();
    assert_runtime_form_parses(&cmd, "template_list");
    // Run the command for real and feed its output through the columnar
    // parser to assert the header is preserved verbatim. Catches the
    // 'AILABLE' bug where a sentence header + indented rows misled the
    // fixed-width parser into chopping the first two characters.
    let out = Command::new("bash")
        .args(["-c", &cmd])
        .output()
        .expect("bash exec failed");
    assert!(out.status.success(), "template_list command failed");
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or_default();
    assert_eq!(first, "NAME", "first line must be the header `NAME`");
    assert!(
        !text.contains("AILABLE"),
        "template_list output regression: parser-truncated header detected"
    );
}
