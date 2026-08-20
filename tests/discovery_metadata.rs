//! Discovery-metadata drift guard.
//!
//! Every shippable manifest that carries a `version` MUST match the crate
//! version (`env!("CARGO_PKG_VERSION")`). The MCPB bundle (`make mcpb`) and the
//! release workflow package `server.json` + `dxt/manifest.json`, so drift here
//! ships a wrong version to the MCP registry / Claude Desktop. CI fails on drift.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// The crate version is the single source of truth.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn read_manifest(rel: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

#[test]
fn server_json_top_level_version_matches_crate() {
    let manifest = read_manifest("server.json");
    assert_eq!(
        manifest["version"], CRATE_VERSION,
        "server.json top-level version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}

#[test]
fn server_json_package_versions_match_crate() {
    let manifest = read_manifest("server.json");
    let packages = manifest["packages"]
        .as_array()
        .expect("server.json must have a packages array");
    for (i, pkg) in packages.iter().enumerate() {
        assert_eq!(
            pkg["version"], CRATE_VERSION,
            "server.json packages[{i}] version drifted from Cargo.toml ({CRATE_VERSION})"
        );
    }
}

#[test]
fn server_card_version_matches_crate() {
    let manifest = read_manifest(".well-known/mcp/server-card.json");
    assert_eq!(
        manifest["version"], CRATE_VERSION,
        "server-card.json version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}

#[test]
fn dxt_manifest_version_matches_crate() {
    let manifest = read_manifest("dxt/manifest.json");
    assert_eq!(
        manifest["version"], CRATE_VERSION,
        "dxt/manifest.json version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}

/// Extract every `"version": "..."` value that starts a line.
///
/// Deliberately mirrors the `VERSION_FIELD` regex in
/// `scripts/sync-server-json.py`, including its refusal to match `"dxt_version"`
/// (a quote must sit immediately before `version`). Used for Markdown, where
/// there is no JSON to parse.
fn line_version_fields(raw: &str) -> Vec<&str> {
    raw.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("\"version\"")?;
            let rest = rest.trim_start().strip_prefix(':')?.trim_start();
            rest.strip_prefix('"')?.split('"').next()
        })
        .collect()
}

#[test]
fn marketplace_plugin_version_matches_crate() {
    let manifest = read_manifest(".claude-plugin/marketplace.json");
    let plugins = manifest["plugins"]
        .as_array()
        .expect("marketplace.json must have a plugins array");
    let entry = plugins
        .iter()
        .find(|p| p["name"] == "bridge-mcp")
        .expect("marketplace.json must list a plugin named bridge-mcp");
    assert_eq!(
        entry["version"], CRATE_VERSION,
        "marketplace.json plugins[bridge-mcp].version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}

#[test]
fn plugin_manifest_version_matches_crate() {
    let manifest = read_manifest("plugin/.claude-plugin/plugin.json");
    assert_eq!(
        manifest["version"], CRATE_VERSION,
        "plugin/.claude-plugin/plugin.json version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}

/// `dxt/README.md` embeds a `manifest.json` example users copy-paste, so a stale
/// version there hands out a wrong number. It is Markdown, not JSON, so it gets
/// a line-level check — and the "exactly one" assertion is the same invariant
/// `sync_regex` enforces, so a second example can never be silently skipped by
/// either the syncer or this test.
#[test]
fn dxt_readme_example_version_matches_crate() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("dxt/README.md");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let found = line_version_fields(&raw);
    assert_eq!(
        found.len(),
        1,
        "dxt/README.md must carry exactly one \"version\" field (the manifest example), found {found:?}"
    );
    assert_eq!(
        found[0], CRATE_VERSION,
        "dxt/README.md manifest example version drifted from Cargo.toml ({CRATE_VERSION})"
    );
}
