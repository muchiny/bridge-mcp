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
