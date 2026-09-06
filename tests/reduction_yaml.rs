//! The reduction pipeline must hand a YAML document back as YAML, run yq on
//! multi-document streams, and honour `limit` with and without a filter.
//! Every case is a shape the 2026-09-06 live probe on the Raspberry Pi saw broken.

#![cfg(feature = "jq")]

use std::path::Path;

use bridge_mcp::domain::data_reduction::DataReductionArgs;
use bridge_mcp::domain::output_kind::OutputKind;
use bridge_mcp::mcp::standard_tool::apply_reduction;

fn fixture(dir: &str, name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn args(v: serde_json::Value) -> DataReductionArgs {
    let mut v = v;
    DataReductionArgs::extract(&mut v).expect("reduction args")
}

#[test]
fn yaml_with_no_reduction_param_is_untouched() {
    let raw = fixture("reduction", "kubectl_ns.yaml");
    let mut out = raw.clone();
    assert!(!apply_reduction(&mut out, &args(serde_json::json!({})), OutputKind::Auto).unwrap());
    assert_eq!(out, raw);
}

#[test]
fn yaml_with_limit_only_is_untouched_on_auto() {
    let raw = fixture("reduction", "kubectl_ns.yaml");
    let mut out = raw.clone();
    apply_reduction(
        &mut out,
        &args(serde_json::json!({"limit": 3})),
        OutputKind::Auto,
    )
    .unwrap();
    assert_eq!(
        out, raw,
        "a plain mapping has nothing to cap and must never become TSV"
    );
}

#[test]
fn yaml_stream_yq_lists_every_document_and_limit_caps_it() {
    let raw = fixture("sanitizer", "helm_template.yaml");
    let mut out = raw.clone();
    assert!(
        apply_reduction(
            &mut out,
            &args(serde_json::json!({"yq_filter": ".kind", "output_format": "tsv"})),
            OutputKind::Yaml
        )
        .unwrap()
    );
    assert_eq!(out, "Secret\nDeployment");
    let mut out = raw.clone();
    apply_reduction(
        &mut out,
        &args(serde_json::json!({"yq_filter": ".kind", "output_format": "tsv", "limit": 1})),
        OutputKind::Yaml,
    )
    .unwrap();
    assert_eq!(out, "Secret");
    let mut out = raw;
    apply_reduction(
        &mut out,
        &args(serde_json::json!({"limit": 1})),
        OutputKind::Yaml,
    )
    .unwrap();
    assert!(
        out.contains("kind: Secret") && !out.contains("kind: Deployment"),
        "{out}"
    );
}

#[test]
fn json_jq_then_limit_returns_exactly_limit_rows() {
    let mut out = r#"{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}},{"metadata":{"name":"c"}}]}"#.to_string();
    apply_reduction(
        &mut out,
        &args(serde_json::json!({"jq_filter": ".items[].metadata.name", "limit": 2})),
        OutputKind::Auto,
    )
    .unwrap();
    assert_eq!(out.lines().count(), 2, "{out}");
}
