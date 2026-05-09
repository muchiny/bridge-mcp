//! Verifies our central `parse_yaml` helper enforces a Budget.
//!
//! Covers FIND-001/002/004/032 — we centralize all production YAML parsing
//! through `crate::domain::yaml::parse_yaml` so anti-DoS caps (anchors,
//! depth, nodes, input bytes) cannot be forgotten at any individual call
//! site.

use mcp_ssh_bridge::domain::yaml::parse_yaml;
use serde_json::Value;

const BILLION_LAUGHS: &str = r#"
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
"#;

#[test]
fn billion_laughs_blocked_by_budget() {
    let out: Result<Value, _> = parse_yaml(BILLION_LAUGHS);
    assert!(out.is_err(), "billion-laughs MUST fail with budget");
}

#[test]
fn deep_nesting_blocked() {
    let mut yaml = String::new();
    for _ in 0..200 {
        yaml.push_str("a:\n  ");
    }
    yaml.push_str("v: 1\n");
    let out: Result<Value, _> = parse_yaml(&yaml);
    assert!(out.is_err(), "200-deep nesting MUST fail");
}

#[test]
fn small_input_passes() {
    let yaml = "name: hello\nversion: 1";
    let out: Result<Value, _> = parse_yaml(yaml);
    assert!(out.is_ok());
}
