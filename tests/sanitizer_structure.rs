//! The sanitizer must redact values without destroying the structure that
//! carries them. Every fixture here is a real output shape that the 2026-09-05
//! live sweep saw corrupted (`"secret": {` in kubectl JSON, `secret:` block
//! keys in kubectl YAML, `summary_fields.credentials` in AWX, `Credentials`
//! in `aws sts`).

use std::path::Path;

use bridge_mcp::config::SanitizeConfig;
use bridge_mcp::security::Sanitizer;

fn sanitizer() -> Sanitizer {
    Sanitizer::from_config(&SanitizeConfig::default())
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sanitizer")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn parse_json(text: &str, what: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{what} is not valid JSON: {e}\n{text}"))
}

#[test]
fn kubectl_pods_json_keeps_structure_and_non_secret_leaves() {
    let raw = fixture("kubectl_pods_secret_volume.json");
    let before = parse_json(&raw, "fixture");
    let out = sanitizer().sanitize(&raw);
    let after = parse_json(&out, "sanitized kubectl JSON");
    assert_eq!(
        before, after,
        "kubectl pods JSON carries no secret value; sanitizing must not change a leaf"
    );
}

#[test]
fn awx_job_json_keeps_credential_id_and_credentials_array() {
    let raw = fixture("awx_job.json");
    let out = sanitizer().sanitize(&raw);
    let after = parse_json(&out, "sanitized AWX JSON");
    assert_eq!(after["credential"], 5, "a credential ID is not a secret");
    assert_eq!(
        after["summary_fields"]["credentials"][0]["name"],
        "deploy-key"
    );
    assert_eq!(after["extra_vars"], "{\"release\": \"1.4.2\"}");
}

#[test]
fn aws_sts_json_redacts_secret_values_but_stays_json() {
    let raw = fixture("aws_sts.json");
    let out = sanitizer().sanitize(&raw);
    let after = parse_json(&out, "sanitized aws sts JSON");
    assert_eq!(after["Credentials"]["Expiration"], "2026-09-05T18:00:00Z");
    assert_eq!(
        after["AssumedRoleUser"]["Arn"],
        "arn:aws:sts::123456789012:assumed-role/deploy/session"
    );
    let secret = after["Credentials"]["SecretAccessKey"]
        .as_str()
        .expect("SecretAccessKey stays a string");
    assert!(
        !secret.contains("wJalrXUtnFEMI"),
        "SecretAccessKey must be redacted, got {secret}"
    );
}

#[test]
fn kubectl_pod_yaml_block_key_is_untouched() {
    let raw = fixture("kubectl_pod_secret_volume.yaml");
    let out = sanitizer().sanitize(&raw);
    assert_eq!(
        out.as_ref(),
        raw,
        "kubectl pod YAML carries no secret value; sanitizing must be a no-op"
    );
}

#[test]
fn helm_template_yaml_redacts_scalars_and_keeps_block_keys() {
    let raw = fixture("helm_template.yaml");
    let out = sanitizer().sanitize(&raw);
    assert_eq!(
        out.lines().count(),
        raw.lines().count(),
        "line-local redaction must never merge lines"
    );
    assert!(
        out.contains("  password: [REDACTED]") || out.contains("  password=[REDACTED]"),
        "stringData.password must be redacted: {out}"
    );
    assert!(!out.contains("hunter2-Xy9"));
    assert!(
        !out.contains("Z2hwX2FiYzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w"),
        "data.token must be redacted"
    );
    assert!(
        out.contains("        secret:\n          secretName: app-db"),
        "a block key followed by its mapping must be left alone: {out}"
    );
}

#[test]
fn text_lines_true_positives_still_redacted() {
    let s = sanitizer();
    let cases = [
        ("password=hunter2", "hunter2"),
        ("password: hunter2", "hunter2"),
        ("\"password\": \"hunter2\"", "hunter2"),
        ("secret=s3cr3t-V4lue_9", "s3cr3t-V4lue_9"),
        ("api_key=AKxq81mZp0Lw4Rt", "AKxq81mZp0Lw4Rt"),
        (
            "credential: ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "ghp_16C7",
        ),
    ];
    for (input, secret) in cases {
        let out = s.sanitize(input);
        assert!(
            !out.contains(secret),
            "{input:?} must be redacted, got {out:?}"
        );
    }
}

#[test]
fn text_lines_false_positives_left_alone() {
    let s = sanitizer();
    let cases = [
        "\"secret\": {",
        "\"credentials\": [",
        "\"credential\": 5,",
        "\"token\": true",
        "secret:\n  secretName: tls",
        "credential:\n  name: deploy-key",
        "secretName: argocd-repo-server-tls",
        "imagePullSecrets: [regcred]",
        "token: enabled",
    ];
    for input in cases {
        let out = s.sanitize(input);
        assert_eq!(out.as_ref(), input, "{input:?} must not be touched");
    }
}
