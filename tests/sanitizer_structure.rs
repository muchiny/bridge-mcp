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

/// Every line that differs between `raw` and `out` must keep everything up
/// to and including its separator, and differ only in the value.
fn assert_only_values_changed(raw: &str, out: &str) {
    assert_eq!(
        raw.lines().count(),
        out.lines().count(),
        "line count changed:\n{out}"
    );
    for (before, after) in raw.lines().zip(out.lines()) {
        if before == after {
            continue;
        }
        let split_at = |s: &str| s.find([':', '=']).map_or(0, |i| i + 1);
        let (bp, ap) = (&before[..split_at(before)], &after[..split_at(after)]);
        assert_eq!(bp, ap, "prefix changed:\n  - {before}\n  + {after}");
        assert!(
            after.contains("[REDACTED]"),
            "changed without a marker:\n  - {before}\n  + {after}"
        );
    }
}

#[test]
fn yaml_scalars_keep_their_separator_and_indentation() {
    let raw = "db:\n  host: pg\n  password: hunter2-Xy9\n  token: Z2hwX2FiYzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w\n  AWS_SESSION_TOKEN: FwoGZXIvYXdzEBYaDHc3RVhBTVBMRVRPS0VOEXAMPLE\n";
    let out = sanitizer().sanitize(raw);
    assert_eq!(
        out.as_ref(),
        "db:\n  host: pg\n  password: [REDACTED]\n  token: [REDACTED]\n  AWS_SESSION_TOKEN: [REDACTED]\n"
    );
    assert_only_values_changed(raw, &out);
}

#[test]
fn env_and_json_forms_keep_their_own_separator() {
    let s = sanitizer();
    assert_eq!(
        s.sanitize("PASSWORD=hunter2").as_ref(),
        "PASSWORD=[REDACTED]"
    );
    assert_eq!(
        s.sanitize("password = 'hunter2'").as_ref(),
        "password = \"[REDACTED]\""
    );
    assert_eq!(
        s.sanitize(r#"{"password": "hunter2"}"#).as_ref(),
        r#"{"password": "[REDACTED]"}"#
    );
    assert_eq!(
        s.sanitize("'password': 'hunter2'").as_ref(),
        "'password': \"[REDACTED]\""
    );
    assert_eq!(
        s.sanitize("aws_session_token: FwoGZXIvYXdzEBYaDHc3RVhBTVBMRVRPS0VOEXAMPLE")
            .as_ref(),
        "aws_session_token: [REDACTED]"
    );
    assert_eq!(
        s.sanitize("CONSUL_HTTP_TOKEN: b1f9c2d4-3e5a-4f6b-8c7d-9e0f1a2b3c4d")
            .as_ref(),
        "CONSUL_HTTP_TOKEN: [REDACTED]"
    );
}

#[test]
fn helm_template_fixture_stays_valid_yaml_after_redaction() {
    let raw = fixture("helm_template.yaml");
    let out = sanitizer().sanitize(&raw);
    assert_only_values_changed(&raw, &out);
    assert!(out.contains("  password: [REDACTED]\n"), "{out}");
    assert!(out.contains("  token: [REDACTED]\n"), "{out}");
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
        out.contains("  password: [REDACTED]"),
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

#[test]
fn brace_wrapped_scalars_are_redacted_but_structures_are_not() {
    let s = sanitizer();
    assert_eq!(
        s.sanitize("password={hunter2}").as_ref(),
        "password=[REDACTED]"
    );
    assert_eq!(
        s.sanitize("password=[hunter2]").as_ref(),
        "password=[REDACTED]"
    );
    assert_eq!(
        s.sanitize("password=[abc123def]").as_ref(),
        "password=[REDACTED]"
    );
    assert_eq!(
        s.sanitize("secret: {s3cr3t-V4lue_9}").as_ref(),
        "secret: [REDACTED]"
    );
    for untouched in [
        r#"{"password": {"nested": "x"}}"#,
        r#"{"password": ["a", "b"]}"#,
        "password: {",
        "credential: [1, 2]",
        "secret: {a: b}",
        "password=[REDACTED]",
        "token=[K3S_TOKEN_REDACTED]",
        // An empty brace/bracket pair is structure — an empty object or
        // array — not a value; scalar_value!()'s brace and bracket
        // alternatives both require at least one character inside.
        r#"{"password": {}}"#,
        r#"{"password": []}"#,
    ] {
        assert_eq!(s.sanitize(untouched).as_ref(), untouched, "{untouched:?}");
    }
}

/// Ruling 19: an angle-wrapped scalar is a value (`<hunter2>`, the way
/// `{hunter2}` already was), but a placeholder — prose with a space, a quote
/// or a colon inside the angle brackets — is not, so `kubectl describe`'s
/// `<set to the key 'auth' in secret 'argocd-redis'>` and its shorter
/// cousins (`<none>`, `<nil>`, `<unset>`, `<invalid>`) stay untouched.
#[test]
fn angle_wrapped_scalars_are_redacted_but_placeholders_are_not() {
    let s = sanitizer();
    assert_eq!(
        s.sanitize("password: <hunter2>").as_ref(),
        "password: [REDACTED]"
    );
    assert_eq!(
        s.sanitize("password=<s3cr3t-V4lue_9>").as_ref(),
        "password=[REDACTED]"
    );
    for untouched in [
        "token: <none>",
        "secret: <nil>",
        "      REDIS_PASSWORD:   <set to the key 'auth' in secret 'argocd-redis'>   Optional: false",
        // An empty angle pair is structure — a placeholder with nothing in
        // it — not a value; the angle alternative requires at least one
        // character inside, same as the brace and bracket alternatives.
        "password=<>",
    ] {
        assert_eq!(s.sanitize(untouched).as_ref(), untouched, "{untouched:?}");
    }
}

/// Regressions found by the differential audit of real host output
/// (`scripts/live_probe/corpus.py` against `raspberry`), one input/expected
/// pair per pattern line in `corpus_regressions.txt`. A missing fixture file
/// makes this a no-op rather than a failure, since it is committed only when
/// the audit finds something.
#[test]
fn corpus_regressions_hold() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sanitizer/corpus_regressions.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let s = sanitizer();
    let mut lines = text.lines().peekable();
    while let Some(input) = lines.next() {
        let expected = lines
            .next()
            .and_then(|l| l.strip_prefix("=> "))
            .unwrap_or_else(|| panic!("missing `=> ` line after {input:?}"));
        assert_eq!(
            s.sanitize(input).as_ref(),
            expected,
            "corpus regression for {input:?}"
        );
    }
}
