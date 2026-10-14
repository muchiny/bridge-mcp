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
            after.contains("[REDACTED]") || after.contains("[HIGH_ENTROPY_REDACTED]"),
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

/// A key name that carries the keyword inside the quotes must not hide its
/// value.
///
/// Which rows carry the regression, measured by running the `849234c`
/// sanitizer over this very table: every row whose key is PREFIXED and quoted
/// fails on the base, including `"db_password": S3cr3t!x` and the
/// `12345678` / `changeit` rows. The rows that pass on the base are the
/// exact-keyword ones (`password`, `credentials`, the two `secret` path rows)
/// and the three unquoted forms; they stay because the acceptance asks for
/// prefix / suffix / bare / quoted coverage. The keyword may be prefixed (`_`, camelCase, `-`, `.`); the closing
/// quote stays glued to it.
#[test]
fn prefixed_json_keys_are_redacted() {
    let s = sanitizer();
    let cases = [
        // bare keyword, as before
        (r#"{"password":"S3cr3t!x"}"#, "S3cr3t!x"),
        // `_` prefix, strong and weak keys
        (r#"{"db_password":"S3cr3t!x"}"#, "S3cr3t!x"),
        (r#"{"db_password": "S3cr3t!x"}"#, "S3cr3t!x"),
        (r#"{"admin_token":"S3cr3t!xyz"}"#, "S3cr3t!xyz"),
        (r#"{"api_secret":"S3cr3t!xyz"}"#, "S3cr3t!xyz"),
        // camelCase prefix: no separator. Strong family only — the weak
        // family needs a separator (see the unchanged table: `adminToken`).
        (r#"{"dbPassword":"S3cr3t!x"}"#, "S3cr3t!x"),
        (r#"{"rootPassword":"Zq8!vN3pLw0x"}"#, "Zq8!vN3pLw0x"),
        // base64 that starts with `/` has `+`/`=`: not a path, still masked
        (r#"{"db_password":"/a+b/c=="}"#, "/a+b/c=="),
        // the common defaults are masked under a prefixed key as under the exact
        // one: the prefixed gate REJECTS shapes, it does not demand a look
        (r#"{"db_password":"changeit"}"#, "changeit"),
        (r#"{"keystore_password":"changeit"}"#, "changeit"),
        (r#"{"db_password":"postgres"}"#, "postgres"),
        (r#"{"mysql_password":"hunter2"}"#, "hunter2"),
        (
            r#"{"db_password":"correcthorsebatterystaple"}"#,
            "correcthorsebatterystaple",
        ),
        (r#"{"dbPassword":"changeit"}"#, "changeit"),
        (r#"{"db_password":12345678}"#, "12345678"),
        // an unlisted root is masked: the safe direction of the path list
        (r#"{"db_password":"/data/x/y"}"#, "/data/x/y"),
        // a path-shaped secret is not spared by a path-shaped GUESS: the entropy
        // tier skips tokens starting with `/`, so only the key can mask these
        (
            r#"{"secret":"/K7MDENGbPxRfiCY/EXAMPLEKEY/abcdefghij"}"#,
            "EXAMPLEKEY",
        ),
        (
            r#"{"secret":"/aB3xZ9kQ/mN7pR2sT/vW5yU8iO1lK4jH6gF0dS"}"#,
            "vW5yU8iO1lK4",
        ),
        (
            r#"{"db_password":"/aB3xZ9kQ/mN7pR2sT/vW5yU8iO1lK4jH6gF0dS"}"#,
            "vW5yU8iO1lK4",
        ),
        // existing verdicts, unchanged: a weak exact key with a path value
        (r#"{"credentials":"/etc/creds"}"#, "/etc/creds"),
        // the exact keyword keeps its no-gate behaviour: any scalar goes
        (r#"{"password":12345678}"#, "12345678"),
        (r#"{"password":"/etc/x"}"#, "/etc/x"),
        // other separators
        (r#"{"x-api-key":"S3cr3t!xyz"}"#, "S3cr3t!xyz"),
        (r#"{"db.password":"S3cr3t!x"}"#, "S3cr3t!x"),
        // single-quoted
        ("{'db_password': 'S3cr3t!x'}", "S3cr3t!x"),
        // YAML flow / bare-after-quoted-key
        (r#""db_password": S3cr3t!x"#, "S3cr3t!x"),
        // unquoted forms, caught by the bare families
        ("db_password: S3cr3t!x", "S3cr3t!x"),
        ("db_password=S3cr3t!x", "S3cr3t!x"),
        ("dbPassword: S3cr3t!x", "S3cr3t!x"),
    ];
    for (input, secret) in cases {
        let out = s.sanitize(input);
        assert!(
            !out.contains(secret),
            "{input:?} must be redacted, got {out:?}"
        );
    }
    // The structure survives: still valid JSON, key kept.
    let out = s.sanitize(r#"{"db_password":"S3cr3t!x","host":"pi"}"#);
    let v = parse_json(&out, "prefixed key");
    assert_eq!(v["host"], "pi");
    assert!(v.get("db_password").is_some(), "key must be kept: {out}");
}

/// The other direction: a name that merely CONTAINS a keyword, or carries a
/// path / boolean / enum, is not a secret. The right anchor (closing quote
/// glued to the keyword) is what keeps these alone.
#[test]
fn prefixed_json_keys_left_alone_when_the_name_is_not_a_secret() {
    let s = sanitizer();
    let cases = [
        r#"{"secretName":"tls-cert"}"#,
        r#"{"secretKeyRef":{"name":"x"}}"#,
        r#"{"AccessKeyId":"AKIAxxxx"}"#,
        r#"{"key":"abc"}"#,
        r#"{"public_key":"ssh-ed25519 AAAA"}"#,
        r#"{"keyword":"nginx"}"#,
        r#"{"max_tokens":4096}"#,
        r#"{"summary_max_tokens":"2048"}"#,
        r#"{"vault_password_file":"/root/.vault_pass"}"#,
        r#"{"db_token":true}"#,
        // The prefixed strong form is gated by `plausible_shape`: a name that
        // only ENDS in the keyword says nothing about its value.
        r#"{"usePassword":true}"#,
        r#"{"MYSQL_ALLOW_EMPTY_PASSWORD":"yes"}"#,
        r#"{"OLDPWD":"/var/lib/rancher/k3s"}"#,
        r#"{"db_password":90}"#,
        r#"{"db_password":"/etc/gcp/sa.json"}"#,
        // the Docker / Kubernetes secret-file idiom: which file holds the
        // credential is what the operator reads
        r#"{"db_password":"/run/secrets/db_password"}"#,
        r#"{"db_password":"/media/usb/data"}"#,
        r#"{"db_password":"/lib/systemd/system"}"#,
        // The weak PREFIXED form refuses the same shapes (R-Z16: a surface
        // this change creates must not mask a path / boolean / number).
        r#"{"GOOGLE_APPLICATION_CREDENTIALS":"/etc/gcp/sa.json"}"#,
        r#"{"db_token":"/etc/x.pem"}"#,
        r#"{"db_secret":"C:\\sa.json"}"#,
        r#"{"admin_token":true}"#,
        r#"{"db_password":"\\fs01\share\p.txt"}"#,
        // The weak family's prefix needs a separator: short pagination cursors
        // are camelCase, and `existingSecret` names a Secret object. (A long
        // cursor such as `NextToken` is masked by the ENTROPY tier, at the
        // base too, so it cannot sit in this table.)
        r#"{"nextPageToken":"CgkIABDr1Zb2BRIf"}"#,
        r#"{"existingSecret":"redis-prod-01"}"#,
        // Documented non-coverage: camelCase weak key with a real secret.
        r#"{"adminToken":"S3cr3t!xyz"}"#,
        r#"{"admin_secret":{"a":1}}"#,
        // Suffixed names (keyword NOT last) are out of scope: the right anchor
        // is deliberately unchanged.
        r#"{"password_db":"S3cr3t!x"}"#,
        // Flag form `--password <value>`: no generic pattern, tracked as T66.
        "--password S3cr3t!x",
        "--db-password S3cr3t!x",
        "docker login -u me --password-stdin reg.example",
        // Escaped form: a JSON document nested in a JSON string, quotes
        // rendered `\"`. The backslash breaks the glued-quote anchor, for the
        // bare key as much as the prefixed one. Documented non-coverage,
        // tracked as T68 — these two lines go away when it is fixed.
        r#"{\"password\":\"S3cr3t!x\"}"#,
        r#"{\"db_password\":\"S3cr3t!x\"}"#,
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
        // The bracket alternative actually needs TWO characters inside (its
        // marker-shaped exclusion is a mandatory one-character leading
        // group, ahead of a `+` trailing class needing one more), unlike
        // brace and angle, which need only one — so a single character in
        // brackets is left alone too.
        "password=[x]",
        "password=[!]",
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

#[test]
fn padded_base64_secret_values_stay_valid_yaml() {
    let raw = "- apiVersion: v1\n  data:\n    admin.password: Q7xP2mZ9kL4vN8bT1wR6yH3jF5sD0aG2cV9nM4pX7qJ=\n    tls.key: Q7xP2mZ9kL4vN8bT1wR6yH3jF5sD0aG2cV9nM4pX7q==\n  kind: Secret\n";
    let out = sanitizer().sanitize(raw);
    assert_eq!(
        out.as_ref(),
        "- apiVersion: v1\n  data:\n    admin.password: [REDACTED]\n    tls.key: [HIGH_ENTROPY_REDACTED]\n  kind: Secret\n"
    );
    assert_only_values_changed(raw, &out);
    let parsed: serde_json::Value =
        bridge_mcp::domain::yaml::parse_yaml(&out).expect("sanitized YAML must parse");
    assert_eq!(parsed[0]["kind"], "Secret");
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

/// An operator pattern now applies to output that holds no built-in keyword
/// (the tier-1 gate used to skip it). A well-anchored pattern must leave a
/// JSON document parseable, because `jq_filter` re-parses the sanitized text
/// and a failure there is a hard tool error. Greedy patterns (a trailing `.*`
/// or `\S*`) swallow the closing quote and are warned against in the
/// CHANGELOG, not pinned here.
#[test]
fn an_anchored_operator_pattern_keeps_keyword_free_json_parseable() {
    let doc = r#"{"items":[{"name":"SA-1234","ready":true},{"name":"web","ready":false}]}"#;
    let s = Sanitizer::from_config(&SanitizeConfig {
        custom_patterns: vec![bridge_mcp::config::CustomSanitizePattern {
            pattern: r"SA-\d{4}".to_string(),
            replacement: "[SA]".to_string(),
            description: None,
        }],
        ..SanitizeConfig::default()
    });
    let out = s.sanitize(doc);
    assert!(!out.contains("SA-1234"), "the pattern must bite: {out}");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("must still parse");
    assert_eq!(parsed["items"][0]["name"], "[SA]");
}
