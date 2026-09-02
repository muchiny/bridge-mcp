#![no_main]

use bridge_mcp::config::{HostKeyVerification, OsType, Protocol, ShellType};
use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::HostConfig;
use libfuzzer_sys::fuzz_target;

// The old target called `serde_saphyr::from_str::<HostConfig>` BARE and then
// `serde_json::from_slice`, asserting nothing beyond "did not panic".
//
// Both halves were wrong. The bare call skips `hardened_options()`, so it
// exercised a parser with none of production's caps — 1 MiB input, 100 anchors,
// 1 000 aliases, depth 50, 10 000 nodes, `with_snippet: false`. And the JSON
// half tested a door that does not exist: a host config is read from a YAML
// file and from nowhere else, so a JSON parse of these bytes measures
// `serde_json` and nothing about this crate.
//
// What a host config decides is whether the bridge trusts a remote host. The
// two properties below are the ones a wrong answer would silently weaken.
fuzz_target!(|data: &str| {
    let Ok(host) = parse_yaml::<HostConfig>(data) else {
        return;
    };

    // Read back what the DOCUMENT carried, through the same parser, rather than
    // hunting for keys in the text. `serde_json::Value` is only the shape the
    // answer arrives in; the reading is saphyr's, so it cannot disagree with
    // the parse above about what a key is.
    let Ok(serde_json::Value::Object(written)) = parse_yaml::<serde_json::Value>(data) else {
        // A YAML mapping with a non-string key has no `serde_json::Value` form.
        // The HostConfig parse above still succeeded, so this is a document
        // this target cannot read — not a defect.
        return;
    };

    // Half A — an omitted security key holds its CLOSED default.
    //
    // Every one of these defaults is the restrictive choice, and each is
    // reached by `#[serde(default)]` rather than being written anywhere. A
    // derive attribute quietly changing — a `default` added to a field that had
    // none, an enum's `#[default]` moving to another variant — turns "the
    // operator did not say" into "the operator said yes", and nothing else in
    // the test suite would notice.
    if !written.contains_key("host_key_verification") {
        assert_eq!(
            host.host_key_verification,
            HostKeyVerification::Strict,
            "an unspecified host key policy must reject unknown hosts, not accept them: {data:?}"
        );
    }
    if !written.contains_key("protocol") {
        assert_eq!(
            host.protocol,
            Protocol::Ssh,
            "an unspecified protocol must be SSH: {data:?}"
        );
    }
    if !written.contains_key("port") {
        assert_eq!(host.port, 22, "an unspecified port must be 22: {data:?}");
    }
    if !written.contains_key("shell") {
        // Not a constant: the closed answer here is the one INFERRED from
        // `os_type`, and asserting a fixed `Posix` would be red on any Windows
        // host config.
        let inferred = match host.os_type {
            OsType::Linux => ShellType::Posix,
            OsType::Windows => ShellType::Cmd,
        };
        assert_eq!(
            host.effective_shell(),
            inferred,
            "an unspecified shell must follow os_type: {data:?}"
        );
    }
    if !written.contains_key("sudo_password") {
        assert!(
            host.sudo_password.is_none(),
            "a sudo password nobody wrote must not exist: {data:?}"
        );
    }
    if !written.contains_key("proxy_jump") {
        assert!(
            host.proxy_jump.is_none(),
            "a jump host nobody wrote must not exist: {data:?}"
        );
    }

    // Half B — a key `auth` does not declare is REFUSED, not swallowed.
    //
    // Before #171, `auth: {type: key, path: ..., passphraze: X}` loaded without
    // a word: serde IGNORES the unrecognised by default, while every other
    // struct in `config/types.rs` refuses it. The operator learned about the
    // typo from `SshKeyInvalid`, an error accusing the key file — so a
    // passphrase that was never applied looked like a broken key.
    //
    // The extra key is taken from the fuzzed bytes and the document is built
    // with `serde_json`, so the key name is escaped and cannot break out of its
    // position however hostile it is. JSON is valid YAML 1.2, so `parse_yaml`
    // reads it as the mapping it looks like.
    const DECLARED: &[&str] = &[
        "type",
        "path",
        "passphrase",
        "password",
        "domain",
        "cert_path",
        "key_path",
    ];
    let surplus = data.trim();
    if surplus.is_empty() || DECLARED.contains(&surplus) {
        return;
    }
    // A STRUCT variant deliberately. `deny_unknown_fields` on an internally
    // tagged enum reaches struct variants only: `Agent` and `Kerberos` are unit
    // variants and still accept surplus keys, which would take declaring them
    // as `Agent {}` and breaking every existing YAML. Asserting refusal for
    // `agent` would be red on healthy code.
    let document = serde_json::json!({
        "hostname": "e.internal",
        "user": "u",
        "auth": { "type": "password", "password": "p", surplus: "x" },
    })
    .to_string();

    assert!(
        parse_yaml::<HostConfig>(&document).is_err(),
        "`auth` accepted the undeclared key {surplus:?} and dropped it silently. \
         That is how a mistyped `passphrase` became an unexplained SshKeyInvalid: \
         the value was never applied and nothing said so.\n  document: {document}"
    );
});
