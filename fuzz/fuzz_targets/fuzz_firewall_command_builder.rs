#![no_main]

use bridge_mcp::domain::use_cases::firewall::{
    FirewallCommandBuilder, validate_port, validate_source,
};
use bridge_mcp_fuzz::{assert_same_shell_skeleton, shell_shape};
use libfuzzer_sys::fuzz_target;

// Every call in this target used to be `let _ = ...`, so it noticed a panic
// and nothing else — and a firewall builder that pasted `; rm -rf /` into a
// rule would not panic.
//
// Three properties. The `firewall_tool` selector must only ever CHOOSE among
// constants; `chain`, which has no validator at all, must not be able to add
// syntax; and a port or source the validators ACCEPTED must reach the rule
// intact, in one piece.
fuzz_target!(|data: (&str, &str, &str)| {
    let (tool, port, value) = data;

    // ── the tool selector chooses, it never interpolates ──────────────
    for (name, built) in [
        ("status", FirewallCommandBuilder::build_status_command(Some(tool))),
        ("list", FirewallCommandBuilder::build_list_command(Some(tool), None)),
    ] {
        let known = matches!(tool, "ufw" | "firewall-cmd" | "iptables");
        if !known {
            // An unknown tool must fall to the detection script, byte for byte
            // identical to what `None` produces — not to a command carrying
            // the caller's text.
            let fallback = match name {
                "status" => FirewallCommandBuilder::build_status_command(None),
                _ => FirewallCommandBuilder::build_list_command(None, None),
            };
            assert_eq!(
                built, fallback,
                "{name}: an unknown tool {tool:?} must select the detection script"
            );
        }
        assert!(
            shell_shape(&built).is_some(),
            "{name}: emitted an unscannable command: {built:?}"
        );
    }

    // ── `chain` has no validator; it must still contribute no syntax ──
    assert_same_shell_skeleton(
        &FirewallCommandBuilder::build_list_command(Some("iptables"), Some("INPUT")),
        &FirewallCommandBuilder::build_list_command(Some("iptables"), Some(value)),
        "list chain",
    );

    // ── an accepted rule reaches the firewall intact ──────────────────
    let port_ok = validate_port(port).is_ok();
    let source_ok = validate_source(value).is_ok();

    for (name, built) in [
        (
            "allow",
            FirewallCommandBuilder::build_allow_command(Some("ufw"), port, Some("tcp"), Some(value)),
        ),
        (
            "deny",
            FirewallCommandBuilder::build_deny_command(
                Some("iptables"),
                port,
                Some("tcp"),
                Some(value),
            ),
        ),
    ] {
        // The builder's verdict is the AND of the two validators, and nothing
        // else: it must not accept what they reject, nor reject what they
        // accept.
        assert_eq!(
            built.is_ok(),
            port_ok && source_ok,
            "{name}: builder disagrees with the validators \
             (port {port:?} ok={port_ok}, source {value:?} ok={source_ok})"
        );

        let Ok(cmd) = built else { continue };
        let shape = shell_shape(&cmd)
            .unwrap_or_else(|| panic!("{name}: emitted an unscannable rule: {cmd:?}"));
        for (what, wanted) in [("port", port), ("source", value)] {
            assert!(
                shape.literals.iter().any(|l| l == wanted),
                "{name}: {what} {wanted:?} did not reach the rule intact; \
                 literals {:?} from {cmd:?}",
                shape.literals
            );
        }
    }
});
