#![no_main]

use bridge_mcp::domain::use_cases::network::{
    NetworkCommandBuilder, validate_network_target,
};
use bridge_mcp_fuzz::{assert_survives_as_one_word, shell_words};
use libfuzzer_sys::fuzz_target;

// This target used to call every builder and throw the result away, so it saw
// a panic and nothing else. What these builders owe their callers is not the
// absence of a panic — it is that the value handed in is the value the remote
// program receives, as one word, in the slot it was meant for.
//
// Three properties, kept apart on purpose:
//
//  1. A selector picks a constant from a closed table. `protocol` and `family`
//     never reach the command line at all, so a hostile one must change
//     nothing.
//  2. An interpolated value survives as exactly one word, byte-identical.
//  3. Each builder agrees with `validate_network_target` SEPARATELY. Comparing
//     the validator against `ping.is_ok() && trace.is_ok() && dns.is_ok()` is
//     blind to the mutation that matters: drop the validator from ONE builder
//     and the conjunction stays false on a rejected target, because the other
//     two still return Err.
fuzz_target!(|data: (&str, &str, &str, bool)| {
    let (target, value, selector, listening) = data;

    // ── 1. selectors choose, they do not interpolate ──────────────────
    let expected_flag = match (selector, listening) {
        ("tcp", true) => "-tlnp",
        ("tcp", false) => "-tnap",
        ("udp", true) => "-ulnp",
        ("udp", false) => "-unap",
        (_, true) => "-tlnp",
        (_, false) => "-tunap",
    };
    let conn =
        NetworkCommandBuilder::build_connections_command(Some(selector), Some(value), listening);
    let Some(words) = shell_words(&conn) else {
        panic!("connections: protocol {selector:?} / state {value:?} produced shell syntax: {conn:?}");
    };
    assert_eq!(
        words,
        vec![
            "ss".to_string(),
            expected_flag.to_string(),
            "state".to_string(),
            value.to_string(),
        ],
        "connections: protocol {selector:?} / state {value:?} produced {conn:?}"
    );

    let routes = NetworkCommandBuilder::build_routes_command(Some(selector));
    let expected_routes = if matches!(selector, "6" | "ipv6") {
        "ip -6 route show"
    } else {
        "ip route show"
    };
    assert_eq!(
        routes, expected_routes,
        "routes: family {selector:?} must select a constant, never reach the command line"
    );

    // ── 2. an accepted interface survives whole ───────────────────────
    match NetworkCommandBuilder::build_interfaces_command(Some(value)) {
        Ok(cmd) => assert_survives_as_one_word(&cmd, value, "interfaces"),
        Err(_) => {} // refused is a fine answer; only acceptance makes a claim
    }

    // ── 3. every builder agrees with the validator, one by one ────────
    let accepted = validate_network_target(target).is_ok();
    let ping = NetworkCommandBuilder::build_ping_command(target, Some(4), Some(5), None);
    let trace = NetworkCommandBuilder::build_traceroute_command(target, Some(15), Some(3));
    let dns = NetworkCommandBuilder::build_dns_command(target, None, None, true);

    for (name, built) in [
        ("ping", ping.is_ok()),
        ("traceroute", trace.is_ok()),
        ("dig", dns.is_ok()),
    ] {
        assert_eq!(
            accepted, built,
            "target {target:?}: {name} disagrees with validate_network_target \
             (validator accepted={accepted}, builder built={built})"
        );
    }

    let (Ok(ping), Ok(trace), Ok(dns)) = (ping, trace, dns) else {
        return; // refused: nothing was built, nothing left to check
    };

    // An accepted target is documented as a hostname or an IP. A word starting
    // with `-` is neither: it lands in operand position and the program reads
    // it as an option instead — `dig -f/etc/passwd` turns a read-only lookup
    // into a file read, and shell-escaping does not help, because the escape
    // only decides where the word ends.
    assert!(
        !target.starts_with('-'),
        "target {target:?} was ACCEPTED but is an option, not a host; built: {dns:?}"
    );

    assert_survives_as_one_word(&ping, target, "ping target");
    assert_survives_as_one_word(&trace, target, "traceroute target");
    assert_survives_as_one_word(&dns, target, "dig domain");
});
