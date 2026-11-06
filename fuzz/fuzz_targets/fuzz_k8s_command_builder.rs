#![no_main]

use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::KubernetesCommandBuilder;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "the program name"))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder ACCEPTED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. Refusal
// is always fine; the fuzzer is looking for values that get THROUGH.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_k8s_command_builder -- -dict=fuzz/dicts/shell.dict`

/// Oracle for one element of `--address`, written WITHOUT `is_loopback_host`,
/// `to_canonical` or `is_loopback`: exactly `localhost` (lower case, as
/// `client-go` `parseAddresses` compares it), an `IPv4` address whose first
/// octet is 127, `::1`, or `::ffff:127.x.y.z`, the last two read from the
/// parsed segments. Anything else, `LOCALHOST` included, is not loopback.
fn oracle_loopback_element(element: &str) -> bool {
    if element == "localhost" {
        return true;
    }
    if let Ok(v4) = element.parse::<std::net::Ipv4Addr>() {
        return v4.octets().first() == Some(&127);
    }
    if let Ok(v6) = element.parse::<std::net::Ipv6Addr>() {
        return match v6.segments() {
            [0, 0, 0, 0, 0, 0, 0, 1] => true,
            [0, 0, 0, 0, 0, 0xffff, high, _] => high >> 8 == 127,
            _ => false,
        };
    }
    false
}

fuzz_target!(|data: &str| {
    // Fuzz 12 KubernetesCommandBuilder entry points with arbitrary strings.
    // Invariant: output must always contain the kubectl detection prefix
    // and must never panic.

    // 1. build_get_command
    let cmd = KubernetesCommandBuilder::build_get_command(
        Some("kubectl"),
        data,         // resource
        Some(data),   // name
        Some(data),   // namespace
        true,         // all_namespaces
        Some(data),   // label_selector
        Some(data),   // field_selector
        Some(data),   // output
        Some(data),   // sort_by
        false,        // raw
        false,        // show_labels
        false,        // show_kind
        None,         // chunk_size
    );
    assert_arrives_as_text(&cmd, data, "get");

    // 2. build_logs_command
    let cmd = KubernetesCommandBuilder::build_logs_command(
        Some("kubectl"),
        data,         // pod
        Some(data),   // namespace
        Some(data),   // container
        Some(100),    // tail
        Some(data),   // since
        true,         // previous
        true,         // timestamps
        None,         // label_selector
        false,        // all_containers
        None,         // max_log_requests
        false,        // prefix
        None,         // since_time
    );
    assert_arrives_as_text(&cmd, data, "logs");

    // 3. build_describe_command
    let cmd = KubernetesCommandBuilder::build_describe_command(
        Some("kubectl"),
        data,       // resource
        Some(data), // name
        Some(data), // namespace
        None,       // label_selector
        false,      // all_namespaces
    );
    assert_arrives_as_text(&cmd, data, "describe");

    // 4. build_apply_command
    let cmd = KubernetesCommandBuilder::build_apply_command(
        Some("kubectl"),
        data,       // manifest
        Some(data), // namespace
        Some(data), // dry_run
        true,       // force
        true,       // server_side
    );
    assert_arrives_as_text(&cmd, data, "apply");

    // 5. build_delete_command
    let cmd = KubernetesCommandBuilder::build_delete_command(
        Some("kubectl"),
        data,       // resource
        Some(data), // name
        Some(data), // namespace
        Some(30),   // grace_period
        true,       // force
        Some(data), // dry_run
        None,       // label_selector
        false,      // all
        None,       // field_selector
    );
    assert_arrives_as_text(&cmd, data, "delete");

    // 6. build_rollout_command
    let cmd = KubernetesCommandBuilder::build_rollout_command(
        Some("kubectl"),
        data,       // action
        data,       // resource
        Some(data), // namespace
        Some(5),    // to_revision
        None,       // watch
        None,       // timeout
        None,       // label_selector
    );
    assert_arrives_as_text(&cmd, data, "rollout");

    // 7. build_scale_command
    let cmd = KubernetesCommandBuilder::build_scale_command(
        Some("kubectl"),
        data,       // resource
        3,          // replicas
        Some(data), // namespace
    );
    assert_arrives_as_text(&cmd, data, "scale");

    // 8. build_exec_command
    let cmd = KubernetesCommandBuilder::build_exec_command(
        Some("kubectl"),
        data,       // pod
        Some(data), // command
        Some(data), // namespace
        Some(data), // container
        None,       // argv
        false,      // stdin
    );
    assert_arrives_as_text(&cmd, data, "exec");

    // 9. build_top_command
    let cmd = KubernetesCommandBuilder::build_top_command(
        Some("kubectl"),
        data,       // resource_type
        Some(data), // namespace
        true,       // all_namespaces
        Some(data), // sort_by
        true,       // containers
    );
    assert_arrives_as_text(&cmd, data, "top");

    // 10. build_port_forward_command: the value reaches the command as text,
    // and the probe `curl` never reads the host's `~/.curlrc`.
    if let Ok(cmd) = KubernetesCommandBuilder::build_port_forward_command(
        Some("kubectl"),
        "svc/web",
        "8080:80",
        Some(data),   // probe_path
        5,
        Some(data),   // namespace
        None,
        Some(data),   // context
    ) {
        assert_arrives_as_text(&cmd, data, "port_forward");
        assert!(cmd.contains(" curl -q -sS -m 5 "), "probe curl without -q: {cmd:?}");
        assert!(!cmd.contains(" curl -sS"), "probe curl without -q: {cmd:?}");
    }

    // 11. `address` (kubectl port-forward --address) is accepted if and only
    // if it is a non-empty comma list of loopback hosts. The oracle
    // (`oracle_loopback_element`) shares no code with `is_loopback_host`: it
    // compares the exact string `localhost` and reads the parsed octets or
    // segments, so a drift in either fails here. `Ipv4Addr`/`Ipv6Addr`
    // parsing is the one thing both sides rely on.
    let loopback_list = !data.is_empty() && data.split(',').all(oracle_loopback_element);
    let result = KubernetesCommandBuilder::build_port_forward_command(
        Some("kubectl"),
        "svc/web",
        "8080:80",
        Some("/healthz"),
        5,
        None,
        Some(data),   // address
        None,
    );
    assert_eq!(
        result.is_ok(),
        loopback_list,
        "address {data:?}: accepted={} but loopback list={loopback_list}",
        result.is_ok()
    );
    if let Ok(cmd) = result {
        assert_arrives_as_text(&cmd, data, "port_forward address");
    }

    // 12. build_traefik_introspect_command: same two properties.
    if let Ok(cmd) = KubernetesCommandBuilder::build_traefik_introspect_command(
        Some("kubectl"),
        data,         // api_path
        Some(data),   // namespace
        8080,
        5,
        Some(data),   // context
    ) {
        assert_arrives_as_text(&cmd, data, "traefik_introspect");
        assert!(cmd.contains(" curl -q -sS -m 8 "), "curl without -q: {cmd:?}");
        assert!(!cmd.contains(" curl -sS"), "curl without -q: {cmd:?}");
    }

    // Also test with auto-detect (None kubectl_bin)
    let cmd = KubernetesCommandBuilder::build_get_command(
        None, data, None, None, false, None, None, None, None, false, false, false, None,
    );
    assert_arrives_as_text(&cmd, data, "auto-detect");
});
