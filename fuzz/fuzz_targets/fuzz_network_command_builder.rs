#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::network::{validate_network_target, NetworkCommandBuilder};

fuzz_target!(|data: &str| {
    // validator
    let _ = validate_network_target(data);

    // connections
    let _ = NetworkCommandBuilder::build_connections_command(Some(data), Some(data), true);

    // interfaces
    let _ = NetworkCommandBuilder::build_interfaces_command(Some(data));

    // routes
    let _ = NetworkCommandBuilder::build_routes_command(Some(data));

    // ping (may fail validation)
    let _ = NetworkCommandBuilder::build_ping_command(data, Some(4), Some(5), Some(data));

    // traceroute (may fail validation)
    let _ = NetworkCommandBuilder::build_traceroute_command(data, Some(15), Some(3));

    // dns (may fail validation)
    let _ = NetworkCommandBuilder::build_dns_command(data, Some(data), Some(data), true);
});
