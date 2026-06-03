#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::tunnel::{TunnelDirection, TunnelInfo, TunnelManager};
use std::time::Instant;

fuzz_target!(|data: (u8, u16, u16, &str)| {
    let (max_tunnels_raw, local_port, remote_port, host_data) = data;

    // Create a tunnel manager with a bounded capacity (1..=50)
    let max_tunnels = (max_tunnels_raw % 50) as usize + 1;
    let manager = TunnelManager::new(max_tunnels);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        // Try to register a tunnel with fuzzed data
        let info = TunnelInfo {
            id: format!("tunnel-{host_data}-{local_port}-{remote_port}"),
            host: host_data.to_string(),
            local_port,
            remote_host: "127.0.0.1".to_string(),
            remote_port,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };

        // Spawn a trivial task as the tunnel handle
        let handle = tokio::spawn(async {});

        let tunnel_id = info.id.clone();
        let result = manager.register(info, handle).await;

        // Invariant: registration should succeed if under max
        if result.is_ok() {
            // Listing should contain our tunnel
            let tunnels = manager.list().await;
            assert!(!tunnels.is_empty(), "Must have at least one tunnel after register");

            // Closing should succeed for our tunnel
            let close_result = manager.close(&tunnel_id).await;
            assert!(close_result.is_ok(), "Close of registered tunnel must succeed");

            // After close, listing should be empty
            let tunnels = manager.list().await;
            assert!(tunnels.is_empty(), "Must be empty after closing all");
        }

        // Closing a non-existent tunnel should fail
        let close_result = manager.close("nonexistent-tunnel-id").await;
        assert!(close_result.is_err(), "Close of unknown tunnel must fail");
    });
});
