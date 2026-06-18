#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::{AuditEvent, CommandResult};

fuzz_target!(|data: (&str, &str, u32, u64)| {
    let (host, command, exit_code, duration_ms) = data;

    // Create audit events with arbitrary data
    let event_success = AuditEvent::new(
        host,
        command,
        CommandResult::Success { exit_code, duration_ms },
    );
    let event_error = AuditEvent::new(
        host,
        command,
        CommandResult::Error { message: command.to_string() },
    );
    let event_denied = AuditEvent::denied(host, command, "test reason");

    // Serialize events - should never panic
    let _ = serde_json::to_string(&event_success);
    let _ = serde_json::to_string(&event_error);
    let _ = serde_json::to_string(&event_denied);

    // Invariants:
    // 1. Serialization should never panic
    // 2. Result should be valid JSON (if Ok)
});
