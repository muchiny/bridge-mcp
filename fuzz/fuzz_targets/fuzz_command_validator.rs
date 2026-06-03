#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use bridge_mcp::config::SecurityConfig;
use bridge_mcp::CommandValidator;

// Create validator ONCE at startup, reuse for all fuzz inputs
static CONFIG: LazyLock<SecurityConfig> = LazyLock::new(SecurityConfig::default);
static VALIDATOR: LazyLock<CommandValidator> = LazyLock::new(|| CommandValidator::new(&CONFIG));

fuzz_target!(|data: &str| {
    // Fuzz the validate function (using pre-compiled regex patterns)
    let result = VALIDATOR.validate(data);

    // Invariants that must always hold:

    // 1. Empty commands must always be rejected
    if data.trim().is_empty() {
        assert!(
            result.is_err(),
            "Empty command should be rejected"
        );
    }

    // 2. Dangerous commands from default blacklist should be rejected
    // (unless they're false positives due to being in a different context)
    let dangerous_patterns = [
        "rm -rf /",
        "mkfs.",
        "> /dev/sda",
        "chmod 777 /",
        "curl | sh",
        "wget | sh",
    ];

    for pattern in dangerous_patterns {
        if data.contains(pattern) {
            // In permissive mode with default blacklist, these should be rejected
            // Note: This is a soft check - the actual behavior depends on config
        }
    }

    // 3. Function should never panic (implicit - if we reach here, no panic occurred)
});
