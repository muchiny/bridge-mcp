#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::AnsibleCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz the 2 validation methods on AnsibleCommandBuilder.
    // These are security-critical: they prevent path traversal
    // and block dangerous ad-hoc module/arg combinations.

    // 1. validate_playbook_path — paths with ".." must ALWAYS be rejected
    let result = AnsibleCommandBuilder::validate_playbook_path(data);
    if data.contains("..") {
        assert!(result.is_err(),
            "Path containing '..' must be rejected: {data}");
    } else {
        assert!(result.is_ok(),
            "Path without '..' must be accepted: {data}");
    }

    // 2. validate_adhoc_module — dangerous modules with dangerous args must be rejected
    let dangerous_patterns = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777"];

    // Test with "shell" module
    let result = AnsibleCommandBuilder::validate_adhoc_module("shell", Some(data));
    let lower = data.to_lowercase();
    for pattern in &dangerous_patterns {
        if lower.contains(pattern) {
            assert!(result.is_err(),
                "Dangerous pattern '{pattern}' with shell module must be rejected");
        }
    }

    // Test with "raw" module
    let result = AnsibleCommandBuilder::validate_adhoc_module("raw", Some(data));
    for pattern in &dangerous_patterns {
        if lower.contains(pattern) {
            assert!(result.is_err(),
                "Dangerous pattern '{pattern}' with raw module must be rejected");
        }
    }

    // Test with "command" module
    let result = AnsibleCommandBuilder::validate_adhoc_module("command", Some(data));
    for pattern in &dangerous_patterns {
        if lower.contains(pattern) {
            assert!(result.is_err(),
                "Dangerous pattern '{pattern}' with command module must be rejected");
        }
    }

    // Safe modules should always pass regardless of args
    let result = AnsibleCommandBuilder::validate_adhoc_module("ping", Some(data));
    assert!(result.is_ok(),
        "Safe module 'ping' must always be accepted");

    let result = AnsibleCommandBuilder::validate_adhoc_module("copy", Some(data));
    assert!(result.is_ok(),
        "Safe module 'copy' must always be accepted");

    // No args should always pass (even for dangerous modules)
    let result = AnsibleCommandBuilder::validate_adhoc_module("shell", None);
    assert!(result.is_ok(),
        "Shell module with no args must be accepted");

    // Fuzz the module name itself with data as the args
    let result = AnsibleCommandBuilder::validate_adhoc_module(data, Some("ls"));
    // Safe args should pass for any module
    assert!(result.is_ok(),
        "Safe args 'ls' must be accepted for any module: {data}");
});
