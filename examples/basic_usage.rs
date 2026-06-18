//! Basic usage example for Bridge MCP
//!
//! This example demonstrates how to:
//! - Load configuration from the default path
//! - Use the command validator to check commands
//! - Create an MCP server instance
//!
//! Run with: `cargo run --example basic_usage`

use std::sync::Arc;

use bridge_mcp::config::{default_config_path, load_config};
use bridge_mcp::security::CommandValidator;

fn main() {
    // Get the default config path
    let config_path = default_config_path();
    println!("Config path: {}", config_path.display());

    // Try to load configuration (may fail if config doesn't exist)
    match load_config(&config_path) {
        Ok(config) => {
            let config = Arc::new(config);

            println!("\n=== Configured Hosts ===");
            for (alias, host) in &config.hosts {
                println!("  {alias} -> {}@{}:{}", host.user, host.hostname, host.port);
                if let Some(desc) = &host.description {
                    println!("      {desc}");
                }
            }

            println!("\n=== Security Settings ===");
            println!("  Mode: {:?}", config.security.mode);
            println!("  Whitelist patterns: {}", config.security.whitelist.len());
            println!("  Blacklist patterns: {}", config.security.blacklist.len());

            // Create a validator and test some commands
            println!("\n=== Command Validation ===");
            let validator = CommandValidator::new(&config.security);

            let test_commands = ["ls -la", "pwd", "whoami", "rm -rf /", "cat /etc/passwd"];

            for cmd in test_commands {
                let result = validator.validate(cmd);
                let status = if result.is_ok() { "ALLOWED" } else { "DENIED" };
                println!("  {cmd} -> {status}");
            }
        }
        Err(e) => {
            println!("Could not load config: {e}");
            println!("\nTo use Bridge MCP, create a config file at:");
            println!("  {}", config_path.display());
            println!("\nSee config/config.example.yaml for the format.");
        }
    }
}
