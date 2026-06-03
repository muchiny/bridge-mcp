# Examples

Usage examples for the MCP SSH Bridge library.

## Contents

| Example | Description |
|---------|-------------|
| `basic_usage.rs` | Config loading and command validation |

## Running

```bash
cargo run --example basic_usage
```

## basic_usage.rs

Demonstrates how to:

1. Load configuration from the default path
2. List configured hosts
3. Use `CommandValidator` to validate commands

```rust
use bridge_mcp::config::{default_config_path, load_config};
use bridge_mcp::security::CommandValidator;

fn main() {
    let config_path = default_config_path();
    let config = load_config(&config_path)?;

    for (alias, host) in &config.hosts {
        println!("{} -> {}@{}", alias, host.user, host.hostname);
    }

    let validator = CommandValidator::new(&config.security);
    match validator.validate("ls -la") {
        Ok(()) => println!("Command allowed"),
        Err(e) => println!("Command denied: {}", e),
    }
}
```
