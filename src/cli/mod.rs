//! CLI module for direct command-line usage
//!
//! This module provides a command-line interface to use the SSH bridge
//! without going through the MCP protocol.

mod runner;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub use runner::{
    DataReductionFlags, run_config_diff, run_describe_tool, run_download, run_exec, run_history,
    run_list_tools, run_status, run_tool, run_upload, run_validate,
};

/// MCP SSH Bridge - Secure SSH access to air-gapped environments
#[derive(Parser)]
#[command(name = "mcp-ssh-bridge")]
#[command(about = "MCP server for SSH access to air-gapped environments")]
#[command(version)]
#[command(after_help = "EXAMPLES:
    # Start MCP server (default mode, for Claude Code integration)
    mcp-ssh-bridge

    # Start MCP server with custom config
    mcp-ssh-bridge --config /path/to/config.yaml

    # Execute a command on a remote host
    mcp-ssh-bridge exec prod-server \"docker ps\"

    # Invoke any of the 337 MCP tools directly via CLI
    mcp-ssh-bridge tool ssh_docker_ps host=prod
    mcp-ssh-bridge tool ssh_exec host=prod command=\"ls -la\" --json
    mcp-ssh-bridge tool ssh_k8s_get --json-args '{\"host\":\"k8s\",\"resource\":\"pods\"}'

    # Reduce output with jq / columns / limit / output-format (ergonomic flags)
    mcp-ssh-bridge --json --jq '.containers[].Names' tool ssh_docker_ps host=prod
    mcp-ssh-bridge --columns name,status --limit 10 tool ssh_docker_ps host=prod
    mcp-ssh-bridge --jq '.items[] | [.metadata.name, .status.phase]' --output-format=tsv \\
        tool ssh_k8s_get host=k8s resource=pods
    mcp-ssh-bridge tool ssh_output_fetch output_id=abc123 offset=40000  # paginate truncated output

    # Progressive tool discovery (token-efficient for AI agents)
    mcp-ssh-bridge list-tools --groups-only
    mcp-ssh-bridge list-tools --group docker
    mcp-ssh-bridge list-tools --search kubernetes
    mcp-ssh-bridge describe-tool ssh_docker_ps

    # Show configured hosts and security settings
    mcp-ssh-bridge status

    # View command history
    mcp-ssh-bridge history --limit 20

    # Upload a file
    mcp-ssh-bridge upload prod-server ./script.sh /tmp/script.sh

    # Download a file
    mcp-ssh-bridge download prod-server /var/log/app.log ./app.log")]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Dry-run mode: show commands without executing
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Output as JSON (applies to all commands)
    #[arg(long, global = true)]
    pub json: bool,

    /// jq expression to apply to tool output (equivalent to `jq_filter=<expr>`).
    /// Explicit `jq_filter=...` in tool args takes precedence over this flag.
    /// Example: `--jq '.containers[].Names'`
    #[cfg(feature = "jq")]
    #[arg(long, global = true)]
    pub jq: Option<String>,

    /// Comma-separated columns to keep in tabular tool output (equivalent to
    /// `columns=name,status,...`). Explicit `columns=...` in tool args wins.
    #[arg(long, global = true, value_delimiter = ',')]
    pub columns: Option<Vec<String>>,

    /// Maximum number of rows/entries to return (equivalent to `limit=N`).
    /// Explicit `limit=N` in tool args wins.
    #[arg(long, global = true)]
    pub limit: Option<usize>,

    /// Output format for jq/yq filter results: `json` (default) or `tsv` for
    /// 60-80% token savings on list-shaped data. Equivalent to
    /// `output_format=<value>`. Explicit `output_format=...` in tool args wins.
    /// Example: `--output-format=tsv`
    #[cfg(feature = "jq")]
    #[arg(long = "output-format", global = true, value_parser = ["json", "tsv"])]
    pub output_format: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Start MCP server (JSON-RPC over stdio) - same as running without arguments
    Serve,

    /// Start MCP server over Streamable HTTP transport
    #[cfg(feature = "http")]
    ServeHttp {
        /// Bind address (overrides config, e.g. "127.0.0.1:3000")
        #[arg(short, long)]
        bind: Option<String>,

        /// SECURITY: allow binding to a non-loopback address with OAuth
        /// disabled. Required only when fronted by an external auth proxy.
        /// Without this flag, non-loopback binds are refused unless OAuth
        /// is enabled in config.
        #[arg(long)]
        insecure_bind: bool,
    },

    /// Execute a command on a remote host
    Exec {
        /// SSH host alias from configuration
        host: String,

        /// Command to execute
        command: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "120")]
        timeout: u64,

        /// Working directory for command execution
        #[arg(short, long)]
        working_dir: Option<String>,
    },

    /// Show configured hosts and security settings
    Status,

    /// Show command execution history
    History {
        /// Number of entries to show
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Filter by host
        #[arg(long)]
        host: Option<String>,
    },

    /// Upload a file to remote host via SFTP
    Upload {
        /// SSH host alias
        host: String,

        /// Local file path
        local_path: PathBuf,

        /// Remote destination path
        remote_path: String,

        /// Transfer mode: overwrite, append, resume, fail-if-exists
        #[arg(long, default_value = "overwrite")]
        mode: String,

        /// Chunk size in bytes for streaming (default: 1MB)
        #[arg(long, default_value = "1048576")]
        chunk_size: u64,

        /// Verify SHA256 checksum after transfer
        #[arg(long)]
        verify_checksum: bool,

        /// Preserve file permissions
        #[arg(long, default_value = "true")]
        preserve_permissions: bool,

        /// Show transfer progress
        #[arg(long, short)]
        progress: bool,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Invoke any registered MCP tool directly via CLI
    ///
    /// Accepts tool arguments as key=value pairs or as a JSON object via --json-args.
    /// Values are auto-coerced to the type declared in the tool's input schema.
    #[command(alias = "t")]
    Tool {
        /// Tool name (e.g. `ssh_docker_ps`, `ssh_exec`, `ssh_k8s_get`)
        tool_name: String,

        /// Tool arguments as key=value pairs (e.g. host=prod command="ls -la")
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Tool arguments as a JSON object (alternative to key=value pairs)
        #[arg(long)]
        json_args: Option<String>,
    },

    /// Show full schema and description for a single tool
    #[command(alias = "dt")]
    DescribeTool {
        /// Tool name (e.g. `ssh_docker_ps`)
        tool_name: String,
    },

    /// List all available MCP tools
    ListTools {
        /// Filter by tool group name
        #[arg(short, long)]
        group: Option<String>,

        /// Show only group names with tool counts (compact output for AI agents)
        #[arg(long)]
        groups_only: bool,

        /// Search tools by keyword in name or description
        #[arg(short, long)]
        search: Option<String>,

        /// Output as JSON (deprecated: use global --json instead)
        #[arg(long)]
        json: bool,
    },

    /// Validate configuration file
    Validate,

    /// Show differences between current and default configuration
    ConfigDiff,

    /// Manage the local daemon that keeps a shared SSH connection pool
    /// alive across CLI invocations.
    ///
    /// When running, the daemon listens on a Unix socket (default:
    /// $XDG_RUNTIME_DIR/mcp-ssh-bridge.sock). CLI commands detect the
    /// socket, forward their tool calls to it, and skip the SSH
    /// handshake on subsequent invocations.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Download a file from remote host via SFTP
    Download {
        /// SSH host alias
        host: String,

        /// Remote file path
        remote_path: String,

        /// Local destination path
        local_path: PathBuf,

        /// Transfer mode: overwrite, append, resume, fail-if-exists
        #[arg(long, default_value = "overwrite")]
        mode: String,

        /// Chunk size in bytes for streaming (default: 1MB)
        #[arg(long, default_value = "1048576")]
        chunk_size: u64,

        /// Verify SHA256 checksum after transfer
        #[arg(long)]
        verify_checksum: bool,

        /// Preserve file permissions
        #[arg(long, default_value = "true")]
        preserve_permissions: bool,

        /// Show transfer progress
        #[arg(long, short)]
        progress: bool,
    },
}

/// Sub-actions for the `daemon` command.
#[derive(Subcommand, Clone, Debug)]
pub enum DaemonAction {
    /// Start the daemon in the foreground (blocks until SIGINT).
    Start {
        /// Override the socket path. Defaults to
        /// `$XDG_RUNTIME_DIR/mcp-ssh-bridge.sock` or `/tmp/mcp-ssh-bridge-$UID.sock`.
        #[arg(long)]
        socket_path: Option<PathBuf>,
    },
    /// Stop a running daemon via SIGTERM.
    Stop {
        #[arg(long)]
        socket_path: Option<PathBuf>,
    },
    /// Show whether a daemon is currently running.
    Status {
        #[arg(long)]
        socket_path: Option<PathBuf>,
    },
}

/// Output format for daemon status (used by `--output`).
#[derive(ValueEnum, Clone, Debug, Default)]
#[allow(
    dead_code,
    reason = "reserved for future --output flag on daemon status"
)]
pub enum DaemonOutputFormat {
    #[default]
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_args_is_serve_mode() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn test_serve_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Serve)));
    }

    #[test]
    fn test_status_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_exec_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "exec", "prod", "docker ps"]).unwrap();
        match cli.command {
            Some(Commands::Exec {
                host,
                command,
                timeout,
                working_dir,
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(command, "docker ps");
                assert_eq!(timeout, 120); // default
                assert!(working_dir.is_none());
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_exec_with_timeout() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "exec", "srv", "ls", "-t", "30"]).unwrap();
        match cli.command {
            Some(Commands::Exec { timeout, .. }) => assert_eq!(timeout, 30),
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_exec_with_working_dir() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "exec", "srv", "ls", "-w", "/var/log"]).unwrap();
        match cli.command {
            Some(Commands::Exec { working_dir, .. }) => {
                assert_eq!(working_dir, Some("/var/log".to_string()));
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_history_defaults() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "history"]).unwrap();
        match cli.command {
            Some(Commands::History { limit, host }) => {
                assert_eq!(limit, 10); // default
                assert!(host.is_none());
            }
            _ => panic!("Expected History command"),
        }
    }

    #[test]
    fn test_history_with_options() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "history", "-l", "50", "--host", "prod"])
            .unwrap();
        match cli.command {
            Some(Commands::History { limit, host }) => {
                assert_eq!(limit, 50);
                assert_eq!(host, Some("prod".to_string()));
            }
            _ => panic!("Expected History command"),
        }
    }

    #[test]
    fn test_global_config_flag() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "--config", "/etc/mcp.yaml", "status"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/etc/mcp.yaml")));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_config_short_flag() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "-c", "/tmp/config.yaml", "serve"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/config.yaml")));
    }

    #[test]
    fn test_upload_subcommand() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "upload",
            "prod",
            "./script.sh",
            "/tmp/script.sh",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Upload {
                host,
                local_path,
                remote_path,
                mode,
                chunk_size,
                verify_checksum,
                ..
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(local_path, PathBuf::from("./script.sh"));
                assert_eq!(remote_path, "/tmp/script.sh");
                assert_eq!(mode, "overwrite");
                assert_eq!(chunk_size, 1_048_576);
                assert!(!verify_checksum);
            }
            _ => panic!("Expected Upload command"),
        }
    }

    #[test]
    fn test_download_subcommand() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "download",
            "prod",
            "/var/log/app.log",
            "./app.log",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Download {
                host,
                remote_path,
                local_path,
                ..
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(remote_path, "/var/log/app.log");
                assert_eq!(local_path, PathBuf::from("./app.log"));
            }
            _ => panic!("Expected Download command"),
        }
    }

    #[test]
    fn test_exec_missing_args_fails() {
        let result = Cli::try_parse_from(["mcp-ssh-bridge", "exec"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_subcommand_fails() {
        let result = Cli::try_parse_from(["mcp-ssh-bridge", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_upload_with_verify_checksum() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "upload",
            "srv",
            "./f",
            "/tmp/f",
            "--verify-checksum",
            "--progress",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Upload {
                verify_checksum,
                progress,
                ..
            }) => {
                assert!(verify_checksum);
                assert!(progress);
            }
            _ => panic!("Expected Upload command"),
        }
    }

    #[test]
    fn test_tool_subcommand() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "tool",
            "ssh_docker_ps",
            "host=prod",
            "all=true",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Tool {
                tool_name,
                args,
                json_args,
            }) => {
                assert_eq!(tool_name, "ssh_docker_ps");
                assert_eq!(args, vec!["host=prod", "all=true"]);
                assert!(json_args.is_none());
            }
            _ => panic!("Expected Tool command"),
        }
    }

    #[test]
    fn test_tool_with_json_args() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "tool",
            "ssh_exec",
            "--json-args",
            r#"{"host":"prod","command":"ls"}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Tool {
                tool_name,
                json_args,
                ..
            }) => {
                assert_eq!(tool_name, "ssh_exec");
                assert!(json_args.is_some());
            }
            _ => panic!("Expected Tool command"),
        }
    }

    #[test]
    fn test_tool_alias() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "t", "ssh_status"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Tool { .. })));
    }

    #[test]
    fn test_describe_tool_subcommand() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "describe-tool", "ssh_docker_ps"]).unwrap();
        match cli.command {
            Some(Commands::DescribeTool { tool_name }) => {
                assert_eq!(tool_name, "ssh_docker_ps");
            }
            _ => panic!("Expected DescribeTool command"),
        }
    }

    #[test]
    fn test_describe_tool_alias() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "dt", "ssh_exec"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::DescribeTool { .. })));
    }

    #[test]
    fn test_list_tools_groups_only() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "list-tools", "--groups-only"]).unwrap();
        match cli.command {
            Some(Commands::ListTools { groups_only, .. }) => {
                assert!(groups_only);
            }
            _ => panic!("Expected ListTools command"),
        }
    }

    #[test]
    fn test_list_tools_search() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "list-tools", "--search", "docker"]).unwrap();
        match cli.command {
            Some(Commands::ListTools { search, .. }) => {
                assert_eq!(search, Some("docker".to_string()));
            }
            _ => panic!("Expected ListTools command"),
        }
    }

    #[test]
    fn test_global_json_flag() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "--json", "status"]).unwrap();
        assert!(cli.json);
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_global_json_flag_with_tool() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "--json", "tool", "ssh_exec", "host=prod"])
                .unwrap();
        assert!(cli.json);
        assert!(matches!(cli.command, Some(Commands::Tool { .. })));
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_global_jq_flag() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "--jq",
            ".containers[].name",
            "tool",
            "ssh_docker_ps",
            "host=prod",
        ])
        .unwrap();
        assert_eq!(cli.jq.as_deref(), Some(".containers[].name"));
        assert!(matches!(cli.command, Some(Commands::Tool { .. })));
    }

    #[cfg(not(feature = "jq"))]
    #[test]
    fn test_global_jq_flag_rejected_without_feature() {
        // When the binary is built without the `jq` feature, --jq must NOT be
        // accepted silently — clap should reject it as an unknown argument so
        // the user knows the filter cannot be applied (#2A).
        let result = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "--jq",
            ".x",
            "tool",
            "ssh_exec",
            "host=h",
            "command=true",
        ]);
        assert!(
            result.is_err(),
            "--jq should be rejected when feature 'jq' is disabled"
        );
    }

    #[test]
    fn test_global_columns_flag_splits_on_comma() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "--columns",
            "name,status,image",
            "tool",
            "ssh_docker_ps",
            "host=prod",
        ])
        .unwrap();
        let cols = cli.columns.expect("expected columns to be set");
        assert_eq!(cols, vec!["name", "status", "image"]);
    }

    #[test]
    fn test_global_limit_flag() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "--limit",
            "5",
            "tool",
            "ssh_docker_ps",
            "host=prod",
        ])
        .unwrap();
        assert_eq!(cli.limit, Some(5));
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_data_reduction_flags_combined() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "--json",
            "--jq",
            ".items[].id",
            "--columns",
            "a,b",
            "--limit",
            "10",
            "tool",
            "ssh_k8s_get",
            "host=k8s",
            "resource=pods",
        ])
        .unwrap();
        assert!(cli.json);
        assert_eq!(cli.jq.as_deref(), Some(".items[].id"));
        assert_eq!(cli.columns.as_ref().map(Vec::len), Some(2));
        assert_eq!(cli.limit, Some(10));
    }
}
